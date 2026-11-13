// Included in Mothership beside the deployment commands so every exchange
// uses its authenticated cluster socket and its exclusive durable registry.
template<class Request, class Response>
bool globalSingleWriterExchange(MothershipTopic topic, uint128_t site, const Request& source, Response& response, String& failure) {
  String name;
  name.assignItoh(site);
  return configureControlTarget(name.c_str(), &failure) && requestTopicRoundTrip(topic, source, response, failure, true);
}

bool globalSingleWriterControl(const ProdigyGlobalSingleWriterControl& q, ProdigyGlobalSingleWriterControl& r, String& failure) {
  return prodigyGlobalSingleWriterControlRequestValid(q) && globalSingleWriterExchange(MothershipTopic::globalSingleWriterControl,q.localClusterUUID,q,r,failure) &&
      prodigyGlobalSingleWriterControlReportValid(r) && r.membershipUUID == q.membershipUUID && r.deploymentID == q.deploymentID &&
      r.operationUUID == q.operationUUID && r.localClusterUUID == q.localClusterUUID && r.containerUUID == q.containerUUID &&
      r.memberID == q.memberID && r.action == q.action && r.targetMemberID == q.targetMemberID &&
      (!q.generation || q.generation == r.generation) && (!q.bootNonce || q.bootNonce == r.bootNonce) &&
      q.expectedCommittedConfigIndex == r.expectedCommittedConfigIndex && q.expectedCommittedConfigSHA256 == r.expectedCommittedConfigSHA256 &&
      r.protocolVersion == q.protocolVersion && r.reservationTopic == q.reservationTopic &&
      r.reservationRequestUUID == q.reservationRequestUUID && r.minimumAppliedIndex == q.minimumAppliedIndex;
}

static ProdigyGlobalSingleWriterControl memberCommand(const MothershipGlobalSingleWriterGroup& state, const GlobalSingleWriterMember& m) {
  ProdigyGlobalSingleWriterControl q{};
  q.membershipUUID = state.group.membershipUUID; q.operationUUID = state.group.operationUUID;
  q.localClusterUUID = m.clusterUUID; q.containerUUID = m.containerUUID; q.memberID = m.memberID;
  q.deploymentID = state.group.deploymentID; q.generation = state.group.generation;
  return q;
}

bool provisionGlobalSingleWriter(const MothershipGlobalSingleWriterGroup& state, const GlobalSingleWriterMember& m,
                    const ProdigyGlobalSingleWriterControl& inspected, String& failure) {
  if (inspected.provisioned) return true;
  auto q = memberCommand(state,m);
  q.action = GlobalSingleWriterControlAction::provisionOnce;
  q.bootNonce = inspected.bootNonce;
  MothershipGlobalSingleWriterGrant grant;
  grant.membershipUUID=q.membershipUUID; grant.operationUUID=q.operationUUID; grant.localClusterUUID=q.localClusterUUID;
  grant.containerUUID=q.containerUUID; grant.bootNonce=q.bootNonce; grant.deploymentID=q.deploymentID; grant.memberID=q.memberID;
  { auto registry=openClusterRegistry(); if (!registry.recordGlobalSingleWriterGrantBeforeDispatch(grant,&failure)) return false; }
  ProdigyGlobalSingleWriterControl reply{};
  return globalSingleWriterControl(q,reply,failure) && reply.provisioned;
}

bool offerGlobalSingleWriterMember(const MothershipGlobalSingleWriterGroup& state, int32_t id, uint128_t site, GlobalSingleWriterMemberRole role,
                      GlobalSingleWriterMember& result, String& failure) {
  ProdigyGlobalSingleWriterPlacementExchange q{}, r{};
  q.membershipUUID=state.group.membershipUUID; q.deploymentID=state.group.deploymentID; q.localClusterUUID=site;
  q.member.memberID=id; q.member.clusterUUID=site; q.member.role=role;
  q.member.containerUUID=Random::generateNumberWithNBits<128,uint128_t>(); q.reserved=state.group.members;
  if (!globalSingleWriterExchange(MothershipTopic::globalSingleWriterPlacement,site,q,r,failure) || r.member.memberID!=id ||
      r.member.clusterUUID!=site || q.member.containerUUID!=r.member.containerUUID || !r.member.privateIPv6.is6 ||
      r.member.privateIPv6.isNull() || r.member.role!=role) return false;
  result = r.member; return true;
}

bool projectGlobalSingleWriter(const MothershipGlobalSingleWriterGroup& state, uint128_t site, String& failure) {
  auto group=state.group; group.localClusterUUID=site;
  CommitGlobalSingleWriterMembershipResponse reply{};
  if (!globalSingleWriterExchange(MothershipTopic::commitGlobalSingleWriterMembership,site,group,reply,failure) || !reply.durableGeneration) return false;
  String wanted,received;
  return BitseryEngine::serialize(wanted,group) && BitseryEngine::serialize(received,reply.projection) && wanted==received;
}

bool globalSingleWriterPlacement(const MothershipGlobalSingleWriterGroup& state,uint128_t site,const GlobalSingleWriterMember* retired,String& failure) {
  ProdigyGlobalSingleWriterPlacementExchange q{},r{};
  q.action=retired ? GlobalSingleWriterPlacementAction::retire : GlobalSingleWriterPlacementAction::reconcile;
  q.membershipUUID=state.group.membershipUUID; q.localClusterUUID=site; q.deploymentID=state.group.deploymentID;
  q.generation=state.group.generation; q.committedConfigIndex=state.group.expectedCommittedConfigIndex;
  q.committedConfigSHA256=state.group.expectedCommittedConfigSHA256;
  if (retired) q.member=*retired;
  return globalSingleWriterExchange(MothershipTopic::globalSingleWriterPlacement,site,q,r,failure);
}

static bool globalSingleWriterHex(const char* raw,uint128_t& out) {
  String text; text.setInvariant(raw); return prodigyParseCanonicalHex128(text,out) && out;
}

void configureGlobalSingleWriterGroup(int argc,char** argv) {
  MothershipGlobalSingleWriterGroup state{};
  auto& g=state.group;
  if (argc < 5 || argc > 7 || !globalSingleWriterHex(argv[0],g.membershipUUID) || !globalSingleWriterHex(argv[1],g.operationUUID) ||
      !mothershipParseUnsignedArgument(argv[2],UINT64_MAX,g.deploymentID) || (!uint16_t(g.deploymentID>>48) || !(g.deploymentID & 0xFFFFFFFFFFFFULL)) ||
      !mothershipParseUnsignedArgument(argv[3],UINT64_MAX,state.graceMs) || !state.graceMs) {
    basics_log("usage: configureGlobalSingleWriterGroup GROUP OPERATION DEPLOYMENT GRACE_MS CLUSTER [CLUSTER [CLUSTER]]\n"); exit(EXIT_FAILURE);
  }
  String failure;
  for (int i=4;i<argc;++i) {
    if (!configureControlTarget(argv[i],&failure) || !socket.configuredClusterUUID()) exit(EXIT_FAILURE);
    state.sites.push_back(socket.configuredClusterUUID());
  }
  std::sort(state.sites.begin(),state.sites.end());
  if (std::adjacent_find(state.sites.begin(),state.sites.end())!=state.sites.end()) exit(EXIT_FAILURE);
  bool resumed=false;
  Vector<MothershipProdigyCluster> inventory;
  { auto registry=openClusterRegistry(); MothershipGlobalSingleWriterGroup saved;
    if (registry.loadGlobalSingleWriterGroup(g.membershipUUID,saved,&failure)) {
      if (saved.group.membershipUUID!=g.membershipUUID || saved.group.operationUUID!=g.operationUUID ||
          saved.group.deploymentID!=g.deploymentID || saved.graceMs!=state.graceMs || saved.sites!=state.sites) exit(EXIT_FAILURE);
      state=std::move(saved); resumed=true;
    } else if (failure!="record not found"_ctv || !registry.listClusters(inventory,&failure)) exit(EXIT_FAILURE);
  }
  if (!resumed) {
    // Initial genesis must not reuse a live deployment identity. Other
    // applications and deployments retain their independent groups.
    for (const auto& site:inventory) {
      ClusterStatusReport report;
      if (!readManagedClusterStatus(site,report,failure)) exit(EXIT_FAILURE);
      for (const auto& app:report.applicationReports) for (const auto& deployment:app.deploymentReports)
        if (((uint64_t(app.applicationID) << 48) | deployment.versionID) == g.deploymentID) {
        basics_log("existing deployment must be fenced before global single-writer genesis\n"); exit(EXIT_FAILURE);
      }
    }
    g.genesisMemberIDs={1,2,3}; g.highestAllocatedMemberID=3; g.localClusterUUID=state.sites.front();
    g.expectedCommittedConfigIndex=1; g.generation=1;
    const auto sites=ProdigyGlobalSingleWriterPlacement::initial({state.sites.begin(),state.sites.end()});
    for (int i=0;i<3;++i) {
      GlobalSingleWriterMember m;
      if (!offerGlobalSingleWriterMember(state,i+1,sites[i],GlobalSingleWriterMemberRole::voter,m,failure)) exit(EXIT_FAILURE);
      g.members.push_back(m);
    }
    if (!prodigyGlobalSingleWriterCommittedConfigDigest(g.membershipUUID,g.deploymentID,1,g.members,g.expectedCommittedConfigSHA256)) exit(EXIT_FAILURE);
    auto registry=openClusterRegistry(); if (!registry.saveGlobalSingleWriterGroup(0,state,&failure)) exit(EXIT_FAILURE);
  }
  for (const auto site:state.sites) if (!projectGlobalSingleWriter(state,site,failure)) { basics_log("global single-writer projection failed: %s\n",failure.c_str()); exit(EXIT_FAILURE); }
  basics_log("configureGlobalSingleWriterGroup success=1 voters=3 sites=%u resumed=%d\n",unsigned(state.sites.size()),int(resumed));
}

void runGlobalSingleWriterControl(int argc,char** argv) {
  uint128_t groupID=0;
  uint64_t member=0;
  const bool receiptInspection = argc == 6 && !std::strcmp(argv[1],"inspectReservation");
  uint64_t topic = 0, minimumAppliedIndex = 0;
  uint128_t requestUUID = 0;
  if ((!receiptInspection && argc != 3) || !globalSingleWriterHex(argv[0],groupID) ||
      !mothershipParseUnsignedArgument(argv[2],INT32_MAX,member) || !member ||
      (receiptInspection && (!mothershipParseUnsignedArgument(argv[3],UINT16_MAX,topic) || !topic ||
          !globalSingleWriterHex(argv[4],requestUUID) || !requestUUID ||
          !mothershipParseUnsignedArgument(argv[5],UINT64_MAX,minimumAppliedIndex) || !minimumAppliedIndex))) {
    basics_log("usage: globalSingleWriterControl GROUP inspect|provisionOnce MEMBER\n"
               "       globalSingleWriterControl GROUP inspectReservation MEMBER TOPIC REQUEST_UUID MIN_APPLIED_INDEX\n"); exit(EXIT_FAILURE);
  }
  MothershipGlobalSingleWriterGroup state; String failure;
  { auto registry=openClusterRegistry(); if (!registry.loadGlobalSingleWriterGroup(groupID,state,&failure)) exit(EXIT_FAILURE); }
  auto m=std::find_if(state.group.members.begin(),state.group.members.end(),[&](const auto& m){return m.memberID==int32_t(member);});
  if (m==state.group.members.end()) exit(EXIT_FAILURE);
  ProdigyGlobalSingleWriterControl report{};
  if (receiptInspection) {
    auto q=memberCommand(state,*m);
    q.protocolVersion=2; q.action=GlobalSingleWriterControlAction::inspectReservation;
    q.reservationTopic=uint16_t(topic); q.reservationRequestUUID=requestUUID; q.minimumAppliedIndex=minimumAppliedIndex;
    if (!globalSingleWriterControl(q,report,failure)) { basics_log("global single-writer reservation inspect failed: %s\n",failure.c_str()); exit(EXIT_FAILURE); }
  } else if (!globalSingleWriterControl(memberCommand(state,*m),report,failure)) {
    basics_log("global single-writer inspect failed: %s\n",failure.c_str()); exit(EXIT_FAILURE);
  }
  if (!receiptInspection && !std::strcmp(argv[1],"provisionOnce")) {
    if (!provisionGlobalSingleWriter(state,*m,report,failure) || !globalSingleWriterControl(memberCommand(state,*m),report,failure)) exit(EXIT_FAILURE);
  } else if (!receiptInspection && std::strcmp(argv[1],"inspect")) exit(EXIT_FAILURE);
  basics_log("globalSingleWriterControl success=1 member=%d provisioned=%d leader=%d term=%llu config=%llu applied=%llu digest=%s receiptTopic=%u receiptRequest=%016llx%016llx receiptMinimumApplied=%llu receiptFound=%u receiptDigest=%s\n",
      m->memberID,int(report.provisioned),report.leaderMemberID,(unsigned long long)report.term,
      (unsigned long long)report.committedConfigIndex,(unsigned long long)report.appliedIndex,report.committedConfigSHA256.c_str(),
      unsigned(report.reservationTopic),(unsigned long long)(report.reservationRequestUUID>>64),(unsigned long long)report.reservationRequestUUID,
      (unsigned long long)report.minimumAppliedIndex,unsigned(report.reservationFound),report.reservationDigest.c_str());
  for (const auto& member : report.members) {
    basics_log("globalSingleWriterCommittedMember member=%d role=%s cluster=%016llx%016llx container=%016llx%016llx reachable=%u caughtUp=%u\n",
        member.memberID, member.role == GlobalSingleWriterMemberRole::voter ? "voter" : "learner",
        (unsigned long long)(member.clusterUUID >> 64), (unsigned long long)member.clusterUUID,
        (unsigned long long)(member.containerUUID >> 64), (unsigned long long)member.containerUUID,
        unsigned(std::binary_search(report.reachableMemberIDs.begin(), report.reachableMemberIDs.end(), member.memberID)),
        unsigned(std::binary_search(report.caughtUpMemberIDs.begin(), report.caughtUpMemberIDs.end(), member.memberID)));
  }
}

bool reconcileGlobalSingleWriterOnce(MothershipGlobalSingleWriterGroup state, String& failure) {
  auto save = [&]() { auto registry=openClusterRegistry(); return registry.saveGlobalSingleWriterGroup(state.revision,state,&failure); };
  auto& g=state.group;
  // An unreachable site cannot veto an existing majority. A projection is
  // replayed to that site before it is considered for any further action.
  std::vector<uint128_t> eligible;
  for (auto site:state.sites) {
    String unavailable;
    if (projectGlobalSingleWriter(state,site,unavailable)) {
      eligible.push_back(site);
      (void)globalSingleWriterPlacement(state,site,nullptr,unavailable);
    }
  }
  std::vector<ProdigyGlobalSingleWriterControl> reports;
  for (const auto& member:g.members) {
    if (std::find(eligible.begin(),eligible.end(),member.clusterUUID)==eligible.end()) continue;
    auto q=memberCommand(state,member); ProdigyGlobalSingleWriterControl r{}; String unavailable;
    if (!globalSingleWriterControl(q,r,unavailable)) continue;
    if (!r.provisioned) {
      if (!provisionGlobalSingleWriter(state,member,r,unavailable))
        basics_log("global single-writer member %d is awaiting provisioning: %s\n", member.memberID, unavailable.c_str());
      continue;
    }
    reports.push_back(std::move(r));
  }
  String routeFailure;
  const bool routed = reconcileGlobalSingleWriterSiblingRoutes(state, eligible, routeFailure);
  if (!routed) basics_log("global single-writer sibling route unavailable: %s\n", routeFailure.c_str());
  // Independent authenticated reports from two current voters must agree on
  // the leader, term and committed configuration. A learner is never a vote.
  auto isVoter=[](const auto& members,int32_t id) {
    return std::any_of(members.begin(),members.end(),[&](const auto& m){return m.memberID==id && m.role==GlobalSingleWriterMemberRole::voter;});
  };
  const ProdigyGlobalSingleWriterControl* leader=nullptr;
  for (const auto& l:reports) {
    if (!l.committedConfigIndex || !l.term || l.memberID!=l.leaderMemberID || !isVoter(l.members,l.memberID)) continue;
    size_t votes=0;
    for (const auto& peer:reports) if (peer.leaderMemberID==l.memberID && peer.term==l.term &&
        peer.committedConfigIndex==l.committedConfigIndex && peer.committedConfigSHA256==l.committedConfigSHA256 &&
        isVoter(l.members,peer.memberID) &&
        std::binary_search(l.reachableMemberIDs.begin(),l.reachableMemberIDs.end(),peer.memberID)) ++votes;
    if (votes>=2) {
      if (leader) { failure.assign("conflicting majority reports"_ctv); return false; }
      leader=&l;
    }
  }
  if (!leader) { basics_log("reconcileGlobalSingleWriter waiting for two matching voter reports\n"); return true; }
  if (leader->committedConfigIndex<g.expectedCommittedConfigIndex ||
      (leader->committedConfigIndex==g.expectedCommittedConfigIndex && leader->committedConfigSHA256!=g.expectedCommittedConfigSHA256)) {
    failure.assign("committed configuration disagrees with registry"_ctv); return false;
  }
  if (!reconcileGlobalSingleWriterMemberRoutes(state, *leader, eligible, failure)) {
    basics_log("reconcileGlobalSingleWriter waiting for the committed members' sibling routes: %s\n", failure.c_str());
    return true;
  }
  if (state.cleanup) {
    // Migrate the v1/v2 single cleanup slot only after the same committed
    // successor that originally authorized retirement has been certified.
    if (leader->members.size()!=3 || isVoter(leader->members,state.outgoing.memberID) ||
        !isVoter(leader->members,state.incoming.memberID) || leader->committedConfigSHA256!=g.expectedCommittedConfigSHA256) {
      failure.assign("retirement needs its exact committed successor"_ctv); return false;
    }
    if (!mothershipGlobalSingleWriterDeferRetirement(state,state.outgoing) || !save()) return false;
  }
  bool retired = false;
  if (!mothershipGlobalSingleWriterRetryRetirements(state,leader->members,[&](const auto& binding) {
    String unavailable;
    if (std::find(eligible.begin(),eligible.end(),binding.clusterUUID)==eligible.end() ||
        !globalSingleWriterPlacement(state,binding.clusterUUID,&binding,unavailable)) return false;
    basics_log("reconcileGlobalSingleWriter retired member %d after committed configuration %llu\n",
        binding.memberID, (unsigned long long)leader->committedConfigIndex);
    return true;
  },retired)) {
    failure.assign("retirement is not fenced by the committed configuration"_ctv); return false;
  }
  if (retired && !save()) return false;
  const auto now=uint64_t(Time::now<TimeResolution::ms>());
  Vector<MothershipGlobalSingleWriterGroup::Missing> missing;
  std::vector<ProdigyGlobalSingleWriterPlacement::Voter> voters;
  bool learnerPresent=false;
  for (const auto& m:leader->members) {
    auto known=std::find_if(g.members.begin(),g.members.end(),[&](const auto& v){return v.memberID==m.memberID;});
    if (known==g.members.end() || known->containerUUID!=m.containerUUID || known->clusterUUID!=m.clusterUUID ||
        !known->privateIPv6.equals(m.privateIPv6)) { failure.assign("unknown committed member binding"_ctv); return false; }
    if (m.role==GlobalSingleWriterMemberRole::learner) {
      if (m.memberID!=state.incoming.memberID) { failure.assign("unowned committed learner"_ctv); return false; }
      learnerPresent=true; continue;
    }
    bool live=std::binary_search(leader->reachableMemberIDs.begin(),leader->reachableMemberIDs.end(),m.memberID);
    uint64_t since=0;
    if (!live) {
      auto before=std::find_if(state.missing.begin(),state.missing.end(),[&](const auto& v){return v.id==m.memberID;});
      since=before==state.missing.end() ? now : std::min(now,before->sinceMs);
      missing.push_back({m.memberID,since});
    }
    voters.push_back({m.memberID,m.clusterUUID,live,since});
  }
  bool changed=missing.size()!=state.missing.size() || !std::equal(missing.begin(),missing.end(),state.missing.begin(),
      [](const auto& a,const auto& b){return a.id==b.id && a.sinceMs==b.sinceMs;});
  if (changed) { state.missing=std::move(missing); if (!save()) return false; }
  using namespace ProdigyGlobalSingleWriterPlacement;
  Replacement binding{state.outgoing.memberID,state.incoming.memberID,state.incoming.clusterUUID};
  bool caught=std::binary_search(leader->caughtUpMemberIDs.begin(),leader->caughtUpMemberIDs.end(),binding.newID);
  // A site whose voter has lost contact with the elected leader is not
  // a repair destination, even if its independent control socket is online.
  auto destinations = eligible;
  if (!state.incoming.memberID && !state.missing.empty()) {
    std::erase_if(destinations, [&](uint128_t site) {
      return std::none_of(voters.begin(), voters.end(), [&](const auto& v){return v.cluster == site && v.reachable;});
    });
  }
  if (!routed && state.missing.empty() && !binding.newID) return true;
  auto d=next(voters,destinations,leader->committedConfigIndex,g.highestAllocatedMemberID,now,state.graceMs,
      binding.newID ? &binding : nullptr,learnerPresent,caught);
  if (d.action==Action::wait) { basics_log("reconcileGlobalSingleWriter waiting config=%llu\n",(unsigned long long)leader->committedConfigIndex); return true; }
  if (d.action==Action::addLearner && !state.incoming.memberID) {
    // Never age out a still-unconfirmed physical retirement to make room for
    // another replacement. Completed tombstones remain bounded separately.
    if (state.pendingRetirementIDs.size() == 256) {
      basics_log("reconcileGlobalSingleWriter waiting for retirement capacity\n"); return true;
    }
    auto old=std::find_if(g.members.begin(),g.members.end(),[&](const auto& m){return m.memberID==d.replacement.oldID;});
    if (old==g.members.end()) return false;
    state.outgoing=*old;
    if (!offerGlobalSingleWriterMember(state,d.replacement.newID,d.replacement.target,GlobalSingleWriterMemberRole::learner,state.incoming,failure)) return false;
    g.highestAllocatedMemberID=state.incoming.memberID; g.members.push_back(state.incoming);
    g.replacementPending=true; g.expectedCommittedConfigIndex=leader->committedConfigIndex;
    g.expectedCommittedConfigSHA256=leader->committedConfigSHA256; ++g.generation;
    return save();
  }
  if (d.action==Action::retireContainer) {
    g.members=leader->members; g.retiredMemberIDs.push_back(state.outgoing.memberID);
    std::sort(g.retiredMemberIDs.begin(),g.retiredMemberIDs.end());
    // IDs below the durable high-water mark can never be issued again.
    if (g.retiredMemberIDs.size()>256) {
      auto obsolete=std::find_if(g.retiredMemberIDs.begin(),g.retiredMemberIDs.end(),[&](int32_t id){
        return id!=state.outgoing.memberID &&
            !std::binary_search(state.pendingRetirementIDs.begin(),state.pendingRetirementIDs.end(),id);
      });
      if (obsolete == g.retiredMemberIDs.end()) return false;
      g.retiredMemberIDs.erase(obsolete);
    }
    // Keep the endpoint that belonged to each retained Raft tombstone. A later
    // rebalance can then identify the exact private route to the former voter.
    auto obsolete = std::remove_if(state.retiredBindings.begin(), state.retiredBindings.end(), [&](const auto& member) {
      return !std::binary_search(g.retiredMemberIDs.begin(), g.retiredMemberIDs.end(), member.memberID);
    });
    state.retiredBindings.erase(obsolete, state.retiredBindings.end());
    g.expectedCommittedConfigIndex=leader->committedConfigIndex; g.expectedCommittedConfigSHA256=leader->committedConfigSHA256;
    g.replacementPending=false; ++g.generation;
    if (!mothershipGlobalSingleWriterDeferRetirement(state,state.outgoing)) return false;
    return save();
  }
  if (std::none_of(reports.begin(),reports.end(),[&](const auto& r){return r.memberID==state.incoming.memberID && r.provisioned;}))
    return true;
  auto m=std::find_if(g.members.begin(),g.members.end(),[&](const auto& v){return v.memberID==leader->memberID;});
  if (m==g.members.end()) return false;
  auto q=memberCommand(state,*m); q.bootNonce=leader->bootNonce;
  q.action=d.action==Action::addLearner ? GlobalSingleWriterControlAction::addLearner :
           d.action==Action::removeVoter ? GlobalSingleWriterControlAction::removeVoter : GlobalSingleWriterControlAction::promoteLearner;
  q.targetMemberID=d.action==Action::removeVoter ? state.outgoing.memberID : state.incoming.memberID;
  q.expectedCommittedConfigIndex=leader->committedConfigIndex; q.expectedCommittedConfigSHA256=leader->committedConfigSHA256;
  ProdigyGlobalSingleWriterControl r{};
  if (globalSingleWriterControl(q,r,failure)) return true;
  // Proposal admission can race a leader change. Re-observe the durable
  // configuration on the next pass; never infer it from an RPC outcome.
  basics_log("reconcileGlobalSingleWriter change pending: %s\n",failure.c_str()); return true;
}

void runReconcileGlobalSingleWriter(int argc,char** argv) {
  uint128_t group=0;
  if ((argc!=1 && argc!=2) || !globalSingleWriterHex(argv[0],group) || (argc==2 && std::strcmp(argv[1],"--watch"))) {
    basics_log("usage: reconcileGlobalSingleWriter GROUP [--watch]\n"); exit(EXIT_FAILURE);
  }
  do {
    MothershipGlobalSingleWriterGroup state; String failure;
    { auto registry=openClusterRegistry(); if (!registry.loadGlobalSingleWriterGroup(group,state,&failure)) exit(EXIT_FAILURE); }
    if (!reconcileGlobalSingleWriterOnce(std::move(state),failure)) { basics_log("reconcileGlobalSingleWriter failed: %s\n",failure.c_str()); exit(EXIT_FAILURE); }
    if (argc==1) return;
    ::sleep(1);
  } while (true);
}
