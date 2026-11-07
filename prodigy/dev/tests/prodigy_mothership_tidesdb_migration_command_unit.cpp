#include <cassert>
#include <prodigy/mothership/mothership.tidesdb.migration.command.h>

int main(int argc, char **argv)
{
  using namespace MothershipTidesMigration;
  assert(argc == 4);
  const auto root=fs::current_path()/".run"/("migration-command-"+std::to_string(::getpid()));
  assert(!fs::exists(root)); fs::create_directories(root/"tools"); ::chmod(root.c_str(),0700);
  fs::create_symlink(fs::absolute(argv[2]),root/"tools/prodigy_tidesdb9_export");
  fs::create_symlink(fs::absolute(argv[3]),root/"tools/prodigy_tidesdb10_import");
  Plan plan; plan.operationRoot=root.string(); plan.planSHA=std::string(64,'a');
  Execution execution(plan); execution.localRuntime=root.string();
  execution.receipt.clusterUUID=1; execution.receipt.operationID=2;
  execution.receipt.phase=MothershipTidesDBMigrationPhase::writersQuiesced;
  for(unsigned i=0;i<8;++i) {
    const auto label="database-"+std::to_string(i), path=(root/label).string();
    execution.run(0,quote(fs::absolute(argv[1]).string())+" "+quote(path));
    execution.addDB(0,label,path,root.string());
  }
  String failure;
  assert(mothershipMigrateTidesDB9To10Offline(execution.receipt,"export"_ctv,"import"_ctv,execution,&failure));
  assert(execution.receipt.phase==MothershipTidesDBMigrationPhase::swapped);
  assert(mothershipMigrateTidesDB9To10Offline(execution.receipt,"export"_ctv,"import"_ctv,execution,&failure));
  MothershipTidesDBMigrationReceipt persisted;
  String bytes=text(read(root/"receipt")); assert(BitseryEngine::deserializeSafe(bytes,persisted));
  assert(persisted.databases.size()==8 && mothershipTidesDBMigrationAllDatabasesSwapped(persisted));
  for(auto& db:persisted.databases) {
    assert(fs::is_directory(str(db.livePath)) && fs::is_directory(str(db.retainedV9Path)) && !fs::exists(str(db.preparedV10Path)));
    assert(execution.validate(db,db.livePath,&failure));
  }
  // A resumed operation must retain each remote database's host authority.
  for(size_t i=0;i<persisted.databases.size();++i) persisted.databases[i].machineUUID=i+100;
  BitseryEngine::serialize(bytes,persisted);
  MothershipTidesDBMigrationReceipt roundtrip;
  assert(BitseryEngine::deserializeSafe(bytes,roundtrip));
  for(size_t i=0;i<roundtrip.databases.size();++i) assert(roundtrip.databases[i].machineUUID==i+100);
  String stop; mothershipBuildTidesDBMigrationServiceQuiesceCommand(stop);
  assert(str(stop).find("systemctl stop prodigy")!=std::string::npos);
  execution.run(0,"bash -n -c "+quote(quiesceServiceCommand()));
  assert(str(stop).find("cgroup.kill")==std::string::npos && str(stop).find("pkill")==std::string::npos);
  // A reply can be lost after an action reaches its postcondition but before
  // the operation marker is durable.  Reentry must reconcile that state and
  // seal it without repeating the action.
  const auto recoveryRoot=(root/"remote-recovery").string();
  fs::create_directory(recoveryRoot); ::chmod(recoveryRoot.c_str(),0700);
  fs::create_directory(fs::path(recoveryRoot)/"target-runtime");
  const auto effect=(root/"effect").string();
  const auto binding=std::string(64,'b');
  const auto reconcile=remoteRecoveryAttestedCommand(recoveryRoot,binding,"fenced",
      "test ! -e "+quote(effect),"test -f "+quote(effect),"false");
  if (::geteuid() == 0) {
    // Publication interrupted after source retention and during target copy:
    // preserve the partial evidence, publish only a complete immutable stage,
    // then accept a second invocation without replacing the live directory.
    const auto publication=root/"publication";
    fs::create_directories(publication/"staged"); fs::create_directory(publication/"retained");
    fs::create_directory(publication/"live.migration-new"); fs::create_directory(publication/"bin");
    { std::ofstream output(publication/"staged/prodigy"); output << "new-runtime"; }
    { std::ofstream output(publication/"staged/complete"); output << "complete"; }
    { std::ofstream output(publication/"retained/prodigy"); output << "old-runtime"; }
    { std::ofstream output(publication/"live.migration-new/partial"); output << "interrupted"; }
    { std::ofstream output(publication/"bin/systemctl"); output << "#!/bin/sh\nprintf '0\\n'\n"; }
    ::chmod((publication/"bin/systemctl").c_str(),0700);
    String oldSHA={},newSHA={};
    assert(prodigyComputeFileSHA256Hex(text((publication/"retained/prodigy").string()),oldSHA,&failure));
    assert(prodigyComputeFileSHA256Hex(text((publication/"staged/prodigy").string()),newSHA,&failure));
    const auto publish=retainedRuntimePublicationCommand((publication/"live").string(),
        (publication/"staged").string(),(publication/"retained").string(),str(oldSHA),std::string(64,'a'),str(newSHA));
    execution.run(0,"export PATH="+quote((publication/"bin").string())+":$PATH; "+publish);
    assert(read(publication/"live/prodigy")=="new-runtime" && fs::exists(publication/"live/complete") &&
           !fs::exists(publication/"live/partial") && !fs::exists(publication/"live.migration-new"));
    unsigned preserved=0;
    for(const auto& entry:fs::directory_iterator(publication))
      if(entry.path().filename().string().starts_with("retained.interrupted-copy.")) {
        assert(read(entry.path()/"runtime/partial")=="interrupted"); ++preserved;
      }
    assert(preserved==1);
    execution.run(0,"export PATH="+quote((publication/"bin").string())+":$PATH; "+publish);
    execution.run(0,"touch "+quote(effect)+"; "+reconcile);
    assert(read(recoveryRoot+"/remote-recovery-fenced")==binding);
    // A first fence probe has no writers-fenced file yet.  Its strict child
    // must return false to the enclosing `if`, which then performs the action
    // exactly once rather than treating that expected predicate miss as fatal.
    const auto fenceRoot=(root/"runtime-fence").string(), fenceDropins=(root/"unit-dropins").string();
    const auto fenceBin=root/"fence-bin";
    const auto fenceAction=(root/"fence-action").string(), hostile=(root/"hostile-bash-env").string();
    fs::create_directories(fenceRoot); fs::create_directories(fenceBin); ::chmod(fenceRoot.c_str(),0700);
    const auto fencePath=fenceRoot+"/writers-fenced", dropin=runtimeStartupFenceDropinPath(binding,fenceDropins);
    const auto reloaded=(root/"daemon-reloaded").string();
    const auto writeExecutable = [](const fs::path& path,const std::string& script) {
      std::ofstream output(path); output << script; output.close(); ::chmod(path.c_str(),0700);
    };
    writeExecutable(fenceBin/"systemctl", "#!/bin/sh\nif test \"$1\" = daemon-reload; then : > "+quote(reloaded)+"; exit 0; fi\n"
        "if test \"$1\" = show; then dropin=\"${FAKE_DROPIN:-"+dropin+"}\"; case \"$*\" in *DropInPaths*) test -f \"$dropin\" && printf '%s\\n' \"$dropin\";; *NeedDaemonReload*) test -e "+quote(reloaded)+" && printf 'no\\n' || printf 'yes\\n';; *Restart*) if test \"${FAKE_RESTART+x}\" = x; then printf '%s\\n' \"$FAKE_RESTART\"; elif test -f \"$dropin\"; then printf 'no\\n'; else printf 'always\\n'; fi;; *) exit 1;; esac; exit 0; fi\nexit 1\n");
    const auto busctlJSON = [&](const std::string& trigger,const std::string& negate,const std::string& path) {
      return "{\"type\":\"a(sbbsi)\",\"data\":[[\"ConditionPathExists\","+trigger+","+negate+",\""+path+"\",0]]}";
    };
    writeExecutable(fenceBin/"busctl", "#!/bin/sh\ncase \"${FAKE_CONDITION_MODE:-positive}\" in positive) printf '%s\\n' "+quote(busctlJSON("false","true",fencePath))+";; negatedwrong) printf '%s\\n' "+quote(busctlJSON("false","false",fencePath))+";; triggered) printf '%s\\n' "+quote(busctlJSON("true","true",fencePath))+";; resetmissing) printf '%s\\n' '{\"type\":\"a(sbbsi)\",\"data\":[]}' ;; *) exit 1;; esac\n");
    { std::ofstream output(hostile); output << ": \"$PS1\"\n"; }
    const auto fencePredicate=runtimeStartupFencePredicate(fenceRoot,binding,fenceDropins,true);
    assert(runtimeStartupFenceCommand(fenceRoot,binding,fenceDropins).find("Restart=no")==std::string::npos);
    assert(runtimeStartupFenceCommand(fenceRoot,binding,fenceDropins,true).find("Restart=no")!=std::string::npos);
    const auto fenceCommand=remoteRecoveryAttestedCommand(fenceRoot,binding,"fence",
        "test ! -e "+quote(fenceAction),fencePredicate,"printf x > "+quote(fenceAction)+"; "+runtimeStartupFenceCommand(fenceRoot,binding,fenceDropins,true));
    assert(fenceCommand.size() < 30976);
    execution.run(0,"BASH_ENV="+quote(hostile)+" FAKE_RESTART=no PATH="+quote(fenceBin.string())+":$PATH "+fenceCommand);
    assert(read(fenceAction)=="x" && read(fenceRoot+"/remote-recovery-fence")==binding);
    execution.run(0,"BASH_ENV="+quote(hostile)+" FAKE_RESTART=no PATH="+quote(fenceBin.string())+":$PATH "+fenceCommand);
    assert(read(fenceAction)=="x");
    assert(!execution.command(0,"FAKE_RESTART=always PATH="+quote(fenceBin.string())+":$PATH "+remoteRecoveryStrictShell(fencePredicate),&failure));
    for (const auto mode:{"negatedwrong","triggered","resetmissing"})
      assert(!execution.command(0,"FAKE_CONDITION_MODE="+quote(mode)+" FAKE_RESTART=no PATH="+quote(fenceBin.string())+":$PATH "+remoteRecoveryStrictShell(fencePredicate),&failure));
    assert(execution.command(0,"FAKE_RESTART=no PATH="+quote(fenceBin.string())+":$PATH "+remoteRecoveryStrictShell(fencePredicate),&failure));
    { std::ofstream output(dropin); output << "altered"; }
    ::chmod(dropin.c_str(),0600);
    assert(!execution.command(0,"FAKE_RESTART=no PATH="+quote(fenceBin.string())+":$PATH "+remoteRecoveryStrictShell(fencePredicate),&failure));
    { std::ofstream output(dropin); output << "[Unit]\nConditionPathExists=!" << fencePath << "\n[Service]\nRestart=no\n"; }
    ::chmod(dropin.c_str(),0600);
    assert(execution.command(0,"FAKE_RESTART=no PATH="+quote(fenceBin.string())+":$PATH "+remoteRecoveryStrictShell(fencePredicate),&failure));
    const auto unfence=runtimeStartupUnfenceCommand(fenceRoot,binding,fenceDropins,true);
    const auto unfencePredicate=runtimeStartupUnfencePredicate(fenceRoot,binding,fenceDropins,true);
    execution.run(0,"PATH="+quote(fenceBin.string())+":$PATH "+remoteRecoveryStrictShell(unfence));
    assert(!fs::exists(fencePath) && !fs::exists(dropin));
    assert(fs::exists(fenceRoot+"/writers-fenced.released") &&
           fs::exists(fenceRoot+"/startup-fence-"+binding.substr(0,16)+".conf.released"));
    assert(execution.command(0,"PATH="+quote(fenceBin.string())+":$PATH "+remoteRecoveryStrictShell("test \"$(systemctl show -p Restart --value prodigy)\" = always"),&failure));
    assert(execution.command(0,"PATH="+quote(fenceBin.string())+":$PATH "+remoteRecoveryStrictShell(unfencePredicate),&failure));
    execution.run(0,"PATH="+quote(fenceBin.string())+":$PATH "+remoteRecoveryStrictShell(unfence));
    assert(!execution.command(0,"PATH="+quote(fenceBin.string())+":$PATH "+
        remoteRecoveryStrictShell(runtimeStartupUnfenceCommand(fenceRoot,std::string(64,'c'),fenceDropins,true)),&failure));
    { std::ofstream output(fenceRoot+"/startup-fence-"+binding.substr(0,16)+".conf.released"); output << "altered"; }
    ::chmod((fenceRoot+"/startup-fence-"+binding.substr(0,16)+".conf.released").c_str(),0600);
    assert(!execution.command(0,"PATH="+quote(fenceBin.string())+":$PATH "+remoteRecoveryStrictShell(unfencePredicate),&failure));
    // An SSH disconnect can happen after either rename but before reload.
    // Each partial, exact pair must converge rather than becoming unreleasable.
    const auto partialFence = [&](const std::string& name, bool moveFence) {
      const auto partialRoot=(root/name).string(), partialDropins=(root/(name+"-dropins")).string();
      const auto partialDropin=runtimeStartupFenceDropinPath(binding,partialDropins);
      fs::create_directories(partialRoot); fs::create_directories(partialDropins); ::chmod(partialRoot.c_str(),0700);
      execution.run(0,"PATH="+quote(fenceBin.string())+":$PATH "+remoteRecoveryStrictShell(runtimeStartupFenceCommand(partialRoot,binding,partialDropins,true)));
      const auto releasedFence=partialRoot+"/writers-fenced.released";
      const auto releasedDropin=partialRoot+"/startup-fence-"+binding.substr(0,16)+".conf.released";
      if (moveFence) execution.run(0,"mv -T "+quote(partialRoot+"/writers-fenced")+" "+quote(releasedFence));
      else execution.run(0,"mv -T "+quote(partialDropin)+" "+quote(releasedDropin));
      fs::remove(reloaded);
      execution.run(0,"FAKE_DROPIN="+quote(partialDropin)+" PATH="+quote(fenceBin.string())+":$PATH "+
          remoteRecoveryStrictShell(runtimeStartupUnfenceCommand(partialRoot,binding,partialDropins,true)));
      assert(execution.command(0,"FAKE_DROPIN="+quote(partialDropin)+" PATH="+quote(fenceBin.string())+":$PATH "+
          remoteRecoveryStrictShell(runtimeStartupUnfencePredicate(partialRoot,binding,partialDropins,true)),&failure));
    };
    partialFence("unfence-after-first-move",false);
    // Both paths moved but daemon-reload not reached: final reconciliation
    // must reload and validate the retained pair, not treat it as terminal.
    const auto bothRoot=(root/"unfence-before-reload").string(), bothDropins=(root/"unfence-before-reload-dropins").string();
    const auto bothDropin=runtimeStartupFenceDropinPath(binding,bothDropins);
    fs::create_directories(bothRoot); fs::create_directories(bothDropins); ::chmod(bothRoot.c_str(),0700);
    execution.run(0,"PATH="+quote(fenceBin.string())+":$PATH "+remoteRecoveryStrictShell(runtimeStartupFenceCommand(bothRoot,binding,bothDropins,true)));
    execution.run(0,"mv -T "+quote(bothDropin)+" "+quote(bothRoot+"/startup-fence-"+binding.substr(0,16)+".conf.released")+
        "; mv -T "+quote(bothRoot+"/writers-fenced")+" "+quote(bothRoot+"/writers-fenced.released"));
    fs::remove(reloaded);
    execution.run(0,"FAKE_DROPIN="+quote(bothDropin)+" PATH="+quote(fenceBin.string())+":$PATH "+
        remoteRecoveryStrictShell(runtimeStartupUnfenceCommand(bothRoot,binding,bothDropins,true)));
    assert(execution.command(0,"FAKE_DROPIN="+quote(bothDropin)+" PATH="+quote(fenceBin.string())+":$PATH "+
        remoteRecoveryStrictShell(runtimeStartupUnfencePredicate(bothRoot,binding,bothDropins,true)),&failure));
    const auto sourceRejected=remoteRecoveryAttestedCommand(fenceRoot,binding,"source-rejected","false",
        "false","touch "+quote(fenceAction+".unexpected"));
    assert(!execution.command(0,"PATH="+quote(fenceBin.string())+":$PATH "+sourceRejected,&failure));
    assert(!fs::exists(fenceAction+".unexpected") && !fs::exists(fenceRoot+"/remote-recovery-source-rejected"));
    const auto replay=remoteRecoveryAttestedCommand(recoveryRoot,binding,"fenced",
        "false","test -f "+quote(effect),"false");
    execution.run(0,replay);
    fs::remove(fs::path(recoveryRoot)/"remote-recovery-fenced");
    { std::ofstream bad(recoveryRoot+"/remote-recovery-fenced"); bad << std::string(64,'c'); }
    ::chmod((recoveryRoot+"/remote-recovery-fenced").c_str(),0600);
    assert(!execution.command(0,remoteRecoveryAttestedCommand(recoveryRoot,binding,"fenced",
        "false","test -f "+quote(effect),"false"),&failure));
    assert(fs::exists(effect));
    assert(!execution.command(0,remoteRecoveryAttestedCommand(recoveryRoot,binding,"invalid-predicate",
        "false", "false; true;", "touch "+quote(effect+".unexpected")),&failure));
    assert(!fs::exists(effect+".unexpected") &&
           !fs::exists(recoveryRoot+"/remote-recovery-invalid-predicate"));
    const auto pending=recoveryRoot+"/remote-recovery-pending.new";
    { std::ofstream output(pending); output << binding; }
    ::chmod(pending.c_str(),0600);
    execution.run(0,remoteRecoveryAttestedCommand(recoveryRoot,binding,"pending",
        "false","test -f "+quote(effect),"false"));
    assert(!fs::exists(pending) && read(recoveryRoot+"/remote-recovery-pending")==binding);
    for (const auto suffix:{"dangling", "dangling-new.new"})
      fs::create_symlink(root/"missing-target",fs::path(recoveryRoot)/(std::string("remote-recovery-")+suffix));
    for (const auto phase:{"dangling", "dangling-new"})
      assert(!execution.command(0,remoteRecoveryAttestedCommand(recoveryRoot,binding,phase,
          "false","test -f "+quote(effect),"false"),&failure));
    assert(!fs::exists(root/"missing-target"));
    const auto invalidMarker=remoteRecoveryAttestedCommand(recoveryRoot,binding,"fenced",
        "false","test -f "+quote(effect),"false");
    assert(!execution.command(0,"bash -c "+quote(invalidMarker),&failure));
    const auto lock=recoveryRoot+"/remote-recovery-effect.lock";
    const int lockFD=::open(lock.c_str(),O_RDWR|O_CLOEXEC);
    assert(lockFD>=0 && ::flock(lockFD,LOCK_EX|LOCK_NB)==0);
    const auto held=remoteRecoveryAttestedCommand(recoveryRoot,binding,"locked",
        "test ! -e "+quote(effect+".locked"),"test -f "+quote(effect+".locked"),"touch "+quote(effect+".locked"));
    assert(!execution.command(0,held,&failure));
    assert(!fs::exists(effect+".locked"));
    ::flock(lockFD,LOCK_UN); ::close(lockFD);
    fs::remove(lock);
    fs::create_symlink(root/"missing-lock",lock);
    assert(!execution.command(0,remoteRecoveryAttestedCommand(recoveryRoot,binding,"unsafe-lock",
        "false","test -f "+quote(effect),"false"),&failure));
    assert(!fs::exists(root/"missing-lock"));
    fs::remove(lock);
  }
  // cgroup pseudo-files cannot be tested with -s: their st_size is zero even
  // when populated.  The helpers deliberately wait on the kernel events.
  const auto frozen=remoteRecoveryCgroupFrozenPredicate("/sys/fs/cgroup/test");
  const auto empty=remoteRecoveryCgroupUnpopulatedPredicate("/sys/fs/cgroup/test");
  assert(frozen.find("cgroup.events")!=std::string::npos && frozen.find("frozen")!=std::string::npos);
  assert(empty.find("cgroup.events")!=std::string::npos && empty.find("populated")!=std::string::npos);
  assert(remoteRecoveryFreezeCgroupCommand("/sys/fs/cgroup/test").find("cgroup.freeze")!=std::string::npos);
  const auto kill=remoteRecoveryKillFrozenCgroupCommand("/sys/fs/cgroup/test");
  assert(kill.find("cgroup.kill")!=std::string::npos && kill.find("cgroup.procs")==std::string::npos);
  execution.run(0,"bash -n -c "+quote(remoteRecoveryFreezeCgroupCommand("/sys/fs/cgroup/test")));
  execution.run(0,"bash -n -c "+quote(kill));
  assert(uuid("0x850fa69cddf33ccdb965f709303710c6")!=0);
  bool rejected=false; try { pathCheck("/var/lib/../prod"); } catch(const std::exception&) { rejected=true; } assert(rejected);
  MothershipProdigyCluster registeredCluster;
  MothershipProdigyClusterMachine adopted; adopted.isBrain=true;
  adopted.ssh.address="fd72:6e61:6d65:1::10"_ctv; adopted.ssh.port=22;
  adopted.ssh.user="root"_ctv; adopted.ssh.hostPublicKeyOpenSSH="fixture-host-key"_ctv;
  registeredCluster.machines.push_back(adopted);
  ClusterMachine topology; mothershipFillAdoptedClusterMachine(adopted,topology); topology.uuid=123;
  registeredCluster.topology.machines.push_back(topology);
  Machine planned; planned.uuid=123; planned.address="fd72:6e61:6d65:1::10";
  resolveRegisteredMachine(registeredCluster,planned);
  assert(planned.registered.ssh.hostPublicKeyOpenSSH==adopted.ssh.hostPublicKeyOpenSSH);
  registeredCluster.topology.machines[0].uuid=124;
  rejected=false; try { resolveRegisteredMachine(registeredCluster,planned); } catch(const std::exception&) { rejected=true; } assert(rejected);
  registeredCluster.topology.machines[0].uuid=123;
  registeredCluster.machines[0].uuid=124;
  rejected=false; try { resolveRegisteredMachine(registeredCluster,planned); } catch(const std::exception&) { rejected=true; } assert(rejected);
  fs::remove_all(root);
}
