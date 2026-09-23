// Included by prodigy_brain_replication_credentials_unit.cpp after its shared
// fixtures and wire helpers.

template <typename Response>
static bool extractAsyncRequestResponse(String& buffer, MothershipTopic topic, Response& response)
{
  bool found = false;
  forEachMessageInBuffer(buffer, [&](Message *message) {
    if (MothershipTopic(message->topic) != topic) return;
    String serialized;
    uint8_t *args = message->args;
    Message::extractToStringView(args, serialized);
    found = BitseryEngine::deserializeSafe(serialized, response);
  });
  return found;
}

static void configureAsyncRequestBrain(TestSuite& suite, TestBrain& brain, Mothership& mothership)
{
  brain.weAreMaster = true;
  brain.noMasterYet = false;
  brain.holdRuntimePersistence = true;
  mothership.isFixedFile = true;
  mothership.fslot = 12;
  suite.expect(brain.activateMothershipConnection(&mothership), "async_request_activates_mothership");
}

static void testMothershipAsyncRequestDurability(TestSuite& suite)
{
  ScopedRing ring;
  {
    TestBrain brain; Mothership mothership; configureAsyncRequestBrain(suite, brain, mothership);
    ApiCredentialExpiryNotice notice = {};
    notice.stableID = 9001; notice.applicationID = 9; notice.name.assign("token"_ctv);
    notice.provider.assign("unit"_ctv); notice.generation = 1; notice.deadlineMs = 1;
    notice.createdAtMs = 1; notice.severity = ApiCredentialExpirySeverity::warning;
    brain.masterAuthorityRuntimeState.apiCredentialExpiryNotices.push_back(notice);
    ApiCredentialExpiryNoticePayload acknowledgement = {};
    acknowledgement.clusterUUID = brain.brainConfig.clusterUUID; acknowledgement.notice = notice;
    acknowledgement.acknowledge = true;
    String serialized, frame;
    BitseryEngine::serialize(serialized, acknowledgement);
    brain.mothershipHandler(&mothership, buildMothershipMessage(frame, MothershipTopic::credentialExpiryNotices, serialized));
    suite.expect(brain.masterAuthorityRuntimeState.apiCredentialExpiryNotices[0].acknowledged &&
                     brain.pendingRuntimePersistence.size() == 1,
                 "async_credential_notice_ack_holds_durable_receipt");
    brain.finishRuntimePersistence(false);
    suite.expect(!brain.masterAuthorityRuntimeState.apiCredentialExpiryNotices[0].acknowledged,
                 "async_credential_notice_ack_failure_restores_candidate");
  }
  auto reserveApplication = [](TestBrain& brain, Mothership& mothership, const String& name, uint16_t id) {
    ApplicationIDReserveRequest request = {};
    request.applicationName.assign(name);
    request.requestedApplicationID = id;
    String serialized, frame;
    BitseryEngine::serialize(serialized, request);
    brain.mothershipHandler(&mothership, buildMothershipMessage(frame, MothershipTopic::reserveApplicationID, serialized));
  };
  auto reserveService = [](TestBrain& brain, Mothership& mothership, uint16_t appID, const String& name) {
    ApplicationServiceReserveRequest request = {};
    request.applicationID = appID;
    request.serviceName.assign(name);
    request.kind = ApplicationServiceIdentity::Kind::stateless;
    String serialized, frame;
    BitseryEngine::serialize(serialized, request);
    brain.mothershipHandler(&mothership, buildMothershipMessage(frame, MothershipTopic::reserveServiceID, serialized));
  };
  auto upsertCredential = [](TestBrain& brain, Mothership& mothership, uint16_t appID, const String& material) {
    ApiCredentialSetUpsertRequest request = {};
    request.applicationID = appID;
    ApiCredential credential = {};
    credential.name.assign("token"_ctv);
    credential.provider.assign("unit"_ctv);
    credential.material.assign(material);
    request.upsertCredentials.push_back(std::move(credential));
    String serialized, frame;
    BitseryEngine::serialize(serialized, request);
    brain.mothershipHandler(&mothership, buildMothershipMessage(frame, MothershipTopic::upsertApiCredentialSet, serialized));
  };
  {
    TestBrain brain; Mothership mothership; configureAsyncRequestBrain(suite, brain, mothership);
    ApplicationTlsVaultFactory factory = {}; String failure = {};
    suite.require(generateApplicationTlsFactory(factory, failure, CryptoScheme::p256), "async_tls_factory_fixture");
    TlsVaultFactoryUpsertRequest request = {};
    request.applicationID = 53'900; request.mode = 1; request.scheme = uint8_t(CryptoScheme::p256);
    request.importRootCertPem = factory.rootCertPem; request.importRootKeyPem = factory.rootKeyPem;
    request.importIntermediateCertPem = factory.intermediateCertPem; request.importIntermediateKeyPem = factory.intermediateKeyPem;
    String serialized, frame; BitseryEngine::serialize(serialized, request);
    brain.mothershipHandler(&mothership, buildMothershipMessage(frame, MothershipTopic::upsertTlsVaultFactory, serialized));
    suite.expect(mothership.wBuffer.empty() && brain.pendingRuntimePersistence.size() == 1,
                 "async_tls_factory_holds_success_until_receipt");
    brain.finishRuntimePersistence(false);
    TlsVaultFactoryUpsertResponse response = {};
    suite.expect(extractAsyncRequestResponse(mothership.wBuffer, MothershipTopic::upsertTlsVaultFactory, response) && !response.success,
                 "async_tls_factory_write_failure_replies_failure");
  }
  auto mintClientIdentity = [&](TestBrain& brain, Mothership& mothership, uint16_t appID) {
    ClientTlsMintRequest request = {};
    request.applicationID = appID; request.name.assign("async-client"_ctv);
    request.subjectCommonName.assign("async-client"_ctv);
    String serialized, frame; BitseryEngine::serialize(serialized, request);
    brain.mothershipHandler(&mothership, buildMothershipMessage(frame, MothershipTopic::mintClientTlsIdentity, serialized));
  };
  auto installMintFactory = [&](TestBrain& brain, uint16_t appID) {
    ApplicationTlsVaultFactory factory = {}; String failure = {};
    suite.require(generateApplicationTlsFactory(factory, failure, CryptoScheme::p256), "async_mint_tls_factory_fixture");
    factory.applicationID = appID; factory.factoryGeneration = 1; factory.defaultLeafValidityDays = 1;
    brain.tlsVaultFactoriesByApp.insert_or_assign(appID, std::move(factory));
  };
  {
    TestBrain brain; Mothership mothership; configureAsyncRequestBrain(suite, brain, mothership);
    installMintFactory(brain, 53'901); mintClientIdentity(brain, mothership, 53'901);
    suite.expect(mothership.wBuffer.empty() && brain.pendingRuntimePersistence.size() == 1,
                 "async_mint_client_tls_holds_success_until_receipt");
    brain.finishRuntimePersistence(true);
    ClientTlsMintResponse response = {};
    suite.expect(extractAsyncRequestResponse(mothership.wBuffer, MothershipTopic::mintClientTlsIdentity, response) && response.success,
                 "async_mint_client_tls_replies_after_durable_success");
  }
  {
    TestBrain brain; Mothership mothership; configureAsyncRequestBrain(suite, brain, mothership);
    installMintFactory(brain, 53'902); const uint64_t before = brain.nextMintedClientTlsGeneration;
    mintClientIdentity(brain, mothership, 53'902); brain.finishRuntimePersistence(false);
    ClientTlsMintResponse response = {};
    suite.expect(extractAsyncRequestResponse(mothership.wBuffer, MothershipTopic::mintClientTlsIdentity, response) && !response.success &&
                     brain.nextMintedClientTlsGeneration == before,
                 "async_mint_client_tls_failure_rolls_back_generation");
  }
  {
    TestBrain brain; Mothership mothership; configureAsyncRequestBrain(suite, brain, mothership);
    installMintFactory(brain, 53'903); mintClientIdentity(brain, mothership, 53'903);
    ++brain.masterAuthorityEpoch; brain.finishRuntimePersistence(true);
    suite.expect(mothership.wBuffer.empty(), "async_mint_client_tls_stale_authority_suppresses_reply");
  }

  {
    TestBrain brain; Mothership mothership; configureAsyncRequestBrain(suite, brain, mothership);
    reserveApplication(brain, mothership, "AsyncAppSuccess"_ctv, 54'001);
    suite.expect(mothership.wBuffer.empty() && brain.pendingRuntimePersistence.size() == 1,
                 "async_application_holds_success_until_durable_receipt");
    reserveApplication(brain, mothership, "AsyncAppSuccess"_ctv, 54'001);
    ApplicationIDReserveResponse pendingResponse = {};
    suite.expect(extractAsyncRequestResponse(mothership.wBuffer, MothershipTopic::reserveApplicationID, pendingResponse) &&
                     !pendingResponse.success && pendingResponse.failure.equal("application reservation durability pending; retry"_ctv) &&
                     brain.pendingRuntimePersistence.size() == 1,
                 "async_application_duplicate_rejects_undurable_candidate");
    mothership.wBuffer.clear();
    brain.finishRuntimePersistence(true);
    ApplicationIDReserveResponse response = {};
    suite.expect(extractAsyncRequestResponse(mothership.wBuffer, MothershipTopic::reserveApplicationID, response) &&
                     response.success && response.created && response.applicationID == 54'001,
                 "async_application_replies_success_after_durable_receipt");
  }
  {
    TestBrain brain; Mothership mothership; configureAsyncRequestBrain(suite, brain, mothership);
    reserveApplication(brain, mothership, "AsyncAppFailure"_ctv, 54'002);
    brain.finishRuntimePersistence(false);
    ApplicationIDReserveResponse response = {};
    suite.expect(extractAsyncRequestResponse(mothership.wBuffer, MothershipTopic::reserveApplicationID, response) &&
                     !response.success && !brain.reservedApplicationIDsByName.contains("AsyncAppFailure"_ctv),
                 "async_application_write_failure_restores_candidate");
  }
  {
    TestBrain brain; Mothership mothership; configureAsyncRequestBrain(suite, brain, mothership);
    reserveApplication(brain, mothership, "AsyncAppDisconnect"_ctv, 54'003);
    brain.activeMotherships.erase(&mothership); brain.finishRuntimePersistence(true);
    suite.expect(mothership.wBuffer.empty() && brain.reservedApplicationIDsByName.contains("AsyncAppDisconnect"_ctv),
                 "async_application_disconnect_suppresses_reply_after_durability");
  }
  {
    TestBrain brain; Mothership mothership; configureAsyncRequestBrain(suite, brain, mothership);
    reserveApplication(brain, mothership, "AsyncAppAuthority"_ctv, 54'004);
    ++brain.masterAuthorityEpoch; brain.finishRuntimePersistence(false);
    suite.expect(mothership.wBuffer.empty() && brain.reservedApplicationIDsByName.contains("AsyncAppAuthority"_ctv),
                 "async_application_authority_change_does_not_stale_rollback");
  }

  {
    TestBrain brain; Mothership mothership; configureAsyncRequestBrain(suite, brain, mothership);
    brain.reserveApplicationIDMapping("AsyncServiceApp"_ctv, 54'010);
    reserveService(brain, mothership, 54'010, "success"_ctv);
    suite.expect(mothership.wBuffer.empty() && brain.pendingRuntimePersistence.size() == 1,
                 "async_service_holds_success_until_durable_receipt");
    reserveService(brain, mothership, 54'010, "duplicate"_ctv);
    ApplicationServiceReserveResponse pendingResponse = {};
    suite.expect(extractAsyncRequestResponse(mothership.wBuffer, MothershipTopic::reserveServiceID, pendingResponse) &&
                     !pendingResponse.success && pendingResponse.failure.equal("service reservation durability pending; retry"_ctv) &&
                     brain.pendingRuntimePersistence.size() == 1,
                 "async_service_duplicate_rejects_undurable_candidate");
    mothership.wBuffer.clear();
    brain.finishRuntimePersistence(true);
    ApplicationServiceReserveResponse response = {};
    suite.expect(extractAsyncRequestResponse(mothership.wBuffer, MothershipTopic::reserveServiceID, response) && response.success && response.created,
                 "async_service_replies_success_after_durable_receipt");
  }
  {
    TestBrain brain; Mothership mothership; configureAsyncRequestBrain(suite, brain, mothership);
    brain.reserveApplicationIDMapping("AsyncServiceApp"_ctv, 54'011);
    reserveService(brain, mothership, 54'011, "failure"_ctv); brain.finishRuntimePersistence(false);
    ApplicationServiceIdentity identity = {};
    suite.expect(!brain.resolveReservedApplicationService(54'011, "failure"_ctv, identity),
                 "async_service_write_failure_restores_candidate");
  }
  {
    TestBrain brain; Mothership mothership; configureAsyncRequestBrain(suite, brain, mothership);
    brain.reserveApplicationIDMapping("AsyncServiceApp"_ctv, 54'012);
    reserveService(brain, mothership, 54'012, "disconnect"_ctv); brain.activeMotherships.erase(&mothership); brain.finishRuntimePersistence(true);
    ApplicationServiceIdentity identity = {};
    suite.expect(mothership.wBuffer.empty() && brain.resolveReservedApplicationService(54'012, "disconnect"_ctv, identity),
                 "async_service_disconnect_suppresses_reply_after_durability");
  }
  {
    TestBrain brain; Mothership mothership; configureAsyncRequestBrain(suite, brain, mothership);
    brain.reserveApplicationIDMapping("AsyncServiceApp"_ctv, 54'013);
    reserveService(brain, mothership, 54'013, "authority"_ctv); ++brain.masterAuthorityEpoch; brain.finishRuntimePersistence(false);
    ApplicationServiceIdentity identity = {};
    suite.expect(mothership.wBuffer.empty() && brain.resolveReservedApplicationService(54'013, "authority"_ctv, identity),
                 "async_service_authority_change_does_not_stale_rollback");
  }

  {
    TestBrain brain; Mothership mothership; configureAsyncRequestBrain(suite, brain, mothership);
    upsertCredential(brain, mothership, 54'020, "success"_ctv);
    suite.expect(mothership.wBuffer.empty() && brain.pendingRuntimePersistence.size() == 1,
                 "async_credential_holds_success_until_durable_receipt");
    upsertCredential(brain, mothership, 54'020, "duplicate"_ctv);
    ApiCredentialSetUpsertResponse pendingResponse = {};
    suite.expect(extractAsyncRequestResponse(mothership.wBuffer, MothershipTopic::upsertApiCredentialSet, pendingResponse) &&
                     !pendingResponse.success && pendingResponse.failure.equal("api credential durability pending; retry"_ctv) &&
                     brain.pendingRuntimePersistence.size() == 1,
                 "async_credential_duplicate_rejects_undurable_candidate");
    mothership.wBuffer.clear();
    brain.finishRuntimePersistence(true);
    ApiCredentialSetUpsertResponse response = {};
    suite.expect(extractAsyncRequestResponse(mothership.wBuffer, MothershipTopic::upsertApiCredentialSet, response) && response.success && response.setGeneration == 1,
                 "async_credential_replies_success_after_durable_receipt");
  }
  {
    TestBrain brain; Mothership mothership; configureAsyncRequestBrain(suite, brain, mothership);
    upsertCredential(brain, mothership, 54'021, "failure"_ctv); brain.finishRuntimePersistence(false);
    suite.expect(!brain.apiCredentialSetsByApp.contains(54'021), "async_credential_write_failure_restores_candidate");
  }
  {
    TestBrain brain; Mothership mothership; configureAsyncRequestBrain(suite, brain, mothership);
    upsertCredential(brain, mothership, 54'022, "disconnect"_ctv); brain.activeMotherships.erase(&mothership); brain.finishRuntimePersistence(true);
    suite.expect(mothership.wBuffer.empty() && brain.apiCredentialSetsByApp.contains(54'022),
                 "async_credential_disconnect_suppresses_reply_after_durability");
  }
  {
    TestBrain brain; Mothership mothership; configureAsyncRequestBrain(suite, brain, mothership);
    upsertCredential(brain, mothership, 54'023, "authority"_ctv); ++brain.masterAuthorityEpoch; brain.finishRuntimePersistence(false);
    suite.expect(mothership.wBuffer.empty() && brain.apiCredentialSetsByApp.contains(54'023),
                 "async_credential_authority_change_does_not_stale_rollback");
  }
}
