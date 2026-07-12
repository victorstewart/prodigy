if (NOT DEFINED PRODIGY_ROOT)
   message(FATAL_ERROR "PRODIGY_ROOT is required")
endif()

file(READ "${PRODIGY_ROOT}/prodigy/iaas/gcp/gcp.provisioning.h" TRANSACTION)
file(READ "${PRODIGY_ROOT}/prodigy/iaas/gcp/gcp.h" PROVIDER)
file(READ "${PRODIGY_ROOT}/prodigy/iaas/gcp/gcp.cpp" PROVIDER_SOURCE)
file(READ "${PRODIGY_ROOT}/prodigy/mothership/mothership.cpp" MOTHERSHIP)
file(READ "${PRODIGY_ROOT}/prodigy/mothership/mothership.cluster.create.h" CLUSTER_CREATE)
file(READ "${PRODIGY_ROOT}/prodigy/host.http.admission.h" ADMISSION)
file(READ "${PRODIGY_ROOT}/prodigy/iaas/iaas.h" PROVIDER_INTERFACE)

foreach(REQUIRED IN ITEMS
   "class GcpMachineProvisioningTransaction final"
   "ProdigyHostHttpBatchOperation"
   "ProdigyHostDelayOperation"
   "maximumMachines = 256"
   "maximumRequestsPerWave = ProdigyHostHttpAdmission::defaultCapacity"
   "maximumObservations = 1200"
   "responseBytes = 1024 * 1024"
   "compute.googleapis.com"
   "MutationState::accepted"
   "MutationState::ambiguous"
   "submitWaves(coro"
   "states[index].mutation == MutationState::accepted"
   "gcp provisioning cloud state may be partial for:")
   string(FIND "${TRANSACTION}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "GCP provisioning transaction contract missing: ${REQUIRED}")
   endif()
endforeach()
foreach(FORBIDDEN IN ITEMS "GcpHttp" "curl_" "usleep" "RefreshCommand" "prodigyMachineSSHSocketAcceptingConnections")
   string(FIND "${TRANSACTION}" "${FORBIDDEN}" OFFSET)
   if (NOT OFFSET EQUAL -1)
      message(FATAL_ERROR "GCP provisioning transaction contains blocking/private path: ${FORBIDDEN}")
   endif()
endforeach()

foreach(REQUIRED IN ITEMS
   "#include <prodigy/iaas/gcp/gcp.provisioning.h>"
   "uint32_t provisioningOperations = 0;"
   "ensureProjectZoneAsync(coro, identityReady, deadline)"
   "ensureTokenAsync(coro, tokenReady, &error, deadline)"
   "GcpMachineProvisioningTransaction transaction("
   "Vector<std::unique_ptr<Machine>> staged"
   "newMachines.insert(machine.release())")
   string(FIND "${PROVIDER}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "GCP provisioning provider cutover missing: ${REQUIRED}")
   endif()
endforeach()
foreach(REMOVED IN ITEMS
   "PendingMachineProvisioning"
   "ConcurrentWaitTask"
   "ConcurrentWaitCoordinator"
   "fetchInstanceByName"
   "fetchInstanceTemplate"
   "appendTemplateBootDiskOverride"
   "waitForInstanceByName"
   "GcpHttp::MultiRequest"
   "GcpHttp::MultiClient")
   string(FIND "${PROVIDER}${PROVIDER_SOURCE}" "${REMOVED}" OFFSET)
   if (NOT OFFSET EQUAL -1)
      message(FATAL_ERROR "obsolete GCP provisioning path remains: ${REMOVED}")
   endif()
endforeach()

string(FIND "${MOTHERSHIP}" "bool createSeedMachine(const MothershipProdigyCluster&" SEED_START)
string(FIND "${MOTHERSHIP}" "bool destroyCreatedSeedMachine(" SEED_END)
math(EXPR SEED_LENGTH "${SEED_END} - ${SEED_START}")
string(SUBSTRING "${MOTHERSHIP}" ${SEED_START} ${SEED_LENGTH} SEED)
foreach(REQUIRED IN ITEMS
   "prepareGcpRingRuntimeEnvironment("
   "owner->hostRuntime.run("
   "services.operationDeadline = deadline"
   "prodigyCreateProviderBrainIaaS(jobEnvironment, services)"
   "mothershipProvisionCreatedSeedMachine(coro,")
   string(FIND "${SEED}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "GCP Ring seed provisioning contract missing: ${REQUIRED}")
   endif()
endforeach()

foreach(REQUIRED IN ITEMS
   "class ProdigyHostHttpAdmission final"
   "defaultCapacity = 64"
   "defaultMaximumQueuedRequests = 256"
   "defaultMaximumQueuedBytes = 64 * 1024 * 1024"
   "entry->request.overallDeadline <= now"
   "result.status = MultiCurlClient::Status::shutdown")
   string(FIND "${ADMISSION}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "shared host HTTP admission contract missing: ${REQUIRED}")
   endif()
endforeach()
string(FIND "${PROVIDER_INTERFACE}" "ProdigyHostHttpSubmission http;" VALUE_HTTP)
string(FIND "${PROVIDER_INTERFACE}" "MultiCurlClient *http" RAW_HTTP)
if (VALUE_HTTP EQUAL -1 OR NOT RAW_HTTP EQUAL -1)
   message(FATAL_ERROR "provider services must carry the admitted HTTP submission by value")
endif()
