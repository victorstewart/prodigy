if (NOT DEFINED PRODIGY_ROOT)
   message(FATAL_ERROR "PRODIGY_ROOT is required")
endif()

file(READ "${PRODIGY_ROOT}/prodigy/iaas/iaas.h" IAAS)
file(READ "${PRODIGY_ROOT}/prodigy/iaas/gcp/gcp.h" GCP)
file(READ "${PRODIGY_ROOT}/prodigy/mothership/mothership.cpp" MOTHERSHIP)
file(READ "${PRODIGY_ROOT}/prodigy/mothership/mothership.provider.credentials.h" CREDENTIALS)

foreach(REQUIRED IN ITEMS
   "virtual void inferMachineSchemaCpuCapability(CoroutineStack *coro"
   "virtual void preflightClusterCreate(CoroutineStack *coro"
   "validationResponseBytes = 1024 * 1024"
   "compute.googleapis.com"
   "cloudresourcemanager.googleapis.com"
   "iam.googleapis.com"
   "request.connectTimeout = std::chrono::seconds(3)"
   "std::chrono::seconds(3) : std::chrono::seconds(8)"
   "request.responseBytes = validationResponseBytes"
   "validationMachineCapabilities.find"
   "validationZoneCpuPlatformsReady"
   "co_await resolveRefreshableBootstrapAccessToken(coro, failure)")
   string(FIND "${IAAS}${GCP}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "GCP validation contract missing: ${REQUIRED}")
   endif()
endforeach()

string(FIND "${GCP}" "static void assignValidationRequestFailure" VALIDATION_START)
string(FIND "${GCP}" "void prepareManagedInstanceTemplates" VALIDATION_END)
math(EXPR VALIDATION_LENGTH "${VALIDATION_END} - ${VALIDATION_START}")
string(SUBSTRING "${GCP}" ${VALIDATION_START} ${VALIDATION_LENGTH} VALIDATION)
foreach(FORBIDDEN IN ITEMS "GcpHttp" "sendElasticComputeRequest" "popen" "usleep")
   string(FIND "${VALIDATION}" "${FORBIDDEN}" OFFSET)
   if (NOT OFFSET EQUAL -1)
      message(FATAL_ERROR "GCP validation retains blocking transport: ${FORBIDDEN}")
   endif()
endforeach()

string(FIND "${MOTHERSHIP}" "bool runGcpClusterValidation" JOB_START)
string(FIND "${MOTHERSHIP}" "bool inferClusterMachineSchemaCpuCapabilities(MothershipProdigyCluster& cluster" JOB_END)
math(EXPR JOB_LENGTH "${JOB_END} - ${JOB_START}")
string(SUBSTRING "${MOTHERSHIP}" ${JOB_START} ${JOB_LENGTH} JOB)
foreach(REQUIRED IN ITEMS
   "std::chrono::seconds(30) : std::chrono::seconds(15)"
   "sourceEnvironment.kind = ProdigyEnvironmentKind::gcp"
   "*credential, sourceEnvironment, jobEnvironment, &failure, deadline"
   "services.operationDeadline = deadline"
   "prodigyCreateProviderBrainIaaS(jobEnvironment, services)"
   "inferClusterMachineSchemaCpuCapabilities(*provider, coro, cluster, capabilities, failure)"
   "preflightClusterProviderCreate(*provider, coro, preflight, failure)")
   string(FIND "${JOB}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "Mothership GCP validation job contract missing: ${REQUIRED}")
   endif()
endforeach()
string(REGEX MATCHALL "prodigyCreateProviderBrainIaaS\\(jobEnvironment, services\\)" FACTORIES "${JOB}")
list(LENGTH FACTORIES FACTORY_COUNT)
if (NOT FACTORY_COUNT EQUAL 1)
   message(FATAL_ERROR "GCP validation must construct exactly one provider per job")
endif()

string(FIND "${MOTHERSHIP}" "bool validateClusterCreate" CREATE_START)
string(FIND "${MOTHERSHIP}" "bool destroyCloudClusterMachines" CREATE_END)
math(EXPR CREATE_LENGTH "${CREATE_END} - ${CREATE_START}")
string(SUBSTRING "${MOTHERSHIP}" ${CREATE_START} ${CREATE_LENGTH} CREATE)
string(FIND "${CREATE}" "runGcpClusterValidation(cluster, credential, true, capabilities, failure)" CREATE_RUN)
string(FIND "${CREATE}" "publishClusterMachineSchemaCpuCapabilities(cluster, capabilities)" CREATE_PUBLISH)
if (CREATE_RUN EQUAL -1 OR CREATE_PUBLISH EQUAL -1 OR CREATE_PUBLISH LESS CREATE_RUN)
   message(FATAL_ERROR "Mothership GCP create must publish only after combined validation succeeds")
endif()
string(FIND "${JOB}" "mothershipBuildClusterProvisioningRuntimeEnvironment" BLOCKING_CONFIG)
if (NOT BLOCKING_CONFIG EQUAL -1)
   message(FATAL_ERROR "GCP validation resolves credential material before its explicit job deadline")
endif()

foreach(REQUIRED IN ITEMS
   "applyCredentialToRuntimeEnvironment(credential, runtimeEnvironment, failure, deadline)"
   "runtimeEnvironment.gcp.bootstrapAccessTokenRefreshCommand")
   string(FIND "${CREDENTIALS}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "GCP validation command quarantine missing: ${REQUIRED}")
   endif()
endforeach()
string(FIND "${CREDENTIALS}" "runtimeEnvironment.gcp.bootstrapAccessTokenRefreshCommand.reset()" QUARANTINE)
if(NOT QUARANTINE EQUAL -1)
   message(FATAL_ERROR "GCP Ring runtime still strips its async credential refresh command")
endif()
