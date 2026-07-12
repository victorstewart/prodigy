if (NOT DEFINED PRODIGY_ROOT)
   message(FATAL_ERROR "PRODIGY_ROOT is required")
endif()

file(READ "${PRODIGY_ROOT}/prodigy/iaas/gcp/gcp.managed.template.h" TEMPLATE)
file(READ "${PRODIGY_ROOT}/prodigy/iaas/gcp/gcp.compute.transaction.h" COMPUTE)
file(READ "${PRODIGY_ROOT}/prodigy/mothership/mothership.gcp.managed.template.plan.h" PLAN)
file(READ "${PRODIGY_ROOT}/prodigy/json.h" JSON)
file(READ "${PRODIGY_ROOT}/prodigy/iaas/gcp/gcp.h" GCP)
file(READ "${PRODIGY_ROOT}/prodigy/mothership/mothership.cpp" MOTHERSHIP)
file(READ "${PRODIGY_ROOT}/prodigy/mothership/mothership.cluster.registry.h" REGISTRY)
file(READ "${PRODIGY_ROOT}/prodigy/mothership/mothership.provider.credentials.h" CREDENTIALS)
file(READ "${PRODIGY_ROOT}/prodigy/command.capture.h" COMMAND_CAPTURE)
file(READ "${PRODIGY_ROOT}/prodigy/iaas/gcp/gcp.h" GCP_PROVIDER)
file(READ "${PRODIGY_ROOT}/prodigy/iaas/aws/aws.h" AWS_PROVIDER)
file(READ "${PRODIGY_ROOT}/prodigy/iaas/azure/azure.h" AZURE_PROVIDER)
file(READ "${PRODIGY_ROOT}/prodigy/dns/provider.http.h" DNS_PROVIDER)

foreach(REQUIRED IN ITEMS
   "ProdigyHostHttpOperation::Submission"
   "ProdigyHostDelayOperation::Submission"
   "responseBytes = 1024 * 1024"
   "maximumPolls = 1200"
   "pollDelayUs = 500 * 1000"
   "pollTimeout = std::chrono::minutes(10)"
   "#include <prodigy/iaas/gcp/gcp.compute.transaction.h>"
   "GcpComputeTransaction::request"
   "GcpComputeTransaction::appendPercentEncoded"
   "GcpComputeTransaction::parseOperationName"
   "GcpComputeTransaction::parseOperation"
   "GcpComputeTransaction::submit"
   "GcpComputeTransaction::wait"
   "transaction requires distinct template names")
   string(FIND "${TEMPLATE}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "GCP managed-template module contract missing: ${REQUIRED}")
   endif()
endforeach()

foreach(REQUIRED IN ITEMS
   "class GcpComputeTransaction"
   "static MultiCurlClient::Request request"
   "httpErrorStatusCode"
   "request.originPolicy.requiredHost")
   string(FIND "${COMPUTE}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "shared GCP Compute request contract missing: ${REQUIRED}")
   endif()
endforeach()
foreach(FORBIDDEN IN ITEMS
   "request.connectTimeout"
   "request.originPolicy.requiredHost"
   "ProdigyHostHttpOperation operation"
   "ProdigyHostDelayOperation operation"
   "static void appendPercentEncoded"
   "static bool parseOperationName")
   string(FIND "${TEMPLATE}" "${FORBIDDEN}" OFFSET)
   if (NOT OFFSET EQUAL -1)
      message(FATAL_ERROR "GCP managed-template module duplicates shared Compute mechanics: ${FORBIDDEN}")
   endif()
endforeach()

foreach(REQUIRED IN ITEMS
   "MothershipGcpManagedTemplatePlan"
   "GcpManagedTemplateTransaction::buildSpec"
   "append(standard, false)"
   "append(spot, true)"
   "std::chrono::minutes(25)"
   "std::chrono::minutes(45)"
   "plan = std::move(built)")
   string(FIND "${PLAN}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "Mothership GCP managed-template plan contract missing: ${REQUIRED}")
   endif()
endforeach()

foreach(REQUIRED IN ITEMS
   "maximumOutputBytes = 1024 * 1024"
   "timeout = std::chrono::seconds(30)"
   "pipe2(pipes[0], O_CLOEXEC)"
   "pipe2(pipes[1], O_CLOEXEC)"
   "O_NONBLOCK"
   "prodigyEnsureSigchldDefaultWaitable()"
   "Ring::queueRawFDPoll"
   "Ring::queueWaitid"
   "Ring::queueTimeout"
   "ProdigyHostSuspend"
   "kill(-pid, SIGKILL)"
   "String diagnostic"
   "credential command deadline exceeded")
   string(FIND "${COMMAND_CAPTURE}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "bounded credential command contract missing: ${REQUIRED}")
   endif()
endforeach()
set(CREDENTIAL_COMMAND_SURFACES
    "${COMMAND_CAPTURE}${CREDENTIALS}${GCP_PROVIDER}${AWS_PROVIDER}${AZURE_PROVIDER}${DNS_PROVIDER}")
foreach(FORBIDDEN IN ITEMS "popen" "pclose" "fread" "system(" "poll(" "waitpid(")
   string(FIND "${CREDENTIAL_COMMAND_SURFACES}" "${FORBIDDEN}" OFFSET)
   if (NOT OFFSET EQUAL -1)
      message(FATAL_ERROR "credential command capture retains unbounded execution: ${FORBIDDEN}")
   endif()
endforeach()
string(FIND "${COMMAND_CAPTURE}" "failure->assign(output)" CREDENTIAL_DISCLOSURE)
if (NOT CREDENTIAL_DISCLOSURE EQUAL -1)
   message(FATAL_ERROR "failed credential stdout can escape through diagnostic text")
endif()
string(FIND "${CREDENTIALS}" "2>&1" STDERR_REDIRECT)
if (NOT STDERR_REDIRECT EQUAL -1)
   message(FATAL_ERROR "credential builders still merge diagnostic stderr into credential material")
endif()
string(FIND "${CREDENTIALS}" "appendShellSingleQuoted(command, azPath)" AZURE_PATH_QUOTING)
if (AZURE_PATH_QUOTING EQUAL -1)
   message(FATAL_ERROR "Azure credential command executable path is not shell-quoted")
endif()
foreach(REQUIRED IN ITEMS
   "ProdigyCommandCapture::run(coro"
   "runtimeEnvironment.gcp.bootstrapAccessTokenRefreshCommand"
   "runtimeEnvironment.aws.bootstrapCredentialRefreshCommand"
   "runtimeEnvironment.azure.bootstrapAccessTokenRefreshCommand"
   "prodigyDNSResolveBearerToken(coro")
   string(FIND "${CREDENTIAL_COMMAND_SURFACES}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "credential refresh surface bypasses bounded command capture: ${REQUIRED}")
   endif()
endforeach()
string(FIND "${TEMPLATE}" "#include <prodigy/json.h>" SHARED_JSON)
string(FIND "${TEMPLATE}" "bootstrap.ssh.h" SSH_DEPENDENCY)
string(FIND "${JSON}" "prodigyAppendEscapedJSONStringLiteral" JSON_HELPER)
if (SHARED_JSON EQUAL -1 OR JSON_HELPER EQUAL -1 OR NOT SSH_DEPENDENCY EQUAL -1)
   message(FATAL_ERROR "GCP managed-template JSON ownership is not isolated from SSH provisioning")
endif()

foreach(FORBIDDEN IN ITEMS "GcpHttp" "sendElasticComputeRequest" "usleep" "popen" "RefreshCommand")
   string(FIND "${TEMPLATE}" "${FORBIDDEN}" OFFSET)
   if (NOT OFFSET EQUAL -1)
      message(FATAL_ERROR "GCP managed-template module retains blocking behavior: ${FORBIDDEN}")
   endif()
endforeach()

foreach(REMOVED IN ITEMS "instanceTemplateExists" "deleteInstanceTemplateIfExists" "waitForGlobalOperation" "ensureManagedInstanceTemplate")
   string(FIND "${GCP}" "${REMOVED}" OFFSET)
   if (NOT OFFSET EQUAL -1)
      message(FATAL_ERROR "GCP managed-template blocking helper remains: ${REMOVED}")
   endif()
endforeach()
string(FIND "${GCP}" "forbids executable credential refresh" REFRESH_GUARD)
if (NOT REFRESH_GUARD EQUAL -1)
   message(FATAL_ERROR "GCP provider still rejects Ring-integrated executable credential refresh")
endif()
foreach(REQUIRED IN ITEMS "gcpHostRequest" "hostRequest" "gcpSuccessfulResponse" "successfulResponse")
   string(FIND "${GCP}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "GCP generic async transport naming missing: ${REQUIRED}")
   endif()
endforeach()
foreach(FORBIDDEN IN ITEMS "gcpHostGet" "hostGet" "gcpSuccessfulGet" "successfulGet")
   string(FIND "${GCP}" "${FORBIDDEN}" OFFSET)
   if (NOT OFFSET EQUAL -1)
      message(FATAL_ERROR "GCP generic async transport retains GET-only name: ${FORBIDDEN}")
   endif()
endforeach()
string(FIND "${MOTHERSHIP}" "bool prepareProviderBootstrapArtifacts" PREPARE_START)
string(FIND "${MOTHERSHIP}" "bool bootstrapLocalSeed" PREPARE_END)
math(EXPR PREPARE_LENGTH "${PREPARE_END} - ${PREPARE_START}")
string(SUBSTRING "${MOTHERSHIP}" ${PREPARE_START} ${PREPARE_LENGTH} PREPARE)
foreach(REQUIRED IN ITEMS
   "MothershipGcpManagedTemplatePlan::build(cluster, plan, localFailure)"
   "plan.timeout()"
   "prepareGcpRingRuntimeEnvironment("
   "jobEnvironment, &localFailure, deadline"
   "owner->hostRuntime.run"
   "services.operationDeadline = deadline"
   "prodigyCreateProviderBrainIaaS(jobEnvironment, services)"
   "gcp->prepareManagedInstanceTemplates(coro, plan.specs, localFailure)")
   string(FIND "${PREPARE}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "Mothership managed-template job contract missing: ${REQUIRED}")
   endif()
endforeach()
foreach(REQUIRED IN ITEMS
   "applyCredentialToRuntimeEnvironment(credential, runtimeEnvironment, failure, deadline)"
   "runtimeEnvironment.gcp.bootstrapAccessTokenRefreshCommand")
   string(FIND "${CREDENTIALS}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "credential deadline propagation missing: ${REQUIRED}")
   endif()
endforeach()
string(FIND "${PREPARE}" "MothershipGcpManagedTemplatePlan::build" BUILD)
string(FIND "${PREPARE}" "const MultiCurlClient::TimePoint deadline" DEADLINE)
string(FIND "${PREPARE}" "prepareGcpRingRuntimeEnvironment(" CREDENTIAL)
string(FIND "${PREPARE}" "owner->hostRuntime.run" RUN)
if (BUILD EQUAL -1 OR DEADLINE LESS BUILD OR CREDENTIAL LESS DEADLINE OR RUN LESS CREDENTIAL)
   message(FATAL_ERROR "GCP templates must be prebuilt before one deadline-bound credential resolution and Ring job")
endif()
string(LENGTH "prepareGcpRingRuntimeEnvironment(" PREPARE_CREDENTIAL_LENGTH)
math(EXPR PREPARE_CREDENTIAL_REMAINDER_START "${CREDENTIAL} + ${PREPARE_CREDENTIAL_LENGTH}")
string(SUBSTRING "${PREPARE}" ${PREPARE_CREDENTIAL_REMAINDER_START} -1 PREPARE_CREDENTIAL_REMAINDER)
string(FIND "${PREPARE_CREDENTIAL_REMAINDER}" "prepareGcpRingRuntimeEnvironment(" CREDENTIAL_SECOND)
if (NOT CREDENTIAL_SECOND EQUAL -1)
   message(FATAL_ERROR "GCP managed-template composition resolves credentials more than once")
endif()
set(FACTORY "prodigyCreateProviderBrainIaaS(jobEnvironment, services)")
string(FIND "${PREPARE}" "${FACTORY}" FACTORY_FIRST)
string(LENGTH "${FACTORY}" FACTORY_LENGTH)
math(EXPR FACTORY_REMAINDER_START "${FACTORY_FIRST} + ${FACTORY_LENGTH}")
string(SUBSTRING "${PREPARE}" ${FACTORY_REMAINDER_START} -1 FACTORY_REMAINDER)
string(FIND "${FACTORY_REMAINDER}" "${FACTORY}" FACTORY_SECOND)
if (FACTORY_FIRST EQUAL -1 OR NOT FACTORY_SECOND EQUAL -1)
   message(FATAL_ERROR "GCP managed-template job must construct exactly one worker-owned provider")
endif()
string(FIND "${PREPARE}" "mothershipBuildClusterProvisioningRuntimeEnvironment(cluster, &credential, runtimeEnvironment" AZURE_CONFIG)
if (AZURE_CONFIG LESS RUN)
   message(FATAL_ERROR "GCP managed-template path resolves credentials through the legacy blocking environment builder")
endif()

string(FIND "${REGISTRY}" "expectedTemplate.equals(expectedSpotTemplate)" DISTINCT)
if (DISTINCT EQUAL -1)
   message(FATAL_ERROR "GCP registry permits standard and spot to share one destructive template name")
endif()
