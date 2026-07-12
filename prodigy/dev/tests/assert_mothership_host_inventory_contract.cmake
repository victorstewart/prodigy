if (NOT DEFINED PRODIGY_ROOT)
   message(FATAL_ERROR "PRODIGY_ROOT is required")
endif()

file(READ "${PRODIGY_ROOT}/prodigy/mothership/mothership.ring.runtime.h" RUNTIME)
file(READ "${PRODIGY_ROOT}/prodigy/mothership/mothership.cpp" MOTHERSHIP)
file(READ "${PRODIGY_ROOT}/prodigy/mothership/mothership.provider.credentials.h" CREDENTIALS)
file(READ "${PRODIGY_ROOT}/prodigy/iaas/gcp/gcp.h" GCP)
file(READ "${PRODIGY_ROOT}/prodigy/brain/brain.h" BRAIN)
file(READ "${PRODIGY_ROOT}/../basics/networking/ring.h" RING)

string(FIND "${MOTHERSHIP}" "bool collectProviderMachineCloudIDs" INVENTORY_CONSUMER_START)
string(FIND "${MOTHERSHIP}" "static bool resolveJSONArgument" INVENTORY_CONSUMER_END)
math(EXPR INVENTORY_CONSUMER_LENGTH "${INVENTORY_CONSUMER_END} - ${INVENTORY_CONSUMER_START}")
string(SUBSTRING "${MOTHERSHIP}" ${INVENTORY_CONSUMER_START} ${INVENTORY_CONSUMER_LENGTH} INVENTORY_CONSUMER)

foreach(REQUIRED IN ITEMS
   "RingProcessIntegration::isolatedWorker"
   "ProdigyHostControlNetwork network;"
   "MothershipHostRuntimeQueue jobs;"
   "std::thread workerThread;"
   "eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK)"
   "Ring::queueRawFDPoll"
   "active->start(services);"
   "completed->retire();")
   string(FIND "${RUNTIME}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "Mothership host runtime contract missing: ${REQUIRED}")
   endif()
endforeach()

foreach(FORBIDDEN IN ITEMS "std::vector" "std::unordered" "getaddrinfo" "curl_easy_" "curl_multi_" "popen" "pclose" "fread")
   string(FIND "${RUNTIME}" "${FORBIDDEN}" OFFSET)
   if (NOT OFFSET EQUAL -1)
      message(FATAL_ERROR "Mothership host runtime contains forbidden ownership: ${FORBIDDEN}")
   endif()
endforeach()

foreach(REQUIRED IN ITEMS
   "runtimeEnvironment.kind != ProdigyEnvironmentKind::gcp"
   "blockingProvider.getMachines(nullptr, metro, machines, failure);"
   "MothershipProviderCredentialRegistry::prepareGcpRingRuntimeEnvironment(credential, runtimeEnvironment, jobRuntimeEnvironment, &failure)"
   "hostRuntime.run"
   "prodigyCreateProviderBrainIaaS(jobRuntimeEnvironment, services)"
   "provider->getMachines(coro, metro, machines, failure);"
   "return failure.size() == 0;")
   string(FIND "${INVENTORY_CONSUMER}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "Mothership inventory consumer contract missing: ${REQUIRED}")
   endif()
endforeach()
string(FIND "${MOTHERSHIP}" "MothershipHostRingRuntime hostRuntime;" HOST_RUNTIME_OWNER)
if (HOST_RUNTIME_OWNER EQUAL -1)
   message(FATAL_ERROR "Mothership inventory host runtime owner missing")
endif()

string(FIND "${INVENTORY_CONSUMER}" "MothershipProviderCredentialRegistry::prepareGcpRingRuntimeEnvironment(credential, runtimeEnvironment, jobRuntimeEnvironment, &failure)" PREPARE_OFFSET)
string(FIND "${INVENTORY_CONSUMER}" "hostRuntime.run" RUNTIME_OFFSET)
if (PREPARE_OFFSET GREATER RUNTIME_OFFSET)
   message(FATAL_ERROR "Mothership must resolve fresh material and quarantine refresh commands before Ring submission")
endif()

foreach(REQUIRED IN ITEMS
   "prodigyOwnRuntimeEnvironmentConfig(source, runtimeEnvironment);"
   "applyCredentialToRuntimeEnvironment(credential, runtimeEnvironment, failure, deadline)"
   "runtimeEnvironment.gcp.bootstrapAccessTokenRefreshCommand.reset();"
   "runtimeEnvironment.gcp.bootstrapAccessTokenRefreshFailureHint.reset();"
   "buildGcpBootstrapAccessTokenRefreshCommand(credential, runtimeEnvironment.gcp.bootstrapAccessTokenRefreshCommand"
   "describeGcpBootstrapAccessTokenRefreshHint(credential, runtimeEnvironment.gcp.bootstrapAccessTokenRefreshFailureHint)")
   string(FIND "${CREDENTIALS}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "legacy main-thread GCP credential refresh contract missing: ${REQUIRED}")
   endif()
endforeach()
string(FIND "${INVENTORY_CONSUMER}" "provider->getMachines(nullptr" NULL_INVENTORY)
if (NOT NULL_INVENTORY EQUAL -1)
   message(FATAL_ERROR "Mothership inventory still uses a null coroutine")
endif()

foreach(REQUIRED IN ITEMS
   "inventoryInstancesRequest"
   "walkInventory"
   "inventoryPageResponseBytes"
   "inventoryMaxPages"
   "inventoryMaxInstances"
   "inventoryPageTokenBytes"
   "inventoryTimeout"
   "requestedPageTokens.contains(pageToken)"
   "Vector<std::unique_ptr<Machine>> pendingMachines"
   "Vector<std::unique_ptr<BrainView>> pendingBrains"
   "if (failure.size() == 0)"
   "http://169.254.169.254"
   "metadata.google.internal"
   "compute.googleapis.com"
   "CaSource::system"
   "originPolicy.requiredHost")
   string(FIND "${GCP}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "GCP async inventory contract missing: ${REQUIRED}")
   endif()
endforeach()

string(FIND "${GCP}" "void getMachines(CoroutineStack *coro" MACHINES_START)
string(FIND "${GCP}" "void hardRebootMachine" INVENTORY_END)
math(EXPR INVENTORY_LENGTH "${INVENTORY_END} - ${MACHINES_START}")
string(SUBSTRING "${GCP}" ${MACHINES_START} ${INVENTORY_LENGTH} INVENTORY)
foreach(FORBIDDEN IN ITEMS "GcpHttp::" "curl_slist" "(void)coro")
   string(FIND "${INVENTORY}" "${FORBIDDEN}" OFFSET)
   if (NOT OFFSET EQUAL -1)
      message(FATAL_ERROR "GCP inventory retains blocking transport: ${FORBIDDEN}")
   endif()
endforeach()

foreach(REQUIRED IN ITEMS
   "CoroutineStack brainInventoryCoroutine;"
   "CoroutineStack *coro = &brainInventoryCoroutine;")
   string(FIND "${BRAIN}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "Brain inventory stack ownership missing: ${REQUIRED}")
   endif()
endforeach()

foreach(REQUIRED IN ITEMS
   "enum class RingProcessIntegration"
   "isolatedWorker"
   "const bool integrateProcess = requestedProcessIntegration == RingProcessIntegration::enabled")
   string(FIND "${RING}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "Basics isolated Ring mode missing: ${REQUIRED}")
   endif()
endforeach()
