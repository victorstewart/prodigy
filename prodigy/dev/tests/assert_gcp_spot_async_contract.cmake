if (NOT DEFINED PRODIGY_ROOT)
   message(FATAL_ERROR "PRODIGY_ROOT is required")
endif()

file(READ "${PRODIGY_ROOT}/prodigy/iaas/gcp/gcp.h" GCP)
file(READ "${PRODIGY_ROOT}/prodigy/iaas/runtime/runtime.h" RUNTIME)
file(READ "${PRODIGY_ROOT}/prodigy/brain/brain.h" BRAIN)

string(FIND "${GCP}" "void checkForSpotTerminations(CoroutineStack *coro, Vector<String>& decommissionedIDs) override" CHECK_START)
string(FIND "${GCP}" "void destroyMachine(Machine *machine) override" CHECK_END)
if (CHECK_START EQUAL -1 OR CHECK_END LESS CHECK_START)
   message(FATAL_ERROR "GCP spot-termination method boundaries not found")
endif()
math(EXPR CHECK_LENGTH "${CHECK_END} - ${CHECK_START}")
string(SUBSTRING "${GCP}" ${CHECK_START} ${CHECK_LENGTH} CHECK)

foreach(FORBIDDEN IN ITEMS "curl_slist" "GcpHttp::get" "(void)coro")
   string(FIND "${CHECK}" "${FORBIDDEN}" OFFSET)
   if (NOT OFFSET EQUAL -1)
      message(FATAL_ERROR "GCP spot polling retains blocking/raw curl surface: ${FORBIDDEN}")
   endif()
endforeach()

foreach(REQUIRED IN ITEMS
   "http://169.254.169.254"
   "metadata.google.internal"
   "compute.googleapis.com"
   "HttpPolicy::requireHttp1"
   "AsyncDnsResolver::Family::ipv4"
   "CaSource::system"
   "originPolicy.requiredScheme"
   "std::chrono::seconds(3)"
   "if (operation.mustSuspend())"
   "ensureProjectZoneAsync"
   "ensureTokenAsync"
   "parseSpotTerminationPage"
   "spotCheckMaxPages"
   "spotCheckMaxResultsPerPage"
   "spotCheckMaxDecommissionedIDs"
   "spotPageTokenBytes"
   "checkDeadline"
   "canRequestSpotPage"
   "requestedPageTokens.contains(nextPageToken)")
   string(FIND "${GCP}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "GCP async spot contract missing: ${REQUIRED}")
   endif()
endforeach()

foreach(REQUIRED IN ITEMS
   "providerDelegate->hasActiveControlOperations()"
   "providerReconfigurationPending = true;"
   "co_await coro->suspendAtIndex(suspendIndex);"
   "applyRuntimeEnvironment();")
   string(FIND "${RUNTIME}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "runtime-aware provider quiescence contract missing: ${REQUIRED}")
   endif()
endforeach()

foreach(REQUIRED IN ITEMS
   "bool spotDecommissionCheckActive = false;"
   "CoroutineStack spotDecommissionCheckCoroutine;"
   "CoroutineStack *coro = &spotDecommissionCheckCoroutine;"
   "refreshAllDeploymentWormholeQuicCidState(true);"
   "spotDecomissionChecker.setTimeoutMs(prodigyBrainSpotDecommissionCheckIntervalMs);"
   "Ring::queueTimeout(&spotDecomissionChecker);")
   string(FIND "${BRAIN}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "Brain spot-check completion ownership missing: ${REQUIRED}")
   endif()
endforeach()

string(FIND "${BRAIN}" "auto coro = std::make_unique<CoroutineStack>();" EPHEMERAL_SPOT_STACK)
if (NOT EPHEMERAL_SPOT_STACK EQUAL -1)
   message(FATAL_ERROR "Brain spot outer caller must not destroy its stack from the stack's own wake")
endif()
