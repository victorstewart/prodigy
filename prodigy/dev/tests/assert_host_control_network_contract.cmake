if (NOT DEFINED PRODIGY_ROOT)
   message(FATAL_ERROR "PRODIGY_ROOT is required")
endif()

file(READ "${PRODIGY_ROOT}/prodigy/host.control.network.h" OWNER)
file(READ "${PRODIGY_ROOT}/prodigy/host.http.operation.h" HTTP_OPERATION)
file(READ "${PRODIGY_ROOT}/prodigy/host.http.admission.h" HTTP_ADMISSION)
file(READ "${PRODIGY_ROOT}/prodigy/prodigy.h" LIFECYCLE)
file(READ "${PRODIGY_ROOT}/prodigy/prodigy.cpp" ENTRYPOINT)
file(READ "${PRODIGY_ROOT}/prodigy/iaas/iaas.h" PROVIDER_INTERFACE)
file(READ "${PRODIGY_ROOT}/prodigy/iaas/runtime/runtime.h" RUNTIME)

string(REGEX MATCHALL "ProdigyDns::ControlClient[ \t]+resolver" RESOLVERS "${OWNER}")
string(REGEX MATCHALL "MultiCurlClient[ \t]+client" CLIENTS "${OWNER}")
list(LENGTH RESOLVERS RESOLVER_COUNT)
list(LENGTH CLIENTS CLIENT_COUNT)
if (NOT RESOLVER_COUNT EQUAL 1 OR NOT CLIENT_COUNT EQUAL 1)
   message(FATAL_ERROR "host control must own exactly one resolver and one HTTP client")
endif()

string(FIND "${OWNER}" "ProdigyDns::ControlClient resolver;" RESOLVER_OFFSET)
string(FIND "${OWNER}" "MultiCurlClient client;" CLIENT_OFFSET)
string(FIND "${OWNER}" "client(resolver.resolver(), clientConfig())" CLIENT_CONSTRUCTION_OFFSET)
if (RESOLVER_OFFSET EQUAL -1 OR CLIENT_OFFSET LESS RESOLVER_OFFSET OR CLIENT_CONSTRUCTION_OFFSET EQUAL -1)
   message(FATAL_ERROR "host control resolver/client lifetime order is not explicit")
endif()

foreach(FORBIDDEN IN ITEMS "std::thread" "curl_easy_" "curl_multi_" "getaddrinfo" "gethostbyname" "RingAsyncDnsResolver" "async.dns.cares" "ares_")
   string(FIND "${OWNER}" "${FORBIDDEN}" OFFSET)
   if (NOT OFFSET EQUAL -1)
      message(FATAL_ERROR "host control owner contains a forbidden alternate execution path: ${FORBIDDEN}")
   endif()
endforeach()

foreach(REQUIRED IN ITEMS
   "ProdigyHostHttpAdmission admission;"
   "config.transfers = ProdigyHostHttpAdmission::defaultCapacity;"
   "return admission.submission();"
   "admission.shutdown();"
   "admission.shutdownSafe()")
   string(FIND "${OWNER}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "host control HTTP admission wiring is missing: ${REQUIRED}")
   endif()
endforeach()
foreach(REQUIRED IN ITEMS
   "class ProdigyHostHttpAdmission final"
   "defaultCapacity = 64"
   "defaultMaximumQueuedRequests = 256"
   "defaultMaximumQueuedBytes = 64 * 1024 * 1024"
   "bytell_hash_map<uint64_t, Entry *> entries"
   "MultiCurlClient::Status::deadlineExceeded"
   "MultiCurlClient::Status::shutdown")
   string(FIND "${HTTP_ADMISSION}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "host HTTP admission policy is missing: ${REQUIRED}")
   endif()
endforeach()

foreach(FORBIDDEN IN ITEMS "async.dns.cares" "RingAsyncDnsResolver" "ares_")
   string(FIND "${HTTP_OPERATION}" "${FORBIDDEN}" OFFSET)
   if (NOT OFFSET EQUAL -1)
      message(FATAL_ERROR "host HTTP operation contains concrete DNS ownership: ${FORBIDDEN}")
   endif()
endforeach()

string(REGEX MATCHALL "#include <[^>]+>" HTTP_OPERATION_INCLUDES "${HTTP_OPERATION}")
list(LENGTH HTTP_OPERATION_INCLUDES HTTP_OPERATION_INCLUDE_COUNT)
if (NOT HTTP_OPERATION_INCLUDE_COUNT EQUAL 2)
   message(FATAL_ERROR "host HTTP operation must depend only on CoroutineStack and MultiCurlClient")
endif()
foreach(REQUIRED IN ITEMS
   "#include <networking/coroutinestack.h>"
   "#include <networking/multi.curl.client.h>")
   string(FIND "${HTTP_OPERATION}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "host HTTP operation dependency boundary is missing: ${REQUIRED}")
   endif()
endforeach()
foreach(FORBIDDEN IN ITEMS "std::thread" "curl_easy_" "curl_multi_" "getaddrinfo" "gethostbyname")
   string(FIND "${HTTP_OPERATION}" "${FORBIDDEN}" OFFSET)
   if (NOT OFFSET EQUAL -1)
      message(FATAL_ERROR "host HTTP operation contains a forbidden alternate execution path: ${FORBIDDEN}")
   endif()
endforeach()

foreach(REQUIRED IN ITEMS
   "class ProdigyHostHttpOperation final"
   "pending = true;"
   "const Ticket ticket = client.submit"
   "if (!ticket)"
   "result.status = MultiCurlClient::Status::initializationFailure;"
   "const bool wake = wakeArmed;\n    wakeArmed = false;"
   "wakeStack->co_consume();"
   "Completion *const active = completion;"
   "active->owner = nullptr;"
   "client.cancel(client.context, active->ticket)")
   string(FIND "${HTTP_OPERATION}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "host HTTP coroutine operation is missing: ${REQUIRED}")
   endif()
endforeach()

string(FIND "${HTTP_OPERATION}" "pending = true;" PENDING_OFFSET)
string(FIND "${HTTP_OPERATION}" "const Ticket ticket = client.submit" SUBMIT_OFFSET)
string(FIND "${HTTP_OPERATION}" "const bool wake = wakeArmed;" WAKE_CAPTURE_OFFSET)
string(FIND "${HTTP_OPERATION}" "wakeStack->co_consume();" WAKE_OFFSET)
if (PENDING_OFFSET GREATER SUBMIT_OFFSET OR
    WAKE_CAPTURE_OFFSET GREATER WAKE_OFFSET)
   message(FATAL_ERROR "host HTTP coroutine operation violates submit/wake ordering")
endif()

foreach(REQUIRED IN ITEMS
   "startupTimer.setTimeoutUs(1);"
   "Ring::queueTimeout(&startupTimer);"
   "if (packet == &startupTimer)"
   "startRuntime();"
   "hostControlNetwork = std::make_unique<HostControlNetworkType>();"
   "hostControlNetwork->sessionReady()"
   "neuron = new NeuronType(*hostControlNetwork);"
   "BrainType *brain = new BrainType(*hostControlNetwork);")
   string(FIND "${LIFECYCLE}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "Prodigy lifecycle is missing host-control ownership: ${REQUIRED}")
   endif()
endforeach()

foreach(REQUIRED IN ITEMS
   "ProdigyHostControlNetwork& hostControlNetwork"
   "{.http = hostControlNetwork.http(), .delay = ProdigyHostDelayOperation::submission()}"
   "RuntimeAwareBrainIaaS(&persistentStateStore,"
   "RuntimeAwareNeuronIaaS(&persistentStateStore,"
   "Prodigy<ProdigyNeuron, ProdigyBrain, ProdigyHostControlNetwork>")
   string(FIND "${ENTRYPOINT}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "Prodigy entrypoint does not inject host control: ${REQUIRED}")
   endif()
endforeach()

foreach(REQUIRED IN ITEMS
   "class ProdigyProviderServices"
   "ProdigyHostHttpSubmission http;"
   "configureProviderServices(ProdigyProviderServices services)")
   string(FIND "${PROVIDER_INTERFACE}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "provider service boundary is missing: ${REQUIRED}")
   endif()
endforeach()

string(REGEX MATCHALL "providerServices[ \t]*=[ \t]*requestedProviderServices" RUNTIME_OWNERS "${RUNTIME}")
list(LENGTH RUNTIME_OWNERS RUNTIME_OWNER_COUNT)
if (NOT RUNTIME_OWNER_COUNT EQUAL 2)
   message(FATAL_ERROR "both runtime-aware provider owners must retain provider services")
endif()
string(FIND "${RUNTIME}" "ProdigyHostControlNetwork" HOST_OWNER_LEAK)
if (NOT HOST_OWNER_LEAK EQUAL -1)
   message(FATAL_ERROR "the concrete host-control owner leaked into provider interfaces")
endif()
