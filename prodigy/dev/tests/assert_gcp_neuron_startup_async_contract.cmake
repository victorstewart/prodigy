if (NOT DEFINED PRODIGY_ROOT)
   message(FATAL_ERROR "PRODIGY_ROOT is required")
endif()

file(READ "${PRODIGY_ROOT}/prodigy/iaas/iaas.h" IAAS)
file(READ "${PRODIGY_ROOT}/prodigy/iaas/gcp/gcp.h" GCP)
file(READ "${PRODIGY_ROOT}/prodigy/iaas/runtime/runtime.h" RUNTIME)
file(READ "${PRODIGY_ROOT}/prodigy/neuron/neuron.h" NEURON)
file(READ "${PRODIGY_ROOT}/prodigy/prodigy.h" PRODIGY)

string(FIND "${GCP}" "class GcpNeuronIaaS" GCP_NEURON_START)
string(FIND "${GCP}" "uint32_t gcpHashRackIdentity" GCP_NEURON_END)
if (GCP_NEURON_START EQUAL -1 OR GCP_NEURON_END LESS GCP_NEURON_START)
   message(FATAL_ERROR "GCP Neuron provider boundaries not found")
endif()
math(EXPR GCP_NEURON_LENGTH "${GCP_NEURON_END} - ${GCP_NEURON_START}")
string(SUBSTRING "${GCP}" ${GCP_NEURON_START} ${GCP_NEURON_LENGTH} GCP_NEURON)

foreach(FORBIDDEN IN ITEMS "GcpHttp::get" "metadata.google.internal/computeMetadata" "curl_slist")
   string(FIND "${GCP_NEURON}" "${FORBIDDEN}" OFFSET)
   if (NOT OFFSET EQUAL -1)
      message(FATAL_ERROR "GCP Neuron startup retains blocking metadata transport: ${FORBIDDEN}")
   endif()
endforeach()

string(FIND "${GCP}" "/instance/attributes/brain" DEAD_ROLE_REQUEST)
if (NOT DEAD_ROLE_REQUEST EQUAL -1)
   message(FATAL_ERROR "GCP Neuron startup must not fetch role metadata overridden by bootstrap state")
endif()

foreach(REQUIRED IN ITEMS
   "http://169.254.169.254"
   "request.authority.assign(\"metadata.google.internal\"_ctv)"
   "HttpPolicy::requireHttp1"
   "AsyncDnsResolver::Family::ipv4"
   "Metadata-Flavor"
   "gcpReadNeuronStartupMetro"
   "gcpReadNeuronStartupMetro(providerServices.http, coro, metro)"
   "co_await coro->suspendAtIndex(suspendIndex)")
   string(FIND "${GCP}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "GCP Neuron async startup contract missing: ${REQUIRED}")
   endif()
endforeach()

foreach(REQUIRED IN ITEMS
   "gatherSelfData(CoroutineStack *coro"
   "activeDelegate()->gatherSelfData(coro"
   "isBrain = (bootstrapConfig.nodeRole == ProdigyBootstrapNodeRole::brain);"
   "iaas->gatherSelfData(coro"
   "neuron->boot(startupCoroutine.get())"
   "co_await startupCoroutine->suspendAtIndex(suspendIndex)"
   "finishRuntimeStartup();")
   string(FIND "${IAAS}${RUNTIME}${NEURON}${PRODIGY}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "Neuron startup coroutine ownership missing: ${REQUIRED}")
   endif()
endforeach()

string(FIND "${PRODIGY}" "void bootRuntime(void)" BOOT_START)
string(FIND "${PRODIGY}" "void startRuntime(void)" BOOT_END)
string(FIND "${PRODIGY}" "finishRuntimeStartup();" FINISH_OFFSET)
string(FIND "${PRODIGY}" "neuron->isBrain" ROLE_OFFSET)
if (BOOT_START EQUAL -1 OR BOOT_END LESS BOOT_START OR FINISH_OFFSET LESS BOOT_START OR FINISH_OFFSET GREATER BOOT_END OR ROLE_OFFSET EQUAL -1)
   message(FATAL_ERROR "Prodigy must finish Neuron boot before reading its role")
endif()
