if(NOT DEFINED PRODIGY_ROOT)
   message(FATAL_ERROR "PRODIGY_ROOT is required")
endif()

file(READ "${PRODIGY_ROOT}/prodigy/iaas/iaas.h" iaas_source)
file(READ "${PRODIGY_ROOT}/prodigy/iaas/gcp/gcp.h" gcp_source)
file(READ "${PRODIGY_ROOT}/prodigy/iaas/gcp/gcp.lifecycle.h" lifecycle_source)
file(READ "${PRODIGY_ROOT}/prodigy/brain/machine.lifecycle.h" coordinator_source)
file(READ "${PRODIGY_ROOT}/prodigy/mothership/mothership.gcp.host.operations.h" mothership_source)

foreach(required
      "hardRebootMachine(CoroutineStack *coro, const String& cloudID, String& failure)"
      "destroyMachine(CoroutineStack *coro, const String& cloudID, String& failure)")
   string(FIND "${iaas_source}" "${required}" found)
   if(found EQUAL -1)
      message(FATAL_ERROR "missing async provider lifecycle contract: ${required}")
   endif()
endforeach()

foreach(forbidden
      "hardRebootMachine(uint128_t"
      "destroyMachine(Machine *")
   string(FIND "${iaas_source}" "${forbidden}" found)
   if(NOT found EQUAL -1)
      message(FATAL_ERROR "stale synchronous lifecycle contract remains: ${forbidden}")
   endif()
endforeach()

foreach(forbidden
      "GcpHttp"
      "curl_"
      "usleep("
      "basics_log(")
   string(FIND "${lifecycle_source}" "${forbidden}" found)
   if(NOT found EQUAL -1)
      message(FATAL_ERROR "GCP lifecycle transaction contains forbidden blocking/logging surface: ${forbidden}")
   endif()
endforeach()

foreach(required
      "lifecycleOperations"
      "usesRefreshableBootstrapAccessToken()"
      "GcpMachineLifecycleTransaction transaction"
      "ProdigyHostDelayOperation::submission()")
   string(FIND "${gcp_source}" "${required}" found)
   if(found EQUAL -1)
      message(FATAL_ERROR "GCP provider lifecycle integration missing: ${required}")
   endif()
endforeach()

foreach(required
      "maximumQueuedOperations = 256"
      "String cloudID;"
      "CoroutineStack coroutine;"
      "provider->destroyMachine(&coroutine, request.cloudID, failure)")
   string(FIND "${coordinator_source}" "${required}" found)
   if(found EQUAL -1)
      message(FATAL_ERROR "Brain lifecycle ownership contract missing: ${required}")
   endif()
endforeach()

foreach(required
      "prepareGcpRingRuntimeEnvironment"
      "runtime.run("
      "mothershipDestroyProviderMachines(coro, *provider")
   string(FIND "${mothership_source}" "${required}" found)
   if(found EQUAL -1)
      message(FATAL_ERROR "Mothership GCP lifecycle Ring contract missing: ${required}")
   endif()
endforeach()
