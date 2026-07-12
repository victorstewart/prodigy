if(NOT DEFINED PRODIGY_ROOT)
   message(FATAL_ERROR "PRODIGY_ROOT is required")
endif()

file(READ "${PRODIGY_ROOT}/prodigy/iaas/iaas.h" iaas_source)
file(READ "${PRODIGY_ROOT}/prodigy/iaas/runtime/runtime.h" runtime_source)
file(READ "${PRODIGY_ROOT}/prodigy/iaas/gcp/gcp.h" gcp_source)
file(READ "${PRODIGY_ROOT}/prodigy/iaas/gcp/gcp.compute.transaction.h" compute_source)
file(READ "${PRODIGY_ROOT}/prodigy/iaas/gcp/gcp.cluster.destroy.h" destroy_source)
file(READ "${PRODIGY_ROOT}/prodigy/mothership/mothership.gcp.host.operations.h" mothership_operations_source)
file(READ "${PRODIGY_ROOT}/prodigy/mothership/mothership.cpp" mothership_source)

foreach(required
      "destroyClusterMachines(CoroutineStack *coro, const String& clusterUUID, uint32_t& destroyed, String& error)")
   string(FIND "${iaas_source}" "${required}" found)
   if(found EQUAL -1)
      message(FATAL_ERROR "async copied-identity cluster-destroy provider contract missing: ${required}")
   endif()
endforeach()

foreach(required
      "provider cluster destroy coroutine required"
      "delegate->destroyClusterMachines(coro, clusterUUID, destroyed, error)"
      "applyPendingRuntimeEnvironment(delegate)"
      "completedDelegate->hasActiveControlOperations() == false")
   string(FIND "${runtime_source}" "${required}" found)
   if(found EQUAL -1)
      message(FATAL_ERROR "runtime cluster-destroy suspension/reconfiguration guard missing: ${required}")
   endif()
endforeach()

foreach(required
      "#include <prodigy/iaas/gcp/gcp.cluster.destroy.h>"
      "clusterDestroyOperations"
      "usesRefreshableBootstrapAccessToken()"
      "GcpClusterDestroyTransaction transaction"
      "ProdigyHostDelayOperation::submission()")
   string(FIND "${gcp_source}" "${required}" found)
   if(found EQUAL -1)
      message(FATAL_ERROR "GCP provider cluster-destroy integration missing: ${required}")
   endif()
endforeach()

foreach(required
      "maximumRequestsPerWave = ProdigyHostHttpAdmission::defaultCapacity"
      "maximumPages = 256"
      "maximumInstances = 128'000"
      "maximumPageTokenBytes = 2048")
   string(FIND "${compute_source}${destroy_source}" "${required}" found)
   if(found EQUAL -1)
      message(FATAL_ERROR "bounded admission-aligned GCP cluster-destroy contract missing: ${required}")
   endif()
endforeach()

foreach(required
      "String clusterLabel;"
      "clusterLabel.assign(clusterUUID);"
      "exactLabels(instance, clusterLabel)"
      "compute.wait(coro, delayComplete)"
      "compute.submit(coro,"
      "compute.request(MultiCurlClient::Method::")
   string(FIND "${destroy_source}" "${required}" found)
   if(found EQUAL -1)
      message(FATAL_ERROR "GCP cluster-destroy Ring transaction contract missing: ${required}")
   endif()
endforeach()

foreach(source "${compute_source}" "${destroy_source}")
   foreach(forbidden
         "GcpHttp"
         "curl_"
         "usleep("
         "basics_log("
         "std::string "
         "std::vector"
         "std::unordered_")
      string(FIND "${source}" "${forbidden}" found)
      if(NOT found EQUAL -1)
         message(FATAL_ERROR "GCP cluster-destroy transaction contains forbidden blocking/logging/owning surface: ${forbidden}")
      endif()
   endforeach()
endforeach()

foreach(required
      "mothershipRunGcpClusterDestroyJob("
      "targetClusterUUID.assign(clusterUUID);"
      "prepareGcpRingRuntimeEnvironment"
      "runtime.run("
      "mothershipDestroyProviderClusterMachines(coro,")
   string(FIND "${mothership_operations_source}" "${required}" found)
   if(found EQUAL -1)
      message(FATAL_ERROR "Mothership GCP cluster-destroy host-Ring job missing: ${required}")
   endif()
endforeach()

foreach(forbidden
      "bool destroyClusterMachines(const String&"
      "bool destroyClusterMachines(String")
   string(FIND "${iaas_source}${gcp_source}" "${forbidden}" found)
   if(NOT found EQUAL -1)
      message(FATAL_ERROR "stale synchronous GCP cluster-destroy API remains: ${forbidden}")
   endif()
endforeach()

foreach(forbidden
      "provider->destroyClusterMachines("
      "gcp.destroyClusterMachines(")
   string(FIND "${mothership_source}" "${forbidden}" found)
   if(NOT found EQUAL -1)
      message(FATAL_ERROR "Mothership bypasses the GCP host-Ring cluster-destroy job: ${forbidden}")
   endif()
endforeach()

foreach(required
      "cleanupDeadline - std::chrono::minutes(3)"
      "(void)mothershipRunGcpClusterDestroyJob("
      "mothershipRunGcpMachineDestroyJob(")
   string(FIND "${mothership_source}" "${required}" found)
   if(found EQUAL -1)
      message(FATAL_ERROR "GCP seed cleanup does not reserve time and prove exact seed-ID absence: ${required}")
   endif()
endforeach()
