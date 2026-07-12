if(NOT DEFINED PRODIGY_ROOT)
   message(FATAL_ERROR "PRODIGY_ROOT is required")
endif()

file(READ "${PRODIGY_ROOT}/prodigy/iaas/iaas.h" iaas_source)
file(READ "${PRODIGY_ROOT}/prodigy/iaas/gcp/gcp.h" gcp_source)
file(READ "${PRODIGY_ROOT}/prodigy/iaas/gcp/gcp.compute.transaction.h" compute_source)
file(READ "${PRODIGY_ROOT}/prodigy/iaas/gcp/gcp.labels.h" labels_source)
file(READ "${PRODIGY_ROOT}/prodigy/cluster.machine.helpers.h" helpers_source)
file(READ "${PRODIGY_ROOT}/prodigy/mothership/mothership.gcp.host.operations.h" mothership_source)

foreach(required
      "ensureProdigyMachineTags(CoroutineStack *coro,"
      "const String& clusterUUID,"
      "const String& cloudID,"
      "String& error)")
   string(FIND "${iaas_source}" "${required}" found)
   if(found EQUAL -1)
      message(FATAL_ERROR "async copied-identity machine-tag provider contract missing: ${required}")
   endif()
endforeach()

foreach(required
      "#include <prodigy/iaas/gcp/gcp.labels.h>"
      "labelOperations"
      "usesRefreshableBootstrapAccessToken()"
      "GcpInstanceLabelsTransaction transaction"
      "ProdigyHostDelayOperation::submission()")
   string(FIND "${gcp_source}" "${required}" found)
   if(found EQUAL -1)
      message(FATAL_ERROR "GCP provider labels integration missing: ${required}")
   endif()
endforeach()

foreach(required
      "GcpComputeTransaction compute"
      "maximumLabels = 64"
      "maximumMutationAttempts = 4"
      "compute.resolveName(coro, targetCloudID"
      "\"id,labelFingerprint,labels\"_ctv"
      "url.append(\"/setLabels\"_ctv)"
      "mutationResult.statusCode == 412"
      "compute.pollOperation(coro, operationName")
   string(FIND "${labels_source}" "${required}" found)
   if(found EQUAL -1)
      message(FATAL_ERROR "GCP labels transaction contract missing: ${required}")
   endif()
endforeach()

foreach(source "${compute_source}" "${labels_source}")
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
         message(FATAL_ERROR "GCP labels Ring transaction contains forbidden blocking/logging/owning surface: ${forbidden}")
      endif()
   endforeach()
endforeach()

foreach(required
      "prodigyEnsureCloudMachineTagged(CoroutineStack *coro"
      "iaas.ensureProdigyMachineTags(coro,"
      "clusterUUIDTagValue,"
      "clusterMachine.cloud.cloudID,"
      "tagFailure);")
   string(FIND "${helpers_source}" "${required}" found)
   if(found EQUAL -1)
      message(FATAL_ERROR "shared machine-tag async ownership contract missing: ${required}")
   endif()
endforeach()

foreach(required
      "mothershipRunGcpMachineTagJob("
      "prepareGcpRingRuntimeEnvironment"
      "runtime.run("
      "prodigyEnsureCloudMachineTagged(coro,")
   string(FIND "${mothership_source}" "${required}" found)
   if(found EQUAL -1)
      message(FATAL_ERROR "Mothership GCP labels Ring job contract missing: ${required}")
   endif()
endforeach()

foreach(forbidden
      "bool ensureProdigyMachineTags(const String&"
      "resolveInstanceNameForCloudID"
      "fetchInstanceDocument"
      "ensureInstanceLabel"
      "ensureInstanceMetadataItem")
   string(FIND "${gcp_source}" "${forbidden}" found)
   if(NOT found EQUAL -1)
      message(FATAL_ERROR "stale blocking GCP label surface remains: ${forbidden}")
   endif()
endforeach()
