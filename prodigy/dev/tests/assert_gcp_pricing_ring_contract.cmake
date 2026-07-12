if(NOT DEFINED PRODIGY_ROOT)
   message(FATAL_ERROR "PRODIGY_ROOT is required")
endif()

file(READ "${PRODIGY_ROOT}/prodigy/mothership/mothership.pricing.h" pricing_source)
file(READ "${PRODIGY_ROOT}/prodigy/mothership/mothership.cpp" mothership_source)
file(READ "${PRODIGY_ROOT}/prodigy/iaas/gcp/gcp.h" gcp_header)
file(READ "${PRODIGY_ROOT}/prodigy/iaas/gcp/gcp.cpp" gcp_source)

foreach(required
      "class MothershipGcpPricingHttp final"
      "maximumPages = 64"
      "maximumPageTokenBytes = 2048"
      "maximumResponseBytes = 8 * 1024 * 1024"
      "maximumTotalResponseBytes = 64 * 1024 * 1024"
      "requestedPageTokens.contains(pageToken)"
      "value.originPolicy.requiredScheme.assign(\"https\"_ctv)"
      "\"compute.googleapis.com\"_ctv"
      "\"cloudbilling.googleapis.com\"_ctv"
      "prepareGcpRingRuntimeEnvironment"
      "hostRuntime.run(")
   string(FIND "${pricing_source}" "${required}" found)
   if(found EQUAL -1)
      message(FATAL_ERROR "GCP pricing Ring contract missing: ${required}")
   endif()
endforeach()

string(REGEX MATCHALL "mothershipSurveyProviderMachineOffers\\(hostRuntime," runtime_calls "${mothership_source}")
list(LENGTH runtime_calls runtime_call_count)
if(NOT runtime_call_count EQUAL 3)
   message(FATAL_ERROR "all three pricing surveys must use the single Mothership host Ring runtime")
endif()

foreach(forbidden
      "GcpHttp"
      "sendElasticComputeRequest"
      "usleep("
      "std::vector"
      "std::unordered_")
   string(FIND "${pricing_source}" "${forbidden}" found)
   if(NOT found EQUAL -1)
      message(FATAL_ERROR "GCP pricing Ring path contains stale blocking/alternate-owning surface: ${forbidden}")
   endif()
endforeach()

foreach(source "${gcp_header}" "${gcp_source}")
   foreach(forbidden
         "GcpHttp"
         "sendElasticComputeRequest"
         "curl_easy_"
         "curl_slist"
         "usleep("
         "std::vector"
         "std::unordered_")
      string(FIND "${source}" "${forbidden}" found)
      if(NOT found EQUAL -1)
         message(FATAL_ERROR "stale blocking/alternate-owning GCP HTTP surface remains: ${forbidden}")
      endif()
   endforeach()
endforeach()

foreach(forbidden
      "bool ensureProjectZone()"
      "bool ensureToken("
      "ensureProviderAccessToken"
      "buildAuthHeaders"
      "isHTTPMethodGET")
   string(FIND "${gcp_header}" "${forbidden}" found)
   if(NOT found EQUAL -1)
      message(FATAL_ERROR "stale synchronous GCP provider adapter remains: ${forbidden}")
   endif()
endforeach()
