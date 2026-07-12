if(NOT DEFINED PRODIGY_ROOT)
   message(FATAL_ERROR "PRODIGY_ROOT is required")
endif()

file(READ "${PRODIGY_ROOT}/prodigy/iaas/azure/azure.h" AZURE)
file(READ "${PRODIGY_ROOT}/prodigy/iaas/azure/azure.cpp" AZURE_CPP)
file(READ "${PRODIGY_ROOT}/prodigy/iaas/azure/azure.http.h" HTTP)
file(READ "${PRODIGY_ROOT}/prodigy/iaas/iaas.h" IAAS)
file(READ "${PRODIGY_ROOT}/prodigy/mothership/mothership.pricing.h" PRICING)
file(READ "${PRODIGY_ROOT}/prodigy/mothership/mothership.ring.runtime.h" MOTHERSHIP_RUNTIME)
file(READ "${PRODIGY_ROOT}/prodigy/prodigy.cpp" PRODIGY)

foreach(FORBIDDEN IN ITEMS
      "curl_easy_"
      "curl_multi_"
      "curl_global_"
      "AzureHttp::"
      "usleep("
      "sleep_for(")
   string(FIND "${AZURE}${AZURE_CPP}" "${FORBIDDEN}" FOUND)
   if(NOT FOUND EQUAL -1)
      message(FATAL_ERROR "Azure IaaS retains forbidden private transport/blocking surface: ${FORBIDDEN}")
   endif()
endforeach()

foreach(REQUIRED IN ITEMS
      "ProdigyHostHttpOperation operation"
      "ProdigyHostDelayOperation operation"
      "ProdigyHostHttpBatchOperation"
      "ProdigyHostSuspend"
      "MultiCurlClient::Method requestedMethod"
      "request.originPolicy.requiredHost.assign(requiredHost)"
      "request.responseBytes = maximumResponseBytes")
   string(FIND "${HTTP}${AZURE}" "${REQUIRED}" FOUND)
   if(FOUND EQUAL -1)
      message(FATAL_ERROR "Azure async HTTP contract missing: ${REQUIRED}")
   endif()
endforeach()

foreach(REQUIRED IN ITEMS
      "ProdigyHostHttpSubmission http;"
      "ProdigyHostDelayOperation::Submission delay;")
   string(FIND "${IAAS}" "${REQUIRED}" FOUND)
   if(FOUND EQUAL -1)
      message(FATAL_ERROR "provider service bundle missing injected Azure dependency: ${REQUIRED}")
   endif()
endforeach()

foreach(SOURCE IN ITEMS MOTHERSHIP_RUNTIME PRODIGY)
   string(FIND "${${SOURCE}}" ".delay = ProdigyHostDelayOperation::submission()" FOUND)
   if(FOUND EQUAL -1)
      message(FATAL_ERROR "${SOURCE} does not inject the Ring-thread delay service")
   endif()
endforeach()

foreach(FORBIDDEN IN ITEMS
      "AzureHttp::send"
      "shim.request(\"GET\"")
   string(FIND "${PRICING}" "${FORBIDDEN}" FOUND)
   if(NOT FOUND EQUAL -1)
      message(FATAL_ERROR "Azure pricing retains obsolete blocking transport: ${FORBIDDEN}")
   endif()
endforeach()

foreach(REQUIRED IN ITEMS
      "MothershipAzurePricingShim::maximumDuration"
      "hostRuntime.run("
      "co_await mothershipSurveyAzureOffers("
      "\"prices.azure.com\"_ctv")
   string(FIND "${PRICING}" "${REQUIRED}" FOUND)
   if(FOUND EQUAL -1)
      message(FATAL_ERROR "Azure pricing Ring transport contract missing: ${REQUIRED}")
   endif()
endforeach()
