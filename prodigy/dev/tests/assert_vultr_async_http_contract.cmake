if(NOT DEFINED PRODIGY_ROOT)
   message(FATAL_ERROR "PRODIGY_ROOT is required")
endif()

file(READ "${PRODIGY_ROOT}/prodigy/iaas/vultr/vultr.h" VULTR)
file(READ "${PRODIGY_ROOT}/prodigy/iaas/vultr/vultr.cpp" VULTR_CPP)
file(READ "${PRODIGY_ROOT}/prodigy/iaas/vultr/vultr.http.h" HTTP)

foreach(FORBIDDEN IN ITEMS
      "curl_easy_"
      "curl_multi_"
      "curl_global_"
      "curl_slist"
      "curl_easy_escape"
      "VultrHttp::"
      "usleep("
      "sleep_for(")
   string(FIND "${VULTR}${VULTR_CPP}${HTTP}" "${FORBIDDEN}" FOUND)
   if(NOT FOUND EQUAL -1)
      message(FATAL_ERROR "Vultr retains forbidden private transport/blocking surface: ${FORBIDDEN}")
   endif()
endforeach()

foreach(REQUIRED IN ITEMS
      "ProdigyHostHttpOperation operation"
      "ProdigyHostDelayOperation operation"
      "ProdigyHostHttpBatchOperation operation"
      "ProdigyHostSuspend"
      "MultiCurlClient::Method::patch"
      "request.originPolicy.requiredHost.assign(\"api.vultr.com\"_ctv)"
      "request.originPolicy.requiredService.assign(\"443\"_ctv)"
      "request.responseBytes = maximumResponseBytes"
      "co_await client.sendBatch"
      "co_await client.wait")
   string(FIND "${HTTP}${VULTR}" "${REQUIRED}" FOUND)
   if(FOUND EQUAL -1)
      message(FATAL_ERROR "Vultr async HTTP contract missing: ${REQUIRED}")
   endif()
endforeach()
