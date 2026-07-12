if(NOT DEFINED PRODIGY_ROOT)
   message(FATAL_ERROR "PRODIGY_ROOT is required")
endif()

file(READ "${PRODIGY_ROOT}/prodigy/iaas/iaas.h" iaas_source)
file(READ "${PRODIGY_ROOT}/prodigy/iaas/runtime/runtime.h" runtime_source)
file(READ "${PRODIGY_ROOT}/prodigy/iaas/gcp/gcp.h" gcp_source)
file(READ "${PRODIGY_ROOT}/prodigy/iaas/gcp/gcp.elastic.address.h" transaction_source)

foreach(required
      "prepareProviderElasticAddress(CoroutineStack *coro,"
      "applyProviderElasticAddress(CoroutineStack *coro,"
      "compensateProviderElasticAddress(CoroutineStack *coro,"
      "const ProviderElasticAddressRequest& request"
      "prodigyComputeElasticAddressPlanBindingDigest"
      "prodigyValidateElasticAddressPlanBinding"
      "releaseProviderElasticAddress(CoroutineStack *coro,"
      "const ProviderElasticAddressRelease& release")
   string(FIND "${iaas_source}" "${required}" found)
   if(found EQUAL -1)
      message(FATAL_ERROR "copied-value coroutine elastic-address provider contract missing: ${required}")
   endif()
endforeach()

foreach(required
      "provider elastic address prepare coroutine required"
      "provider elastic address apply coroutine required"
      "provider elastic address compensation coroutine required"
      "provider elastic address release coroutine required"
      "providerReconfigurationPending"
      "providerDelegate->validateProviderElasticAddressPlan(plan, request, transactionNonce)"
      "delegate->prepareProviderElasticAddress(coro, request, transactionNonce, plan, error);"
      "delegate->applyProviderElasticAddress(coro, plan, assignment, error);"
      "delegate->compensateProviderElasticAddress(coro, plan, error);"
      "delegate->releaseProviderElasticAddress(coro, release, error);")
   string(FIND "${runtime_source}" "${required}" found)
   if(found EQUAL -1)
      message(FATAL_ERROR "runtime elastic-address suspension/reconfiguration contract missing: ${required}")
   endif()
endforeach()

foreach(required
      "#include <prodigy/iaas/gcp/gcp.elastic.address.h>"
      "uint32_t elasticOperations = 0;"
      "ProviderElasticAddressRequest owned;"
      "ProviderElasticAddressRelease owned;"
      "GcpElasticAddressTransaction::planMatchesRequest(decoded, request, transactionNonce)"
      "transaction.prepare(coro, owned, plan, failure);"
      "transaction.apply(coro, plan, assignment, failure);"
      "transaction.compensate(coro, plan, failure);"
      "GcpElasticAddressTransaction transaction(hostHttpSubmission(),"
      "ProdigyHostDelayOperation::submission()")
   string(FIND "${gcp_source}" "${required}" found)
   if(found EQUAL -1)
      message(FATAL_ERROR "GCP elastic-address provider integration missing: ${required}")
   endif()
endforeach()

foreach(required
      "maximumDuration {110}"
      "recoveryReserve {35}"
      "pollOperationAtUrl(coro,"
      "&requestId="
      "class GcpElasticAddressPlanV1"
      "planMatchesRequest"
      "alreadySatisfied"
      "owned.transactionNonce != requestNonce"
      "prodigy-elastic-saga"
      "gcp elastic association token scope mismatch"
      "gcp elastic release tuple does not match association token"
      "gcp elastic owned allocation release requires immutable association token")
   string(FIND "${transaction_source}" "${required}" found)
   if(found EQUAL -1)
      message(FATAL_ERROR "bounded ABA-safe GCP elastic-address transaction contract missing: ${required}")
   endif()
endforeach()

file(READ "${PRODIGY_ROOT}/prodigy/iaas/aws/aws.h" aws_source)
foreach(forbidden
      "describeElasticAddressByPublicIP"
      "allocateElasticAddress"
      "associateElasticAddress"
      "disassociateElasticAddress"
      "releaseElasticAddressAllocation")
   string(FIND "${aws_source}" "${forbidden}" found)
   if(NOT found EQUAL -1)
      message(FATAL_ERROR "stale blocking AWS elastic-address helper remains: ${forbidden}")
   endif()
endforeach()

foreach(forbidden
      "GcpHttp"
      "curl_"
      "usleep("
      "basics_log("
      "std::string "
      "std::vector"
      "std::unordered_")
   string(FIND "${transaction_source}" "${forbidden}" found)
   if(NOT found EQUAL -1)
      message(FATAL_ERROR "GCP elastic-address transaction contains forbidden blocking/logging/owning surface: ${forbidden}")
   endif()
endforeach()

foreach(forbidden
      "assignProviderElasticAddress(Machine *"
      "releaseProviderElasticAddress(const DistributableExternalSubnet&"
      "waitForElasticZoneOperation"
      "waitForElasticRegionOperation"
      "fetchElasticInstanceNameForCloudID"
      "parseElasticAssociationID"
      "releaseElasticAddressAllocation")
   string(FIND "${gcp_source}" "${forbidden}" found)
   if(NOT found EQUAL -1)
      message(FATAL_ERROR "stale blocking GCP elastic-address path remains: ${forbidden}")
   endif()
endforeach()
