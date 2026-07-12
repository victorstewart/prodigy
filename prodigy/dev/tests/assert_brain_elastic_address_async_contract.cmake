if(NOT DEFINED PRODIGY_ROOT)
   message(FATAL_ERROR "PRODIGY_ROOT is required")
endif()

file(READ "${PRODIGY_ROOT}/prodigy/brain/elastic.address.operations.h" coordinator_source)
file(READ "${PRODIGY_ROOT}/prodigy/brain/routable.subnet.control.h" control_source)
file(READ "${PRODIGY_ROOT}/prodigy/brain/brain.h" brain_source)
file(READ "${PRODIGY_ROOT}/prodigy/brain/base.h" base_source)
file(READ "${PRODIGY_ROOT}/prodigy/iaas/iaas.h" iaas_source)
file(READ "${PRODIGY_ROOT}/prodigy/iaas/gcp/gcp.elastic.address.h" gcp_source)
file(READ "${PRODIGY_ROOT}/prodigy/types.h" types_source)

foreach(required
      "maximumQueuedOperations = 256"
      "Action::prepareAssignment"
      "Action::applyAssignment"
      "Action::compensateAssignment"
      "copy(operation.plan, plan);"
      "beginElasticAddressOperationBatch")
   string(FIND "${coordinator_source}" "${required}" found)
   if(found EQUAL -1)
      message(FATAL_ERROR "Brain elastic coordinator contract missing: ${required}")
   endif()
endforeach()

foreach(required
      "virtual bool persistLocalRuntimeState(void)"
      "BrainIaaS *iaas = nullptr;")
   string(FIND "${base_source}" "${required}" found)
   if(found EQUAL -1)
      message(FATAL_ERROR "Brain durability base contract missing: ${required}")
   endif()
endforeach()

foreach(required
      "prepareProviderElasticAddress"
      "applyProviderElasticAddress"
      "compensateProviderElasticAddress"
      "constexpr static uint32_t maximumBytes = 32_KB")
   string(FIND "${iaas_source}" "${required}" found)
   if(found EQUAL -1)
      message(FATAL_ERROR "Provider saga contract missing: ${required}")
   endif()
endforeach()

foreach(required
      "pendingElasticAddressAssignments"
      "pendingElasticAddressReleases"
      "providerPlan"
      "providerPlanBindingDigest"
      "transactionNonce"
      "compensating")
   string(FIND "${types_source}" "${required}" found)
   if(found EQUAL -1)
      message(FATAL_ERROR "Persisted elastic saga contract missing: ${required}")
   endif()
endforeach()

foreach(required
      "validatePendingElasticAddressOperations"
      "captureDurableElasticAddressOperations"
      "commitPendingElasticAddressStateChange(false)"
      "pendingElasticAddressOperationHasMajority"
      "reconcilePendingElasticAddressAssignments"
      "durableElasticOperationTransitions"
      "ProdigyMasterAuthorityStateTransition"
      "prodigyValidateElasticAddressPlanBinding"
      "countedPeerUUIDs"
      "stream->connectionIncarnation != operation.mothershipIncarnation")
   string(FIND "${control_source}${brain_source}" "${required}" found)
   if(found EQUAL -1)
      message(FATAL_ERROR "Brain durable elastic integration missing: ${required}")
   endif()
endforeach()

foreach(required
      "class GcpElasticAddressPlanV1"
      "MutationStep::applyCreateAllocation"
      "MutationStep::compensateRestoreSource"
      "prodigy-elastic-saga"
      "void prepare(CoroutineStack *coro"
      "void apply(CoroutineStack *coro"
      "void compensate(CoroutineStack *coro")
   string(FIND "${gcp_source}" "${required}" found)
   if(found EQUAL -1)
      message(FATAL_ERROR "GCP durable elastic transaction missing: ${required}")
   endif()
endforeach()

foreach(forbidden
      "void assign(CoroutineStack *coro"
      "legacyAllocate"
      "mutationSequence")
   string(FIND "${gcp_source}" "${forbidden}" found)
   if(NOT found EQUAL -1)
      message(FATAL_ERROR "parallel GCP elastic assignment engine remains: ${forbidden}")
   endif()
endforeach()

foreach(forbidden "std::string" "std::vector" "std::unordered_")
   string(FIND "${control_source}" "${forbidden}" found)
   if(NOT found EQUAL -1)
      message(FATAL_ERROR "non-Basics Brain elastic ownership surface remains: ${forbidden}")
   endif()
endforeach()
