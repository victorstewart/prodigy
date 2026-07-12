foreach(_file IN ITEMS
   "${PRODIGY_ROOT}/ebpf/common/structs.h"
   "${PRODIGY_ROOT}/ebpf/kernel/services.h"
   "${PRODIGY_ROOT}/switchboard/kernel/container.egress.router.ebpf.c"
   "${PRODIGY_ROOT}/switchboard/kernel/container.ingress.router.ebpf.c"
   "${PRODIGY_ROOT}/switchboard/kernel/container.ingress.policy.h"
   "${PRODIGY_ROOT}/switchboard/kernel/container.egress.policy.h"
   "${PRODIGY_ROOT}/switchboard/kernel/container.tcp.flow.h"
   "${PRODIGY_ROOT}/switchboard/kernel/host.ingress.router.ebpf.c"
   "${PRODIGY_ROOT}/switchboard/kernel/whitehole.maps.h"
   "${PRODIGY_ROOT}/switchboard/kernel/whitehole.routing.h"
   "${PRODIGY_ROOT}/prodigy/declared.network.policy.h"
   "${PRODIGY_ROOT}/prodigy/neuron/containers.h"
   "${PRODIGY_ROOT}/prodigy/neuron/neuron.h"
   "${PRODIGY_ROOT}/prodigy/system.container.policy.h")
   file(READ "${_file}" _text)
   string(APPEND _all "\n${_text}")
endforeach()

foreach(_required IN ITEMS
   "ContainerNetworkAccess::declaredOnly"
   "CONTAINER_NETWORK_DECLARED_ONLY"
   "containerNetworkAddressMatches"
   "containerWhiteholePublicEgressIPv4"
   "containerWhiteholePublicEgressIPv6"
   "containerDeclaredInternalEgressIPv6"
   "containerLearnOrAuthorizeInboundTCP"
   "ct_sub_targets"
   "ct_adv_sources"
   "ct_tcp_flows"
   "containerAuthorizeTCPFlow"
   "CONTAINER_SERVICE_PAIRINGS_MAP_ENTRIES"
   "CONTAINER_TCP_FLOWS_MAP_ENTRIES"
   "#if PRODIGY_DECLARED_NETWORK_MAPS"
   "syncDeclaredNetworkPolicy"
   "syncDeclaredNetworkPairingPolicy"
   "denyDeclaredNetwork"
   "container.egress.router.declared.ebpf.o"
   "container.ingress.router.declared.ebpf.o"
   "switchboardPublicDestinationIPv4(htonl(address))"
   "whitehole_reply_binding_lookup"
   "expiresAtNs <= now"
   "whitehole_binding_matches(current, &reply->binding)")
   string(FIND "${_all}" "${_required}" _position)
   if(_position EQUAL -1)
      message(FATAL_ERROR "declared network contract missing: ${_required}")
   endif()
endforeach()

file(READ "${PRODIGY_ROOT}/prodigy/dev/CMakeLists.txt" _dev_cmake)
foreach(_required IN ITEMS
   "OUTPUT container.ingress.router.declared.ebpf.o"
   "OUTPUT container.egress.router.declared.ebpf.o"
   "-DPRODIGY_DECLARED_NETWORK_MAPS=1"
   "container_ingress_declared_router"
   "container_egress_declared_router")
   string(FIND "${_dev_cmake}" "${_required}" _position)
   if(_position EQUAL -1)
      message(FATAL_ERROR "declared network BPF object contract missing: ${_required}")
   endif()
endforeach()

foreach(_legacy IN ITEMS
   "egressWhiteholesOnly"
   "CONTAINER_EGRESS_WHITEHOLES_ONLY"
   "ct_reverse_flows"
   "ct_advertisements"
   "container_reverse_flow")
   string(FIND "${_all}" "${_legacy}" _position)
   if(NOT _position EQUAL -1)
      message(FATAL_ERROR "declared network contract retains legacy concept: ${_legacy}")
   endif()
endforeach()

foreach(_map_name IN ITEMS "ct_sub_targets" "ct_adv_sources" "ct_tcp_flows")
   string(LENGTH "${_map_name}" _map_name_length)
   if(_map_name_length GREATER 15)
      message(FATAL_ERROR "BPF map name exceeds Linux visible-name limit: ${_map_name}")
   endif()
endforeach()

file(READ "${PRODIGY_ROOT}/prodigy/mothership/mothership.cpp" _mothership)
file(READ "${PRODIGY_ROOT}/prodigy/mothership/mothership.deployment.plan.helpers.h" _deployment_helpers)
foreach(_required IN ITEMS
   "subkey.equal(\"count\"_ctv)"
   "mothershipParseWhiteholeCount"
   "mothershipAppendWhiteholeDeclaration"
   "key.equal(\"networkAccess\"_ctv)"
   "mothershipParseDeploymentPlanNetworkAccess"
   "mothershipValidateDeploymentPlanNetworkAccess"
   "MAX_WHITEHOLE_BINDINGS")
   string(FIND "${_mothership}\n${_deployment_helpers}" "${_required}" _position)
   if(_position EQUAL -1)
      message(FATAL_ERROR "declared network deployment contract missing: ${_required}")
   endif()
endforeach()

file(READ "${PRODIGY_ROOT}/switchboard/kernel/whitehole.maps.h" _maps)
if(NOT _maps MATCHES "__type\\(value, struct switchboard_whitehole_binding\\);[^}]*} whiteholes SEC" OR
   NOT _maps MATCHES "__type\\(value, struct switchboard_whitehole_reply\\);[^}]*} white_replies SEC")
   message(FATAL_ERROR "whitehole reply map value contracts are reversed or missing")
endif()

file(READ "${PRODIGY_ROOT}/switchboard/kernel/container.ingress.policy.h" _ingress_policy)
file(READ "${PRODIGY_ROOT}/switchboard/kernel/container.egress.policy.h" _egress_policy)
string(FIND "${_ingress_policy}" "whitehole.routing.h" _ingress_whiteholes)
string(FIND "${_ingress_policy}" "ct_sub_targets" _ingress_subscriptions)
string(FIND "${_egress_policy}" "ct_adv_sources" _egress_advertisements)
if(NOT _ingress_whiteholes EQUAL -1 OR NOT _ingress_subscriptions EQUAL -1 OR NOT _egress_advertisements EQUAL -1)
   message(FATAL_ERROR "declared network ingress/egress policy maps are not directionally isolated")
endif()
