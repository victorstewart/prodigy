if (NOT DEFINED PRODIGY_ROOT)
   message(FATAL_ERROR "PRODIGY_ROOT is required")
endif()

file(READ "${PRODIGY_ROOT}/switchboard/common/structs.h" COMMON)
file(READ "${PRODIGY_ROOT}/switchboard/kernel/host.ingress.router.ebpf.c" HOST_INGRESS)

foreach(REQUIRED IN ITEMS
   "switchboardHostIngressOverlayMinimumLinearBytes(__be16 wire_protocol, __u8 inner_protocol, __u8 transport_protocol)"
   "switchboardPacketBudgetTransportHeaderBytes(transport_protocol)")
   string(FIND "${COMMON}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "host-ingress overlay sizing contract is missing: ${REQUIRED}")
   endif()
endforeach()

foreach(REQUIRED IN ITEMS
   "overlay_inner_ipv4_matches_declared_endpoint"
   "overlay_inner_ipv6_matches_declared_endpoint"
   "whitehole_binding_lookup(portal.proto, false, &portal.addr4, portal.port, &binding)"
   "whitehole_binding_lookup(portal.proto, true, portal.addr6, portal.port, &binding)"
   "inner_protocol != IPPROTO_IPIP && inner_protocol != IPPROTO_IPV6"
   "overlay_minimum_linear_bytes(skb, eth->h_proto, &minimum_linear_bytes)"
   "bpf_skb_pull_data(skb, minimum_linear_bytes)")
   string(FIND "${HOST_INGRESS}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "host-ingress overlay dispatch contract is missing: ${REQUIRED}")
   endif()
endforeach()

foreach(FORBIDDEN IN ITEMS
   "overlay_inner_ipv4_matches_external_portal"
   "overlay_inner_ipv6_matches_external_portal"
   "switchboardHostIngressOverlayMinimumLinearBytes(eth->h_proto)")
   string(FIND "${HOST_INGRESS}" "${FORBIDDEN}" OFFSET)
   if (NOT OFFSET EQUAL -1)
      message(FATAL_ERROR "host-ingress overlay retains incomplete dispatch: ${FORBIDDEN}")
   endif()
endforeach()

string(FIND "${HOST_INGRESS}" "bool decapped =" DECAP_OFFSET)
if (DECAP_OFFSET EQUAL -1)
   message(FATAL_ERROR "host-ingress overlay decapsulation is missing")
endif()
string(SUBSTRING "${HOST_INGRESS}" ${DECAP_OFFSET} -1 POST_DECAP)
string(FIND "${POST_DECAP}" "bool handledDecappedIPv6Portal" IPV6_PORTAL_OFFSET)
string(FIND "${POST_DECAP}" "if (localSubnetContainsDaddr(daddr6))" IPV6_ROUTE_OFFSET)
if (IPV6_PORTAL_OFFSET EQUAL -1 OR
    IPV6_ROUTE_OFFSET LESS IPV6_PORTAL_OFFSET)
   message(FATAL_ERROR "decapped IPv6 portals must be dispatched before private IPv6 routing")
endif()
