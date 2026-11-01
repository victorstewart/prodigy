if (NOT DEFINED PRODIGY_ROOT)
   message(FATAL_ERROR "PRODIGY_ROOT is required")
endif()

file(READ "${PRODIGY_ROOT}/switchboard/kernel/overlay.encap.h" OVERLAY_ENCAP)
file(READ "${PRODIGY_ROOT}/switchboard/kernel/egress.routing.h" EGRESS)
file(READ "${PRODIGY_ROOT}/switchboard/kernel/container.egress.router.ebpf.c" CONTAINER_EGRESS)
file(READ "${PRODIGY_ROOT}/switchboard/kernel/host.ingress.router.ebpf.c" HOST_INGRESS)
file(READ "${PRODIGY_ROOT}/prodigy/dev/tests/cross_cluster_masque_gateway.DiscombobuFile.in" MASQUE_RECIPE)
file(READ "${PRODIGY_ROOT}/prodigy/dev/CMakeLists.txt" DEV_CMAKE)

foreach(REQUIRED IN ITEMS
   "FROM @PRODIGY_MASQUE_GATEWAY_RUNTIME_BASE@"
   "library/archlinux@sha256:5b0bb8064e4fcb1b2092fdee45e959c3c2d18dc7fb986a046aaddaae4d731993 for x86_64"
   "remote add dockerhub docker.io"
   "explicit digest-pinned PRODIGY_MASQUE_GATEWAY_RUNTIME_BASE"
   "must be exactly a dockerhub repository@sha256 digest pinned"
   "64-character lowercase sha256 digest")
   if (REQUIRED STREQUAL "FROM @PRODIGY_MASQUE_GATEWAY_RUNTIME_BASE@")
      string(FIND "${MASQUE_RECIPE}" "${REQUIRED}" OFFSET)
   else()
      string(FIND "${DEV_CMAKE}" "${REQUIRED}" OFFSET)
   endif()
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "MASQUE gateway target runtime contract is missing: ${REQUIRED}")
   endif()
endforeach()

set(MASQUE_RUNTIME_BASE_PATTERN "^remote[ \t]+dockerhub[ \t]+[^ \t@]+@sha256:([0-9a-f]+)[ \t]+for[ \t]+aarch64$")
set(MASQUE_RUNTIME_BASE_VALID "remote dockerhub example/gateway@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef for aarch64")
if (NOT MASQUE_RUNTIME_BASE_VALID MATCHES "${MASQUE_RUNTIME_BASE_PATTERN}")
   message(FATAL_ERROR "MASQUE runtime-base grammar rejected a valid pinned aarch64 override")
endif()
foreach(MASQUE_RUNTIME_BASE_INVALID IN ITEMS
   "remote dockerhub example/gateway:latest for aarch64"
   "remote dockerhub example/gateway@sha256:0123456789abcdef for aarch64"
   "remote dockerhub example/gateway@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef for x86_64"
   "remote dockerhub example/gateway@sha256:0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef for aarch64")
   if (MASQUE_RUNTIME_BASE_INVALID MATCHES "${MASQUE_RUNTIME_BASE_PATTERN}")
      string(LENGTH "${CMAKE_MATCH_1}" MASQUE_RUNTIME_BASE_DIGEST_LENGTH)
      if (MASQUE_RUNTIME_BASE_DIGEST_LENGTH EQUAL 64)
         message(FATAL_ERROR "MASQUE runtime-base grammar accepted an unpinned, wrong-architecture, or noncanonical override: ${MASQUE_RUNTIME_BASE_INVALID}")
      endif()
   endif()
endforeach()

foreach(REQUIRED IN ITEMS
   "switchboardCompleteMasqueGatewayInjection"
   "switchboardMasqueGatewayRedirectPermitted(route->use_gateway_mac, fragment, true) == false"
   "redirectContainerFragment(fragment, true) == false"
   "skb->mark = SWITCHBOARD_MASQUE_GATEWAY_INJECTION_SKB_MARK"
   "return TC_ACT_REDIRECT")
   string(FIND "${OVERLAY_ENCAP}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "MASQUE injection completion contract is missing: ${REQUIRED}")
   endif()
endforeach()

foreach(REQUIRED IN ITEMS
   "*action = switchboardCompleteMasqueGatewayInjection(skb, route)")
   string(FIND "${OVERLAY_ENCAP}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "hosted or wormhole injection completion is missing: ${REQUIRED}")
   endif()
endforeach()

foreach(REQUIRED IN ITEMS
   "return switchboardCompleteMasqueGatewayInjection(skb, route)")
   string(FIND "${EGRESS}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "ordinary egress injection completion is missing: ${REQUIRED}")
   endif()
endforeach()

foreach(REQUIRED IN ITEMS
   "int injectionAction = switchboardCompleteMasqueGatewayInjection(skb, route)"
   "if (injectionAction == TC_ACT_REDIRECT) return NETKIT_REDIRECT"
   "if (outbound_action == TC_ACT_REDIRECT) return NETKIT_REDIRECT")
   string(FIND "${CONTAINER_EGRESS}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "container egress must preserve local gateway redirect: ${REQUIRED}")
   endif()
endforeach()

string(FIND "${HOST_INGRESS}" "return switchboardCompleteMasqueGatewayInjection(skb, route)" HOST_WORMHOLE)
if (HOST_WORMHOLE EQUAL -1)
   message(FATAL_ERROR "host ingress wormhole path can silently pass a local gateway route")
endif()
