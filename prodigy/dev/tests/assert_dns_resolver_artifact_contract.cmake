if (NOT DEFINED PRODIGY_ROOT)
   message(FATAL_ERROR "PRODIGY_ROOT is required")
endif()

file(READ "${PRODIGY_ROOT}/prodigy/dev/CMakeLists.txt" BUILD)
file(READ "${PRODIGY_ROOT}/prodigy/dns/DiscombobuFile.in" DISCOMBOBUFILE)
file(READ "${PRODIGY_ROOT}/prodigy/dns/prodigy-dns-resolver.deployment.plan.v1.json.in" PLAN)

foreach(REQUIRED IN ITEMS
   "add_executable(prodigy_dns_resolver \${PRODIGY_ROOT}/prodigy/dns/resolver.cpp)"
   "list(REMOVE_ITEM PRODIGY_COMMON_LINK_TARGETS prodigy_dns_resolver prodigy_dns_resolver_unit)"
   "depos_link(prodigy_dns_resolver PRIVATE basics::basics)"
   "set(PRODIGY_CARES_TARGETS"
   "prodigy_mothership_host_runtime_unit"
   "--kind app"
   "--container-artifact \"\${PRODIGY_DNS_RESOLVER_CONTAINER_ARTIFACT}\""
   "--container-plan \"\${PRODIGY_DNS_RESOLVER_DEPLOYMENT_PLAN}\"")
   string(FIND "${BUILD}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "DNS resolver build contract missing: ${REQUIRED}")
   endif()
endforeach()
string(FIND "${BUILD}" "target_compile_definitions(prodigy_dns_resolver " DEBUG_OFFSET)
if (NOT DEBUG_OFFSET EQUAL -1)
   message(FATAL_ERROR "DNS resolver production artifact must not enable diagnostic logging")
endif()

foreach(REQUIRED IN ITEMS
   "FROM scratch for @PRODIGY_RESOLVED_TARGET_ARCH@"
   "COPY {resolver} ./prodigy-dns-resolver /app/prodigy-dns-resolver"
   "SURVIVE /app/prodigy-dns-resolver"
   "EXECUTE [\"/app/prodigy-dns-resolver\"]")
   string(FIND "${DISCOMBOBUFILE}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "DNS resolver DiscombobuFile contract missing: ${REQUIRED}")
   endif()
endforeach()
foreach(FORBIDDEN IN ITEMS ".ebpf.o" "ingress" "egress" "/root/prodigy")
   string(FIND "${DISCOMBOBUFILE}" "${FORBIDDEN}" OFFSET)
   if (NOT OFFSET EQUAL -1)
      message(FATAL_ERROR "DNS resolver app artifact contains forbidden payload: ${FORBIDDEN}")
   endif()
endforeach()

string(JSON APPLICATION_ID GET "${PLAN}" config applicationID)
string(JSON ARCHITECTURE GET "${PLAN}" config architecture)
string(JSON N_BASE GET "${PLAN}" stateless nBase)
string(JSON MAX_RACK GET "${PLAN}" stateless maxPerRackRatio)
string(JSON MAX_MACHINE GET "${PLAN}" stateless maxPerMachineRatio)
string(JSON NETWORK_ACCESS GET "${PLAN}" networkAccess)
string(JSON HOST_NETWORK GET "${PLAN}" useHostNetworkNamespace)
string(JSON SUBSCRIPTIONS LENGTH "${PLAN}" subscriptions)
string(JSON WORMHOLES LENGTH "${PLAN}" wormholes)
string(JSON ADVERTISEMENTS LENGTH "${PLAN}" advertisements)
string(JSON SERVICE GET "${PLAN}" advertisements 0 service)
string(JSON PORT GET "${PLAN}" advertisements 0 port)
if (NOT APPLICATION_ID EQUAL 1 OR NOT ARCHITECTURE STREQUAL "@PRODIGY_RESOLVED_TARGET_ARCH@" OR NOT N_BASE EQUAL 2 OR
    NOT MAX_RACK EQUAL 0.5 OR NOT MAX_MACHINE EQUAL 0.5 OR
    NOT NETWORK_ACCESS STREQUAL "declaredOnly" OR HOST_NETWORK OR
    NOT SUBSCRIPTIONS EQUAL 0 OR NOT WORMHOLES EQUAL 0 OR
    NOT ADVERTISEMENTS EQUAL 1 OR
    NOT SERVICE STREQUAL "MeshRegistry::DNS::resolver" OR NOT PORT EQUAL 5353)
   message(FATAL_ERROR "DNS resolver deployment plan violates its built-in service contract")
endif()

string(JSON WHITEHOLE_COUNT LENGTH "${PLAN}" whiteholes)
if (NOT WHITEHOLE_COUNT EQUAL 4)
   message(FATAL_ERROR "DNS resolver deployment plan must declare four whitehole pools")
endif()
set(WHITEHOLES)
foreach(INDEX RANGE 0 3)
   string(JSON TRANSPORT GET "${PLAN}" whiteholes ${INDEX} transport)
   string(JSON FAMILY GET "${PLAN}" whiteholes ${INDEX} family)
   string(JSON SOURCE GET "${PLAN}" whiteholes ${INDEX} source)
   string(JSON COUNT GET "${PLAN}" whiteholes ${INDEX} count)
   list(APPEND WHITEHOLES "${TRANSPORT}/${FAMILY}/${SOURCE}/${COUNT}")
endforeach()
list(SORT WHITEHOLES)
set(EXPECTED_WHITEHOLES
   "quic/ipv4/hostPublicAddress/2"
   "quic/ipv6/hostPublicAddress/2"
   "tcp/ipv4/hostPublicAddress/2"
   "tcp/ipv6/hostPublicAddress/2")
list(SORT EXPECTED_WHITEHOLES)
if (NOT WHITEHOLES STREQUAL EXPECTED_WHITEHOLES)
   message(FATAL_ERROR "DNS resolver deployment plan has the wrong whitehole pools: ${WHITEHOLES}")
endif()

foreach(FORBIDDEN IN ITEMS "apiCredentials" "tlsCredentials" "credentialUUID" "nThreads")
   string(FIND "${PLAN}" "\"${FORBIDDEN}\"" OFFSET)
   if (NOT OFFSET EQUAL -1)
      message(FATAL_ERROR "DNS resolver deployment plan contains forbidden field: ${FORBIDDEN}")
   endif()
endforeach()

file(GLOB_RECURSE PRODIGY_PRODUCTION_CPP_SOURCES
   LIST_DIRECTORIES false
   RELATIVE "${PRODIGY_ROOT}"
   "${PRODIGY_ROOT}/prodigy/*.h"
   "${PRODIGY_ROOT}/prodigy/*.hh"
   "${PRODIGY_ROOT}/prodigy/*.hpp"
   "${PRODIGY_ROOT}/prodigy/*.cc"
   "${PRODIGY_ROOT}/prodigy/*.cpp"
   "${PRODIGY_ROOT}/prodigy/*.cxx"
   "${PRODIGY_ROOT}/prodigy/*.c"
   "${PRODIGY_ROOT}/prodigy/*.py"
   "${PRODIGY_ROOT}/prodigy/*.rs"
   "${PRODIGY_ROOT}/prodigy/*.sh"
)
list(FILTER PRODIGY_PRODUCTION_CPP_SOURCES EXCLUDE REGEX "/target/")

# These exact files own provider HTTP policy, not resolver backends.
set(PRODIGY_HOST_CONTROL_NETWORK_OWNERS
   "prodigy/dns/provider.http.h"
   "prodigy/iaas/aws/aws.h"
   "prodigy/iaas/azure/azure.cpp"
   "prodigy/iaas/gcp/gcp.cpp"
   "prodigy/iaas/vultr/vultr.cpp"
   "prodigy/iaas/vultr/vultr.h"
)
set(PRODIGY_RESOLVER_OWNERS
   "prodigy/dns/resolver.config.h"
   "prodigy/dns/resolver.cpp"
   "prodigy/dns/resolver.h"
   "prodigy/dns/resolver.service.h"
   "prodigy/host.control.network.h"
   "prodigy/dev/tests/prodigy_host_control_network_unit.cpp"
)
list(SORT PRODIGY_PRODUCTION_CPP_SOURCES)
foreach(SOURCE IN LISTS PRODIGY_PRODUCTION_CPP_SOURCES)
   file(READ "${PRODIGY_ROOT}/${SOURCE}" CONTENTS)
   list(FIND PRODIGY_RESOLVER_OWNERS "${SOURCE}" RESOLVER_OWNER_INDEX)
   if (RESOLVER_OWNER_INDEX EQUAL -1)
      foreach(FORBIDDEN IN ITEMS
         "RingAsyncDnsResolver"
         "async.dns.cares"
      )
         string(FIND "${CONTENTS}" "${FORBIDDEN}" OFFSET)
         if (NOT OFFSET EQUAL -1)
            message(FATAL_ERROR
               "${SOURCE} owns the c-ares resolver outside the DNS service: ${FORBIDDEN}"
            )
         endif()
      endforeach()
      string(REGEX MATCH "(^|[^A-Za-z0-9_])ares_[A-Za-z0-9_]+" CARES_SYMBOL "${CONTENTS}")
      if (CARES_SYMBOL)
         message(FATAL_ERROR
            "${SOURCE} owns the c-ares resolver outside the DNS service: ${CARES_SYMBOL}"
         )
      endif()
   endif()

   foreach(FORBIDDEN IN ITEMS
      "<netdb.h>"
      "getaddrinfo"
      "getaddrinfo_a"
      "freeaddrinfo"
      "gethostbyaddr"
      "gethostbyname"
      "getnameinfo"
      "res_query"
      "res_search"
      "res_send"
   )
      string(FIND "${CONTENTS}" "${FORBIDDEN}" OFFSET)
      if (NOT OFFSET EQUAL -1)
         message(FATAL_ERROR "${SOURCE} owns synchronous DNS: ${FORBIDDEN}")
      endif()
   endforeach()

   list(FIND PRODIGY_HOST_CONTROL_NETWORK_OWNERS "${SOURCE}" HOST_CONTROL_OWNER_INDEX)
   if (HOST_CONTROL_OWNER_INDEX EQUAL -1)
      foreach(FORBIDDEN IN ITEMS
         "curl_easy_"
         "curl_multi_"
      )
         string(FIND "${CONTENTS}" "${FORBIDDEN}" OFFSET)
         if (NOT OFFSET EQUAL -1)
            message(FATAL_ERROR
               "${SOURCE} owns local resolution or raw HTTP outside the explicit host/control boundary: ${FORBIDDEN}"
            )
         endif()
      endforeach()
   endif()
endforeach()
