if (NOT DEFINED PRODIGY_ROOT)
   message(FATAL_ERROR "PRODIGY_ROOT is required")
endif()

file(READ "${PRODIGY_ROOT}/prodigy/dns/control.bootstrap.h" BOOTSTRAP)
file(READ "${PRODIGY_ROOT}/prodigy/dns/control.client.h" CLIENT)
file(READ "${PRODIGY_ROOT}/prodigy/dns/control.leases.h" LEASES)
file(READ "${PRODIGY_ROOT}/prodigy/host.control.network.h" HOST)
file(READ "${PRODIGY_ROOT}/prodigy/prodigy.h" PRODIGY)
file(READ "${PRODIGY_ROOT}/prodigy/mothership/mothership.ring.runtime.h" MOTHERSHIP)
file(READ "${PRODIGY_ROOT}/prodigy/persistent.state.h" PERSISTENCE)
file(READ "${PRODIGY_ROOT}/prodigy/brain/brain.h" BRAIN)
file(READ "${PRODIGY_ROOT}/enums/datacenter.h" TOPICS)
file(READ "${PRODIGY_ROOT}/prodigy/ingress.validation.h" INGRESS)

foreach(REQUIRED IN ITEMS
   "defaultProdigyControlBootstrapPath"
   "defaultMothershipControlBootstrapPath"
   "controlBootstrapPath"
   "validControlBootstrapMetadata"
   "O_NOFOLLOW"
   "metadata.st_uid == 0"
   "(metadata.st_mode & 0777) == 0600"
   "endpoint.is6 == false"
   "DNS control pairing lease is expired")
   string(FIND "${BOOTSTRAP}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "DNS control bootstrap contract missing: ${REQUIRED}")
   endif()
endforeach()

foreach(REQUIRED IN ITEMS
   "MothershipTopic::manageDnsControlPairing"
   "manageDnsControlPairing(operation)"
   "persistDnsControlPairingState"
   "dispatchDnsControlPairing"
   "container->advertisementPairing("
   "commitMasterAuthorityStateChange()")
   string(FIND "${BRAIN}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "DNS management pairing operation missing: ${REQUIRED}")
   endif()
endforeach()
string(FIND "${TOPICS}" "manageDnsControlPairing" TOPIC_OFFSET)
string(FIND "${INGRESS}" "MothershipTopic::manageDnsControlPairing" INGRESS_OFFSET)
if (TOPIC_OFFSET EQUAL -1 OR INGRESS_OFFSET EQUAL -1)
   message(FATAL_ERROR "DNS control pairing operation is not admitted as one bidirectional Mothership topic")
endif()
foreach(REQUIRED IN ITEMS "OPENSSL_cleanse(bytes.data(), bytes.reservedBytes())" "expectedRole && role != *expectedRole")
   string(FIND "${BOOTSTRAP}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "DNS bootstrap secret isolation is missing: ${REQUIRED}")
   endif()
endforeach()

foreach(REQUIRED IN ITEMS
   "class ControlClient final"
   "AegisStream stream;"
   "ProdigySDK::Opinionated::Dns::Client"
   "client.sessionReady()"
   "serviceLost"
   "transportConnected"
   "Ring::queueConnect"
   "AF_INET6"
   "maximumReconnectMilliseconds")
   string(FIND "${CLIENT}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "DNS direct Ring/Aegis client contract missing: ${REQUIRED}")
   endif()
endforeach()

foreach(FORBIDDEN IN ITEMS
   "RingAsyncDnsResolver"
   "async.dns.cares"
   "ares_"
   "getaddrinfo"
   "std::thread"
   "NeuronHub"
   "AegisHub"
   "getenv")
   string(FIND "${CLIENT}" "${FORBIDDEN}" OFFSET)
   if (NOT OFFSET EQUAL -1)
      message(FATAL_ERROR "DNS direct client contains forbidden ownership: ${FORBIDDEN}")
   endif()
endforeach()

foreach(REQUIRED IN ITEMS
   "maximumLeases = 1024"
   "nextDnsControlPairingGeneration"
   "state.dnsControlPairingLeases"
   "persist(failure) == false"
   "pair(lease, true, failure)"
   "pair(lease, false, failure)")
   string(FIND "${LEASES}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "DNS control pairing lease contract missing: ${REQUIRED}")
   endif()
endforeach()

foreach(REQUIRED IN ITEMS
   "ProdigyPersistentDnsControlPairingSecret"
   "dnsControlPairingSecrets"
   "runtimeState.dnsControlPairingLeases")
   string(FIND "${PERSISTENCE}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "DNS control pairing persistence contract missing: ${REQUIRED}")
   endif()
endforeach()

foreach(CONTENT IN ITEMS HOST PRODIGY MOTHERSHIP)
   foreach(FORBIDDEN IN ITEMS "RingAsyncDnsResolver" "async.dns.cares" "ares_")
      string(FIND "${${CONTENT}}" "${FORBIDDEN}" OFFSET)
      if (NOT OFFSET EQUAL -1)
         message(FATAL_ERROR "${CONTENT} still embeds c-ares ownership: ${FORBIDDEN}")
      endif()
   endforeach()
endforeach()

foreach(REQUIRED IN ITEMS
   "ProdigyDns::ControlClient resolver;"
   "resolver.sessionReady()"
   "readControlBootstrap"
   "controlBootstrapPath(role)")
   string(FIND "${HOST}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "host DNS control-service wiring missing: ${REQUIRED}")
   endif()
endforeach()
string(FIND "${PRODIGY}" "hostControlNetwork->sessionReady()" PRODIGY_GATE)
string(FIND "${MOTHERSHIP}" "network.sessionReady()" MOTHERSHIP_GATE)
string(FIND "${MOTHERSHIP}" "ProdigyDnsControlClientRole::mothership" MOTHERSHIP_ROLE)
if (PRODIGY_GATE EQUAL -1 OR MOTHERSHIP_GATE EQUAL -1 OR MOTHERSHIP_ROLE EQUAL -1)
   message(FATAL_ERROR "Prodigy and Mothership must gate provider readiness on sessionReady()")
endif()

string(FIND "${PRODIGY}" "hostControlNetwork = std::make_unique<HostControlNetworkType>()" PRODIGY_NETWORK_CREATE)
string(FIND "${PRODIGY}" "hostControlNetwork->sessionReady()" PRODIGY_SESSION_GATE)
string(FIND "${PRODIGY}" "neuron = new NeuronType(*hostControlNetwork)" PRODIGY_NEURON_CREATE)
if (PRODIGY_NETWORK_CREATE EQUAL -1 OR PRODIGY_SESSION_GATE EQUAL -1 OR
    PRODIGY_NEURON_CREATE EQUAL -1 OR
    PRODIGY_NETWORK_CREATE GREATER_EQUAL PRODIGY_SESSION_GATE OR
    PRODIGY_SESSION_GATE GREATER_EQUAL PRODIGY_NEURON_CREATE)
   message(FATAL_ERROR "Prodigy DNS control bootstrap/session must precede Neuron construction")
endif()

string(FIND "${MOTHERSHIP}" "ProdigyHostControlNetwork network(ProdigyDnsControlClientRole::mothership)" MOTHERSHIP_NETWORK_CREATE)
string(FIND "${MOTHERSHIP}" "Worker worker(*this, network)" MOTHERSHIP_WORKER_CREATE)
if (MOTHERSHIP_NETWORK_CREATE EQUAL -1 OR MOTHERSHIP_WORKER_CREATE EQUAL -1 OR
    MOTHERSHIP_NETWORK_CREATE GREATER_EQUAL MOTHERSHIP_WORKER_CREATE)
   message(FATAL_ERROR "Mothership role-bound DNS control bootstrap must precede worker construction")
endif()

foreach(CONTENT IN ITEMS BOOTSTRAP HOST)
   foreach(FORBIDDEN IN ITEMS "getaddrinfo" "getenv" "RingAsyncDnsResolver" "async.dns.cares" "ares_")
      string(FIND "${${CONTENT}}" "${FORBIDDEN}" OFFSET)
      if (NOT OFFSET EQUAL -1)
         message(FATAL_ERROR "${CONTENT} DNS bootstrap path contains forbidden fallback: ${FORBIDDEN}")
      endif()
   endforeach()
endforeach()
