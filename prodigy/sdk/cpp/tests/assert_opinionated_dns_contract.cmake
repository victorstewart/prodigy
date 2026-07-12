# Copyright 2026 Victor Stewart
# SPDX-License-Identifier: Apache-2.0

if (NOT DEFINED PRODIGY_SDK_SOURCE_DIR)
  message(FATAL_ERROR "PRODIGY_SDK_SOURCE_DIR is required")
endif()

file(READ
  "${PRODIGY_SDK_SOURCE_DIR}/cpp/opinionated/dns_wire.h"
  _prodigy_dns_wire
)
file(READ
  "${PRODIGY_SDK_SOURCE_DIR}/cpp/opinionated/dns_client.h"
  _prodigy_dns_client
)
set(_prodigy_dns_sources "${_prodigy_dns_wire}\n${_prodigy_dns_client}")

foreach(_prodigy_dns_forbidden IN ITEMS
  "std::string"
  "std::vector"
  "std::unordered_"
  "std::map<"
  "RingAsyncDnsResolver"
  "async.dns.cares"
  "getaddrinfo"
  "ares_"
  "struct ResolveRequest"
  "struct ResolveResult"
  "memcpy(&bool"
)
  string(FIND
    "${_prodigy_dns_sources}"
    "${_prodigy_dns_forbidden}"
    _prodigy_dns_forbidden_index
  )
  if (NOT _prodigy_dns_forbidden_index EQUAL -1)
    message(FATAL_ERROR "Opinionated DNS SDK contains forbidden '${_prodigy_dns_forbidden}'")
  endif()
endforeach()

foreach(_prodigy_dns_required IN ITEMS
  "class Client final : public AsyncDnsClient"
  "maximumPendingRequests = 64"
  "externalCallDepth"
  "if (externalCallDepth != 0 || !pending.empty())"
  "struct Resolve"
  "struct Cancel"
  "struct Session"
  "maximumAnswers = 32"
  "maximumHostnameBytes = 253"
  "maximumDeadlineMilliseconds = 30000"
  "bytell_hash_map<std::uint64_t, Pending> pending"
  "String hostname;"
  "String service;"
  "bool sessionReady(void) const"
  "request.transportGeneration = 0"
  "void replayPending(void)"
  "transportConnected(std::uint64_t connectedService,"
  "serviceLost(std::uint64_t lostService,"
  "handleFrame(std::uint64_t sourceService,"
  "generation != transportGeneration"
)
  string(FIND
    "${_prodigy_dns_sources}"
    "${_prodigy_dns_required}"
    _prodigy_dns_required_index
  )
  if (_prodigy_dns_required_index EQUAL -1)
    message(FATAL_ERROR "Opinionated DNS SDK is missing '${_prodigy_dns_required}'")
  endif()
endforeach()
