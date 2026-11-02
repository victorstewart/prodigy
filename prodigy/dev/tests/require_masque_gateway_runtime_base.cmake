if (NOT DEFINED PRODIGY_RESOLVED_TARGET_ARCH OR PRODIGY_RESOLVED_TARGET_ARCH STREQUAL "")
   message(FATAL_ERROR "MASQUE gateway runtime validation requires PRODIGY_RESOLVED_TARGET_ARCH.")
endif()

if (NOT DEFINED PRODIGY_MASQUE_GATEWAY_RUNTIME_BASE OR PRODIGY_MASQUE_GATEWAY_RUNTIME_BASE STREQUAL "")
   message(FATAL_ERROR "Cross-cluster MASQUE gateway requires an explicit digest-pinned PRODIGY_MASQUE_GATEWAY_RUNTIME_BASE for ${PRODIGY_RESOLVED_TARGET_ARCH}.")
endif()

string(REGEX MATCH "^remote[ \t]+dockerhub[ \t]+[^ \t@]+@sha256:([0-9a-f]+)[ \t]+for[ \t]+${PRODIGY_RESOLVED_TARGET_ARCH}$"
   _prodigy_masque_gateway_runtime_base_match "${PRODIGY_MASQUE_GATEWAY_RUNTIME_BASE}")
if (_prodigy_masque_gateway_runtime_base_match STREQUAL "")
   message(FATAL_ERROR "PRODIGY_MASQUE_GATEWAY_RUNTIME_BASE must be exactly a dockerhub repository@sha256 digest pinned for ${PRODIGY_RESOLVED_TARGET_ARCH}.")
endif()

set(_prodigy_masque_gateway_runtime_digest "${CMAKE_MATCH_1}")
string(LENGTH "${_prodigy_masque_gateway_runtime_digest}" _prodigy_masque_gateway_runtime_digest_length)
if (NOT _prodigy_masque_gateway_runtime_digest_length EQUAL 64)
   message(FATAL_ERROR "PRODIGY_MASQUE_GATEWAY_RUNTIME_BASE must contain a 64-character lowercase sha256 digest.")
endif()
