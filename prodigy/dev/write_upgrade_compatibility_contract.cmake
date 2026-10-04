if (NOT DEFINED PRODIGY_BINARY OR NOT DEFINED MOTHERSHIP_BINARY OR NOT DEFINED ARCHITECTURE OR NOT DEFINED OUTPUT)
   message(FATAL_ERROR "PRODIGY_BINARY, MOTHERSHIP_BINARY, ARCHITECTURE, and OUTPUT are required")
endif()

foreach (_input IN ITEMS "${PRODIGY_BINARY}" "${MOTHERSHIP_BINARY}")
   if (NOT EXISTS "${_input}")
      message(FATAL_ERROR "upgrade compatibility component is missing: ${_input}")
   endif()
endforeach()

if (NOT ARCHITECTURE MATCHES "^(x86_64|aarch64)$")
   message(FATAL_ERROR "upgrade compatibility architecture is unsupported: ${ARCHITECTURE}")
endif()

function(_prodigy_upgrade_policy_error message_text)
   message(FATAL_ERROR "invalid qualified upgrade release policy: ${message_text}")
endfunction()

function(_prodigy_upgrade_policy_get_string json out_var)
   string(JSON _value ERROR_VARIABLE _error GET "${json}" ${ARGN})
   string(JSON _type ERROR_VARIABLE _type_error TYPE "${json}" ${ARGN})
   if (NOT _error STREQUAL "NOTFOUND" OR NOT _type_error STREQUAL "NOTFOUND" OR NOT _type STREQUAL "STRING" OR _value STREQUAL "")
      _prodigy_upgrade_policy_error("${ARGN} must be a nonempty string")
   endif()
   set(${out_var} "${_value}" PARENT_SCOPE)
endfunction()

function(_prodigy_upgrade_policy_get_uint json out_var)
   string(JSON _value ERROR_VARIABLE _error GET "${json}" ${ARGN})
   string(JSON _type ERROR_VARIABLE _type_error TYPE "${json}" ${ARGN})
   if (NOT _error STREQUAL "NOTFOUND" OR NOT _type_error STREQUAL "NOTFOUND" OR NOT _type STREQUAL "NUMBER" OR NOT _value MATCHES "^[0-9]+$")
      _prodigy_upgrade_policy_error("${ARGN} must be an unsigned integer")
   endif()
   set(${out_var} "${_value}" PARENT_SCOPE)
endfunction()

function(_prodigy_upgrade_policy_exact_members json label)
   set(_allowed ${ARGN})
   string(JSON _length ERROR_VARIABLE _error LENGTH "${json}")
   if (NOT _error STREQUAL "NOTFOUND")
      _prodigy_upgrade_policy_error("${label} must be an object")
   endif()
   if (_length EQUAL 0)
      _prodigy_upgrade_policy_error("${label} must not be empty")
   endif()
   math(EXPR _last "${_length} - 1")
   foreach (_index RANGE 0 ${_last})
      string(JSON _member ERROR_VARIABLE _member_error MEMBER "${json}" ${_index})
      if (NOT _member_error STREQUAL "NOTFOUND")
         _prodigy_upgrade_policy_error("${label} member lookup failed")
      endif()
      list(FIND _allowed "${_member}" _allowed_index)
      if (_allowed_index EQUAL -1)
         _prodigy_upgrade_policy_error("${label} contains unsupported field '${_member}'")
      endif()
   endforeach()
   list(LENGTH _allowed _allowed_length)
   if (NOT _length EQUAL _allowed_length)
      _prodigy_upgrade_policy_error("${label} is missing a required field")
   endif()
endfunction()

function(_prodigy_upgrade_policy_safe_text value label)
   if (NOT "${value}" MATCHES "^[A-Za-z0-9._+-]+$")
      _prodigy_upgrade_policy_error("${label} contains unsupported characters")
   endif()
endfunction()

function(_prodigy_upgrade_policy_sha256 value label)
   string(LENGTH "${value}" _length)
   if (NOT _length EQUAL 64 OR NOT "${value}" MATCHES "^[0-9a-f]+$")
      _prodigy_upgrade_policy_error("${label} must be a canonical lowercase SHA-256")
   endif()
endfunction()

file(SHA256 "${PRODIGY_BINARY}" PRODIGY_SHA256)
file(SHA256 "${MOTHERSHIP_BINARY}" MOTHERSHIP_SHA256)

# A normal local build must never accidentally declare upgrade eligibility.
if (NOT DEFINED RELEASE_POLICY OR RELEASE_POLICY STREQUAL "")
   file(WRITE "${OUTPUT}"
"{\n"
"  \"manifestVersion\": 1,\n"
"  \"releaseID\": \"local-build-unqualified\",\n"
"  \"prodigySHA256\": \"${PRODIGY_SHA256}\",\n"
"  \"containerRetirementJournalVersion\": 3,\n"
"  \"mothershipSHA256\": \"${MOTHERSHIP_SHA256}\",\n"
"  \"architecture\": \"${ARCHITECTURE}\",\n"
"  \"binaryVersion\": \"unknown\",\n"
"  \"disposition\": \"unsupported\",\n"
"  \"compatibility\": {\n"
"    \"wire\": \"unknown\",\n"
"    \"persistentState\": \"unknown\",\n"
"    \"authorityState\": \"unknown\",\n"
"    \"transportTrust\": \"unknown\",\n"
"    \"containerProtocol\": \"unknown\",\n"
"    \"dataPlane\": \"unknown\",\n"
"    \"appState\": \"unknown\"\n"
"  },\n"
"  \"supportedSourceReleaseIDs\": [],\n"
"  \"sourceContracts\": [],\n"
"  \"minimumHealthyBrains\": 1,\n"
"  \"requiredFreeBytes\": 0,\n"
"  \"rollbackMode\": \"unsupported\",\n"
"  \"transportIdentityMode\": \"unsupported\",\n"
"  \"migrationProtocolVersion\": \"none\"\n"
"}\n")
   return()
endif()

if (NOT EXISTS "${RELEASE_POLICY}")
   _prodigy_upgrade_policy_error("file does not exist")
endif()
file(READ "${RELEASE_POLICY}" _prodigy_upgrade_policy)
string(JSON _policy_type ERROR_VARIABLE _policy_error TYPE "${_prodigy_upgrade_policy}")
if (NOT _policy_error STREQUAL "NOTFOUND" OR NOT _policy_type STREQUAL "OBJECT")
   _prodigy_upgrade_policy_error("root must be a JSON object")
endif()

_prodigy_upgrade_policy_exact_members("${_prodigy_upgrade_policy}" "root"
   manifestVersion releaseID binaryVersion architecture disposition compatibility
   supportedSourceReleaseIDs sourceContracts minimumHealthyBrains requiredFreeBytes
   rollbackMode transportIdentityMode migrationProtocolVersion)
_prodigy_upgrade_policy_get_uint("${_prodigy_upgrade_policy}" _manifest_version manifestVersion)
if (NOT _manifest_version EQUAL 1)
   _prodigy_upgrade_policy_error("manifestVersion must be 1")
endif()
_prodigy_upgrade_policy_get_string("${_prodigy_upgrade_policy}" _release_id releaseID)
_prodigy_upgrade_policy_get_string("${_prodigy_upgrade_policy}" _binary_version binaryVersion)
_prodigy_upgrade_policy_get_string("${_prodigy_upgrade_policy}" _architecture architecture)
_prodigy_upgrade_policy_get_string("${_prodigy_upgrade_policy}" _disposition disposition)
_prodigy_upgrade_policy_get_string("${_prodigy_upgrade_policy}" _rollback_mode rollbackMode)
_prodigy_upgrade_policy_get_string("${_prodigy_upgrade_policy}" _transport_identity_mode transportIdentityMode)
_prodigy_upgrade_policy_get_string("${_prodigy_upgrade_policy}" _migration_protocol migrationProtocolVersion)
_prodigy_upgrade_policy_safe_text("${_release_id}" "releaseID")
_prodigy_upgrade_policy_safe_text("${_binary_version}" "binaryVersion")
_prodigy_upgrade_policy_safe_text("${_rollback_mode}" "rollbackMode")
_prodigy_upgrade_policy_safe_text("${_migration_protocol}" "migrationProtocolVersion")
if (NOT _architecture STREQUAL "${ARCHITECTURE}")
   _prodigy_upgrade_policy_error("architecture must equal the built target architecture")
endif()
if (NOT _disposition MATCHES "^(same-cluster-rollout|new-cluster-required)$")
   _prodigy_upgrade_policy_error("disposition must be a qualified release disposition")
endif()
if (NOT _transport_identity_mode MATCHES "^(preserveClusterIdentity|unsupported)$" OR
    (_disposition STREQUAL "same-cluster-rollout" AND NOT _transport_identity_mode STREQUAL "preserveClusterIdentity"))
   _prodigy_upgrade_policy_error("same-cluster releases must preserve cluster transport identity")
endif()
_prodigy_upgrade_policy_get_uint("${_prodigy_upgrade_policy}" _minimum_healthy minimumHealthyBrains)
if (_minimum_healthy LESS 1 OR _minimum_healthy GREATER 4294967295)
   _prodigy_upgrade_policy_error("minimumHealthyBrains must be 1..4294967295")
endif()
_prodigy_upgrade_policy_get_uint("${_prodigy_upgrade_policy}" _required_free_bytes requiredFreeBytes)

string(JSON _compatibility ERROR_VARIABLE _compatibility_error GET "${_prodigy_upgrade_policy}" compatibility)
if (NOT _compatibility_error STREQUAL "NOTFOUND")
   _prodigy_upgrade_policy_error("compatibility is missing")
endif()
_prodigy_upgrade_policy_exact_members("${_compatibility}" "compatibility"
   wire persistentState authorityState transportTrust containerProtocol dataPlane appState)
foreach (_axis IN ITEMS wire persistentState authorityState transportTrust containerProtocol dataPlane appState)
   _prodigy_upgrade_policy_get_string("${_compatibility}" _axis_value ${_axis})
   if (NOT _axis_value MATCHES "^(compatible|incompatible)$")
      _prodigy_upgrade_policy_error("compatibility.${_axis} must be compatible or incompatible")
   endif()
   set(_compatibility_${_axis} "${_axis_value}")
endforeach()

string(JSON _source_id_count ERROR_VARIABLE _source_id_error LENGTH "${_prodigy_upgrade_policy}" supportedSourceReleaseIDs)
string(JSON _source_contract_count ERROR_VARIABLE _source_contract_error LENGTH "${_prodigy_upgrade_policy}" sourceContracts)
if (NOT _source_id_error STREQUAL "NOTFOUND" OR NOT _source_contract_error STREQUAL "NOTFOUND" OR
    _source_id_count LESS 1 OR NOT _source_id_count EQUAL _source_contract_count)
   _prodigy_upgrade_policy_error("supported source IDs and source contracts must be nonempty one-to-one arrays")
endif()

set(_source_ids "")
set(_source_contracts "")
math(EXPR _last_source "${_source_id_count} - 1")
foreach (_index RANGE 0 ${_last_source})
   _prodigy_upgrade_policy_get_string("${_prodigy_upgrade_policy}" _source_id supportedSourceReleaseIDs ${_index})
   _prodigy_upgrade_policy_safe_text("${_source_id}" "supportedSourceReleaseIDs[${_index}]")
   list(FIND _source_ids "${_source_id}" _duplicate_source)
   if (NOT _duplicate_source EQUAL -1)
      _prodigy_upgrade_policy_error("supported source IDs must be unique")
   endif()
   list(APPEND _source_ids "${_source_id}")

   string(JSON _source ERROR_VARIABLE _source_error GET "${_prodigy_upgrade_policy}" sourceContracts ${_index})
   string(JSON _source_type ERROR_VARIABLE _source_type_error TYPE "${_prodigy_upgrade_policy}" sourceContracts ${_index})
   if (NOT _source_error STREQUAL "NOTFOUND" OR NOT _source_type_error STREQUAL "NOTFOUND" OR NOT _source_type STREQUAL "OBJECT")
      _prodigy_upgrade_policy_error("sourceContracts[${_index}] must be an object")
   endif()
   _prodigy_upgrade_policy_exact_members("${_source}" "sourceContracts[${_index}]" releaseID contractSHA256 prodigySHA256 mothershipSHA256)
   _prodigy_upgrade_policy_get_string("${_source}" _source_release releaseID)
   _prodigy_upgrade_policy_get_string("${_source}" _source_contract_sha contractSHA256)
   _prodigy_upgrade_policy_get_string("${_source}" _source_prodigy_sha prodigySHA256)
   _prodigy_upgrade_policy_get_string("${_source}" _source_mothership_sha mothershipSHA256)
   _prodigy_upgrade_policy_safe_text("${_source_release}" "sourceContracts[${_index}].releaseID")
   if (NOT _source_release STREQUAL "${_source_id}")
      _prodigy_upgrade_policy_error("sourceContracts[${_index}] does not declare the matching exact source identity")
   endif()
   _prodigy_upgrade_policy_sha256("${_source_contract_sha}" "sourceContracts[${_index}].contractSHA256")
   _prodigy_upgrade_policy_sha256("${_source_prodigy_sha}" "sourceContracts[${_index}].prodigySHA256")
   _prodigy_upgrade_policy_sha256("${_source_mothership_sha}" "sourceContracts[${_index}].mothershipSHA256")
   list(APPEND _source_contracts "{\"releaseID\": \"${_source_release}\", \"contractSHA256\": \"${_source_contract_sha}\", \"prodigySHA256\": \"${_source_prodigy_sha}\", \"mothershipSHA256\": \"${_source_mothership_sha}\"}")
endforeach()
string(JOIN ", " _source_contract_json ${_source_contracts})
string(JOIN "\", \"" _source_id_json ${_source_ids})

file(WRITE "${OUTPUT}"
"{\n"
"  \"manifestVersion\": 1,\n"
"  \"releaseID\": \"${_release_id}\",\n"
"  \"prodigySHA256\": \"${PRODIGY_SHA256}\",\n"
"  \"mothershipSHA256\": \"${MOTHERSHIP_SHA256}\",\n"
"  \"architecture\": \"${ARCHITECTURE}\",\n"
"  \"binaryVersion\": \"${_binary_version}\",\n"
"  \"disposition\": \"${_disposition}\",\n"
"  \"compatibility\": {\n"
"    \"wire\": \"${_compatibility_wire}\",\n"
"    \"persistentState\": \"${_compatibility_persistentState}\",\n"
"    \"authorityState\": \"${_compatibility_authorityState}\",\n"
"    \"transportTrust\": \"${_compatibility_transportTrust}\",\n"
"    \"containerProtocol\": \"${_compatibility_containerProtocol}\",\n"
"    \"dataPlane\": \"${_compatibility_dataPlane}\",\n"
"    \"appState\": \"${_compatibility_appState}\"\n"
"  },\n"
"  \"supportedSourceReleaseIDs\": [\"${_source_id_json}\"],\n"
"  \"sourceContracts\": [${_source_contract_json}],\n"
"  \"minimumHealthyBrains\": ${_minimum_healthy},\n"
"  \"requiredFreeBytes\": ${_required_free_bytes},\n"
"  \"rollbackMode\": \"${_rollback_mode}\",\n"
"  \"transportIdentityMode\": \"${_transport_identity_mode}\",\n"
"  \"migrationProtocolVersion\": \"${_migration_protocol}\"\n"
"}\n")
