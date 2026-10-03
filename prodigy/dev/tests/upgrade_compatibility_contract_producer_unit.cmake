if (NOT DEFINED PRODIGY_ROOT)
   message(FATAL_ERROR "PRODIGY_ROOT is required")
endif()

set(GENERATOR "${PRODIGY_ROOT}/prodigy/dev/write_upgrade_compatibility_contract.cmake")
if (NOT EXISTS "${GENERATOR}")
   message(FATAL_ERROR "upgrade contract generator is missing")
endif()

set(WORK "${CMAKE_CURRENT_BINARY_DIR}/upgrade-compatibility-contract-producer-unit")
file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}")
set(PRODIGY_BINARY "${WORK}/prodigy")
set(MOTHERSHIP_BINARY "${WORK}/mothership")
file(WRITE "${PRODIGY_BINARY}" "fake prodigy bytes\n")
file(WRITE "${MOTHERSHIP_BINARY}" "fake mothership bytes\n")
file(SHA256 "${PRODIGY_BINARY}" PRODIGY_SHA256)
file(SHA256 "${MOTHERSHIP_BINARY}" MOTHERSHIP_SHA256)

function(run_generator name policy expect_success)
   set(output "${WORK}/${name}.json")
   set(command
      "-DPRODIGY_BINARY=${PRODIGY_BINARY}"
      "-DMOTHERSHIP_BINARY=${MOTHERSHIP_BINARY}"
      "-DARCHITECTURE=aarch64"
      "-DOUTPUT=${output}")
   if (NOT policy STREQUAL "")
      list(APPEND command "-DRELEASE_POLICY=${policy}")
   endif()
   execute_process(COMMAND "${CMAKE_COMMAND}" ${command} -P "${GENERATOR}"
                   RESULT_VARIABLE result OUTPUT_VARIABLE stdout ERROR_VARIABLE stderr)
   if (expect_success AND NOT result EQUAL 0)
      message(FATAL_ERROR "${name} unexpectedly failed: ${stdout}${stderr}")
   endif()
   if (NOT expect_success AND result EQUAL 0)
      message(FATAL_ERROR "${name} unexpectedly succeeded")
   endif()
   set(${name}_OUTPUT "${output}" PARENT_SCOPE)
endfunction()

run_generator(default "" TRUE)
file(READ "${default_OUTPUT}" DEFAULT_CONTRACT)
string(JSON DEFAULT_RELEASE GET "${DEFAULT_CONTRACT}" releaseID)
string(JSON DEFAULT_DISPOSITION GET "${DEFAULT_CONTRACT}" disposition)
string(JSON DEFAULT_PRODIGY_SHA GET "${DEFAULT_CONTRACT}" prodigySHA256)
string(JSON DEFAULT_MOTHERSHIP_SHA GET "${DEFAULT_CONTRACT}" mothershipSHA256)
string(JSON DEFAULT_IDENTITY_MODE GET "${DEFAULT_CONTRACT}" transportIdentityMode)
string(JSON DEFAULT_AXIS GET "${DEFAULT_CONTRACT}" compatibility wire)
if (NOT DEFAULT_RELEASE STREQUAL "local-build-unqualified" OR NOT DEFAULT_DISPOSITION STREQUAL "unsupported" OR
    NOT DEFAULT_IDENTITY_MODE STREQUAL "unsupported" OR NOT DEFAULT_AXIS STREQUAL "unknown" OR NOT DEFAULT_PRODIGY_SHA STREQUAL PRODIGY_SHA256 OR
    NOT DEFAULT_MOTHERSHIP_SHA STREQUAL MOTHERSHIP_SHA256)
   message(FATAL_ERROR "default producer contract is not fail-closed or does not bind computed component hashes")
endif()

set(POLICY "${WORK}/qualified-policy.json")
file(WRITE "${POLICY}" [=[{
  "manifestVersion": 1,
  "releaseID": "v0.4.13",
  "binaryVersion": "0.4.13",
  "architecture": "aarch64",
  "disposition": "same-cluster-rollout",
  "compatibility": {
    "wire": "compatible",
    "persistentState": "compatible",
    "authorityState": "compatible",
    "transportTrust": "compatible",
    "containerProtocol": "compatible",
    "dataPlane": "compatible",
    "appState": "compatible"
  },
  "supportedSourceReleaseIDs": ["v0.4.12"],
  "sourceContracts": [{
    "releaseID": "v0.4.12",
    "contractSHA256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "prodigySHA256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "mothershipSHA256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
  }],
  "minimumHealthyBrains": 3,
  "requiredFreeBytes": 4096,
  "rollbackMode": "forward-only",
  "transportIdentityMode": "preserveClusterIdentity",
  "migrationProtocolVersion": "1"
}]=])
run_generator(qualified "${POLICY}" TRUE)
file(READ "${qualified_OUTPUT}" QUALIFIED_CONTRACT)
string(JSON QUALIFIED_RELEASE GET "${QUALIFIED_CONTRACT}" releaseID)
string(JSON QUALIFIED_DISPOSITION GET "${QUALIFIED_CONTRACT}" disposition)
string(JSON QUALIFIED_PRODIGY_SHA GET "${QUALIFIED_CONTRACT}" prodigySHA256)
string(JSON QUALIFIED_MOTHERSHIP_SHA GET "${QUALIFIED_CONTRACT}" mothershipSHA256)
string(JSON QUALIFIED_SOURCE GET "${QUALIFIED_CONTRACT}" sourceContracts 0 releaseID)
string(JSON QUALIFIED_IDENTITY_MODE GET "${QUALIFIED_CONTRACT}" transportIdentityMode)
string(JSON QUALIFIED_MINIMUM GET "${QUALIFIED_CONTRACT}" minimumHealthyBrains)
if (NOT QUALIFIED_RELEASE STREQUAL "v0.4.13" OR NOT QUALIFIED_DISPOSITION STREQUAL "same-cluster-rollout" OR
    NOT QUALIFIED_PRODIGY_SHA STREQUAL PRODIGY_SHA256 OR NOT QUALIFIED_MOTHERSHIP_SHA STREQUAL MOTHERSHIP_SHA256 OR
    NOT QUALIFIED_IDENTITY_MODE STREQUAL "preserveClusterIdentity" OR NOT QUALIFIED_SOURCE STREQUAL "v0.4.12" OR NOT QUALIFIED_MINIMUM EQUAL 3)
   message(FATAL_ERROR "qualified producer contract does not preserve policy semantics and computed hashes")
endif()

file(READ "${POLICY}" POLICY_TEXT)
string(JSON MISSING_IDENTITY_MODE REMOVE "${POLICY_TEXT}" transportIdentityMode)
file(WRITE "${WORK}/missing-identity-mode.json" "${MISSING_IDENTITY_MODE}")
run_generator(missing_identity_mode "${WORK}/missing-identity-mode.json" FALSE)
foreach (mode IN ITEMS unknown rotateCA unsupported)
   string(REPLACE "preserveClusterIdentity" "${mode}" BAD_IDENTITY_MODE "${POLICY_TEXT}")
   file(WRITE "${WORK}/bad-identity-${mode}.json" "${BAD_IDENTITY_MODE}")
   run_generator(bad_identity_${mode} "${WORK}/bad-identity-${mode}.json" FALSE)
endforeach()

string(REPLACE "\"architecture\": \"aarch64\"" "\"architecture\": \"x86_64\"" BAD_ARCHITECTURE "${POLICY_TEXT}")
file(WRITE "${WORK}/bad-architecture.json" "${BAD_ARCHITECTURE}")
run_generator(bad_architecture "${WORK}/bad-architecture.json" FALSE)

string(REPLACE "\"wire\": \"compatible\"" "\"wire\": \"unknown\"" BAD_AXIS "${POLICY_TEXT}")
file(WRITE "${WORK}/bad-axis.json" "${BAD_AXIS}")
run_generator(bad_axis "${WORK}/bad-axis.json" FALSE)

string(REPLACE "\"releaseID\": \"v0.4.12\"" "\"releaseID\": \"v0.4.11\"" BAD_SOURCE "${POLICY_TEXT}")
file(WRITE "${WORK}/bad-source.json" "${BAD_SOURCE}")
run_generator(bad_source "${WORK}/bad-source.json" FALSE)

string(REPLACE "  \"migrationProtocolVersion\": \"1\"" "  \"migrationProtocolVersion\": \"1\",\n  \"prodigySHA256\": \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"" BAD_TARGET_HASH "${POLICY_TEXT}")
file(WRITE "${WORK}/bad-target-hash.json" "${BAD_TARGET_HASH}")
run_generator(bad_target_hash "${WORK}/bad-target-hash.json" FALSE)

string(REPLACE "v0.4.13" "v0.4.13;unexpected" BAD_TEXT "${POLICY_TEXT}")
file(WRITE "${WORK}/bad-text.json" "${BAD_TEXT}")
run_generator(bad_text "${WORK}/bad-text.json" FALSE)

string(REPLACE "same-cluster-rollout" "new-cluster-required" NEW_CLUSTER "${POLICY_TEXT}")
string(REPLACE "\"wire\": \"compatible\"" "\"wire\": \"incompatible\"" NEW_CLUSTER "${NEW_CLUSTER}")
file(WRITE "${WORK}/new-cluster.json" "${NEW_CLUSTER}")
run_generator(new_cluster "${WORK}/new-cluster.json" TRUE)

file(REMOVE_RECURSE "${WORK}")
