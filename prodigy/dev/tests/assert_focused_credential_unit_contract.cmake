if (NOT DEFINED PRODIGY_ROOT OR PRODIGY_ROOT STREQUAL "")
   message(FATAL_ERROR "PRODIGY_ROOT is required.")
endif()

file(READ "${PRODIGY_ROOT}/prodigy/dev/CMakeLists.txt" _prodigy_cmake)
foreach(_prodigy_forbidden_dependency IN ITEMS
   host_ingress_router
   host_egress_router
   prodigy_bundle
   prodigy_mothership_tunnel_provider_artifact
   prodigy_cross_cluster_masque_gateway_artifact
   prodigy_pingpong_container_artifact
)
   if (_prodigy_cmake MATCHES
      "add_dependencies\\(prodigy_brain_replication_credentials_unit[^)]*${_prodigy_forbidden_dependency}")
      message(FATAL_ERROR
         "prodigy_brain_replication_credentials_unit must not depend on ${_prodigy_forbidden_dependency}.")
   endif()
endforeach()
string(FIND "${_prodigy_cmake}"
   "PRODIGY_TEST_ONLY=async-recovery" _prodigy_async_recovery_ctest_index)
if (_prodigy_async_recovery_ctest_index EQUAL -1)
   message(FATAL_ERROR
      "The three-Neuron durable recovery composition must be registered with CTest.")
endif()

file(READ "${PRODIGY_ROOT}/depos.project.cmake" _prodigy_depos_project)
file(SHA256 "${PRODIGY_ROOT}/.depos.cmake" _prodigy_depos_interface_sha256)
if (NOT _prodigy_depos_interface_sha256 STREQUAL
   "a0809260842cd2b7cdc7390134f814c8ec75208fe43a13eb8b7a08ca9f35a3f8")
   message(FATAL_ERROR "Prodigy's Depos interface must match the published 0.5.7 helper byte-for-byte.")
endif()
if (NOT _prodigy_depos_project MATCHES
   "set\\(DEPOS_BOOTSTRAP_VERSION \"0\\.5\\.7\" CACHE STRING \"Pinned depos version used by prodigy\" FORCE\\)")
   message(FATAL_ERROR "Prodigy must pin Depos bootstrap 0.5.7.")
endif()

file(READ "${PRODIGY_ROOT}/tools/build-evaluation.sh" _prodigy_build_evaluation)
if (NOT _prodigy_build_evaluation MATCHES
   "raw.githubusercontent.com/victorstewart/depos/v0\\.5\\.7/.depos.cmake")
   message(FATAL_ERROR "build-evaluation must bootstrap Depos 0.5.7.")
endif()
if (NOT _prodigy_build_evaluation MATCHES
   "a0809260842cd2b7cdc7390134f814c8ec75208fe43a13eb8b7a08ca9f35a3f8")
   message(FATAL_ERROR "build-evaluation must verify the Depos 0.5.7 helper checksum.")
endif()
string(FIND "${_prodigy_build_evaluation}"
   [[sha256sum "${depos_interface}"]] _prodigy_existing_depos_checksum_index)
if (_prodigy_existing_depos_checksum_index EQUAL -1)
   message(FATAL_ERROR "build-evaluation must validate an existing Depos helper before reusing it.")
endif()
string(FIND "${_prodigy_build_evaluation}"
   [[mv "${bootstrap}" "${depos_interface}"]] _prodigy_depos_atomic_replace_index)
if (_prodigy_depos_atomic_replace_index EQUAL -1)
   message(FATAL_ERROR "build-evaluation must atomically replace a missing or stale Depos helper.")
endif()

file(READ "${PRODIGY_ROOT}/depofiles/rust-toolchain.DepoFile" _prodigy_rust_toolchain)
if (_prodigy_rust_toolchain MATCHES "ARTIFACT lib(\\r?\\n|$)")
   message(FATAL_ERROR "Rust's lib directory must not be declared as a file ARTIFACT.")
endif()
if (NOT _prodigy_rust_toolchain MATCHES
   "TARGET rust_toolchain::sysroot INTERFACE lib")
   message(FATAL_ERROR "Rust's lib directory must be exported as an interface tree.")
endif()
