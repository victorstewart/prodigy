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

file(READ "${PRODIGY_ROOT}/depos.project.cmake" _prodigy_depos_project)
if (NOT _prodigy_depos_project MATCHES
   "set\\(DEPOS_BOOTSTRAP_VERSION \"0\\.5\\.5\" CACHE STRING \"Pinned depos version used by prodigy\" FORCE\\)")
   message(FATAL_ERROR "Prodigy must pin Depos bootstrap 0.5.5.")
endif()

file(READ "${PRODIGY_ROOT}/tools/build-evaluation.sh" _prodigy_build_evaluation)
if (NOT _prodigy_build_evaluation MATCHES
   "raw.githubusercontent.com/victorstewart/depos/v0\\.5\\.5/.depos.cmake")
   message(FATAL_ERROR "build-evaluation must bootstrap Depos 0.5.5.")
endif()
if (NOT _prodigy_build_evaluation MATCHES
   "dcf232d697ca8250871a33d9a5d58b135f03d09b3081bf9d1bd7a2d44e383497")
   message(FATAL_ERROR "build-evaluation must verify the Depos 0.5.5 helper checksum.")
endif()

file(READ "${PRODIGY_ROOT}/depofiles/rust-toolchain.DepoFile" _prodigy_rust_toolchain)
if (_prodigy_rust_toolchain MATCHES "ARTIFACT lib(\\r?\\n|$)")
   message(FATAL_ERROR "Rust's lib directory must not be declared as a file ARTIFACT.")
endif()
if (NOT _prodigy_rust_toolchain MATCHES
   "TARGET rust_toolchain::sysroot INTERFACE lib")
   message(FATAL_ERROR "Rust's lib directory must be exported as an interface tree.")
endif()
