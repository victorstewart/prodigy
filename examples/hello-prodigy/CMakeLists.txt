set(HELLO_PRODIGY_ASSETS_DIR "${CMAKE_BINARY_DIR}/evaluation-assets")
file(MAKE_DIRECTORY "${HELLO_PRODIGY_ASSETS_DIR}")

add_executable(hello_prodigy_v1 hello_prodigy.cpp)
add_executable(hello_prodigy_v2 hello_prodigy.cpp)
foreach(_hello_prodigy_target IN ITEMS hello_prodigy_v1 hello_prodigy_v2)
   target_include_directories(${_hello_prodigy_target} PRIVATE "${PRODIGY_ROOT}")
   depos_link(${_hello_prodigy_target} PRIVATE ${PRODIGY_COMMON_DEPO_TARGETS} pthread)
   target_compile_options(${_hello_prodigy_target} PRIVATE -O2)
endforeach()
target_compile_definitions(hello_prodigy_v1 PRIVATE HELLO_PRODIGY_VERSION="v1")
target_compile_definitions(hello_prodigy_v2 PRIVATE HELLO_PRODIGY_VERSION="v2")

function(_hello_prodigy_artifact version)
   set(HELLO_PRODIGY_BINARY "hello_prodigy_${version}")
   set(_recipe "${HELLO_PRODIGY_ASSETS_DIR}/hello-prodigy-${version}.DiscombobuFile")
   set(_artifact "${HELLO_PRODIGY_ASSETS_DIR}/hello-prodigy-${version}.${PRODIGY_RESOLVED_TARGET_ARCH}.container.zst")
   set(_plan_source "${CMAKE_CURRENT_SOURCE_DIR}/hello-prodigy-${version}.deployment.plan.v1.json")
   set(_plan "${HELLO_PRODIGY_ASSETS_DIR}/hello-prodigy-${version}.deployment.plan.v1.json")

   configure_file("${CMAKE_CURRENT_SOURCE_DIR}/HelloProdigy.DiscombobuFile.in" "${_recipe}" @ONLY)
   add_custom_command(
      OUTPUT "${_artifact}"
      COMMAND "${CMAKE_COMMAND}" -E env
              CARGO_TARGET_DIR=${DISCOMBOBULATOR_CARGO_TARGET_DIR}
              cargo run --quiet --manifest-path "${DISCOMBOBULATOR_MANIFEST}" --
              build
              --file "${_recipe}"
              --context "bin=$<TARGET_FILE_DIR:hello_prodigy_${version}>"
              --context "ebpf=${CMAKE_BINARY_DIR}"
              --output "${_artifact}"
              --kind app
      DEPENDS hello_prodigy_${version}
              container_egress_router
              container_ingress_router
              "${CMAKE_CURRENT_SOURCE_DIR}/HelloProdigy.DiscombobuFile.in"
              "${_recipe}"
              "${DISCOMBOBULATOR_MANIFEST}"
              "${DISCOMBOBULATOR_CARGO_LOCK}"
              ${DISCOMBOBULATOR_SOURCE_FILES}
      COMMENT "Building Hello Prodigy ${version} app container"
      VERBATIM
   )
   add_custom_command(
      OUTPUT "${_plan}"
      COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${_plan_source}" "${_plan}"
      DEPENDS "${_plan_source}"
      COMMENT "Staging Hello Prodigy ${version} deployment plan"
      VERBATIM
   )
   set(HELLO_PRODIGY_${version}_ARTIFACT "${_artifact}" PARENT_SCOPE)
   set(HELLO_PRODIGY_${version}_PLAN "${_plan}" PARENT_SCOPE)
endfunction()

_hello_prodigy_artifact(v1)
_hello_prodigy_artifact(v2)

add_custom_target(hello_prodigy_artifacts
   DEPENDS
      "${HELLO_PRODIGY_v1_ARTIFACT}"
      "${HELLO_PRODIGY_v1_PLAN}"
      "${HELLO_PRODIGY_v2_ARTIFACT}"
      "${HELLO_PRODIGY_v2_PLAN}"
)
