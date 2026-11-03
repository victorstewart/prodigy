if (NOT DEFINED PRODIGY_SOURCE_DIR OR "${PRODIGY_SOURCE_DIR}" STREQUAL "")
   message(FATAL_ERROR "PRODIGY_SOURCE_DIR is required.")
endif()
if (NOT DEFINED PRODIGY_STATE_PATH_TEST_ROOT OR "${PRODIGY_STATE_PATH_TEST_ROOT}" STREQUAL "")
   message(FATAL_ERROR "PRODIGY_STATE_PATH_TEST_ROOT is required.")
endif()

function(require_cache_path build_dir variable expected)
   file(STRINGS "${build_dir}/CMakeCache.txt" cache_lines REGEX "^${variable}:PATH=")
   list(LENGTH cache_lines cache_line_count)
   if (NOT cache_line_count EQUAL 1)
      message(FATAL_ERROR "${build_dir} must contain exactly one ${variable}:PATH cache entry.")
   endif()
   list(GET cache_lines 0 cache_line)
   if (NOT cache_line STREQUAL "${variable}:PATH=${expected}")
      message(FATAL_ERROR "${build_dir} selected '${cache_line}', expected ${variable}:PATH=${expected}.")
   endif()
endfunction()

function(run_state_path_probe label)
   set(options)
   set(one_value_args ROOT)
   set(multi_value_args ENVIRONMENT CMAKE_ARGS)
   cmake_parse_arguments(PROBE "${options}" "${one_value_args}" "${multi_value_args}" ${ARGN})
   if (NOT DEFINED PROBE_ROOT OR "${PROBE_ROOT}" STREQUAL "")
      message(FATAL_ERROR "${label} requires ROOT.")
   endif()

   set(build_dir "${PRODIGY_STATE_PATH_TEST_ROOT}/${label}")
   execute_process(
      COMMAND
         "${CMAKE_COMMAND}" -E env --unset=DEPOS_ROOT ${PROBE_ENVIRONMENT}
         "${CMAKE_COMMAND}"
         -S "${PRODIGY_SOURCE_DIR}"
         -B "${build_dir}"
         -DPRODIGY_VALIDATE_DEPOS_STATE_PATHS_ONLY=ON
         ${PROBE_CMAKE_ARGS}
      RESULT_VARIABLE configure_result
      OUTPUT_VARIABLE configure_stdout
      ERROR_VARIABLE configure_stderr
   )
   if (NOT configure_result EQUAL 0)
      message(FATAL_ERROR
         "${label} state-path configure failed (${configure_result}).\nstdout:\n${configure_stdout}\nstderr:\n${configure_stderr}")
   endif()

   require_cache_path("${build_dir}" DEPOS_ROOT "${PROBE_ROOT}")
   require_cache_path("${build_dir}" DEPOS_BOOTSTRAP_DIR "${build_dir}/depos-bootstrap")
endfunction()

file(REMOVE_RECURSE "${PRODIGY_STATE_PATH_TEST_ROOT}")
file(MAKE_DIRECTORY "${PRODIGY_STATE_PATH_TEST_ROOT}")

run_state_path_probe(
   default
   ROOT "${PRODIGY_STATE_PATH_TEST_ROOT}/default/depos-root"
)
run_state_path_probe(
   explicit
   ROOT "${PRODIGY_STATE_PATH_TEST_ROOT}/explicit-root"
   CMAKE_ARGS "-DDEPOS_ROOT:PATH=${PRODIGY_STATE_PATH_TEST_ROOT}/explicit-root"
)
run_state_path_probe(
   environment
   ROOT "${PRODIGY_STATE_PATH_TEST_ROOT}/environment-root"
   ENVIRONMENT "DEPOS_ROOT=${PRODIGY_STATE_PATH_TEST_ROOT}/environment-root"
)
