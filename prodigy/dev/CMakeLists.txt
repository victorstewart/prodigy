cmake_minimum_required(VERSION 3.21)

include(CheckCXXCompilerFlag)

project(prodigy LANGUAGES C CXX)

get_filename_component(PRODIGY_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
include("${PRODIGY_ROOT}/.depos.cmake")

if (NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
   message(FATAL_ERROR "Prodigy dev requires Clang for C builds.")
endif()
if (NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
   message(FATAL_ERROR "Prodigy dev requires Clang for C++ builds.")
endif()

if (NOT DEFINED CMAKE_CXX_STANDARD)
   set(_prodigy_detected_cxx_standard "")
   foreach(_prodigy_candidate_standard IN ITEMS 26 23 20)
      set(_prodigy_support_var "PRODIGY_SUPPORTS_GNUXX${_prodigy_candidate_standard}")
      check_cxx_compiler_flag("-std=gnu++${_prodigy_candidate_standard}" ${_prodigy_support_var})
      if (${_prodigy_support_var})
         set(_prodigy_detected_cxx_standard "${_prodigy_candidate_standard}")
         break()
      endif()
   endforeach()

   if (_prodigy_detected_cxx_standard STREQUAL "")
      message(FATAL_ERROR "Unable to detect a supported C++ dialect for this Clang toolchain.")
   endif()

   set(CMAKE_CXX_STANDARD ${_prodigy_detected_cxx_standard})
endif()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

option(PROJECT_ENABLE_TESTS "Build Prodigy dev tests" ON)
option(
   PRODIGY_ENABLE_LEGACY_NATIVE_CONTAINER_PROBES
   "Build legacy native probe containers that still depend on the old NeuronHub runtime path"
   OFF
)
set(
   PRODIGY_DEV_BASICS_SOURCE_MODE
   "LOCAL"
   CACHE STRING
   "How Prodigy dev resolves Basics: LOCAL for /root/basics workspace state, RELEASE for the published GitHub release asset, or AUTO to prefer local when present"
)
set_property(CACHE PRODIGY_DEV_BASICS_SOURCE_MODE PROPERTY STRINGS LOCAL RELEASE AUTO)

function(_prodigy_resolve_target_arch out_var)
   string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" _prodigy_processor)
   if (_prodigy_processor STREQUAL "")
      string(TOLOWER "${CMAKE_HOST_SYSTEM_PROCESSOR}" _prodigy_processor)
   endif()
   if (_prodigy_processor STREQUAL "")
      execute_process(
         COMMAND uname -m
         OUTPUT_VARIABLE _prodigy_processor
         OUTPUT_STRIP_TRAILING_WHITESPACE
         ERROR_QUIET
      )
      string(TOLOWER "${_prodigy_processor}" _prodigy_processor)
   endif()

   if (_prodigy_processor STREQUAL "amd64")
      set(_prodigy_processor "x86_64")
   elseif (_prodigy_processor STREQUAL "arm64")
      set(_prodigy_processor "aarch64")
   endif()

   if (NOT (_prodigy_processor STREQUAL "x86_64"
      OR _prodigy_processor STREQUAL "aarch64"
      OR _prodigy_processor STREQUAL "riscv64"))
      message(FATAL_ERROR "Unsupported Prodigy target architecture '${_prodigy_processor}'.")
   endif()

   set(${out_var} "${_prodigy_processor}" PARENT_SCOPE)
endfunction()

function(_prodigy_collect_imported_library_dirs out_var)
   set(_prodigy_dirs "")
   foreach(_prodigy_target IN LISTS ARGN)
      if (NOT TARGET "${_prodigy_target}")
         continue()
      endif()

      foreach(_prodigy_property IN ITEMS
         IMPORTED_LOCATION
         IMPORTED_LOCATION_NOCONFIG
         IMPORTED_LOCATION_RELEASE
         IMPORTED_LOCATION_DEBUG
         IMPORTED_LOCATION_RELWITHDEBINFO
         IMPORTED_LOCATION_MINSIZEREL
         IMPORTED_IMPLIB
         IMPORTED_IMPLIB_NOCONFIG
         IMPORTED_IMPLIB_RELEASE
         IMPORTED_IMPLIB_DEBUG
         IMPORTED_IMPLIB_RELWITHDEBINFO
         IMPORTED_IMPLIB_MINSIZEREL
      )
         get_target_property(_prodigy_location "${_prodigy_target}" ${_prodigy_property})
         if (NOT _prodigy_location OR _prodigy_location MATCHES "-NOTFOUND$")
            continue()
         endif()

         get_filename_component(_prodigy_dir "${_prodigy_location}" DIRECTORY)
         if (IS_DIRECTORY "${_prodigy_dir}")
            list(APPEND _prodigy_dirs "${_prodigy_dir}")
         endif()
      endforeach()
   endforeach()

   if (_prodigy_dirs)
      list(REMOVE_DUPLICATES _prodigy_dirs)
   endif()
   set(${out_var} "${_prodigy_dirs}" PARENT_SCOPE)
endfunction()

function(_prodigy_collect_interface_include_flags out_var)
   set(_prodigy_flags "")
   foreach(_prodigy_target IN LISTS ARGN)
      if (NOT TARGET "${_prodigy_target}")
         continue()
      endif()

      get_target_property(_prodigy_include_dirs "${_prodigy_target}" INTERFACE_INCLUDE_DIRECTORIES)
      foreach(_prodigy_include_dir IN LISTS _prodigy_include_dirs)
         if (_prodigy_include_dir AND NOT _prodigy_include_dir MATCHES "^\\$<")
            list(APPEND _prodigy_flags "-I${_prodigy_include_dir}")
         endif()
      endforeach()
   endforeach()

   if (_prodigy_flags)
      list(REMOVE_DUPLICATES _prodigy_flags)
   endif()
   set(${out_var} "${_prodigy_flags}" PARENT_SCOPE)
endfunction()

_prodigy_resolve_target_arch(PRODIGY_RESOLVED_TARGET_ARCH)

set(PRODIGY_DEPOFILES_DIR "${PRODIGY_ROOT}/depofiles")
prodigy_resolve_basics_depofile(
   PRODIGY_BASICS_DEPOFILE
   ENABLE_TIDESDB
   SOURCE_MODE "${PRODIGY_DEV_BASICS_SOURCE_MODE}"
)
set(PRODIGY_DEPOFILES
   "${PRODIGY_BASICS_DEPOFILE}"
   "${PRODIGY_DEPOFILES_DIR}/cppsort.DepoFile"
   "${PRODIGY_DEPOFILES_DIR}/libcap.DepoFile"
   "${PRODIGY_DEPOFILES_DIR}/libseccomp.DepoFile"
   "${PRODIGY_DEPOFILES_DIR}/tidesdb.DepoFile"
)

depos_depend(FILES ${PRODIGY_DEPOFILES})
_depos_ensure_registry_ready()

set(PRODIGY_SDK_ENABLE_TESTS OFF CACHE BOOL "Disable standalone SDK tests when embedding the SDK into the Prodigy dev build" FORCE)
add_subdirectory("${PRODIGY_ROOT}/prodigy/sdk" "${CMAKE_BINARY_DIR}/sdk")

find_program(PRODIGY_CLANG_EXECUTABLE clang REQUIRED)

set(PRODIGY_BUNDLED_FIO_BIN "" CACHE FILEPATH "Path to fio binary bundled with Prodigy")
set(PRODIGY_BUNDLED_IPERF3_BIN "" CACHE FILEPATH "Path to iperf3 binary bundled with Prodigy")
set(PRODIGY_BUNDLED_SYSBENCH_BIN "" CACHE FILEPATH "Path to sysbench binary bundled with Prodigy")
set(PRODIGY_BUNDLED_LAT_MEM_RD_BIN "" CACHE FILEPATH "Path to lmbench lat_mem_rd binary bundled with Prodigy")
set(PRODIGY_BUNDLED_BW_MEM_BIN "" CACHE FILEPATH "Path to lmbench bw_mem binary bundled with Prodigy")
set(PRODIGY_BUNDLED_SPEEDTEST_BIN "" CACHE FILEPATH "Path to official Ookla speedtest binary bundled with Prodigy")
set(PRODIGY_BUNDLED_SPEEDTEST_VERSION "1.2.0" CACHE STRING "Pinned official Ookla Speedtest CLI version used for bundle auto-download")
set(PRODIGY_BUNDLED_SPEEDTEST_DOWNLOAD_URL "" CACHE STRING "Override URL for the official Ookla Speedtest CLI archive")

function(prodigy_resolve_bundled_program output_var command_name cache_help)
   if (${output_var} STREQUAL "")
      execute_process(
         COMMAND bash -lc "command -v ${command_name}"
         RESULT_VARIABLE _prodigy_program_rc
         OUTPUT_VARIABLE _prodigy_program_out
         ERROR_VARIABLE _prodigy_program_err
         OUTPUT_STRIP_TRAILING_WHITESPACE
      )

      if (NOT _prodigy_program_rc EQUAL 0 OR _prodigy_program_out STREQUAL "")
         set(_prodigy_probe_stub "${CMAKE_CURRENT_SOURCE_DIR}/tests/assets/probes/${command_name}")
         if (EXISTS "${_prodigy_probe_stub}")
            set(_prodigy_program_out "${_prodigy_probe_stub}")
         else()
            message(FATAL_ERROR "Unable to locate ${command_name} for Prodigy bundle: ${_prodigy_program_err}")
         endif()
      endif()
      set(${output_var} "${_prodigy_program_out}" CACHE FILEPATH "${cache_help}" FORCE)
   endif()
endfunction()

function(prodigy_validate_official_speedtest candidate_path result_var)
   if (NOT EXISTS "${candidate_path}")
      set(${result_var} FALSE PARENT_SCOPE)
      return()
   endif()

   string(TOLOWER "${CMAKE_HOST_SYSTEM_PROCESSOR}" _prodigy_speedtest_host_processor)
   set(_prodigy_speedtest_host_arch "")
   if (_prodigy_speedtest_host_processor STREQUAL "x86_64" OR _prodigy_speedtest_host_processor STREQUAL "amd64")
      set(_prodigy_speedtest_host_arch "x86_64")
   elseif (_prodigy_speedtest_host_processor STREQUAL "aarch64" OR _prodigy_speedtest_host_processor STREQUAL "arm64")
      set(_prodigy_speedtest_host_arch "aarch64")
   endif()

   if (NOT _prodigy_speedtest_host_arch STREQUAL "" AND NOT _prodigy_speedtest_host_arch STREQUAL PRODIGY_RESOLVED_TARGET_ARCH)
      execute_process(
         COMMAND file -b "${candidate_path}"
         RESULT_VARIABLE _prodigy_speedtest_file_rc
         OUTPUT_VARIABLE _prodigy_speedtest_file_out
         ERROR_VARIABLE _prodigy_speedtest_file_err
         OUTPUT_STRIP_TRAILING_WHITESPACE
      )

      if (_prodigy_speedtest_file_rc EQUAL 0)
         if (PRODIGY_RESOLVED_TARGET_ARCH STREQUAL "x86_64" AND _prodigy_speedtest_file_out MATCHES "ELF .* x86-64")
            set(${result_var} TRUE PARENT_SCOPE)
            return()
         elseif (PRODIGY_RESOLVED_TARGET_ARCH STREQUAL "aarch64" AND _prodigy_speedtest_file_out MATCHES "ELF .* ARM aarch64")
            set(${result_var} TRUE PARENT_SCOPE)
            return()
         endif()
      endif()

      set(${result_var} FALSE PARENT_SCOPE)
      return()
   endif()

   execute_process(
      COMMAND "${candidate_path}" --version
      RESULT_VARIABLE _prodigy_speedtest_version_rc
      OUTPUT_VARIABLE _prodigy_speedtest_version_out
      ERROR_VARIABLE _prodigy_speedtest_version_err
      OUTPUT_STRIP_TRAILING_WHITESPACE
   )

   if (_prodigy_speedtest_version_rc EQUAL 0 AND _prodigy_speedtest_version_out MATCHES "Speedtest by Ookla")
      set(${result_var} TRUE PARENT_SCOPE)
   else()
      set(${result_var} FALSE PARENT_SCOPE)
   endif()
endfunction()

function(prodigy_resolve_speedtest_archive_arch output_var)
   if (PRODIGY_RESOLVED_TARGET_ARCH STREQUAL "x86_64")
      set(${output_var} "x86_64" PARENT_SCOPE)
   elseif (PRODIGY_RESOLVED_TARGET_ARCH STREQUAL "aarch64")
      set(${output_var} "aarch64" PARENT_SCOPE)
   else()
      message(FATAL_ERROR "Unsupported architecture for official Ookla Speedtest CLI auto-download: ${PRODIGY_RESOLVED_TARGET_ARCH}. Set PRODIGY_BUNDLED_SPEEDTEST_BIN explicitly.")
   endif()
endfunction()

function(prodigy_resolve_official_speedtest output_var cache_help)
   if (NOT ${output_var} STREQUAL "")
      prodigy_validate_official_speedtest("${${output_var}}" _prodigy_configured_speedtest_valid)
      if (NOT _prodigy_configured_speedtest_valid)
         message(FATAL_ERROR "${output_var} must point to the official Ookla Speedtest CLI binary.")
      endif()
      return()
   endif()

   execute_process(
      COMMAND bash -lc "command -v speedtest"
      RESULT_VARIABLE _prodigy_speedtest_lookup_rc
      OUTPUT_VARIABLE _prodigy_speedtest_lookup_out
      ERROR_VARIABLE _prodigy_speedtest_lookup_err
      OUTPUT_STRIP_TRAILING_WHITESPACE
   )

   if (_prodigy_speedtest_lookup_rc EQUAL 0 AND NOT _prodigy_speedtest_lookup_out STREQUAL "")
      prodigy_validate_official_speedtest("${_prodigy_speedtest_lookup_out}" _prodigy_system_speedtest_valid)
      if (_prodigy_system_speedtest_valid)
         set(${output_var} "${_prodigy_speedtest_lookup_out}" CACHE FILEPATH "${cache_help}" FORCE)
         return()
      endif()
   endif()

   if (NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
      message(FATAL_ERROR "Official Ookla Speedtest CLI auto-download is only implemented for Linux. Set ${output_var} explicitly.")
   endif()

   prodigy_resolve_speedtest_archive_arch(_prodigy_speedtest_archive_arch)

   if (PRODIGY_BUNDLED_SPEEDTEST_DOWNLOAD_URL STREQUAL "")
      set(_prodigy_speedtest_download_url "https://install.speedtest.net/app/cli/ookla-speedtest-${PRODIGY_BUNDLED_SPEEDTEST_VERSION}-linux-${_prodigy_speedtest_archive_arch}.tgz")
   else()
      set(_prodigy_speedtest_download_url "${PRODIGY_BUNDLED_SPEEDTEST_DOWNLOAD_URL}")
   endif()

   set(_prodigy_speedtest_root "${CMAKE_CURRENT_BINARY_DIR}/third_party/speedtest")
   set(_prodigy_speedtest_archive "${_prodigy_speedtest_root}/ookla-speedtest.tgz")
   set(_prodigy_speedtest_extract_dir "${_prodigy_speedtest_root}/extract")
   set(_prodigy_speedtest_binary "${_prodigy_speedtest_extract_dir}/speedtest")

   file(MAKE_DIRECTORY "${_prodigy_speedtest_root}")
   file(MAKE_DIRECTORY "${_prodigy_speedtest_extract_dir}")

   file(
      DOWNLOAD
      "${_prodigy_speedtest_download_url}"
      "${_prodigy_speedtest_archive}"
      STATUS _prodigy_speedtest_download_status
      TLS_VERIFY ON
   )

   list(GET _prodigy_speedtest_download_status 0 _prodigy_speedtest_download_rc)
   list(GET _prodigy_speedtest_download_status 1 _prodigy_speedtest_download_msg)
   if (NOT _prodigy_speedtest_download_rc EQUAL 0)
      message(FATAL_ERROR "Failed to download official Ookla Speedtest CLI from ${_prodigy_speedtest_download_url}: ${_prodigy_speedtest_download_msg}")
   endif()

   execute_process(
      COMMAND "${CMAKE_COMMAND}" -E tar xzf "${_prodigy_speedtest_archive}"
      WORKING_DIRECTORY "${_prodigy_speedtest_extract_dir}"
      RESULT_VARIABLE _prodigy_speedtest_extract_rc
      OUTPUT_VARIABLE _prodigy_speedtest_extract_out
      ERROR_VARIABLE _prodigy_speedtest_extract_err
   )

   if (NOT _prodigy_speedtest_extract_rc EQUAL 0)
      message(FATAL_ERROR "Failed to extract official Ookla Speedtest CLI archive: ${_prodigy_speedtest_extract_err}")
   endif()

   if (NOT EXISTS "${_prodigy_speedtest_binary}")
      message(FATAL_ERROR "Official Ookla Speedtest CLI archive did not contain a speedtest binary: ${_prodigy_speedtest_download_url}")
   endif()

   file(CHMOD "${_prodigy_speedtest_binary}"
      PERMISSIONS
         OWNER_READ OWNER_WRITE OWNER_EXECUTE
         GROUP_READ GROUP_EXECUTE
         WORLD_READ WORLD_EXECUTE
   )

   prodigy_validate_official_speedtest("${_prodigy_speedtest_binary}" _prodigy_downloaded_speedtest_valid)
   if (NOT _prodigy_downloaded_speedtest_valid)
      message(FATAL_ERROR "Downloaded speedtest binary is not the official Ookla Speedtest CLI: ${_prodigy_speedtest_binary}")
   endif()

   set(${output_var} "${_prodigy_speedtest_binary}" CACHE FILEPATH "${cache_help}" FORCE)
endfunction()

prodigy_resolve_bundled_program(PRODIGY_BUNDLED_FIO_BIN fio "Path to fio binary bundled with Prodigy")
prodigy_resolve_bundled_program(PRODIGY_BUNDLED_IPERF3_BIN iperf3 "Path to iperf3 binary bundled with Prodigy")
prodigy_resolve_bundled_program(PRODIGY_BUNDLED_SYSBENCH_BIN sysbench "Path to sysbench binary bundled with Prodigy")
prodigy_resolve_bundled_program(PRODIGY_BUNDLED_LAT_MEM_RD_BIN lat_mem_rd "Path to lmbench lat_mem_rd binary bundled with Prodigy")
prodigy_resolve_bundled_program(PRODIGY_BUNDLED_BW_MEM_BIN bw_mem "Path to lmbench bw_mem binary bundled with Prodigy")
prodigy_resolve_official_speedtest(PRODIGY_BUNDLED_SPEEDTEST_BIN "Path to official Ookla speedtest binary bundled with Prodigy")

set(PRODIGY_BUNDLED_TOOL_BINARIES
   "${PRODIGY_BUNDLED_FIO_BIN}"
   "${PRODIGY_BUNDLED_IPERF3_BIN}"
   "${PRODIGY_BUNDLED_SYSBENCH_BIN}"
   "${PRODIGY_BUNDLED_LAT_MEM_RD_BIN}"
   "${PRODIGY_BUNDLED_BW_MEM_BIN}"
   "${PRODIGY_BUNDLED_SPEEDTEST_BIN}"
)

set(DISCOMBOBULATOR_MANIFEST "${PRODIGY_ROOT}/prodigy/discombobulator/Cargo.toml")
set(DISCOMBOBULATOR_CARGO_LOCK "${PRODIGY_ROOT}/prodigy/discombobulator/Cargo.lock")
set(DISCOMBOBULATOR_CARGO_TARGET_DIR "${CMAKE_BINARY_DIR}/discombobulator-target")
file(GLOB DISCOMBOBULATOR_SOURCE_FILES CONFIGURE_DEPENDS
   "${PRODIGY_ROOT}/prodigy/discombobulator/src/*.rs")

add_executable(prodigy ${PRODIGY_ROOT}/prodigy/prodigy.cpp)
add_executable(mothership ${PRODIGY_ROOT}/prodigy/mothership/mothership.cpp)
add_executable(prodigy_ready_container ${CMAKE_CURRENT_SOURCE_DIR}/tests/ready_container.cpp)
set(PRODIGY_LEGACY_NATIVE_CONTAINER_PROBE_TARGETS)
if (PRODIGY_ENABLE_LEGACY_NATIVE_CONTAINER_PROBES)
   add_executable(prodigy_pingpong_container ${CMAKE_CURRENT_SOURCE_DIR}/tests/pingpong_container.cpp)
   add_executable(prodigy_pingpong_container_alt ${CMAKE_CURRENT_SOURCE_DIR}/tests/pingpong_container.cpp)
   add_executable(prodigy_pingpong_container_noport ${CMAKE_CURRENT_SOURCE_DIR}/tests/pingpong_container.cpp)
   add_executable(prodigy_pingpong_container_google_egress ${CMAKE_CURRENT_SOURCE_DIR}/tests/pingpong_container.cpp)
   add_executable(prodigy_whitehole_probe_container ${CMAKE_CURRENT_SOURCE_DIR}/tests/whitehole_probe_container.cpp)
   add_executable(prodigy_quic_wormhole_probe_container ${CMAKE_CURRENT_SOURCE_DIR}/tests/quic_wormhole_probe_container.cpp)
   set(
      PRODIGY_LEGACY_NATIVE_CONTAINER_PROBE_TARGETS
      prodigy_pingpong_container
      prodigy_pingpong_container_alt
      prodigy_pingpong_container_noport
      prodigy_pingpong_container_google_egress
      prodigy_whitehole_probe_container
      prodigy_quic_wormhole_probe_container
   )
endif()
add_executable(prodigy_gpu_device_mount_smoke ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_gpu_device_mount_smoke.cpp)
add_executable(prodigy_shared_cpu_affinity_seccomp_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_shared_cpu_affinity_seccomp_unit.cpp)
add_executable(prodigy_metrics_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_metrics_unit.cpp)
add_executable(prodigy_wire_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_wire_unit.cpp)
add_executable(prodigy_sdk_cpp_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_sdk_cpp_unit.cpp)
add_executable(prodigy_mesh_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_mesh_unit.cpp)
add_executable(prodigy_deployments_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_deployments_unit.cpp)
add_executable(prodigy_brain_config_ssh_replication_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_brain_config_ssh_replication_unit.cpp)
add_executable(prodigy_brain_replication_credentials_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_brain_replication_credentials_unit.cpp)
add_executable(prodigy_pairing_parser_adversarial_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_pairing_parser_adversarial_unit.cpp)
add_executable(prodigy_bootstrap_config_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_bootstrap_config_unit.cpp)
add_executable(prodigy_persistent_state_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_persistent_state_unit.cpp)
add_executable(prodigy_runtime_environment_bgp_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_runtime_environment_bgp_unit.cpp)
add_executable(prodigy_transport_tls_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_transport_tls_unit.cpp)
add_executable(prodigy_cluster_topology_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_cluster_topology_unit.cpp)
add_executable(prodigy_neuron_hub_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_neuron_hub_unit.cpp)
add_executable(prodigy_ring_recvmsg_multishot_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_ring_recvmsg_multishot_unit.cpp)
add_executable(prodigy_switchboard_routable_prefix_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_switchboard_routable_prefix_unit.cpp)
add_executable(prodigy_switchboard_balancer_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_switchboard_balancer_unit.cpp)
add_executable(prodigy_container_storage_layout_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_container_storage_layout_unit.cpp)
add_executable(prodigy_switchboard_overlay_route_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_switchboard_overlay_route_unit.cpp)
add_executable(prodigy_container_overlay_sync_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_container_overlay_sync_unit.cpp)
add_executable(prodigy_brain_overlay_hosted_ingress_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_brain_overlay_hosted_ingress_unit.cpp)
add_executable(prodigy_switchboard_whitehole_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_switchboard_whitehole_unit.cpp)
add_executable(prodigy_quic_cid_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_quic_cid_unit.cpp)
add_executable(prodigy_cluster_bootstrap_concurrency_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_cluster_bootstrap_concurrency_unit.cpp)
add_executable(prodigy_brain_reachability_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_brain_reachability_unit.cpp)
add_executable(prodigy_brain_master_uuid_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_brain_master_uuid_unit.cpp)
add_executable(prodigy_brain_ipv6_topology_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_brain_ipv6_topology_unit.cpp)
add_executable(prodigy_private4_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_private4_unit.cpp)
add_executable(prodigy_gcp_provider_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_gcp_provider_unit.cpp)
add_executable(prodigy_mothership_pricing_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_mothership_pricing_unit.cpp)
add_executable(prodigy_provider_rack_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_provider_rack_unit.cpp)
add_executable(prodigy_provider_elastic_address_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_provider_elastic_address_unit.cpp)
add_executable(prodigy_machine_hardware_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_machine_hardware_unit.cpp)
add_executable(prodigy_test_cluster_boot_json ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_test_cluster_boot_json.cpp)
add_executable(prodigy_bundle_artifact_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_bundle_artifact_unit.cpp)
add_executable(prodigy_remote_bootstrap_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_remote_bootstrap_unit.cpp)
add_executable(prodigy_remote_bootstrap_smoke ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_remote_bootstrap_smoke.cpp)
add_executable(prodigy_mothership_cluster_registry_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_mothership_cluster_registry_unit.cpp)
add_executable(prodigy_mothership_cluster_report_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_mothership_cluster_report_unit.cpp)
add_executable(prodigy_mothership_restart_persistence_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_mothership_restart_persistence_unit.cpp)
add_executable(prodigy_mothership_cluster_reconcile_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_mothership_cluster_reconcile_unit.cpp)
add_executable(prodigy_mothership_cluster_remove_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_mothership_cluster_remove_unit.cpp)
add_executable(prodigy_mothership_cluster_create_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_mothership_cluster_create_unit.cpp)
add_executable(prodigy_mothership_addmachines_progress_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_mothership_addmachines_progress_unit.cpp)
add_executable(prodigy_mothership_unix_connect_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_mothership_unix_connect_unit.cpp)
add_executable(prodigy_mothership_test_cluster_runner_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_mothership_test_cluster_runner_unit.cpp)
add_executable(prodigy_mothership_provider_credential_registry_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_mothership_provider_credential_registry_unit.cpp)
add_executable(prodigy_mothership_provider_machine_destroy_unit ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_mothership_provider_machine_destroy_unit.cpp)

set(PRODIGY_ALL_BUILD_TARGETS
   prodigy
   mothership
   prodigy_ready_container
   ${PRODIGY_LEGACY_NATIVE_CONTAINER_PROBE_TARGETS}
   prodigy_gpu_device_mount_smoke
   prodigy_shared_cpu_affinity_seccomp_unit
   prodigy_metrics_unit
   prodigy_wire_unit
   prodigy_sdk_cpp_unit
   prodigy_mesh_unit
   prodigy_deployments_unit
   prodigy_brain_config_ssh_replication_unit
   prodigy_brain_replication_credentials_unit
   prodigy_pairing_parser_adversarial_unit
   prodigy_bootstrap_config_unit
   prodigy_persistent_state_unit
   prodigy_runtime_environment_bgp_unit
   prodigy_transport_tls_unit
   prodigy_cluster_topology_unit
   prodigy_neuron_hub_unit
   prodigy_ring_recvmsg_multishot_unit
   prodigy_switchboard_routable_prefix_unit
   prodigy_switchboard_balancer_unit
   prodigy_container_storage_layout_unit
   prodigy_switchboard_overlay_route_unit
   prodigy_container_overlay_sync_unit
   prodigy_brain_overlay_hosted_ingress_unit
   prodigy_switchboard_whitehole_unit
   prodigy_quic_cid_unit
   prodigy_cluster_bootstrap_concurrency_unit
   prodigy_brain_reachability_unit
   prodigy_brain_master_uuid_unit
   prodigy_brain_ipv6_topology_unit
   prodigy_private4_unit
   prodigy_gcp_provider_unit
   prodigy_mothership_pricing_unit
   prodigy_provider_rack_unit
   prodigy_provider_elastic_address_unit
   prodigy_machine_hardware_unit
   prodigy_test_cluster_boot_json
   prodigy_bundle_artifact_unit
   prodigy_remote_bootstrap_unit
   prodigy_remote_bootstrap_smoke
   prodigy_mothership_cluster_registry_unit
   prodigy_mothership_cluster_report_unit
   prodigy_mothership_restart_persistence_unit
   prodigy_mothership_cluster_reconcile_unit
   prodigy_mothership_cluster_remove_unit
   prodigy_mothership_cluster_create_unit
   prodigy_mothership_addmachines_progress_unit
   prodigy_mothership_unix_connect_unit
   prodigy_mothership_test_cluster_runner_unit
   prodigy_mothership_provider_credential_registry_unit
   prodigy_mothership_provider_machine_destroy_unit
)

set(PRODIGY_COMMON_DEPO_TARGETS
   basics::basics
   cppsort::cppsort
   libcap::libcap
   libseccomp::libseccomp
)

set(PRODIGY_BUNDLE_OUTPUT "${CMAKE_BINARY_DIR}/prodigy.${PRODIGY_RESOLVED_TARGET_ARCH}.bundle.tar.zst")
set(PRODIGY_BUNDLE_SHA256_OUTPUT "${PRODIGY_BUNDLE_OUTPUT}.sha256")
set(PRODIGY_BUNDLE_LIBRARY_SEARCH_DIRS
   ${CMAKE_C_IMPLICIT_LINK_DIRECTORIES}
   ${CMAKE_CXX_IMPLICIT_LINK_DIRECTORIES}
)
_prodigy_collect_imported_library_dirs(_prodigy_depos_library_dirs
   aegis::aegis
   libbpf::libbpf
   libcap::libcap
   libcurl::libcurl
   libseccomp::libseccomp
   libssh2::libssh2
   liburing::liburing::static
   nghttp2::nghttp2
   openssl::crypto
   openssl::ssl
   simdjson::simdjson
   tidesdb::tidesdb
)
list(APPEND PRODIGY_BUNDLE_LIBRARY_SEARCH_DIRS ${_prodigy_depos_library_dirs})
list(REMOVE_DUPLICATES PRODIGY_BUNDLE_LIBRARY_SEARCH_DIRS)
set(PRODIGY_BUNDLE_LIBRARY_SEARCH_ARGS)
foreach(_prodigy_bundle_library_search_dir IN LISTS PRODIGY_BUNDLE_LIBRARY_SEARCH_DIRS)
   if (IS_DIRECTORY "${_prodigy_bundle_library_search_dir}")
      list(APPEND PRODIGY_BUNDLE_LIBRARY_SEARCH_ARGS
         --library-search-dir "${_prodigy_bundle_library_search_dir}")
   endif()
endforeach()

_prodigy_collect_interface_include_flags(PRODIGY_EBPF_INCLUDE_ARGS libbpf::libbpf)





option(PRODIGY_ENABLE_FUZZ_TESTS "Build Prodigy fuzz smoke targets" ON)
if (PRODIGY_ENABLE_FUZZ_TESTS)
   add_executable(prodigy_pairing_parser_fuzz ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_pairing_parser_fuzz.cpp)
   add_executable(prodigy_mothership_topic_fuzz ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_mothership_topic_fuzz.cpp)
   add_executable(prodigy_brain_topic_fuzz ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_brain_topic_fuzz.cpp)
   add_executable(prodigy_neuron_topic_fuzz ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_neuron_topic_fuzz.cpp)
   add_executable(prodigy_container_topic_fuzz ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_container_topic_fuzz.cpp)
   list(APPEND PRODIGY_ALL_BUILD_TARGETS
      prodigy_pairing_parser_fuzz
      prodigy_mothership_topic_fuzz
      prodigy_brain_topic_fuzz
      prodigy_neuron_topic_fuzz
      prodigy_container_topic_fuzz
   )
endif()

foreach(prodigy_target IN LISTS PRODIGY_ALL_BUILD_TARGETS)
   target_include_directories(${prodigy_target} PRIVATE "${PRODIGY_ROOT}")
   depos_link(${prodigy_target} PRIVATE ${PRODIGY_COMMON_DEPO_TARGETS})
endforeach()

if (NOT TARGET Prodigy::SdkCppOpinionated)
   message(FATAL_ERROR "Prodigy dev requires Prodigy::SdkCppOpinionated for the SDK-owned neuron hub fixture coverage.")
endif()
target_link_libraries(prodigy_sdk_cpp_unit PRIVATE Prodigy::SdkCppOpinionated)

set(PRODIGY_PTHREAD_TARGETS ${PRODIGY_ALL_BUILD_TARGETS})
list(REMOVE_ITEM PRODIGY_PTHREAD_TARGETS prodigy mothership prodigy_sdk_cpp_unit)
foreach(prodigy_target IN LISTS PRODIGY_PTHREAD_TARGETS)
   depos_link(${prodigy_target} PRIVATE pthread)
endforeach()

target_compile_definitions(prodigy PUBLIC PRODIGY_DEBUG=1)
target_compile_definitions(prodigy PUBLIC NAMETAG_PRODIGY_DEV_FAKE_IPV4_ROUTE=1)
target_compile_definitions(mothership PUBLIC PRODIGY_DEBUG=1)
target_compile_definitions(prodigy_ready_container PUBLIC PRODIGY_DEBUG=1)
target_compile_definitions(prodigy_bundle_artifact_unit PUBLIC PRODIGY_TEST_BINARY_DIR="${CMAKE_BINARY_DIR}")
target_compile_definitions(prodigy_mothership_cluster_report_unit PUBLIC PRODIGY_TEST_BINARY_DIR="${CMAKE_BINARY_DIR}" PRODIGY_ROOT_DIR="${PRODIGY_ROOT}")
target_compile_definitions(prodigy_mothership_restart_persistence_unit PUBLIC PRODIGY_TEST_BINARY_DIR="${CMAKE_BINARY_DIR}")
if (PRODIGY_ENABLE_LEGACY_NATIVE_CONTAINER_PROBES)
   target_compile_definitions(prodigy_pingpong_container PUBLIC PRODIGY_DEBUG=1)
   target_compile_definitions(prodigy_pingpong_container_alt PUBLIC PRODIGY_DEBUG=1 PRODIGY_PINGPONG_DEFAULT_PORT=19091)
   target_compile_definitions(prodigy_pingpong_container_noport PUBLIC PRODIGY_DEBUG=1 PRODIGY_PINGPONG_DISABLE_SERVER=1)
   target_compile_definitions(prodigy_pingpong_container_google_egress PUBLIC PRODIGY_DEBUG=1 PRODIGY_PINGPONG_REQUIRE_GOOGLE_EGRESS=1)
endif()
target_compile_definitions(prodigy_gpu_device_mount_smoke PUBLIC PRODIGY_DEBUG=1)
target_compile_definitions(prodigy_shared_cpu_affinity_seccomp_unit PUBLIC PRODIGY_DEBUG=1)
target_compile_definitions(prodigy_metrics_unit PUBLIC PRODIGY_DEBUG=1)
target_compile_definitions(prodigy_wire_unit PUBLIC PRODIGY_DEBUG=1)
target_compile_definitions(prodigy_sdk_cpp_unit PUBLIC PRODIGY_DEBUG=1 PRODIGY_SDK_FIXTURE_DIR="${PRODIGY_ROOT}/prodigy/sdk/fixtures")
target_compile_definitions(prodigy_mesh_unit PUBLIC PRODIGY_DEBUG=1)
target_compile_definitions(prodigy_deployments_unit PUBLIC PRODIGY_DEBUG=1)
target_compile_definitions(prodigy_ring_recvmsg_multishot_unit PUBLIC PRODIGY_DEBUG=1)
target_compile_definitions(prodigy_brain_config_ssh_replication_unit PUBLIC PRODIGY_DEBUG=1)
target_compile_definitions(prodigy_brain_replication_credentials_unit PUBLIC PRODIGY_DEBUG=1)
target_compile_definitions(prodigy_pairing_parser_adversarial_unit PUBLIC PRODIGY_DEBUG=1)
target_compile_definitions(prodigy_container_overlay_sync_unit PUBLIC PRODIGY_DEBUG=1 PRODIGY_TEST_BINARY_DIR="${CMAKE_BINARY_DIR}")
target_compile_definitions(prodigy_switchboard_whitehole_unit PUBLIC PRODIGY_TEST_BINARY_DIR="${CMAKE_BINARY_DIR}")
if (PRODIGY_ENABLE_FUZZ_TESTS)
   target_compile_definitions(prodigy_pairing_parser_fuzz PUBLIC PRODIGY_DEBUG=1)
   target_compile_definitions(prodigy_mothership_topic_fuzz PUBLIC PRODIGY_DEBUG=1)
   target_compile_definitions(prodigy_brain_topic_fuzz PUBLIC PRODIGY_DEBUG=1)
   target_compile_definitions(prodigy_neuron_topic_fuzz PUBLIC PRODIGY_DEBUG=1)
   target_compile_definitions(prodigy_container_topic_fuzz PUBLIC PRODIGY_DEBUG=1)
endif()

target_compile_options(prodigy PUBLIC -O2) # -g -flto
target_compile_options(mothership PUBLIC -O2) # -g -flto
target_compile_options(prodigy_ready_container PUBLIC -O2)
if (PRODIGY_ENABLE_LEGACY_NATIVE_CONTAINER_PROBES)
   target_compile_options(prodigy_pingpong_container PUBLIC -O2)
   target_compile_options(prodigy_pingpong_container_alt PUBLIC -O2)
   target_compile_options(prodigy_pingpong_container_noport PUBLIC -O2)
   target_compile_options(prodigy_pingpong_container_google_egress PUBLIC -O2)
   target_compile_options(prodigy_whitehole_probe_container PUBLIC -O2)
   target_compile_options(prodigy_quic_wormhole_probe_container PUBLIC -O2)
endif()
target_compile_options(prodigy_gpu_device_mount_smoke PUBLIC -O2)
target_compile_options(prodigy_shared_cpu_affinity_seccomp_unit PUBLIC -O2)
target_compile_options(prodigy_metrics_unit PUBLIC -O2)
target_compile_options(prodigy_wire_unit PUBLIC -O2)
target_compile_options(prodigy_sdk_cpp_unit PUBLIC -O2)
target_compile_options(prodigy_mesh_unit PUBLIC -O2)
target_compile_options(prodigy_deployments_unit PUBLIC -O2)
target_compile_options(prodigy_brain_config_ssh_replication_unit PUBLIC -O2)
target_compile_options(prodigy_brain_replication_credentials_unit PUBLIC -O2)
target_compile_options(prodigy_pairing_parser_adversarial_unit PUBLIC -O2)
target_compile_options(prodigy_bootstrap_config_unit PUBLIC -O2)
target_compile_options(prodigy_persistent_state_unit PUBLIC -O2)
target_compile_options(prodigy_runtime_environment_bgp_unit PUBLIC -O2)
target_compile_options(prodigy_transport_tls_unit PUBLIC -O2)
target_compile_options(prodigy_cluster_topology_unit PUBLIC -O2)
target_compile_options(prodigy_neuron_hub_unit PUBLIC -O2)
target_compile_options(prodigy_ring_recvmsg_multishot_unit PUBLIC -O2)
target_compile_options(prodigy_switchboard_routable_prefix_unit PUBLIC -O2)
target_compile_options(prodigy_switchboard_balancer_unit PUBLIC -O2)
target_compile_options(prodigy_container_storage_layout_unit PUBLIC -O2)
target_compile_options(prodigy_switchboard_overlay_route_unit PUBLIC -O2)
target_compile_options(prodigy_container_overlay_sync_unit PUBLIC -O2)
target_compile_options(prodigy_brain_overlay_hosted_ingress_unit PUBLIC -O2)
target_compile_options(prodigy_switchboard_whitehole_unit PUBLIC -O2)
target_compile_options(prodigy_quic_cid_unit PUBLIC -O2)
target_compile_options(prodigy_cluster_bootstrap_concurrency_unit PUBLIC -O2)
target_compile_options(prodigy_brain_reachability_unit PUBLIC -O2)
target_compile_options(prodigy_brain_master_uuid_unit PUBLIC -O2)
target_compile_options(prodigy_brain_ipv6_topology_unit PUBLIC -O2)
target_compile_options(prodigy_private4_unit PUBLIC -O2)
target_compile_options(prodigy_gcp_provider_unit PUBLIC -O0 -fno-lto)
target_compile_options(prodigy_mothership_pricing_unit PUBLIC -O0 -fno-lto)
target_compile_options(prodigy_provider_rack_unit PUBLIC -O0 -fno-lto)
target_compile_options(prodigy_provider_elastic_address_unit PUBLIC -O0 -fno-lto)
target_compile_options(prodigy_machine_hardware_unit PUBLIC -O2)
target_compile_options(prodigy_test_cluster_boot_json PUBLIC -O2)
target_compile_options(prodigy_bundle_artifact_unit PUBLIC -O2)
target_compile_options(prodigy_remote_bootstrap_unit PUBLIC -O2)
target_compile_options(prodigy_remote_bootstrap_smoke PUBLIC -O2)
target_compile_options(prodigy_mothership_cluster_registry_unit PUBLIC -O2)
target_compile_options(prodigy_mothership_cluster_report_unit PUBLIC -O2)
target_compile_options(prodigy_mothership_restart_persistence_unit PUBLIC -O2)
target_compile_options(prodigy_mothership_cluster_reconcile_unit PUBLIC -O2)
target_compile_options(prodigy_mothership_cluster_remove_unit PUBLIC -O2)
target_compile_options(prodigy_mothership_cluster_create_unit PUBLIC -O2)
target_compile_options(prodigy_mothership_addmachines_progress_unit PUBLIC -O2)
target_compile_options(prodigy_mothership_unix_connect_unit PUBLIC -O2)
target_compile_options(prodigy_mothership_test_cluster_runner_unit PUBLIC -O2)
target_compile_options(prodigy_mothership_provider_credential_registry_unit PUBLIC -O2)
target_compile_options(prodigy_mothership_provider_machine_destroy_unit PUBLIC -O2)
if (PRODIGY_ENABLE_FUZZ_TESTS)
   target_compile_options(prodigy_pairing_parser_fuzz PRIVATE -O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer,address)
   target_link_options(prodigy_pairing_parser_fuzz PRIVATE -fsanitize=fuzzer,address)
   target_compile_options(prodigy_mothership_topic_fuzz PRIVATE -O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer,address)
   target_link_options(prodigy_mothership_topic_fuzz PRIVATE -fsanitize=fuzzer,address)
   target_compile_options(prodigy_brain_topic_fuzz PRIVATE -O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer,address)
   target_link_options(prodigy_brain_topic_fuzz PRIVATE -fsanitize=fuzzer,address)
   target_compile_options(prodigy_neuron_topic_fuzz PRIVATE -O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer,address)
   target_link_options(prodigy_neuron_topic_fuzz PRIVATE -fsanitize=fuzzer,address)
   target_compile_options(prodigy_container_topic_fuzz PRIVATE -O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer,address)
   target_link_options(prodigy_container_topic_fuzz PRIVATE -fsanitize=fuzzer,address)
endif()


target_link_options(prodigy_gcp_provider_unit PRIVATE -fno-lto)
target_link_options(prodigy_mothership_pricing_unit PRIVATE -fno-lto)
target_link_options(prodigy_provider_rack_unit PRIVATE -fno-lto)
target_link_options(prodigy_provider_elastic_address_unit PRIVATE -fno-lto)

# -g adds BTF information, which we need to access the maps
add_custom_command(OUTPUT tunnel_to_nic.ebpf.o
                   COMMAND "${PRODIGY_CLANG_EXECUTABLE}" -g -O2 -target bpf -I${PRODIGY_ROOT} ${PRODIGY_EBPF_INCLUDE_ARGS} -DPRODIGY_DEBUG=1 -MMD -MF tunnel_to_nic.ebpf.o.d -c ${CMAKE_CURRENT_SOURCE_DIR}/tunnel_to_nic.ebpf.c -o tunnel_to_nic.ebpf.o
                   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/tunnel_to_nic.ebpf.c
                   DEPFILE tunnel_to_nic.ebpf.o.d)

add_custom_target(tunnel_to_nic ALL DEPENDS tunnel_to_nic.ebpf.o)

# Build the switchboard balancer object used by the neuron-owned switchboard runtime.
add_custom_command(OUTPUT balancer.ebpf.o
                   COMMAND "${PRODIGY_CLANG_EXECUTABLE}" -g -O2 -target bpf -I${PRODIGY_ROOT} ${PRODIGY_EBPF_INCLUDE_ARGS} -DPRODIGY_DEBUG=1 -MMD -MF balancer.ebpf.o.d -c ${PRODIGY_ROOT}/switchboard/kernel/balancer.ebpf.c -o balancer.ebpf.o
                   DEPENDS ${PRODIGY_ROOT}/switchboard/kernel/balancer.ebpf.c
                   DEPFILE balancer.ebpf.o.d)

add_custom_target(balancer_router ALL DEPENDS balancer.ebpf.o)

# Build the host ingress router object required by the isolated netns harness.
add_custom_command(OUTPUT host.ingress.router.ebpf.o
                   COMMAND "${PRODIGY_CLANG_EXECUTABLE}" -g -O2 -target bpf -I${PRODIGY_ROOT} ${PRODIGY_EBPF_INCLUDE_ARGS} -DPRODIGY_DEBUG=1 -MMD -MF host.ingress.router.ebpf.o.d -c ${PRODIGY_ROOT}/switchboard/kernel/host.ingress.router.ebpf.c -o host.ingress.router.ebpf.o
                   DEPENDS ${PRODIGY_ROOT}/switchboard/kernel/host.ingress.router.ebpf.c
                   DEPFILE host.ingress.router.ebpf.o.d)

add_custom_target(host_ingress_router ALL DEPENDS host.ingress.router.ebpf.o)

add_custom_command(OUTPUT host.egress.router.ebpf.o
                   COMMAND "${PRODIGY_CLANG_EXECUTABLE}" -g -O2 -target bpf -I${PRODIGY_ROOT} ${PRODIGY_EBPF_INCLUDE_ARGS} -DPRODIGY_DEBUG=1 -MMD -MF host.egress.router.ebpf.o.d -c ${PRODIGY_ROOT}/switchboard/kernel/host.egress.router.ebpf.c -o host.egress.router.ebpf.o
                   DEPENDS ${PRODIGY_ROOT}/switchboard/kernel/host.egress.router.ebpf.c
                   DEPFILE host.egress.router.ebpf.o.d)

add_custom_target(host_egress_router ALL DEPENDS host.egress.router.ebpf.o)

add_custom_command(OUTPUT container.ingress.router.ebpf.o
                   COMMAND "${PRODIGY_CLANG_EXECUTABLE}" -g -O2 -target bpf -I${PRODIGY_ROOT} ${PRODIGY_EBPF_INCLUDE_ARGS} -DPRODIGY_DEBUG=1 -MMD -MF container.ingress.router.ebpf.o.d -c ${PRODIGY_ROOT}/switchboard/kernel/container.ingress.router.ebpf.c -o container.ingress.router.ebpf.o
                   DEPENDS ${PRODIGY_ROOT}/switchboard/kernel/container.ingress.router.ebpf.c
                   DEPFILE container.ingress.router.ebpf.o.d)

add_custom_target(container_ingress_router ALL DEPENDS container.ingress.router.ebpf.o)

add_custom_command(OUTPUT container.egress.router.ebpf.o
                   COMMAND "${PRODIGY_CLANG_EXECUTABLE}" -g -O2 -target bpf -I${PRODIGY_ROOT} ${PRODIGY_EBPF_INCLUDE_ARGS} -DPRODIGY_DEBUG=1 -MMD -MF container.egress.router.ebpf.o.d -c ${PRODIGY_ROOT}/switchboard/kernel/container.egress.router.ebpf.c -o container.egress.router.ebpf.o
                   DEPENDS ${PRODIGY_ROOT}/switchboard/kernel/container.egress.router.ebpf.c
                   DEPFILE container.egress.router.ebpf.o.d)

add_custom_target(container_egress_router ALL DEPENDS container.egress.router.ebpf.o)

add_dependencies(prodigy_container_overlay_sync_unit
   container_egress_router)

add_dependencies(prodigy_switchboard_whitehole_unit
   host_ingress_router
   host_egress_router)

# Build the boundary fake-ipv4 NAT object used by netns ingress/egress testing.
add_custom_command(OUTPUT fake_ipv4_boundary_nat.ebpf.o
                   COMMAND "${PRODIGY_CLANG_EXECUTABLE}" -g -O2 -target bpf -I${PRODIGY_ROOT} ${PRODIGY_EBPF_INCLUDE_ARGS} -DPRODIGY_DEBUG=1 -MMD -MF fake_ipv4_boundary_nat.ebpf.o.d -c ${CMAKE_CURRENT_SOURCE_DIR}/fake_ipv4_boundary_nat.ebpf.c -o fake_ipv4_boundary_nat.ebpf.o
                   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/fake_ipv4_boundary_nat.ebpf.c
                   DEPFILE fake_ipv4_boundary_nat.ebpf.o.d)

add_custom_target(fake_ipv4_boundary_nat ALL DEPENDS fake_ipv4_boundary_nat.ebpf.o)

add_dependencies(prodigy
   tunnel_to_nic
   balancer_router
   host_ingress_router
   host_egress_router
   container_ingress_router
   container_egress_router
   fake_ipv4_boundary_nat)

add_custom_command(
   OUTPUT "${PRODIGY_BUNDLE_OUTPUT}"
   COMMAND "${CMAKE_COMMAND}" -E env
           CARGO_TARGET_DIR=${DISCOMBOBULATOR_CARGO_TARGET_DIR}
           cargo run --quiet --manifest-path "${DISCOMBOBULATOR_MANIFEST}" --
           bundle flat
           --binary "$<TARGET_FILE:prodigy>"
           --build-dir "${CMAKE_BINARY_DIR}"
           --output "${PRODIGY_BUNDLE_OUTPUT}"
           ${PRODIGY_BUNDLE_LIBRARY_SEARCH_ARGS}
           --tool-binary "${PRODIGY_BUNDLED_FIO_BIN}"
           --tool-binary "${PRODIGY_BUNDLED_IPERF3_BIN}"
           --tool-binary "${PRODIGY_BUNDLED_SYSBENCH_BIN}"
           --tool-binary "${PRODIGY_BUNDLED_LAT_MEM_RD_BIN}"
           --tool-binary "${PRODIGY_BUNDLED_BW_MEM_BIN}"
           --tool-binary "${PRODIGY_BUNDLED_SPEEDTEST_BIN}"
   DEPENDS prodigy
           balancer.ebpf.o
           host.ingress.router.ebpf.o
           host.egress.router.ebpf.o
           container.ingress.router.ebpf.o
           container.egress.router.ebpf.o
           tunnel_to_nic.ebpf.o
           fake_ipv4_boundary_nat.ebpf.o
           "${DISCOMBOBULATOR_MANIFEST}"
           "${DISCOMBOBULATOR_CARGO_LOCK}"
           ${DISCOMBOBULATOR_SOURCE_FILES}
   COMMENT "Packaging ${PRODIGY_BUNDLE_OUTPUT}"
   COMMAND_EXPAND_LISTS
   VERBATIM
)

add_custom_target(prodigy_bundle DEPENDS "${PRODIGY_BUNDLE_OUTPUT}")

add_custom_command(
   OUTPUT "${PRODIGY_BUNDLE_SHA256_OUTPUT}"
   COMMAND "${CMAKE_COMMAND}"
           -DINPUT_BUNDLE=${PRODIGY_BUNDLE_OUTPUT}
           -DOUTPUT_SHA256=${PRODIGY_BUNDLE_SHA256_OUTPUT}
           -P "${CMAKE_CURRENT_SOURCE_DIR}/write_prodigy_bundle_sha256_file.cmake"
   DEPENDS "${PRODIGY_BUNDLE_OUTPUT}" "${CMAKE_CURRENT_SOURCE_DIR}/write_prodigy_bundle_sha256_file.cmake"
   COMMENT "Generating ${PRODIGY_BUNDLE_SHA256_OUTPUT}"
   VERBATIM
)

add_custom_target(prodigy_bundle_sha256 DEPENDS "${PRODIGY_BUNDLE_SHA256_OUTPUT}")
add_dependencies(prodigy_bundle prodigy_bundle_sha256)
add_dependencies(prodigy_bundle_artifact_unit prodigy_bundle prodigy_bundle_sha256)
add_dependencies(prodigy_mothership_cluster_report_unit mothership)
add_dependencies(prodigy_mothership_restart_persistence_unit mothership prodigy_bundle prodigy_bundle_sha256)
add_dependencies(prodigy_remote_bootstrap_smoke prodigy_bundle)





find_program(RUSTC_EXECUTABLE rustc)
if (RUSTC_EXECUTABLE)
   set(PRODIGY_CI_RS "${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_ci.rs")
   set(PRODIGY_CI_BIN "${CMAKE_BINARY_DIR}/prodigy_ci")
   set(PRODIGY_CI_STAMP "${CMAKE_BINARY_DIR}/prodigy_ci.rust.stamp")

   add_custom_command(
      OUTPUT "${PRODIGY_CI_STAMP}"
      COMMAND "${RUSTC_EXECUTABLE}" --edition=2021 -C opt-level=2 "${PRODIGY_CI_RS}" -o "${PRODIGY_CI_BIN}"
      COMMAND "${CMAKE_COMMAND}" -E touch "${PRODIGY_CI_STAMP}"
      DEPENDS "${PRODIGY_CI_RS}"
      BYPRODUCTS "${PRODIGY_CI_BIN}"
      COMMENT "Building Rust Prodigy CI runner"
      VERBATIM
   )




   add_custom_target(prodigy_ci_runner ALL DEPENDS "${PRODIGY_CI_STAMP}")
else()
endif()

if (PROJECT_ENABLE_TESTS)
   include(CTest)

   add_test(
      NAME prodigy_dev_hostns_fail_closed
      COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_dev_hostns_fail_closed.sh ${CMAKE_BINARY_DIR}/prodigy
   )

   add_test(
      NAME prodigy_dev_single_ns_safety
      COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_dev_single_ns_safety.sh ${CMAKE_BINARY_DIR}/prodigy
   )

   add_test(
      NAME prodigy_dev_bpffs_mount_unit
      COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_dev_bpffs_mount_unit.sh ${CMAKE_BINARY_DIR}/prodigy
   )

   add_test(
      NAME prodigy_dev_overlay_link_mtu_unit
      COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_dev_overlay_link_mtu_unit.sh ${CMAKE_BINARY_DIR}/prodigy
   )

   add_test(
      NAME prodigy_dev_host_tcp_unit
      COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_dev_host_tcp_unit.sh ${CMAKE_BINARY_DIR}/prodigy ${CMAKE_BINARY_DIR}/mothership ${CMAKE_BINARY_DIR}/prodigy_ready_container
   )

   add_test(
      NAME prodigy_dev_runtime_bundle_refresh_unit
      COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_dev_runtime_bundle_refresh_unit.sh
   )

   add_test(
      NAME prodigy_dev_container_netkit_mtu_unit
      COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_dev_container_netkit_mtu_unit.sh ${CMAKE_BINARY_DIR}/prodigy ${CMAKE_BINARY_DIR}/mothership ${CMAKE_BINARY_DIR}/prodigy_ready_container
   )

   add_test(
      NAME prodigy_dev_accepted_fixed_file_sender_unit
      COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_dev_accepted_fixed_file_sender_unit.sh ${CMAKE_BINARY_DIR}/prodigy_transport_tls_unit
   )

   add_test(
      NAME prodigy_dev_single_ns_mothership_boot
      COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_dev_single_ns_mothership_boot.sh ${CMAKE_BINARY_DIR}/prodigy ${CMAKE_BINARY_DIR}/mothership
   )

   set_tests_properties(prodigy_dev_bpffs_mount_unit PROPERTIES SKIP_RETURN_CODE 77)
   set_tests_properties(prodigy_dev_overlay_link_mtu_unit PROPERTIES SKIP_RETURN_CODE 77)
   set_tests_properties(prodigy_dev_host_tcp_unit PROPERTIES SKIP_RETURN_CODE 77)
   set_tests_properties(prodigy_dev_container_netkit_mtu_unit PROPERTIES SKIP_RETURN_CODE 77)
   set_tests_properties(prodigy_dev_accepted_fixed_file_sender_unit PROPERTIES SKIP_RETURN_CODE 77)

   add_test(
      NAME prodigy_dev_test_cluster_membership_smoke
      COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_dev_test_cluster_membership_smoke.sh ${CMAKE_BINARY_DIR}/prodigy ${CMAKE_BINARY_DIR}/mothership
   )

   add_test(
      NAME prodigy_dev_three_ns_boot
      COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_dev_three_ns_boot.sh ${CMAKE_BINARY_DIR}/prodigy
   )

   add_test(
      NAME prodigy_dev_master_failure_matrix_smoke
      COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_dev_master_failure_matrix.sh ${CMAKE_BINARY_DIR}/prodigy ${CMAKE_BINARY_DIR}/mothership --mode=smoke
   )

   add_test(
      NAME prodigy_dev_master_failure_matrix_full
      COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_dev_master_failure_matrix.sh ${CMAKE_BINARY_DIR}/prodigy ${CMAKE_BINARY_DIR}/mothership --mode=full
   )

   add_test(
      NAME prodigy_dev_master_upgrade_sim
      COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_dev_master_upgrade_sim.sh ${CMAKE_BINARY_DIR}/prodigy ${CMAKE_BINARY_DIR}/mothership
   )

   if (PRODIGY_ENABLE_LEGACY_NATIVE_CONTAINER_PROBES)
      add_test(
         NAME prodigy_dev_pingpong_deploy_smoke
         COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_dev_pingpong_deploy_smoke.sh ${CMAKE_BINARY_DIR}/prodigy ${CMAKE_BINARY_DIR}/mothership ${CMAKE_BINARY_DIR}/prodigy_pingpong_container
      )
   endif()

   add_test(
      NAME prodigy_dev_sdk_mesh_e2e_matrix_smoke
      COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_dev_sdk_mesh_e2e_matrix.sh ${CMAKE_BINARY_DIR}/prodigy ${CMAKE_BINARY_DIR}/mothership --languages=rust,python,typescript,cpp
   )
   set_tests_properties(prodigy_dev_sdk_mesh_e2e_matrix_smoke PROPERTIES SKIP_RETURN_CODE 77)





   if (PRODIGY_ENABLE_LEGACY_NATIVE_CONTAINER_PROBES)
      add_test(
         NAME prodigy_dev_whitehole_fake_ipv4_smoke
         COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_dev_whitehole_fake_ipv4_smoke.sh ${CMAKE_BINARY_DIR}/prodigy ${CMAKE_BINARY_DIR}/mothership ${CMAKE_BINARY_DIR}/prodigy_whitehole_probe_container
      )

      add_test(
         NAME prodigy_dev_whitehole_host_ipv4_smoke
         COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_dev_whitehole_host_ipv4_smoke.sh ${CMAKE_BINARY_DIR}/prodigy ${CMAKE_BINARY_DIR}/mothership ${CMAKE_BINARY_DIR}/prodigy_whitehole_probe_container
      )

      add_test(
         NAME prodigy_dev_autoscale_metrics_smoke
         COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_dev_autoscale_metrics_smoke.sh ${CMAKE_BINARY_DIR}/prodigy ${CMAKE_BINARY_DIR}/mothership ${CMAKE_BINARY_DIR}/prodigy_pingpong_container
      )

      add_test(
         NAME prodigy_dev_storage_multidrive_resize_smoke
         COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_dev_storage_multidrive_resize_smoke.sh ${CMAKE_BINARY_DIR}/prodigy ${CMAKE_BINARY_DIR}/mothership ${CMAKE_BINARY_DIR}/prodigy_pingpong_container
      )

      add_test(
         NAME prodigy_dev_autoscale_ingress_composite_smoke
         COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_dev_autoscale_ingress_composite_smoke.sh ${CMAKE_BINARY_DIR}/prodigy ${CMAKE_BINARY_DIR}/mothership ${CMAKE_BINARY_DIR}/prodigy_pingpong_container
      )
   endif()

   add_test(
      NAME prodigy_dev_autoscale_schema_contract
      COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_dev_autoscale_schema_contract.sh ${CMAKE_BINARY_DIR}/mothership
   )

   if (PRODIGY_ENABLE_LEGACY_NATIVE_CONTAINER_PROBES)
      add_test(
         NAME prodigy_dev_autoscale_runtime_matrix
         COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_dev_autoscale_runtime_matrix.sh ${CMAKE_BINARY_DIR}/prodigy ${CMAKE_BINARY_DIR}/mothership ${CMAKE_BINARY_DIR}/prodigy_pingpong_container
      )

      add_test(
         NAME prodigy_dev_container_migration_matrix
         COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_dev_container_migration_matrix.sh ${CMAKE_BINARY_DIR}/prodigy ${CMAKE_BINARY_DIR}/mothership ${CMAKE_BINARY_DIR}/prodigy_pingpong_container
      )

      add_test(
         NAME prodigy_dev_quic_wormhole_smoke
         COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_dev_quic_wormhole_smoke.sh ${CMAKE_BINARY_DIR}/prodigy ${CMAKE_BINARY_DIR}/mothership ${CMAKE_BINARY_DIR}/prodigy_quic_wormhole_probe_container
      )

      add_test(
         NAME prodigy_dev_deployments_matrix_smoke
         COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_dev_deployments_matrix.sh ${CMAKE_BINARY_DIR}/prodigy ${CMAKE_BINARY_DIR}/mothership ${CMAKE_BINARY_DIR}/prodigy_pingpong_container ${CMAKE_BINARY_DIR}/prodigy_pingpong_container_alt ${CMAKE_BINARY_DIR}/prodigy_pingpong_container_noport --mode=smoke
      )

      add_test(
         NAME prodigy_dev_deployments_matrix_ci
         COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_dev_deployments_matrix.sh ${CMAKE_BINARY_DIR}/prodigy ${CMAKE_BINARY_DIR}/mothership ${CMAKE_BINARY_DIR}/prodigy_pingpong_container ${CMAKE_BINARY_DIR}/prodigy_pingpong_container_alt ${CMAKE_BINARY_DIR}/prodigy_pingpong_container_noport --mode=ci
      )
   endif()

   add_test(
      NAME prodigy_shared_cpu_affinity_seccomp_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_shared_cpu_affinity_seccomp_unit
   )

   add_test(
      NAME prodigy_dev_metrics_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_metrics_unit
   )

   add_test(
      NAME prodigy_dev_wire_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_wire_unit
   )

   add_test(
      NAME prodigy_dev_sdk_cpp_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_sdk_cpp_unit
   )

   add_test(
      NAME prodigy_private4_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_private4_unit
   )

   add_test(
      NAME prodigy_pairing_parser_adversarial_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_pairing_parser_adversarial_unit
   )

   add_test(
      NAME prodigy_dev_sdk_compatibility_matrix
      COMMAND bash ${PRODIGY_ROOT}/prodigy/sdk/compatibility_matrix.sh ${CMAKE_BINARY_DIR}/sdk-compatibility-matrix
   )

   add_test(
      NAME prodigy_discombobulator_parser
      COMMAND ${CMAKE_COMMAND} -E env
              CARGO_TARGET_DIR=${DISCOMBOBULATOR_CARGO_TARGET_DIR}
              cargo test --quiet --manifest-path "${DISCOMBOBULATOR_MANIFEST}" --test parser
   )

   add_test(
      NAME prodigy_discombobulator_registry
      COMMAND ${CMAKE_COMMAND} -E env
              CARGO_TARGET_DIR=${DISCOMBOBULATOR_CARGO_TARGET_DIR}
              cargo test --quiet --manifest-path "${DISCOMBOBULATOR_MANIFEST}" --test registry
   )

   add_test(
      NAME prodigy_discombobulator_bundle
      COMMAND ${CMAKE_COMMAND} -E env
              CARGO_TARGET_DIR=${DISCOMBOBULATOR_CARGO_TARGET_DIR}
              cargo test --quiet --manifest-path "${DISCOMBOBULATOR_MANIFEST}" --test bundle
   )

   add_test(
      NAME prodigy_discombobulator_build_smoke
      COMMAND bash -lc "command -v mkfs.btrfs >/dev/null 2>&1 || exit 77; exec env CARGO_TARGET_DIR=${DISCOMBOBULATOR_CARGO_TARGET_DIR} cargo test --quiet --manifest-path '${DISCOMBOBULATOR_MANIFEST}' --test build_smoke"
   )

   set_tests_properties(
      prodigy_discombobulator_parser
      prodigy_discombobulator_registry
      prodigy_discombobulator_bundle
      prodigy_discombobulator_build_smoke
      PROPERTIES
      RUN_SERIAL TRUE
   )
   set_tests_properties(prodigy_discombobulator_build_smoke PROPERTIES SKIP_RETURN_CODE 77)
   set_tests_properties(prodigy_discombobulator_build_smoke PROPERTIES TIMEOUT 1800)
   set(_prodigy_optional_skip_test_candidates
      prodigy_dev_pingpong_deploy_smoke
      prodigy_dev_whitehole_fake_ipv4_smoke
      prodigy_dev_whitehole_host_ipv4_smoke
      prodigy_dev_autoscale_metrics_smoke
      prodigy_dev_storage_multidrive_resize_smoke
      prodigy_dev_autoscale_ingress_composite_smoke
      prodigy_dev_autoscale_schema_contract
      prodigy_dev_autoscale_runtime_matrix
      prodigy_dev_container_migration_matrix
      prodigy_dev_quic_wormhole_smoke
      prodigy_dev_deployments_matrix_smoke
      prodigy_dev_deployments_matrix_ci
   )
   set(_prodigy_optional_skip_tests)
   foreach(_prodigy_test_name IN LISTS _prodigy_optional_skip_test_candidates)
      if (TEST ${_prodigy_test_name})
         list(APPEND _prodigy_optional_skip_tests ${_prodigy_test_name})
      endif()
   endforeach()
   if (_prodigy_optional_skip_tests)
      set_tests_properties(
         ${_prodigy_optional_skip_tests}
         PROPERTIES
         SKIP_RETURN_CODE 77
      )
   endif()

   add_test(
      NAME prodigy_dev_mesh_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_mesh_unit
   )

   add_test(
      NAME prodigy_dev_deployments_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_deployments_unit
   )

   add_test(
      NAME prodigy_brain_config_ssh_replication_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_brain_config_ssh_replication_unit
   )

   add_test(
      NAME prodigy_persistent_state_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_persistent_state_unit
   )

   add_test(
      NAME prodigy_runtime_environment_bgp_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_runtime_environment_bgp_unit
   )

   add_test(
      NAME prodigy_transport_tls_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_transport_tls_unit
   )

   add_test(
      NAME prodigy_cluster_topology_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_cluster_topology_unit
   )

   add_test(
      NAME prodigy_neuron_hub_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_neuron_hub_unit
   )

   add_test(
      NAME prodigy_ring_recvmsg_multishot_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_ring_recvmsg_multishot_unit
   )

   add_test(
      NAME prodigy_switchboard_routable_prefix_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_switchboard_routable_prefix_unit
   )
   add_test(
      NAME prodigy_switchboard_balancer_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_switchboard_balancer_unit
   )

   add_test(
      NAME prodigy_container_storage_layout_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_container_storage_layout_unit
   )

   add_test(
      NAME prodigy_switchboard_overlay_route_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_switchboard_overlay_route_unit
   )
   add_test(
      NAME prodigy_container_overlay_sync_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_container_overlay_sync_unit
   )
   add_test(
      NAME prodigy_brain_overlay_hosted_ingress_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_brain_overlay_hosted_ingress_unit
   )
   add_test(
      NAME prodigy_switchboard_whitehole_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_switchboard_whitehole_unit
   )
   add_test(
      NAME prodigy_host_egress_bpf_load_smoke
      COMMAND
         bash
         ${CMAKE_CURRENT_SOURCE_DIR}/tests/prodigy_host_egress_bpf_load_smoke.sh
         ${CMAKE_BINARY_DIR}/host.egress.router.ebpf.o
   )

   add_test(
      NAME prodigy_quic_cid_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_quic_cid_unit
   )

   add_test(
      NAME prodigy_cluster_bootstrap_concurrency_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_cluster_bootstrap_concurrency_unit
   )

   add_test(
      NAME prodigy_gcp_provider_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_gcp_provider_unit
   )

   add_test(
      NAME prodigy_mothership_pricing_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_mothership_pricing_unit
   )

   add_test(
      NAME prodigy_provider_rack_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_provider_rack_unit
   )

   add_test(
      NAME prodigy_provider_elastic_address_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_provider_elastic_address_unit
   )

   add_test(
      NAME prodigy_machine_hardware_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_machine_hardware_unit
   )

   add_test(
      NAME prodigy_bundle_artifact_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_bundle_artifact_unit
   )

   add_test(
      NAME prodigy_brain_reachability_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_brain_reachability_unit
   )

   add_test(
      NAME prodigy_brain_master_uuid_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_brain_master_uuid_unit
   )

   add_test(
      NAME prodigy_brain_ipv6_topology_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_brain_ipv6_topology_unit
   )

   add_test(
      NAME prodigy_remote_bootstrap_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_remote_bootstrap_unit
   )

   add_test(
      NAME prodigy_bootstrap_config_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_bootstrap_config_unit
   )

   add_test(
      NAME prodigy_mothership_cluster_registry_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_mothership_cluster_registry_unit
   )

   add_test(
      NAME prodigy_mothership_cluster_report_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_mothership_cluster_report_unit
   )

   add_test(
      NAME prodigy_mothership_restart_persistence_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_mothership_restart_persistence_unit
   )

   add_test(
      NAME prodigy_mothership_cluster_reconcile_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_mothership_cluster_reconcile_unit
   )

   add_test(
      NAME prodigy_mothership_cluster_remove_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_mothership_cluster_remove_unit
   )

   add_test(
      NAME prodigy_mothership_cluster_create_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_mothership_cluster_create_unit
   )

   add_test(
      NAME prodigy_mothership_addmachines_progress_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_mothership_addmachines_progress_unit
   )

   add_test(
      NAME prodigy_mothership_unix_connect_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_mothership_unix_connect_unit
   )

add_test(
      NAME prodigy_mothership_test_cluster_runner_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_mothership_test_cluster_runner_unit
)

   add_test(
      NAME prodigy_mothership_provider_credential_registry_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_mothership_provider_credential_registry_unit
   )

   add_test(
      NAME prodigy_mothership_provider_machine_destroy_unit
      COMMAND ${CMAKE_BINARY_DIR}/prodigy_mothership_provider_machine_destroy_unit
   )
















































   if (RUSTC_EXECUTABLE)
      add_test(
         NAME prodigy_ci_runner_help
         COMMAND ${CMAKE_BINARY_DIR}/prodigy_ci --help
      )
   endif()
endif()
