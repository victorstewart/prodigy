# Copyright 2026 Victor Stewart
# SPDX-License-Identifier: Apache-2.0

set(DEPOS_BOOTSTRAP_VERSION "0.5.0" CACHE STRING "Pinned depos version used by prodigy" FORCE)

set(
  PRODIGY_RELEASE_DEPOFILE_CACHE_DIR
  "${CMAKE_CURRENT_LIST_DIR}/.run/release-depofiles"
  CACHE PATH
  "Cache directory for detached upstream release DepoFile assets consumed by Prodigy"
  FORCE
)
set(
  PRODIGY_BASICS_RELEASE_VERSION
  "0.2.2"
  CACHE STRING
  "Pinned Basics release version consumed through the published detached DepoFile asset"
  FORCE
)
set(
  PRODIGY_BASICS_RELEASE_DEPOFILE_URL
  "https://github.com/victorstewart/basics/releases/download/v0.2.2/basics.DepoFile"
  CACHE STRING
  "Published Basics detached DepoFile asset URL"
  FORCE
)
set(
  PRODIGY_BASICS_RELEASE_DEPOFILE_SHA256
  "c6f2043bb756abd7c56d01a7cbf60a200f72da10914834cc2ae823d442baf10a"
  CACHE STRING
  "SHA256 for the published Basics detached DepoFile asset"
  FORCE
)
set(
  PRODIGY_BASICS_TIDESDB_PACKAGE_NAME
  "basics_mimalloc_object_deps_static_tidesdb_on"
  CACHE STRING
  "Package name used for the locally derived Basics release DepoFile variant with TidesDB enabled"
  FORCE
)
set(
  PRODIGY_BASICS_TIDESDB_DEPENDENCY_VERSION
  "8.6.2"
  CACHE STRING
  "Pinned TidesDB package version used when deriving the Basics-with-TidesDB release DepoFile variant"
  FORCE
)

if (NOT DEFINED PRODIGY_BASICS_LOCAL_REPO_DIR OR "${PRODIGY_BASICS_LOCAL_REPO_DIR}" STREQUAL "")
  set(
    PRODIGY_BASICS_LOCAL_REPO_DIR
    "${CMAKE_CURRENT_LIST_DIR}/../basics"
    CACHE PATH
    "Local Basics repository root used by Prodigy dev when consuming workspace state directly"
  )
endif()
if (NOT DEFINED PRODIGY_BASICS_LOCAL_BUILD_ROOT OR "${PRODIGY_BASICS_LOCAL_BUILD_ROOT}" STREQUAL "")
  set(
    PRODIGY_BASICS_LOCAL_BUILD_ROOT
    "${CMAKE_CURRENT_LIST_DIR}/.run/local-basics"
    CACHE PATH
    "Prodigy-owned work root used when generating a local Basics self DepoFile for dev builds"
  )
endif()

function(_prodigy_sanitizers_enabled out_var)
  set(_prodigy_flag_fields
    "${CMAKE_C_FLAGS}"
    "${CMAKE_CXX_FLAGS}"
    "${CMAKE_EXE_LINKER_FLAGS}"
    "${CMAKE_SHARED_LINKER_FLAGS}"
    "${CMAKE_MODULE_LINKER_FLAGS}"
  )

  if (DEFINED CMAKE_BUILD_TYPE AND NOT "${CMAKE_BUILD_TYPE}" STREQUAL "")
    string(TOUPPER "${CMAKE_BUILD_TYPE}" _prodigy_build_type_upper)
    list(APPEND _prodigy_flag_fields
      "${CMAKE_C_FLAGS_${_prodigy_build_type_upper}}"
      "${CMAKE_CXX_FLAGS_${_prodigy_build_type_upper}}"
      "${CMAKE_EXE_LINKER_FLAGS_${_prodigy_build_type_upper}}"
      "${CMAKE_SHARED_LINKER_FLAGS_${_prodigy_build_type_upper}}"
      "${CMAKE_MODULE_LINKER_FLAGS_${_prodigy_build_type_upper}}"
    )
  endif()

  string(JOIN " " _prodigy_joined_flags ${_prodigy_flag_fields})
  if (_prodigy_joined_flags MATCHES "(^|[ \t;])-fsanitize=")
    set(${out_var} TRUE PARENT_SCOPE)
  else()
    set(${out_var} FALSE PARENT_SCOPE)
  endif()
endfunction()

function(_prodigy_resolve_basics_mimalloc_mode out_var)
  _prodigy_sanitizers_enabled(_prodigy_has_sanitizers)
  if (_prodigy_has_sanitizers)
    set(${out_var} "NONE" PARENT_SCOPE)
  else()
    set(${out_var} "OBJECT" PARENT_SCOPE)
  endif()
endfunction()

function(_prodigy_resolve_basics_package_name out_var mimalloc_mode tidesdb_enabled)
  string(TOLOWER "${mimalloc_mode}" _prodigy_mimalloc_mode_suffix)
  if (tidesdb_enabled)
    set(_prodigy_tidesdb_suffix "on")
  else()
    set(_prodigy_tidesdb_suffix "off")
  endif()
  set(
    ${out_var}
    "basics_mimalloc_${_prodigy_mimalloc_mode_suffix}_deps_static_tidesdb_${_prodigy_tidesdb_suffix}"
    PARENT_SCOPE
  )
endfunction()

function(prodigy_resolve_release_depofile out_var)
  set(options)
  set(oneValueArgs NAME VERSION URL SHA256)
  cmake_parse_arguments(PRODIGY_RELEASE "${options}" "${oneValueArgs}" "" ${ARGN})

  foreach(_prodigy_required_arg IN ITEMS NAME VERSION URL SHA256)
    if ("${PRODIGY_RELEASE_${_prodigy_required_arg}}" STREQUAL "")
      message(FATAL_ERROR "prodigy_resolve_release_depofile requires ${_prodigy_required_arg}.")
    endif()
  endforeach()

  file(MAKE_DIRECTORY "${PRODIGY_RELEASE_DEPOFILE_CACHE_DIR}")

  set(
    _prodigy_depofile
    "${PRODIGY_RELEASE_DEPOFILE_CACHE_DIR}/${PRODIGY_RELEASE_NAME}-${PRODIGY_RELEASE_VERSION}.DepoFile"
  )
  set(_prodigy_expected_hash "${PRODIGY_RELEASE_SHA256}")
  set(_prodigy_should_download TRUE)

  if (EXISTS "${_prodigy_depofile}")
    file(SHA256 "${_prodigy_depofile}" _prodigy_existing_hash)
    if (_prodigy_existing_hash STREQUAL _prodigy_expected_hash)
      set(_prodigy_should_download FALSE)
    endif()
  endif()

  if (_prodigy_should_download)
    set(_prodigy_temp_depofile "${_prodigy_depofile}.tmp")
    file(
      DOWNLOAD
      "${PRODIGY_RELEASE_URL}"
      "${_prodigy_temp_depofile}"
      EXPECTED_HASH "SHA256=${_prodigy_expected_hash}"
      STATUS _prodigy_download_status
      TLS_VERIFY ON
    )
    list(GET _prodigy_download_status 0 _prodigy_download_rc)
    list(GET _prodigy_download_status 1 _prodigy_download_msg)
    if (NOT _prodigy_download_rc EQUAL 0)
      file(REMOVE "${_prodigy_temp_depofile}")
      message(
        FATAL_ERROR
        "Failed to download ${PRODIGY_RELEASE_NAME} ${PRODIGY_RELEASE_VERSION} detached DepoFile from ${PRODIGY_RELEASE_URL}: ${_prodigy_download_msg}"
      )
    endif()
    file(RENAME "${_prodigy_temp_depofile}" "${_prodigy_depofile}")
  endif()

  set(${out_var} "${_prodigy_depofile}" PARENT_SCOPE)
endfunction()

function(_prodigy_patch_basics_release_depofile_for_tidesdb out_var source_depofile)
  if (NOT EXISTS "${source_depofile}")
    message(FATAL_ERROR "Cannot derive a Basics TidesDB variant from missing DepoFile ${source_depofile}.")
  endif()

  file(READ "${source_depofile}" _prodigy_basics_depofile_contents)

  string(FIND "${_prodigy_basics_depofile_contents}" "# tidesdb support: ON" _prodigy_tidesdb_on_marker_index)
  if (NOT _prodigy_tidesdb_on_marker_index EQUAL -1)
    set(${out_var} "${source_depofile}" PARENT_SCOPE)
    return()
  endif()

  _prodigy_resolve_basics_mimalloc_mode(_prodigy_basics_mimalloc_mode)
  _prodigy_resolve_basics_package_name(
    _prodigy_basics_variant_package_name
    "${_prodigy_basics_mimalloc_mode}"
    TRUE
  )

  set(_prodigy_basics_variant_depofile
    "${PRODIGY_RELEASE_DEPOFILE_CACHE_DIR}/basics-${PRODIGY_BASICS_RELEASE_VERSION}-tidesdb-on-mimalloc-${_prodigy_basics_mimalloc_mode}.DepoFile"
  )

  set(_prodigy_expected_basics_name_line "NAME basics")
  set(_prodigy_variant_basics_name_line "NAME ${_prodigy_basics_variant_package_name}")
  string(FIND "${_prodigy_basics_depofile_contents}" "${_prodigy_expected_basics_name_line}" _prodigy_basics_name_index)
  if (_prodigy_basics_name_index EQUAL -1)
    message(
      FATAL_ERROR
      "Published Basics release DepoFile at ${source_depofile} no longer matches the expected package name contract."
    )
  endif()
  string(REPLACE
    "${_prodigy_expected_basics_name_line}"
    "${_prodigy_variant_basics_name_line}"
    _prodigy_basics_depofile_contents
    "${_prodigy_basics_depofile_contents}"
  )

  string(FIND "${_prodigy_basics_depofile_contents}" "# tidesdb support: OFF" _prodigy_tidesdb_off_marker_index)
  if (_prodigy_tidesdb_off_marker_index EQUAL -1)
    message(
      FATAL_ERROR
      "Published Basics release DepoFile at ${source_depofile} no longer exposes the expected tidesdb support marker."
    )
  endif()
  string(REPLACE
    "# tidesdb support: OFF"
    "# tidesdb support: ON"
    _prodigy_basics_depofile_contents
    "${_prodigy_basics_depofile_contents}"
  )

  string(FIND "${_prodigy_basics_depofile_contents}" "DEPENDS tidesdb VERSION " _prodigy_tidesdb_depends_index)
  if (_prodigy_tidesdb_depends_index EQUAL -1)
    set(_prodigy_tidesdb_depends_line "DEPENDS tidesdb VERSION ${PRODIGY_BASICS_TIDESDB_DEPENDENCY_VERSION}")
    string(FIND "${_prodigy_basics_depofile_contents}" "DEPENDS mimalloc VERSION 3.0.1" _prodigy_mimalloc_depends_index)
    if (_prodigy_mimalloc_depends_index EQUAL -1)
      message(
        FATAL_ERROR
        "Published Basics release DepoFile at ${source_depofile} no longer exposes the expected mimalloc dependency anchor."
      )
    endif()
    string(REPLACE
      "DEPENDS mimalloc VERSION 3.0.1"
      "${_prodigy_tidesdb_depends_line}\nDEPENDS mimalloc VERSION 3.0.1"
      _prodigy_basics_depofile_contents
      "${_prodigy_basics_depofile_contents}"
    )
  endif()

  string(FIND "${_prodigy_basics_depofile_contents}" "STAGE_TREE SOURCE databases include/databases" _prodigy_databases_stage_index)
  if (_prodigy_databases_stage_index EQUAL -1)
    string(FIND "${_prodigy_basics_depofile_contents}" "STAGE_FILE SOURCE includes.h include/includes.h" _prodigy_includes_stage_index)
    if (_prodigy_includes_stage_index EQUAL -1)
      message(
        FATAL_ERROR
        "Published Basics release DepoFile at ${source_depofile} no longer exposes the expected includes staging anchor."
      )
    endif()
    string(REPLACE
      "STAGE_FILE SOURCE includes.h include/includes.h"
      "STAGE_FILE SOURCE includes.h include/includes.h\nSTAGE_TREE SOURCE databases include/databases"
      _prodigy_basics_depofile_contents
      "${_prodigy_basics_depofile_contents}"
    )
  endif()

  string(FIND "${_prodigy_basics_depofile_contents}" " tidesdb::tidesdb" _prodigy_tidesdb_link_index)
  if (_prodigy_tidesdb_link_index EQUAL -1)
    string(FIND "${_prodigy_basics_depofile_contents}" " mimalloc::runtime::object" _prodigy_mimalloc_link_index)
    if (_prodigy_mimalloc_link_index EQUAL -1)
      message(
        FATAL_ERROR
        "Published Basics release DepoFile at ${source_depofile} no longer exposes the expected mimalloc link anchor."
      )
    endif()
    string(REPLACE
      " mimalloc::runtime::object"
      " tidesdb::tidesdb mimalloc::runtime::object"
      _prodigy_basics_depofile_contents
      "${_prodigy_basics_depofile_contents}"
    )
  endif()

  if (_prodigy_basics_mimalloc_mode STREQUAL "NONE")
    string(REPLACE
      "# mimalloc mode: OBJECT"
      "# mimalloc mode: NONE"
      _prodigy_basics_depofile_contents
      "${_prodigy_basics_depofile_contents}"
    )
    string(REPLACE
      "\nDEPENDS mimalloc VERSION 3.0.1"
      ""
      _prodigy_basics_depofile_contents
      "${_prodigy_basics_depofile_contents}"
    )
    string(REPLACE
      "DEFINES basics::basics USE_MIMALLOC=1"
      "DEFINES basics::basics USE_MIMALLOC=0"
      _prodigy_basics_depofile_contents
      "${_prodigy_basics_depofile_contents}"
    )
    string(REPLACE
      " tidesdb::tidesdb mimalloc::runtime::object"
      " tidesdb::tidesdb"
      _prodigy_basics_depofile_contents
      "${_prodigy_basics_depofile_contents}"
    )
    string(REPLACE
      " mimalloc::runtime::object"
      ""
      _prodigy_basics_depofile_contents
      "${_prodigy_basics_depofile_contents}"
    )
  endif()

  file(WRITE "${_prodigy_basics_variant_depofile}" "${_prodigy_basics_depofile_contents}")
  set(${out_var} "${_prodigy_basics_variant_depofile}" PARENT_SCOPE)
endfunction()

function(prodigy_resolve_basics_release_depofile out_var)
  set(options ENABLE_TIDESDB)
  cmake_parse_arguments(PRODIGY_BASICS_VARIANT "${options}" "" "" ${ARGN})

  prodigy_resolve_release_depofile(
    _prodigy_basics_depofile
    NAME basics
    VERSION "${PRODIGY_BASICS_RELEASE_VERSION}"
    URL "${PRODIGY_BASICS_RELEASE_DEPOFILE_URL}"
    SHA256 "${PRODIGY_BASICS_RELEASE_DEPOFILE_SHA256}"
  )
  if (PRODIGY_BASICS_VARIANT_ENABLE_TIDESDB)
    _prodigy_patch_basics_release_depofile_for_tidesdb(
      _prodigy_basics_depofile
      "${_prodigy_basics_depofile}"
    )
  endif()
  set(${out_var} "${_prodigy_basics_depofile}" PARENT_SCOPE)
endfunction()

function(prodigy_resolve_basics_local_depofile out_var)
  set(options ENABLE_TIDESDB)
  set(oneValueArgs REPO_DIR BUILD_ROOT)
  cmake_parse_arguments(PRODIGY_BASICS_LOCAL_ARGS "${options}" "${oneValueArgs}" "" ${ARGN})

  if (PRODIGY_BASICS_LOCAL_ARGS_REPO_DIR)
    set(_prodigy_local_basics_repo_dir "${PRODIGY_BASICS_LOCAL_ARGS_REPO_DIR}")
  else()
    set(_prodigy_local_basics_repo_dir "${PRODIGY_BASICS_LOCAL_REPO_DIR}")
  endif()
  if (PRODIGY_BASICS_LOCAL_ARGS_BUILD_ROOT)
    set(_prodigy_local_basics_build_root "${PRODIGY_BASICS_LOCAL_ARGS_BUILD_ROOT}")
  else()
    set(_prodigy_local_basics_build_root "${PRODIGY_BASICS_LOCAL_BUILD_ROOT}")
  endif()

  get_filename_component(_prodigy_local_basics_repo_dir "${_prodigy_local_basics_repo_dir}" ABSOLUTE)
  get_filename_component(_prodigy_local_basics_build_root "${_prodigy_local_basics_build_root}" ABSOLUTE)

  if (NOT EXISTS "${_prodigy_local_basics_repo_dir}/CMakeLists.txt")
    message(
      FATAL_ERROR
      "Local Basics source mode requires a Basics repo at ${_prodigy_local_basics_repo_dir}, but CMakeLists.txt was not found there."
    )
  endif()

  if (PRODIGY_BASICS_LOCAL_ARGS_ENABLE_TIDESDB)
    set(_prodigy_local_basics_tidesdb_enabled "ON")
    set(_prodigy_local_basics_variant_suffix "tidesdb-on")
  else()
    set(_prodigy_local_basics_tidesdb_enabled "OFF")
    set(_prodigy_local_basics_variant_suffix "tidesdb-off")
  endif()

  _prodigy_resolve_basics_mimalloc_mode(_prodigy_local_basics_mimalloc_mode)
  string(TOLOWER "${_prodigy_local_basics_mimalloc_mode}" _prodigy_local_basics_mimalloc_mode_suffix)

  set(
    _prodigy_local_basics_build_dir
    "${_prodigy_local_basics_build_root}/mimalloc-${_prodigy_local_basics_mimalloc_mode_suffix}-deps-static-${_prodigy_local_basics_variant_suffix}"
  )
  set(_prodigy_local_basics_depofile "${_prodigy_local_basics_build_dir}/.deps/basics-self/basics.DepoFile")
  file(MAKE_DIRECTORY "${_prodigy_local_basics_build_root}")

  set(_prodigy_local_basics_configure_command
    "${CMAKE_COMMAND}"
    -S "${_prodigy_local_basics_repo_dir}"
    -B "${_prodigy_local_basics_build_dir}"
  )
  if (DEFINED CMAKE_GENERATOR AND NOT "${CMAKE_GENERATOR}" STREQUAL "")
    list(APPEND _prodigy_local_basics_configure_command -G "${CMAKE_GENERATOR}")
  endif()
  if (DEFINED CMAKE_GENERATOR_PLATFORM AND NOT "${CMAKE_GENERATOR_PLATFORM}" STREQUAL "")
    list(APPEND _prodigy_local_basics_configure_command -A "${CMAKE_GENERATOR_PLATFORM}")
  endif()
  if (DEFINED CMAKE_GENERATOR_TOOLSET AND NOT "${CMAKE_GENERATOR_TOOLSET}" STREQUAL "")
    list(APPEND _prodigy_local_basics_configure_command -T "${CMAKE_GENERATOR_TOOLSET}")
  endif()
  if (DEFINED CMAKE_C_COMPILER AND NOT "${CMAKE_C_COMPILER}" STREQUAL "")
    list(APPEND _prodigy_local_basics_configure_command "-DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}")
  endif()
  if (DEFINED CMAKE_CXX_COMPILER AND NOT "${CMAKE_CXX_COMPILER}" STREQUAL "")
    list(APPEND _prodigy_local_basics_configure_command "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}")
  endif()
  if (DEFINED CMAKE_CXX_STANDARD AND NOT "${CMAKE_CXX_STANDARD}" STREQUAL "")
    list(APPEND _prodigy_local_basics_configure_command "-DCMAKE_CXX_STANDARD=${CMAKE_CXX_STANDARD}")
  endif()
  if (DEFINED CMAKE_CXX_EXTENSIONS)
    list(APPEND _prodigy_local_basics_configure_command "-DCMAKE_CXX_EXTENSIONS=${CMAKE_CXX_EXTENSIONS}")
  endif()
  if (DEFINED CMAKE_BUILD_TYPE AND NOT "${CMAKE_BUILD_TYPE}" STREQUAL "")
    list(APPEND _prodigy_local_basics_configure_command "-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}")
  endif()
  list(APPEND
    _prodigy_local_basics_configure_command
    "-DBUILD_TESTING=OFF"
    "-DBASICS_MIMALLOC_MODE=${_prodigy_local_basics_mimalloc_mode}"
    "-DBASICS_DEPENDENCY_LINK_MODE=STATIC"
    "-DBASICS_ENABLE_TIDESDB=${_prodigy_local_basics_tidesdb_enabled}"
    "-DDEPOS_ROOT=${_prodigy_local_basics_build_root}/depos-root"
    "-DDEPOS_BOOTSTRAP_DIR=${_prodigy_local_basics_build_root}/depos-bootstrap"
  )

  execute_process(
    COMMAND ${_prodigy_local_basics_configure_command}
    RESULT_VARIABLE _prodigy_local_basics_configure_result
    OUTPUT_VARIABLE _prodigy_local_basics_configure_output
    ERROR_VARIABLE _prodigy_local_basics_configure_error
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_STRIP_TRAILING_WHITESPACE
  )
  if (NOT _prodigy_local_basics_configure_result EQUAL 0)
    message(
      FATAL_ERROR
      "Failed to configure local Basics at ${_prodigy_local_basics_repo_dir} for Prodigy dev source mode.\nCommand: ${_prodigy_local_basics_configure_command}\nstdout:\n${_prodigy_local_basics_configure_output}\nstderr:\n${_prodigy_local_basics_configure_error}"
    )
  endif()

  if (NOT EXISTS "${_prodigy_local_basics_depofile}")
    message(
      FATAL_ERROR
      "Configured local Basics at ${_prodigy_local_basics_repo_dir}, but it did not produce the expected self DepoFile at ${_prodigy_local_basics_depofile}."
    )
  endif()

  set(${out_var} "${_prodigy_local_basics_depofile}" PARENT_SCOPE)
endfunction()

function(prodigy_resolve_basics_depofile out_var)
  set(options ENABLE_TIDESDB)
  set(oneValueArgs SOURCE_MODE REPO_DIR BUILD_ROOT)
  cmake_parse_arguments(PRODIGY_BASICS_SELECT "${options}" "${oneValueArgs}" "" ${ARGN})

  set(_prodigy_basics_source_mode "${PRODIGY_BASICS_SELECT_SOURCE_MODE}")
  if ("${_prodigy_basics_source_mode}" STREQUAL "")
    set(_prodigy_basics_source_mode "RELEASE")
  endif()
  string(TOUPPER "${_prodigy_basics_source_mode}" _prodigy_basics_source_mode)

  if (_prodigy_basics_source_mode STREQUAL "AUTO")
    if (PRODIGY_BASICS_SELECT_REPO_DIR)
      set(_prodigy_basics_local_repo_probe "${PRODIGY_BASICS_SELECT_REPO_DIR}")
    else()
      set(_prodigy_basics_local_repo_probe "${PRODIGY_BASICS_LOCAL_REPO_DIR}")
    endif()
    get_filename_component(_prodigy_basics_local_repo_probe "${_prodigy_basics_local_repo_probe}" ABSOLUTE)
    if (EXISTS "${_prodigy_basics_local_repo_probe}/CMakeLists.txt")
      set(_prodigy_basics_source_mode "LOCAL")
    else()
      set(_prodigy_basics_source_mode "RELEASE")
    endif()
  endif()

  if (_prodigy_basics_source_mode STREQUAL "LOCAL")
    set(_prodigy_local_basics_args)
    if (PRODIGY_BASICS_SELECT_ENABLE_TIDESDB)
      list(APPEND _prodigy_local_basics_args ENABLE_TIDESDB)
    endif()
    if (PRODIGY_BASICS_SELECT_REPO_DIR)
      list(APPEND _prodigy_local_basics_args REPO_DIR "${PRODIGY_BASICS_SELECT_REPO_DIR}")
    endif()
    if (PRODIGY_BASICS_SELECT_BUILD_ROOT)
      list(APPEND _prodigy_local_basics_args BUILD_ROOT "${PRODIGY_BASICS_SELECT_BUILD_ROOT}")
    endif()
    prodigy_resolve_basics_local_depofile(_prodigy_basics_depofile ${_prodigy_local_basics_args})
  elseif (_prodigy_basics_source_mode STREQUAL "RELEASE")
    if (PRODIGY_BASICS_SELECT_ENABLE_TIDESDB)
      prodigy_resolve_basics_release_depofile(_prodigy_basics_depofile ENABLE_TIDESDB)
    else()
      prodigy_resolve_basics_release_depofile(_prodigy_basics_depofile)
    endif()
  else()
    message(
      FATAL_ERROR
      "Unsupported Basics source mode '${_prodigy_basics_source_mode}'. Expected AUTO, LOCAL, or RELEASE."
    )
  endif()

  set(${out_var} "${_prodigy_basics_depofile}" PARENT_SCOPE)
endfunction()
