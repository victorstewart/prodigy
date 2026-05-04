cmake_minimum_required(VERSION 3.18)
project(ProdigySDK VERSION 1.0.0 LANGUAGES C CXX)

get_filename_component(PRODIGY_REPO_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CTest)

option(PRODIGY_SDK_ENABLE_TESTS "Build Prodigy SDK tests" OFF)
option(PRODIGY_SDK_USE_DEPOS_BASICS "Resolve Basics for the opinionated C++ SDK surface through Prodigy's depofile inventory when available" ON)
set(PRODIGY_SDK_DEPOFILES_DIR "${PRODIGY_REPO_ROOT}/depofiles" CACHE PATH "Path to the Prodigy depofile directory")

if (EXISTS "${PRODIGY_REPO_ROOT}/.depos.cmake")
   include("${PRODIGY_REPO_ROOT}/.depos.cmake")
endif()

add_library(prodigy_sdk_c STATIC
   c/prodigy_neuron_hub.c
)
add_library(Prodigy::SdkC ALIAS prodigy_sdk_c)
target_compile_features(prodigy_sdk_c PUBLIC c_std_11)
target_include_directories(prodigy_sdk_c
   PUBLIC
      $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/c>
      $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
set_target_properties(prodigy_sdk_c PROPERTIES
   EXPORT_NAME SdkC
   OUTPUT_NAME prodigy-sdk-c
)

add_library(prodigy_sdk_cpp INTERFACE)
add_library(Prodigy::SdkCpp ALIAS prodigy_sdk_cpp)
target_compile_features(prodigy_sdk_cpp INTERFACE cxx_std_20)
target_include_directories(prodigy_sdk_cpp
   INTERFACE
      $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/cpp>
      $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
set_target_properties(prodigy_sdk_cpp PROPERTIES
   EXPORT_NAME SdkCpp
)

set(_PRODIGY_SDK_C_EXPORTED_TARGETS "Prodigy::SdkC")
set(_PRODIGY_SDK_CPP_EXPORTED_TARGETS "Prodigy::SdkCpp")
set(_PRODIGY_SDK_HAS_CPP_OPINIONATED OFF)
set(_PRODIGY_SDK_C_INSTALL_TARGETS prodigy_sdk_c)
set(_PRODIGY_SDK_CPP_INSTALL_TARGETS prodigy_sdk_cpp)
set(_PRODIGY_SDK_C_INSTALLED_DEPOFILE_RELATIVE_PATHS)
set(_PRODIGY_SDK_CPP_INSTALLED_DEPOFILE_RELATIVE_PATHS)
set(
   _PRODIGY_SDK_C_INSTALL_DEPOFILES
   "${PRODIGY_SDK_DEPOFILES_DIR}/aegis.DepoFile"
   "${PRODIGY_SDK_DEPOFILES_DIR}/gxhash.DepoFile"
)
set(
   _PRODIGY_SDK_CPP_INSTALL_DEPOFILES
   "${PRODIGY_SDK_DEPOFILES_DIR}/aegis.DepoFile"
   "${PRODIGY_SDK_DEPOFILES_DIR}/gxhash.DepoFile"
)

if (PRODIGY_SDK_USE_DEPOS_BASICS
   AND COMMAND depos_depend
   AND NOT TARGET basics::basics
   AND COMMAND prodigy_resolve_basics_release_depofile)
   prodigy_resolve_basics_release_depofile(_PRODIGY_SDK_BASICS_DEPOFILE)
   file(GLOB _PRODIGY_SDK_LOCAL_DEPOFILES CONFIGURE_DEPENDS "${PRODIGY_SDK_DEPOFILES_DIR}/*.DepoFile")
   list(SORT _PRODIGY_SDK_LOCAL_DEPOFILES)
   set(_PRODIGY_SDK_DEPOFILES "${_PRODIGY_SDK_BASICS_DEPOFILE}")
   list(APPEND _PRODIGY_SDK_DEPOFILES ${_PRODIGY_SDK_LOCAL_DEPOFILES})
   list(SORT _PRODIGY_SDK_DEPOFILES)
   depos_depend(FILES ${_PRODIGY_SDK_DEPOFILES})
   _depos_ensure_registry_ready()
   unset(_PRODIGY_SDK_BASICS_DEPOFILE)
   unset(_PRODIGY_SDK_LOCAL_DEPOFILES)
   unset(_PRODIGY_SDK_DEPOFILES)
endif()

if (NOT TARGET aegis::aegis OR NOT TARGET gxhash::gxhash)
   message(FATAL_ERROR "Prodigy C and C++ SDKs require aegis::aegis and gxhash::gxhash targets.")
endif()

target_link_libraries(prodigy_sdk_c
   PUBLIC
      aegis::aegis
      gxhash::gxhash
)
target_link_libraries(prodigy_sdk_cpp
   INTERFACE
      aegis::aegis
      gxhash::gxhash
)

if (PRODIGY_SDK_ENABLE_TESTS)
   add_executable(
      prodigy_sdk_c_selftest
      c/prodigy_neuron_hub_selftest.c
   )
   target_link_libraries(
      prodigy_sdk_c_selftest
      PRIVATE
         Prodigy::SdkC
   )
   target_compile_definitions(
      prodigy_sdk_c_selftest
      PRIVATE
         PRODIGY_SDK_FIXTURES_DIR="${CMAKE_CURRENT_LIST_DIR}/fixtures"
   )
   add_test(
      NAME prodigy_sdk_c_selftest
      COMMAND prodigy_sdk_c_selftest
   )

   add_executable(
      prodigy_sdk_c_aegis_example_smoke
      c/examples/aegis_roundtrip.c
   )
   target_link_libraries(
      prodigy_sdk_c_aegis_example_smoke
      PRIVATE
         Prodigy::SdkC
   )
   add_test(
      NAME prodigy_sdk_c_aegis_example_smoke
      COMMAND prodigy_sdk_c_aegis_example_smoke
   )

   add_executable(
      prodigy_sdk_cpp_aegis_example_smoke
      cpp/examples/aegis_roundtrip.cpp
   )
   target_link_libraries(
      prodigy_sdk_cpp_aegis_example_smoke
      PRIVATE
         Prodigy::SdkCpp
   )
   add_test(
      NAME prodigy_sdk_cpp_aegis_example_smoke
      COMMAND prodigy_sdk_cpp_aegis_example_smoke
   )
endif()

if (TARGET basics::basics)

   add_library(prodigy_sdk_cpp_opinionated INTERFACE)
   add_library(Prodigy::SdkCppOpinionated ALIAS prodigy_sdk_cpp_opinionated)
   target_compile_features(prodigy_sdk_cpp_opinionated INTERFACE cxx_std_20)
   target_link_libraries(prodigy_sdk_cpp_opinionated
      INTERFACE
         Prodigy::SdkCpp
         basics::basics
   )
   set_target_properties(prodigy_sdk_cpp_opinionated PROPERTIES
      EXPORT_NAME SdkCppOpinionated
   )
   set(_PRODIGY_SDK_HAS_CPP_OPINIONATED ON)
   list(APPEND _PRODIGY_SDK_CPP_EXPORTED_TARGETS "Prodigy::SdkCppOpinionated")
   list(APPEND _PRODIGY_SDK_CPP_INSTALL_TARGETS prodigy_sdk_cpp_opinionated)

   if (PRODIGY_SDK_ENABLE_TESTS)
      add_executable(
         prodigy_sdk_cpp_opinionated_example_smoke
         cpp/examples/opinionated_aegis_roundtrip.cpp
      )
      target_link_libraries(
         prodigy_sdk_cpp_opinionated_example_smoke
         PRIVATE
            Prodigy::SdkCppOpinionated
      )

      add_executable(
         prodigy_sdk_cpp_opinionated_smoke
         cpp/tests/opinionated_aegis_smoke.cpp
      )
      target_link_libraries(
         prodigy_sdk_cpp_opinionated_smoke
         PRIVATE
            Prodigy::SdkCppOpinionated
      )
      target_compile_definitions(
         prodigy_sdk_cpp_opinionated_smoke
         PRIVATE
            PRODIGY_SDK_FIXTURES_DIR="${CMAKE_CURRENT_LIST_DIR}/fixtures"
      )
      add_test(
         NAME prodigy_sdk_cpp_opinionated_smoke
         COMMAND prodigy_sdk_cpp_opinionated_smoke
      )
      add_test(
         NAME prodigy_sdk_cpp_opinionated_example_smoke
         COMMAND prodigy_sdk_cpp_opinionated_example_smoke
      )
   endif()
endif()

foreach(_PRODIGY_SDK_DEPOFILE IN LISTS _PRODIGY_SDK_C_INSTALL_DEPOFILES)
   get_filename_component(_PRODIGY_SDK_DEPOFILE_NAME "${_PRODIGY_SDK_DEPOFILE}" NAME)
   list(APPEND _PRODIGY_SDK_C_INSTALLED_DEPOFILE_RELATIVE_PATHS "${CMAKE_INSTALL_DATADIR}/prodigy-sdk/depofiles/${_PRODIGY_SDK_DEPOFILE_NAME}")
endforeach()

foreach(_PRODIGY_SDK_DEPOFILE IN LISTS _PRODIGY_SDK_CPP_INSTALL_DEPOFILES)
   get_filename_component(_PRODIGY_SDK_DEPOFILE_NAME "${_PRODIGY_SDK_DEPOFILE}" NAME)
   list(APPEND _PRODIGY_SDK_CPP_INSTALLED_DEPOFILE_RELATIVE_PATHS "${CMAKE_INSTALL_DATADIR}/prodigy-sdk/depofiles/${_PRODIGY_SDK_DEPOFILE_NAME}")
endforeach()

if (_PRODIGY_SDK_HAS_CPP_OPINIONATED)
   if (NOT COMMAND prodigy_resolve_basics_release_depofile)
      message(FATAL_ERROR "Installed opinionated C++ SDK target requires prodigy_resolve_basics_release_depofile.")
   endif()

   prodigy_resolve_basics_release_depofile(_PRODIGY_SDK_INSTALL_BASICS_DEPOFILE)
   list(APPEND _PRODIGY_SDK_CPP_INSTALLED_DEPOFILE_RELATIVE_PATHS "${CMAKE_INSTALL_DATADIR}/prodigy-sdk/depofiles/basics.DepoFile")
endif()

set(_PRODIGY_SDK_INSTALL_DEPOFILES ${_PRODIGY_SDK_C_INSTALL_DEPOFILES} ${_PRODIGY_SDK_CPP_INSTALL_DEPOFILES})
list(REMOVE_DUPLICATES _PRODIGY_SDK_INSTALL_DEPOFILES)

configure_package_config_file(
   "${CMAKE_CURRENT_LIST_DIR}/cmake/ProdigySDKCConfig.cmake.in"
   "${CMAKE_CURRENT_BINARY_DIR}/ProdigySDKCConfig.cmake"
   INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/ProdigySDKC"
)
configure_package_config_file(
   "${CMAKE_CURRENT_LIST_DIR}/cmake/ProdigySDKConfig.cmake.in"
   "${CMAKE_CURRENT_BINARY_DIR}/ProdigySDKConfig.cmake"
   INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/ProdigySDK"
)
write_basic_package_version_file(
   "${CMAKE_CURRENT_BINARY_DIR}/ProdigySDKCConfigVersion.cmake"
   VERSION "${PROJECT_VERSION}"
   COMPATIBILITY SameMajorVersion
)
write_basic_package_version_file(
   "${CMAKE_CURRENT_BINARY_DIR}/ProdigySDKConfigVersion.cmake"
   VERSION "${PROJECT_VERSION}"
   COMPATIBILITY SameMajorVersion
)

install(TARGETS ${_PRODIGY_SDK_C_INSTALL_TARGETS}
   EXPORT ProdigySDKCTargets
   ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
   LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
   RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)
install(TARGETS ${_PRODIGY_SDK_CPP_INSTALL_TARGETS}
   EXPORT ProdigySDKTargets
   ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
   LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
   RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)

install(FILES
   "${CMAKE_CURRENT_LIST_DIR}/c/prodigy_neuron_hub.h"
   DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/prodigy/c"
   RENAME neuron_hub.h
)
install(FILES
   "${CMAKE_CURRENT_LIST_DIR}/cpp/neuron_hub.h"
   "${CMAKE_CURRENT_LIST_DIR}/cpp/aegis_session.h"
   DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/prodigy"
)
if (_PRODIGY_SDK_HAS_CPP_OPINIONATED)
   install(FILES
      "${CMAKE_CURRENT_LIST_DIR}/cpp/opinionated/aegis_stream.h"
      "${CMAKE_CURRENT_LIST_DIR}/cpp/opinionated/pairings.h"
      DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/prodigy/opinionated"
   )
endif()
install(FILES
   "${CMAKE_CURRENT_LIST_DIR}/c/prodigy_neuron_hub.c"
   "${CMAKE_CURRENT_LIST_DIR}/c/prodigy_neuron_hub.h"
   DESTINATION "${CMAKE_INSTALL_DATADIR}/prodigy-sdk-c/src"
)
install(FILES
   "${CMAKE_CURRENT_LIST_DIR}/LICENSE"
   "${CMAKE_CURRENT_LIST_DIR}/README.md"
   "${CMAKE_CURRENT_LIST_DIR}/AEGIS.md"
   "${CMAKE_CURRENT_LIST_DIR}/INTERFACES.md"
   "${CMAKE_CURRENT_LIST_DIR}/WIRE.md"
   "${CMAKE_CURRENT_LIST_DIR}/VERSIONING.md"
   "${CMAKE_CURRENT_LIST_DIR}/versioning.json"
   DESTINATION "${CMAKE_INSTALL_DATADIR}/prodigy-sdk"
)
install(FILES
   "${CMAKE_CURRENT_BINARY_DIR}/ProdigySDKCConfig.cmake"
   "${CMAKE_CURRENT_BINARY_DIR}/ProdigySDKCConfigVersion.cmake"
   DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/ProdigySDKC"
)
install(FILES
   "${CMAKE_CURRENT_BINARY_DIR}/ProdigySDKConfig.cmake"
   "${CMAKE_CURRENT_BINARY_DIR}/ProdigySDKConfigVersion.cmake"
   DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/ProdigySDK"
)
install(FILES
   "${PRODIGY_REPO_ROOT}/.depos.cmake"
   DESTINATION "${CMAKE_INSTALL_DATADIR}/prodigy-sdk/cmake"
   RENAME ProdigySDKDepos.cmake
)
if (_PRODIGY_SDK_HAS_CPP_OPINIONATED)
   install(FILES
      "${_PRODIGY_SDK_INSTALL_BASICS_DEPOFILE}"
      DESTINATION "${CMAKE_INSTALL_DATADIR}/prodigy-sdk/depofiles"
      RENAME basics.DepoFile
   )
endif()
install(FILES
   ${_PRODIGY_SDK_INSTALL_DEPOFILES}
   DESTINATION "${CMAKE_INSTALL_DATADIR}/prodigy-sdk/depofiles"
)
install(EXPORT ProdigySDKTargets
   FILE ProdigySDKTargets.cmake
   NAMESPACE Prodigy::
   DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/ProdigySDK"
)
install(EXPORT ProdigySDKCTargets
   FILE ProdigySDKCTargets.cmake
   NAMESPACE Prodigy::
   DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/ProdigySDKC"
)
