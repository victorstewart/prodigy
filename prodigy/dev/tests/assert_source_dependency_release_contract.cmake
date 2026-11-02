if (NOT DEFINED PRODIGY_ROOT OR PRODIGY_ROOT STREQUAL "")
   message(FATAL_ERROR "PRODIGY_ROOT is required.")
endif()

set(_prodigy_source_dependency_packager
   "${PRODIGY_ROOT}/tools/package-source-dependency.sh")
if (NOT EXISTS "${_prodigy_source_dependency_packager}")
   message(FATAL_ERROR "Missing Prodigy source-dependency release producer.")
endif()

file(READ "${PRODIGY_ROOT}/depos.project.cmake" _prodigy_depos_project)
foreach(_prodigy_basics_release_contract IN ITEMS
   [[PRODIGY_BASICS_RELEASE_VERSION
  "0.4.14-rc.1"]]
   [[https://github.com/victorstewart/basics/releases/download/v0.4.14-rc.1/basics.DepoFile]]
   [[0d9343147640e59f5ee68dc1110fbc74b0817d1443dd49338e09ad8ea8afe3f6]]
)
   string(FIND "${_prodigy_depos_project}" "${_prodigy_basics_release_contract}"
      _prodigy_basics_release_contract_index)
   if (_prodigy_basics_release_contract_index EQUAL -1)
      message(FATAL_ERROR
         "Prodigy dev does not select the release-tested Basics candidate: ${_prodigy_basics_release_contract}")
   endif()
endforeach()

file(READ "${_prodigy_source_dependency_packager}" _prodigy_source_dependency_script)
if (NOT _prodigy_source_dependency_script MATCHES
   "for public_root in prodigy switchboard macros enums services; do")
   message(FATAL_ERROR "The source-dependency release producer must stage the Prodigy public header tree.")
endif()
foreach(_prodigy_required_public_header IN ITEMS
   cousin.session.h
   cousin.discovery.h
   cousin.route.h
   cluster.pair.keys.h
)
   if (NOT EXISTS "${PRODIGY_ROOT}/prodigy/${_prodigy_required_public_header}")
      message(FATAL_ERROR
         "Missing required public header prodigy/${_prodigy_required_public_header}.")
   endif()
endforeach()

if (NOT _prodigy_source_dependency_script MATCHES
   "DEPENDS \\$\\{basics_package\\} VERSION \\$\\{basics_version\\}")
   message(FATAL_ERROR "The source-dependency release producer must declare its Basics dependency.")
endif()
if (NOT _prodigy_source_dependency_script MATCHES
   "basics_version=\"0\\.4\\.14-rc\\.1\"")
   message(FATAL_ERROR "The source-dependency release producer must pin Basics 0.4.14-rc.1.")
endif()
if (NOT _prodigy_source_dependency_script MATCHES
   "basics_package=\"basics\"")
   message(FATAL_ERROR "The source-dependency release producer must use the published Basics package name.")
endif()
foreach(_prodigy_basics_release_input IN ITEMS
   PRODIGY_SOURCE_DEPENDENCY_BASICS_ARCHIVE
   PRODIGY_SOURCE_DEPENDENCY_BASICS_ARCHIVE_SHA256
   PRODIGY_SOURCE_DEPENDENCY_BASICS_RELEASE_URL
   BASICS_RELEASE_INPUT
)
   if (NOT _prodigy_source_dependency_script MATCHES "${_prodigy_basics_release_input}")
      message(FATAL_ERROR "The source-dependency release producer must require ${_prodigy_basics_release_input}.")
   endif()
endforeach()
if (NOT _prodigy_source_dependency_script MATCHES
   "basics/releases/download/v")
   message(FATAL_ERROR "The source-dependency release producer must require an immutable Basics release URL.")
endif()
if (NOT _prodigy_source_dependency_script MATCHES
   "rust_toolchain_version=\"1\\.97\\.1\"")
   message(FATAL_ERROR "The source-dependency release producer must pin Rust 1.97.1.")
endif()
foreach(_prodigy_pinned_rust_tool IN ITEMS
   "PRODIGY_SOURCE_DEPENDENCY_CARGO"
   "PRODIGY_SOURCE_DEPENDENCY_RUSTC"
)
   if (NOT _prodigy_source_dependency_script MATCHES "${_prodigy_pinned_rust_tool}")
      message(FATAL_ERROR "The source-dependency release producer must select ${_prodigy_pinned_rust_tool}.")
   endif()
endforeach()
if (NOT _prodigy_source_dependency_script MATCHES
   "releases/download/v\\$\\{version\\}/\\$\\{asset_name\\}")
   message(FATAL_ERROR "The publishable DepoFile must use its immutable release asset URL.")
endif()
if (NOT _prodigy_source_dependency_script MATCHES
   "libprodigy_noise\\.a")
   message(FATAL_ERROR "The source-dependency release producer must package the Noise static library.")
endif()
