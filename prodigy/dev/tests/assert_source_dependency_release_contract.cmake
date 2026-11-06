if (NOT DEFINED PRODIGY_ROOT OR PRODIGY_ROOT STREQUAL "")
   message(FATAL_ERROR "PRODIGY_ROOT is required.")
endif()

set(_prodigy_source_dependency_packager
   "${PRODIGY_ROOT}/tools/package-source-dependency.sh")
if (NOT EXISTS "${_prodigy_source_dependency_packager}")
   message(FATAL_ERROR "Missing Prodigy source-dependency release producer.")
endif()

file(GLOB _prodigy_release_depofiles "${PRODIGY_ROOT}/depofiles/*.DepoFile")
foreach(_prodigy_release_depofile IN LISTS _prodigy_release_depofiles)
   file(READ "${_prodigy_release_depofile}" _prodigy_release_depofile_contents)
   if (_prodigy_release_depofile_contents MATCHES "SOURCE[ \t]+URL[ \t]+file://" OR
       _prodigy_release_depofile_contents MATCHES "(^|[/])\\.run([/]|$)")
      message(FATAL_ERROR
         "Published Prodigy dependency recipes must not reference task-local sources: ${_prodigy_release_depofile}")
   endif()
endforeach()
file(READ "${PRODIGY_ROOT}/depofiles/tidesdb.DepoFile" _prodigy_tidesdb_depofile)
foreach(_prodigy_tidesdb_release_contract IN ITEMS
   [[VERSION 10.2.1.20261106.051416]]
   [[SOURCE URL https://github.com/victorstewart/tidesdb/archive/81691faa9032b1e192c0e15cb63170f485e89d30.tar.gz]]
   [[SHA256 a8288f4098ae21ddad86a67f22b6f07b5fe1043a5e3dcbf996765d4c48d36877]]
)
   string(FIND "${_prodigy_tidesdb_depofile}" "${_prodigy_tidesdb_release_contract}"
      _prodigy_tidesdb_release_contract_index)
   if (_prodigy_tidesdb_release_contract_index EQUAL -1)
      message(FATAL_ERROR "TidesDB release contract drifted: ${_prodigy_tidesdb_release_contract}")
   endif()
endforeach()

file(READ "${PRODIGY_ROOT}/depos.project.cmake" _prodigy_depos_project)
foreach(_prodigy_basics_release_contract IN ITEMS
   [[PRODIGY_BASICS_RELEASE_VERSION
  "0.4.14-rc.6"]]
   [[https://github.com/victorstewart/basics/releases/download/v0.4.14-rc.6/basics.DepoFile]]
   [[589570e477ee33566f824f310f63833762a3b62c92b2e30ccb5b057d702c7f3e]]
)
   string(FIND "${_prodigy_depos_project}" "${_prodigy_basics_release_contract}"
      _prodigy_basics_release_contract_index)
   if (_prodigy_basics_release_contract_index EQUAL -1)
      message(FATAL_ERROR
         "Prodigy dev does not select the release-tested Basics candidate: ${_prodigy_basics_release_contract}")
   endif()
endforeach()
foreach(_prodigy_pinned_basics_cache_contract IN ITEMS
   PRODIGY_BASICS_RELEASE_VERSION
   PRODIGY_BASICS_RELEASE_DEPOFILE_URL
   PRODIGY_BASICS_RELEASE_DEPOFILE_SHA256
   PRODIGY_BASICS_TIDESDB_DEPENDENCY_VERSION
)
   string(REGEX MATCH
      "set\\([ \t\r\n]*${_prodigy_pinned_basics_cache_contract}[ \t\r\n]+[^)]*FORCE[ \t\r\n]*\\)"
      _prodigy_pinned_basics_cache_match
      "${_prodigy_depos_project}")
   if ("${_prodigy_pinned_basics_cache_match}" STREQUAL "")
      message(FATAL_ERROR
         "Prodigy must replace stale cache state for ${_prodigy_pinned_basics_cache_contract}.")
   endif()
endforeach()
if (NOT _prodigy_depos_project MATCHES
   "PRODIGY_BASICS_TIDESDB_DEPENDENCY_VERSION[ \t\r\n]+\"10\\.2\\.1\\.20261106\\.051416\"")
   message(FATAL_ERROR "The derived Basics package must depend on the published TidesDB foundation.")
endif()

file(READ "${_prodigy_source_dependency_packager}" _prodigy_source_dependency_script)
string(FIND "${_prodigy_source_dependency_script}"
   [[version="${PRODIGY_SOURCE_DEPENDENCY_VERSION:-0.4.5-rc.3}"]]
   _prodigy_source_release_identity_index)
if (_prodigy_source_release_identity_index EQUAL -1)
   message(FATAL_ERROR "The source-dependency release producer must own Prodigy 0.4.5-rc.3.")
endif()
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
   "basics_version=\"0\\.4\\.14-rc\\.6\"")
   message(FATAL_ERROR "The source-dependency release producer must pin Basics 0.4.14-rc.6.")
endif()
if (NOT _prodigy_source_dependency_script MATCHES
   "basics_package=\"basics\"")
   message(FATAL_ERROR "The source-dependency release producer must use the published Basics package name.")
endif()
foreach(_prodigy_basics_release_input IN ITEMS
   PRODIGY_SOURCE_DEPENDENCY_BASICS_ARCHIVE
   PRODIGY_SOURCE_DEPENDENCY_BASICS_ARCHIVE_SHA256
   PRODIGY_SOURCE_DEPENDENCY_BASICS_RELEASE_URL
   RELEASE-RECEIPT.txt
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
foreach(_prodigy_release_receipt_contract IN ITEMS
   [[FORMAT=prodigy-source-dependency-release-v1]]
   [[SOURCE_MANIFEST_SHA256=]]
   [[NOISE_PREFLIGHT_ARCHIVE_SHA256=]]
   [[NOISE_PREFLIGHT_ELF_CLASS=]]
   [[NOISE_PREFLIGHT_ELF_MACHINE=]]
   [[BASICS_ARCHIVE_NAME=]]
   [[CARGO_EXECUTABLE_SHA256=]]
   [[RUSTC_EXECUTABLE_SHA256=]]
   [[RELEASE-RECEIPT.txt SOURCE-MANIFEST.sha256 > SHA256SUMS]]
)
   string(FIND "${_prodigy_source_dependency_script}" "${_prodigy_release_receipt_contract}"
      _prodigy_release_receipt_contract_index)
   if (_prodigy_release_receipt_contract_index EQUAL -1)
      message(FATAL_ERROR
         "The source-dependency release receipt is missing: ${_prodigy_release_receipt_contract}")
   endif()
endforeach()
if (_prodigy_source_dependency_script MATCHES
   [[sha256sum "\$\{archive\}" "\$\{depofile\}" "\$\{local_depofile\}"]])
   message(FATAL_ERROR "Published source-dependency checksums must not include a host-specific local DepoFile.")
endif()
if (_prodigy_source_dependency_script MATCHES [[BASICS_ARCHIVE=\$\{basics_archive\}]])
   message(FATAL_ERROR "The source-dependency release receipt must not disclose a producer-local Basics path.")
endif()
