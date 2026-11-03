if (NOT DEFINED PRODIGY_ROOT)
   message(FATAL_ERROR "PRODIGY_ROOT is required")
endif()

function(require_contains file needle)
   file(READ "${file}" contents)
   string(FIND "${contents}" "${needle}" found)
   if (found EQUAL -1)
      message(FATAL_ERROR "${file} is missing: ${needle}")
   endif()
endfunction()

set(gxhash "${PRODIGY_ROOT}/depofiles/gxhash.DepoFile")
foreach(contract IN ITEMS
   "SHA256 2193998ffd0ae6e3db5e4a53d364d98255c2a44f268a11cafbe70a44fbec6768"
   "default-features = false"
   "DEPENDS rust_toolchain VERSION 1.97.1"
   "export RUSTC=\"\${dep:rust_toolchain}/bin/rustc\""
   "cargo build --offline"
   "x86_64) rustflags='-C target-cpu=x86-64 -C target-feature=+aes,+sse2'"
   "aarch64|arm64) rustflags='-C target-cpu=generic -C target-feature=+aes,+neon'"
)
   require_contains("${gxhash}" "${contract}")
endforeach()

set(rust_toolchain "${PRODIGY_ROOT}/depofiles/rust-toolchain.DepoFile")
foreach(contract IN ITEMS
   "VERSION 1.97.1"
   "SOURCE_VARIANT linux x86_64 URL https://static.rust-lang.org/dist/rust-1.97.1-x86_64-unknown-linux-gnu.tar.xz SHA256 88f28fa9af20594179f85d6df67078dfd6fa93e2f6da5e1e9b0ac4997988ca4f"
   "SOURCE_VARIANT linux aarch64"
   "SOURCE_VARIANT macos x86_64"
   "SOURCE_VARIANT macos aarch64"
   "\"\${DEPO_SOURCE_DIR}/install.sh\""
   "--prefix=\"\${DEPO_PREFIX}\" --disable-ldconfig"
   "ARTIFACT bin/rustc"
   "ARTIFACT bin/rustdoc"
   "ARTIFACT bin/cargo"
   "TARGET rust_toolchain::sysroot INTERFACE lib"
)
   require_contains("${rust_toolchain}" "${contract}")
endforeach()

set(openssl "${PRODIGY_ROOT}/depofiles/openssl.DepoFile")
foreach(contract IN ITEMS
   "SHA256 c32cf49a959c4f345f9606982dd36e7d28f7c58b19c2e25d75624d2b3d2f79ac"
   "Darwin:aarch64|Darwin:arm64) openssl_target=darwin64-arm64-cc"
   "Darwin:x86_64|Darwin:amd64) openssl_target=darwin64-x86_64-cc"
   "Linux:*) openssl_target=\"linux-\${DEPO_TARGET_ARCH}\""
   "CC=clang ./Configure"
)
   require_contains("${openssl}" "${contract}")
endforeach()

set(masque_tunnel "${PRODIGY_ROOT}/depofiles/masque-tunnel.DepoFile")
foreach(contract IN ITEMS
   "NAME masque_tunnel"
   "VERSION 0.18.3-mtls-site-routing-12"
   "SOURCE URL https://github.com/ferneast/masque-tunnel/archive/17d7282d0638d742e1302ac2219e35376bcdc7e2.tar.gz"
   "SHA256 ee9decc7d06316d41856dbfbdf623f8291998c82e0ec8ab6dbb7633331e795ec"
   "e2a1aa35820269d70cea5730330167647896d1b42d9135fd5a50f168afdbdc19"
   "115605ce3f2c8e456336ae8c57780c5ccca68d6217fa57dc414dc88b90c25b63"
   "Cargo.lock is generated from immutable upstream v0.18.3 plus this verified patch."
   "| gzip -dc > \"$lock_file\""
   "| gzip -dc > \"$patch_file\""
   "patch --batch -d \"$DEPO_SOURCE_DIR\" -p1"
   "cargo build --locked --release --bin masque-tunnel"
   "STAGE_FILE BUILD cargo-target/release/masque-tunnel bin/masque-tunnel"
   "ARTIFACT bin/masque-tunnel"
)
   require_contains("${masque_tunnel}" "${contract}")
endforeach()

file(SIZE "${masque_tunnel}" masque_tunnel_depofile_bytes)
if (masque_tunnel_depofile_bytes GREATER 131072)
   message(FATAL_ERROR "masque-tunnel DepoFile payload must remain below the Linux per-argument safety bound")
endif()

set(prodigy_dev "${PRODIGY_ROOT}/prodigy/dev/CMakeLists.txt")
foreach(contract IN ITEMS
   "Prodigy build-local Depos root"
   "Prodigy Depos root inherited from ENV{DEPOS_ROOT}"
   "Prodigy build-local Depos bootstrap state"
   [["$ENV{DEPOS_ROOT}"]]
   "\${PRODIGY_DEPOFILES_DIR}/masque-tunnel.DepoFile"
   "file(STRINGS \"\${DEPOS_MANIFEST_FILE}\" _prodigy_masque_tunnel_manifest_lines"
   "masque_tunnel VERSION [^ )]+\${_prodigy_masque_tunnel_manifest_namespace_suffix}"
   "_prodigy_masque_tunnel_materialized_version"
   "expected \${_prodigy_masque_tunnel_version} from \${_prodigy_masque_tunnel_depofile}"
   "\${_prodigy_masque_tunnel_version}/bin/masque-tunnel"
   "unset(PRODIGY_MASQUE_TUNNEL_BINARY CACHE)"
   "PRODIGY_MASQUE_TUNNEL_BINARY"
   "add_executable(prodigy::masque_tunnel IMPORTED GLOBAL)"
   "--depos-root=\${PRODIGY_DEPOS_ROOT}"
)
   require_contains("${prodigy_dev}" "${contract}")
endforeach()

set(prodigy_sdk_mesh "${PRODIGY_ROOT}/prodigy/dev/tests/prodigy_dev_sdk_mesh_e2e_matrix.sh")
foreach(contract IN ITEMS
   [[--depos-root=*)]]
   [[local dep_store_root="${depos_root}/store"]]
)
   require_contains("${prodigy_sdk_mesh}" "${contract}")
endforeach()
file(READ "${prodigy_sdk_mesh}" prodigy_sdk_mesh_contents)
if (prodigy_sdk_mesh_contents MATCHES "REPO_ROOT}/\\.depos/\\.root")
   message(FATAL_ERROR "SDK mesh must consume the configured Depos root, not source-adjacent state.")
endif()

file(READ "${prodigy_dev}" prodigy_dev_contents)
string(FIND "${prodigy_dev_contents}" "0.18.3-mtls-site-routing-3" stale_masque_tunnel_version)
if (NOT stale_masque_tunnel_version EQUAL -1)
   message(FATAL_ERROR "Prodigy dev must not retain a stale masque-tunnel package version.")
endif()

if (DEFINED PRODIGY_DEPOS_MANIFEST_FILE)
   if (NOT EXISTS "${PRODIGY_DEPOS_MANIFEST_FILE}")
      message(FATAL_ERROR "PRODIGY_DEPOS_MANIFEST_FILE does not exist: ${PRODIGY_DEPOS_MANIFEST_FILE}")
   endif()
   if (NOT DEFINED PRODIGY_DEPOS_MANIFEST_VISIBLE_NAMESPACE OR NOT DEFINED PRODIGY_MASQUE_TUNNEL_VERSION)
      message(FATAL_ERROR "Generated Depos manifest regression requires its namespace and masque-tunnel version.")
   endif()
   set(materialized_masque_tunnel_namespace_suffix "")
   if (NOT "${PRODIGY_DEPOS_MANIFEST_VISIBLE_NAMESPACE}" STREQUAL "")
      set(materialized_masque_tunnel_namespace_suffix
         " NAMESPACE ${PRODIGY_DEPOS_MANIFEST_VISIBLE_NAMESPACE}")
   endif()
   file(STRINGS "${PRODIGY_DEPOS_MANIFEST_FILE}" materialized_masque_tunnel_lines
      REGEX "^depos_require\\(masque_tunnel VERSION ${PRODIGY_MASQUE_TUNNEL_VERSION}${materialized_masque_tunnel_namespace_suffix}\\)$")
   list(LENGTH materialized_masque_tunnel_lines materialized_masque_tunnel_count)
   if (NOT materialized_masque_tunnel_count EQUAL 1)
      message(FATAL_ERROR "Generated Depos manifest must contain exactly one current masque_tunnel request for the configured namespace and version.")
   endif()
endif()
