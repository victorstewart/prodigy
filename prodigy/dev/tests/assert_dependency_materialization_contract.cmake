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
   "cargo build --offline"
   "x86_64) rustflags='-C target-cpu=x86-64 -C target-feature=+aes,+sse2'"
   "aarch64|arm64) rustflags='-C target-cpu=generic -C target-feature=+aes,+neon'"
)
   require_contains("${gxhash}" "${contract}")
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
