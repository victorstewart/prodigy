if (NOT DEFINED PRODIGY_ROOT OR PRODIGY_ROOT STREQUAL "")
   message(FATAL_ERROR "PRODIGY_ROOT is required.")
endif()

set(_prodigy_public_headers
   prodigy/machine.hardware.types.h
   prodigy/cousin.route.h
   prodigy/cousin.service.permission.h
   prodigy/runtime.environment.h
   prodigy/sha256.digest.h
)
foreach(_prodigy_public_header IN LISTS _prodigy_public_headers)
   file(READ "${PRODIGY_ROOT}/${_prodigy_public_header}" _prodigy_public_header_contents)
   if (_prodigy_public_header_contents MATCHES "#include <basics/includes.h>")
      message(FATAL_ERROR "${_prodigy_public_header} uses the non-exported Basics include path.")
   endif()
   if (NOT _prodigy_public_header_contents MATCHES "#include <includes.h>")
      message(FATAL_ERROR "${_prodigy_public_header} must include the Basics public includes.h header.")
   endif()
endforeach()
