if (NOT DEFINED PRODIGY_ROOT)
   message(FATAL_ERROR "PRODIGY_ROOT is required")
endif()

file(GLOB_RECURSE PRODIGY_SOURCES LIST_DIRECTORIES false
   "${PRODIGY_ROOT}/prodigy/*.h"
   "${PRODIGY_ROOT}/prodigy/*.cpp")

foreach(SOURCE IN LISTS PRODIGY_SOURCES)
   file(READ "${SOURCE}" CONTENT)
   foreach(FORBIDDEN IN ITEMS
      "networking/email.client.h"
      "EmailClient"
      "EmailReporter"
      "sendEmail"
      "batphone"
      "reporterPassword"
      ".reporter"
      "smtp"
      "SMTP")
      string(FIND "${CONTENT}" "${FORBIDDEN}" OFFSET)
      if (NOT OFFSET EQUAL -1)
         message(FATAL_ERROR "Dead SMTP reporter surface '${FORBIDDEN}' remains in ${SOURCE}")
      endif()
   endforeach()
endforeach()
