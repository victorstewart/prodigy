if (NOT DEFINED PRODIGY_ROOT)
   message(FATAL_ERROR "PRODIGY_ROOT is required")
endif()

file(READ "${PRODIGY_ROOT}/prodigy/host.delay.operation.h" DELAY_OPERATION)

foreach(REQUIRED IN ITEMS
   "class ProdigyHostDelayOperation final"
   "class Completion final : public TimeoutDispatcher"
   "packet.dispatcher = this;"
   "Ring::queueTimeout(packet);"
   "Ring::queueCancelTimeout(packet);"
   "operation = nullptr;\n      ring.cancel(ring.context, &packet);"
   "pending = nullptr;\n    complete = true;"
   "wakeStack->co_consume();"
   "if (microseconds == 0)"
   "complete = true;\n      return true;")
   string(FIND "${DELAY_OPERATION}" "${REQUIRED}" OFFSET)
   if (OFFSET EQUAL -1)
      message(FATAL_ERROR "host delay operation is missing: ${REQUIRED}")
   endif()
endforeach()

string(FIND "${DELAY_OPERATION}" "operation = nullptr;" DISARM_OWNER_OFFSET)
string(FIND "${DELAY_OPERATION}" "ring.cancel(ring.context, &packet);" CANCEL_OFFSET)
string(FIND "${DELAY_OPERATION}" "pending = nullptr;" CLEAR_PENDING_OFFSET)
string(FIND "${DELAY_OPERATION}" "wakeStack->co_consume();" WAKE_OFFSET)
if (DISARM_OWNER_OFFSET GREATER CANCEL_OFFSET OR CLEAR_PENDING_OFFSET GREATER WAKE_OFFSET)
   message(FATAL_ERROR "host delay operation violates disarm/wake lifetime ordering")
endif()

foreach(FORBIDDEN IN ITEMS
   "std::thread"
   "std::this_thread"
   "sleep("
   "usleep("
   "nanosleep("
   "curl_easy_"
   "curl_multi_")
   string(FIND "${DELAY_OPERATION}" "${FORBIDDEN}" OFFSET)
   if (NOT OFFSET EQUAL -1)
      message(FATAL_ERROR "host delay operation contains alternate blocking/event-loop machinery: ${FORBIDDEN}")
   endif()
endforeach()
