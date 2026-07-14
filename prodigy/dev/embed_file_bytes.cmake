if(NOT DEFINED INPUT OR NOT DEFINED OUTPUT OR NOT DEFINED SYMBOL)
   message(FATAL_ERROR "INPUT, OUTPUT, and SYMBOL are required")
endif()

file(READ "${INPUT}" CONTENT HEX)
string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," BYTES "${CONTENT}")
get_filename_component(OUTPUT_DIRECTORY "${OUTPUT}" DIRECTORY)
file(MAKE_DIRECTORY "${OUTPUT_DIRECTORY}")
set(TEMPORARY "${OUTPUT}.tmp")
file(WRITE "${TEMPORARY}" "inline constexpr unsigned char ${SYMBOL}[] = {${BYTES}};\n")
execute_process(
   COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${TEMPORARY}" "${OUTPUT}"
   COMMAND_ERROR_IS_FATAL ANY
)
file(REMOVE "${TEMPORARY}")
