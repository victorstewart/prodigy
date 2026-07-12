#pragma once

#include <types/types.string.h>
#include <simdjson.h>

template <typename Element>
static inline simdjson::error_code prodigyJSONString(Element&& element, String& value)
{
  auto parsed = element.get_string();
  const simdjson::error_code error = parsed.error();
  if (error != simdjson::SUCCESS)
  {
    value.reset();
    return error;
  }

  value.assign(parsed.value_unsafe());
  return simdjson::SUCCESS;
}

static inline void prodigyAppendEscapedJSONStringLiteral(String& output, const String& value)
{
  constexpr static char hex[] = "0123456789ABCDEF";
  output.append('"');

  for (uint64_t index = 0; index < value.size(); ++index)
  {
    uint8_t byte = value[index];

    switch (byte)
    {
      case '\\':
        {
          output.append("\\\\"_ctv);
          break;
        }
      case '"':
        {
          output.append("\\\""_ctv);
          break;
        }
      case '\b':
        {
          output.append("\\b"_ctv);
          break;
        }
      case '\f':
        {
          output.append("\\f"_ctv);
          break;
        }
      case '\n':
        {
          output.append("\\n"_ctv);
          break;
        }
      case '\r':
        {
          output.append("\\r"_ctv);
          break;
        }
      case '\t':
        {
          output.append("\\t"_ctv);
          break;
        }
      default:
        {
          if (byte < 0x20)
          {
            output.append("\\u00"_ctv);
            output.append(uint8_t(hex[byte >> 4]));
            output.append(uint8_t(hex[byte & 0x0f]));
          }
          else
          {
            output.append(byte);
          }
          break;
        }
    }
  }

  output.append('"');
}
