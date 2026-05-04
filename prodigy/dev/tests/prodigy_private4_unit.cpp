#include <networking/private4.h>
#include <services/debug.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

class TestSuite
{
public:

   int failed = 0;

   void expect(bool condition, const char *name)
   {
      if (condition)
      {
         basics_log("PASS: %s\n", name);
      }
      else
      {
         basics_log("FAIL: %s\n", name);
         failed += 1;
      }
   }
};

static uint32_t makeIPv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
   uint32_t ipv4 = 0;
   uint8_t bytes[4] = { a, b, c, d };
   std::memcpy(&ipv4, bytes, sizeof(bytes));
   return ipv4;
}

int main(void)
{
   TestSuite suite;

   suite.expect(isRFC1918Private4(makeIPv4(10, 0, 0, 1)), "private4_10_8");
   suite.expect(isRFC1918Private4(makeIPv4(172, 31, 14, 99)), "private4_172_16_12");
   suite.expect(isRFC1918Private4(makeIPv4(192, 168, 1, 25)), "private4_192_168_16");
   suite.expect(isRFC1918Private4(makeIPv4(172, 15, 255, 255)) == false, "private4_reject_172_outside");
   suite.expect(isRFC1918Private4(makeIPv4(8, 8, 8, 8)) == false, "private4_reject_public");

   if (suite.failed != 0)
   {
      basics_log("private4_unit failed=%d\n", suite.failed);
      return EXIT_FAILURE;
   }

   basics_log("private4_unit ok\n");
   return EXIT_SUCCESS;
}
