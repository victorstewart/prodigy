#include <prodigy/prodigy.h>
#include <services/debug.h>

#include <cstdio>
#include <unistd.h>

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
         std::fprintf(stderr, "FAIL: %s\n", name);
         std::fflush(stderr);
         failed += 1;
      }
   }
};

class ScopedRing final
{
public:
   bool created = false;

   ScopedRing()
   {
      if (Ring::getRingFD() <= 0)
      {
         Ring::createRing(8, 8, 32, 32, -1, -1, 0);
         created = true;
      }
   }

   ~ScopedRing()
   {
      if (created)
      {
         Ring::shutdownForExec();
      }
   }
};

class FakeRecvmsgSocket final : public UDPSocket, public RecvmsgMultishoter
{
};

int main(void)
{
   TestSuite suite;

   {
      ScopedRing scopedRing = {};

      FakeRecvmsgSocket socket = {};
      socket.setIPVersion(AF_INET6);
      Ring::installFDIntoFixedFileSlot(&socket);
      socket.bgid = 7;

      Ring::queueRecvmsgMultishot(&socket);
      const uint64_t firstSerial = socket.recvmsgMultishotSerial;

      suite.expect(firstSerial == 1, "ring_recvmsg_multishot_rearm_tracking_first_arm_bumps_socket_serial");
      suite.expect(Ring::recvmsgMultishotTrackingMatchesCurrent(&socket, firstSerial), "ring_recvmsg_multishot_rearm_tracking_first_arm_matches_current_serial");

      Ring::queueRecvmsgMultishot(&socket);
      const uint64_t secondSerial = socket.recvmsgMultishotSerial;

      suite.expect(secondSerial == 2, "ring_recvmsg_multishot_rearm_tracking_second_arm_bumps_socket_serial");
      suite.expect(Ring::recvmsgMultishotTrackingMatchesCurrent(&socket, firstSerial) == false, "ring_recvmsg_multishot_rearm_tracking_stale_first_arm_no_longer_matches_current_serial");
      suite.expect(Ring::recvmsgMultishotTrackingMatchesCurrent(&socket, secondSerial), "ring_recvmsg_multishot_rearm_tracking_second_arm_matches_current_serial");

      if (socket.isFixedFile)
      {
         Ring::uninstallFromFixedFileSlot(&socket);
      }
      else if (socket.fd >= 0)
      {
         ::close(socket.fd);
      }
   }

   int result = suite.failed == 0 ? 0 : 1;
   std::fflush(stdout);
   std::fflush(stderr);
   _exit(result);
}
