#include <prodigy/sdk/cpp/neuron_hub.h>
#include <services/debug.h>
#include <prodigy/sdk/cpp/opinionated/aegis_stream.h>
#include <prodigy/sdk/cpp/opinionated/pairings.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

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

static ProdigySDK::Bytes readFixture(const char *name)
{
   char path[1024];
   std::snprintf(path, sizeof(path), "%s/%s", PRODIGY_SDK_FIXTURE_DIR, name);

   FILE *input = std::fopen(path, "rb");
   if (input == nullptr)
   {
      std::perror(path);
      std::exit(1);
   }

   if (std::fseek(input, 0, SEEK_END) != 0)
   {
      std::fclose(input);
      std::perror("fseek");
      std::exit(1);
   }

   long fileSize = std::ftell(input);
   if (fileSize < 0)
   {
      std::fclose(input);
      std::perror("ftell");
      std::exit(1);
   }

   if (std::fseek(input, 0, SEEK_SET) != 0)
   {
      std::fclose(input);
      std::perror("fseek");
      std::exit(1);
   }

   ProdigySDK::Bytes bytes(static_cast<std::size_t>(fileSize));
   if (!bytes.empty() && std::fread(bytes.data(), 1, bytes.size(), input) != bytes.size())
   {
      std::fclose(input);
      std::perror("fread");
      std::exit(1);
   }

   std::fclose(input);
   return bytes;
}

static bool equalBytes(const ProdigySDK::Bytes& actual, const ProdigySDK::Bytes& expected)
{
   return actual.size() == expected.size() &&
      (actual.empty() || std::memcmp(actual.data(), expected.data(), actual.size()) == 0);
}

static bool equalString(const std::string& actual, const char *expected)
{
   return actual == expected;
}

static void writeAll(int fd, const ProdigySDK::Bytes& bytes)
{
   std::size_t offset = 0;
   while (offset < bytes.size())
   {
      ssize_t written = ::write(fd, bytes.data() + offset, bytes.size() - offset);
      if (written < 0)
      {
         if (errno == EINTR)
         {
            continue;
         }

         std::perror("write");
         std::exit(1);
      }

      offset += static_cast<std::size_t>(written);
   }
}

static ProdigySDK::Bytes readAll(int fd, std::size_t size)
{
   ProdigySDK::Bytes bytes(size);
   std::size_t offset = 0;
   while (offset < size)
   {
      ssize_t received = ::read(fd, bytes.data() + offset, size - offset);
      if (received < 0)
      {
         if (errno == EINTR)
         {
            continue;
         }

         std::perror("read");
         std::exit(1);
      }

      if (received == 0)
      {
         std::fprintf(stderr, "unexpected eof\n");
         std::exit(1);
      }

      offset += static_cast<std::size_t>(received);
   }

   return bytes;
}

class RecordingDispatch : public ProdigySDK::Dispatch
{
public:

   int endOfDynamicArgsCount = 0;
   int shutdownCount = 0;
   int advertisementPairingCount = 0;
   int subscriptionPairingCount = 0;
   int resourceDeltaCount = 0;
   int credentialsRefreshCount = 0;
   int messageCount = 0;

   ProdigySDK::AdvertisementPairing lastAdvertisementPairing;
   ProdigySDK::SubscriptionPairing lastSubscriptionPairing;
   ProdigySDK::ResourceDelta lastResourceDelta;
   ProdigySDK::CredentialDelta lastCredentialDelta;
   ProdigySDK::Bytes lastMessage;

   void beginShutdown(ProdigySDK::NeuronHub& hub) override
   {
      (void)hub;
      shutdownCount += 1;
   }

   void endOfDynamicArgs(ProdigySDK::NeuronHub& hub) override
   {
      (void)hub;
      endOfDynamicArgsCount += 1;
   }

   void advertisementPairing(ProdigySDK::NeuronHub& hub, const ProdigySDK::AdvertisementPairing& pairing) override
   {
      (void)hub;
      advertisementPairingCount += 1;
      lastAdvertisementPairing = pairing;
   }

   void subscriptionPairing(ProdigySDK::NeuronHub& hub, const ProdigySDK::SubscriptionPairing& pairing) override
   {
      (void)hub;
      subscriptionPairingCount += 1;
      lastSubscriptionPairing = pairing;
   }

   void resourceDelta(ProdigySDK::NeuronHub& hub, const ProdigySDK::ResourceDelta& delta) override
   {
      (void)hub;
      resourceDeltaCount += 1;
      lastResourceDelta = delta;
   }

   void credentialsRefresh(ProdigySDK::NeuronHub& hub, const ProdigySDK::CredentialDelta& delta) override
   {
      (void)hub;
      credentialsRefreshCount += 1;
      lastCredentialDelta = delta;
   }

   void messageFromProdigy(ProdigySDK::NeuronHub& hub, const ProdigySDK::Bytes& payload) override
   {
      (void)hub;
      messageCount += 1;
      lastMessage = payload;
   }
};

static ProdigySDK::MessageFrame parseFixtureFrame(const char *name)
{
   ProdigySDK::MessageFrame frame;
   ProdigySDK::Bytes bytes = readFixture(name);
   if (ProdigySDK::parseMessageFrame(bytes, frame) != ProdigySDK::Result::ok)
   {
      std::fprintf(stderr, "failed to parse fixture frame: %s\n", name);
      std::exit(1);
   }

   return frame;
}

int main(void)
{
   TestSuite suite;

   ProdigySDK::CredentialBundle bundle;
   suite.expect(
      ProdigySDK::decodeCredentialBundle(readFixture("startup.credential_bundle.full.bin"), bundle) == ProdigySDK::Result::ok,
      "decode fixture credential bundle");
   suite.expect(bundle.bundleGeneration == 101, "credential bundle generation");
   suite.expect(bundle.tlsIdentities.size() == 1 && equalString(bundle.tlsIdentities[0].name, "demo-cert"), "credential bundle tls identity");
   suite.expect(
      bundle.apiCredentials.size() == 1 &&
      bundle.apiCredentials[0].metadata.find("scope") != bundle.apiCredentials[0].metadata.end() &&
      bundle.apiCredentials[0].metadata.at("scope") == "demo",
      "credential bundle api credential");

   ProdigySDK::CredentialDelta delta;
   suite.expect(
      ProdigySDK::decodeCredentialDelta(readFixture("startup.credential_delta.full.bin"), delta) == ProdigySDK::Result::ok,
      "decode fixture credential delta");
   suite.expect(delta.bundleGeneration == 102, "credential delta generation");
   suite.expect(delta.removedTLSNames.size() == 1 && equalString(delta.removedTLSNames[0], "legacy-cert"), "credential delta removed tls");
   suite.expect(delta.removedAPINames.size() == 1 && equalString(delta.removedAPINames[0], "legacy-token"), "credential delta removed api");
   suite.expect(equalString(delta.reason, "fixture-rotation"), "credential delta reason");

   ProdigySDK::ContainerParameters parameters;
   suite.expect(
      ProdigySDK::decodeContainerParameters(readFixture("startup.container_parameters.full.bin"), parameters) == ProdigySDK::Result::ok,
      "decode fixture container parameters");
   suite.expect(parameters.memoryMB == 1536, "container parameters memory");
   suite.expect(parameters.storageMB == 4096, "container parameters storage");
   suite.expect(parameters.logicalCores == 5, "container parameters logical cores");
   suite.expect(parameters.datacenterUniqueTag == 23, "container parameters datacenter tag");
   suite.expect(parameters.flags.size() == 3 && parameters.flags[0] == 44 && parameters.flags[1] == 55 && parameters.flags[2] == 66, "container parameters flags");
   suite.expect(
      parameters.advertises.size() == 1 &&
      parameters.advertises[0].service == 0x445566778899aabbULL &&
      parameters.advertises[0].port == 24001,
      "container parameters advertised port");
   suite.expect(
      parameters.subscriptionPairings.size() == 1 &&
      parameters.subscriptionPairings[0].service == 0x2233000000001001ULL &&
      parameters.subscriptionPairings[0].port == 3210 &&
      parameters.subscriptionPairings[0].applicationID == 0x2233 &&
      parameters.subscriptionPairings[0].activate,
      "container parameters subscription pairing");
   suite.expect(
      parameters.advertisementPairings.size() == 1 &&
      parameters.advertisementPairings[0].service == 0x3344000000002002ULL &&
      parameters.advertisementPairings[0].applicationID == 0x3344 &&
      parameters.advertisementPairings[0].activate,
      "container parameters advertisement pairing");
   suite.expect(
      parameters.credentialBundle.has_value() &&
      parameters.credentialBundle->bundleGeneration == 101,
      "container parameters credential bundle");

   ProdigySDK::Opinionated::PairingBook pairingBook;
   const auto startupActions = pairingBook.seedFromParameters(parameters);
   suite.expect(
      startupActions.size() == 2 &&
      startupActions[0].kind == ProdigySDK::Opinionated::ActivationActionKind::registerAdvertiser &&
      startupActions[0].advertisement.has_value() &&
      startupActions[1].kind == ProdigySDK::Opinionated::ActivationActionKind::connectSubscriber &&
      startupActions[1].subscription.has_value() &&
      pairingBook.advertisements().size() == 1 &&
      pairingBook.subscriptions().size() == 1,
      "opinionated pairing book seeds startup pairings");

   ProdigySDK::Opinionated::AegisStream subscriberStream(parameters.subscriptionPairings[0]);
   const ProdigySDK::Bytes subscriberTfoData = subscriberStream.tfoData();
   suite.expect(
      subscriberStream.pairingHash() != 0 &&
      subscriberTfoData.size() == sizeof(std::uint64_t),
      "opinionated aegis stream builds from startup subscription");

   ProdigySDK::MessageFrame ackFrame;
   ProdigySDK::Bytes ackBytes = readFixture("frame.resource_delta_ack.accepted.bin");
   suite.expect(
      ProdigySDK::parseMessageFrame(ackBytes, ackFrame) == ProdigySDK::Result::ok,
      "parse resource delta ack frame");
   suite.expect(
      ackFrame.topic == ProdigySDK::ContainerTopic::resourceDeltaAck &&
      ackFrame.payload.size() == 1 &&
      ackFrame.payload[0] == 1,
      "resource delta ack frame payload");

   std::vector<ProdigySDK::MetricPair> metrics;
   ProdigySDK::Bytes statisticsPayload = readFixture("payload.statistics.demo.bin");
   suite.expect(
      ProdigySDK::decodeMetricPairs(statisticsPayload, metrics) == ProdigySDK::Result::ok,
      "decode metric pairs payload");
   suite.expect(
      metrics.size() == 2 &&
      metrics[0].key == 1 && metrics[0].value == 2 &&
      metrics[1].key == 3 && metrics[1].value == 4,
      "metric pair values");

   ProdigySDK::Bytes builtFrame;
   suite.expect(
      ProdigySDK::buildReadyFrame(builtFrame) == ProdigySDK::Result::ok &&
      equalBytes(builtFrame, readFixture("frame.healthy.empty.bin")),
      "build ready frame");
   suite.expect(
      ProdigySDK::buildStatisticsFrame(
         builtFrame,
         std::vector<ProdigySDK::MetricPair> {
            ProdigySDK::MetricPair{1, 2},
            ProdigySDK::MetricPair{3, 4},
         }) == ProdigySDK::Result::ok &&
      equalBytes(builtFrame, readFixture("frame.statistics.demo.bin")),
      "build statistics frame");
   suite.expect(
      ProdigySDK::buildResourceDeltaAckFrame(builtFrame, true) == ProdigySDK::Result::ok &&
      equalBytes(builtFrame, ackBytes),
      "build resource delta ack frame");
   suite.expect(
      ProdigySDK::buildCredentialsRefreshAckFrame(builtFrame) == ProdigySDK::Result::ok &&
      equalBytes(builtFrame, readFixture("frame.credentials_refresh_ack.empty.bin")),
      "build credentials refresh ack frame");

   ProdigySDK::Bytes pingFrameBytes = readFixture("frame.ping.empty.bin");
   ProdigySDK::FrameDecoder decoder;
   std::vector<ProdigySDK::MessageFrame> decodedFrames;
   suite.expect(
      decoder.feed(pingFrameBytes.data(), 5, decodedFrames) == ProdigySDK::Result::ok &&
      decodedFrames.empty(),
      "frame decoder partial feed");
   suite.expect(
      decoder.feed(pingFrameBytes.data() + 5, pingFrameBytes.size() - 5, decodedFrames) == ProdigySDK::Result::ok &&
      decodedFrames.size() == 1 &&
      decodedFrames[0].topic == ProdigySDK::ContainerTopic::ping,
      "frame decoder final feed");

   RecordingDispatch dispatch;
   ProdigySDK::NeuronHub hub(&dispatch, parameters);
   std::vector<ProdigySDK::MessageFrame> automaticResponses;

   suite.expect(
      hub.handleFrame(parseFixtureFrame("frame.advertisement_pairing.activate.bin"), automaticResponses) == ProdigySDK::Result::ok &&
      dispatch.advertisementPairingCount == 1 &&
      dispatch.lastAdvertisementPairing.service == 0x5566000000003003ULL &&
      dispatch.lastAdvertisementPairing.applicationID == 0x5566 &&
      dispatch.lastAdvertisementPairing.activate,
      "hub advertisement pairing dispatch");

   suite.expect(
      hub.handleFrame(parseFixtureFrame("frame.subscription_pairing.activate.bin"), automaticResponses) == ProdigySDK::Result::ok &&
      dispatch.subscriptionPairingCount == 1 &&
      dispatch.lastSubscriptionPairing.service == 0x6677000000004004ULL &&
      dispatch.lastSubscriptionPairing.port == 8123 &&
      dispatch.lastSubscriptionPairing.applicationID == 0x6677 &&
      dispatch.lastSubscriptionPairing.activate,
      "hub subscription pairing dispatch");

   suite.expect(
      hub.handleFrame(parseFixtureFrame("frame.resource_delta.scale_up.bin"), automaticResponses) == ProdigySDK::Result::ok &&
      dispatch.resourceDeltaCount == 1 &&
      dispatch.lastResourceDelta.logicalCores == 6 &&
      dispatch.lastResourceDelta.memoryMB == 2048 &&
      dispatch.lastResourceDelta.storageMB == 8192 &&
      dispatch.lastResourceDelta.isDownscale == false &&
      dispatch.lastResourceDelta.graceSeconds == 45,
      "hub resource delta dispatch");

   suite.expect(
      hub.handleFrame(parseFixtureFrame("frame.credentials_refresh.full.bin"), automaticResponses) == ProdigySDK::Result::ok &&
      dispatch.credentialsRefreshCount == 1 &&
      dispatch.lastCredentialDelta.bundleGeneration == 102 &&
      equalString(dispatch.lastCredentialDelta.reason, "fixture-rotation"),
      "hub credentials refresh dispatch");

   suite.expect(
      hub.handleFrame(parseFixtureFrame("frame.message.demo.bin"), automaticResponses) == ProdigySDK::Result::ok &&
      dispatch.messageCount == 1 &&
      std::string(dispatch.lastMessage.begin(), dispatch.lastMessage.end()) == "hello-prodigy",
      "hub message dispatch");

   suite.expect(
      hub.handleFrame(parseFixtureFrame("frame.stop.empty.bin"), automaticResponses) == ProdigySDK::Result::ok &&
      dispatch.shutdownCount == 1,
      "hub stop dispatch");

   ProdigySDK::Bytes noneFrameBytes;
   suite.expect(
      ProdigySDK::buildMessageFrame(noneFrameBytes, ProdigySDK::ContainerTopic::none, nullptr, 0) == ProdigySDK::Result::ok,
      "build none frame");
   ProdigySDK::MessageFrame noneFrame;
   suite.expect(
      ProdigySDK::parseMessageFrame(noneFrameBytes, noneFrame) == ProdigySDK::Result::ok &&
      hub.handleFrame(noneFrame, automaticResponses) == ProdigySDK::Result::ok &&
      dispatch.endOfDynamicArgsCount == 1,
      "hub end of dynamic args");

   suite.expect(
      hub.handleFrame(parseFixtureFrame("frame.datacenter_unique_tag.23.bin"), automaticResponses) == ProdigySDK::Result::ok &&
      hub.parameters.datacenterUniqueTag == 23,
      "hub datacenter tag update");

   automaticResponses.clear();
   suite.expect(
      hub.handleFrame(decodedFrames[0], automaticResponses) == ProdigySDK::Result::ok &&
      automaticResponses.size() == 1 &&
      automaticResponses[0].topic == ProdigySDK::ContainerTopic::ping &&
      automaticResponses[0].payload.empty(),
      "hub ping automatic response");

   ProdigySDK::Bytes outboundReadyFrame;
   suite.expect(
      hub.signalReady(outboundReadyFrame) == ProdigySDK::Result::ok &&
      equalBytes(outboundReadyFrame, readFixture("frame.healthy.empty.bin")),
      "hub ready frame builder");

   ProdigySDK::Bytes outboundStatisticsFrame;
   suite.expect(
      hub.publishStatistics(
         outboundStatisticsFrame,
         std::vector<ProdigySDK::MetricPair> {
            ProdigySDK::MetricPair{1, 2},
            ProdigySDK::MetricPair{3, 4},
         }) == ProdigySDK::Result::ok &&
      equalBytes(outboundStatisticsFrame, readFixture("frame.statistics.demo.bin")),
      "hub statistics frame builder");

   ProdigySDK::Bytes outboundAckFrame;
   suite.expect(
      hub.acknowledgeResourceDelta(outboundAckFrame, true) == ProdigySDK::Result::ok &&
      equalBytes(outboundAckFrame, ackBytes),
      "hub resource delta ack builder");

   ProdigySDK::Bytes outboundCredentialAckFrame;
   suite.expect(
      hub.acknowledgeCredentialsRefresh(outboundCredentialAckFrame) == ProdigySDK::Result::ok &&
      equalBytes(outboundCredentialAckFrame, readFixture("frame.credentials_refresh_ack.empty.bin")),
      "hub credentials refresh ack builder");

   int sockets[2] = {-1, -1};
   if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0)
   {
      std::perror("socketpair");
      return 1;
   }

   writeAll(sockets[0], outboundReadyFrame);
   suite.expect(
      equalBytes(readAll(sockets[1], outboundReadyFrame.size()), readFixture("frame.healthy.empty.bin")),
      "external transport writes ready frame");

   ProdigySDK::Bytes pingResponseBytes;
   suite.expect(
      ProdigySDK::buildMessageFrame(pingResponseBytes, automaticResponses[0].topic, automaticResponses[0].payload) == ProdigySDK::Result::ok &&
      equalBytes(pingResponseBytes, pingFrameBytes),
      "external transport encodes ping response");
   writeAll(sockets[0], pingResponseBytes);
   suite.expect(
      equalBytes(readAll(sockets[1], pingResponseBytes.size()), pingFrameBytes),
      "external transport writes ping response");

   suite.expect(::close(sockets[0]) == 0, "close external transport socket 0");
   suite.expect(::close(sockets[1]) == 0, "close external transport socket 1");

   return suite.failed == 0 ? 0 : 1;
}
