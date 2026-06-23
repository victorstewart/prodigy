#include <prodigy/sdk/cpp/neuron_hub.h>
#include <services/debug.h>
#include <prodigy/sdk/cpp/opinionated/aegis_stream.h>
#include <prodigy/sdk/cpp/opinionated/pairings.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

class TestSuite {
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
      std::fprintf(stderr, "FAIL: %s\n", name);
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

class RecordingDispatch : public ProdigySDK::Dispatch {
public:

  int endOfDynamicArgsCount = 0;
  int shutdownCount = 0;
  int advertisementPairingCount = 0;
  int subscriptionPairingCount = 0;
  int resourceDeltaCount = 0;
  int credentialsRefreshCount = 0;
  int messageCount = 0;
  int wormholesRefreshCount = 0;

  ProdigySDK::AdvertisementPairing lastAdvertisementPairing;
  ProdigySDK::SubscriptionPairing lastSubscriptionPairing;
  ProdigySDK::ResourceDelta lastResourceDelta;
  ProdigySDK::CredentialDelta lastCredentialDelta;
  ProdigySDK::Bytes lastMessage;
  ProdigySDK::Bytes lastWormholesRefresh;

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

  void wormholesRefreshRaw(ProdigySDK::NeuronHub& hub, const ProdigySDK::Bytes& payload) override
  {
    (void)hub;
    wormholesRefreshCount += 1;
    lastWormholesRefresh = payload;
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
  suite.expect(
      bundle.tlsResumptionSnapshots.size() == 1 &&
          bundle.tlsResumptionSnapshots[0].generation == 103 &&
          bundle.tlsResumptionSnapshots[0].wormholeName == "public-api-quic" &&
          bundle.tlsResumptionSnapshots[0].keyRing.size() == 1,
      "credential bundle resumption snapshot");

  ProdigySDK::CredentialDelta delta;
  suite.expect(
      ProdigySDK::decodeCredentialDelta(readFixture("startup.credential_delta.full.bin"), delta) == ProdigySDK::Result::ok,
      "decode fixture credential delta");
  suite.expect(delta.bundleGeneration == 102, "credential delta generation");
  suite.expect(delta.removedTLSNames.size() == 1 && equalString(delta.removedTLSNames[0], "legacy-cert"), "credential delta removed tls");
  suite.expect(delta.removedAPINames.size() == 1 && equalString(delta.removedAPINames[0], "legacy-token"), "credential delta removed api");
  suite.expect(equalString(delta.reason, "fixture-rotation"), "credential delta reason");
  suite.expect(
      delta.updatedResumptionSnapshots.size() == 1 &&
          delta.updatedResumptionSnapshots[0].generation == 104 &&
          delta.updatedResumptionSnapshots[0].wormholeName == "public-api-quic" &&
          delta.removedResumptionWormholeNames.size() == 1 &&
          delta.removedResumptionWormholeNames[0] == "legacy-public-api-quic",
      "credential delta resumption update and removal");

  ProdigySDK::ContainerParameters parameters;
  suite.expect(
      ProdigySDK::decodeContainerParameters(readFixture("startup.container_parameters.full.bin"), parameters) == ProdigySDK::Result::ok,
      "decode fixture container parameters");
  suite.expect(parameters.memoryMB == 1536, "container parameters memory");
  suite.expect(parameters.storageMB == 4096, "container parameters storage");
  suite.expect(parameters.logicalCores == 5, "container parameters logical cores");
  suite.expect(parameters.deploymentID == 0 && parameters.taskAttemptNumber == 0, "container parameters legacy task identity defaults");
  suite.expect(parameters.datacenterUniqueTag == 23, "container parameters datacenter tag");
  suite.expect(parameters.flags.size() == 3 && parameters.flags[0] == 44 && parameters.flags[1] == 55 && parameters.flags[2] == 66, "container parameters flags");
  suite.expect(
      parameters.advertises.size() == 1 &&
          parameters.advertises[0].service == 0x445566778899aabbULL &&
          parameters.advertises[0].port == 24'001,
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
          parameters.credentialBundle->bundleGeneration == 101 &&
          parameters.credentialBundle->tlsResumptionSnapshots.size() == 1,
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
      ProdigySDK::buildRuntimeReadyFrame(builtFrame) == ProdigySDK::Result::ok &&
          parseFixtureFrame("frame.healthy.empty.bin").payload.empty(),
      "build runtime ready frame");
  ProdigySDK::MessageFrame runtimeReadyFrame;
  suite.expect(
      ProdigySDK::parseMessageFrame(builtFrame, runtimeReadyFrame) == ProdigySDK::Result::ok &&
          runtimeReadyFrame.topic == ProdigySDK::ContainerTopic::runtimeReady &&
          runtimeReadyFrame.payload.empty(),
      "runtime ready frame topic");
  suite.expect(
      ProdigySDK::buildStatisticsFrame(
          builtFrame,
          std::vector<ProdigySDK::MetricPair> {
              ProdigySDK::MetricPair {1, 2},
              ProdigySDK::MetricPair {3, 4},
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

  ProdigySDK::TlsResumptionApplyAck resumptionAck;
  resumptionAck.results.push_back(ProdigySDK::TlsResumptionApplyResult {
      "public-api-quic",
      12'345,
      true,
      "",
  });
  resumptionAck.results.push_back(ProdigySDK::TlsResumptionApplyResult {
      "admin-api-quic",
      12'346,
      false,
      "stale generation",
  });

  ProdigySDK::Bytes typedCredentialAckFrame;
  ProdigySDK::MessageFrame typedAckFrame;
  ProdigySDK::TlsResumptionApplyAck decodedResumptionAck;
  suite.expect(
      ProdigySDK::buildCredentialsRefreshAckFrame(typedCredentialAckFrame, resumptionAck) == ProdigySDK::Result::ok &&
          ProdigySDK::parseMessageFrame(typedCredentialAckFrame, typedAckFrame) == ProdigySDK::Result::ok &&
          typedAckFrame.topic == ProdigySDK::ContainerTopic::credentialsRefresh &&
          typedAckFrame.payload.empty() == false &&
          ProdigySDK::decodeTlsResumptionApplyAckPayload(typedAckFrame.payload, decodedResumptionAck) == ProdigySDK::Result::ok,
      "build typed credentials refresh ack frame");
  suite.expect(
      decodedResumptionAck.results.size() == 2 &&
          decodedResumptionAck.results[0].wormholeName == "public-api-quic" &&
          decodedResumptionAck.results[0].generation == 12'345 &&
          decodedResumptionAck.results[0].success &&
          decodedResumptionAck.results[1].failureReason == "stale generation",
      "typed credentials refresh ack payload preserves resumption apply results");

  ProdigySDK::CredentialApplyAck credentialAck;
  credentialAck.tlsResults.push_back(ProdigySDK::TlsIdentityApplyResult {
      "api-public",
      77,
      true,
      "",
  });
  credentialAck.tlsResults.push_back(ProdigySDK::TlsIdentityApplyResult {
      "admin-public",
      78,
      false,
      "application rejected TLS identity",
  });
  credentialAck.resumptionResults = resumptionAck.results;

  ProdigySDK::Bytes credentialApplyAckFrame;
  ProdigySDK::MessageFrame credentialApplyAckMessage;
  ProdigySDK::CredentialApplyAck decodedCredentialAck;
  suite.expect(
      ProdigySDK::buildCredentialsRefreshAckFrame(credentialApplyAckFrame, credentialAck) == ProdigySDK::Result::ok &&
          ProdigySDK::parseMessageFrame(credentialApplyAckFrame, credentialApplyAckMessage) == ProdigySDK::Result::ok &&
          credentialApplyAckMessage.topic == ProdigySDK::ContainerTopic::credentialsRefresh &&
          ProdigySDK::decodeCredentialApplyAckPayload(credentialApplyAckMessage.payload, decodedCredentialAck) == ProdigySDK::Result::ok,
      "build credential apply ack frame");
  suite.expect(
      decodedCredentialAck.tlsResults.size() == 2 &&
          decodedCredentialAck.tlsResults[0].identityName == "api-public" &&
          decodedCredentialAck.tlsResults[0].generation == 77 &&
          decodedCredentialAck.tlsResults[0].success &&
          decodedCredentialAck.tlsResults[1].failureReason == "application rejected TLS identity" &&
          decodedCredentialAck.resumptionResults.size() == 2 &&
          decodedCredentialAck.resumptionResults[1].wormholeName == "admin-api-quic",
      "credential apply ack payload preserves TLS and resumption results");

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
          equalString(dispatch.lastCredentialDelta.reason, "fixture-rotation") &&
          dispatch.lastCredentialDelta.updatedResumptionSnapshots.size() == 1,
      "hub credentials refresh dispatch");

  RecordingDispatch resumptionDispatch;
  ProdigySDK::NeuronHub resumptionHub(&resumptionDispatch, parameters);
  resumptionHub.withAutoAcks();
  std::vector<ProdigySDK::MessageFrame> resumptionResponses;
  suite.expect(
      resumptionHub.handleFrame(parseFixtureFrame("frame.credentials_refresh.full.bin"), resumptionResponses) == ProdigySDK::Result::ok &&
          resumptionDispatch.credentialsRefreshCount == 1 &&
          resumptionDispatch.lastCredentialDelta.updatedResumptionSnapshots.size() == 1,
      "hub credentials refresh dispatches resumption delta");
  std::vector<ProdigySDK::Bytes> resumptionQueuedResponses;
  suite.expect(
      resumptionHub.drainQueuedResponseBytes(resumptionQueuedResponses) == ProdigySDK::Result::ok &&
          resumptionQueuedResponses.empty(),
      "hub auto credentials ack skips resumption delta until application ack");
  resumptionHub.applyCredentialDeltaLocally(resumptionDispatch.lastCredentialDelta);
  suite.expect(
      resumptionHub.parameters.credentialBundle.has_value() &&
          resumptionHub.parameters.credentialBundle->bundleGeneration == 102 &&
          resumptionHub.parameters.credentialBundle->tlsResumptionSnapshots[0].generation == 103,
      "hub local credential update leaves resumption storage to app");

  suite.expect(
      hub.handleFrame(parseFixtureFrame("frame.message.demo.bin"), automaticResponses) == ProdigySDK::Result::ok &&
          dispatch.messageCount == 1 &&
          std::string(dispatch.lastMessage.begin(), dispatch.lastMessage.end()) == "hello-prodigy",
      "hub message dispatch");

  ProdigySDK::Bytes wormholesPayload {'w', 'o', 'r', 'm'};
  ProdigySDK::MessageFrame wormholesFrame {ProdigySDK::ContainerTopic::wormholesRefresh, wormholesPayload};
  suite.expect(
      hub.handleFrame(wormholesFrame, automaticResponses) == ProdigySDK::Result::ok &&
          dispatch.wormholesRefreshCount == 1 &&
          equalBytes(dispatch.lastWormholesRefresh, wormholesPayload),
      "hub wormholes refresh dispatch");

  automaticResponses.clear();
  suite.expect(
      hub.handleFrame(runtimeReadyFrame, automaticResponses) == ProdigySDK::Result::ok &&
          automaticResponses.empty(),
      "hub runtime ready inbound no-op");

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

  ProdigySDK::Bytes outboundRuntimeReadyFrame;
  suite.expect(
      hub.signalRuntimeReady(outboundRuntimeReadyFrame) == ProdigySDK::Result::ok &&
          ProdigySDK::parseMessageFrame(outboundRuntimeReadyFrame, runtimeReadyFrame) == ProdigySDK::Result::ok &&
          runtimeReadyFrame.topic == ProdigySDK::ContainerTopic::runtimeReady &&
          runtimeReadyFrame.payload.empty(),
      "hub runtime ready frame builder");

  ProdigySDK::Bytes taskResult {'o', 'k'};
  ProdigySDK::Bytes outboundTaskResultFrame;
  ProdigySDK::MessageFrame decodedTaskResultFrame;
  suite.expect(
      ProdigySDK::buildTaskResultFrame(outboundTaskResultFrame, taskResult) == ProdigySDK::Result::ok &&
          ProdigySDK::parseMessageFrame(outboundTaskResultFrame, decodedTaskResultFrame) == ProdigySDK::Result::ok &&
          decodedTaskResultFrame.topic == ProdigySDK::ContainerTopic::taskResult &&
          equalBytes(decodedTaskResultFrame.payload, taskResult),
      "hub task result frame builder");
  ProdigySDK::NeuronHub taskHub(&dispatch, parameters);
  std::vector<ProdigySDK::Bytes> queuedTaskResults;
  suite.expect(
      taskHub.queueTaskResult(taskResult) == ProdigySDK::Result::ok &&
          taskHub.drainQueuedResponseBytes(queuedTaskResults) == ProdigySDK::Result::ok &&
          queuedTaskResults.size() == 1 &&
          equalBytes(queuedTaskResults[0], outboundTaskResultFrame),
      "hub task result queued response");
  ProdigySDK::Bytes oversizedTaskResult(64u * 1024u + 1u);
  suite.expect(
      ProdigySDK::buildTaskResultFrame(outboundTaskResultFrame, oversizedTaskResult) == ProdigySDK::Result::argument &&
          taskHub.queueTaskResult(oversizedTaskResult) == ProdigySDK::Result::argument,
      "hub task result rejects oversize payload");

  ProdigySDK::Bytes outboundStatisticsFrame;
  suite.expect(
      hub.publishStatistics(
          outboundStatisticsFrame,
          std::vector<ProdigySDK::MetricPair> {
              ProdigySDK::MetricPair {1, 2},
              ProdigySDK::MetricPair {3, 4},
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

  ProdigySDK::Bytes outboundTypedCredentialAckFrame;
  ProdigySDK::MessageFrame outboundTypedAckFrame;
  ProdigySDK::TlsResumptionApplyAck outboundDecodedResumptionAck;
  suite.expect(
      hub.acknowledgeCredentialsRefresh(outboundTypedCredentialAckFrame, resumptionAck) == ProdigySDK::Result::ok &&
          ProdigySDK::parseMessageFrame(outboundTypedCredentialAckFrame, outboundTypedAckFrame) == ProdigySDK::Result::ok &&
          ProdigySDK::decodeTlsResumptionApplyAckPayload(outboundTypedAckFrame.payload, outboundDecodedResumptionAck) == ProdigySDK::Result::ok &&
          outboundDecodedResumptionAck.results.size() == 2,
      "hub typed credentials refresh ack builder");

  ProdigySDK::Bytes outboundCredentialApplyAckFrame;
  ProdigySDK::MessageFrame outboundCredentialApplyAckMessage;
  ProdigySDK::CredentialApplyAck outboundDecodedCredentialAck;
  suite.expect(
      hub.acknowledgeCredentialsRefresh(outboundCredentialApplyAckFrame, credentialAck) == ProdigySDK::Result::ok &&
          ProdigySDK::parseMessageFrame(outboundCredentialApplyAckFrame, outboundCredentialApplyAckMessage) == ProdigySDK::Result::ok &&
          ProdigySDK::decodeCredentialApplyAckPayload(outboundCredentialApplyAckMessage.payload, outboundDecodedCredentialAck) == ProdigySDK::Result::ok &&
          outboundDecodedCredentialAck.tlsResults.size() == 2,
      "hub credential apply ack builder");

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
