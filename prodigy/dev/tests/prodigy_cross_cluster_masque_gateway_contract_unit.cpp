#include <networking/includes.h>
#include <macros/bytes.h>
#include <services/time.h>
#include <services/prodigy.h>
#include <networking/socket.h>
#include <networking/ring.h>
#include <networking/stream.h>
#include <networking/multiplexer.h>
#include <prodigy/cross.cluster.mesh.route.h>
#include <prodigy/container.contract.h>
#include <prodigy/neuron/masque.gateway.launch.h>

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <unistd.h>

class TestSuite {
public:
  int failures = 0;

  void expect(bool value, const char *name)
  {
    if (value) return;
    std::fprintf(stderr, "FAIL: %s\n", name);
    ++failures;
  }
};

// Runtime53 emitted this positional plan layout.  Keep it test-local so the
// production codec has one current definition while this fixture guards the
// retained stateUpload boundary against inserted launch-local fields.
struct Runtime53SystemContainerRuntimePlan {
  SystemContainerRuntimePlan plan;
};

template <typename S>
static void serialize(S&& serializer, Runtime53SystemContainerRuntimePlan& legacy)
{
  auto& plan = legacy.plan;
  serializer.value1b(plan.kind);
  serializer.object(plan.artifact);
  serializer.object(plan.egress);
  serializer.text1b(plan.gatewayReadinessSocket, 255);
  serializer.text1b(plan.gatewayLaunchToken, 128);
  serializer.text1b(plan.gatewayRole, 16);
  serializer.text1b(plan.gatewayRoutes, 512);
  serializer.text1b(plan.gatewayEndpoint, 128);
  serializer.text1b(plan.gatewayLocalIdentity, 64);
  serializer.text1b(plan.gatewayPeerIdentity, 64);
  serializer.text1b(plan.gatewayPeerTrust, 64);
  serializer.text1b(plan.gatewayTunnelInterface, 15);
  serializer.value16b(plan.gatewayPairUUID);
  serializer.value16b(plan.gatewayLocalClusterUUID);
  serializer.value16b(plan.gatewayLocalMachineUUID);
  serializer.value8b(plan.gatewayKeyEpoch);
  serializer.value8b(plan.gatewayAuthorityGeneration);
  serializer.value8b(plan.gatewayGeneration);
}

int main()
{
  TestSuite suite;
  ProdigyCrossClusterMasqueGatewayLocalReceipt receipt = {};
  receipt.launchToken.assign("0123456789abcdef0123456789abcdef"_ctv);
  receipt.routeSetSHA256.assign("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_ctv);
  receipt.ready = true;
  receipt.readiness.authenticatedMasqueQUICReady = true;
  String readinessFrame = {};
  suite.expect(prodigyEncodeCrossClusterMasqueGatewayLocalReceiptFrame(receipt, readinessFrame),
               "gateway_readiness_frame_encodes_bounded_versioned_receipt");
  ProdigyCrossClusterMasqueGatewayLocalReceipt decodedReceipt = {};
  suite.expect(prodigyDecodeCrossClusterMasqueGatewayLocalReceiptFrame(
                   reinterpret_cast<const uint8_t *>(readinessFrame.data()), uint32_t(readinessFrame.size()), decodedReceipt) &&
                   decodedReceipt.launchToken.equal(receipt.launchToken),
               "gateway_readiness_frame_decodes_exact_receipt");
  uint8_t malformedReadinessFrame[5] = {1, 0, 0, 0, 0};
  suite.expect(!prodigyDecodeCrossClusterMasqueGatewayLocalReceiptFrame(
                   malformedReadinessFrame, sizeof(malformedReadinessFrame), decodedReceipt),
               "gateway_readiness_frame_rejects_truncated_payload");

  auto tuple = [] {
    ProdigyGatewayLocalTuple value = {};
    value.pairUUID = 1; value.localClusterUUID = 2; value.localMachineUUID = 3;
    value.keyEpoch = 4; value.authorityGeneration = 5; value.gatewayGeneration = 6;
    return value;
  };
  constexpr auto digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"_ctv;
  constexpr auto token = "abcdef0123456789abcdef0123456789"_ctv;
  auto appendByte = [](String& bytes, uint8_t value) {
    bytes.append(reinterpret_cast<const char *>(&value), 1);
  };
  auto appendLE = [&appendByte](String& bytes, auto value) {
    for (uint32_t index = 0; index < sizeof(value); ++index)
      appendByte(bytes, uint8_t(value >> (index * 8)));
  };
  auto appendTuple = [&appendLE](String& bytes) {
    appendLE(bytes, uint128_t(1)); appendLE(bytes, uint128_t(2)); appendLE(bytes, uint128_t(3));
    appendLE(bytes, uint64_t(4)); appendLE(bytes, uint64_t(5)); appendLE(bytes, uint64_t(6));
  };
  auto beginFixture = [&appendLE, &appendByte](String& bytes, uint32_t payloadBytes, uint8_t direction, uint8_t kind) {
    appendLE(bytes, payloadBytes); appendLE(bytes, uint32_t(2)); appendByte(bytes, direction); appendByte(bytes, kind);
  };
  ProdigyGatewayLocalControlFrame v2Readiness = {};
  v2Readiness.direction = ProdigyGatewayLocalDirection::gatewayToNeuron;
  v2Readiness.kind = ProdigyGatewayLocalKind::readiness;
  v2Readiness.readiness.launchToken.assign(token);
  v2Readiness.readiness.tuple = tuple();
  v2Readiness.readiness.authenticatedMasqueQUICReady = true;
  v2Readiness.readiness.routeSetSHA256.assign(digest);
  v2Readiness.readiness.ready = true;
  String v2ReadinessFrame = {};
  ProdigyGatewayLocalControlFrame decodedControl = {};
  suite.expect(prodigyEncodeGatewayLocalControlFrame(v2Readiness, v2ReadinessFrame) &&
                   prodigyDecodeGatewayLocalControlFrame(reinterpret_cast<const uint8_t *>(v2ReadinessFrame.data()), uint32_t(v2ReadinessFrame.size()), decodedControl) &&
                   decodedControl.kind == ProdigyGatewayLocalKind::readiness && decodedControl.readiness.launchToken.equal(token) &&
                   decodedControl.readiness.tuple.gatewayGeneration == 6 && decodedControl.readiness.authenticatedMasqueQUICReady && decodedControl.readiness.ready,
               "gateway_local_control_v2_readiness_round_trips");
  String readinessFixture = {};
  beginFixture(readinessFixture, 178, 1, 1); appendByte(readinessFixture, 32); readinessFixture.append(token); appendTuple(readinessFixture);
  appendByte(readinessFixture, 1); appendByte(readinessFixture, 64); readinessFixture.append(digest); appendByte(readinessFixture, 1);
  suite.expect(v2ReadinessFrame.equal(readinessFixture), "gateway_local_control_v2_readiness_fixed_bytes");

  ProdigyGatewayLocalControlFrame hello = {};
  hello.direction = ProdigyGatewayLocalDirection::gatewayToNeuron;
  hello.kind = ProdigyGatewayLocalKind::rebindHello;
  hello.rebindHello.recoveryToken.assign(token);
  hello.rebindHello.tuple = tuple();
  String helloFrame = {};
  suite.expect(prodigyEncodeGatewayLocalControlFrame(hello, helloFrame) &&
                   prodigyDecodeGatewayLocalControlFrame(reinterpret_cast<const uint8_t *>(helloFrame.data()), uint32_t(helloFrame.size()), decodedControl) &&
                   decodedControl.kind == ProdigyGatewayLocalKind::rebindHello && decodedControl.rebindHello.recoveryToken.equal(token) && decodedControl.rebindHello.tuple.pairUUID == 1,
               "gateway_local_control_v2_rebind_hello_round_trips");
  String helloFixture = {};
  beginFixture(helloFixture, 111, 1, 2); appendByte(helloFixture, 32); helloFixture.append(token); appendTuple(helloFixture);
  suite.expect(helloFrame.equal(helloFixture), "gateway_local_control_v2_rebind_hello_fixed_bytes");

  ProdigyGatewayLocalControlFrame challenge = {};
  challenge.direction = ProdigyGatewayLocalDirection::neuronToGateway;
  challenge.kind = ProdigyGatewayLocalKind::rebindChallenge;
  challenge.rebindChallenge.tuple = tuple();
  for (uint8_t index = 0; index < 16; ++index) challenge.rebindChallenge.nonce[index] = 7;
  String challengeFrame = {};
  const uint8_t challengeFixture[] = {
      94,0,0,0, 2,0,0,0, 2,3,
      1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      4,0,0,0,0,0,0,0, 5,0,0,0,0,0,0,0, 6,0,0,0,0,0,0,0,
      7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7};
  suite.expect(prodigyEncodeGatewayLocalControlFrame(challenge, challengeFrame) &&
                   challengeFrame.size() == sizeof(challengeFixture) &&
                   memcmp(challengeFrame.data(), challengeFixture, sizeof(challengeFixture)) == 0 &&
                   prodigyDecodeGatewayLocalControlFrame(challengeFixture, sizeof(challengeFixture), decodedControl) &&
                   decodedControl.rebindChallenge.tuple.authorityGeneration == 5 && decodedControl.rebindChallenge.nonce[15] == 7,
               "gateway_local_control_v2_challenge_cross_language_byte_fixture");

  ProdigyGatewayLocalControlFrame rebindReceipt = {};
  rebindReceipt.direction = ProdigyGatewayLocalDirection::gatewayToNeuron;
  rebindReceipt.kind = ProdigyGatewayLocalKind::rebindReceipt;
  rebindReceipt.rebindReceipt.tuple = tuple();
  memcpy(rebindReceipt.rebindReceipt.nonce, challenge.rebindChallenge.nonce, 16);
  rebindReceipt.rebindReceipt.authenticatedMasqueQUICReady = true;
  rebindReceipt.rebindReceipt.routeSetSHA256.assign(digest);
  rebindReceipt.rebindReceipt.ready = true;
  String receiptV2Frame = {};
  suite.expect(prodigyEncodeGatewayLocalControlFrame(rebindReceipt, receiptV2Frame) &&
                   prodigyDecodeGatewayLocalControlFrame(reinterpret_cast<const uint8_t *>(receiptV2Frame.data()), uint32_t(receiptV2Frame.size()), decodedControl) &&
                   decodedControl.kind == ProdigyGatewayLocalKind::rebindReceipt && decodedControl.rebindReceipt.tuple.localMachineUUID == 3 && decodedControl.rebindReceipt.nonce[0] == 7 && decodedControl.rebindReceipt.ready,
               "gateway_local_control_v2_rebind_receipt_round_trips");
  String receiptFixture = {};
  beginFixture(receiptFixture, 161, 1, 4); appendTuple(receiptFixture);
  for (uint8_t index = 0; index < 16; ++index) appendByte(receiptFixture, 7);
  appendByte(receiptFixture, 1); appendByte(receiptFixture, 64); receiptFixture.append(digest); appendByte(receiptFixture, 1);
  suite.expect(receiptV2Frame.equal(receiptFixture), "gateway_local_control_v2_rebind_receipt_fixed_bytes");

  ProdigyGatewayLocalControlFrame pathFault = {};
  pathFault.direction = ProdigyGatewayLocalDirection::neuronToGateway;
  pathFault.kind = ProdigyGatewayLocalKind::pathFault;
  pathFault.pathFault.protocolVersion = ProdigyCrossClusterPathFaultGatewayControlPayload::leaseVersion;
  pathFault.pathFault.action = ProdigyCrossClusterPathFaultGatewayAction::query;
  pathFault.pathFault.operationUUID = 7; pathFault.pathFault.pairUUID = 1;
  pathFault.pathFault.clusterUUID = 2; pathFault.pathFault.machineUUID = 3;
  pathFault.pathFault.keyEpoch = 4; pathFault.pathFault.authorityGeneration = 5;
  pathFault.pathFault.gatewayGeneration = 6; pathFault.pathFault.expiresAtMilliseconds = 7;
  String pathFaultFrame = {};
  suite.expect(prodigyEncodeGatewayLocalControlFrame(pathFault, pathFaultFrame) &&
                   prodigyDecodeGatewayLocalControlFrame(reinterpret_cast<const uint8_t *>(pathFaultFrame.data()), uint32_t(pathFaultFrame.size()), decodedControl) &&
                   decodedControl.pathFault.protocolVersion == pathFault.pathFault.protocolVersion && decodedControl.pathFault.operationUUID == 7 &&
                   decodedControl.pathFault.action == ProdigyCrossClusterPathFaultGatewayAction::query && !decodedControl.pathFault.fromGateway &&
                   !decodedControl.pathFault.accepted && !decodedControl.pathFault.authenticatedReady,
               "gateway_local_control_v2_embeds_existing_path_fault_payload");
  String pathFaultFixture = {};
  beginFixture(pathFaultFixture, 110, 2, 5); appendLE(pathFaultFixture, uint32_t(2)); appendByte(pathFaultFixture, 0); appendByte(pathFaultFixture, 2);
  appendLE(pathFaultFixture, uint128_t(7)); appendTuple(pathFaultFixture); appendLE(pathFaultFixture, uint64_t(7)); appendByte(pathFaultFixture, 0); appendByte(pathFaultFixture, 0);
  suite.expect(pathFaultFrame.equal(pathFaultFixture), "gateway_local_control_v2_lease_path_fault_fixed_bytes");

  auto malformedControl = v2ReadinessFrame;
  malformedControl[4] = 3;
  suite.expect(!prodigyDecodeGatewayLocalControlFrame(reinterpret_cast<const uint8_t *>(malformedControl.data()), uint32_t(malformedControl.size()), decodedControl),
               "gateway_local_control_rejects_unknown_version");
  malformedControl = v2ReadinessFrame;
  malformedControl[8] = 9;
  suite.expect(!prodigyDecodeGatewayLocalControlFrame(reinterpret_cast<const uint8_t *>(malformedControl.data()), uint32_t(malformedControl.size()), decodedControl),
               "gateway_local_control_rejects_unknown_direction");
  malformedControl = v2ReadinessFrame;
  malformedControl[9] = 9;
  suite.expect(!prodigyDecodeGatewayLocalControlFrame(reinterpret_cast<const uint8_t *>(malformedControl.data()), uint32_t(malformedControl.size()), decodedControl),
               "gateway_local_control_rejects_unknown_kind");
  malformedControl = v2ReadinessFrame;
  malformedControl.append("x"_ctv);
  suite.expect(!prodigyDecodeGatewayLocalControlFrame(reinterpret_cast<const uint8_t *>(malformedControl.data()), uint32_t(malformedControl.size()), decodedControl),
               "gateway_local_control_rejects_trailing_bytes");
  uint8_t overlongControl[512] = {};
  uint32_t overlongBytes = 509;
  memcpy(overlongControl, &overlongBytes, sizeof(overlongBytes));
  suite.expect(!prodigyDecodeGatewayLocalControlFrame(overlongControl, sizeof(overlongControl), decodedControl),
               "gateway_local_control_rejects_payload_over_508_bytes");
  auto invalidBody = hello;
  invalidBody.rebindHello.recoveryToken.clear();
  suite.expect(!prodigyEncodeGatewayLocalControlFrame(invalidBody, malformedControl),
               "gateway_local_control_rejects_invalid_selected_body");
  auto invalidV2Token = hello;
  invalidV2Token.rebindHello.recoveryToken.assign("0123456789abcdef0123456789abcde"_ctv);
  suite.expect(!prodigyEncodeGatewayLocalControlFrame(invalidV2Token, malformedControl),
               "gateway_local_control_v2_rejects_short_token");
  invalidV2Token = hello;
  invalidV2Token.rebindHello.recoveryToken.assign("0123456789ABCDEF0123456789ABCDEF"_ctv);
  suite.expect(!prodigyEncodeGatewayLocalControlFrame(invalidV2Token, malformedControl),
               "gateway_local_control_v2_rejects_uppercase_token");
  invalidV2Token = hello;
  invalidV2Token.rebindHello.recoveryToken.assign("0123456789abcdef0123456789abcdeg"_ctv);
  suite.expect(!prodigyEncodeGatewayLocalControlFrame(invalidV2Token, malformedControl),
               "gateway_local_control_v2_rejects_nonhex_token");
  auto inadmissibleReadiness = v2Readiness;
  inadmissibleReadiness.readiness.authenticatedMasqueQUICReady = false;
  suite.expect(!prodigyEncodeGatewayLocalControlFrame(inadmissibleReadiness, malformedControl),
               "gateway_local_control_v2_rejects_unauthenticated_initial_readiness");
  inadmissibleReadiness = v2Readiness;
  inadmissibleReadiness.readiness.ready = false;
  suite.expect(!prodigyEncodeGatewayLocalControlFrame(inadmissibleReadiness, malformedControl),
               "gateway_local_control_v2_rejects_unready_initial_readiness");

  ProdigyGatewayLocalCarrierMode mode = ProdigyGatewayLocalCarrierMode::undecided;
  suite.expect(prodigyGatewayLocalCarrierLockMode(mode, reinterpret_cast<const uint8_t *>(v2ReadinessFrame.data()), uint32_t(v2ReadinessFrame.size()), false) &&
                   mode == ProdigyGatewayLocalCarrierMode::v2 &&
                   !prodigyGatewayLocalCarrierLockMode(mode, reinterpret_cast<const uint8_t *>(readinessFrame.data()), uint32_t(readinessFrame.size()), false),
               "gateway_local_control_v2_carrier_never_falls_back_to_legacy");
  mode = ProdigyGatewayLocalCarrierMode::undecided;
  suite.expect(prodigyGatewayLocalCarrierLockMode(mode, reinterpret_cast<const uint8_t *>(readinessFrame.data()), uint32_t(readinessFrame.size()), false) &&
                   mode == ProdigyGatewayLocalCarrierMode::legacyV1 &&
                   !prodigyGatewayLocalCarrierLockMode(mode, reinterpret_cast<const uint8_t *>(v2ReadinessFrame.data()), uint32_t(v2ReadinessFrame.size()), false),
               "gateway_local_control_legacy_initial_readiness_remains_mode_locked");
  mode = ProdigyGatewayLocalCarrierMode::undecided;
  suite.expect(!prodigyGatewayLocalCarrierLockMode(mode, reinterpret_cast<const uint8_t *>(readinessFrame.data()), uint32_t(readinessFrame.size()), true),
               "gateway_local_control_recovery_carrier_rejects_legacy_v1");
  suite.expect(prodigyGatewayLocalControlFrameAllowed(ProdigyGatewayLocalCarrierMode::v2, ProdigyGatewayLocalCarrierPhase::initial, v2Readiness) &&
                   !prodigyGatewayLocalControlFrameAllowed(ProdigyGatewayLocalCarrierMode::v2, ProdigyGatewayLocalCarrierPhase::initial, hello) &&
                   prodigyGatewayLocalControlFrameAllowed(ProdigyGatewayLocalCarrierMode::v2, ProdigyGatewayLocalCarrierPhase::rebindHello, hello) &&
                   prodigyGatewayLocalControlFrameAllowed(ProdigyGatewayLocalCarrierMode::v2, ProdigyGatewayLocalCarrierPhase::rebindReceipt, rebindReceipt) &&
                   prodigyGatewayLocalControlFrameAllowed(ProdigyGatewayLocalCarrierMode::v2, ProdigyGatewayLocalCarrierPhase::established, pathFault),
               "gateway_local_control_enforces_direction_kind_phase_rules");
  auto wrongDirection = rebindReceipt;
  wrongDirection.direction = ProdigyGatewayLocalDirection::neuronToGateway;
  auto wrongPathDirection = pathFault;
  wrongPathDirection.direction = ProdigyGatewayLocalDirection::gatewayToNeuron;
  suite.expect(!prodigyGatewayLocalControlFrameAllowed(ProdigyGatewayLocalCarrierMode::v2, ProdigyGatewayLocalCarrierPhase::rebindReceipt, wrongDirection) &&
                   !prodigyGatewayLocalControlFrameAllowed(ProdigyGatewayLocalCarrierMode::v2, ProdigyGatewayLocalCarrierPhase::established, wrongPathDirection),
               "gateway_local_control_rejects_direction_body_mismatches");

  Runtime53SystemContainerRuntimePlan runtime53 = {};
  auto& runtime53Plan = runtime53.plan;
  runtime53Plan.kind = SystemContainerKind::crossClusterMasqueGateway;
  runtime53Plan.artifact.sha256.assign("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"_ctv);
  runtime53Plan.artifact.bytes = 0x0102030405060708ULL;
  runtime53Plan.egress.policyVersion = 2;
  runtime53Plan.egress.address4 = 0x01020304;
  for (uint8_t index = 0; index < sizeof(runtime53Plan.egress.address6); ++index) runtime53Plan.egress.address6[index] = uint8_t(index + 1);
  runtime53Plan.egress.port = 4433;
  runtime53Plan.egress.protocol = 17;
  runtime53Plan.egress.peerIsIPv6 = true;
  runtime53Plan.egress.allowIngressFromPeer = true;
  runtime53Plan.gatewayReadinessSocket.assign("/run/prodigy/ready.soc"_ctv);
  runtime53Plan.gatewayLaunchToken.assign("0123456789abcdef0123456789abcdef"_ctv);
  runtime53Plan.gatewayRole.assign("listener"_ctv);
  runtime53Plan.gatewayRoutes.assign("2001:db8:1::/64"_ctv);
  runtime53Plan.gatewayEndpoint.assign("[2001:db8:2::1]:4433"_ctv);
  runtime53Plan.gatewayLocalIdentity.assign("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"_ctv);
  runtime53Plan.gatewayPeerIdentity.assign("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"_ctv);
  runtime53Plan.gatewayPeerTrust.assign("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"_ctv);
  runtime53Plan.gatewayTunnelInterface.assign("mtbgp000001"_ctv);
  runtime53Plan.gatewayPairUUID = uint128_t(0x1112131415161718ULL);
  runtime53Plan.gatewayLocalClusterUUID = uint128_t(0x2122232425262728ULL);
  runtime53Plan.gatewayLocalMachineUUID = uint128_t(0x3132333435363738ULL);
  runtime53Plan.gatewayKeyEpoch = 0x4142434445464748ULL;
  runtime53Plan.gatewayAuthorityGeneration = 0x5152535455565758ULL;
  runtime53Plan.gatewayGeneration = 0x6162636465666768ULL;
  String runtime53Bytes = {};
  SystemContainerRuntimePlan decodedRuntime53 = {};
  suite.expect(BitseryEngine::serialize(runtime53Bytes, runtime53) &&
                   BitseryEngine::deserializeSafe(runtime53Bytes, decodedRuntime53) &&
                   decodedRuntime53.kind == runtime53Plan.kind &&
                   decodedRuntime53.artifact.sha256 == runtime53Plan.artifact.sha256 && decodedRuntime53.artifact.bytes == runtime53Plan.artifact.bytes &&
                   decodedRuntime53.egress.policyVersion == runtime53Plan.egress.policyVersion && decodedRuntime53.egress.address4 == runtime53Plan.egress.address4 &&
                   memcmp(decodedRuntime53.egress.address6, runtime53Plan.egress.address6, sizeof(runtime53Plan.egress.address6)) == 0 &&
                   decodedRuntime53.egress.port == runtime53Plan.egress.port && decodedRuntime53.egress.protocol == runtime53Plan.egress.protocol &&
                   decodedRuntime53.egress.peerIsIPv6 == runtime53Plan.egress.peerIsIPv6 && decodedRuntime53.egress.allowIngressFromPeer == runtime53Plan.egress.allowIngressFromPeer &&
                   decodedRuntime53.gatewayReadinessSocket == runtime53Plan.gatewayReadinessSocket && decodedRuntime53.gatewayLaunchToken == runtime53Plan.gatewayLaunchToken &&
                   decodedRuntime53.gatewayRole == runtime53Plan.gatewayRole && decodedRuntime53.gatewayRoutes == runtime53Plan.gatewayRoutes &&
                   decodedRuntime53.gatewayEndpoint == runtime53Plan.gatewayEndpoint && decodedRuntime53.gatewayLocalIdentity == runtime53Plan.gatewayLocalIdentity &&
                   decodedRuntime53.gatewayPeerIdentity == runtime53Plan.gatewayPeerIdentity && decodedRuntime53.gatewayPeerTrust == runtime53Plan.gatewayPeerTrust &&
                   decodedRuntime53.gatewayTunnelInterface == runtime53Plan.gatewayTunnelInterface &&
                   decodedRuntime53.gatewayPairUUID == runtime53Plan.gatewayPairUUID && decodedRuntime53.gatewayLocalClusterUUID == runtime53Plan.gatewayLocalClusterUUID &&
                   decodedRuntime53.gatewayLocalMachineUUID == runtime53Plan.gatewayLocalMachineUUID && decodedRuntime53.gatewayKeyEpoch == runtime53Plan.gatewayKeyEpoch &&
                   decodedRuntime53.gatewayAuthorityGeneration == runtime53Plan.gatewayAuthorityGeneration && decodedRuntime53.gatewayGeneration == runtime53Plan.gatewayGeneration &&
                   decodedRuntime53.gatewayRecoverySocket.empty() && decodedRuntime53.gatewayRecoveryToken.empty(),
               "gateway_runtime53_layout_decodes_every_legacy_field_in_position");
  String currentPlanBytes = {};
  auto recoveryVariant = decodedRuntime53;
  recoveryVariant.gatewayRecoverySocket.assign("/run/prodigy/recovery-a.soc"_ctv);
  recoveryVariant.gatewayRecoveryToken.assign("abcdef0123456789abcdef0123456789"_ctv);
  String recoveryVariantBytes = {};
  suite.expect(BitseryEngine::serialize(currentPlanBytes, decodedRuntime53) &&
                   BitseryEngine::serialize(recoveryVariantBytes, recoveryVariant) &&
                   currentPlanBytes == runtime53Bytes && currentPlanBytes == recoveryVariantBytes,
               "gateway_recovery_fields_are_excluded_from_runtime_plan_wire_bytes");

  SystemContainerEgressPolicy ipv4Tunnel = {};
  ipv4Tunnel.address4 = 0x5db8d822u;
  ipv4Tunnel.port = 443;
  suite.expect(ipv4Tunnel.configured() && ipv4Tunnel.protocol == 6 && !ipv4Tunnel.peerIsIPv6,
               "tunnel_provider_ipv4_tcp_policy_remains_supported");

  SystemContainerEgressPolicy ipv6Gateway = {};
  ipv6Gateway.peerIsIPv6 = true;
  ipv6Gateway.protocol = 17;
  ipv6Gateway.port = 4433;
  ipv6Gateway.address6[15] = 1;
  ipv6Gateway.allowIngressFromPeer = true;
  suite.expect(ipv6Gateway.configured(), "gateway_ipv6_udp_exact_peer_policy_is_configured");
  ipv6Gateway.protocol = 1;
  suite.expect(!ipv6Gateway.configured(), "gateway_rejects_unsupported_protocol_policy");
  ipv6Gateway.protocol = 17;
  ipv6Gateway.port = 0;
  suite.expect(!ipv6Gateway.configured(), "gateway_rejects_wrong_port_policy");
  ipv6Gateway.port = 4433;
  ipv6Gateway.policyVersion = 1;
  suite.expect(!ipv6Gateway.configured(), "gateway_rejects_stale_policy_version");

  SystemContainerRuntimePlan gatewayPlan = {};
  gatewayPlan.kind = SystemContainerKind::crossClusterMasqueGateway;
  gatewayPlan.gatewayPairUUID = uint128_t(0x0123456789abcdefULL);
  gatewayPlan.gatewayLocalClusterUUID = uint128_t(0x1020304050607080ULL);
  gatewayPlan.gatewayLocalMachineUUID = uint128_t(0xfedcba9876543210ULL);
  gatewayPlan.gatewayKeyEpoch = 17;
  gatewayPlan.gatewayAuthorityGeneration = 23;
  gatewayPlan.gatewayGeneration = 29;
  gatewayPlan.gatewayTunnelInterface.assign("mtbgp000001"_ctv);
  const SystemContainerRuntimePlan completeGatewayPlan = gatewayPlan;
  Vector<String> gatewayEnvironment = {};
  suite.expect(
      prodigyAppendCrossClusterMasqueGatewayAuthorityEnvironment(gatewayPlan, gatewayEnvironment) &&
          gatewayEnvironment.size() == 7 &&
          gatewayEnvironment[0] == "PRODIGY_MASQUE_PAIR_UUID=0123456789abcdef"_ctv &&
          gatewayEnvironment[1] == "PRODIGY_MASQUE_LOCAL_CLUSTER_UUID=1020304050607080"_ctv &&
          gatewayEnvironment[2] == "PRODIGY_MASQUE_LOCAL_MACHINE_UUID=fedcba9876543210"_ctv &&
          gatewayEnvironment[3] == "PRODIGY_MASQUE_KEY_EPOCH=17"_ctv &&
          gatewayEnvironment[4] == "PRODIGY_MASQUE_AUTHORITY_GENERATION=23"_ctv &&
          gatewayEnvironment[5] == "PRODIGY_MASQUE_GATEWAY_GENERATION=29"_ctv &&
          gatewayEnvironment[6] == "PRODIGY_MASQUE_TUN_INTERFACE=mtbgp000001"_ctv,
      "gateway_authority_environment_has_exact_canonical_values");
  auto rejectsMissingAuthorityReference = [](const SystemContainerRuntimePlan& candidate) {
    Vector<String> environment = {};
    return !prodigyAppendCrossClusterMasqueGatewayAuthorityEnvironment(candidate, environment) && environment.empty();
  };
  gatewayPlan = completeGatewayPlan; gatewayPlan.gatewayPairUUID = 0;
  suite.expect(rejectsMissingAuthorityReference(gatewayPlan), "gateway_authority_environment_rejects_missing_pair_uuid");
  gatewayPlan = completeGatewayPlan; gatewayPlan.gatewayLocalClusterUUID = 0;
  suite.expect(rejectsMissingAuthorityReference(gatewayPlan), "gateway_authority_environment_rejects_missing_local_cluster_uuid");
  gatewayPlan = completeGatewayPlan; gatewayPlan.gatewayLocalMachineUUID = 0;
  suite.expect(rejectsMissingAuthorityReference(gatewayPlan), "gateway_authority_environment_rejects_missing_local_machine_uuid");
  gatewayPlan = completeGatewayPlan; gatewayPlan.gatewayKeyEpoch = 0;
  suite.expect(rejectsMissingAuthorityReference(gatewayPlan), "gateway_authority_environment_rejects_missing_key_epoch");
  gatewayPlan = completeGatewayPlan; gatewayPlan.gatewayAuthorityGeneration = 0;
  suite.expect(rejectsMissingAuthorityReference(gatewayPlan), "gateway_authority_environment_rejects_missing_authority_generation");
  gatewayPlan = completeGatewayPlan; gatewayPlan.gatewayGeneration = 0;
  suite.expect(rejectsMissingAuthorityReference(gatewayPlan), "gateway_authority_environment_rejects_missing_gateway_generation");
  gatewayPlan = completeGatewayPlan; gatewayPlan.gatewayTunnelInterface.clear();
  suite.expect(rejectsMissingAuthorityReference(gatewayPlan), "gateway_authority_environment_rejects_missing_tunnel_interface");

  auto gatewayAuthority = [](uint128_t pairUUID, uint128_t localMachineUUID, uint128_t peerMachineUUID,
                             uint8_t gatewaySlot, uint8_t tunnelSlot, const String& interfaceName) {
    CrossClusterMasqueGatewayAuthority authority = {};
    authority.pairUUID = pairUUID; authority.pairOperationUUID = pairUUID + 0x100;
    authority.localClusterUUID = 0xE001; authority.peerClusterUUID = pairUUID + 0xE100;
    authority.localMachineUUID = localMachineUUID; authority.peerMachineUUID = peerMachineUUID;
    authority.localDatacenterFragment = 1; authority.peerDatacenterFragment = uint8_t(pairUUID + 1);
    authority.localSitePrefix = prodigyContainerDatacenterSitePrefix(authority.localDatacenterFragment);
    authority.peerSitePrefix = prodigyContainerDatacenterSitePrefix(authority.peerDatacenterFragment);
    authority.artifactSHA256.assign("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"_ctv);
    authority.artifactBytes = 1; authority.listenerPublicUDPEndpoint.is6 = true;
    authority.listenerPublicUDPEndpoint.v6[0] = 0x20; authority.listenerPublicUDPEndpoint.v6[1] = 1;
    authority.listenerPublicUDPPort = 4433; authority.gatewaySlot = gatewaySlot; authority.tunnelSlot = tunnelSlot;
    authority.privateTunnelInterface = interfaceName; authority.privateTunnelLocalIPv6.is6 = authority.privateTunnelPeerIPv6.is6 = true;
    authority.privateTunnelLocalIPv6.v6[0] = 0xfd; authority.privateTunnelLocalIPv6.v6[15] = 1;
    authority.privateTunnelPeerIPv6.v6[0] = 0xfd; authority.privateTunnelPeerIPv6.v6[15] = 2;
    authority.privateLocalASN = 42001; authority.privatePeerASN = 42002;
    authority.privateLocalBGPID = 1; authority.privatePeerBGPID = 2;
    authority.privateSessionCredentialSHA256.assign("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"_ctv);
    authority.localIdentitySHA256.assign("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"_ctv);
    authority.peerIdentitySHA256.assign("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"_ctv);
    authority.peerTrustSHA256.assign("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"_ctv);
    authority.generation = authority.pairAuthorityGeneration = authority.keyGeneration = 1;
    return authority;
  };
  Vector<CrossClusterMasqueGatewayAuthority> reusedHostAuthorities = {};
  reusedHostAuthorities.push_back(gatewayAuthority(1, 0xA001, 0xB001, 0, 0, "mtbgpaaaaaa"_ctv));
  reusedHostAuthorities.push_back(gatewayAuthority(2, 0xA001, 0xC001, 0, 1, "mtbgpbbbbbb"_ctv));
  auto launchAuthority = reusedHostAuthorities[0];
  launchAuthority.privateTunnelLocalIPv6.v6[15] = 0;
  launchAuthority.privateTunnelPeerIPv6.v6[15] = 1;
  launchAuthority.localRole = CrossClusterMasqueGatewayRole::listener;
  Vector<String> launchArgs = {};
  Vector<int32_t> launchFDs = {};
  auto optionValue = [&](const char *flag) -> String {
    for (size_t index = 0; index + 1 < launchArgs.size(); ++index)
      if (launchArgs[index].equal(String(flag))) return launchArgs[index + 1];
    return {};
  };
  suite.expect(prodigyBuildMasqueGatewayExecArguments(launchAuthority,
      "root-cert"_ctv, "leaf-cert"_ctv, "private-key"_ctv, "aabb"_ctv, launchArgs, launchFDs) &&
      launchFDs.size() == 4 && launchArgs[0] == "server"_ctv &&
      optionValue("--listen") == "[::]:4433"_ctv &&
      optionValue("--ip6-p2p-local") == "fd00::"_ctv &&
      optionValue("--ip6-p2p-peer") == "fd00::1"_ctv &&
      optionValue("--ip-pool").empty() && optionValue("--ip6-pool").empty(),
      "listener_uses_exact_p2p_and_vault_fd_arguments");
  for (int fd : launchFDs)
  {
    suite.expect((fcntl(fd, F_GET_SEALS) & (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL)) ==
        (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) &&
        (fcntl(fd, F_GETFD) & FD_CLOEXEC) == 0 && write(fd, "x", 1) == -1,
        "launch_file_is_sealed_and_survives_exec");
    close(fd);
  }
  for (const auto& arg : launchArgs)
    suite.expect(arg != "private-key"_ctv && arg != "leaf-cert"_ctv && arg != "root-cert"_ctv,
                 "launch_arguments_never_contain_pem_material");
  launchFDs.clear(); launchArgs.clear();
  launchAuthority.localRole = CrossClusterMasqueGatewayRole::connector;
  suite.expect(prodigyBuildMasqueGatewayExecArguments(launchAuthority,
      "root-cert"_ctv, "leaf-cert"_ctv, "private-key"_ctv, "aabb"_ctv, launchArgs, launchFDs) &&
      launchFDs.size() == 3 && launchArgs[0] == "client-ip"_ctv &&
      optionValue("--proxy-url") == "https://[2001::]:4433"_ctv &&
      !optionValue("--local-ip6-route").empty() && optionValue("--insecure").empty(),
      "connector_uses_ipv6_url_and_local_site_route_without_insecure_tls");
  for (int fd : launchFDs) close(fd);
  launchFDs.clear(); launchArgs.clear();
  launchAuthority.privateTunnelPeerIPv6.v6[15] = 2;
  suite.expect(!prodigyBuildMasqueGatewayExecArguments(launchAuthority,
      "root-cert"_ctv, "leaf-cert"_ctv, "private-key"_ctv, "aabb"_ctv, launchArgs, launchFDs) &&
      launchArgs.empty() && launchFDs.empty(), "launch_rejects_non_p2p_tuple_without_leaking_fds");
  suite.expect(prodigyCrossClusterMasqueGatewayAuthoritiesValid(reusedHostAuthorities, 0xE001),
               "gateway_host_accepts_two_pair_distinct_authorities");
  ProdigyCrossClusterMasqueGatewayAuthorityProjection reusedProjection = {};
  reusedProjection.authorities = reusedHostAuthorities;
  suite.expect(prodigyCrossClusterMasqueGatewayAuthorityProjectionValidForMachine(reusedProjection, 0xE001, 0xA001),
               "gateway_projection_accepts_two_exact_pair_distinct_authorities");
  auto interfaceCollision = reusedHostAuthorities;
  interfaceCollision[1].privateTunnelInterface = interfaceCollision[0].privateTunnelInterface;
  suite.expect(!prodigyCrossClusterMasqueGatewayAuthoritiesValid(interfaceCollision, 0xE001),
               "gateway_host_rejects_pair_interface_collision");
  auto thirdPair = reusedHostAuthorities;
  thirdPair.push_back(gatewayAuthority(3, 0xA001, 0xD001, 0, 2, "mtbgpcccccc"_ctv));
  suite.expect(!prodigyCrossClusterMasqueGatewayAuthoritiesValid(thirdPair, 0xE001),
               "gateway_host_rejects_more_than_two_pair_authorities");
  auto retainedTombstone = thirdPair;
  retainedTombstone[0].generation = 2;
  retainedTombstone[0].state = CrossClusterMasqueGatewayState::withdrawn;
  suite.expect(prodigyCrossClusterMasqueGatewayAuthoritiesValid(retainedTombstone, 0xE001) &&
                   prodigyCrossClusterMasqueGatewayRuntimeFragment(
                       retainedTombstone, retainedTombstone[1].pairUUID,
                       retainedTombstone[1].localMachineUUID) ==
                       prodigyCrossClusterMasqueGatewayRuntimeFragmentSecond &&
                   prodigyCrossClusterMasqueGatewayRuntimeFragment(
                       retainedTombstone, retainedTombstone[2].pairUUID,
                       retainedTombstone[2].localMachineUUID) == 0,
               "gateway_withdrawal_tombstone_retains_history_without_claiming_live_capacity");
  ProdigyCrossClusterMasqueGatewayAuthorityProjection overfullProjection = {};
  overfullProjection.authorities = retainedTombstone;
  suite.expect(!prodigyCrossClusterMasqueGatewayAuthorityProjectionValidForMachine(
                   overfullProjection, 0xE001, 0xA001),
               "gateway_projection_never_exposes_three_authorities_during_retirement");
  auto withdrawOnePair = reusedProjection;
  withdrawOnePair.authorities[0].generation = 2;
  withdrawOnePair.authorities[0].state = CrossClusterMasqueGatewayState::withdrawn;
  suite.expect(prodigyCrossClusterMasqueGatewayAuthorityProjectionValidForMachine(withdrawOnePair, 0xE001, 0xA001) &&
                   withdrawOnePair.authorities[1].state == CrossClusterMasqueGatewayState::active,
               "gateway_one_pair_withdrawal_preserves_other_pair_authority");

  std::filesystem::create_directories(".run");
  char path[] = ".run/prodigy-cross-cluster-masque-contract-XXXXXX";
  const int writeFD = mkstemp(path);
  suite.expect(writeFD >= 0, "creates_temporary_gateway_artifact");
  if (writeFD >= 0)
  {
    String blob = prodigyDiscombobulatorCrossClusterMasqueGatewayBlobHeaderText();
    blob.append("payload"_ctv);
    suite.expect(write(writeFD, blob.data(), blob.size()) == ssize_t(blob.size()),
                 "writes_typed_gateway_artifact");
    close(writeFD);

    int payloadFD = -1;
    String failure = {};
    suite.expect(
        prodigyOpenSystemContainerBlobPayloadAfterContractHeader(
            SystemContainerKind::crossClusterMasqueGateway, String(path), payloadFD, &failure) &&
            payloadFD >= 0,
        "typed_dispatcher_accepts_cross_cluster_gateway_contract");
    if (payloadFD >= 0) close(payloadFD);

    payloadFD = -1;
    suite.expect(
        !prodigyOpenSystemContainerBlobPayloadAfterContractHeader(
            SystemContainerKind::mothershipTunnelProvider, String(path), payloadFD, &failure) &&
            payloadFD == -1,
        "typed_dispatcher_rejects_gateway_as_tunnel_provider");
    unlink(path);
  }

  return suite.failures == 0 ? 0 : 1;
}
