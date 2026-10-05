#pragma once

// Pair-control authentication is a bounded prelude/resolver adapter for the
// existing fresh Noise+AEGIS stream. Enrollment and the local Brain policy own
// roster approval, root persistence, endpoint listening, and all control
// records; this header owns neither a listener nor authorization state.

#include <array>
#include <cstdint>
#include <cstring>

#include <prodigy/cluster.pair.keys.h>

#include <prodigy/cluster.pair.endpoint.h>

// The claim is deliberately fixed width. It contains no root or derived key;
// the surrounding Noise prologue authenticates its exact bytes.
struct ClusterPairControlEndpointClaim {
  static constexpr uint32_t version = 1;
  uint32_t protocolVersion = version;
  uint128_t pairUUID = 0;
  uint64_t rootGeneration = 0;
  uint64_t keyEpoch = 0;
  ClusterPairControlEndpoint initiator = {};
  ClusterPairControlEndpoint responder = {};
  ClusterPairControlEndpoint presenter = {};
};

static inline bool clusterPairControlEndpointClaimValid(const ClusterPairControlEndpointClaim& claim)
{
  if (claim.protocolVersion != ClusterPairControlEndpointClaim::version || claim.pairUUID == 0 ||
      claim.rootGeneration == 0 || claim.keyEpoch == 0 || !clusterPairControlEndpointValid(claim.initiator) ||
      !clusterPairControlEndpointValid(claim.responder) || !clusterPairControlEndpointValid(claim.presenter) ||
      claim.initiator.clusterUUID == claim.responder.clusterUUID ||
      clusterPairControlEndpointEquals(claim.initiator, claim.responder)) return false;
  return clusterPairControlEndpointEquals(claim.presenter, claim.initiator) ||
         clusterPairControlEndpointEquals(claim.presenter, claim.responder);
}

static inline void clusterPairControlAppendU16BE(String& output, uint16_t value)
{
  output.append(uint8_t(value >> 8));
  output.append(uint8_t(value));
}

static inline void clusterPairControlAppendU32BE(String& output, uint32_t value)
{
  for (int shift = 24; shift >= 0; shift -= 8) output.append(uint8_t(value >> shift));
}

static inline void clusterPairControlAppendEndpoint(String& output, const ClusterPairControlEndpoint& endpoint)
{
  clusterPairControlAppendU32BE(output, endpoint.protocolVersion);
  clusterPairKeyAppendU128BE(output, endpoint.clusterUUID);
  clusterPairKeyAppendU128BE(output, endpoint.nodeUUID);
  clusterPairKeyAppendU64BE(output, uint64_t(endpoint.role));
  output.append(endpoint.address.v6, sizeof(endpoint.address.v6));
  clusterPairControlAppendU16BE(output, endpoint.port);
}

static constexpr uint32_t clusterPairControlEndpointClaimBytes = 4 + 16 + 8 + 8 + 3 * (4 + 16 + 16 + 8 + 16 + 2);

static inline bool clusterPairRenderControlEndpointClaim(const ClusterPairControlEndpointClaim& claim, String& output)
{
  output.clear();
  if (!clusterPairControlEndpointClaimValid(claim) || !output.reserve(clusterPairControlEndpointClaimBytes)) return false;
  clusterPairControlAppendU32BE(output, claim.protocolVersion);
  clusterPairKeyAppendU128BE(output, claim.pairUUID);
  clusterPairKeyAppendU64BE(output, claim.rootGeneration);
  clusterPairKeyAppendU64BE(output, claim.keyEpoch);
  clusterPairControlAppendEndpoint(output, claim.initiator);
  clusterPairControlAppendEndpoint(output, claim.responder);
  clusterPairControlAppendEndpoint(output, claim.presenter);
  if (output.size() != clusterPairControlEndpointClaimBytes) { output.clear(); return false; }
  return true;
}

static inline bool clusterPairControlReadU16BE(const uint8_t *&cursor, const uint8_t *terminal, uint16_t& value)
{
  if (cursor == nullptr || terminal - cursor < 2) return false;
  value = uint16_t(uint16_t(cursor[0]) << 8 | cursor[1]); cursor += 2; return true;
}

static inline bool clusterPairControlReadU32BE(const uint8_t *&cursor, const uint8_t *terminal, uint32_t& value)
{
  if (cursor == nullptr || terminal - cursor < 4) return false;
  value = 0; for (uint32_t index = 0; index < 4; ++index) value = (value << 8) | cursor[index]; cursor += 4; return true;
}

static inline bool clusterPairControlReadU64BE(const uint8_t *&cursor, const uint8_t *terminal, uint64_t& value)
{
  if (cursor == nullptr || terminal - cursor < 8) return false;
  value = 0; for (uint32_t index = 0; index < 8; ++index) value = (value << 8) | cursor[index]; cursor += 8; return true;
}

static inline bool clusterPairControlReadU128BE(const uint8_t *&cursor, const uint8_t *terminal, uint128_t& value)
{
  if (cursor == nullptr || terminal - cursor < 16) return false;
  value = 0; for (uint32_t index = 0; index < 16; ++index) value = (value << 8) | cursor[index]; cursor += 16; return true;
}

static inline bool clusterPairControlReadEndpoint(const uint8_t *&cursor, const uint8_t *terminal,
                                                  ClusterPairControlEndpoint& endpoint)
{
  uint64_t role = 0;
  if (!clusterPairControlReadU32BE(cursor, terminal, endpoint.protocolVersion) ||
      !clusterPairControlReadU128BE(cursor, terminal, endpoint.clusterUUID) ||
      !clusterPairControlReadU128BE(cursor, terminal, endpoint.nodeUUID) ||
      !clusterPairControlReadU64BE(cursor, terminal, role) || terminal - cursor < 16) return false;
  std::memcpy(endpoint.address.v6, cursor, 16);
  cursor += 16;
  if (!clusterPairControlReadU16BE(cursor, terminal, endpoint.port)) return false;
  endpoint.address.is6 = true;
  endpoint.role = ClusterPairControlNodeRole(role);
  return clusterPairControlEndpointValid(endpoint);
}

static inline bool clusterPairParseControlEndpointClaim(const String& input, ClusterPairControlEndpointClaim& claim)
{
  claim = {};
  if (input.size() != clusterPairControlEndpointClaimBytes) return false;
  const uint8_t *cursor = reinterpret_cast<const uint8_t *>(input.data());
  const uint8_t *terminal = cursor + input.size();
  if (!clusterPairControlReadU32BE(cursor, terminal, claim.protocolVersion) ||
      !clusterPairControlReadU128BE(cursor, terminal, claim.pairUUID) ||
      !clusterPairControlReadU64BE(cursor, terminal, claim.rootGeneration) ||
      !clusterPairControlReadU64BE(cursor, terminal, claim.keyEpoch) ||
      !clusterPairControlReadEndpoint(cursor, terminal, claim.initiator) ||
      !clusterPairControlReadEndpoint(cursor, terminal, claim.responder) ||
      !clusterPairControlReadEndpoint(cursor, terminal, claim.presenter) || cursor != terminal)
  { claim = {}; return false; }
  return clusterPairControlEndpointClaimValid(claim);
}

class ClusterPairControlResolver {
  ClusterPairDerivedKey key = {};
  String canonicalContext = {};
  String localClaim = {};
  String expectedRemoteClaim = {};
  uint128_t remoteNodeUUID = 0;

public:
  ClusterPairControlResolver() = default;
  ClusterPairControlResolver(const ClusterPairControlResolver&) = delete;
  ClusterPairControlResolver& operator=(const ClusterPairControlResolver&) = delete;
  ClusterPairControlResolver(ClusterPairControlResolver&&) noexcept = default;
  ClusterPairControlResolver& operator=(ClusterPairControlResolver&&) noexcept = default;

  void clear()
  {
    key.clear();
    if (canonicalContext.ownsMemory()) OPENSSL_cleanse(canonicalContext.data(), canonicalContext.size());
    canonicalContext.clear(); localClaim.clear(); expectedRemoteClaim.clear(); remoteNodeUUID = 0;
  }
  ~ClusterPairControlResolver() { clear(); }

  const String& localPublicClaim() const { return localClaim; }
  bool ready() const { return key.size == 32 && !canonicalContext.empty() && !localClaim.empty() && !expectedRemoteClaim.empty() && remoteNodeUUID != 0; }
  bool initialize(ClusterPairDerivedKey&& sourceKey, String&& sourceContext, String&& sourceLocalClaim,
                  String&& sourceExpectedRemoteClaim, uint128_t expectedRemoteNodeUUID)
  {
    clear();
    ClusterPairControlEndpointClaim local = {}, remote = {};
    if (sourceKey.size != 32 || sourceContext.empty() || sourceLocalClaim.empty() ||
        sourceExpectedRemoteClaim.empty() || expectedRemoteNodeUUID == 0 ||
        !clusterPairParseControlEndpointClaim(sourceLocalClaim, local) ||
        !clusterPairParseControlEndpointClaim(sourceExpectedRemoteClaim, remote) ||
        local.pairUUID != remote.pairUUID || local.rootGeneration != remote.rootGeneration || local.keyEpoch != remote.keyEpoch ||
        !clusterPairControlEndpointEquals(local.initiator, remote.initiator) ||
        !clusterPairControlEndpointEquals(local.responder, remote.responder) ||
        clusterPairControlEndpointEquals(local.presenter, remote.presenter) ||
        expectedRemoteNodeUUID != remote.presenter.nodeUUID) return false;
    key = std::move(sourceKey);
    canonicalContext = std::move(sourceContext);
    localClaim = std::move(sourceLocalClaim);
    expectedRemoteClaim = std::move(sourceExpectedRemoteClaim);
    remoteNodeUUID = expectedRemoteNodeUUID;
    return ready();
  }

  bool resolve(const String& incomingClaim, std::array<uint8_t, 32>& outputPSK,
               String& outputContext, uint128_t& authenticatedNodeUUID) const
  {
    OPENSSL_cleanse(outputPSK.data(), outputPSK.size()); outputContext.clear(); authenticatedNodeUUID = 0;
    ClusterPairControlEndpointClaim parsed = {};
    if (!ready() || !clusterPairParseControlEndpointClaim(incomingClaim, parsed) || incomingClaim != expectedRemoteClaim) return false;
    std::memcpy(outputPSK.data(), key.bytes.data(), outputPSK.size());
    outputContext = canonicalContext;
    authenticatedNodeUUID = remoteNodeUUID;
    return outputContext.size() != 0;
  }
};

static inline bool clusterPairPrepareControlResolver(const ClusterPairRoot& root,
                                                     const ClusterPairControlEndpoint& initiator,
                                                     const ClusterPairControlEndpoint& responder,
                                                     const ClusterPairControlEndpoint& local,
                                                     const ClusterPairControlEndpoint& remote,
                                                     uint64_t keyEpoch, const String& channelIdentity,
                                                     ClusterPairControlResolver& resolver)
{
  resolver.clear();
  if (!clusterPairRootValid(root) || keyEpoch == 0 || channelIdentity.empty() || channelIdentity.size() > 128 ||
      !clusterPairControlEndpointValid(initiator) || !clusterPairControlEndpointValid(responder) ||
      !clusterPairControlEndpointValid(local) || !clusterPairControlEndpointValid(remote) ||
      initiator.clusterUUID == responder.clusterUUID ||
      !(clusterPairControlEndpointEquals(local, initiator) || clusterPairControlEndpointEquals(local, responder)) ||
      !(clusterPairControlEndpointEquals(remote, initiator) || clusterPairControlEndpointEquals(remote, responder)) ||
      clusterPairControlEndpointEquals(local, remote)) return false;
  if (initiator.clusterUUID != root.firstClusterUUID && initiator.clusterUUID != root.secondClusterUUID) return false;
  if (responder.clusterUUID != root.firstClusterUUID && responder.clusterUUID != root.secondClusterUUID) return false;

  ClusterPairKeyContext context = {};
  context.scope = ClusterPairKeyScope::pairControlEndpoint;
  context.keyEpoch = keyEpoch;
  context.purpose = ClusterPairKeyPurpose::pairControl;
  context.senderClusterUUID = initiator.clusterUUID;
  context.receiverClusterUUID = responder.clusterUUID;
  context.senderNodeUUID = initiator.nodeUUID;
  context.receiverNodeUUID = responder.nodeUUID;
  context.senderRole = uint64_t(initiator.role);
  context.receiverRole = uint64_t(responder.role);
  context.channelIdentity = channelIdentity;
  ClusterPairDerivedKey key = {};
  String canonicalContext = {}, localClaim = {}, expectedRemoteClaim = {};
  if (!clusterPairDeriveKey(root, context, key) ||
      !clusterPairCanonicalKeyContext(root, context, canonicalContext)) return false;

  ClusterPairControlEndpointClaim localWire = {};
  localWire.pairUUID = root.pairUUID; localWire.rootGeneration = root.rootGeneration; localWire.keyEpoch = keyEpoch;
  localWire.initiator = initiator; localWire.responder = responder; localWire.presenter = local;
  ClusterPairControlEndpointClaim remoteWire = localWire; remoteWire.presenter = remote;
  if (!clusterPairRenderControlEndpointClaim(localWire, localClaim) ||
      !clusterPairRenderControlEndpointClaim(remoteWire, expectedRemoteClaim)) return false;
  return resolver.initialize(std::move(key), std::move(canonicalContext), std::move(localClaim),
                             std::move(expectedRemoteClaim), remote.nodeUUID);
}
