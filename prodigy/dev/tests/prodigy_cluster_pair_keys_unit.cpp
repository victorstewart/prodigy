#include <prodigy/cluster.pair.keys.h>

#include <cstdio>
#include <type_traits>
#include <utility>

static bool expect(bool value, const char *name)
{
  std::printf("%s: %s\n", value ? "PASS" : "FAIL", name);
  return value;
}

static ClusterPairRoot testRoot()
{
  ClusterPairRoot root = {};
  root.pairUUID = 0x100;
  root.firstClusterUUID = 0x200;
  root.secondClusterUUID = 0x300;
  root.rootGeneration = 7;
  for (uint32_t index = 0; index < root.root.size(); ++index) root.root[index] = uint8_t(index + 1);
  return root;
}

static ClusterPairKeyContext serviceContext()
{
  ClusterPairKeyContext context = {};
  context.logicalWorkloadUUID = 0x400;
  context.logicalServiceUUID = 0x500;
  context.slots.insert(3);
  context.slots.insert(1001);
  context.keyEpoch = 9;
  context.senderClusterUUID = 0x200;
  context.receiverClusterUUID = 0x300;
  context.channelIdentity = "hse-change-stream"_ctv;
  return context;
}

static bool matchesHex(const ClusterPairDerivedKey& key, const char *hex)
{
  if (std::strlen(hex) != key.size * 2) return false;
  constexpr char digits[] = "0123456789abcdef";
  for (uint32_t index = 0; index < key.size; ++index)
    if (hex[index * 2] != digits[key.bytes[index] >> 4] || hex[index * 2 + 1] != digits[key.bytes[index] & 15]) return false;
  return true;
}

int main()
{
  bool ok = true;
  static_assert(!std::is_copy_constructible_v<ClusterPairRoot>);
  static_assert(!std::is_copy_assignable_v<ClusterPairRoot>);
  static_assert(std::is_move_constructible_v<ClusterPairRoot>);
  static_assert(std::is_move_assignable_v<ClusterPairRoot>);
  static_assert(!std::is_copy_constructible_v<ClusterPairDerivedKey>);
  static_assert(!std::is_copy_assignable_v<ClusterPairDerivedKey>);
  static_assert(std::is_move_constructible_v<ClusterPairDerivedKey>);
  static_assert(std::is_move_assignable_v<ClusterPairDerivedKey>);
  ClusterPairRoot root = testRoot();
  const auto context = serviceContext();
  ClusterPairDerivedKey first = {}, second = {};
  ok &= expect(clusterPairDeriveKey(root, context, first) && clusterPairDeriveKey(root, context, second) &&
                   first.bytes == second.bytes && first.size == 16, "independent_service_derivation");
  // Fixed vectors independently generated with Python hmac/hashlib RFC 5869
  // extract+expand over the documented big-endian field encoding, root 01..20.
  ok &= expect(matchesHex(first, "57dc20c07b7280b78e5b1e0067d8ea38"), "service_golden_vector");

  ClusterPairRoot moveSource = testRoot();
  ClusterPairRoot movedRoot(std::move(moveSource));
  ClusterPairDerivedKey movedRootKey = {};
  ok &= expect(moveSource.pairUUID == 0 && moveSource.firstClusterUUID == 0 && moveSource.secondClusterUUID == 0 &&
                   moveSource.rootGeneration == 0 && moveSource.root == std::array<uint8_t, 32>{} &&
                   clusterPairDeriveKey(movedRoot, context, movedRootKey) && movedRootKey.bytes == first.bytes,
               "root_move_cleans_source_and_preserves_material");
  ClusterPairRoot assignedRoot = {};
  assignedRoot = std::move(movedRoot);
  ok &= expect(movedRoot.pairUUID == 0 && movedRoot.rootGeneration == 0 && movedRoot.root == std::array<uint8_t, 32>{} &&
                   clusterPairDeriveKey(assignedRoot, context, movedRootKey) && movedRootKey.bytes == first.bytes,
               "root_move_assignment_cleans_source_and_preserves_material");
  assignedRoot = std::move(assignedRoot);
  ok &= expect(clusterPairDeriveKey(assignedRoot, context, movedRootKey) && movedRootKey.bytes == first.bytes,
               "root_self_move_preserves_material");

  ClusterPairDerivedKey moveSourceKey = {};
  ClusterPairDerivedKey assignedKey = {};
  ok &= expect(clusterPairDeriveKey(root, context, moveSourceKey), "derived_key_move_fixture");
  ClusterPairDerivedKey movedKey(std::move(moveSourceKey));
  ok &= expect(moveSourceKey.size == 0 && moveSourceKey.bytes == std::array<uint8_t, 32>{} && movedKey.bytes == first.bytes,
               "derived_key_move_cleans_source");
  assignedKey = std::move(movedKey);
  ok &= expect(movedKey.size == 0 && movedKey.bytes == std::array<uint8_t, 32>{} && assignedKey.bytes == first.bytes,
               "derived_key_second_move_cleans_source");
  assignedKey = std::move(assignedKey);
  ok &= expect(assignedKey.size == first.size && assignedKey.bytes == first.bytes, "derived_key_self_move_preserves_material");

  auto reversed = testRoot();
  std::swap(reversed.firstClusterUUID, reversed.secondClusterUUID);
  ok &= expect(clusterPairDeriveKey(reversed, context, second) && second.bytes == first.bytes,
               "opposite_local_endpoint_order_matches");
  auto different = [&](const auto& changedRoot, const auto& changedContext, const char *name) {
    ClusterPairDerivedKey key = {};
    ok &= expect(clusterPairDeriveKey(changedRoot, changedContext, key) && key.bytes != first.bytes, name);
  };
  auto changedRoot = testRoot();
  changedRoot.pairUUID++;
  different(changedRoot, context, "pair_identity_separates_key");
  changedRoot = testRoot();
  changedRoot.rootGeneration++;
  different(changedRoot, context, "root_generation_separates_key");
  changedRoot = testRoot();
  changedRoot.root[0] ^= 1;
  different(changedRoot, context, "root_material_separates_key");
  changedRoot = testRoot();
  changedRoot.secondClusterUUID++;
  auto changed = context;
  changed.receiverClusterUUID = changedRoot.secondClusterUUID;
  different(changedRoot, changed, "cluster_identity_separates_key");
  changed = context;
  changed.keyEpoch++;
  different(root, changed, "key_epoch_separates_key");
  changed = context;
  changed.logicalWorkloadUUID++;
  different(root, changed, "workload_separates_key");
  changed = context;
  changed.logicalServiceUUID++;
  different(root, changed, "service_separates_key");
  changed = context;
  changed.slots.insert(4);
  different(root, changed, "logical_range_separates_key");
  changed = context;
  changed.purpose = ClusterPairKeyPurpose::switchboardAdmissionControl;
  different(root, changed, "admission_purpose_separates_key");
  changed = context;
  std::swap(changed.senderClusterUUID, changed.receiverClusterUUID);
  different(root, changed, "traffic_direction_separates_key");

  // The channel is an explicitly length-delimited byte string, not C text.
  const uint8_t binary[] = {'a', 0, 'b'};
  String channel = {};
  channel.assign(binary, sizeof(binary));
  changed = context;
  changed.channelIdentity = channel;
  ClusterPairDerivedKey binaryKey = {}, truncatedKey = {};
  ok &= expect(changed.channelIdentity.size() == 3 && clusterPairDeriveKey(root, changed, binaryKey),
               "binary_channel_fixture_is_complete");
  changed.channelIdentity = "a"_ctv;
  ok &= expect(clusterPairDeriveKey(root, changed, truncatedKey) && binaryKey.bytes != truncatedKey.bytes,
               "embedded_nul_is_not_a_context_terminator");
  changed.channelIdentity = "ab"_ctv;
  ok &= expect(clusterPairDeriveKey(root, changed, truncatedKey) && binaryKey.bytes != truncatedKey.bytes,
               "channel_length_and_contents_are_bound");
  String encoded = "read-only output view"_ctv;
  ok &= expect(clusterPairCanonicalKeyContext(root, context, encoded) && !encoded.empty() && encoded.ownsMemory(),
               "canonical_output_detaches_read_only_storage");

  auto invalid = [&](const auto& badRoot, const auto& badContext, const char *name) {
    ClusterPairDerivedKey key = {};
    key.bytes.fill(0xaa);
    key.size = 32;
    String output = "prior context"_ctv;
    ok &= expect(!clusterPairDeriveKey(badRoot, badContext, key) && key.size == 0 &&
                     key.bytes == std::array<uint8_t, 32>{} &&
                     !clusterPairCanonicalKeyContext(badRoot, badContext, output) && output.empty(), name);
  };
  changedRoot = testRoot();
  changedRoot.pairUUID = 0;
  invalid(changedRoot, context, "zero_pair_rejected_and_outputs_cleared");
  changedRoot = testRoot();
  changedRoot.firstClusterUUID = changedRoot.secondClusterUUID;
  invalid(changedRoot, context, "same_cluster_rejected");
  changedRoot = testRoot();
  changedRoot.rootGeneration = 0;
  invalid(changedRoot, context, "zero_root_generation_rejected");
  changedRoot = testRoot();
  changedRoot.root.fill(0);
  invalid(changedRoot, context, "missing_root_rejected");
  changed = context;
  changed.keyEpoch = 0;
  invalid(root, changed, "zero_key_epoch_rejected");
  changed = context;
  changed.logicalWorkloadUUID = 0;
  invalid(root, changed, "missing_workload_rejected");
  changed = context;
  changed.logicalServiceUUID = 0;
  invalid(root, changed, "missing_service_rejected");
  changed = context;
  changed.slots = {};
  invalid(root, changed, "empty_service_range_rejected");
  changed = context;
  changed.senderClusterUUID = 0x999;
  invalid(root, changed, "foreign_sender_rejected");
  changed = context;
  changed.receiverClusterUUID = 0x999;
  invalid(root, changed, "foreign_receiver_rejected");
  changed = context;
  changed.purpose = static_cast<ClusterPairKeyPurpose>(99);
  invalid(root, changed, "unknown_purpose_rejected");
  changed = context;
  changed.scope = static_cast<ClusterPairKeyScope>(99);
  invalid(root, changed, "unknown_scope_rejected");

  ClusterPairKeyContext control = {};
  control.scope = ClusterPairKeyScope::pairControl;
  control.purpose = ClusterPairKeyPurpose::pairControl;
  control.keyEpoch = 9;
  control.senderClusterUUID = 0x200;
  control.receiverClusterUUID = 0x300;
  control.channelIdentity = "enrollment-control"_ctv;
  ok &= expect(clusterPairDeriveKey(root, control, second) &&
                   matchesHex(second, "56ea765a4cde830e72bf83609d21c074c34ae3bb80d2187395760f0c9aab5e86"),
               "pair_control_golden_vector_without_fake_workload");
  changed = control;
  changed.logicalWorkloadUUID = 1;
  invalid(root, changed, "control_rejects_service_scope_confusion");
  changed = control;
  changed.senderNodeUUID = 1;
  invalid(root, changed, "cluster_control_does_not_claim_node_identity");

  auto node = control;
  node.scope = ClusterPairKeyScope::nodeRoleCredential;
  node.purpose = ClusterPairKeyPurpose::switchboardAdmissionControl;
  node.senderNodeUUID = 0x701;
  node.receiverNodeUUID = 0x702;
  node.senderRole = 1;
  node.receiverRole = 2;
  node.channelIdentity = "node-session"_ctv;
  ClusterPairDerivedKey nodeKey = {};
  ok &= expect(clusterPairDeriveKey(root, node, nodeKey) &&
                   matchesHex(nodeKey, "c103d09826242c8f68ebb5fc8a38208d092298d2588ab6e9dfee7666090695ae"),
               "node_role_golden_vector");
  changed = node;
  changed.senderRole++;
  ok &= expect(clusterPairDeriveKey(root, changed, second) && second.bytes != nodeKey.bytes,
               "sender_role_separates_key");
  changed = node;
  changed.receiverNodeUUID++;
  ok &= expect(clusterPairDeriveKey(root, changed, second) && second.bytes != nodeKey.bytes,
               "receiver_node_separates_key");
  changed = node;
  changed.senderNodeUUID = 0;
  invalid(root, changed, "node_scope_requires_node_identity");

  ClusterPairRoot generated = {};
  generated.pairUUID = 0x100;
  generated.firstClusterUUID = 0x200;
  generated.secondClusterUUID = 0x300;
  generated.rootGeneration = 7;
  ok &= expect(clusterPairGenerateRoot(generated) && clusterPairRootValid(generated) && generated.root != root.root,
               "private_random_root_generation");
  ClusterPairDerivedKey generatedBefore = {}, generatedAfter = {};
  const bool generatedKey = clusterPairDeriveKey(generated, context, generatedBefore);
  ok &= expect(!clusterPairGenerateRoot(generated) && generatedKey && clusterPairDeriveKey(generated, context, generatedAfter) &&
                   generatedAfter.bytes == generatedBefore.bytes && generated.pairUUID == 0x100 && generated.rootGeneration == 7,
               "same_identity_regeneration_rejected_without_root_replacement");
  ClusterPairRoot invalidGeneration = {};
  invalidGeneration.firstClusterUUID = 0x200;
  invalidGeneration.secondClusterUUID = 0x300;
  invalidGeneration.rootGeneration = 7;
  ok &= expect(!clusterPairGenerateRoot(invalidGeneration) && invalidGeneration.root == std::array<uint8_t, 32>{},
               "invalid_empty_generation_leaves_root_empty");
  return ok ? 0 : 1;
}
