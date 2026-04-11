#include <networking/includes.h>
#include <services/debug.h>

#include <ebpf/common/structs.h>

#include <switchboard/common/checksum.h>
#include <switchboard/common/local_container_subnet.h>
#include <switchboard/whitehole.route.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <array>
#include <vector>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

class TestSuite
{
public:

   int failed = 0;

   void expect(bool condition, const char *name)
   {
      if (condition)
      {
         std::fprintf(stderr, "PASS: %s\n", name);
      }
      else
      {
         std::fprintf(stderr, "FAIL: %s\n", name);
         failed += 1;
      }
   }
};

static uint16_t foldChecksum(uint32_t sum)
{
   while (sum >> 16)
   {
      sum = (sum & 0xffffu) + (sum >> 16);
   }

   uint16_t checksum = static_cast<uint16_t>(~sum & 0xffffu);
   return checksum == 0 ? 0xffffu : checksum;
}

static uint16_t checksumBytes(const void *data, size_t size)
{
   const uint8_t *bytes = static_cast<const uint8_t *>(data);
   uint32_t sum = 0;

   for (size_t index = 0; index + 1 < size; index += 2)
   {
      sum += static_cast<uint32_t>(bytes[index] << 8 | bytes[index + 1]);
   }

   if (size & 1U)
   {
      sum += static_cast<uint32_t>(bytes[size - 1] << 8);
   }

   return foldChecksum(sum);
}

static uint16_t checksumIPv6Transport(const uint8_t src[16],
   const uint8_t dst[16],
   uint8_t nextHeader,
   const void *transport,
   size_t transportSize)
{
   uint32_t sum = 0;

   auto accumulate = [&] (const void *data, size_t size) -> void {
      const uint8_t *bytes = static_cast<const uint8_t *>(data);
      for (size_t index = 0; index + 1 < size; index += 2)
      {
         sum += static_cast<uint32_t>(bytes[index] << 8 | bytes[index + 1]);
      }

      if (size & 1U)
      {
         sum += static_cast<uint32_t>(bytes[size - 1] << 8);
      }
   };

   accumulate(src, 16);
   accumulate(dst, 16);

   uint8_t lengthBytes[4] = {
      static_cast<uint8_t>((transportSize >> 24) & 0xffU),
      static_cast<uint8_t>((transportSize >> 16) & 0xffU),
      static_cast<uint8_t>((transportSize >> 8) & 0xffU),
      static_cast<uint8_t>(transportSize & 0xffU)
   };
   accumulate(lengthBytes, sizeof(lengthBytes));

   uint8_t nextHeaderBytes[4] = {0, 0, 0, nextHeader};
   accumulate(nextHeaderBytes, sizeof(nextHeaderBytes));
   accumulate(transport, transportSize);

   return foldChecksum(sum);
}

static uint32_t checksumBytesChunkedSum(const void *data, size_t size, size_t chunkBytes)
{
   const uint8_t *bytes = static_cast<const uint8_t *>(data);
   uint32_t sum = 0;
   size_t offset = 0;
   size_t remaining = size;

   auto accumulate = [&] (const void *chunkData, size_t chunkSize) -> void {
      const uint8_t *chunkBytesData = static_cast<const uint8_t *>(chunkData);
      for (size_t index = 0; index + 1 < chunkSize; index += 2)
      {
         sum += static_cast<uint32_t>(chunkBytesData[index] << 8 | chunkBytesData[index + 1]);
      }

      if (chunkSize & 1U)
      {
         sum += static_cast<uint32_t>(chunkBytesData[chunkSize - 1] << 8);
      }
   };

   while (remaining >= chunkBytes)
   {
      accumulate(bytes + offset, chunkBytes);
      offset += chunkBytes;
      remaining -= chunkBytes;
   }

   if (remaining & 64U)
   {
      accumulate(bytes + offset, 64);
      offset += 64;
      remaining -= 64;
   }

   if (remaining & 32U)
   {
      accumulate(bytes + offset, 32);
      offset += 32;
      remaining -= 32;
   }

   if (remaining & 16U)
   {
      accumulate(bytes + offset, 16);
      offset += 16;
      remaining -= 16;
   }

   if (remaining & 8U)
   {
      accumulate(bytes + offset, 8);
      offset += 8;
      remaining -= 8;
   }

   if (remaining & 4U)
   {
      accumulate(bytes + offset, 4);
      offset += 4;
      remaining -= 4;
   }

   if (remaining > 0)
   {
      uint8_t tailWord[4] = {};
      std::memcpy(tailWord, bytes + offset, remaining);
      accumulate(tailWord, sizeof(tailWord));
   }

   return sum;
}

static uint16_t checksumBytesChunked(const void *data, size_t size, size_t chunkBytes)
{
   return foldChecksum(checksumBytesChunkedSum(data, size, chunkBytes));
}

static uint16_t checksumIPv6TransportChunked(const uint8_t src[16],
   const uint8_t dst[16],
   uint8_t nextHeader,
   const void *transport,
   size_t transportSize,
   size_t checksumByteOffset,
   size_t chunkBytes)
{
   const uint8_t *segmentBytes = static_cast<const uint8_t *>(transport);
   uint32_t sum = 0;
   uint8_t lengthBytes[4] = {
      static_cast<uint8_t>((transportSize >> 24) & 0xffU),
      static_cast<uint8_t>((transportSize >> 16) & 0xffU),
      static_cast<uint8_t>((transportSize >> 8) & 0xffU),
      static_cast<uint8_t>(transportSize & 0xffU)
   };
   uint8_t nextHeaderBytes[4] = {0, 0, 0, nextHeader};
   size_t suffixOffset = checksumByteOffset + sizeof(uint16_t);

   auto accumulate = [&] (const void *data, size_t size) -> void {
      const uint8_t *bytes = static_cast<const uint8_t *>(data);
      for (size_t index = 0; index + 1 < size; index += 2)
      {
         sum += static_cast<uint32_t>(bytes[index] << 8 | bytes[index + 1]);
      }

      if (size & 1U)
      {
         sum += static_cast<uint32_t>(bytes[size - 1] << 8);
      }
   };

   accumulate(src, 16);
   accumulate(dst, 16);
   accumulate(lengthBytes, sizeof(lengthBytes));
   accumulate(nextHeaderBytes, sizeof(nextHeaderBytes));

   if (checksumByteOffset > 0)
   {
      sum += checksumBytesChunkedSum(segmentBytes, checksumByteOffset, chunkBytes);
   }

   if (transportSize > suffixOffset)
   {
      sum += checksumBytesChunkedSum(segmentBytes + suffixOffset, transportSize - suffixOffset, chunkBytes);
   }

   return foldChecksum(sum);
}

static uint16_t replaceChecksumIPv6AddressIncremental(uint16_t checksum, const uint8_t oldValue[16], const uint8_t newValue[16])
{
   uint16_t updated = checksum;
   for (size_t offset = 0; offset < 16; offset += sizeof(uint32_t))
   {
      updated = replace_l4_checksum_portable(updated, oldValue + offset, newValue + offset, sizeof(uint32_t));
   }

   return updated;
}

int main(void)
{
   TestSuite suite = {};

   Whitehole whitehole = {};
   whitehole.transport = ExternalAddressTransport::quic;
   whitehole.family = ExternalAddressFamily::ipv6;
   whitehole.source = ExternalAddressSource::distributableSubnet;
   whitehole.hasAddress = true;
   whitehole.address = IPAddress("2001:db8::44", true);
   whitehole.sourcePort = 5353;
   whitehole.bindingNonce = 0x12345678u;

   local_container_subnet6 subnet = {};
   subnet.dpfx = 0x7A;
   subnet.mpfx[0] = 0x01;
   subnet.mpfx[1] = 0x02;
   subnet.mpfx[2] = 0x03;

   uint32_t containerID = 0x01020304u;
   portal_definition key = {};
   switchboard_whitehole_binding value = {};
   suite.expect(switchboardBuildWhiteholeBinding(whitehole, containerID, subnet, key, value), "switchboard_whitehole_binding_builds");
   suite.expect(key.port == htons(whitehole.sourcePort), "switchboard_whitehole_binding_stores_network_order_port");
   suite.expect(ntohs(key.port) == whitehole.sourcePort, "switchboard_whitehole_binding_roundtrips_port");
   suite.expect(key.proto == IPPROTO_UDP, "switchboard_whitehole_binding_maps_quic_to_udp");
   suite.expect(std::memcmp(key.addr6, whitehole.address.v6, sizeof(key.addr6)) == 0, "switchboard_whitehole_binding_preserves_address");
   suite.expect(value.nonce == whitehole.bindingNonce, "switchboard_whitehole_binding_preserves_nonce");
   suite.expect(value.container.hasID, "switchboard_whitehole_binding_sets_container_has_id");
   suite.expect(value.container.value[0] == subnet.dpfx, "switchboard_whitehole_binding_sets_datacenter_prefix");
   suite.expect(value.container.value[1] == 0x04 && value.container.value[2] == 0x03 && value.container.value[3] == 0x02 && value.container.value[4] == 0x01, "switchboard_whitehole_binding_sets_container_suffix");

   String pinPath = {};
   switchboardWhiteholeReplyFlowPinPath(pinPath, 17);
   suite.expect(pinPath == "/sys/fs/bpf/prodigy_whitehole_reply_flows_17"_ctv, "switchboard_whitehole_pin_path_uses_interface_index");
   suite.expect((switchboardPacketRewriteStoreFlags() & BPF_F_RECOMPUTE_CSUM) != 0, "switchboard_packet_rewrite_store_flags_recompute_checksum");
   suite.expect((switchboardPacketRewriteStoreFlags() & BPF_F_INVALIDATE_HASH) != 0, "switchboard_packet_rewrite_store_flags_invalidate_hash");
   suite.expect((switchboardPacketRewriteManualChecksumStoreFlags() & BPF_F_RECOMPUTE_CSUM) == 0, "switchboard_packet_rewrite_manual_checksum_store_flags_skip_incremental_checksum");
   suite.expect((switchboardPacketRewriteManualChecksumStoreFlags() & BPF_F_INVALIDATE_HASH) != 0, "switchboard_packet_rewrite_manual_checksum_store_flags_invalidate_hash");
   suite.expect((switchboardAdjustRoomPreserveOffloadFlags() & BPF_F_ADJ_ROOM_NO_CSUM_RESET) != 0, "switchboard_adjust_room_preserves_checksum_offload");
   suite.expect((switchboardAdjustRoomPreserveOffloadFlags() & BPF_F_ADJ_ROOM_FIXED_GSO) != 0, "switchboard_adjust_room_preserves_gso");
   suite.expect((switchboardOverlayEncapAdjustRoomFlagsIPv6() & BPF_F_ADJ_ROOM_ENCAP_L3_IPV6) != 0, "switchboard_overlay_encap_ipv6_sets_l3_flag");
   suite.expect((switchboardOverlayEncapAdjustRoomFlagsIPv6() & BPF_F_ADJ_ROOM_NO_CSUM_RESET) != 0, "switchboard_overlay_encap_ipv6_preserves_checksum_offload");
   suite.expect((switchboardOverlayEncapAdjustRoomFlagsIPv6() & BPF_F_ADJ_ROOM_FIXED_GSO) != 0, "switchboard_overlay_encap_ipv6_preserves_gso");
   suite.expect((switchboardOverlayEncapAdjustRoomFlagsIPv4() & BPF_F_ADJ_ROOM_ENCAP_L3_IPV4) != 0, "switchboard_overlay_encap_ipv4_sets_l3_flag");
   suite.expect((switchboardOverlayEncapAdjustRoomFlagsIPv4() & BPF_F_ADJ_ROOM_NO_CSUM_RESET) != 0, "switchboard_overlay_encap_ipv4_preserves_checksum_offload");
   suite.expect((switchboardOverlayEncapAdjustRoomFlagsIPv4() & BPF_F_ADJ_ROOM_FIXED_GSO) != 0, "switchboard_overlay_encap_ipv4_preserves_gso");
   suite.expect(switchboardManualChecksumMaxBytes() == 2048u, "switchboard_manual_checksum_max_bytes_matches_live_quic_budget");
   suite.expect(switchboardManualChecksumSKBChunkBytes() == 128u, "switchboard_manual_checksum_skb_chunk_bytes_is_verifier_safe");
   suite.expect((switchboardManualChecksumSKBChunkBytes() & 3u) == 0u, "switchboard_manual_checksum_skb_chunk_bytes_is_word_aligned");
   suite.expect(switchboardManualChecksumSKBChunkBytes() <= 128u, "switchboard_manual_checksum_skb_chunk_bytes_leaves_stack_headroom");

   {
      uint8_t src[16] = {0xfd, 0xf8, 0xd9, 0x4c, 0x7c, 0x33, 0xe2, 0x6e, 0xca, 0x4b, 0xf5, 0x01, 0x8e, 0xdc, 0x41, 0x3a};
      uint8_t dst[16] = {0xfd, 0xf8, 0xd9, 0x4c, 0x7c, 0x33, 0xe2, 0x6e, 0xca, 0x4b, 0xf5, 0x01, 0xda, 0x7b, 0xae, 0x2c};
      std::vector<uint8_t> payload(2043u - sizeof(struct udphdr));

      for (size_t index = 0; index < payload.size(); index += 1)
      {
         payload[index] = static_cast<uint8_t>((index * 29u + 17u) & 0xffu);
      }

      struct udphdr udp = {};
      udp.source = htons(443);
      udp.dest = htons(35644);
      udp.len = htons(static_cast<uint16_t>(sizeof(struct udphdr) + payload.size()));

      std::vector<uint8_t> segment(sizeof(struct udphdr) + payload.size());
      std::memcpy(segment.data(), &udp, sizeof(udp));
      std::memcpy(segment.data() + sizeof(udp), payload.data(), payload.size());

      uint16_t expectedChecksum = compute_ipv6_transport_checksum_portable(
         src,
         dst,
         IPPROTO_UDP,
         segment.data(),
         segment.size(),
         __builtin_offsetof(struct udphdr, check));
      uint16_t emulatedSKBChunkedChecksum = htons(checksumIPv6TransportChunked(
         src,
         dst,
         IPPROTO_UDP,
         segment.data(),
         segment.size(),
         __builtin_offsetof(struct udphdr, check),
         switchboardManualChecksumSKBChunkBytes()));

      suite.expect(segment.size() == 2043u, "switchboard_wormhole_skb_chunked_checksum_application_reply_segment_size_matches_capture");
      suite.expect(checksumBytesChunked(segment.data(), segment.size(), switchboardManualChecksumSKBChunkBytes()) == checksumBytes(segment.data(), segment.size()), "switchboard_wormhole_skb_chunked_checksum_matches_full_checksum_for_application_reply_size");
      suite.expect(emulatedSKBChunkedChecksum == expectedChecksum, "switchboard_wormhole_skb_chunked_transport_checksum_matches_application_reply_capture");
   }

   {
      uint8_t src[16] = {0xfd, 0xf8, 0xd9, 0x4c, 0x7c, 0x33, 0xe2, 0x6e, 0xca, 0x4b, 0xf5, 0x01, 0xf2, 0x66, 0xe5, 0xd9};
      uint8_t dst[16] = {0xfd, 0xf8, 0xd9, 0x4c, 0x7c, 0x33, 0xe2, 0x6e, 0xca, 0x4b, 0xf5, 0x01, 0x6e, 0x1f, 0xdd, 0x55};
      std::vector<uint8_t> payload(2047u - sizeof(struct udphdr));

      for (size_t index = 0; index < payload.size(); index += 1)
      {
         payload[index] = static_cast<uint8_t>((index * 37u + 11u) & 0xffu);
      }

      struct udphdr udp = {};
      udp.source = htons(443);
      udp.dest = htons(34267);
      udp.len = htons(static_cast<uint16_t>(sizeof(struct udphdr) + payload.size()));

      std::vector<uint8_t> segment(sizeof(struct udphdr) + payload.size());
      std::memcpy(segment.data(), &udp, sizeof(udp));
      std::memcpy(segment.data() + sizeof(udp), payload.data(), payload.size());

      uint16_t expectedChecksum = compute_ipv6_transport_checksum_portable(
         src,
         dst,
         IPPROTO_UDP,
         segment.data(),
         segment.size(),
         __builtin_offsetof(struct udphdr, check));
      uint16_t emulatedSKBChunkedChecksum = htons(checksumIPv6TransportChunked(
         src,
         dst,
         IPPROTO_UDP,
         segment.data(),
         segment.size(),
         __builtin_offsetof(struct udphdr, check),
         switchboardManualChecksumSKBChunkBytes()));

      suite.expect(segment.size() == 2047u, "switchboard_wormhole_skb_chunked_checksum_current_live_segment_size_matches_capture");
      suite.expect(checksumBytesChunked(segment.data(), segment.size(), switchboardManualChecksumSKBChunkBytes()) == checksumBytes(segment.data(), segment.size()), "switchboard_wormhole_skb_chunked_checksum_matches_full_checksum_for_current_live_size");
      suite.expect(emulatedSKBChunkedChecksum == expectedChecksum, "switchboard_wormhole_skb_chunked_transport_checksum_matches_current_live_capture");
   }

   {
      uint8_t wormholeSource[16] = {};
      std::memcpy(wormholeSource, container_network_subnet6.value, sizeof(container_network_subnet6.value));
      wormholeSource[11] = 0x7a;
      wormholeSource[12] = 0x01;
      wormholeSource[13] = 0x02;
      wormholeSource[14] = 0x03;
      wormholeSource[15] = 0x11;

      uint8_t internalDestination[16] = {};
      std::memcpy(internalDestination, container_network_subnet6.value, sizeof(container_network_subnet6.value));
      internalDestination[11] = 0x7a;
      internalDestination[12] = 0x01;
      internalDestination[13] = 0x02;
      internalDestination[14] = 0x03;
      internalDestination[15] = 0x22;

      uint8_t remoteMachineDestination[16] = {};
      std::memcpy(remoteMachineDestination, container_network_subnet6.value, sizeof(container_network_subnet6.value));
      remoteMachineDestination[11] = 0x7a;
      remoteMachineDestination[12] = 0x09;
      remoteMachineDestination[13] = 0x08;
      remoteMachineDestination[14] = 0x07;
      remoteMachineDestination[15] = 0x33;

      local_container_subnet6 localSubnet = {};
      localSubnet.dpfx = 0x7a;
      localSubnet.mpfx[0] = 0x01;
      localSubnet.mpfx[1] = 0x02;
      localSubnet.mpfx[2] = 0x03;

      uint8_t externalDestination[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x77};
      uint8_t externalSource[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x44};

      suite.expect(switchboardWormholeSourceRewriteEligibleIPv6(wormholeSource, internalDestination), "switchboard_wormhole_rewrite_allows_internal_destination");
      suite.expect(switchboardContainerIPv6TargetsLocalMachine(internalDestination, &localSubnet), "switchboard_wormhole_rewrite_internal_destination_is_same_machine");
      suite.expect(switchboardContainerIPv6TargetsRemoteMachine(remoteMachineDestination, &localSubnet), "switchboard_wormhole_rewrite_remote_destination_is_other_machine");
      suite.expect(switchboardWormholeSourceRewriteEligibleIPv6(wormholeSource, remoteMachineDestination), "switchboard_wormhole_rewrite_allows_remote_machine_container_destination");
      suite.expect(switchboardWormholeSourceRewriteEligibleIPv6(wormholeSource, externalDestination), "switchboard_wormhole_rewrite_allows_external_destination");
      suite.expect(switchboardWormholeSourceRewriteEligibleIPv6(externalSource, internalDestination) == false, "switchboard_wormhole_rewrite_rejects_non_container_source");
   }

   {
      uint8_t src[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0x01, 0x00, 0, 0, 0, 0x0b};
      uint8_t dst[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x84, 0x43};
      uint8_t rewrittenSrc[16] = {0xfd, 0xf8, 0xd9, 0x4c, 0x7c, 0x33, 0xe2, 0x6e, 0xca, 0x4b, 0xf5, 0x01, 0xb1, 0x31, 0xc7, 0xcb};
      uint8_t payload[8] = {'w', 'o', 'r', 'm', 'h', 'o', 'l', 'e'};

      struct udphdr udp = {};
      udp.source = htons(8443);
      udp.dest = htons(35076);
      udp.len = htons(sizeof(udp) + sizeof(payload));

      uint8_t udpSegment[sizeof(udp) + sizeof(payload)] = {};
      memcpy(udpSegment, &udp, sizeof(udp));
      memcpy(udpSegment + sizeof(udp), payload, sizeof(payload));
      reinterpret_cast<struct udphdr *>(udpSegment)->check = htons(checksumIPv6Transport(src, dst, IPPROTO_UDP, udpSegment, sizeof(udpSegment)));

      struct udphdr updatedUDP = *reinterpret_cast<struct udphdr *>(udpSegment);
      uint16_t originalUDPChecksum = updatedUDP.check;
      uint16_t rewrittenUDPPort = htons(443);
      updatedUDP.check = replace_l4_checksum_word16(updatedUDP.check, updatedUDP.source, rewrittenUDPPort);
      updatedUDP.check = replaceChecksumIPv6AddressIncremental(updatedUDP.check, src, rewrittenSrc);
      updatedUDP.source = rewrittenUDPPort;

      uint8_t expectedUDPSegment[sizeof(updatedUDP) + sizeof(payload)] = {};
      memcpy(expectedUDPSegment, &updatedUDP, sizeof(updatedUDP));
      memcpy(expectedUDPSegment + sizeof(updatedUDP), payload, sizeof(payload));
      reinterpret_cast<struct udphdr *>(expectedUDPSegment)->check = 0;
      uint16_t expectedUDPChecksum = htons(checksumIPv6Transport(rewrittenSrc, dst, IPPROTO_UDP, expectedUDPSegment, sizeof(expectedUDPSegment)));

      suite.expect(originalUDPChecksum != expectedUDPChecksum, "switchboard_wormhole_udp_source_rewrite_changes_checksum");
      suite.expect(updatedUDP.check == expectedUDPChecksum, "switchboard_wormhole_udp_source_rewrite_matches_full_checksum");
   }

   {
      uint8_t src[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0x01, 0x00, 0, 0, 0, 0x0b};
      uint8_t dst[16] = {0xfd, 0xf8, 0xd9, 0x4c, 0x7c, 0x33, 0xe2, 0x6e, 0xca, 0x4b, 0xf5, 0x01, 0x6e, 0x1f, 0xdd, 0x55};
      uint8_t rewrittenSrc[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xc};

      constexpr size_t payloadSize = 2037;
      std::vector<uint8_t> payload(payloadSize);
      for (size_t index = 0; index < payload.size(); index += 1)
      {
         payload[index] = static_cast<uint8_t>((index * 37u + 11u) & 0xffu);
      }

      struct udphdr udp = {};
      udp.source = htons(8443);
      udp.dest = htons(34267);
      udp.len = htons(sizeof(udp) + payload.size());

      std::vector<uint8_t> udpSegment(sizeof(udp) + payload.size());
      std::memcpy(udpSegment.data(), &udp, sizeof(udp));
      std::memcpy(udpSegment.data() + sizeof(udp), payload.data(), payload.size());
      reinterpret_cast<struct udphdr *>(udpSegment.data())->check = htons(checksumIPv6Transport(src, dst, IPPROTO_UDP, udpSegment.data(), udpSegment.size()));

      struct udphdr updatedUDP = *reinterpret_cast<struct udphdr *>(udpSegment.data());
      uint16_t originalUDPChecksum = updatedUDP.check;
      uint16_t rewrittenUDPPort = htons(443);
      updatedUDP.check = replace_l4_checksum_word16(updatedUDP.check, updatedUDP.source, rewrittenUDPPort);
      updatedUDP.check = replaceChecksumIPv6AddressIncremental(updatedUDP.check, src, rewrittenSrc);
      updatedUDP.source = rewrittenUDPPort;

      std::vector<uint8_t> expectedUDPSegment(sizeof(updatedUDP) + payload.size());
      std::memcpy(expectedUDPSegment.data(), &updatedUDP, sizeof(updatedUDP));
      std::memcpy(expectedUDPSegment.data() + sizeof(updatedUDP), payload.data(), payload.size());
      reinterpret_cast<struct udphdr *>(expectedUDPSegment.data())->check = 0;
      uint16_t expectedUDPChecksum = htons(checksumIPv6Transport(rewrittenSrc, dst, IPPROTO_UDP, expectedUDPSegment.data(), expectedUDPSegment.size()));

      suite.expect(originalUDPChecksum != expectedUDPChecksum, "switchboard_wormhole_udp_large_source_rewrite_changes_checksum");
      suite.expect(updatedUDP.check == expectedUDPChecksum, "switchboard_wormhole_udp_large_source_rewrite_matches_full_checksum");
   }

   {
      uint8_t src[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x44};
      uint8_t dst[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0x01, 0x00, 0, 0, 0, 0x0b};
      uint8_t rewrittenDst[16] = {0xfd, 0xf8, 0xd9, 0x4c, 0x7c, 0x33, 0xe2, 0x6e, 0xca, 0x4b, 0xf5, 0x01, 0x01, 0x1f, 0x63, 0x5b};
      uint8_t payload[8] = {'i', 'n', 'g', 'r', 'e', 's', 's', '!'};

      struct udphdr udp = {};
      udp.source = htons(51515);
      udp.dest = htons(443);
      udp.len = htons(sizeof(udp) + sizeof(payload));

      uint8_t udpSegment[sizeof(udp) + sizeof(payload)] = {};
      memcpy(udpSegment, &udp, sizeof(udp));
      memcpy(udpSegment + sizeof(udp), payload, sizeof(payload));
      reinterpret_cast<struct udphdr *>(udpSegment)->check = htons(checksumIPv6Transport(src, dst, IPPROTO_UDP, udpSegment, sizeof(udpSegment)));

      struct udphdr updatedUDP = *reinterpret_cast<struct udphdr *>(udpSegment);
      uint16_t originalUDPChecksum = updatedUDP.check;
      updatedUDP.check = replaceChecksumIPv6AddressIncremental(updatedUDP.check, dst, rewrittenDst);
      updatedUDP.check = replace_l4_checksum_word16(updatedUDP.check, updatedUDP.dest, htons(8443));
      updatedUDP.dest = htons(8443);

      uint8_t expectedUDPSegment[sizeof(updatedUDP) + sizeof(payload)] = {};
      memcpy(expectedUDPSegment, &updatedUDP, sizeof(updatedUDP));
      memcpy(expectedUDPSegment + sizeof(updatedUDP), payload, sizeof(payload));
      reinterpret_cast<struct udphdr *>(expectedUDPSegment)->check = 0;
      uint16_t expectedUDPChecksum = htons(checksumIPv6Transport(src, rewrittenDst, IPPROTO_UDP, expectedUDPSegment, sizeof(expectedUDPSegment)));

      suite.expect(originalUDPChecksum != expectedUDPChecksum, "switchboard_wormhole_udp_ipv6_target_rewrite_changes_checksum");
      suite.expect(updatedUDP.check == expectedUDPChecksum, "switchboard_wormhole_udp_ipv6_target_rewrite_matches_full_checksum");
   }

   {
      uint8_t src[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x77};
      uint8_t dst[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x19, 0x84};

      struct tcphdr tcp = {};
      tcp.source = htons(8443);
      tcp.dest = htons(50000);
      tcp.seq = htonl(0x11223344);
      tcp.ack_seq = htonl(0x55667788);
      tcp.doff = sizeof(tcp) / 4;
      tcp.syn = 1;
      tcp.ack = 1;
      tcp.window = htons(4096);

      uint8_t tcpSegment[sizeof(tcp)] = {};
      memcpy(tcpSegment, &tcp, sizeof(tcp));
      reinterpret_cast<struct tcphdr *>(tcpSegment)->check = htons(checksumIPv6Transport(src, dst, IPPROTO_TCP, tcpSegment, sizeof(tcpSegment)));

      struct tcphdr updatedTCP = *reinterpret_cast<struct tcphdr *>(tcpSegment);
      uint16_t originalTCPChecksum = updatedTCP.check;
      uint16_t rewrittenTCPPort = htons(443);
      updatedTCP.check = replace_l4_checksum_word16(updatedTCP.check, updatedTCP.source, rewrittenTCPPort);
      updatedTCP.source = rewrittenTCPPort;

      uint8_t expectedTCPSegment[sizeof(updatedTCP)] = {};
      memcpy(expectedTCPSegment, &updatedTCP, sizeof(updatedTCP));
      reinterpret_cast<struct tcphdr *>(expectedTCPSegment)->check = 0;
      uint16_t expectedTCPChecksum = htons(checksumIPv6Transport(src, dst, IPPROTO_TCP, expectedTCPSegment, sizeof(expectedTCPSegment)));

      suite.expect(originalTCPChecksum != expectedTCPChecksum, "switchboard_wormhole_tcp_port_rewrite_changes_checksum");
      suite.expect(updatedTCP.check == expectedTCPChecksum, "switchboard_wormhole_tcp_port_rewrite_matches_full_checksum");
   }

   {
      uint8_t src[16] = {0xfd, 0xf8, 0xd9, 0x4c, 0x7c, 0x33, 0xe2, 0x6e, 0xca, 0x4b, 0xf5, 0x01, 0x01, 0x1f, 0x63, 0x5b};
      uint8_t rewrittenSrc[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0x01, 0x00, 0, 0, 0, 0x0b};
      uint8_t dst[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x77};

      struct tcphdr tcp = {};
      tcp.source = htons(8443);
      tcp.dest = htons(50000);
      tcp.seq = htonl(0x11223344);
      tcp.ack_seq = htonl(0x55667788);
      tcp.doff = sizeof(tcp) / 4;
      tcp.syn = 1;
      tcp.ack = 1;
      tcp.window = htons(4096);

      uint8_t tcpSegment[sizeof(tcp)] = {};
      memcpy(tcpSegment, &tcp, sizeof(tcp));
      reinterpret_cast<struct tcphdr *>(tcpSegment)->check = htons(checksumIPv6Transport(src, dst, IPPROTO_TCP, tcpSegment, sizeof(tcpSegment)));

      struct tcphdr updatedTCP = *reinterpret_cast<struct tcphdr *>(tcpSegment);
      uint16_t originalTCPChecksum = updatedTCP.check;
      updatedTCP.check = replace_l4_checksum_portable(updatedTCP.check, src, rewrittenSrc, sizeof(rewrittenSrc));
      updatedTCP.check = replace_l4_checksum_word16(updatedTCP.check, updatedTCP.source, htons(443));
      updatedTCP.source = htons(443);

      uint8_t expectedTCPSegment[sizeof(updatedTCP)] = {};
      memcpy(expectedTCPSegment, &updatedTCP, sizeof(updatedTCP));
      reinterpret_cast<struct tcphdr *>(expectedTCPSegment)->check = 0;
      uint16_t expectedTCPChecksum = htons(checksumIPv6Transport(rewrittenSrc, dst, IPPROTO_TCP, expectedTCPSegment, sizeof(expectedTCPSegment)));

      suite.expect(originalTCPChecksum != expectedTCPChecksum, "switchboard_wormhole_tcp_ipv6_source_rewrite_changes_checksum");
      suite.expect(updatedTCP.check == expectedTCPChecksum, "switchboard_wormhole_tcp_ipv6_source_rewrite_matches_full_checksum");
   }

   {
      uint8_t src[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x44};
      uint8_t dst[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0x01, 0x00, 0, 0, 0, 0x0b};
      uint8_t rewrittenDst[16] = {0xfd, 0xf8, 0xd9, 0x4c, 0x7c, 0x33, 0xe2, 0x6e, 0xca, 0x4b, 0xf5, 0x01, 0x01, 0x1f, 0x63, 0x5b};
      uint8_t payload[12] = {'p', 'a', 'r', 't', 'i', 'a', 'l', '-', 'u', 'd', 'p', '!'};

      struct udphdr udp = {};
      udp.source = htons(51515);
      udp.dest = htons(443);
      udp.len = htons(sizeof(udp) + sizeof(payload));
      udp.check = htons(0x6267);

      uint8_t rewrittenSegment[sizeof(udp) + sizeof(payload)] = {};
      memcpy(rewrittenSegment, &udp, sizeof(udp));
      memcpy(rewrittenSegment + sizeof(udp), payload, sizeof(payload));
      reinterpret_cast<struct udphdr *>(rewrittenSegment)->dest = htons(8443);

      uint8_t expectedSegment[sizeof(rewrittenSegment)] = {};
      memcpy(expectedSegment, rewrittenSegment, sizeof(expectedSegment));
      reinterpret_cast<struct udphdr *>(expectedSegment)->check = 0;
      uint16_t expectedChecksum = htons(checksumIPv6Transport(src, rewrittenDst, IPPROTO_UDP, expectedSegment, sizeof(expectedSegment)));

      struct udphdr incremental = *reinterpret_cast<struct udphdr *>(rewrittenSegment);
      incremental.check = replace_l4_checksum_portable(incremental.check, dst, rewrittenDst, sizeof(rewrittenDst));
      incremental.check = replace_l4_checksum_word16(incremental.check, htons(443), htons(8443));

      uint16_t recomputed = compute_ipv6_transport_checksum_portable(
         src,
         rewrittenDst,
         IPPROTO_UDP,
         rewrittenSegment,
         sizeof(rewrittenSegment),
         __builtin_offsetof(struct udphdr, check));

      suite.expect(incremental.check != expectedChecksum, "switchboard_wormhole_udp_partial_checksum_incremental_rewrite_fails");
      suite.expect(recomputed == expectedChecksum, "switchboard_wormhole_udp_partial_checksum_full_recompute_matches");
   }

   {
      uint8_t rewrittenSrc[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0x01, 0x00, 0, 0, 0, 0x0b};
      uint8_t dst[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x77};
      uint8_t src[16] = {0xfd, 0xf8, 0xd9, 0x4c, 0x7c, 0x33, 0xe2, 0x6e, 0xca, 0x4b, 0xf5, 0x01, 0x01, 0x1f, 0x63, 0x5b};

      struct tcphdr tcp = {};
      tcp.source = htons(8443);
      tcp.dest = htons(50000);
      tcp.seq = htonl(0xCAFEBABEu);
      tcp.ack_seq = htonl(0x10203040u);
      tcp.doff = sizeof(tcp) / 4;
      tcp.syn = 1;
      tcp.window = htons(8192);
      tcp.check = htons(0x4a31);

      uint8_t rewrittenSegment[sizeof(tcp)] = {};
      memcpy(rewrittenSegment, &tcp, sizeof(tcp));
      reinterpret_cast<struct tcphdr *>(rewrittenSegment)->source = htons(443);

      uint8_t expectedSegment[sizeof(rewrittenSegment)] = {};
      memcpy(expectedSegment, rewrittenSegment, sizeof(expectedSegment));
      reinterpret_cast<struct tcphdr *>(expectedSegment)->check = 0;
      uint16_t expectedChecksum = htons(checksumIPv6Transport(rewrittenSrc, dst, IPPROTO_TCP, expectedSegment, sizeof(expectedSegment)));

      struct tcphdr incremental = *reinterpret_cast<struct tcphdr *>(rewrittenSegment);
      incremental.check = replace_l4_checksum_portable(incremental.check, src, rewrittenSrc, sizeof(rewrittenSrc));
      incremental.check = replace_l4_checksum_word16(incremental.check, htons(8443), htons(443));

      uint16_t recomputed = compute_ipv6_transport_checksum_portable(
         rewrittenSrc,
         dst,
         IPPROTO_TCP,
         rewrittenSegment,
         sizeof(rewrittenSegment),
         __builtin_offsetof(struct tcphdr, check));

      suite.expect(incremental.check != expectedChecksum, "switchboard_wormhole_tcp_partial_checksum_incremental_rewrite_fails");
      suite.expect(recomputed == expectedChecksum, "switchboard_wormhole_tcp_partial_checksum_full_recompute_matches");
   }

   {
      uint8_t src[16] = {0x20, 0x01, 0x0d, 0xb8, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
      uint8_t dst[16] = {0x20, 0x01, 0x0d, 0xb8, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0b};
      uint8_t rewrittenDst[16] = {0xfd, 0xf8, 0xd9, 0x4c, 0x7c, 0x33, 0xe2, 0x6e, 0xca, 0x4b, 0xf5, 0x01, 0x12, 0xc3, 0x87, 0x62};
      std::array<uint8_t, 1232> payload = {};

      for (size_t index = 0; index < payload.size(); ++index)
      {
         payload[index] = static_cast<uint8_t>((index * 17u + 3u) & 0xffu);
      }

      struct udphdr udp = {};
      udp.source = htons(47957);
      udp.dest = htons(443);
      udp.len = htons(sizeof(udp) + payload.size());

      std::array<uint8_t, sizeof(udp) + payload.size()> originalSegment = {};
      memcpy(originalSegment.data(), &udp, sizeof(udp));
      memcpy(originalSegment.data() + sizeof(udp), payload.data(), payload.size());
      reinterpret_cast<struct udphdr *>(originalSegment.data())->check = htons(checksumIPv6Transport(
         src,
         dst,
         IPPROTO_UDP,
         originalSegment.data(),
         originalSegment.size()));

      std::array<uint8_t, originalSegment.size()> rewrittenSegment = originalSegment;
      reinterpret_cast<struct udphdr *>(rewrittenSegment.data())->dest = htons(8443);

      std::array<uint8_t, originalSegment.size()> expectedSegment = rewrittenSegment;
      reinterpret_cast<struct udphdr *>(expectedSegment.data())->check = 0;
      uint16_t expectedChecksum = htons(checksumIPv6Transport(
         src,
         rewrittenDst,
         IPPROTO_UDP,
         expectedSegment.data(),
         expectedSegment.size()));

      uint16_t recomputed = compute_ipv6_transport_checksum_portable(
         src,
         rewrittenDst,
         IPPROTO_UDP,
         rewrittenSegment.data(),
         rewrittenSegment.size(),
         __builtin_offsetof(struct udphdr, check));

      suite.expect(recomputed == expectedChecksum, "switchboard_wormhole_udp_quic_portal_full_recompute_matches_expected_checksum");
      suite.expect(recomputed != reinterpret_cast<const struct udphdr *>(originalSegment.data())->check, "switchboard_wormhole_udp_quic_portal_full_recompute_changes_checksum");
   }

   {
      uint8_t rewrittenSrc[16] = {0x20, 0x01, 0x0d, 0xb8, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0b};
      uint8_t dst[16] = {0xfd, 0xf8, 0xd9, 0x4c, 0x7c, 0x33, 0xe2, 0x6e, 0xca, 0x4b, 0xf5, 0x01, 0x9e, 0x98, 0xca, 0xc3};
      uint8_t src[16] = {0xfd, 0xf8, 0xd9, 0x4c, 0x7c, 0x33, 0xe2, 0x6e, 0xca, 0x4b, 0xf5, 0x01, 0xcc, 0x5a, 0xb2, 0x89};
      std::array<uint8_t, 2037> payload = {};

      for (size_t index = 0; index < payload.size(); ++index)
      {
         payload[index] = static_cast<uint8_t>((index * 13u + 7u) & 0xffu);
      }

      struct udphdr udp = {};
      udp.source = htons(8443);
      udp.dest = htons(42264);
      udp.len = htons(sizeof(udp) + payload.size());
      udp.check = htons(0x8e00);

      std::array<uint8_t, sizeof(udp) + payload.size()> rewrittenSegment = {};
      memcpy(rewrittenSegment.data(), &udp, sizeof(udp));
      memcpy(rewrittenSegment.data() + sizeof(udp), payload.data(), payload.size());
      reinterpret_cast<struct udphdr *>(rewrittenSegment.data())->source = htons(443);

      std::array<uint8_t, rewrittenSegment.size()> expectedSegment = rewrittenSegment;
      reinterpret_cast<struct udphdr *>(expectedSegment.data())->check = 0;
      uint16_t expectedChecksum = htons(checksumIPv6Transport(
         rewrittenSrc,
         dst,
         IPPROTO_UDP,
         expectedSegment.data(),
         expectedSegment.size()));

      struct udphdr incremental = udp;
      incremental.check = replace_l4_checksum_portable(incremental.check, src, rewrittenSrc, sizeof(rewrittenSrc));
      incremental.check = replace_l4_checksum_word16(incremental.check, htons(8443), htons(443));

      uint16_t recomputed = compute_ipv6_transport_checksum_portable(
         rewrittenSrc,
         dst,
         IPPROTO_UDP,
         rewrittenSegment.data(),
         rewrittenSegment.size(),
         __builtin_offsetof(struct udphdr, check));

      suite.expect(rewrittenSegment.size() == 2045u, "switchboard_wormhole_udp_quic_source_rewrite_segment_size_matches_live_path");
      suite.expect(incremental.check != expectedChecksum, "switchboard_wormhole_udp_quic_source_incremental_rewrite_fails");
      suite.expect(recomputed == expectedChecksum, "switchboard_wormhole_udp_quic_source_full_recompute_matches_expected_checksum");
   }

   {
      uint8_t rewrittenSrc[16] = {0x20, 0x01, 0x0d, 0xb8, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a};
      uint8_t dst[16] = {0xfd, 0xf8, 0xd9, 0x4c, 0x7c, 0x33, 0xe2, 0x6e, 0xca, 0x4b, 0xf5, 0x01, 0xda, 0x7b, 0xae, 0x2c};
      uint8_t src[16] = {0xfd, 0xf8, 0xd9, 0x4c, 0x7c, 0x33, 0xe2, 0x6e, 0xca, 0x4b, 0xf5, 0x01, 0x8e, 0xdc, 0x41, 0x3a};
      std::array<uint8_t, 2035> payload = {};

      for (size_t index = 0; index < payload.size(); ++index)
      {
         payload[index] = static_cast<uint8_t>((index * 13u + 31u) & 0xffu);
      }

      struct udphdr udp = {};
      udp.source = htons(8443);
      udp.dest = htons(35644);
      udp.len = htons(sizeof(udp) + payload.size());
      udp.check = htons(0x4b37);

      std::array<uint8_t, sizeof(udp) + payload.size()> rewrittenSegment = {};
      memcpy(rewrittenSegment.data(), &udp, sizeof(udp));
      memcpy(rewrittenSegment.data() + sizeof(udp), payload.data(), payload.size());
      reinterpret_cast<struct udphdr *>(rewrittenSegment.data())->source = htons(443);

      std::array<uint8_t, rewrittenSegment.size()> expectedSegment = rewrittenSegment;
      reinterpret_cast<struct udphdr *>(expectedSegment.data())->check = 0;
      uint16_t expectedChecksum = htons(checksumIPv6Transport(
         rewrittenSrc,
         dst,
         IPPROTO_UDP,
         expectedSegment.data(),
         expectedSegment.size()));

      struct udphdr incremental = udp;
      incremental.check = replace_l4_checksum_portable(incremental.check, src, rewrittenSrc, sizeof(rewrittenSrc));
      incremental.check = replace_l4_checksum_word16(incremental.check, htons(8443), htons(443));

      uint16_t recomputed = compute_ipv6_transport_checksum_portable(
         rewrittenSrc,
         dst,
         IPPROTO_UDP,
         rewrittenSegment.data(),
         rewrittenSegment.size(),
         __builtin_offsetof(struct udphdr, check));

      suite.expect(rewrittenSegment.size() == 2043u, "switchboard_wormhole_udp_quic_source_rewrite_application_reply_segment_size_matches_capture");
      suite.expect(incremental.check != expectedChecksum, "switchboard_wormhole_udp_quic_source_incremental_rewrite_fails_on_application_reply_capture");
      suite.expect(recomputed == expectedChecksum, "switchboard_wormhole_udp_quic_source_full_recompute_matches_application_reply_capture");
   }

   {
      uint8_t rewrittenSrc[16] = {0x20, 0x01, 0x0d, 0xb8, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0b};
      uint8_t dst[16] = {0xfd, 0xf8, 0xd9, 0x4c, 0x7c, 0x33, 0xe2, 0x6e, 0xca, 0x4b, 0xf5, 0x01, 0xa8, 0xe8, 0x59, 0x6f};
      uint8_t src[16] = {0xfd, 0xf8, 0xd9, 0x4c, 0x7c, 0x33, 0xe2, 0x6e, 0xca, 0x4b, 0xf5, 0x01, 0x71, 0x1f, 0x40, 0x89};
      std::array<uint8_t, 2039> payload = {};

      for (size_t index = 0; index < payload.size(); ++index)
      {
         payload[index] = static_cast<uint8_t>((index * 17u + 19u) & 0xffu);
      }

      struct udphdr udp = {};
      udp.source = htons(8443);
      udp.dest = htons(52262);
      udp.len = htons(sizeof(udp) + payload.size());
      udp.check = htons(0xa67c);

      std::array<uint8_t, sizeof(udp) + payload.size()> rewrittenSegment = {};
      memcpy(rewrittenSegment.data(), &udp, sizeof(udp));
      memcpy(rewrittenSegment.data() + sizeof(udp), payload.data(), payload.size());
      reinterpret_cast<struct udphdr *>(rewrittenSegment.data())->source = htons(443);

      std::array<uint8_t, rewrittenSegment.size()> expectedSegment = rewrittenSegment;
      reinterpret_cast<struct udphdr *>(expectedSegment.data())->check = 0;
      uint16_t expectedChecksum = htons(checksumIPv6Transport(
         rewrittenSrc,
         dst,
         IPPROTO_UDP,
         expectedSegment.data(),
         expectedSegment.size()));

      struct udphdr incremental = udp;
      incremental.check = replace_l4_checksum_portable(incremental.check, src, rewrittenSrc, sizeof(rewrittenSrc));
      incremental.check = replace_l4_checksum_word16(incremental.check, htons(8443), htons(443));

      uint16_t recomputed = compute_ipv6_transport_checksum_portable(
         rewrittenSrc,
         dst,
         IPPROTO_UDP,
         rewrittenSegment.data(),
         rewrittenSegment.size(),
         __builtin_offsetof(struct udphdr, check));

      suite.expect(rewrittenSegment.size() == 2047u, "switchboard_wormhole_udp_quic_source_rewrite_current_live_segment_size_matches_capture");
      suite.expect(incremental.check != expectedChecksum, "switchboard_wormhole_udp_quic_source_incremental_rewrite_fails_at_current_live_size");
      suite.expect(recomputed == expectedChecksum, "switchboard_wormhole_udp_quic_source_full_recompute_matches_expected_checksum_at_current_live_size");
   }

   {
      uint8_t src[16] = {0x20, 0x01, 0x0d, 0xb8, 0x02, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x21};
      uint8_t dst[16] = {0x20, 0x01, 0x0d, 0xb8, 0x02, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x45};
      uint8_t rewrittenDst[16] = {0xfd, 0xf8, 0xd9, 0x4c, 0x7c, 0x33, 0xe2, 0x6e, 0xca, 0x4b, 0xf5, 0x01, 0x01, 0xa5, 0x77, 0x62};
      std::array<uint8_t, 1527> payload = {};

      for (size_t index = 0; index < payload.size(); ++index)
      {
         payload[index] = static_cast<uint8_t>((index * 29u + 11u) & 0xffu);
      }

      struct udphdr udp = {};
      udp.source = htons(53001);
      udp.dest = htons(443);
      udp.len = htons(sizeof(udp) + payload.size());

      std::array<uint8_t, sizeof(udp) + payload.size()> rewrittenSegment = {};
      memcpy(rewrittenSegment.data(), &udp, sizeof(udp));
      memcpy(rewrittenSegment.data() + sizeof(udp), payload.data(), payload.size());
      reinterpret_cast<struct udphdr *>(rewrittenSegment.data())->dest = htons(8443);

      std::array<uint8_t, rewrittenSegment.size()> expectedSegment = rewrittenSegment;
      reinterpret_cast<struct udphdr *>(expectedSegment.data())->check = 0;
      uint16_t expectedChecksum = htons(checksumIPv6Transport(
         src,
         rewrittenDst,
         IPPROTO_UDP,
         expectedSegment.data(),
         expectedSegment.size()));

      uint16_t recomputed = compute_ipv6_transport_checksum_portable(
         src,
         rewrittenDst,
         IPPROTO_UDP,
         rewrittenSegment.data(),
         rewrittenSegment.size(),
         __builtin_offsetof(struct udphdr, check));

      suite.expect(rewrittenSegment.size() == 1535u, "switchboard_wormhole_udp_full_recompute_boundary_segment_size");
      suite.expect(recomputed == expectedChecksum, "switchboard_wormhole_udp_full_recompute_matches_expected_checksum_at_boundary");
   }

   return suite.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
