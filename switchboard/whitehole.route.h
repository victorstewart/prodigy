#pragma once

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cstring>
#include <unistd.h>

#include <ebpf/common/structs.h>

#include <prodigy/types.h>
#include <switchboard/common/structs.h>

static inline bool switchboardPortalDefinitionEquals(const portal_definition& lhs, const portal_definition& rhs)
{
   return lhs.port == rhs.port
      && lhs.proto == rhs.proto
      && std::memcmp(lhs.addr6, rhs.addr6, sizeof(lhs.addr6)) == 0;
}

static inline bool switchboardWhiteholeBindingEquals(const switchboard_whitehole_binding& lhs, const switchboard_whitehole_binding& rhs)
{
   return lhs.nonce == rhs.nonce
      && lhs.container.hasID == rhs.container.hasID
      && std::memcmp(lhs.container.value, rhs.container.value, sizeof(lhs.container.value)) == 0;
}

static inline uint8_t switchboardTransportProtocol(ExternalAddressTransport transport)
{
   return (transport == ExternalAddressTransport::quic) ? uint8_t(IPPROTO_UDP) : uint8_t(IPPROTO_TCP);
}

static inline uint16_t switchboardPortalKeyPort(uint16_t hostPort)
{
   return htons(hostPort);
}

static inline bool switchboardMakeWhiteholeBindingKey(const IPAddress& address, uint16_t sourcePort, ExternalAddressTransport transport, portal_definition& key)
{
   key = {};
   if (address.isNull() || sourcePort == 0)
   {
      return false;
   }

   std::memcpy(key.addr6, address.v6, sizeof(key.addr6));
   key.port = switchboardPortalKeyPort(sourcePort);
   key.proto = switchboardTransportProtocol(transport);
   return true;
}

static inline bool switchboardBuildWhiteholeBindingValue(uint32_t containerID, const local_container_subnet6& subnet, uint64_t nonce, switchboard_whitehole_binding& binding)
{
   binding = {};
   if (subnet.dpfx == 0 || containerID == 0 || nonce == 0)
   {
      return false;
   }

   const uint8_t *raw = reinterpret_cast<const uint8_t *>(&containerID);
   binding.container.hasID = true;
   binding.container.value[0] = subnet.dpfx;
   binding.container.value[1] = raw[0];
   binding.container.value[2] = raw[1];
   binding.container.value[3] = raw[2];
   binding.container.value[4] = raw[3];
   binding.nonce = nonce;
   return true;
}

static inline bool switchboardBuildWhiteholeBinding(const Whitehole& whitehole,
   uint32_t containerID,
   const local_container_subnet6& subnet,
   portal_definition& key,
   switchboard_whitehole_binding& binding)
{
   if (switchboardMakeWhiteholeBindingKey(whitehole.address, whitehole.sourcePort, whitehole.transport, key) == false)
   {
      return false;
   }

   return switchboardBuildWhiteholeBindingValue(containerID, subnet, whitehole.bindingNonce, binding);
}

static inline void switchboardWhiteholeReplyFlowPinPath(String& path, uint32_t ifindex)
{
   path.snprintf<"/sys/fs/bpf/prodigy_whitehole_reply_flows_{itoa}"_ctv>(ifindex);
}

template <typename Program>
static inline bool switchboardPinWhiteholeReplyFlowMap(Program *program, uint32_t ifindex)
{
   if (program == nullptr || ifindex == 0)
   {
      return false;
   }

   bool pinned = false;
   String path = {};
   switchboardWhiteholeReplyFlowPinPath(path, ifindex);

   program->openMap("whitehole_reply_flows"_ctv, [&] (int map_fd) -> void {

      if (map_fd < 0)
      {
         return;
      }

      (void)unlink(path.c_str());
      pinned = (bpf_obj_pin(map_fd, path.c_str()) == 0);
   });

   return pinned;
}

static inline bool switchboardReusePinnedWhiteholeReplyFlowMap(struct bpf_object *obj, uint32_t ifindex, Vector<int>& inner_map_fds)
{
   if (obj == nullptr || ifindex == 0)
   {
      return false;
   }

   String path = {};
   switchboardWhiteholeReplyFlowPinPath(path, ifindex);

   int pinnedReplyMapFD = bpf_obj_get(path.c_str());
   if (pinnedReplyMapFD < 0)
   {
      return false;
   }

   struct bpf_map *replyMap = bpf_object__find_map_by_name(obj, "whitehole_reply_flows");
   if (replyMap == nullptr || bpf_map__reuse_fd(replyMap, pinnedReplyMapFD) != 0)
   {
      ::close(pinnedReplyMapFD);
      return false;
   }

   inner_map_fds.push_back(pinnedReplyMapFD);
   return true;
}
