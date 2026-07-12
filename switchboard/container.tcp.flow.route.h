#pragma once

#include <switchboard/whitehole.route.h>

static inline void switchboardContainerTCPFlowPinPath(String& path, uint32_t ifindex)
{
  path.snprintf<"/sys/fs/bpf/prodigy_container_tcp_flows_{itoa}"_ctv>(ifindex);
}

template <typename Program>
static inline bool switchboardPinContainerTCPFlowMap(Program *program, uint32_t ifindex)
{
  return switchboardPinProgramMap(program, ifindex, "ct_tcp_flows", switchboardContainerTCPFlowPinPath);
}

static inline bool switchboardReusePinnedContainerTCPFlowMap(struct bpf_object *obj, uint32_t ifindex, Vector<int>& inner_map_fds)
{
  return switchboardReusePinnedProgramMap(obj, ifindex, "ct_tcp_flows", switchboardContainerTCPFlowPinPath, inner_map_fds);
}

static inline void switchboardUnpinContainerTCPFlowMap(uint32_t ifindex)
{
  String path = {};
  switchboardContainerTCPFlowPinPath(path, ifindex);
  (void)unlink(path.c_str());
}
