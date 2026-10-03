// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <bpf/bpf.h>
#include <cerrno>
#include <cstring>
#include <linux/magic.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <vector>

#include <networking/netlink.h>

#include <switchboard/whitehole.route.h>

// A retained TCX link is a runtime-owned recovery reference. The provider only
// preserves the fake machine's bpffs mount across a worker replacement.
enum class SwitchboardHostTCXDirection : uint8_t { ingress, egress };

struct SwitchboardHostTCXRetentionIdentity {
  uint32_t linkID = 0;
  uint32_t programID = 0;
  uint32_t interfaceIndex = 0;
  uint32_t wormholeFlowMapID = 0;
  uint32_t wormholePendingFlowMapID = 0;
  SwitchboardHostTCXDirection direction = SwitchboardHostTCXDirection::ingress;
  uint8_t programTag[BPF_TAG_SIZE] = {};
};

struct SwitchboardHostTCXRetentionPair {
  SwitchboardHostTCXRetentionIdentity ingress = {};
  SwitchboardHostTCXRetentionIdentity egress = {};
};

static inline enum bpf_attach_type switchboardHostTCXAttachType(SwitchboardHostTCXDirection direction)
{
  return direction == SwitchboardHostTCXDirection::ingress ? BPF_TCX_INGRESS : BPF_TCX_EGRESS;
}

static inline const char *switchboardHostTCXProgramName(SwitchboardHostTCXDirection direction)
{
  return direction == SwitchboardHostTCXDirection::ingress ? "host_ingress" : "host_egress";
}

static inline void switchboardHostTCXRetentionPath(String& path,
                                                    StringType auto&& bpffsRoot,
                                                    uint32_t ifindex,
                                                    SwitchboardHostTCXDirection direction)
{
  if (direction == SwitchboardHostTCXDirection::ingress)
    path.snprintf<"{}/prodigy_host_tcx_ingress_{itoa}"_ctv>(bpffsRoot, ifindex);
  else
    path.snprintf<"{}/prodigy_host_tcx_egress_{itoa}"_ctv>(bpffsRoot, ifindex);
}

static inline void switchboardHostTCXMapPinPath(String& path, StringType auto&& bpffsRoot, uint32_t ifindex, bool pending)
{
  if (pending) path.snprintf<"{}/prodigy_wormhole_pending_flows_{itoa}"_ctv>(bpffsRoot, ifindex);
  else path.snprintf<"{}/prodigy_wormhole_flows_{itoa}"_ctv>(bpffsRoot, ifindex);
}

static inline bool switchboardHostTCXValidBPFFSRoot(StringType auto&& bpffsRoot)
{
  String root = {};
  root.assign(bpffsRoot);
  struct stat metadata = {};
  struct statfs filesystem = {};
  return root.empty() == false && ::lstat(root.c_str(), &metadata) == 0 && S_ISDIR(metadata.st_mode) &&
         S_ISLNK(metadata.st_mode) == false && ::statfs(root.c_str(), &filesystem) == 0 &&
         static_cast<unsigned long>(filesystem.f_type) == static_cast<unsigned long>(BPF_FS_MAGIC);
}

static inline bool switchboardHostTCXReadPinnedMapIDs(StringType auto&& bpffsRoot,
                                                       uint32_t ifindex,
                                                       uint32_t& flowMapID,
                                                       uint32_t& pendingMapID)
{
  flowMapID = 0;
  pendingMapID = 0;
  if (switchboardHostTCXValidBPFFSRoot(bpffsRoot) == false || ifindex == 0) return false;

  String flowPath = {};
  String pendingPath = {};
  switchboardHostTCXMapPinPath(flowPath, bpffsRoot, ifindex, false);
  switchboardHostTCXMapPinPath(pendingPath, bpffsRoot, ifindex, true);
  int flowFD = bpf_obj_get(flowPath.c_str());
  int pendingFD = bpf_obj_get(pendingPath.c_str());
  const bool valid = switchboardWormholeEstablishedFlowMapCompatibleFD(flowFD) &&
                     switchboardWormholePendingFlowMapCompatibleFD(pendingFD);
  if (valid)
  {
    flowMapID = switchboardKernelMapID(flowFD);
    pendingMapID = switchboardKernelMapID(pendingFD);
  }
  if (flowFD >= 0) ::close(flowFD);
  if (pendingFD >= 0) ::close(pendingFD);
  return valid && flowMapID != 0 && pendingMapID != 0;
}

static inline bool switchboardHostTCXProgramUsesMaps(int programFD, uint32_t flowMapID, uint32_t pendingMapID)
{
  struct bpf_prog_info info = {};
  __u32 infoBytes = sizeof(info);
  if (programFD < 0 || flowMapID == 0 || pendingMapID == 0 ||
      bpf_prog_get_info_by_fd(programFD, &info, &infoBytes) != 0 || info.nr_map_ids == 0)
  {
    return false;
  }
  std::vector<__u32> mapIDs(info.nr_map_ids);
  struct bpf_prog_info request = {};
  request.nr_map_ids = static_cast<__u32>(mapIDs.size());
  request.map_ids = reinterpret_cast<__u64>(mapIDs.data());
  infoBytes = sizeof(request);
  if (bpf_prog_get_info_by_fd(programFD, &request, &infoBytes) != 0 || request.nr_map_ids != mapIDs.size()) return false;
  bool hasFlow = false;
  bool hasPending = false;
  for (__u32 mapID : mapIDs)
  {
    hasFlow |= mapID == flowMapID;
    hasPending |= mapID == pendingMapID;
  }
  return hasFlow && hasPending;
}

static inline bool switchboardHostTCXIdentityFromFDs(int linkFD,
                                                      int programFD,
                                                      uint32_t ifindex,
                                                      SwitchboardHostTCXDirection direction,
                                                      uint32_t flowMapID,
                                                      uint32_t pendingMapID,
                                                      SwitchboardHostTCXRetentionIdentity& identity)
{
  struct bpf_link_info link = {};
  struct bpf_prog_info program = {};
  __u32 linkBytes = sizeof(link);
  __u32 programBytes = sizeof(program);
  if (linkFD < 0 || programFD < 0 || flowMapID == 0 || pendingMapID == 0 ||
      bpf_obj_get_info_by_fd(linkFD, &link, &linkBytes) != 0 || bpf_prog_get_info_by_fd(programFD, &program, &programBytes) != 0 ||
      link.type != BPF_LINK_TYPE_TCX || link.id == 0 || link.prog_id == 0 || link.prog_id != program.id ||
      link.tcx.ifindex != ifindex || link.tcx.attach_type != switchboardHostTCXAttachType(direction) ||
      std::strncmp(reinterpret_cast<const char *>(program.name), switchboardHostTCXProgramName(direction), BPF_OBJ_NAME_LEN) != 0 ||
      switchboardHostTCXProgramUsesMaps(programFD, flowMapID, pendingMapID) == false)
  {
    return false;
  }
  identity = {};
  identity.linkID = link.id;
  identity.programID = program.id;
  identity.interfaceIndex = ifindex;
  identity.wormholeFlowMapID = flowMapID;
  identity.wormholePendingFlowMapID = pendingMapID;
  identity.direction = direction;
  std::memcpy(identity.programTag, program.tag, sizeof(identity.programTag));
  return true;
}

static inline bool switchboardHostTCXIdentityEquals(const SwitchboardHostTCXRetentionIdentity& lhs,
                                                     const SwitchboardHostTCXRetentionIdentity& rhs)
{
  return lhs.linkID == rhs.linkID && lhs.programID == rhs.programID && lhs.interfaceIndex == rhs.interfaceIndex &&
         lhs.wormholeFlowMapID == rhs.wormholeFlowMapID && lhs.wormholePendingFlowMapID == rhs.wormholePendingFlowMapID &&
         lhs.direction == rhs.direction && std::memcmp(lhs.programTag, rhs.programTag, sizeof(lhs.programTag)) == 0;
}

static inline bool switchboardHostTCXOpenPinnedLink(StringType auto&& bpffsRoot,
                                                     uint32_t ifindex,
                                                     SwitchboardHostTCXDirection direction,
                                                     int& linkFD,
                                                     bool& present)
{
  linkFD = -1;
  present = false;
  if (switchboardHostTCXValidBPFFSRoot(bpffsRoot) == false || ifindex == 0) return false;
  String path = {};
  switchboardHostTCXRetentionPath(path, bpffsRoot, ifindex, direction);
  linkFD = bpf_obj_get(path.c_str());
  if (linkFD >= 0)
  {
    present = true;
    return true;
  }
  return errno == ENOENT;
}

static inline bool switchboardHostTCXReadPinnedIdentity(StringType auto&& bpffsRoot,
                                                         const SwitchboardHostTCXRetentionIdentity& expected,
                                                         SwitchboardHostTCXRetentionIdentity& observed)
{
  int linkFD = -1;
  bool present = false;
  int programFD = -1;
  uint32_t flowMapID = 0;
  uint32_t pendingMapID = 0;
  bool valid = switchboardHostTCXOpenPinnedLink(bpffsRoot, expected.interfaceIndex, expected.direction, linkFD, present) && present &&
               switchboardHostTCXReadPinnedMapIDs(bpffsRoot, expected.interfaceIndex, flowMapID, pendingMapID);
  struct bpf_link_info link = {};
  __u32 linkBytes = sizeof(link);
  if (valid && bpf_obj_get_info_by_fd(linkFD, &link, &linkBytes) == 0) programFD = bpf_prog_get_fd_by_id(link.prog_id);
  valid = valid && programFD >= 0 && switchboardHostTCXIdentityFromFDs(linkFD, programFD, expected.interfaceIndex,
                                                                         expected.direction, flowMapID, pendingMapID, observed) &&
          switchboardHostTCXIdentityEquals(expected, observed);
  if (programFD >= 0) ::close(programFD);
  if (linkFD >= 0) ::close(linkFD);
  return valid;
}

static inline bool switchboardHostTCXReadAnyPinnedIdentity(StringType auto&& bpffsRoot,
                                                            uint32_t ifindex,
                                                            SwitchboardHostTCXDirection direction,
                                                            SwitchboardHostTCXRetentionIdentity& observed,
                                                            bool& present)
{
  int linkFD = -1;
  if (switchboardHostTCXOpenPinnedLink(bpffsRoot, ifindex, direction, linkFD, present) == false) return false;
  if (present == false) return true;
  int programFD = -1;
  uint32_t flowMapID = 0;
  uint32_t pendingMapID = 0;
  bool valid = switchboardHostTCXReadPinnedMapIDs(bpffsRoot, ifindex, flowMapID, pendingMapID);
  struct bpf_link_info link = {};
  __u32 linkBytes = sizeof(link);
  if (valid && bpf_obj_get_info_by_fd(linkFD, &link, &linkBytes) == 0) programFD = bpf_prog_get_fd_by_id(link.prog_id);
  valid = valid && programFD >= 0 &&
          switchboardHostTCXIdentityFromFDs(linkFD, programFD, ifindex, direction, flowMapID, pendingMapID, observed);
  if (programFD >= 0) ::close(programFD);
  ::close(linkFD);
  return valid;
}

static inline bool switchboardHostTCXOpenCurrent(uint32_t ifindex,
                                                  StringType auto&& bpffsRoot,
                                                  SwitchboardHostTCXDirection direction,
                                                  uint32_t expectedProgramID,
                                                  SwitchboardHostTCXRetentionIdentity& identity)
{
  uint32_t flowMapID = 0;
  uint32_t pendingMapID = 0;
  BPFProgram::TCXIdentity borrowed = {};
  if (switchboardHostTCXReadPinnedMapIDs(bpffsRoot, ifindex, flowMapID, pendingMapID) == false ||
      BPFProgram::openTCXIdentity(ifindex, switchboardHostTCXAttachType(direction), expectedProgramID, borrowed) == false)
  {
    return false;
  }
  const bool valid = switchboardHostTCXIdentityFromFDs(borrowed.linkFD, borrowed.programFD, ifindex, direction,
                                                        flowMapID, pendingMapID, identity);
  BPFProgram::closeTCXIdentity(borrowed);
  return valid;
}

static inline bool switchboardHostTCXOpenCurrent(NetDevice& device,
                                                  StringType auto&& bpffsRoot,
                                                  SwitchboardHostTCXDirection direction,
                                                  uint32_t expectedProgramID,
                                                  SwitchboardHostTCXRetentionIdentity& identity)
{
  return switchboardHostTCXOpenCurrent(device.ifidx, bpffsRoot, direction, expectedProgramID, identity);
}

static inline bool switchboardHostTCXPinExact(StringType auto&& bpffsRoot,
                                               const SwitchboardHostTCXRetentionIdentity& expected,
                                               bool *created = nullptr)
{
  if (created) *created = false;
  SwitchboardHostTCXRetentionIdentity current = {};
  if (switchboardHostTCXOpenCurrent(expected.interfaceIndex, bpffsRoot, expected.direction, expected.programID, current) == false ||
      switchboardHostTCXIdentityEquals(expected, current) == false)
  {
    return false;
  }
  int existing = -1;
  bool present = false;
  if (switchboardHostTCXOpenPinnedLink(bpffsRoot, expected.interfaceIndex, expected.direction, existing, present) == false) return false;
  if (present)
  {
    ::close(existing);
    SwitchboardHostTCXRetentionIdentity pinned = {};
    return switchboardHostTCXReadPinnedIdentity(bpffsRoot, expected, pinned);
  }
  BPFProgram::TCXIdentity borrowed = {};
  if (BPFProgram::openTCXIdentity(expected.interfaceIndex, switchboardHostTCXAttachType(expected.direction),
                                  expected.programID, borrowed) == false)
  {
    return false;
  }
  if (borrowed.linkID != expected.linkID || std::memcmp(borrowed.programTag, expected.programTag, sizeof(expected.programTag)) != 0)
  {
    BPFProgram::closeTCXIdentity(borrowed);
    return false;
  }
  String path = {};
  switchboardHostTCXRetentionPath(path, bpffsRoot, expected.interfaceIndex, expected.direction);
  const bool pinned = bpf_obj_pin(borrowed.linkFD, path.c_str()) == 0;
  BPFProgram::closeTCXIdentity(borrowed);
  if (pinned && created) *created = true;
  return pinned;
}

static inline bool switchboardHostTCXReleaseExact(StringType auto&& bpffsRoot,
                                                   const SwitchboardHostTCXRetentionIdentity& expected)
{
  SwitchboardHostTCXRetentionIdentity observed = {};
  if (switchboardHostTCXReadPinnedIdentity(bpffsRoot, expected, observed) == false) return false;
  String path = {};
  switchboardHostTCXRetentionPath(path, bpffsRoot, expected.interfaceIndex, expected.direction);
  return ::unlink(path.c_str()) == 0;
}

static inline bool switchboardHostTCXRetainCurrentPair(uint32_t ifindex,
                                                        StringType auto&& bpffsRoot,
                                                        SwitchboardHostTCXRetentionPair& pair)
{
  SwitchboardHostTCXRetentionPair current = {};
  if (switchboardHostTCXOpenCurrent(ifindex, bpffsRoot, SwitchboardHostTCXDirection::ingress, 0, current.ingress) == false ||
      switchboardHostTCXOpenCurrent(ifindex, bpffsRoot, SwitchboardHostTCXDirection::egress, 0, current.egress) == false)
  {
    return false;
  }
  bool ingressCreated = false;
  if (switchboardHostTCXPinExact(bpffsRoot, current.ingress, &ingressCreated) == false ||
      switchboardHostTCXPinExact(bpffsRoot, current.egress) == false)
  {
    if (ingressCreated) (void)switchboardHostTCXReleaseExact(bpffsRoot, current.ingress);
    return false;
  }
  pair = current;
  return true;
}

static inline bool switchboardHostTCXRetainCurrentPair(NetDevice& device,
                                                        StringType auto&& bpffsRoot,
                                                        SwitchboardHostTCXRetentionPair& pair)
{
  return switchboardHostTCXRetainCurrentPair(device.ifidx, bpffsRoot, pair);
}

static inline bool switchboardHostTCXVerifyRetainedPair(uint32_t ifindex,
                                                         StringType auto&& bpffsRoot,
                                                         const SwitchboardHostTCXRetentionPair& expected)
{
  SwitchboardHostTCXRetentionIdentity ingress = {};
  SwitchboardHostTCXRetentionIdentity egress = {};
  return expected.ingress.interfaceIndex == ifindex && expected.egress.interfaceIndex == ifindex &&
         switchboardHostTCXReadPinnedIdentity(bpffsRoot, expected.ingress, ingress) &&
         switchboardHostTCXReadPinnedIdentity(bpffsRoot, expected.egress, egress) &&
         switchboardHostTCXOpenCurrent(ifindex, bpffsRoot, SwitchboardHostTCXDirection::ingress, expected.ingress.programID, ingress) &&
         switchboardHostTCXOpenCurrent(ifindex, bpffsRoot, SwitchboardHostTCXDirection::egress, expected.egress.programID, egress) &&
         switchboardHostTCXIdentityEquals(expected.ingress, ingress) && switchboardHostTCXIdentityEquals(expected.egress, egress);
}

static inline bool switchboardHostTCXVerifyRetainedPair(NetDevice& device,
                                                         StringType auto&& bpffsRoot,
                                                         const SwitchboardHostTCXRetentionPair& expected)
{
  return switchboardHostTCXVerifyRetainedPair(device.ifidx, bpffsRoot, expected);
}

static inline bool switchboardHostTCXReadRetainedPair(NetDevice& device,
                                                       StringType auto&& bpffsRoot,
                                                       SwitchboardHostTCXRetentionPair& pair,
                                                       bool& present)
{
  bool ingressPresent = false;
  bool egressPresent = false;
  if (switchboardHostTCXReadAnyPinnedIdentity(bpffsRoot, device.ifidx, SwitchboardHostTCXDirection::ingress,
                                              pair.ingress, ingressPresent) == false ||
      switchboardHostTCXReadAnyPinnedIdentity(bpffsRoot, device.ifidx, SwitchboardHostTCXDirection::egress,
                                              pair.egress, egressPresent) == false)
  {
    return false;
  }
  present = ingressPresent || egressPresent;
  return ingressPresent == egressPresent;
}
