#pragma once

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <net/if.h>
#include <linux/if_link.h>

#include <ebpf/common/structs.h>
#include <prodigy/additional.ingress.h>

struct MothershipAdditionalIngressRetirement {
  String bootID, interfaceName;
  uint32_t ifindex = 0, programID = 0, mapCount = 0, localSubnetMapID = 0;
  uint8_t tag[BPF_TAG_SIZE] = {}, subnet[sizeof(local_container_subnet6)] = {};
};

static inline bool mothershipAdditionalIngressRetirementHex(const char *text, uint8_t *out, size_t bytes)
{
  if (!text || std::strlen(text) != bytes * 2) return false;
  for (size_t index = 0; index < bytes; ++index) {
    const char pair[] = {text[index * 2], text[index * 2 + 1], '\0'};
    if (!std::isxdigit(static_cast<unsigned char>(pair[0])) || !std::isxdigit(static_cast<unsigned char>(pair[1]))) return false;
    char *end = nullptr;
    const unsigned long value = std::strtoul(pair, &end, 16);
    if (end != pair + 2) return false;
    out[index] = uint8_t(value);
  }
  return true;
}

static inline bool mothershipAdditionalIngressRetirementProgramMatches(
    const MothershipAdditionalIngressRetirement& request, const struct bpf_prog_info& info)
{
  return info.id == request.programID && info.type == BPF_PROG_TYPE_XDP &&
         info.nr_map_ids == request.mapCount &&
         std::strncmp(reinterpret_cast<const char *>(info.name), "bal_ingress", BPF_OBJ_NAME_LEN) == 0 &&
         std::memcmp(info.tag, request.tag, BPF_TAG_SIZE) == 0;
}

static inline bool mothershipAdditionalIngressRetirementReadBootID(String& bootID)
{
  char value[64] = {}; const int fd = ::open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  const ssize_t bytes = fd >= 0 ? ::read(fd, value, sizeof(value) - 1) : -1; if (fd >= 0) ::close(fd);
  if (bytes != 37 || value[36] != '\n') return false;
  for (uint32_t i = 0; i < 36; ++i) if ((i == 8 || i == 13 || i == 18 || i == 23) ? value[i] != '-' : !std::isxdigit(static_cast<unsigned char>(value[i]))) return false;
  bootID.assign(value, 36); return true;
}

static inline bool mothershipRetireAdditionalIngressLocal(const MothershipAdditionalIngressRetirement& request, String *failure)
{
  auto reject = [&](const char *why) { if (failure) failure->assign(why); return false; };
  if (::geteuid() != 0) return reject("additional ingress retirement requires root");
  if (request.ifindex == 0 || request.programID == 0 || request.mapCount == 0 || request.localSubnetMapID == 0) return reject("invalid additional ingress retirement identity");
  String bootID = {}, configured = {};
  if (!mothershipAdditionalIngressRetirementReadBootID(bootID) || !bootID.equals(request.bootID) || !prodigyResolveOptionalAdditionalIngressDevice(configured, failure) || !configured.equals(request.interfaceName)) return reject("additional ingress retirement boot or configured interface differs");
  if (::if_nametoindex(configured.c_str()) != request.ifindex) return reject("additional ingress retirement interface index differs");
  __u32 attached = 0;
  if (bpf_xdp_query_id(request.ifindex, XDP_FLAGS_SKB_MODE, &attached) != 0 || attached != request.programID) return reject("additional ingress retirement attached program differs");
  const int programFD = bpf_prog_get_fd_by_id(request.programID); if (programFD < 0) return reject("additional ingress retirement program unavailable");
  struct bpf_prog_info info = {}; __u32 infoLength = sizeof(info);
  const bool programMatches = bpf_prog_get_info_by_fd(programFD, &info, &infoLength) == 0 && mothershipAdditionalIngressRetirementProgramMatches(request, info);
  if (!programMatches) { ::close(programFD); return reject("additional ingress retirement program identity differs"); }
  Vector<__u32> mapIDs = {}; mapIDs.resize(info.nr_map_ids); struct bpf_prog_info mapInfo = {}; mapInfo.nr_map_ids = info.nr_map_ids; mapInfo.map_ids = reinterpret_cast<__u64>(mapIDs.data()); infoLength = sizeof(mapInfo);
  if (bpf_prog_get_info_by_fd(programFD, &mapInfo, &infoLength) != 0 || mapInfo.nr_map_ids != info.nr_map_ids) { ::close(programFD); return reject("additional ingress retirement map inventory unreadable"); }
  bool subnetMatches = false; uint32_t localSubnetMaps = 0;
  for (__u32 mapID : mapIDs) {
    const int mapFD = bpf_map_get_fd_by_id(mapID); struct bpf_map_info observed = {}; __u32 observedLength = sizeof(observed); uint32_t zero = 0; uint8_t subnet[sizeof(request.subnet)] = {};
    const bool readable = mapFD >= 0 && bpf_obj_get_info_by_fd(mapFD, &observed, &observedLength) == 0;
    if (!readable) { if (mapFD >= 0) ::close(mapFD); ::close(programFD); return reject("additional ingress retirement map inventory unreadable"); }
    const bool localSubnet = readable && std::strncmp(reinterpret_cast<const char *>(observed.name), "lc_subnet", BPF_OBJ_NAME_LEN) == 0;
    if (localSubnet) ++localSubnetMaps;
    if (mapID == request.localSubnetMapID) subnetMatches = localSubnet && observed.type == BPF_MAP_TYPE_ARRAY && observed.key_size == sizeof(zero) && observed.value_size == sizeof(subnet) && observed.max_entries >= 1 && bpf_map_lookup_elem(mapFD, &zero, subnet) == 0 && std::memcmp(subnet, request.subnet, sizeof(subnet)) == 0;
    if (mapFD >= 0) ::close(mapFD);
  }
  if (!subnetMatches || localSubnetMaps != 1) { ::close(programFD); return reject("additional ingress retirement local subnet map differs"); }
  struct bpf_xdp_attach_opts options = {}; options.sz = sizeof(options); options.old_prog_fd = programFD;
  const int detached = bpf_xdp_attach(request.ifindex, -1, XDP_FLAGS_SKB_MODE, &options); ::close(programFD);
  if (detached != 0) return reject("additional ingress retirement CAS detach failed");
  attached = 0;
  if (bpf_xdp_query_id(request.ifindex, XDP_FLAGS_SKB_MODE, &attached) != 0 || attached != 0) return reject("additional ingress retirement detach verification failed");
  return true;
}
