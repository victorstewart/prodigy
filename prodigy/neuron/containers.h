#pragma once

#include <fcntl.h>         /* Definition of O_* and S_* constants */
#include <services/debug.h>
#include <linux/sched.h>    /* Definition of struct clone_args */
#include <sched.h>          /* Definition of CLONE_* constants */
#include <simdjson.h>
#include <sys/syscall.h>    /* Definition of SYS_* constants */
#include <unistd.h>
#include <signal.h>
#include <sys/capability.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/statvfs.h>
#include <seccomp.h>
#include <sys/sysmacros.h>
#include <spawn.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <arpa/inet.h>
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <limits>
#include <string>

#include <services/memfd.h>
#include <prodigy/build.identity.h>
#include <prodigy/wire.h>

#include <prodigy/neuron/container.storage.layout.h>
#include <switchboard/overlay.route.h>

#define nReservedCores 2
static constexpr int containerStartupFailureExitCode = 125;
static constexpr int containerExecInheritedFDMinimum = 64;
static constexpr int64_t failedContainerArtifactRetentionMs = 24LL * 60LL * 60LL * 1000LL;
static constexpr int64_t failedContainerArtifactCleanupIntervalMs = 3LL * 60LL * 60LL * 1000LL;

static void prodigyAppendAttachTrace(String& line)
{
   int fd = ::open("/switchboard.attach.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
   if (fd < 0)
   {
      return;
   }

   (void)line.addNullTerminator();
   (void)::write(fd, line.data(), line.size());
   (void)::write(fd, "\n", 1);
   (void)::close(fd);
}

// Upstream Linux source of truth for netkit program orientation:
// - netkit_new_link() marks the root RTM_NEWLINK device as primary and the
//   peer-info device as peer.
// - netkit_dev_fetch() requires the primary ifindex as the attach target and
//   maps BPF_NETKIT_PEER from that primary endpoint to its peer endpoint.
// - netkit_xmit() runs the attached program on the transmitting endpoint.
// For Prodigy's NetkitPair, host.name is the root device and peer.name is moved
// into the container netns, so host.ifidx + PRIMARY is host -> container and
// host.ifidx + PEER is container -> host. Do not flip these without new Linux
// source proof.
static constexpr enum bpf_attach_type prodigyContainerIngressNetkitAttachType()
{
   return BPF_NETKIT_PRIMARY;
}

static constexpr enum bpf_attach_type prodigyContainerEgressNetkitAttachType()
{
   return BPF_NETKIT_PEER;
}

#ifndef NAMETAG_PRODIGY_DEV_FAKE_IPV4_ROUTE
#define NAMETAG_PRODIGY_DEV_FAKE_IPV4_ROUTE 0
#endif

static void installDatacenterMeshRoutes(NetDevice& device, uint8_t datacenterFragment)
{
   auto addDatacenterRoute = [&] (const container_network_subnet6_prefix& subnet) -> void
   {
      uint8_t routeBytes[16] = {0};
      memcpy(routeBytes, subnet.value, 11);
      routeBytes[11] = datacenterFragment;

      char routeText[INET6_ADDRSTRLEN] = {0};
      if (inet_ntop(AF_INET6, routeBytes, routeText, sizeof(routeText)) == nullptr)
      {
         return;
      }

      String routePrefix;
      routePrefix.assign(routeText);
      device.addDirectRoute(routePrefix, 96, AF_INET6);
   };

   addDatacenterRoute(container_network_subnet6);
}

template <typename Key, typename Equals>
static bool prodigyOverlayKeyPresent(const Vector<Key>& haystack, const Key& needle, Equals&& equals)
{
   for (const Key& candidate : haystack)
   {
      if (equals(candidate, needle))
      {
         return true;
      }
   }

   return false;
}

template <typename Key, StringType MapName, typename Equals>
static void prodigySyncOverlayPresenceMap(BPFProgram *program,
   MapName&& mapName,
   Vector<Key>& installedKeys,
   const Vector<Key>& desiredKeys,
   Equals&& equals)
{
   if (program == nullptr)
   {
      installedKeys = desiredKeys;
      return;
   }

   program->openMap(mapName, [&] (int map_fd) -> void {

      if (map_fd < 0)
      {
         basics_log("Prodigy missing overlay presence map\n");
         return;
      }

      for (const Key& existing : installedKeys)
      {
         if (prodigyOverlayKeyPresent(desiredKeys, existing, equals) == false)
         {
            bpf_map_delete_elem(map_fd, &existing);
         }
      }

      __u8 present = 1;
      for (const Key& desired : desiredKeys)
      {
         bpf_map_update_elem(map_fd, &desired, &present, BPF_ANY);
      }
   });

   installedKeys = desiredKeys;
}

template <typename Key, typename Value, StringType MapName, typename Equals>
static void prodigySyncOverlayValueMap(BPFProgram *program,
   MapName&& mapName,
   Vector<Key>& installedKeys,
   const Vector<std::pair<Key, Value>>& desiredEntries,
   Equals&& equals)
{
   Vector<Key> desiredKeys = {};
   desiredKeys.reserve(desiredEntries.size());
   for (const auto& entry : desiredEntries)
   {
      desiredKeys.push_back(entry.first);
   }

   if (program == nullptr)
   {
      installedKeys = desiredKeys;
      return;
   }

   program->openMap(mapName, [&] (int map_fd) -> void {

      if (map_fd < 0)
      {
         basics_log("Prodigy missing overlay value map\n");
         return;
      }

      for (const Key& existing : installedKeys)
      {
         if (prodigyOverlayKeyPresent(desiredKeys, existing, equals) == false)
         {
            bpf_map_delete_elem(map_fd, &existing);
         }
      }

      for (const auto& entry : desiredEntries)
      {
         bpf_map_update_elem(map_fd, &entry.first, &entry.second, BPF_ANY);
      }
   });

   installedKeys = desiredKeys;
}

static void prodigyBuildOverlayDesiredRoutes(const SwitchboardOverlayRoutingConfig& config,
   Vector<std::pair<switchboard_overlay_machine_route_key, switchboard_overlay_machine_route>>& desiredRoutesFull,
   Vector<std::pair<switchboard_overlay_machine_route_key, switchboard_overlay_machine_route>>& desiredRoutesLow8)
{
   uint8_t low8Counts[256] = {0};

   desiredRoutesFull.clear();
   desiredRoutesLow8.clear();
   desiredRoutesFull.reserve(config.machineRoutes.size());
   desiredRoutesLow8.reserve(config.machineRoutes.size());

   for (const SwitchboardOverlayMachineRoute& route : config.machineRoutes)
   {
      switchboard_overlay_machine_route value = {};
      if (switchboardBuildOverlayMachineRouteValue(route, value) == false)
      {
         continue;
      }

      desiredRoutesFull.emplace_back(switchboardMakeOverlayMachineRouteKey(route.machineFragment), value);

      uint32_t low8 = route.machineFragment & 0xFFu;
      if (low8 > 0)
      {
         low8Counts[low8] += 1;
      }
   }

   for (const SwitchboardOverlayMachineRoute& route : config.machineRoutes)
   {
      uint32_t low8 = route.machineFragment & 0xFFu;
      if (low8 == 0 || low8Counts[low8] != 1)
      {
         continue;
      }

      switchboard_overlay_machine_route value = {};
      if (switchboardBuildOverlayMachineRouteValue(route, value) == false)
      {
         continue;
      }

      desiredRoutesLow8.emplace_back(switchboardMakeOverlayMachineRouteKey(low8), value);
   }
}

static void prodigyBuildOverlayDesiredHostedIngressRoutes(const SwitchboardOverlayRoutingConfig& config,
   Vector<std::pair<switchboard_overlay_prefix4_key, switchboard_overlay_hosted_ingress_route4>>& desiredRoutes4,
   Vector<std::pair<switchboard_overlay_prefix6_key, switchboard_overlay_hosted_ingress_route6>>& desiredRoutes6)
{
   switchboardBuildOverlayHostedIngressRouteEntries(config.hostedIngressRoutes, desiredRoutes4, desiredRoutes6);
}

static void prodigySyncOverlayEgressRoutingProgram(BPFProgram *program,
   const SwitchboardOverlayRoutingConfig& config,
   Vector<switchboard_overlay_prefix4_key>& installedPrefixes4,
   Vector<switchboard_overlay_prefix6_key>& installedPrefixes6,
   Vector<switchboard_overlay_machine_route_key>& installedRouteKeysFull,
   Vector<switchboard_overlay_machine_route_key>& installedRouteKeysLow8,
   Vector<switchboard_overlay_prefix4_key>& installedHostedIngressRouteKeys4,
   Vector<switchboard_overlay_prefix6_key>& installedHostedIngressRouteKeys6)
{
   Vector<switchboard_overlay_prefix4_key> desiredPrefixes4 = {};
   Vector<switchboard_overlay_prefix6_key> desiredPrefixes6 = {};
   switchboardBuildOverlayPrefixKeys(config.overlaySubnets, desiredPrefixes4, desiredPrefixes6);

   prodigySyncOverlayPresenceMap(program,
      "overlay_routable_prefixes4"_ctv,
      installedPrefixes4,
      desiredPrefixes4,
      [] (const switchboard_overlay_prefix4_key& lhs, const switchboard_overlay_prefix4_key& rhs) -> bool {

         return switchboardOverlayPrefix4Equals(lhs, rhs);
      });
   prodigySyncOverlayPresenceMap(program,
      "overlay_routable_prefixes6"_ctv,
      installedPrefixes6,
      desiredPrefixes6,
      [] (const switchboard_overlay_prefix6_key& lhs, const switchboard_overlay_prefix6_key& rhs) -> bool {

         return switchboardOverlayPrefix6Equals(lhs, rhs);
      });

   Vector<std::pair<switchboard_overlay_machine_route_key, switchboard_overlay_machine_route>> desiredRoutesFull = {};
   Vector<std::pair<switchboard_overlay_machine_route_key, switchboard_overlay_machine_route>> desiredRoutesLow8 = {};
   prodigyBuildOverlayDesiredRoutes(config, desiredRoutesFull, desiredRoutesLow8);

   prodigySyncOverlayValueMap(program,
      "overlay_machine_routes_full"_ctv,
      installedRouteKeysFull,
      desiredRoutesFull,
      [] (const switchboard_overlay_machine_route_key& lhs, const switchboard_overlay_machine_route_key& rhs) -> bool {

         return switchboardOverlayMachineRouteKeyEquals(lhs, rhs);
      });
   prodigySyncOverlayValueMap(program,
      "overlay_machine_routes_low8"_ctv,
      installedRouteKeysLow8,
      desiredRoutesLow8,
      [] (const switchboard_overlay_machine_route_key& lhs, const switchboard_overlay_machine_route_key& rhs) -> bool {

         return switchboardOverlayMachineRouteKeyEquals(lhs, rhs);
      });

   Vector<std::pair<switchboard_overlay_prefix4_key, switchboard_overlay_hosted_ingress_route4>> desiredHostedIngressRoutes4 = {};
   Vector<std::pair<switchboard_overlay_prefix6_key, switchboard_overlay_hosted_ingress_route6>> desiredHostedIngressRoutes6 = {};
   prodigyBuildOverlayDesiredHostedIngressRoutes(config, desiredHostedIngressRoutes4, desiredHostedIngressRoutes6);

   prodigySyncOverlayValueMap(program,
      "overlay_hosted_ingress_routes4"_ctv,
      installedHostedIngressRouteKeys4,
      desiredHostedIngressRoutes4,
      [] (const switchboard_overlay_prefix4_key& lhs, const switchboard_overlay_prefix4_key& rhs) -> bool {

         return switchboardOverlayPrefix4Equals(lhs, rhs);
      });
   prodigySyncOverlayValueMap(program,
      "overlay_hosted_ingress_routes6"_ctv,
      installedHostedIngressRouteKeys6,
      desiredHostedIngressRoutes6,
      [] (const switchboard_overlay_prefix6_key& lhs, const switchboard_overlay_prefix6_key& rhs) -> bool {

         return switchboardOverlayPrefix6Equals(lhs, rhs);
      });

   if (program)
   {
      switchboard_overlay_config overlayConfig = {};
      overlayConfig.container_network_enabled = config.containerNetworkViaOverlay ? 1 : 0;
      program->setArrayElement("overlay_config_map"_ctv, 0, overlayConfig);
   }
}

static bool bringContainerLoopbackUp(int peernetnsfd, int hostnetnsfd, uint64_t containerUUID, String *failureReport = nullptr)
{
   NetDevice loopback;
   loopback.name.assign("lo"_ctv);
   loopback.moveSocketToNamespace(peernetnsfd, hostnetnsfd);
   loopback.getInfo();

   if (loopback.ifidx == 0)
   {
      if (failureReport)
      {
         failureReport->snprintf<"failed to resolve loopback device for container {itoa}"_ctv>(containerUUID);
      }

      basics_log("container loopback setup failed uuid=%llu reason=resolve-loopback\n",
         (unsigned long long)containerUUID);
      return false;
   }

   loopback.bringUp();
   return true;
}

static void removeAddressFromDevice(NetDevice& device, const IPPrefix& prefix)
{
   char addressText[INET6_ADDRSTRLEN] = {0};
   if (prefix.network.is6)
   {
      if (inet_ntop(AF_INET6, prefix.network.v6, addressText, sizeof(addressText)) == nullptr)
      {
         return;
      }

      String address;
      address.assign(addressText);
      device.removeIP(address, prefix.cidr, AF_INET6);
      return;
   }

   if (inet_ntop(AF_INET, prefix.network.v6, addressText, sizeof(addressText)) == nullptr)
   {
      return;
   }

   String address;
   address.assign(addressText);
   device.removeIP(address, prefix.cidr, AF_INET);
}

static bool hasAddress(const Vector<IPPrefix>& addresses, const IPPrefix& candidate)
{
   for (const IPPrefix& prefix : addresses)
   {
      if (prefix.equals(candidate))
      {
         return true;
      }
   }

   return false;
}

template <typename T>
static bool needsAnyExternalAddressFamily(const T& value, ExternalAddressFamily family)
{
   bool is6 = (family == ExternalAddressFamily::ipv6);

   for (const Wormhole& wormhole : value.wormholes)
   {
      if (wormhole.externalAddress.is6 == is6)
      {
         return true;
      }
   }

   for (const Whitehole& need : value.whiteholes)
   {
      if (need.family == family)
      {
         return true;
      }
   }

   return false;
}

static void addAddressIfMissing(Vector<IPPrefix>& addresses, const IPPrefix& candidate)
{
   if (hasAddress(addresses, candidate) == false)
   {
      addresses.emplace_back(candidate);
   }
}

#if NAMETAG_PRODIGY_DEV_FAKE_IPV4_ROUTE
static bool devFakeIPv4ModeEnabled(void)
{
   const char *mode = getenv("PRODIGY_DEV_FAKE_IPV4_MODE");
   return (mode && mode[0] == '1' && mode[1] == '\0');
}
#endif

static bool writeProcSysctlValue(const char *path, const char *value)
{
   if (path == nullptr || value == nullptr)
   {
      return false;
   }

   int fd = open(path, O_WRONLY | O_CLOEXEC);
   if (fd < 0)
   {
      return false;
   }

   size_t length = strlen(value);
   bool ok = (write(fd, value, length) == ssize_t(length));
   close(fd);
   return ok;
}

static std::filesystem::path prodigyFilesystemPathFromString(const String& path)
{
   String pathText = {};
   pathText.assign(path);
   return std::filesystem::path(pathText.c_str());
}

static String prodigyStringFromFilesystemPath(const std::filesystem::path& path)
{
   String value = {};
   value.assign(path.c_str());
   return value;
}

static void enableWhiteholeNonlocalBind(const ContainerPlan& plan)
{
   bool needs4 = false;
   bool needs6 = false;

   for (const Whitehole& whitehole : plan.whiteholes)
   {
      if (whitehole.family == ExternalAddressFamily::ipv4)
      {
         needs4 = true;
      }
      else
      {
         needs6 = true;
      }
   }

   if (needs4)
   {
      (void)writeProcSysctlValue("/proc/sys/net/ipv4/ip_nonlocal_bind", "1");
   }

   if (needs6)
   {
      (void)writeProcSysctlValue("/proc/sys/net/ipv6/ip_nonlocal_bind", "1");
   }
}

class Container : public UnixStream, public WaitableProcess {
public:

   class StorageLoopDevice {
   public:

      String mountPath;
      String backingFilePath;
      String loopDevicePath;
      uint64_t sizeMB = 0;
   };

   enum class ResourceDeltaMode : uint8_t {
      none = 0,
      upscale,
      downscale
   };

   ContainerPlan plan;
   uint64_t neuronScalingDimensionsMask = 0;
   uint32_t neuronMetricsCadenceMs = 0;
   TimeoutPacket *killSwitch = nullptr; // must be a pointer otherwise if they container gets destroyed the packet is also destroyed 
   TimeoutPacket *resourceDeltaTimer = nullptr;
   String name;
   CoroutineStack *resumeAfterShutdown = nullptr; // we could make this an array someday if need be
   NetkitPair netdevs;
   pid_t pid = -1;
   int pidfd = -1;
   uint16_t lcores[256];
   int cgroup = -1;
   uint32_t userID = 0;
   bool killedOnPurpose = false;
   bool pendingKillAckToBrain = false;
   bool pendingDestroy = false;
   bool failedArtifactsPreserved = false;
   bool deleteStorageOnCleanUp = true;
   bool storageUsesLoopFilesystem = false;
   ResourceDeltaMode resourceDeltaMode = ResourceDeltaMode::none;
   uint16_t pendingDeltaLogicalCores = 0;
   uint32_t pendingDeltaMemoryMB = 0;
   uint32_t pendingDeltaStorageMB = 0;
   String artifactRootPath;
   String rootfsPath;
   String executePath;
   Vector<String> executeArgs;
   Vector<String> executeEnv;
   String executeCwd;
   MachineCpuArchitecture executeArchitecture = MachineCpuArchitecture::unknown;
   String storageRootPath;
   String storagePayloadPath;
   Vector<StorageLoopDevice> storageLoopDevices;

   BPFProgram *peer_program = nullptr;
   BPFProgram *primary_program = nullptr;
   Vector<switchboard_overlay_prefix4_key> installedPeerOverlayPrefixes4 = {};
   Vector<switchboard_overlay_prefix6_key> installedPeerOverlayPrefixes6 = {};
   Vector<switchboard_overlay_machine_route_key> installedPeerOverlayRouteKeysFull = {};
   Vector<switchboard_overlay_machine_route_key> installedPeerOverlayRouteKeysLow8 = {};
   Vector<switchboard_overlay_prefix4_key> installedPeerHostedIngressRouteKeys4 = {};
   Vector<switchboard_overlay_prefix6_key> installedPeerHostedIngressRouteKeys6 = {};

private:

   static bool writeContainerDeviceMapEntry(int mapFD, uint32_t fragment, uint32_t ifidx, const char *scope, uint64_t ownerUUID, String *failureReport = nullptr)
   {
      if (mapFD < 0)
      {
         basics_log("containerDeviceMap missing scope=%s owner=%llu fragment=%u ifidx=%u\n",
            (scope ? scope : "unknown"),
            (unsigned long long)ownerUUID,
            unsigned(fragment),
            unsigned(ifidx));
         if (failureReport && failureReport->size() == 0)
         {
            failureReport->assign("container device map missing"_ctv);
         }
         return false;
      }

      if (bpf_map_update_elem(mapFD, &fragment, &ifidx, BPF_ANY) != 0)
      {
         basics_log("containerDeviceMap update failed scope=%s owner=%llu fragment=%u ifidx=%u errno=%d(%s)\n",
            (scope ? scope : "unknown"),
            (unsigned long long)ownerUUID,
            unsigned(fragment),
            unsigned(ifidx),
            errno,
            strerror(errno));
         if (failureReport && failureReport->size() == 0)
         {
            failureReport->assign("container device map update failed"_ctv);
         }
         return false;
      }

      uint32_t readback = 0;
      if (bpf_map_lookup_elem(mapFD, &fragment, &readback) != 0 || readback != ifidx)
      {
         int lookupErrno = errno;
         basics_log("containerDeviceMap readback failed scope=%s owner=%llu fragment=%u wrote=%u read=%u errno=%d(%s)\n",
            (scope ? scope : "unknown"),
            (unsigned long long)ownerUUID,
            unsigned(fragment),
            unsigned(ifidx),
            unsigned(readback),
            lookupErrno,
            strerror(lookupErrno));
         if (failureReport && failureReport->size() == 0)
         {
            failureReport->assign("container device map readback failed"_ctv);
         }
         return false;
      }

      return true;
   }

   static bool syncContainerDeviceMapForProgram(BPFProgram *program, uint64_t ownerUUID, uint32_t nicIfidx, bool includeNIC, Container *extraContainer = nullptr, Container *excludedContainer = nullptr, String *failureReport = nullptr)
   {
      if (program == nullptr || thisNeuron == nullptr)
      {
         return true;
      }

      bool ok = true;
      program->openMap("container_device_map"_ctv, [&] (int mapFD) -> void {
         bool traceHostIngress = (ownerUUID == 0);

         if (mapFD < 0)
         {
            basics_log("containerDeviceMap open failed owner=%llu includeNIC=%d\n",
               (unsigned long long)ownerUUID,
               int(includeNIC));
            if (failureReport && failureReport->size() == 0)
            {
               failureReport->assign("container device map open failed"_ctv);
            }
            ok = false;
            return;
         }

         if (traceHostIngress)
         {
            struct bpf_map_info mapInfo = {};
            __u32 mapInfoLen = sizeof(mapInfo);
            String traceLine = {};
            if (bpf_map_get_info_by_fd(mapFD, &mapInfo, &mapInfoLen) == 0)
            {
               traceLine.snprintf<"containerDeviceMap sync begin owner={} includeNIC={} map_fd={} map_id={} map_name={} containers={} extra={} excluded={} nic={}"_ctv>(
                  ownerUUID,
                  int(includeNIC),
                  mapFD,
                  uint32_t(mapInfo.id),
                  String(mapInfo.name),
                  uint64_t(thisNeuron->containers.size()),
                  uint64_t(extraContainer ? extraContainer->plan.uuid : 0),
                  uint64_t(excludedContainer ? excludedContainer->plan.uuid : 0),
                  nicIfidx);
            }
            else
            {
               traceLine.snprintf<"containerDeviceMap sync begin owner={} includeNIC={} map_fd={} map_info_errno={}({}) containers={} extra={} excluded={} nic={}"_ctv>(
                  ownerUUID,
                  int(includeNIC),
                  mapFD,
                  errno,
                  String(strerror(errno)),
                  uint64_t(thisNeuron->containers.size()),
                  uint64_t(extraContainer ? extraContainer->plan.uuid : 0),
                  uint64_t(excludedContainer ? excludedContainer->plan.uuid : 0),
                  nicIfidx);
            }
            prodigyAppendAttachTrace(traceLine);
         }

         for (uint32_t fragment = 0; fragment < 256; fragment += 1)
         {
            uint32_t desiredIfidx = (includeNIC && fragment == 0) ? nicIfidx : 0;

            auto considerContainer = [&] (Container *container) -> void {
               if (container == nullptr
                  || container == excludedContainer
                  || container->plan.useHostNetworkNamespace
                  || container->netdevs.areActive() == false)
               {
                  return;
               }

               if (container->plan.fragment == fragment)
               {
                  desiredIfidx = container->netdevs.host.ifidx;
               }
            };

            for (const auto& [uuid, container] : thisNeuron->containers)
            {
               considerContainer(container);
            }

            considerContainer(extraContainer);

            if (traceHostIngress && desiredIfidx != 0)
            {
               String traceLine = {};
               traceLine.snprintf<"containerDeviceMap sync write owner={} fragment={} ifidx={} includeNIC={}"_ctv>(
                  ownerUUID,
                  fragment,
                  desiredIfidx,
                  int(includeNIC));
               prodigyAppendAttachTrace(traceLine);
            }

            if (writeContainerDeviceMapEntry(mapFD, fragment, desiredIfidx, "container_device_map", ownerUUID, failureReport) == false)
            {
               ok = false;
            }
         }
      });

      return ok;
   }

   static bool syncContainerDeviceMaps(Container *extraContainer = nullptr, Container *excludedContainer = nullptr, String *failureReport = nullptr)
   {
      if (thisNeuron == nullptr)
      {
         return true;
      }

      bool ok = true;

      if (thisNeuron->tcx_ingress_program)
      {
         ok = syncContainerDeviceMapForProgram(thisNeuron->tcx_ingress_program, 0, 0, false, extraContainer, excludedContainer, failureReport) && ok;
      }

      auto syncEgressProgram = [&] (Container *container) -> void {
         if (container == nullptr
            || container == excludedContainer
            || container->plan.useHostNetworkNamespace
            || container->netdevs.areActive() == false
            || container->peer_program == nullptr)
         {
            return;
         }

         ok = syncContainerDeviceMapForProgram(container->peer_program,
            container->plan.uuid,
            thisNeuron->eth.ifidx,
            true,
            extraContainer,
            excludedContainer,
            failureReport) && ok;
      };

      for (const auto& [uuid, container] : thisNeuron->containers)
      {
         syncEgressProgram(container);
      }

      syncEgressProgram(extraContainer);

      return ok;
   }

public:

   void syncPeerOverlayRoutingProgram(void)
   {
      if (thisNeuron == nullptr)
      {
         return;
      }

      const SwitchboardOverlayRoutingConfig *overlayConfig = thisNeuron->overlayRoutingConfigForContainerNetworking();
      if (overlayConfig == nullptr)
      {
         return;
      }

      prodigySyncOverlayEgressRoutingProgram(peer_program,
         *overlayConfig,
         installedPeerOverlayPrefixes4,
         installedPeerOverlayPrefixes6,
         installedPeerOverlayRouteKeysFull,
         installedPeerOverlayRouteKeysLow8,
         installedPeerHostedIngressRouteKeys4,
         installedPeerHostedIngressRouteKeys6);
   }

   // rescheduleIfCrashes == false for canaries, true otherwise under the justification these would be extensively tested binaries
   // triggering rare edge cases that are unlikely to be triggered again, AND we have an entire fleet running
   // this binary, so if this is bad those are bad too, and we can't take our app offline. this is the best choice
   // while we triage.

   void closeSocket(void)
   {
      if (Ring::socketIsClosing(this))
      {
         return;
      }

      if (isFixedFile)
      {
         if (fslot >= 0)
         {
            Ring::queueClose(this);
         }
         return;
      }

      // fd/fslot are a union; negative slot means no active descriptor.
      if (fslot < 0)
      {
         return;
      }

      basics_log("Container::closeSocket expected fixed-file socket uuid=%llu fd=%d fslot=%d\n",
         (unsigned long long)plan.uuid, fd, fslot);
      std::abort();
   }

   void enableKillSwitch(void)
   {
      killedOnPurpose = true;

      killSwitch = new TimeoutPacket();
      killSwitch->setTimeoutMs(plan.config.sTilKillable * 1000);

      killSwitch->identifier = plan.uuid;
      killSwitch->flags = uint64_t(NeuronTimeoutFlags::killContainer);
      // Route timeout to the Neuron instance, which is registered as a multiplexee
      killSwitch->originator = thisNeuron;

      Ring::queueTimeout(killSwitch);
   }

   void stop(void)
   {
      // there's no advantage sending it a signal... which is a dumb 1 dimensional kill signal
      // since the signal will get handled through the same event loop as socket messages. so
      // we might as well just send a complex message

      // we MIGHT want to create a process for a coordinated handoff of resources from an old version of an application to a new one
      Message::construct(wBuffer, ContainerTopic::stop); 
      Ring::queueSend(this);

      // set a timer after which if the pid is still active, we SIGKILL it
      enableKillSwitch();
   }

   void disableKillSwitch(void)
   {
      if (killSwitch) Ring::queueCancelTimeout(killSwitch);
   }

   void ping(void)
   {
      Message::construct(wBuffer, ContainerTopic::ping);
      Ring::queueSend(this);
   }

// configuration

   bool restoreNetwork(String *failureReport = nullptr)
   {
      int hostnetnsfd = Filesystem::openFileAt(-1, "/proc/self/ns/net"_ctv, O_RDONLY);

      String path;
      path.snprintf<"/proc/{itoa}/ns/net"_ctv>(pid);
      int peernetnsfd = Filesystem::openFileAt(-1, path, O_RDONLY);

      netdevs.setNames(String{plan.fragment});
      netdevs.peer.moveSocketToNamespace(peernetnsfd, hostnetnsfd);
      if (bringContainerLoopbackUp(peernetnsfd, hostnetnsfd, plan.uuid, failureReport) == false)
      {
         if (peernetnsfd >= 0) ::close(peernetnsfd);
         if (hostnetnsfd >= 0) ::close(hostnetnsfd);
         return false;
      }
      netdevs.getInfo();

      // Container netkit routers are neuron runtime infrastructure, not per-image artifacts.
      struct container_network_policy networkPolicy = {};
      networkPolicy.requiresPublic4 = needsAnyExternalAddressFamily(plan, ExternalAddressFamily::ipv4) ? 1 : 0;
      networkPolicy.requiresPublic6 = needsAnyExternalAddressFamily(plan, ExternalAddressFamily::ipv6) ? 1 : 0;

      path.assign("/root/prodigy/container.egress.router.ebpf.o"_ctv);
      peer_program = netdevs.host.loadPreattachedProgram(prodigyContainerEgressNetkitAttachType(), path);
      if (peer_program)
      {
         peer_program->setArrayElement("local_container_subnet_map"_ctv, 0, thisNeuron->lcsubnet6);
         peer_program->setArrayElement("mac_map"_ctv, 0, thisNeuron->eth.mac);
         peer_program->setArrayElement("gateway_mac_map"_ctv, 0, thisNeuron->eth.gateway_mac);
         peer_program->setArrayElement("container_network_policy_map"_ctv, 0, networkPolicy);
      }

      path.assign("/root/prodigy/container.ingress.router.ebpf.o"_ctv);
      primary_program = netdevs.host.loadPreattachedProgram(prodigyContainerIngressNetkitAttachType(), path);
      if (primary_program)
      {
         primary_program->setArrayElement("container_network_policy_map"_ctv, 0, networkPolicy);
      }

      bool synced = syncContainerDeviceMaps(this, nullptr, failureReport);
      if (synced)
      {
         syncPeerOverlayRoutingProgram();
         thisNeuron->syncContainerSwitchboardRuntime(this);
      }

      if (peernetnsfd >= 0) ::close(peernetnsfd);
      if (hostnetnsfd >= 0) ::close(hostnetnsfd);

      return synced;
   }

   bool setupNetwork(String *failureReport = nullptr)
   {
      int hostnetnsfd = Filesystem::openFileAt(-1, "/proc/self/ns/net"_ctv, O_RDONLY);
      if (hostnetnsfd < 0)
      {
         if (failureReport) failureReport->snprintf<"failed to open host netns for container {itoa}: {}"_ctv>(plan.uuid, String(strerror(errno)));
         basics_log("setupNetwork failed uuid=%llu reason=open-host-netns errno=%d(%s)\n",
            (unsigned long long)plan.uuid, errno, strerror(errno));
         return false;
      }

      String path;
      path.snprintf<"/proc/{itoa}/ns/net"_ctv>(pid);
      int peernetnsfd = Filesystem::openFileAt(-1, path, O_RDONLY);
      if (peernetnsfd < 0)
      {
         if (failureReport) failureReport->snprintf<"failed to open peer netns for container {itoa}: {}"_ctv>(plan.uuid, String(strerror(errno)));
         basics_log("setupNetwork failed uuid=%llu reason=open-peer-netns path=%s errno=%d(%s)\n",
            (unsigned long long)plan.uuid, path.c_str(), errno, strerror(errno));
         if (hostnetnsfd >= 0) ::close(hostnetnsfd);
         return false;
      }

      netdevs.createPair(pid);
      netdevs.peer.moveSocketToNamespace(peernetnsfd, hostnetnsfd);
      if (bringContainerLoopbackUp(peernetnsfd, hostnetnsfd, plan.uuid, failureReport) == false)
      {
         if (peernetnsfd >= 0) ::close(peernetnsfd);
         if (hostnetnsfd >= 0) ::close(hostnetnsfd);
         return false;
      }
      netdevs.getInfo();

      auto& host = netdevs.host;
      auto& peer = netdevs.peer;

      host.bringUp();
      peer.bringUp();

      for (const IPPrefix& prefix : plan.addresses)
      {
         peer.addIP(prefix);
      }

      peer.addDefaultRoutes();

      // Mesh subscriptions target datacenter-scoped container IPv6s (prefix11 + dpfx + machine + fragment).
      // Add datacenter-wide /96 routes so cross-machine container traffic is routable from this netns.
      installDatacenterMeshRoutes(peer, thisNeuron->lcsubnet6.dpfx);

   // add us to host map
      if (thisNeuron->ensureHostNetworkingReady(failureReport) == false)
      {
         if (peernetnsfd >= 0) ::close(peernetnsfd);
         if (hostnetnsfd >= 0) ::close(hostnetnsfd);
         return false;
      }

      if (thisNeuron->tcx_ingress_program == nullptr || thisNeuron->tcx_egress_program == nullptr)
      {
         if (failureReport)
         {
            failureReport->snprintf<"container veth networking requires host router bpf programs for container {itoa}"_ctv>(plan.uuid);
         }
         basics_log("setupNetwork failed uuid=%llu reason=missing-host-router-bpf ingress=%d egress=%d\n",
            (unsigned long long)plan.uuid,
            int(thisNeuron->tcx_ingress_program != nullptr),
            int(thisNeuron->tcx_egress_program != nullptr));
         if (peernetnsfd >= 0) ::close(peernetnsfd);
         if (hostnetnsfd >= 0) ::close(hostnetnsfd);
         return false;
      }

      path.assign("/root/prodigy/container.egress.router.ebpf.o"_ctv);
      peer_program = host.attachBPF(prodigyContainerEgressNetkitAttachType(), path, "container_egress_router"_ctv);
      if (peer_program == nullptr)
      {
         if (failureReport) failureReport->snprintf<"failed to attach container egress bpf for container {itoa} path={}"_ctv>(plan.uuid, path);
         basics_log("setupNetwork failed uuid=%llu reason=attach-container-egress-bpf path=%s\n",
            (unsigned long long)plan.uuid, path.c_str());
         if (peernetnsfd >= 0) ::close(peernetnsfd);
         if (hostnetnsfd >= 0) ::close(hostnetnsfd);
         return false;
      }

      struct container_network_policy networkPolicy = {};
      networkPolicy.requiresPublic4 = needsAnyExternalAddressFamily(plan, ExternalAddressFamily::ipv4) ? 1 : 0;
      networkPolicy.requiresPublic6 = needsAnyExternalAddressFamily(plan, ExternalAddressFamily::ipv6) ? 1 : 0;
      peer_program->setArrayElement("local_container_subnet_map"_ctv, 0, thisNeuron->lcsubnet6);
      peer_program->setArrayElement("mac_map"_ctv, 0, thisNeuron->eth.mac);
      peer_program->setArrayElement("gateway_mac_map"_ctv, 0, thisNeuron->eth.gateway_mac);
      peer_program->setArrayElement("container_network_policy_map"_ctv, 0, networkPolicy);
      
      path.assign("/root/prodigy/container.ingress.router.ebpf.o"_ctv);
      primary_program = host.attachBPF(prodigyContainerIngressNetkitAttachType(), path, "container_ingress_router"_ctv);
      if (primary_program == nullptr)
      {
         if (failureReport) failureReport->snprintf<"failed to attach container ingress bpf for container {itoa} path={}"_ctv>(plan.uuid, path);
         basics_log("setupNetwork failed uuid=%llu reason=attach-container-ingress-bpf path=%s\n",
            (unsigned long long)plan.uuid, path.c_str());
         if (peernetnsfd >= 0) ::close(peernetnsfd);
         if (hostnetnsfd >= 0) ::close(hostnetnsfd);
         return false;
      }
      primary_program->setArrayElement("container_network_policy_map"_ctv, 0, networkPolicy);

      if (syncContainerDeviceMaps(this, nullptr, failureReport) == false)
      {
         if (peernetnsfd >= 0) ::close(peernetnsfd);
         if (hostnetnsfd >= 0) ::close(hostnetnsfd);
         return false;
      }

      syncPeerOverlayRoutingProgram();
      thisNeuron->syncContainerSwitchboardRuntime(this);

      if (peernetnsfd >= 0) ::close(peernetnsfd);
      if (hostnetnsfd >= 0) ::close(hostnetnsfd);
      return true;
   }

   void cleanupNetwork(void)
   {
      if (plan.useHostNetworkNamespace)
      {
         for (const IPPrefix& prefix : plan.addresses)
         {
            removeAddressFromDevice(thisNeuron->eth, prefix);
         }
      }

      (void)syncContainerDeviceMaps(nullptr, this);

      if (peer_program) peer_program->close();
      if (primary_program) primary_program->close();
      if (netdevs.areActive()) netdevs.destroyPair();
   }
};

class ContainerRegistry {
private:

   static inline bytell_hash_map<uint64_t, uint32_t> log;

public:

   static void retain(uint64_t deploymentID)
   {
      log[deploymentID] += 1;
   }

   static void pop(Container *container)
   {
      uint64_t deploymentID = container->plan.config.deploymentID();

      if (--log[deploymentID] == 0 && ContainerStore::autoDestroy)
      {
         ContainerStore::destroy(deploymentID);
      }
   }
};

class ContainerManager {
private:

   int slicefd;
   static inline bool rootCgroupSeeded = false;
   static inline bool sigchldWaitabilityEnsured = false;

   static void ensureSigchldIsWaitable(void)
   {
      if (sigchldWaitabilityEnsured)
      {
         return;
      }

      // Guardian defaults SIGCHLD to SIG_IGN globally; container lifecycle
      // supervision relies on waitid/waitpid semantics, so keep SIGCHLD waitable.
      struct sigaction currentSigChld {};
      if (sigaction(SIGCHLD, nullptr, &currentSigChld) != 0)
      {
         return;
      }

      if (currentSigChld.sa_handler == SIG_IGN)
      {
         struct sigaction defaultSigChld {};
         sigemptyset(&defaultSigChld.sa_mask);
         defaultSigChld.sa_handler = SIG_DFL;
         defaultSigChld.sa_flags = 0;
         sigaction(SIGCHLD, &defaultSigChld, nullptr);
      }

      sigchldWaitabilityEnsured = true;
   }

   static void trimTrailingWhitespace(String& text)
   {
      while (text.size() > 0)
      {
         uint8_t tail = text[text.size() - 1];
         if (tail == ' ' || tail == '\n' || tail == '\r' || tail == '\t')
         {
            text.resize(text.size() - 1);
            continue;
         }

         break;
      }
   }

   static constexpr uint64_t maxCompressedContainerBlobBytes = prodigyContainerRuntimeLimits.maxCompressedBlobBytes;
   static constexpr uint64_t maxContainerArtifactRegularFileBytes = prodigyContainerRuntimeLimits.maxArtifactBytes;
   static constexpr uint64_t maxLaunchMetadataBytes = prodigyContainerRuntimeLimits.maxLaunchMetadataBytes;
   static constexpr uint64_t maxPendingCreateMarkerBytes = prodigyContainerRuntimeLimits.maxPendingCreateMarkerBytes;
   static constexpr uint64_t maxLaunchMetadataStringBytes = prodigyContainerRuntimeLimits.maxLaunchMetadataEntryBytes;
   static constexpr uint64_t maxLaunchMetadataPathBytes = prodigyContainerRuntimeLimits.maxLaunchMetadataPathBytes;
   static constexpr uint64_t maxLaunchMetadataArchBytes = prodigyContainerRuntimeLimits.maxLaunchMetadataArchitectureBytes;
   static constexpr uint32_t maxLaunchMetadataArgs = prodigyContainerRuntimeLimits.maxLaunchMetadataArrayEntries;
   static constexpr uint32_t maxLaunchMetadataEnv = prodigyContainerRuntimeLimits.maxLaunchMetadataArrayEntries;
   static constexpr uint32_t maxContainerArtifactEntries = prodigyContainerRuntimeLimits.maxArtifactEntries;

   static bool parseLaunchMetadataStringArray(
      const simdjson::dom::element& value,
      const String& fieldName,
      uint32_t maxEntries,
      Vector<String>& output,
      String *failureReport = nullptr)
   {
      output.clear();
      if (value.type() != simdjson::dom::element_type::ARRAY)
      {
         if (failureReport)
         {
            failureReport->snprintf<"launch metadata {} must be an array"_ctv>(fieldName);
         }

         return false;
      }

      uint32_t entryCount = 0;
      for (auto item : value.get_array())
      {
         if (entryCount >= maxEntries)
         {
            if (failureReport)
            {
               failureReport->snprintf<"launch metadata {} must contain at most {itoa} entries"_ctv>(fieldName, maxEntries);
            }

            output.clear();
            return false;
         }

         if (item.type() != simdjson::dom::element_type::STRING)
         {
            if (failureReport)
            {
               failureReport->snprintf<"launch metadata {} entries must be strings"_ctv>(fieldName);
            }

            output.clear();
            return false;
         }

         String entry = {};
         entry.assign(item.get_c_str());
         if (entry.size() > maxLaunchMetadataStringBytes)
         {
            if (failureReport)
            {
               failureReport->snprintf<"launch metadata {} entries must be at most {itoa} bytes"_ctv>(
                  fieldName,
                  uint32_t(maxLaunchMetadataStringBytes));
            }

            output.clear();
            return false;
         }

         output.push_back(entry);
         entryCount += 1;
      }

      return true;
   }

   static bool readOpenFileDescriptorIntoString(int fd, String& output, uint64_t maxBytes, String *failureReport = nullptr)
   {
      output.clear();
      if (fd < 0)
      {
         if (failureReport) failureReport->assign("file descriptor is invalid"_ctv);
         return false;
      }

      struct stat statbuf = {};
      if (fstat(fd, &statbuf) != 0)
      {
         if (failureReport) failureReport->snprintf<"fstat failed errno={}({})"_ctv>(errno, String(strerror(errno)));
         return false;
      }

      if (S_ISREG(statbuf.st_mode) == 0)
      {
         if (failureReport) failureReport->assign("file descriptor does not reference a regular file"_ctv);
         return false;
      }

      if (lseek(fd, 0, SEEK_SET) < 0)
      {
         if (failureReport) failureReport->snprintf<"lseek failed errno={}({})"_ctv>(errno, String(strerror(errno)));
         return false;
      }

      uint64_t fileBytes = (statbuf.st_size > 0) ? uint64_t(statbuf.st_size) : 0;
      if (maxBytes > 0 && fileBytes > maxBytes)
      {
         if (failureReport) failureReport->snprintf<"file exceeds maximum size {} bytes"_ctv>(maxBytes);
         return false;
      }

      if (fileBytes > 0)
      {
         output.need(fileBytes);
      }

      while (true)
      {
         if (output.remainingCapacity() == 0)
         {
            if (maxBytes > 0 && output.size() >= maxBytes)
            {
               if (failureReport) failureReport->snprintf<"file exceeds maximum size {} bytes"_ctv>(maxBytes);
               output.clear();
               return false;
            }

            uint64_t growBy = 4096;
            if (maxBytes > 0)
            {
               growBy = std::min<uint64_t>(growBy, maxBytes - output.size());
            }

            if (output.need(growBy) == false)
            {
               if (failureReport) failureReport->assign("failed to reserve buffer for file read"_ctv);
               return false;
            }
         }

         ssize_t bytesRead = read(fd, output.pTail(), output.remainingCapacity());
         if (bytesRead == 0)
         {
            break;
         }

         if (bytesRead < 0)
         {
            if (errno == EINTR)
            {
               continue;
            }

            if (failureReport) failureReport->snprintf<"read failed errno={}({})"_ctv>(errno, String(strerror(errno)));
            output.clear();
            return false;
         }

         if (maxBytes > 0 && (output.size() + uint64_t(bytesRead)) > maxBytes)
         {
            if (failureReport) failureReport->snprintf<"file exceeds maximum size {} bytes"_ctv>(maxBytes);
            output.clear();
            return false;
         }

         output.advance(bytesRead);
      }

      return true;
   }

   static bool validateNormalizedAbsoluteContainerPath(const String& path, const String& fieldName, bool allowRoot, String *failureReport = nullptr)
   {
      if (path.size() == 0 || path[0] != '/')
      {
         if (failureReport) failureReport->snprintf<"launch metadata {} must be absolute"_ctv>(fieldName);
         return false;
      }

      if (path.size() == 1)
      {
         if (allowRoot)
         {
            return true;
         }

         if (failureReport) failureReport->snprintf<"launch metadata {} must not resolve to the container root directory"_ctv>(fieldName);
         return false;
      }

      uint64_t componentStart = 1;
      while (componentStart < path.size())
      {
         uint64_t componentEnd = componentStart;
         while (componentEnd < path.size() && path[componentEnd] != '/')
         {
            componentEnd += 1;
         }

         uint64_t componentSize = componentEnd - componentStart;
         if (componentSize == 0)
         {
            if (failureReport) failureReport->snprintf<"launch metadata {} must be normalized and must not contain empty path components"_ctv>(fieldName);
            return false;
         }

         if (componentSize == 1 && path[componentStart] == '.')
         {
            if (failureReport) failureReport->snprintf<"launch metadata {} must not contain '.' path components"_ctv>(fieldName);
            return false;
         }

         if (componentSize == 2 && path[componentStart] == '.' && path[componentStart + 1] == '.')
         {
            if (failureReport) failureReport->snprintf<"launch metadata {} must not contain '..' path components"_ctv>(fieldName);
            return false;
         }

         componentStart = componentEnd + 1;
      }

      if (path[path.size() - 1] == '/')
      {
         if (failureReport) failureReport->snprintf<"launch metadata {} must be normalized and must not end with '/'"_ctv>(fieldName);
         return false;
      }

      return true;
   }

   static bool containerAbsolutePathToRelative(const String& absolutePath, String& relativePath, const String& fieldName, bool allowRoot, String *failureReport = nullptr)
   {
      relativePath.clear();
      if (validateNormalizedAbsoluteContainerPath(absolutePath, fieldName, allowRoot, failureReport) == false)
      {
         return false;
      }

      if (absolutePath.size() == 1)
      {
         return true;
      }

      relativePath.assign(absolutePath.data() + 1, absolutePath.size() - 1);
      return true;
   }

   static constexpr uint64_t containerExecutionResolveFlags =
      RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS;

   static bool openContainerExecutionPathAt(
      int rootfd,
      const String& absolutePath,
      const String& fieldName,
      bool expectDirectory,
      int& resolvedFD,
      String *failureReport = nullptr)
   {
      resolvedFD = -1;
      if (rootfd < 0)
      {
         if (failureReport) failureReport->assign("container rootfs fd is invalid"_ctv);
         return false;
      }

      String relativePath = {};
      if (containerAbsolutePathToRelative(absolutePath, relativePath, fieldName, expectDirectory, failureReport) == false)
      {
         return false;
      }

      if (relativePath.size() == 0)
      {
         resolvedFD = dup(rootfd);
         if (resolvedFD < 0 && failureReport)
         {
            failureReport->snprintf<"failed to duplicate container rootfs fd for {} errno={}({})"_ctv>(fieldName, errno, String(strerror(errno)));
         }
         return resolvedFD >= 0;
      }

      if (expectDirectory)
      {
         resolvedFD = Filesystem::openDirectoryAt(
            rootfd,
            relativePath,
            O_PATH | O_DIRECTORY | O_CLOEXEC,
            containerExecutionResolveFlags);
      }
      else
      {
         resolvedFD = Filesystem::openFileAt(
            rootfd,
            relativePath,
            O_PATH | O_CLOEXEC,
            0,
            containerExecutionResolveFlags);
      }

      if (resolvedFD < 0 && failureReport)
      {
         failureReport->snprintf<"launch metadata {} does not resolve beneath container rootfs errno={}({})"_ctv>(
            fieldName,
            errno,
            String(strerror(errno)));
      }

      return resolvedFD >= 0;
   }

   static bool validateContainerLaunchTargetsInRootfs(Container *container, int rootfd, String *failureReport = nullptr)
   {
      if (container == nullptr)
      {
         if (failureReport) failureReport->assign("container is null"_ctv);
         return false;
      }

      int executeFD = -1;
      if (openContainerExecutionPathAt(rootfd, container->executePath, "execute_path"_ctv, false, executeFD, failureReport) == false)
      {
         return false;
      }

      struct stat executeStat = {};
      bool executeValid = (fstat(executeFD, &executeStat) == 0
         && S_ISREG(executeStat.st_mode) != 0
         && (executeStat.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0);
      int executeErrno = errno;
      close(executeFD);
      if (executeValid == false)
      {
         if (failureReport)
         {
            failureReport->snprintf<"launch metadata execute_path must resolve to an executable regular file errno={}({})"_ctv>(
               executeErrno,
               String(strerror(executeErrno)));
         }
         return false;
      }

      int cwdFD = -1;
      if (openContainerExecutionPathAt(rootfd, container->executeCwd, "execute_cwd"_ctv, true, cwdFD, failureReport) == false)
      {
         return false;
      }

      struct stat cwdStat = {};
      bool cwdValid = (fstat(cwdFD, &cwdStat) == 0 && S_ISDIR(cwdStat.st_mode) != 0);
      int cwdErrno = errno;
      close(cwdFD);
      if (cwdValid == false)
      {
         if (failureReport)
         {
            failureReport->snprintf<"launch metadata execute_cwd must resolve to a directory beneath container rootfs errno={}({})"_ctv>(
               cwdErrno,
               String(strerror(cwdErrno)));
         }
         return false;
      }

      return true;
   }

   static bool loadContainerLaunchMetadata(Container *container, String *failureReport = nullptr)
   {
      if (failureReport)
      {
         failureReport->clear();
      }

      container->executePath.clear();
      container->executeArgs.clear();
      container->executeEnv.clear();
      container->executeCwd.clear();
      container->executeArchitecture = MachineCpuArchitecture::unknown;

      int artifactRootFD = -1;
      if (openVerifiedContainerArtifactRoot(container, artifactRootFD, failureReport) == false)
      {
         return false;
      }

      int privateFD = Filesystem::openDirectoryAt(
         artifactRootFD,
         ".prodigy-private"_ctv,
         O_RDONLY | O_DIRECTORY | O_CLOEXEC,
         secureContainerResolveFlags);
      if (privateFD < 0)
      {
         if (failureReport) failureReport->snprintf<"failed to open container private metadata directory without following symlinks errno={}({})"_ctv>(errno, String(strerror(errno)));
         close(artifactRootFD);
         return false;
      }

      int metadataFD = Filesystem::openFileAt(
         privateFD,
         "launch.metadata"_ctv,
         O_RDONLY | O_CLOEXEC | O_NOFOLLOW,
         0,
         secureContainerResolveFlags);
      if (metadataFD < 0)
      {
         if (failureReport) failureReport->snprintf<"failed to open launch.metadata without following symlinks errno={}({})"_ctv>(errno, String(strerror(errno)));
         close(privateFD);
         close(artifactRootFD);
         return false;
      }

      String metadataJSON = {};
      String metadataReadFailure = {};
      bool metadataRead = readOpenFileDescriptorIntoString(metadataFD, metadataJSON, maxLaunchMetadataBytes, &metadataReadFailure);
      close(metadataFD);
      close(privateFD);
      close(artifactRootFD);
      if (metadataRead == false)
      {
         if (failureReport)
         {
            failureReport->snprintf<"failed to read launch metadata: {}"_ctv>(metadataReadFailure);
         }

         return false;
      }

      simdjson::dom::parser parser;
      simdjson::dom::element doc;
      simdjson::padded_string paddedMetadata(
         reinterpret_cast<const char *>(metadataJSON.data()),
         metadataJSON.size());
      if (parser.parse(paddedMetadata).get(doc) != simdjson::SUCCESS
         || doc.type() != simdjson::dom::element_type::OBJECT)
      {
         if (failureReport)
         {
            failureReport->assign("launch metadata must be a json object"_ctv);
         }

         return false;
      }

      bool sawExecutePath = false;
      bool sawExecuteArgs = false;
      bool sawExecuteEnv = false;
      bool sawExecuteCwd = false;
      bool sawExecuteArch = false;

      for (auto field : doc.get_object())
      {
         String key = {};
         key.setInvariant(field.key.data(), field.key.size());

         if (key == "execute_path"_ctv)
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               if (failureReport)
               {
                  failureReport->assign("launch metadata execute_path must be a string"_ctv);
               }

               return false;
            }

            container->executePath.assign(field.value.get_c_str());
            if (container->executePath.size() > maxLaunchMetadataPathBytes)
            {
               if (failureReport) failureReport->snprintf<"launch metadata execute_path must be at most {itoa} bytes"_ctv>(uint32_t(maxLaunchMetadataPathBytes));
               return false;
            }
            sawExecutePath = true;
         }
         else if (key == "execute_args"_ctv)
         {
            if (parseLaunchMetadataStringArray(field.value, key, maxLaunchMetadataArgs, container->executeArgs, failureReport) == false)
            {
               return false;
            }

            sawExecuteArgs = true;
         }
         else if (key == "execute_env"_ctv)
         {
            if (parseLaunchMetadataStringArray(field.value, key, maxLaunchMetadataEnv, container->executeEnv, failureReport) == false)
            {
               return false;
            }

            sawExecuteEnv = true;
         }
         else if (key == "execute_cwd"_ctv)
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               if (failureReport)
               {
                  failureReport->assign("launch metadata execute_cwd must be a string"_ctv);
               }

               return false;
            }

            container->executeCwd.assign(field.value.get_c_str());
            if (container->executeCwd.size() > maxLaunchMetadataPathBytes)
            {
               if (failureReport) failureReport->snprintf<"launch metadata execute_cwd must be at most {itoa} bytes"_ctv>(uint32_t(maxLaunchMetadataPathBytes));
               return false;
            }
            sawExecuteCwd = true;
         }
         else if (key == "execute_arch"_ctv)
         {
            if (field.value.type() != simdjson::dom::element_type::STRING)
            {
               if (failureReport)
               {
                  failureReport->assign("launch metadata execute_arch must be a string"_ctv);
               }

               return false;
            }

            String executeArchText = {};
            executeArchText.assign(field.value.get_c_str());
            if (executeArchText.size() > maxLaunchMetadataArchBytes)
            {
               if (failureReport) failureReport->snprintf<"launch metadata execute_arch must be at most {itoa} bytes"_ctv>(uint32_t(maxLaunchMetadataArchBytes));
               return false;
            }
            if (parseMachineCpuArchitecture(executeArchText, container->executeArchitecture) == false
               || prodigyMachineCpuArchitectureSupportedTarget(container->executeArchitecture) == false)
            {
               if (failureReport)
               {
                  failureReport->snprintf<"launch metadata execute_arch {} is not supported"_ctv>(executeArchText);
               }

               container->executeArchitecture = MachineCpuArchitecture::unknown;
               return false;
            }

            sawExecuteArch = true;
         }
         else
         {
            if (failureReport)
            {
               failureReport->snprintf<"launch metadata field {} is not recognized"_ctv>(key);
            }

            return false;
         }
      }

      if (sawExecutePath == false || sawExecuteArgs == false || sawExecuteEnv == false || sawExecuteCwd == false || sawExecuteArch == false)
      {
         if (failureReport)
         {
            failureReport->assign("launch metadata missing one or more required execute_* fields"_ctv);
         }

         return false;
      }

      auto normalizeOwnedString = [] (String& value) -> void
      {
         String owned = {};
         owned.append(value.data(), value.size());
         value = std::move(owned);
      };

      normalizeOwnedString(container->executePath);
      normalizeOwnedString(container->executeCwd);
      for (String& value : container->executeArgs)
      {
         normalizeOwnedString(value);
      }
      for (String& value : container->executeEnv)
      {
         normalizeOwnedString(value);
      }

      if (container->executePath.size() == 0 || container->executePath[0] != '/')
      {
         if (failureReport) failureReport->assign("launch metadata execute_path must be absolute"_ctv);
         return false;
      }

      if (validateNormalizedAbsoluteContainerPath(container->executePath, "execute_path"_ctv, false, failureReport) == false)
      {
         return false;
      }

      if (container->executeCwd.size() == 0 || container->executeCwd[0] != '/')
      {
         if (failureReport) failureReport->assign("launch metadata execute_cwd must be absolute"_ctv);
         return false;
      }

      if (validateNormalizedAbsoluteContainerPath(container->executeCwd, "execute_cwd"_ctv, true, failureReport) == false)
      {
         return false;
      }

      for (const String& assignment : container->executeEnv)
      {
         bool foundEquals = false;
         for (uint64_t index = 0; index < assignment.size(); ++index)
         {
            if (assignment[index] == '=')
            {
               foundEquals = (index > 0);
               break;
            }
         }

         if (foundEquals == false)
         {
            if (failureReport)
            {
               failureReport->snprintf<"launch metadata execute_env entry {} must be KEY=VALUE"_ctv>(assignment);
            }

            return false;
         }
      }

      if (container->plan.config.architecture != MachineCpuArchitecture::unknown
         && container->plan.config.architecture != container->executeArchitecture)
      {
         if (failureReport)
         {
            String executeArchitectureName = {};
            executeArchitectureName.assign(machineCpuArchitectureName(container->executeArchitecture));
            String planArchitectureName = {};
            planArchitectureName.assign(machineCpuArchitectureName(container->plan.config.architecture));
            failureReport->snprintf<"launch metadata execute_arch {} mismatches plan architecture {}"_ctv>(
               executeArchitectureName,
               planArchitectureName);
         }

         return false;
      }

      MachineCpuArchitecture localArchitecture = nametagCurrentBuildMachineArchitecture();
      if (localArchitecture != MachineCpuArchitecture::unknown
         && localArchitecture != container->executeArchitecture)
      {
         if (failureReport)
         {
            String executeArchitectureName = {};
            executeArchitectureName.assign(machineCpuArchitectureName(container->executeArchitecture));
            String localArchitectureName = {};
            localArchitectureName.assign(machineCpuArchitectureName(localArchitecture));
            failureReport->snprintf<"launch metadata execute_arch {} mismatches local machine architecture {}"_ctv>(
               executeArchitectureName,
               localArchitectureName);
         }

         return false;
      }

      return true;
   }

public:
   static int terminalSignalForFailedContainer(const siginfo_t& infop)
   {
      return failedContainerTerminalSignal(infop);
   }

   static bool preserveFailedContainerArtifacts(
      const Container *container,
      const siginfo_t& infop,
      int64_t failureTimeMs,
      int terminalSignal,
      String *retainedBundlePath = nullptr,
      String *failureReport = nullptr)
   {
      return preserveFailedContainerArtifactsWithDefaultRoot(
         container,
         infop,
         failureTimeMs,
         terminalSignal,
         retainedBundlePath,
         failureReport);
   }

   static bool preserveFailedContainerArtifactsIfNeeded(
      Container *container,
      int64_t failureTimeMs,
      String *retainedBundlePath = nullptr,
      String *failureReport = nullptr)
   {
      return preserveFailedContainerArtifactsIfNeededWithDefaultRoot(
         container,
         failureTimeMs,
         retainedBundlePath,
         failureReport);
   }

   static bool cleanupExpiredFailedContainerArtifacts(int64_t nowMs, String *failureReport = nullptr)
   {
      return cleanupExpiredFailedContainerArtifactsWithDefaultRoot(nowMs, failureReport);
   }

#if PRODIGY_DEBUG
   static bool debugCleanupFailedCreateArtifactRoot(Container *container, String *failureReport = nullptr)
   {
      return cleanupFailedCreateArtifactRoot(container, failureReport);
   }

   static bool debugCloseContainerChildPrivilegedFDs(Container *container, String *failureReport = nullptr)
   {
      return closeContainerChildPrivilegedFDs(container, failureReport);
   }

   static bool debugSetContainerNoNewPrivileges(Container *container, String *failureReport = nullptr)
   {
      return setContainerNoNewPrivileges(container, failureReport);
   }

   static bool debugApplyContainerPostMountExecutionSecurityPolicy(Container *container, String *failureReport = nullptr)
   {
      return applyContainerPostMountExecutionSecurityPolicy(container, failureReport);
   }

   static bool debugMoveContainerExecDescriptorAboveMinimum(int& fd, String *failureReport = nullptr)
   {
      return moveContainerExecDescriptorAboveMinimum(fd, failureReport);
   }

   static bool debugCloseAllContainerExecDescriptorsExcept(int preservedFD0, int preservedFD1, String *failureReport = nullptr)
   {
      return closeAllContainerExecDescriptorsExcept(preservedFD0, preservedFD1, failureReport);
   }

   static bool debugCleanupRejectedOrphanedContainerArtifacts(const String& containersRootPath, String *failureReport = nullptr)
   {
      return cleanupRejectedOrphanedContainerArtifactsAtPath(containersRootPath, failureReport);
   }

   static bool debugPreserveFailedContainerArtifactsAtPath(
      const String& retentionRootPath,
      const Container *container,
      const siginfo_t& infop,
      int64_t failureTimeMs,
      int terminalSignal,
      String *retainedBundlePath = nullptr,
      String *failureReport = nullptr)
   {
      return preserveFailedContainerArtifactsAtPath(
         retentionRootPath,
         container,
         infop,
         failureTimeMs,
         terminalSignal,
         retainedBundlePath,
         failureReport);
   }

   static bool debugPreserveFailedContainerArtifactsIfNeededAtPath(
      const String& retentionRootPath,
      Container *container,
      int64_t failureTimeMs,
      String *retainedBundlePath = nullptr,
      String *failureReport = nullptr)
   {
      return preserveFailedContainerArtifactsIfNeededAtPath(
         retentionRootPath,
         container,
         failureTimeMs,
         retainedBundlePath,
         failureReport);
   }

   static bool debugCleanupExpiredFailedContainerArtifactsAtPath(
      const String& retentionRootPath,
      int64_t nowMs,
      int64_t retentionMs,
      String *failureReport = nullptr)
   {
      return cleanupExpiredFailedContainerArtifactsAtPath(
         retentionRootPath,
         nowMs,
         retentionMs,
         failureReport);
   }

   static bool debugLoadContainerLaunchMetadata(Container *container, String *failureReport = nullptr)
   {
      return loadContainerLaunchMetadata(container, failureReport);
   }

   static bool debugValidateContainerLaunchTargets(Container *container, String *failureReport = nullptr)
   {
      int rootfd = -1;
      if (openVerifiedContainerRootfs(container, rootfd, failureReport) == false)
      {
         return false;
      }

      bool valid = validateContainerLaunchTargetsInRootfs(container, rootfd, failureReport);
      close(rootfd);
      return valid;
   }

   static bool debugValidateContainerArtifactShape(const String& artifactRootPath, String *failureReport = nullptr)
   {
      return validateContainerArtifactShape(artifactRootPath, failureReport);
   }

   static bool debugValidateContainerArtifactResourceLimits(
      const String& artifactRootPath,
      uint64_t maxRootfsRegularFileBytes,
      uint32_t maxEntries,
      uint64_t maxArtifactRegularFileBytes,
      String *failureReport = nullptr)
   {
      return validateContainerArtifactResourceLimits(
         artifactRootPath,
         maxRootfsRegularFileBytes,
         maxEntries,
         maxArtifactRegularFileBytes,
         failureReport);
   }

   static bool debugSelectReceivedContainerArtifactFromScratch(
      const String& receiveScratchPath,
      String& receivedArtifactName,
      String& receivedArtifactPath,
      String *failureReport = nullptr)
   {
      return selectReceivedContainerArtifactFromScratch(
         receiveScratchPath,
         receivedArtifactName,
         receivedArtifactPath,
         failureReport);
   }

   static bool debugVerifyCompressedContainerBlob(
      const String& compressedContainerPath,
      const String& expectedDigest,
      uint64_t expectedBytes,
      String *failureReport = nullptr)
   {
      return verifyCompressedContainerBlob(compressedContainerPath, expectedDigest, expectedBytes, failureReport);
   }
#endif

private:

   static bool runExternalCommand(const char *label, const char *program, std::vector<char *>& argv, String *capturedStdout = nullptr, String *failureReport = nullptr)
   {
      ensureSigchldIsWaitable();

      String labelText = {};
      if (label != nullptr)
      {
         labelText.assign(label);
      }

      if (program == nullptr || argv.empty() || argv.back() != nullptr)
      {
         if (failureReport) failureReport->assign("invalid external command arguments"_ctv);
         return false;
      }

      int stdoutPipe[2] = {-1, -1};
      bool capturing = (capturedStdout != nullptr);
      if (capturing)
      {
         if (pipe(stdoutPipe) != 0)
         {
            if (failureReport) failureReport->snprintf<"{} pipe failed: {}"_ctv>(labelText, String(strerror(errno)));
            return false;
         }

         capturedStdout->clear();
      }

      posix_spawn_file_actions_t actions;
      posix_spawn_file_actions_init(&actions);
      if (capturing)
      {
         posix_spawn_file_actions_adddup2(&actions, stdoutPipe[1], STDOUT_FILENO);
         posix_spawn_file_actions_adddup2(&actions, stdoutPipe[1], STDERR_FILENO);
         posix_spawn_file_actions_addclose(&actions, stdoutPipe[0]);
      }

      pid_t pid = -1;
      int rc = posix_spawnp(&pid, program, &actions, nullptr, argv.data(), environ);
      posix_spawn_file_actions_destroy(&actions);

      if (capturing)
      {
         close(stdoutPipe[1]);
         stdoutPipe[1] = -1;
      }

      if (rc != 0)
      {
         if (capturing && stdoutPipe[0] >= 0)
         {
            close(stdoutPipe[0]);
         }

         if (failureReport) failureReport->snprintf<"{} spawn failed: {}"_ctv>(labelText, String(strerror(rc)));
         return false;
      }

      if (capturing)
      {
         char buffer[512];
         while (true)
         {
            ssize_t nRead = read(stdoutPipe[0], buffer, sizeof(buffer));
            if (nRead > 0)
            {
               capturedStdout->append(buffer, uint64_t(nRead));
               continue;
            }

            if (nRead == 0)
            {
               break;
            }

            if (errno == EINTR)
            {
               continue;
            }

            break;
         }

         close(stdoutPipe[0]);
         trimTrailingWhitespace(*capturedStdout);
      }

      int status = 0;
      while (waitpid(pid, &status, 0) < 0)
      {
         if (errno != EINTR)
         {
            if (failureReport) failureReport->snprintf<"{} waitpid failed: {}"_ctv>(labelText, String(strerror(errno)));
            return false;
         }
      }

      if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
      {
         return true;
      }

      if (failureReport)
      {
         if (capturing && capturedStdout && capturedStdout->size() > 0)
         {
            failureReport->snprintf<"{} failed: {}"_ctv>(labelText, *capturedStdout);
         }
         else if (WIFEXITED(status))
         {
            failureReport->snprintf<"{} exited with code {itoa}"_ctv>(labelText, uint32_t(WEXITSTATUS(status)));
         }
         else if (WIFSIGNALED(status))
         {
            failureReport->snprintf<"{} terminated by signal {itoa}"_ctv>(labelText, uint32_t(WTERMSIG(status)));
         }
         else
         {
            failureReport->snprintf<"{} failed with wait status {itoa}"_ctv>(labelText, uint32_t(status));
         }
      }

      return false;
   }

   static bool createDirectoryTree(const String& path)
   {
      std::error_code error;
      std::filesystem::create_directories(std::string(reinterpret_cast<const char *>(path.data()), path.size()), error);
      return (error.value() == 0);
   }

   static bool eraseDirectoryTree(const String& path)
   {
      std::error_code error;
      std::filesystem::remove_all(std::string(reinterpret_cast<const char *>(path.data()), path.size()), error);
      return (error.value() == 0);
   }

   static bool closeContainerFDIfPresent(int& fd, const char *label, String *failureReport = nullptr)
   {
      String labelText = {};
      if (label != nullptr)
      {
         labelText.assign(label);
      }

      if (fd < 0)
      {
         return true;
      }

      while (close(fd) != 0)
      {
         if (errno == EINTR)
         {
            continue;
         }

         if (errno == EBADF)
         {
            fd = -1;
            return true;
         }

         if (failureReport)
         {
            String errnoText = {};
            errnoText.assign(strerror(errno));
            failureReport->snprintf<"failed to close inherited {} fd errno={}({})"_ctv>(
               labelText,
               errno,
               errnoText);
         }
         return false;
      }

      fd = -1;
      return true;
   }

   static bool closeContainerChildPrivilegedFDs(Container *container, String *failureReport = nullptr)
   {
      if (closeContainerFDIfPresent(container->pidfd, "pidfd", failureReport) == false)
      {
         return false;
      }

      if (closeContainerFDIfPresent(container->cgroup, "cgroup", failureReport) == false)
      {
         return false;
      }

      return true;
   }

   static bool setContainerNoNewPrivileges(Container *container, String *failureReport = nullptr)
   {
      if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
      {
         if (failureReport)
         {
            failureReport->snprintf<"PR_SET_NO_NEW_PRIVS failed for container {itoa}: {}"_ctv>(
               container->plan.uuid,
               String(strerror(errno)));
         }

         return false;
      }

      errno = 0;
      int noNewPrivs = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
      if (noNewPrivs != 1)
      {
         if (failureReport)
         {
            failureReport->snprintf<"PR_GET_NO_NEW_PRIVS failed to confirm state for container {itoa}: result={itoa} errno={itoa}({})"_ctv>(
               container->plan.uuid,
               uint32_t(noNewPrivs < 0 ? 0 : noNewPrivs),
               uint32_t(errno),
               String(strerror(errno)));
         }

         return false;
      }

      return true;
   }

   static bool moveContainerExecDescriptorAboveMinimum(int& fd, String *failureReport = nullptr)
   {
      if (fd < 0 || fd >= containerExecInheritedFDMinimum)
      {
         return true;
      }

      int movedFD = fcntl(fd, F_DUPFD, containerExecInheritedFDMinimum);
      if (movedFD < 0)
      {
         if (failureReport)
         {
            failureReport->snprintf<"failed to duplicate inherited container exec fd {itoa} above {itoa}: {}"_ctv>(
               uint32_t(fd),
               uint32_t(containerExecInheritedFDMinimum),
               String(strerror(errno)));
         }
         return false;
      }

      if (close(fd) != 0)
      {
         int closeErrno = errno;
         close(movedFD);
         if (failureReport)
         {
            failureReport->snprintf<"failed to close original inherited container exec fd {itoa}: {}"_ctv>(
               uint32_t(fd),
               String(strerror(closeErrno)));
         }
         return false;
      }

      fd = movedFD;
      return true;
   }

   static bool closeContainerExecDescriptorRange(uint32_t firstFD, uint32_t lastFD, String *failureReport = nullptr)
   {
      if (firstFD > lastFD)
      {
         return true;
      }

#ifdef SYS_close_range
      if (syscall(SYS_close_range, firstFD, lastFD, 0) == 0)
      {
         return true;
      }

      if (errno != ENOSYS && errno != EINVAL)
      {
         if (failureReport)
         {
            failureReport->snprintf<"close_range failed for inherited container exec fds {itoa}-{itoa}: {}"_ctv>(
               firstFD,
               lastFD,
               String(strerror(errno)));
         }
         return false;
      }
#endif

      struct rlimit nofileLimit = {};
      if (getrlimit(RLIMIT_NOFILE, &nofileLimit) != 0)
      {
         if (failureReport)
         {
            failureReport->snprintf<"getrlimit(RLIMIT_NOFILE) failed while closing inherited container exec fds: {}"_ctv>(
               String(strerror(errno)));
         }
         return false;
      }

      uint64_t maximumFD = 0;
      if (nofileLimit.rlim_cur == RLIM_INFINITY)
      {
         maximumFD = std::numeric_limits<uint32_t>::max();
      }
      else if (nofileLimit.rlim_cur > 0)
      {
         maximumFD = nofileLimit.rlim_cur - 1;
      }

      if (firstFD > maximumFD)
      {
         return true;
      }

      uint64_t currentFD = firstFD;
      uint64_t finalFD = std::min<uint64_t>(lastFD, maximumFD);
      while (currentFD <= finalFD)
      {
         if (close(int(currentFD)) != 0 && errno != EBADF)
         {
            if (failureReport)
            {
               failureReport->snprintf<"failed to close inherited container exec fd {itoa}: {}"_ctv>(
                  uint32_t(currentFD),
                  String(strerror(errno)));
            }
            return false;
         }

         currentFD += 1;
      }

      return true;
   }

   static bool closeAllContainerExecDescriptorsExcept(int preservedFD0, int preservedFD1, String *failureReport = nullptr)
   {
      int preservedFDs[2] = {preservedFD0, preservedFD1};
      std::sort(std::begin(preservedFDs), std::end(preservedFDs));

      uint32_t nextFD = 3;
      for (int preservedFD : preservedFDs)
      {
         if (preservedFD < 3)
         {
            continue;
         }

         if (uint32_t(preservedFD) > nextFD)
         {
            if (closeContainerExecDescriptorRange(nextFD, uint32_t(preservedFD) - 1, failureReport) == false)
            {
               return false;
            }
         }

         if (preservedFD == std::numeric_limits<int>::max())
         {
            return true;
         }

         nextFD = uint32_t(preservedFD) + 1;
      }

      return closeContainerExecDescriptorRange(nextFD, std::numeric_limits<uint32_t>::max(), failureReport);
   }

   static bool listDirectoryEntriesAt(int directoryFD, Vector<String>& entries, String *failureReport = nullptr)
   {
      entries.clear();
      if (directoryFD < 0)
      {
         if (failureReport) failureReport->assign("directory fd is invalid"_ctv);
         return false;
      }

      int iteratorFD = dup(directoryFD);
      if (iteratorFD < 0)
      {
         if (failureReport) failureReport->snprintf<"failed to duplicate directory fd errno={}({})"_ctv>(errno, String(strerror(errno)));
         return false;
      }

      DIR *dir = fdopendir(iteratorFD);
      if (dir == nullptr)
      {
         if (failureReport) failureReport->snprintf<"fdopendir failed errno={}({})"_ctv>(errno, String(strerror(errno)));
         close(iteratorFD);
         return false;
      }

      bool ok = true;
      errno = 0;
      while (struct dirent *entry = readdir(dir))
      {
         const char *name = entry->d_name;
         if (name == nullptr || name[0] == '\0')
         {
            continue;
         }

         if ((name[0] == '.' && name[1] == '\0')
            || (name[0] == '.' && name[1] == '.' && name[2] == '\0'))
         {
            continue;
         }

         String entryName = {};
         entryName.assign(name);
         entries.push_back(entryName);
         errno = 0;
      }

      if (errno != 0)
      {
         ok = false;
         if (failureReport) failureReport->snprintf<"readdir failed errno={}({})"_ctv>(errno, String(strerror(errno)));
      }

      closedir(dir);
      return ok;
   }

   static bool setContainerArtifactSubvolumeWritable(const String& path, String *failureReport = nullptr)
   {
      String pathText = {};
      pathText.assign(path);
      std::vector<char *> argv;
      argv.push_back((char *)"btrfs");
      argv.push_back((char *)"property");
      argv.push_back((char *)"set");
      argv.push_back((char *)"-f");
      argv.push_back((char *)pathText.c_str());
      argv.push_back((char *)"ro");
      argv.push_back((char *)"false");
      argv.push_back(nullptr);
      String commandOutput = {};
      return runExternalCommand("btrfs_property_set", "btrfs", argv, &commandOutput, failureReport);
   }

   static bool snapshotContainerArtifactSubvolume(const String& sourcePath, const String& targetPath, String *failureReport = nullptr)
   {
      String sourceText = {};
      sourceText.assign(sourcePath);
      String targetText = {};
      targetText.assign(targetPath);
      std::vector<char *> argv;
      argv.push_back((char *)"btrfs");
      argv.push_back((char *)"subvolume");
      argv.push_back((char *)"snapshot");
      argv.push_back((char *)sourceText.c_str());
      argv.push_back((char *)targetText.c_str());
      argv.push_back(nullptr);
      String commandOutput = {};
      return runExternalCommand("btrfs_subvolume_snapshot", "btrfs", argv, &commandOutput, failureReport);
   }

   static bool moveContainerArtifactSubvolumeIntoPlace(
      const String& sourcePath,
      const String& targetPath,
      bool& usedSnapshotFallback,
      String *failureReport = nullptr)
   {
      usedSnapshotFallback = false;

      String sourceText = {};
      sourceText.assign(sourcePath);
      String targetText = {};
      targetText.assign(targetPath);
      if (rename(sourceText.c_str(), targetText.c_str()) == 0)
      {
         return true;
      }

      int renameErrno = errno;
      if (renameErrno != EXDEV)
      {
         if (failureReport)
         {
            failureReport->snprintf<"failed to rename container artifact from {} to {} errno={}({})"_ctv>(
               sourcePath,
               targetPath,
               renameErrno,
               String(strerror(renameErrno)));
         }
         return false;
      }

      if (snapshotContainerArtifactSubvolume(sourcePath, targetPath, failureReport) == false)
      {
         return false;
      }

      usedSnapshotFallback = true;
      return true;
   }

   static bool validateContainerArtifactResourceLimits(
      const String& artifactRootPath,
      uint64_t maxRootfsRegularFileBytes,
      uint32_t maxEntries,
      uint64_t maxArtifactRegularFileBytes,
      String *failureReport = nullptr)
   {
      std::filesystem::path artifactRoot(std::string(reinterpret_cast<const char *>(artifactRootPath.data()), artifactRootPath.size()));
      std::error_code rootError;
      if (std::filesystem::exists(artifactRoot, rootError) == false
         || std::filesystem::is_directory(artifactRoot, rootError) == false)
      {
         if (failureReport) failureReport->snprintf<"artifact root {} is not a readable directory"_ctv>(artifactRootPath);
         return false;
      }

      bytell_hash_set<uint128_t> seenRegularFiles = {};
      uint64_t totalEntries = 0;
      uint64_t totalRegularFileBytes = 0;
      uint64_t rootfsRegularFileBytes = 0;

      std::error_code iteratorError;
      std::filesystem::recursive_directory_iterator it(artifactRoot, std::filesystem::directory_options::none, iteratorError);
      std::filesystem::recursive_directory_iterator end = {};
      if (iteratorError)
      {
         if (failureReport) failureReport->snprintf<"failed to walk artifact root {}"_ctv>(artifactRootPath);
         return false;
      }

      while (it != end)
      {
         const std::filesystem::path entryPath = it->path();
         const std::filesystem::path relativePath = entryPath.lexically_relative(artifactRoot);
         const bool underRootfs = (relativePath.empty() == false && *relativePath.begin() == "rootfs");

         std::string nativeEntryPath = entryPath.string();
         struct stat statbuf = {};
         if (::lstat(nativeEntryPath.c_str(), &statbuf) != 0)
         {
            if (failureReport)
            {
               String entryText = {};
               entryText.assign(nativeEntryPath.data(), nativeEntryPath.size());
               failureReport->snprintf<"failed to stat artifact entry {} errno={}({})"_ctv>(
                  entryText,
                  errno,
                  String(strerror(errno)));
            }
            return false;
         }

         totalEntries += 1;
         if (totalEntries > maxEntries)
         {
            if (failureReport) failureReport->snprintf<"artifact contains too many entries: {itoa} > {itoa}"_ctv>(
               uint32_t(totalEntries),
               maxEntries);
            return false;
         }

         if (S_ISREG(statbuf.st_mode) != 0)
         {
            uint128_t inodeKey = (uint128_t(uint64_t(statbuf.st_dev)) << 64) | uint64_t(statbuf.st_ino);
            if (seenRegularFiles.contains(inodeKey) == false)
            {
               seenRegularFiles.insert(inodeKey);
               totalRegularFileBytes += uint64_t(statbuf.st_size);
               if (totalRegularFileBytes > maxArtifactRegularFileBytes)
               {
                  if (failureReport) failureReport->snprintf<"artifact regular-file bytes exceed maximum: {} > {}"_ctv>(
                     totalRegularFileBytes,
                     maxArtifactRegularFileBytes);
                  return false;
               }

               if (underRootfs)
               {
                  rootfsRegularFileBytes += uint64_t(statbuf.st_size);
                  if (maxRootfsRegularFileBytes > 0 && rootfsRegularFileBytes > maxRootfsRegularFileBytes)
                  {
                     if (failureReport) failureReport->snprintf<"artifact rootfs regular-file bytes exceed filesystemMB: {} > {}"_ctv>(
                        rootfsRegularFileBytes,
                        maxRootfsRegularFileBytes);
                     return false;
                  }
               }
            }
         }

         it.increment(iteratorError);
         if (iteratorError)
         {
            if (failureReport) failureReport->snprintf<"failed to continue artifact walk {}"_ctv>(artifactRootPath);
            return false;
         }
      }

      return true;
   }

   static bool deleteContainerArtifactTree(const String& path, String *failureReport = nullptr)
   {
      if (path.size() == 0 || pathExists(path) == false)
      {
         return true;
      }

      String ignoredFailure = {};
      (void)setContainerArtifactSubvolumeWritable(path, &ignoredFailure);

      String pathText = {};
      pathText.assign(path);
      std::vector<char *> argv;
      argv.push_back((char *)"btrfs");
      argv.push_back((char *)"subvolume");
      argv.push_back((char *)"delete");
      argv.push_back((char *)pathText.c_str());
      argv.push_back(nullptr);
      String commandOutput = {};
      if (runExternalCommand("btrfs_subvolume_delete", "btrfs", argv, &commandOutput, nullptr))
      {
         return true;
      }

      if (eraseDirectoryTree(path))
      {
         return true;
      }

      if (failureReport)
      {
         failureReport->snprintf<"failed to delete container artifact tree {}"_ctv>(path);
      }
      return false;
   }

   static constexpr auto containerCreatePendingMarkerRelativePath = ".prodigy-private/create.pending"_ctv;

   static bool writeToFileDescriptor(int fd, const String& payload, String *failureReport = nullptr)
   {
      if (fd < 0)
      {
         if (failureReport) failureReport->assign("file descriptor is invalid"_ctv);
         return false;
      }

      uint64_t written = 0;
      while (written < payload.size())
      {
         ssize_t bytesWritten = write(fd, payload.data() + written, payload.size() - written);
         if (bytesWritten < 0)
         {
            if (errno == EINTR)
            {
               continue;
            }

            if (failureReport) failureReport->snprintf<"write failed errno={}({})"_ctv>(errno, String(strerror(errno)));
            return false;
         }

         written += uint64_t(bytesWritten);
      }

      return true;
   }

   static bool writeContainerCreatePendingMarker(const String& artifactRootPath, pid_t creatorPID, String *failureReport = nullptr)
   {
      int artifactRootFD = Filesystem::openDirectoryAt(
         -1,
         artifactRootPath,
         O_PATH | O_DIRECTORY | O_CLOEXEC,
         RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS);
      if (artifactRootFD < 0)
      {
         if (failureReport) failureReport->snprintf<"failed to open artifact root {} without following symlinks errno={}({})"_ctv>(artifactRootPath, errno, String(strerror(errno)));
         return false;
      }

      int privateFD = Filesystem::openDirectoryAt(
         artifactRootFD,
         ".prodigy-private"_ctv,
         O_PATH | O_DIRECTORY | O_CLOEXEC,
         secureContainerResolveFlags);
      if (privateFD < 0)
      {
         if (failureReport) failureReport->snprintf<"failed to open artifact private metadata directory for pending-create marker errno={}({})"_ctv>(errno, String(strerror(errno)));
         close(artifactRootFD);
         return false;
      }

      int markerFD = Filesystem::openFileAt(
         privateFD,
         "create.pending"_ctv,
         O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC | O_NOFOLLOW,
         S_IRUSR | S_IWUSR,
         secureContainerResolveFlags);
      if (markerFD < 0)
      {
         if (failureReport) failureReport->snprintf<"failed to create pending-create marker without following symlinks errno={}({})"_ctv>(errno, String(strerror(errno)));
         close(privateFD);
         close(artifactRootFD);
         return false;
      }

      String payload = {};
      payload.assignItoa(uint64_t(creatorPID));
      payload.append("\n"_ctv);
      bool wrote = writeToFileDescriptor(markerFD, payload, failureReport);
      close(markerFD);
      close(privateFD);
      close(artifactRootFD);
      return wrote;
   }

   static bool clearContainerCreatePendingMarker(const String& artifactRootPath, String *failureReport = nullptr)
   {
      int artifactRootFD = Filesystem::openDirectoryAt(
         -1,
         artifactRootPath,
         O_PATH | O_DIRECTORY | O_CLOEXEC,
         RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS);
      if (artifactRootFD < 0)
      {
         if (errno == ENOENT)
         {
            return true;
         }

         if (failureReport) failureReport->snprintf<"failed to open artifact root {} without following symlinks errno={}({})"_ctv>(artifactRootPath, errno, String(strerror(errno)));
         return false;
      }

      int privateFD = Filesystem::openDirectoryAt(
         artifactRootFD,
         ".prodigy-private"_ctv,
         O_PATH | O_DIRECTORY | O_CLOEXEC,
         secureContainerResolveFlags);
      if (privateFD < 0)
      {
         int openErrno = errno;
         close(artifactRootFD);
         if (openErrno == ENOENT)
         {
            return true;
         }

         if (failureReport) failureReport->snprintf<"failed to open artifact private metadata directory for pending-create marker cleanup errno={}({})"_ctv>(openErrno, String(strerror(openErrno)));
         return false;
      }

      int rc = unlinkat(privateFD, "create.pending", 0);
      int unlinkErrno = errno;
      close(privateFD);
      close(artifactRootFD);
      if (rc == 0 || unlinkErrno == ENOENT)
      {
         return true;
      }

      if (failureReport) failureReport->snprintf<"failed to remove pending-create marker errno={}({})"_ctv>(unlinkErrno, String(strerror(unlinkErrno)));
      return false;
   }

   static bool readContainerCreatePendingMarker(const String& artifactRootPath, bool& markerPresent, pid_t& creatorPID, String *failureReport = nullptr)
   {
      markerPresent = false;
      creatorPID = -1;

      int artifactRootFD = Filesystem::openDirectoryAt(
         -1,
         artifactRootPath,
         O_PATH | O_DIRECTORY | O_CLOEXEC,
         RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS);
      if (artifactRootFD < 0)
      {
         if (errno == ENOENT)
         {
            return true;
         }

         if (failureReport) failureReport->snprintf<"failed to open artifact root {} without following symlinks errno={}({})"_ctv>(artifactRootPath, errno, String(strerror(errno)));
         return false;
      }

      int privateFD = Filesystem::openDirectoryAt(
         artifactRootFD,
         ".prodigy-private"_ctv,
         O_PATH | O_DIRECTORY | O_CLOEXEC,
         secureContainerResolveFlags);
      if (privateFD < 0)
      {
         int openErrno = errno;
         close(artifactRootFD);
         if (openErrno == ENOENT)
         {
            return true;
         }

         if (failureReport) failureReport->snprintf<"failed to open artifact private metadata directory while inspecting pending-create marker errno={}({})"_ctv>(openErrno, String(strerror(openErrno)));
         return false;
      }

      int markerFD = Filesystem::openFileAt(
         privateFD,
         "create.pending"_ctv,
         O_RDONLY | O_CLOEXEC | O_NOFOLLOW,
         0,
         secureContainerResolveFlags);
      if (markerFD < 0)
      {
         int openErrno = errno;
         close(privateFD);
         close(artifactRootFD);
         if (openErrno == ENOENT)
         {
            return true;
         }

         if (failureReport) failureReport->snprintf<"failed to open pending-create marker without following symlinks errno={}({})"_ctv>(openErrno, String(strerror(openErrno)));
         return false;
      }

      markerPresent = true;
      String markerContents = {};
      String readFailure = {};
      bool readOK = readOpenFileDescriptorIntoString(markerFD, markerContents, maxPendingCreateMarkerBytes, &readFailure);
      close(markerFD);
      close(privateFD);
      close(artifactRootFD);
      if (readOK == false)
      {
         if (failureReport) failureReport->snprintf<"failed to read pending-create marker: {}"_ctv>(readFailure);
         return false;
      }

      trimTrailingWhitespace(markerContents);
      if (markerContents.size() == 0)
      {
         creatorPID = -1;
         return true;
      }

      char *tail = nullptr;
      long long parsed = std::strtoll(markerContents.c_str(), &tail, 10);
      if (tail == markerContents.c_str()
         || (tail != nullptr && *tail != '\0')
         || parsed <= 0
         || parsed > std::numeric_limits<pid_t>::max())
      {
         creatorPID = -1;
         return true;
      }

      creatorPID = pid_t(parsed);
      return true;
   }

   static bool isLivePendingCreateOwner(pid_t creatorPID)
   {
      if (creatorPID <= 0)
      {
         return false;
      }

      if (kill(creatorPID, 0) == 0)
      {
         return true;
      }

      return errno == EPERM;
   }

   static bool isJanitorExcludedContainerArtifactName(const String& entryName)
   {
      if (entryName.size() == 0 || entryName[0] == '.')
      {
         return true;
      }

      return entryName.equal("store"_ctv) || entryName.equal("storage"_ctv);
   }

   static bool isActiveContainerArtifactName(const String& entryName)
   {
      if (thisNeuron == nullptr)
      {
         return false;
      }

      for (const auto& [uuid, container] : thisNeuron->containers)
      {
         (void)uuid;
         if (container != nullptr && container->name == entryName)
         {
            return true;
         }
      }

      return false;
   }

   static String failedContainerArtifactRootPath(void)
   {
      return "/var/log/prodigy/failed-containers"_ctv;
   }

   static int failedContainerTerminalSignal(const siginfo_t& infop)
   {
      if (infop.si_code == CLD_EXITED)
      {
         return 0;
      }

      if (infop.si_code == CLD_KILLED || infop.si_code == CLD_DUMPED)
      {
         return infop.si_status;
      }

      return infop.si_code;
   }

   static bool ensureDirectoryTree(const std::filesystem::path& directoryPath, String *failureReport = nullptr)
   {
      std::error_code error = {};
      if (std::filesystem::create_directories(directoryPath, error) == false && error)
      {
         if (failureReport)
         {
            failureReport->snprintf<"failed to create directory tree {} reason={}"_ctv>(
               prodigyStringFromFilesystemPath(directoryPath),
               String(error.message().c_str()));
         }

         return false;
      }

      return true;
   }

   static bool copyRegularFileIfPresent(
      const std::filesystem::path& sourcePath,
      const std::filesystem::path& destinationPath,
      String *failureReport = nullptr)
   {
      std::error_code statusError = {};
      std::filesystem::file_status status = std::filesystem::symlink_status(sourcePath, statusError);
      if (statusError)
      {
         if (statusError == std::make_error_code(std::errc::no_such_file_or_directory)
            || statusError.value() == ENOENT)
         {
            return true;
         }

         if (failureReport)
         {
            failureReport->snprintf<"failed to stat failure artifact {} reason={}"_ctv>(
               prodigyStringFromFilesystemPath(sourcePath),
               String(statusError.message().c_str()));
         }

         return false;
      }

      if (std::filesystem::exists(status) == false)
      {
         return true;
      }

      if (std::filesystem::is_regular_file(status) == false)
      {
         if (failureReport)
         {
            failureReport->snprintf<"failure artifact {} is not a regular file"_ctv>(
               prodigyStringFromFilesystemPath(sourcePath));
         }

         return false;
      }

      if (ensureDirectoryTree(destinationPath.parent_path(), failureReport) == false)
      {
         return false;
      }

      std::error_code copyError = {};
      if (std::filesystem::copy_file(
            sourcePath,
            destinationPath,
            std::filesystem::copy_options::overwrite_existing,
            copyError) == false
         && copyError)
      {
         if (failureReport)
         {
            failureReport->snprintf<"failed to copy failure artifact {} to {} reason={}"_ctv>(
               prodigyStringFromFilesystemPath(sourcePath),
               prodigyStringFromFilesystemPath(destinationPath),
               String(copyError.message().c_str()));
         }

         return false;
      }

      return true;
   }

   static bool writeFailureArtifactTextFile(
      const std::filesystem::path& destinationPath,
      const String& contents,
      String *failureReport = nullptr)
   {
      if (ensureDirectoryTree(destinationPath.parent_path(), failureReport) == false)
      {
         return false;
      }

      int fd = ::open(destinationPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
      if (fd < 0)
      {
         if (failureReport)
         {
            failureReport->snprintf<"failed to open failure artifact {} for write errno={}({})"_ctv>(
               prodigyStringFromFilesystemPath(destinationPath),
               errno,
               String(strerror(errno)));
         }

         return false;
      }

      bool ok = true;
      int writeErrno = 0;
      if (contents.size() > 0)
      {
         ssize_t wrote = ::write(fd, reinterpret_cast<const char *>(contents.data()), contents.size());
         ok = (wrote == ssize_t(contents.size()));
         if (ok == false)
         {
            writeErrno = errno;
         }
      }

      if (::close(fd) != 0 && writeErrno == 0)
      {
         writeErrno = errno;
         ok = false;
      }

      if (ok == false)
      {
         if (failureReport)
         {
            failureReport->snprintf<"failed to write failure artifact {} errno={}({})"_ctv>(
               prodigyStringFromFilesystemPath(destinationPath),
               writeErrno,
               String(strerror(writeErrno)));
         }

         return false;
      }

      return true;
   }

   static bool preserveFailedContainerArtifactsAtPath(
      const String& retentionRootPath,
      const Container *container,
      const siginfo_t& infop,
      int64_t failureTimeMs,
      int terminalSignal,
      String *retainedBundlePath = nullptr,
      String *failureReport = nullptr)
   {
      if (container == nullptr)
      {
         if (failureReport) failureReport->assign("container missing for failed-container artifact retention"_ctv);
         return false;
      }

      std::filesystem::path retentionRoot = prodigyFilesystemPathFromString(retentionRootPath);
      String applicationIDText = {};
      applicationIDText.assignItoa(unsigned(container->plan.config.applicationID));
      String containerNameText = {};
      containerNameText.assign(container->name);
      String failureTimeText = {};
      failureTimeText.assignItoa(uint64_t(failureTimeMs));
      std::filesystem::path bundlePath =
         retentionRoot
         / applicationIDText.c_str()
         / containerNameText.c_str()
         / failureTimeText.c_str();

      if (ensureDirectoryTree(bundlePath, failureReport) == false)
      {
         return false;
      }

      String metadata = {};
      metadata.snprintf<
         "applicationID={itoa}\ncontainerName={}\nfailureTimeMs={itoa}\nterminalSignal={itoa}\nsiCode={itoa}\nsiStatus={itoa}\npid={itoa}\nstate={itoa}\nkilledOnPurpose={itoa}\nrestartOnFailure={itoa}\nartifactRoot={}\nrootfs={}\n"_ctv>(
         unsigned(container->plan.config.applicationID),
         container->name,
         static_cast<long long>(failureTimeMs),
         terminalSignal,
         int(infop.si_code),
         int(infop.si_status),
         int(container->pid),
         unsigned(container->plan.state),
         int(container->killedOnPurpose),
         int(container->plan.restartOnFailure),
         container->artifactRootPath,
         container->rootfsPath);

      if (writeFailureArtifactTextFile(bundlePath / "metadata.txt", metadata, failureReport) == false)
      {
         return false;
      }

      std::filesystem::path artifactRoot = prodigyFilesystemPathFromString(container->artifactRootPath);
      std::filesystem::path rootfsRoot = prodigyFilesystemPathFromString(container->rootfsPath);
      struct FailedArtifactCopy
      {
         const std::filesystem::path *sourceRoot;
         const char *sourceRelative;
         const char *destinationRelative;
      };
      const FailedArtifactCopy copies[] = {
         {&rootfsRoot, "bootstage.txt", "bootstage.txt"},
         {&rootfsRoot, "crashreport.txt", "crashreport.txt"},
         {&rootfsRoot, "readytrace.log", "readytrace.log"},
         {&rootfsRoot, "aegis.hash.log", "aegis.hash.log"},
         {&rootfsRoot, "params.dump", "params.dump"},
         {&artifactRoot, ".prodigy-private/launch.metadata", "launch.metadata"},
         {&rootfsRoot, "logs/stdout.log", "logs/stdout.log"},
         {&rootfsRoot, "logs/stderr.log", "logs/stderr.log"}
      };

      for (const FailedArtifactCopy& copy : copies)
      {
         if (copyRegularFileIfPresent(
               (*copy.sourceRoot) / copy.sourceRelative,
               bundlePath / copy.destinationRelative,
               failureReport) == false)
         {
            return false;
         }
      }

      if (retainedBundlePath)
      {
         retainedBundlePath->assign(prodigyStringFromFilesystemPath(bundlePath));
      }

      return true;
   }

   static bool preserveFailedContainerArtifactsIfNeededAtPath(
      const String& retentionRootPath,
      Container *container,
      int64_t failureTimeMs,
      String *retainedBundlePath = nullptr,
      String *failureReport = nullptr)
   {
      if (container == nullptr)
      {
         if (failureReport) failureReport->assign("container missing for failed-container artifact retention"_ctv);
         return false;
      }

      if (retainedBundlePath)
      {
         retainedBundlePath->clear();
      }

      if (container->killedOnPurpose || container->failedArtifactsPreserved)
      {
         return true;
      }

      if (container->infop.si_pid <= 0)
      {
         if (failureReport) failureReport->assign("failed-container artifact retention requires waitid siginfo"_ctv);
         return false;
      }

      String localRetainedBundlePath = {};
      bool preserved = preserveFailedContainerArtifactsAtPath(
         retentionRootPath,
         container,
         container->infop,
         failureTimeMs,
         failedContainerTerminalSignal(container->infop),
         &localRetainedBundlePath,
         failureReport);
      if (preserved == false)
      {
         return false;
      }

      container->failedArtifactsPreserved = true;
      if (retainedBundlePath)
      {
         retainedBundlePath->assign(localRetainedBundlePath);
      }

      return true;
   }

   static bool preserveFailedContainerArtifactsWithDefaultRoot(
      const Container *container,
      const siginfo_t& infop,
      int64_t failureTimeMs,
      int terminalSignal,
      String *retainedBundlePath = nullptr,
      String *failureReport = nullptr)
   {
      return preserveFailedContainerArtifactsAtPath(
         failedContainerArtifactRootPath(),
         container,
         infop,
         failureTimeMs,
         terminalSignal,
         retainedBundlePath,
         failureReport);
   }

   static bool preserveFailedContainerArtifactsIfNeededWithDefaultRoot(
      Container *container,
      int64_t failureTimeMs,
      String *retainedBundlePath = nullptr,
      String *failureReport = nullptr)
   {
      return preserveFailedContainerArtifactsIfNeededAtPath(
         failedContainerArtifactRootPath(),
         container,
         failureTimeMs,
         retainedBundlePath,
         failureReport);
   }

   static bool cleanupExpiredFailedContainerArtifactsAtPath(
      const String& retentionRootPath,
      int64_t nowMs,
      int64_t retentionMs,
      String *failureReport = nullptr)
   {
      std::filesystem::path retentionRoot = prodigyFilesystemPathFromString(retentionRootPath);
      std::error_code rootError = {};
      std::filesystem::file_status rootStatus = std::filesystem::symlink_status(retentionRoot, rootError);
      if (rootError)
      {
         if (rootError.value() == ENOENT)
         {
            return true;
         }

         if (failureReport)
         {
            failureReport->snprintf<"failed to inspect failure artifact root {} reason={}"_ctv>(
               retentionRootPath,
               String(rootError.message().c_str()));
         }

         return false;
      }

      if (std::filesystem::exists(rootStatus) == false)
      {
         return true;
      }

      if (std::filesystem::is_directory(rootStatus) == false)
      {
         if (failureReport)
         {
            failureReport->snprintf<"failure artifact root {} is not a directory"_ctv>(retentionRootPath);
         }

         return false;
      }

      bool allCleaned = true;
      auto directoryChildren = [&] (const std::filesystem::path& directoryPath) -> Vector<std::filesystem::path> {
         Vector<std::filesystem::path> children = {};
         std::error_code iteratorError = {};
         for (std::filesystem::directory_iterator it(directoryPath, iteratorError), end; it != end; it.increment(iteratorError))
         {
            if (iteratorError)
            {
               break;
            }

            std::error_code statusError = {};
            std::filesystem::file_status status = it->symlink_status(statusError);
            if (statusError)
            {
               iteratorError = statusError;
               break;
            }

            if (std::filesystem::is_directory(status))
            {
               children.push_back(it->path());
            }
         }

         if (iteratorError)
         {
            allCleaned = false;
            if (failureReport && failureReport->size() == 0)
            {
               failureReport->snprintf<"failed to iterate failure artifact directory {} reason={}"_ctv>(
                  prodigyStringFromFilesystemPath(directoryPath),
                  String(iteratorError.message().c_str()));
            }
         }

         return children;
      };

      for (const std::filesystem::path& appPath : directoryChildren(retentionRoot))
      {
         for (const std::filesystem::path& containerPath : directoryChildren(appPath))
         {
            for (const std::filesystem::path& bundlePath : directoryChildren(containerPath))
            {
               struct stat bundleStat = {};
               if (::stat(bundlePath.c_str(), &bundleStat) != 0)
               {
                  allCleaned = false;
                  if (failureReport && failureReport->size() == 0)
                  {
                     failureReport->snprintf<"failed to stat failure artifact bundle {} errno={}({})"_ctv>(
                        prodigyStringFromFilesystemPath(bundlePath),
                        errno,
                        String(strerror(errno)));
                  }
                  continue;
               }

               int64_t modifiedMs = int64_t(bundleStat.st_mtime) * 1000LL;
               if (modifiedMs + retentionMs > nowMs)
               {
                  continue;
               }

               std::error_code removeError = {};
               std::filesystem::remove_all(bundlePath, removeError);
               if (removeError)
               {
                  allCleaned = false;
                  if (failureReport && failureReport->size() == 0)
                  {
                     failureReport->snprintf<"failed to remove expired failure artifact bundle {} reason={}"_ctv>(
                        prodigyStringFromFilesystemPath(bundlePath),
                        String(removeError.message().c_str()));
                  }
               }
            }

            std::error_code emptyError = {};
            if (std::filesystem::is_empty(containerPath, emptyError))
            {
               (void)std::filesystem::remove(containerPath, emptyError);
            }
         }

         std::error_code emptyError = {};
         if (std::filesystem::is_empty(appPath, emptyError))
         {
            (void)std::filesystem::remove(appPath, emptyError);
         }
      }

      if (allCleaned == false && failureReport && failureReport->size() == 0)
      {
         failureReport->assign("failed to clean one or more expired failed container artifact bundles"_ctv);
      }

      return allCleaned;
   }

   static bool cleanupExpiredFailedContainerArtifactsWithDefaultRoot(int64_t nowMs, String *failureReport = nullptr)
   {
      return cleanupExpiredFailedContainerArtifactsAtPath(
         failedContainerArtifactRootPath(),
         nowMs,
         failedContainerArtifactRetentionMs,
         failureReport);
   }

   static bool cleanupRejectedOrphanedContainerArtifactsAtPath(const String& containersRootPath, String *failureReport = nullptr)
   {
      int containersRootFD = Filesystem::openDirectoryAt(
         -1,
         containersRootPath,
         O_RDONLY | O_DIRECTORY | O_CLOEXEC,
         RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS);
      if (containersRootFD < 0)
      {
         if (errno == ENOENT)
         {
            return true;
         }

         if (failureReport) failureReport->snprintf<"failed to open containers root {} without following symlinks errno={}({})"_ctv>(containersRootPath, errno, String(strerror(errno)));
         return false;
      }

      Vector<String> entries = {};
      bool listed = listDirectoryEntriesAt(containersRootFD, entries, failureReport);
      close(containersRootFD);
      if (listed == false)
      {
         return false;
      }

      bool allCleaned = true;
      for (const String& entryName : entries)
      {
         if (isJanitorExcludedContainerArtifactName(entryName) || isActiveContainerArtifactName(entryName))
         {
            continue;
         }

         String artifactRootPath = {};
         artifactRootPath.assign(containersRootPath);
         if (artifactRootPath.size() > 0 && artifactRootPath[artifactRootPath.size() - 1] != '/')
         {
            artifactRootPath.append('/');
         }
         artifactRootPath.append(entryName);

         bool markerPresent = false;
         pid_t creatorPID = -1;
         String markerFailure = {};
         if (readContainerCreatePendingMarker(artifactRootPath, markerPresent, creatorPID, &markerFailure) == false)
         {
            basics_log("cleanupRejectedOrphanedContainerArtifacts marker inspection failed path=%s reason=%s\n",
               artifactRootPath.c_str(),
               markerFailure.c_str());
            allCleaned = false;
            continue;
         }

         if (markerPresent == false || isLivePendingCreateOwner(creatorPID))
         {
            continue;
         }

         String deleteFailure = {};
         if (deleteContainerArtifactTree(artifactRootPath, &deleteFailure) == false)
         {
            basics_log("cleanupRejectedOrphanedContainerArtifacts delete failed path=%s reason=%s\n",
               artifactRootPath.c_str(),
               deleteFailure.c_str());
            allCleaned = false;
         }
      }

      if (allCleaned == false && failureReport && failureReport->size() == 0)
      {
         failureReport->assign("failed to clean one or more rejected/orphaned container artifacts"_ctv);
      }

      return allCleaned;
   }

   static void cleanupContainerReceiveScratch(const String& scratchPath)
   {
      if (scratchPath.size() == 0 || pathExists(scratchPath) == false)
      {
         return;
      }

      Filesystem::iterateOverDirectoryAtPath(scratchPath, [&] (const String& entryName) -> void {
         String childPath = {};
         childPath.assign(scratchPath);
         if (childPath[childPath.size() - 1] != '/')
         {
            childPath.append('/');
         }
         childPath.append(entryName);
         String ignoredFailure = {};
         (void)deleteContainerArtifactTree(childPath, &ignoredFailure);
      });

      (void)eraseDirectoryTree(scratchPath);
   }

   static bool selectReceivedContainerArtifactFromScratch(
      const String& receiveScratchPath,
      String& receivedArtifactName,
      String& receivedArtifactPath,
      String *failureReport = nullptr)
   {
      receivedArtifactName.clear();
      receivedArtifactPath.clear();

      int scratchFD = Filesystem::openDirectoryAt(
         -1,
         receiveScratchPath,
         O_RDONLY | O_DIRECTORY | O_CLOEXEC,
         RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS);
      if (scratchFD < 0)
      {
         if (failureReport) failureReport->snprintf<"failed to open receive scratch {} without following symlinks errno={}({})"_ctv>(
            receiveScratchPath,
            errno,
            String(strerror(errno)));
         return false;
      }

      Vector<String> entries = {};
      bool listed = listDirectoryEntriesAt(scratchFD, entries, failureReport);
      close(scratchFD);
      if (listed == false)
      {
         return false;
      }

      if (entries.size() == 0)
      {
         if (failureReport) failureReport->snprintf<"receive scratch {} produced no artifact"_ctv>(receiveScratchPath);
         return false;
      }

      if (entries.size() != 1)
      {
         if (failureReport) failureReport->snprintf<"receive scratch {} must contain exactly one top-level artifact entry, got {itoa}"_ctv>(
            receiveScratchPath,
            uint32_t(entries.size()));
         return false;
      }

      if (entries[0].size() == 0 || entries[0][0] == '.')
      {
         if (failureReport) failureReport->snprintf<"receive scratch {} must not contain hidden top-level artifact entries"_ctv>(receiveScratchPath);
         return false;
      }

      receivedArtifactName.assign(entries[0]);
      receivedArtifactPath.assign(receiveScratchPath);
      if (receivedArtifactPath[receivedArtifactPath.size() - 1] != '/')
      {
         receivedArtifactPath.append('/');
      }
      receivedArtifactPath.append(receivedArtifactName);
      return true;
   }

   static uint64_t storageBytesForMB(uint64_t sizeMB)
   {
      return sizeMB * 1024ULL * 1024ULL;
   }

   static bool statDeviceID(const String& path, dev_t& deviceID)
   {
      std::string nativePath(reinterpret_cast<const char *>(path.data()), path.size());
      struct stat statbuf = {};
      if (stat(nativePath.c_str(), &statbuf) != 0)
      {
         return false;
      }

      deviceID = statbuf.st_dev;
      return true;
   }

   static bool statFilesystemAvailability(const String& path, uint64_t& availableBytes)
   {
      std::string nativePath(reinterpret_cast<const char *>(path.data()), path.size());
      struct statvfs statbuf = {};
      if (statvfs(nativePath.c_str(), &statbuf) != 0)
      {
         return false;
      }

      availableBytes = uint64_t(statbuf.f_bavail) * uint64_t(statbuf.f_frsize);
      return true;
   }

   static bool ensureSizedBackingFile(const String& path, uint64_t targetBytes, String *failureReport = nullptr)
   {
      size_t slash = size_t(path.rfindChar('/'));
      if (slash != size_t(-1))
      {
         String parent;
         parent.assign(path.data(), slash);
         if (parent.size() > 0 && createDirectoryTree(parent) == false)
         {
            if (failureReport) failureReport->snprintf<"failed to create backing file parent {}"_ctv>(parent);
            return false;
         }
      }

      std::string nativePath(reinterpret_cast<const char *>(path.data()), path.size());
      int fd = open(nativePath.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
      if (fd < 0)
      {
         if (failureReport) failureReport->snprintf<"failed to open backing file {}: {}"_ctv>(path, String(strerror(errno)));
         return false;
      }

      struct stat statbuf = {};
      if (fstat(fd, &statbuf) != 0)
      {
         if (failureReport) failureReport->snprintf<"failed to stat backing file {}: {}"_ctv>(path, String(strerror(errno)));
         close(fd);
         return false;
      }

      if (uint64_t(statbuf.st_size) < targetBytes)
      {
         if (ftruncate(fd, off_t(targetBytes)) != 0)
         {
            if (failureReport) failureReport->snprintf<"failed to grow backing file {}: {}"_ctv>(path, String(strerror(errno)));
            close(fd);
            return false;
         }
      }

      close(fd);
      return true;
   }

   static bool attachLoopDevice(const String& backingFilePath, String& loopDevicePath, String *failureReport = nullptr)
   {
      String backingFileCString = backingFilePath;
      backingFileCString.addNullTerminator();
      std::vector<char *> argv;
      argv.push_back((char *)"losetup");
      argv.push_back((char *)"--find");
      argv.push_back((char *)"--show");
      argv.push_back(reinterpret_cast<char *>(backingFileCString.data()));
      argv.push_back(nullptr);

      String output;
      if (runExternalCommand("losetup_attach", "losetup", argv, &output, failureReport) == false)
      {
         return false;
      }

      loopDevicePath.assign(output);
      return (loopDevicePath.size() > 0);
   }

   static bool refreshLoopDeviceCapacity(const String& loopDevicePath, String *failureReport = nullptr)
   {
      String loopDeviceCString = loopDevicePath;
      loopDeviceCString.addNullTerminator();
      std::vector<char *> argv;
      argv.push_back((char *)"losetup");
      argv.push_back((char *)"-c");
      argv.push_back(reinterpret_cast<char *>(loopDeviceCString.data()));
      argv.push_back(nullptr);
      return runExternalCommand("losetup_refresh", "losetup", argv, nullptr, failureReport);
   }

   static void detachLoopDevice(const String& loopDevicePath)
   {
      if (loopDevicePath.size() == 0)
      {
         return;
      }

      std::vector<char *> argv;
      argv.push_back((char *)"losetup");
      argv.push_back((char *)"-d");
      String loopDeviceCString = loopDevicePath;
      loopDeviceCString.addNullTerminator();
      argv.push_back(reinterpret_cast<char *>(loopDeviceCString.data()));
      argv.push_back(nullptr);
      String ignored;
      (void)runExternalCommand("losetup_detach", "losetup", argv, &ignored, nullptr);
   }

   static bool pathExists(const String& path)
   {
      std::string nativePath(reinterpret_cast<const char *>(path.data()), path.size());
      return (access(nativePath.c_str(), F_OK) == 0);
   }

   static void appendAssignedGPUPciBusVariants(const String& busAddress, Vector<String>& variants)
   {
      variants.clear();
      if (busAddress.size() == 0)
      {
         return;
      }

      auto appendUnique = [&] (const String& candidate) -> void {
         for (const String& existing : variants)
         {
            if (existing.equals(candidate))
            {
               return;
            }
         }

         variants.push_back(candidate);
      };

      String lowered = {};
      lowered.reserve(busAddress.size());
      for (uint64_t index = 0; index < busAddress.size(); ++index)
      {
         lowered.append(char(std::tolower(unsigned(busAddress[index]))));
      }

      appendUnique(busAddress);
      appendUnique(lowered);

      auto appendTrimmedDomainVariant = [&] (const String& candidate) -> void {
         int32_t firstColon = -1;
         for (uint64_t index = 0; index < candidate.size(); ++index)
         {
            if (candidate[index] == ':')
            {
               firstColon = int32_t(index);
               break;
            }
         }

         if (firstColon == 8)
         {
            bool leadingZeroDomain = true;
            for (int32_t index = 0; index < 4; ++index)
            {
               if (candidate[uint64_t(index)] != '0')
               {
                  leadingZeroDomain = false;
                  break;
               }
            }

            if (leadingZeroDomain)
            {
               appendUnique(candidate.substr(4, candidate.size() - 4, Copy::yes));
            }
         }
      };

      appendTrimmedDomainVariant(busAddress);
      appendTrimmedDomainVariant(lowered);
   }

   static void collectAssignedGPUDevicePathCandidates(const AssignedGPUDevice& gpu, Vector<String>& paths)
   {
      paths.clear();

      Vector<String> busVariants = {};
      appendAssignedGPUPciBusVariants(gpu.busAddress, busVariants);

      for (const String& busVariant : busVariants)
      {
         String path = {};
         path.snprintf<"/dev/dri/by-path/pci-{}-render"_ctv>(busVariant);
         paths.push_back(path);
         path.snprintf<"/dev/dri/by-path/pci-{}-card"_ctv>(busVariant);
         paths.push_back(path);
      }
   }

   static bool canonicalGPUDevicePathMatchesNumericSuffix(const String& path, const String& prefix)
   {
      if (path.size() <= prefix.size())
      {
         return false;
      }

      if (memcmp(path.data(), prefix.data(), prefix.size()) != 0)
      {
         return false;
      }

      for (uint64_t index = prefix.size(); index < path.size(); ++index)
      {
         if (std::isdigit(unsigned(path[index])) == 0)
         {
            return false;
         }
      }

      return true;
   }

   static bool isAllowlistedCanonicalGPUDevicePath(const String& canonicalPath)
   {
      if (canonicalPath.equal("/dev/nvidiactl"_ctv)
         || canonicalPath.equal("/dev/nvidia-uvm"_ctv)
         || canonicalPath.equal("/dev/nvidia-uvm-tools"_ctv)
         || canonicalPath.equal("/dev/nvidia-modeset"_ctv))
      {
         return true;
      }

      return canonicalGPUDevicePathMatchesNumericSuffix(canonicalPath, "/dev/nvidia"_ctv)
         || canonicalGPUDevicePathMatchesNumericSuffix(canonicalPath, "/dev/dri/card"_ctv)
         || canonicalGPUDevicePathMatchesNumericSuffix(canonicalPath, "/dev/dri/renderD"_ctv);
   }

   static bool resolveCanonicalPath(const String& path, String& canonicalPath)
   {
      canonicalPath.clear();
      if (path.size() == 0 || pathExists(path) == false)
      {
         return false;
      }

      std::error_code error = {};
      std::filesystem::path resolved = std::filesystem::canonical(std::string(reinterpret_cast<const char *>(path.data()), path.size()), error);
      if (error.value() != 0)
      {
         canonicalPath.assign(path);
         return true;
      }

      std::string resolvedNative = resolved.string();
      canonicalPath.assign(resolvedNative.data(), resolvedNative.size());
      return canonicalPath.size() > 0;
   }

   static bool pathStat(const String& path, struct stat& statbuf)
   {
      std::string nativePath(reinterpret_cast<const char *>(path.data()), path.size());
      return stat(nativePath.c_str(), &statbuf) == 0;
   }

   static constexpr uint64_t secureContainerResolveFlags =
      RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS;

   static bool validateContainerRelativePathComponent(const String& component, const String& fullPath, String *failureReport = nullptr)
   {
      if (component.size() == 0 || component.equal("."_ctv) || component.equal(".."_ctv))
      {
         if (failureReport) failureReport->snprintf<"container rootfs path {} contains an unsafe path component"_ctv>(fullPath);
         return false;
      }

      return true;
   }

   static bool openContainerDirectoryTreeAt(int rootfd, const String& relativePath, bool create, int createFlags, int& directoryFD, String *failureReport = nullptr)
   {
      directoryFD = -1;
      if (rootfd < 0)
      {
         if (failureReport) failureReport->assign("container rootfs fd is invalid"_ctv);
         return false;
      }

      if (relativePath.size() == 0)
      {
         directoryFD = dup(rootfd);
         if (directoryFD < 0 && failureReport)
         {
            failureReport->snprintf<"failed to duplicate container rootfs fd errno={}({})"_ctv>(errno, String(strerror(errno)));
         }
         return directoryFD >= 0;
      }

      int currentFD = dup(rootfd);
      if (currentFD < 0)
      {
         if (failureReport) failureReport->snprintf<"failed to duplicate container rootfs fd errno={}({})"_ctv>(errno, String(strerror(errno)));
         return false;
      }

      uint64_t cursor = 0;
      while (cursor < relativePath.size())
      {
         while (cursor < relativePath.size() && relativePath[cursor] == '/')
         {
            cursor += 1;
         }

         if (cursor >= relativePath.size())
         {
            break;
         }

         uint64_t componentStart = cursor;
         while (cursor < relativePath.size() && relativePath[cursor] != '/')
         {
            cursor += 1;
         }

         String component = {};
         component.append(relativePath.data() + componentStart, cursor - componentStart);
         if (validateContainerRelativePathComponent(component, relativePath, failureReport) == false)
         {
            close(currentFD);
            return false;
         }

         if (create)
         {
            if (mkdirat(currentFD, component.c_str(), createFlags) != 0 && errno != EEXIST)
            {
               if (failureReport)
               {
                  failureReport->snprintf<"failed to create container rootfs directory {} errno={}({})"_ctv>(
                     relativePath,
                     errno,
                     String(strerror(errno)));
               }
               close(currentFD);
               return false;
            }
         }

         int nextFD = Filesystem::openDirectoryAt(
            currentFD,
            component,
            O_PATH | O_DIRECTORY | O_CLOEXEC,
            secureContainerResolveFlags);
         if (nextFD < 0)
         {
            if (failureReport)
            {
               failureReport->snprintf<"failed to open container rootfs directory {} without following symlinks errno={}({})"_ctv>(
                  relativePath,
                  errno,
                  String(strerror(errno)));
            }
            close(currentFD);
            return false;
         }

         close(currentFD);
         currentFD = nextFD;
      }

      directoryFD = currentFD;
      return true;
   }

   static bool assignContainerDescriptorOwnership(int descriptor, uid_t userID, gid_t groupID, String *failureReport = nullptr)
   {
      if (descriptor < 0)
      {
         if (failureReport) failureReport->assign("container descriptor is invalid"_ctv);
         return false;
      }

      if (fchownat(descriptor, "", userID, groupID, AT_EMPTY_PATH) != 0)
      {
         if (failureReport)
         {
            failureReport->snprintf<"failed to chown container descriptor via descriptor errno={}({})"_ctv>(
               errno,
               String(strerror(errno)));
         }
         return false;
      }

      return true;
   }

   static bool openContainerFileAtNoSymlinks(
      int rootfd,
      const String& relativePath,
      bool create,
      int createMode,
      int& fileFD,
      String *failureReport = nullptr)
   {
      fileFD = -1;
      int32_t slash = relativePath.rfindChar('/');
      String filename = {};
      filename.assign(relativePath.data() + slash + 1, relativePath.size() - uint64_t(slash + 1));
      if (validateContainerRelativePathComponent(filename, relativePath, failureReport) == false)
      {
         return false;
      }

      int parentFD = -1;
      if (slash >= 0)
      {
         String parentPath = {};
         parentPath.assign(relativePath.data(), uint64_t(slash));
         if (openContainerDirectoryTreeAt(rootfd, parentPath, true, S_IRWXU, parentFD, failureReport) == false)
         {
            return false;
         }
      }
      else
      {
         parentFD = dup(rootfd);
         if (parentFD < 0)
         {
            if (failureReport) failureReport->snprintf<"failed to duplicate container rootfs fd errno={}({})"_ctv>(errno, String(strerror(errno)));
            return false;
         }
      }

      int openFlags = O_CLOEXEC | O_NOFOLLOW;
      if (create)
      {
         openFlags |= O_CREAT;
      }

      fileFD = Filesystem::openFileAt(
         parentFD,
         filename,
         openFlags,
         createMode,
         secureContainerResolveFlags);
      int openErrno = errno;
      close(parentFD);

      if (fileFD < 0)
      {
         if (failureReport)
         {
            failureReport->snprintf<"failed to create container rootfs file {} without following symlinks errno={}({})"_ctv>(
               relativePath,
               openErrno,
               String(strerror(openErrno)));
         }
         return false;
      }

      return true;
   }

   static bool createContainerFileAtNoSymlinks(int rootfd, const String& relativePath, int createMode = S_IRUSR | S_IWUSR, String *failureReport = nullptr)
   {
      int fileFD = -1;
      bool opened = openContainerFileAtNoSymlinks(rootfd, relativePath, true, createMode, fileFD, failureReport);
      if (fileFD >= 0)
      {
         close(fileFD);
      }
      return opened;
   }

   static bool openVerifiedContainerArtifactRoot(Container *container, int& artifactRootFD, String *failureReport = nullptr)
   {
      artifactRootFD = -1;
      if (container == nullptr || container->artifactRootPath.size() == 0)
      {
         if (failureReport) failureReport->assign("container artifact root path is missing"_ctv);
         return false;
      }

      artifactRootFD = Filesystem::openDirectoryAt(
         -1,
         container->artifactRootPath,
         O_PATH | O_DIRECTORY | O_CLOEXEC,
         RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS);
      if (artifactRootFD < 0 && failureReport)
      {
         failureReport->snprintf<"failed to open artifact root {} without following symlinks errno={}({})"_ctv>(
            container->artifactRootPath,
            errno,
            String(strerror(errno)));
      }

      return artifactRootFD >= 0;
   }

   static bool openVerifiedContainerRootfs(Container *container, int& rootfd, String *failureReport = nullptr)
   {
      rootfd = -1;
      int artifactRootFD = -1;
      if (openVerifiedContainerArtifactRoot(container, artifactRootFD, failureReport) == false)
      {
         return false;
      }

      bool opened = openContainerDirectoryTreeAt(artifactRootFD, "rootfs"_ctv, false, 0, rootfd, failureReport);
      close(artifactRootFD);
      if (opened == false)
      {
         rootfd = -1;
         return false;
      }

      struct stat rootStat = {};
      if (fstat(rootfd, &rootStat) != 0 || S_ISDIR(rootStat.st_mode) == 0)
      {
         if (failureReport)
         {
            failureReport->snprintf<"container rootfs is not a directory errno={}({})"_ctv>(errno, String(strerror(errno)));
         }
         close(rootfd);
         rootfd = -1;
         return false;
      }

      return true;
   }

public:

   template <typename... Args>
   static void appendContainerTrace(Container *container, const char *format, Args... args)
   {
      if (container == nullptr || format == nullptr || container->rootfsPath.size() == 0)
      {
         return;
      }

      String tracePath = {};
      tracePath.assign(container->rootfsPath);
      tracePath.append("/neuron.hosttrace.log"_ctv);

      int fd = open(tracePath.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0644);
      if (fd < 0)
      {
         return;
      }

      (void)dprintf(fd, format, args...);
      (void)close(fd);
   }

private:

   static bool assignContainerRootfsOwnership(int rootfd, uid_t userID, gid_t groupID, String *failureReport = nullptr)
   {
      return assignContainerDescriptorOwnership(rootfd, userID, groupID, failureReport);
   }

   static bool validateContainerArtifactShapeAt(int artifactRootFD, String *failureReport = nullptr)
   {
      Vector<String> topLevelEntries = {};
      if (listDirectoryEntriesAt(artifactRootFD, topLevelEntries, failureReport) == false)
      {
         return false;
      }

      bool sawRootfs = false;
      bool sawPrivateMetadataDirectory = false;
      for (const String& entryName : topLevelEntries)
      {
         if (entryName.equal("rootfs"_ctv))
         {
            sawRootfs = true;
            continue;
         }

         if (entryName.equal(".prodigy-private"_ctv))
         {
            sawPrivateMetadataDirectory = true;
            continue;
         }

         if (failureReport) failureReport->snprintf<"unexpected top-level artifact entry {}"_ctv>(entryName);
         return false;
      }

      if (sawRootfs == false)
      {
         if (failureReport) failureReport->assign("container artifact is missing required top-level rootfs directory"_ctv);
         return false;
      }

      if (sawPrivateMetadataDirectory == false)
      {
         if (failureReport) failureReport->assign("container artifact is missing required .prodigy-private directory"_ctv);
         return false;
      }

      int rootfsFD = Filesystem::openDirectoryAt(
         artifactRootFD,
         "rootfs"_ctv,
         O_PATH | O_DIRECTORY | O_CLOEXEC,
         secureContainerResolveFlags);
      if (rootfsFD < 0)
      {
         if (failureReport) failureReport->snprintf<"failed to open artifact rootfs without following symlinks errno={}({})"_ctv>(errno, String(strerror(errno)));
         return false;
      }

      struct stat rootfsStat = {};
      if (fstat(rootfsFD, &rootfsStat) != 0 || S_ISDIR(rootfsStat.st_mode) == 0)
      {
         if (failureReport) failureReport->snprintf<"artifact rootfs is not a directory errno={}({})"_ctv>(errno, String(strerror(errno)));
         close(rootfsFD);
         return false;
      }
      close(rootfsFD);

      int privateFD = Filesystem::openDirectoryAt(
         artifactRootFD,
         ".prodigy-private"_ctv,
         O_RDONLY | O_DIRECTORY | O_CLOEXEC,
         secureContainerResolveFlags);
      if (privateFD < 0)
      {
         if (failureReport) failureReport->snprintf<"failed to open artifact private metadata directory without following symlinks errno={}({})"_ctv>(errno, String(strerror(errno)));
         return false;
      }

      Vector<String> privateEntries = {};
      bool listedPrivateEntries = listDirectoryEntriesAt(privateFD, privateEntries, failureReport);
      if (listedPrivateEntries == false)
      {
         close(privateFD);
         return false;
      }

      if (privateEntries.size() != 1 || privateEntries[0].equal("launch.metadata"_ctv) == false)
      {
         if (failureReport)
         {
            if (privateEntries.size() == 0)
            {
               failureReport->assign("artifact private metadata directory is missing launch.metadata"_ctv);
            }
            else
            {
               failureReport->snprintf<"artifact private metadata directory must contain only launch.metadata, found {} entries"_ctv>(uint32_t(privateEntries.size()));
            }
         }
         close(privateFD);
         return false;
      }

      int metadataFD = Filesystem::openFileAt(
         privateFD,
         "launch.metadata"_ctv,
         O_RDONLY | O_CLOEXEC | O_NOFOLLOW,
         0,
         secureContainerResolveFlags);
      if (metadataFD < 0)
      {
         if (failureReport) failureReport->snprintf<"failed to open launch.metadata without following symlinks errno={}({})"_ctv>(errno, String(strerror(errno)));
         close(privateFD);
         return false;
      }

      struct stat metadataStat = {};
      bool metadataIsRegular = (fstat(metadataFD, &metadataStat) == 0 && S_ISREG(metadataStat.st_mode) != 0);
      if (metadataIsRegular == false && failureReport)
      {
         failureReport->snprintf<"artifact launch.metadata is not a regular file errno={}({})"_ctv>(errno, String(strerror(errno)));
      }
      else if (metadataIsRegular && uint64_t(metadataStat.st_size) > maxLaunchMetadataBytes)
      {
         if (failureReport) failureReport->snprintf<"artifact launch.metadata exceeds maximum size: {} > {}"_ctv>(
            uint64_t(metadataStat.st_size),
            maxLaunchMetadataBytes);
         metadataIsRegular = false;
      }

      close(metadataFD);
      close(privateFD);
      return metadataIsRegular;
   }

   static bool validateContainerArtifactShape(const String& artifactRootPath, String *failureReport = nullptr)
   {
      int artifactRootFD = Filesystem::openDirectoryAt(
         -1,
         artifactRootPath,
         O_RDONLY | O_DIRECTORY | O_CLOEXEC,
         RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS);
      if (artifactRootFD < 0)
      {
         if (failureReport) failureReport->snprintf<"failed to open artifact root {} without following symlinks errno={}({})"_ctv>(artifactRootPath, errno, String(strerror(errno)));
         return false;
      }

      bool valid = validateContainerArtifactShapeAt(artifactRootFD, failureReport);
      close(artifactRootFD);
      return valid;
   }

   static bool verifyCompressedContainerBlob(
      const String& compressedContainerPath,
      const String& expectedDigest,
      uint64_t expectedBytes,
      String *failureReport = nullptr)
   {
      if (expectedDigest.size() == 0)
      {
         if (failureReport) failureReport->assign("container blob sha256 is missing from the plan"_ctv);
         return false;
      }

      if (expectedBytes == 0)
      {
         if (failureReport) failureReport->assign("container blob size is missing from the plan"_ctv);
         return false;
      }

      if (expectedBytes > maxCompressedContainerBlobBytes)
      {
         if (failureReport) failureReport->snprintf<"container blob size exceeds maximum: {} > {}"_ctv>(
            expectedBytes,
            maxCompressedContainerBlobBytes);
         return false;
      }

      String actualDigest = {};
      uint64_t actualBytes = 0;
      if (prodigyFileMatchesExpectedSHA256HexAndSize(compressedContainerPath, expectedDigest, expectedBytes, actualDigest, &actualBytes, failureReport) == false)
      {
         return false;
      }

      return true;
   }

   static bool prepareContainerDeviceMountTarget(
      int rootfd,
      int devFD,
      const String& deviceName,
      uid_t userID,
      gid_t groupID,
      dev_t deviceNumber,
      String *failureReport = nullptr)
   {
      String deviceNameText = {};
      deviceNameText.assign(deviceName);
      if (mknodat(devFD, deviceNameText.c_str(), S_IFCHR | 0666, deviceNumber) == 0 || errno == EEXIST)
      {
         if (fchownat(devFD, deviceNameText.c_str(), userID, groupID, AT_SYMLINK_NOFOLLOW) != 0)
         {
            if (failureReport)
            {
               failureReport->snprintf<"failed to chown container device node {} errno={}({})"_ctv>(
                  deviceName,
                  errno,
                  String(strerror(errno)));
            }
            return false;
         }

         return true;
      }

      int createErrno = errno;
      if (createErrno != EPERM && createErrno != EACCES)
      {
         if (failureReport)
         {
            failureReport->snprintf<"failed to create container device node {} errno={}({})"_ctv>(
               deviceName,
               createErrno,
               String(strerror(createErrno)));
         }
         return false;
      }

      String relativePath = {};
      relativePath.assign("dev/"_ctv);
      relativePath.append(deviceName);
      if (createContainerFileAtNoSymlinks(rootfd, relativePath, S_IRUSR | S_IWUSR, failureReport) == false)
      {
         return false;
      }

      if (fchownat(devFD, deviceNameText.c_str(), userID, groupID, AT_SYMLINK_NOFOLLOW) != 0)
      {
         if (failureReport)
         {
            failureReport->snprintf<"failed to chown container device placeholder {} errno={}({})"_ctv>(
               deviceName,
               errno,
               String(strerror(errno)));
         }
         return false;
      }

      return true;
   }

   static bool prepareContainerRootFSMountTargets(Container *container, int rootfd, String *failureReport = nullptr)
   {
      uid_t userID = container ? uid_t(container->userID) : 0;
      gid_t groupID = container ? gid_t(container->userID) : 0;

      int devFD = -1;
      if (openContainerDirectoryTreeAt(rootfd, "dev"_ctv, true, S_IRWXU, devFD, failureReport) == false)
      {
         return false;
      }

      if (assignContainerDescriptorOwnership(devFD, userID, groupID, failureReport) == false
         || prepareContainerDeviceMountTarget(rootfd, devFD, "null"_ctv, userID, groupID, makedev(1, 3), failureReport) == false
         || prepareContainerDeviceMountTarget(rootfd, devFD, "zero"_ctv, userID, groupID, makedev(1, 5), failureReport) == false
         || prepareContainerDeviceMountTarget(rootfd, devFD, "random"_ctv, userID, groupID, makedev(1, 8), failureReport) == false
         || prepareContainerDeviceMountTarget(rootfd, devFD, "urandom"_ctv, userID, groupID, makedev(1, 9), failureReport) == false)
      {
         close(devFD);
         return false;
      }
      close(devFD);

      int procFD = -1;
      if (openContainerDirectoryTreeAt(rootfd, "proc"_ctv, true, S_IRWXU, procFD, failureReport) == false)
      {
         return false;
      }
      if (assignContainerDescriptorOwnership(procFD, userID, groupID, failureReport) == false)
      {
         close(procFD);
         return false;
      }
      close(procFD);

      int etcFD = -1;
      if (openContainerDirectoryTreeAt(rootfd, "etc"_ctv, true, S_IRWXU, etcFD, failureReport) == false)
      {
         return false;
      }
      if (assignContainerDescriptorOwnership(etcFD, userID, groupID, failureReport) == false)
      {
         close(etcFD);
         return false;
      }
      close(etcFD);

      int resolvFD = -1;
      if (openContainerFileAtNoSymlinks(rootfd, "etc/resolv.conf"_ctv, true, S_IRUSR | S_IWUSR, resolvFD, failureReport) == false)
      {
         return false;
      }
      bool resolvOwned = assignContainerDescriptorOwnership(resolvFD, userID, groupID, failureReport);
      close(resolvFD);
      if (resolvOwned == false)
      {
         return false;
      }

      if (container != nullptr && container->plan.config.storageMB > 0)
      {
         int storageFD = -1;
         if (openContainerDirectoryTreeAt(rootfd, "storage"_ctv, true, S_IRWXU, storageFD, failureReport) == false)
         {
            return false;
         }
         if (assignContainerDescriptorOwnership(storageFD, userID, groupID, failureReport) == false)
         {
            close(storageFD);
            return false;
         }
         close(storageFD);
      }

      return true;
   }

   static bool bindMountHostDeviceIntoRootFS(const String& sourcePath, const String& containerRoot, String *failureReport = nullptr)
   {
      if (sourcePath.size() == 0 || containerRoot.size() == 0 || sourcePath[0] != '/')
      {
         if (failureReport) failureReport->assign("host device mount source path must be absolute"_ctv);
         return false;
      }

      struct stat sourceStat = {};
      if (pathStat(sourcePath, sourceStat) == false)
      {
         if (failureReport) failureReport->snprintf<"host device source {} missing"_ctv>(sourcePath);
         return false;
      }

      if (S_ISCHR(sourceStat.st_mode) == 0)
      {
         if (failureReport) failureReport->snprintf<"host device source {} is not a character device"_ctv>(sourcePath);
         return false;
      }

      String targetPath = {};
      targetPath.assign(containerRoot);
      targetPath.append(sourcePath);

      String sourcePathText = {};
      sourcePathText.assign(sourcePath);
      if (mount(sourcePathText.c_str(), targetPath.c_str(), nullptr, MS_BIND, nullptr) != 0)
      {
         if (failureReport) failureReport->snprintf<"failed to bind mount host device {}"_ctv>(sourcePath);
         return false;
      }

      if (mount(nullptr, targetPath.c_str(), nullptr, MS_BIND | MS_REMOUNT | MS_NOSUID, nullptr) != 0)
      {
         if (failureReport) failureReport->snprintf<"failed to remount host device {}"_ctv>(sourcePath);
         return false;
      }

      return true;
   }

   static bool bindMountFileIntoRootFS(const String& sourcePath, const String& containerRoot, int containerRootFD, String *failureReport = nullptr)
   {
      if (sourcePath.size() == 0 || containerRoot.size() == 0 || containerRootFD < 0)
      {
         return false;
      }

      if (isAllowlistedCanonicalGPUDevicePath(sourcePath) == false)
      {
         if (failureReport) failureReport->snprintf<"gpu device source {} is not allowlisted"_ctv>(sourcePath);
         return false;
      }

      struct stat sourceStat = {};
      if (pathStat(sourcePath, sourceStat) == false)
      {
         if (failureReport) failureReport->snprintf<"gpu device source {} missing"_ctv>(sourcePath);
         return false;
      }

      if (S_ISCHR(sourceStat.st_mode) == 0)
      {
         if (failureReport) failureReport->snprintf<"gpu device source {} is not a character device"_ctv>(sourcePath);
         return false;
      }

      String relativeTargetPath = {};
      relativeTargetPath.assign(sourcePath.data() + 1, sourcePath.size() - 1);
      if (createContainerFileAtNoSymlinks(containerRootFD, relativeTargetPath, S_IRUSR | S_IWUSR, failureReport) == false)
      {
         return false;
      }

      String targetPath = {};
      targetPath.assign(containerRoot);
      targetPath.append(sourcePath);

      std::string nativeSourcePath(reinterpret_cast<const char *>(sourcePath.data()), sourcePath.size());
      if (mount(nativeSourcePath.c_str(), targetPath.c_str(), nullptr, MS_BIND, nullptr) != 0)
      {
         if (failureReport) failureReport->snprintf<"failed to bind mount gpu device {}"_ctv>(sourcePath);
         return false;
      }

      if (mount(nullptr, targetPath.c_str(), nullptr, MS_BIND | MS_REMOUNT | MS_NOSUID, nullptr) != 0)
      {
         if (failureReport) failureReport->snprintf<"failed to remount gpu device {}"_ctv>(targetPath);
         return false;
      }

      return true;
   }

   static bool parseNvidiaDeviceMinor(const String& informationPath, uint32_t& deviceMinor)
   {
      deviceMinor = 0;
      String information = {};
      String mutableInformationPath = informationPath;
      Filesystem::openReadAtClose(-1, mutableInformationPath, information);
      if (information.size() == 0)
      {
         return false;
      }

      String prefix = "Device Minor:"_ctv;
      uint64_t lineHead = 0;
      for (uint64_t index = 0; index <= information.size(); ++index)
      {
         if (index < information.size() && information[index] != '\n')
         {
            continue;
         }

         uint64_t lineTail = index;
         if ((lineTail - lineHead) >= prefix.size() && memcmp(information.data() + lineHead, prefix.data(), prefix.size()) == 0)
         {
            String value = {};
            uint64_t cursor = lineHead + prefix.size();
            while (cursor < lineTail && std::isspace(unsigned(information[cursor])))
            {
               cursor += 1;
            }

            if (cursor < lineTail)
            {
               value.assign(information.data() + cursor, lineTail - cursor);
               unsigned long parsed = std::strtoul(value.c_str(), nullptr, 10);
               if (parsed > std::numeric_limits<uint32_t>::max())
               {
                  return false;
               }

               deviceMinor = uint32_t(parsed);
               return true;
            }
         }

         lineHead = index + 1;
      }

      return false;
   }

   static bool mountAssignedGPUDevicesInCurrentNamespace(Container *container, const String& containerRoot, int containerRootFD, String *failureReport = nullptr)
   {
      if (container == nullptr || container->plan.assignedGPUDevices.empty())
      {
         return true;
      }

      bytell_hash_set<String> mountedPaths = {};
      auto mountUniquePath = [&] (const String& sourcePath, bool required) -> bool {
         String canonicalPath = {};
         if (resolveCanonicalPath(sourcePath, canonicalPath) == false)
         {
            return required == false;
         }

         if (mountedPaths.contains(canonicalPath))
         {
            return true;
         }

         if (bindMountFileIntoRootFS(canonicalPath, containerRoot, containerRootFD, failureReport) == false)
         {
            return false;
         }

         mountedPaths.insert(canonicalPath);
         return true;
      };

      bool needsNvidiaGlobals = false;
      for (const AssignedGPUDevice& gpu : container->plan.assignedGPUDevices)
      {
         Vector<String> candidates = {};
         collectAssignedGPUDevicePathCandidates(gpu, candidates);

         bool mountedAnyPerGPUDevice = false;
         for (const String& candidate : candidates)
         {
            if (mountUniquePath(candidate, false))
            {
               String canonicalPath = {};
               if (resolveCanonicalPath(candidate, canonicalPath))
               {
                  mountedAnyPerGPUDevice = true;
               }
            }
         }

         String vendorLower = {};
         vendorLower.reserve(gpu.vendor.size());
         for (uint64_t index = 0; index < gpu.vendor.size(); ++index)
         {
            vendorLower.append(char(std::tolower(unsigned(gpu.vendor[index]))));
         }

         if (vendorLower == "nvidia"_ctv)
         {
            needsNvidiaGlobals = true;

            Vector<String> busVariants = {};
            appendAssignedGPUPciBusVariants(gpu.busAddress, busVariants);
            bool mountedNvidiaMinor = false;
            for (const String& busVariant : busVariants)
            {
               String informationPath = {};
               informationPath.snprintf<"/proc/driver/nvidia/gpus/{}/information"_ctv>(busVariant);
               uint32_t deviceMinor = 0;
               if (parseNvidiaDeviceMinor(informationPath, deviceMinor))
               {
                  String nvidiaPath = {};
                  nvidiaPath.snprintf<"/dev/nvidia{itoa}"_ctv>(deviceMinor);
                  if (mountUniquePath(nvidiaPath, true) == false)
                  {
                     return false;
                  }

                  mountedNvidiaMinor = true;
                  break;
               }
            }

            if (mountedNvidiaMinor == false)
            {
               if (failureReport) failureReport->snprintf<"failed to resolve nvidia gpu device for bus {}"_ctv>(gpu.busAddress);
               return false;
            }
         }

         if (mountedAnyPerGPUDevice == false && vendorLower != "nvidia"_ctv)
         {
            if (failureReport) failureReport->snprintf<"failed to resolve gpu device nodes for bus {}"_ctv>(gpu.busAddress);
            return false;
         }
      }

      if (needsNvidiaGlobals)
      {
         if (mountUniquePath("/dev/nvidiactl"_ctv, true) == false)
         {
            return false;
         }

         (void)mountUniquePath("/dev/nvidia-uvm"_ctv, false);
         (void)mountUniquePath("/dev/nvidia-uvm-tools"_ctv, false);
         (void)mountUniquePath("/dev/nvidia-modeset"_ctv, false);
      }

      return true;
   }

public:
#if PRODIGY_DEBUG
   static bool debugIsAllowlistedCanonicalGPUDevicePath(const String& sourcePath)
   {
      return isAllowlistedCanonicalGPUDevicePath(sourcePath);
   }

   static bool debugMountAssignedGPUDevicesInCurrentNamespace(Container *container, const String& containerRoot, String *failureReport = nullptr)
   {
      String mutableContainerRoot = {};
      mutableContainerRoot.assign(containerRoot);
      int containerRootFD = Filesystem::openDirectoryAt(
         -1,
         mutableContainerRoot,
         O_PATH | O_DIRECTORY | O_CLOEXEC,
         RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS);
      if (containerRootFD < 0)
      {
         if (failureReport) failureReport->snprintf<"failed to open debug container root {} without following symlinks errno={}({})"_ctv>(containerRoot, errno, String(strerror(errno)));
         return false;
      }

      bool mounted = mountAssignedGPUDevicesInCurrentNamespace(container, containerRoot, containerRootFD, failureReport);
      close(containerRootFD);
      return mounted;
   }

   static bool debugOpenVerifiedContainerRootfs(Container *container, String *failureReport = nullptr)
   {
      int rootfd = -1;
      bool opened = openVerifiedContainerRootfs(container, rootfd, failureReport);
      if (rootfd >= 0)
      {
         close(rootfd);
      }
      return opened;
   }

   static bool debugAssignContainerRootfsOwnership(Container *container, uint32_t userID, uint32_t groupID, String *failureReport = nullptr)
   {
      int rootfd = -1;
      if (openVerifiedContainerRootfs(container, rootfd, failureReport) == false)
      {
         return false;
      }

      bool assigned = assignContainerRootfsOwnership(rootfd, uid_t(userID), gid_t(groupID), failureReport);
      close(rootfd);
      return assigned;
   }

   static bool debugPrepareContainerRootFSMountTargets(Container *container, String *failureReport = nullptr)
   {
      int rootfd = -1;
      if (openVerifiedContainerRootfs(container, rootfd, failureReport) == false)
      {
         return false;
      }

      bool prepared = prepareContainerRootFSMountTargets(container, rootfd, failureReport);
      close(rootfd);
      return prepared;
   }

   static bool debugPrepareBindMountFileTargetInRootFS(Container *container, const String& sourcePath, String *failureReport = nullptr)
   {
      if (sourcePath.size() == 0 || sourcePath[0] != '/')
      {
         if (failureReport) failureReport->assign("bind mount target source path must be absolute"_ctv);
         return false;
      }

      int rootfd = -1;
      if (openVerifiedContainerRootfs(container, rootfd, failureReport) == false)
      {
         return false;
      }

      String relativeTargetPath = {};
      relativeTargetPath.assign(sourcePath.data() + 1, sourcePath.size() - 1);
      bool prepared = createContainerFileAtNoSymlinks(rootfd, relativeTargetPath, S_IRUSR | S_IWUSR, failureReport);
      close(rootfd);
      return prepared;
   }
#endif

   static bool isEligibleContainerStorageFilesystemType(const String& filesystemType)
   {
      return filesystemType.equal("ext4"_ctv)
         || filesystemType.equal("xfs"_ctv)
         || filesystemType.equal("btrfs"_ctv)
         || filesystemType.equal("f2fs"_ctv)
         || filesystemType.equal("zfs"_ctv)
         || filesystemType.equal("bcachefs"_ctv);
   }

   static void collectConfiguredContainerStorageMountPaths(Vector<String>& configuredMountPaths)
   {
      configuredMountPaths.clear();

      if (thisNeuron == nullptr)
      {
         return;
      }

      if (const MachineHardwareProfile *hardware = thisNeuron->latestHardwareProfileIfReady(); hardware != nullptr)
      {
         // Dedicated loop-backed storage must come from the machine's
         // inventoried disk mount points. Scanning arbitrary writable mounts in
         // the current namespace can accidentally pick transient harness mounts
         // and break container materialization.
         prodigyCollectUniqueContainerStorageMountPaths(hardware->disks, configuredMountPaths);
      }
   }

   static bool collectEligibleStorageDevicePlans(const String& containerName, uint32_t targetStorageMB, Vector<ProdigyContainerStorageDevicePlan>& devices)
   {
      devices.clear();

      Vector<String> configuredMountPaths;
      collectConfiguredContainerStorageMountPaths(configuredMountPaths);
      if (configuredMountPaths.size() == 0)
      {
         return true;
      }

      dev_t containersDevice = 0;
      bool haveContainersDevice = statDeviceID("/containers"_ctv, containersDevice);

      Vector<String> eligiblePaths;
      eligiblePaths.reserve(configuredMountPaths.size());

      for (const String& mountPath : configuredMountPaths)
      {
         std::string nativePath(reinterpret_cast<const char *>(mountPath.data()), mountPath.size());
         if (access(nativePath.c_str(), W_OK) != 0)
         {
            continue;
         }

         dev_t mountDevice = 0;
         if (statDeviceID(mountPath, mountDevice) == false)
         {
            continue;
         }

         if (haveContainersDevice && mountDevice == containersDevice)
         {
            continue;
         }

         uint64_t availableBytes = 0;
         if (statFilesystemAvailability(mountPath, availableBytes) == false || availableBytes == 0)
         {
            continue;
         }

         eligiblePaths.push_back(mountPath);
      }

      prodigyBuildContainerStorageDevicePlan(eligiblePaths, containerName, targetStorageMB, devices);
      return true;
   }

   static void fillStorageLoopDevicesFromPlans(const Vector<ProdigyContainerStorageDevicePlan>& plans, Vector<Container::StorageLoopDevice>& loopDevices)
   {
      loopDevices.clear();
      loopDevices.reserve(plans.size());

      for (const ProdigyContainerStorageDevicePlan& plan : plans)
      {
         Container::StorageLoopDevice device = {};
         device.mountPath = plan.mountPath;
         device.backingFilePath = plan.backingFilePath;
         device.sizeMB = plan.sizeMB;
         loopDevices.push_back(std::move(device));
      }
   }

   static bool anyContainerStorageBackingFileExists(const Vector<Container::StorageLoopDevice>& loopDevices)
   {
      for (const Container::StorageLoopDevice& device : loopDevices)
      {
         if (pathExists(device.backingFilePath))
         {
            return true;
         }
      }

      return false;
   }

   static bool allContainerStorageBackingFilesExist(const Vector<Container::StorageLoopDevice>& loopDevices)
   {
      if (loopDevices.size() == 0)
      {
         return false;
      }

      for (const Container::StorageLoopDevice& device : loopDevices)
      {
         if (pathExists(device.backingFilePath) == false)
         {
            return false;
         }
      }

      return true;
   }

   static bool mountLoopBackedStorage(Container *container, bool existingBackend, String *failureReport = nullptr)
   {
      if (container == nullptr || container->storageLoopDevices.size() == 0)
      {
         return false;
      }

      if (createDirectoryTree(container->storageRootPath) == false)
      {
         if (failureReport) failureReport->snprintf<"failed to create storage root {}"_ctv>(container->storageRootPath);
         return false;
      }

      for (Container::StorageLoopDevice& device : container->storageLoopDevices)
      {
         if (existingBackend == false)
         {
            if (ensureSizedBackingFile(device.backingFilePath, storageBytesForMB(device.sizeMB), failureReport) == false)
            {
               return false;
            }
         }
         else if (Filesystem::fileExists(device.backingFilePath) == false)
         {
            if (failureReport) failureReport->snprintf<"missing storage backing file {}"_ctv>(device.backingFilePath);
            return false;
         }

         if (attachLoopDevice(device.backingFilePath, device.loopDevicePath, failureReport) == false)
         {
            return false;
         }
      }

      if (existingBackend == false)
      {
         std::vector<char *> argv;
         argv.push_back((char *)"mkfs.btrfs");
         argv.push_back((char *)"-f");
         argv.push_back((char *)"-d");
         argv.push_back((char *)((container->storageLoopDevices.size() > 1) ? "raid0" : "single"));
         argv.push_back((char *)"-m");
         argv.push_back((char *)"single");
         for (Container::StorageLoopDevice& device : container->storageLoopDevices)
         {
            argv.push_back((char *)device.loopDevicePath.c_str());
         }
         argv.push_back(nullptr);

         if (runExternalCommand("mkfs_btrfs_storage", "mkfs.btrfs", argv, nullptr, failureReport) == false)
         {
            return false;
         }
      }

      {
         std::vector<char *> argv;
         argv.push_back((char *)"btrfs");
         argv.push_back((char *)"device");
         argv.push_back((char *)"scan");
         argv.push_back(nullptr);
         String ignored;
         (void)runExternalCommand("btrfs_device_scan", "btrfs", argv, &ignored, nullptr);
      }

      if (mount(container->storageLoopDevices[0].loopDevicePath.c_str(), container->storageRootPath.c_str(), "btrfs", MS_NOSUID | MS_NODEV, nullptr) != 0)
      {
         if (failureReport) failureReport->snprintf<"failed to mount storage root {}: {}"_ctv>(container->storageRootPath, String(strerror(errno)));
         return false;
      }

      if (existingBackend == false)
      {
         std::vector<char *> argv;
         argv.push_back((char *)"btrfs");
         argv.push_back((char *)"subvolume");
         argv.push_back((char *)"create");
         argv.push_back((char *)container->storagePayloadPath.c_str());
         argv.push_back(nullptr);
         if (runExternalCommand("btrfs_storage_subvolume_create", "btrfs", argv, nullptr, failureReport) == false)
         {
            return false;
         }
      }

      return true;
   }

   static bool applyLoopBackedStorageQuota(Container *container, uint32_t targetStorageMB, bool strict, String *failureReport = nullptr)
   {
      if (container == nullptr || container->storageUsesLoopFilesystem == false)
      {
         return true;
      }

      std::vector<char *> enableArgv;
      enableArgv.push_back((char *)"btrfs");
      enableArgv.push_back((char *)"quota");
      enableArgv.push_back((char *)"enable");
      enableArgv.push_back((char *)"-s");
      enableArgv.push_back((char *)container->storageRootPath.c_str());
      enableArgv.push_back(nullptr);
      String quotaOutput;
      bool quotaEnabled = runExternalCommand("btrfs_quota_enable", "btrfs", enableArgv, &quotaOutput, failureReport);

      String limitText;
      limitText.snprintf<"{itoa}M"_ctv>(targetStorageMB);

      std::vector<char *> limitArgv;
      limitArgv.push_back((char *)"btrfs");
      limitArgv.push_back((char *)"qgroup");
      limitArgv.push_back((char *)"limit");
      limitArgv.push_back((char *)limitText.c_str());
      limitArgv.push_back((char *)container->storagePayloadPath.c_str());
      limitArgv.push_back(nullptr);
      bool limitApplied = runExternalCommand("btrfs_qgroup_limit", "btrfs", limitArgv, nullptr, failureReport);

      if (limitApplied)
      {
         return true;
      }

      if (strict && failureReport && failureReport->size() == 0)
      {
         failureReport->assign("failed to apply strict storage quota"_ctv);
      }

      if (strict)
      {
         return false;
      }

      basics_log("container storage quota best-effort fallback uuid=%llu root=%s payload=%s quotaEnabled=%d limitApplied=%d detail=%s\n",
         (unsigned long long)container->plan.uuid,
         container->storageRootPath.c_str(),
         container->storagePayloadPath.c_str(),
         int(quotaEnabled),
         int(limitApplied),
         (failureReport && failureReport->size()) ? failureReport->c_str() : "");
      if (failureReport)
      {
         failureReport->clear();
      }

      return true;
   }

   static bool prepareContainerStorage(Container *container, String *failureReport = nullptr)
   {
      if (container == nullptr || container->plan.config.storageMB == 0)
      {
         return true;
      }

      prodigyContainerStorageRootPathForName(container->name, container->storageRootPath);
      container->storagePayloadPath.assign(container->storageRootPath);
      container->storageUsesLoopFilesystem = false;
      container->storageLoopDevices.clear();

      Vector<ProdigyContainerStorageDevicePlan> devicePlans;
      if (collectEligibleStorageDevicePlans(container->name, container->plan.config.storageMB, devicePlans) == false)
      {
         if (failureReport) failureReport->assign("failed to collect storage devices"_ctv);
         return false;
      }

      if (devicePlans.size() == 0)
      {
         Filesystem::createDirectoryAt(-1, "/containers/storage"_ctv);
         Filesystem::createDirectoryAt(-1, container->storageRootPath);
         if (chown(container->storageRootPath.c_str(), uid_t(container->userID), gid_t(container->userID)) != 0)
         {
            basics_log("createContainer storage chown failed uuid=%llu path=%s userID=%u errno=%d(%s)\n",
               (unsigned long long)container->plan.uuid,
               container->storageRootPath.c_str(),
               unsigned(container->userID),
               errno,
               strerror(errno));
         }

         return true;
      }

      fillStorageLoopDevicesFromPlans(devicePlans, container->storageLoopDevices);
      prodigyContainerStoragePayloadPathForName(container->name, container->storagePayloadPath);
      container->storageUsesLoopFilesystem = true;

      bool anyBackingExists = anyContainerStorageBackingFileExists(container->storageLoopDevices);
      bool allBackingExists = allContainerStorageBackingFilesExist(container->storageLoopDevices);
      if (anyBackingExists != allBackingExists)
      {
         if (failureReport) failureReport->assign("partial storage backing set exists"_ctv);
         return false;
      }

      bool existingBackend = allBackingExists;
      if (mountLoopBackedStorage(container, existingBackend, failureReport) == false)
      {
         return false;
      }

      String quotaFailure;
      bool strictQuota = false;
      if (applyLoopBackedStorageQuota(container, container->plan.config.storageMB, strictQuota, &quotaFailure) == false)
      {
         if (failureReport && quotaFailure.size() > 0)
         {
            failureReport->assign(quotaFailure);
         }
         return false;
      }

      if (chown(container->storagePayloadPath.c_str(), uid_t(container->userID), gid_t(container->userID)) != 0)
      {
         basics_log("createContainer loop storage chown failed uuid=%llu path=%s userID=%u errno=%d(%s)\n",
            (unsigned long long)container->plan.uuid,
            container->storagePayloadPath.c_str(),
            unsigned(container->userID),
            errno,
            strerror(errno));
      }

      return true;
   }

   static bool resizeContainerStorage(Container *container, uint32_t targetStorageMB, String *failureReport = nullptr)
   {
      if (container == nullptr || targetStorageMB == 0)
      {
         if (failureReport) failureReport->assign("target storage must be positive"_ctv);
         return false;
      }

      uint32_t currentStorageMB = container->plan.config.storageMB;
      if (currentStorageMB == 0 && targetStorageMB > 0)
      {
         if (failureReport) failureReport->assign("runtime storage create from zero is unsupported"_ctv);
         return false;
      }

      if (container->storageUsesLoopFilesystem == false)
      {
         return true;
      }

      if (targetStorageMB > currentStorageMB)
      {
         Vector<uint64_t> newSizes;
         if (prodigySplitContainerStorageAcrossDevices(targetStorageMB, uint32_t(container->storageLoopDevices.size()), newSizes) == false)
         {
            if (failureReport) failureReport->assign("failed to split target storage across loop devices"_ctv);
            return false;
         }

         for (uint32_t index = 0; index < container->storageLoopDevices.size(); ++index)
         {
            Container::StorageLoopDevice& device = container->storageLoopDevices[index];
            uint64_t targetDeviceMB = newSizes[index];
            if (targetDeviceMB <= device.sizeMB)
            {
               continue;
            }

            if (ensureSizedBackingFile(device.backingFilePath, storageBytesForMB(targetDeviceMB), failureReport) == false)
            {
               return false;
            }

            if (refreshLoopDeviceCapacity(device.loopDevicePath, failureReport) == false)
            {
               return false;
            }

            device.sizeMB = targetDeviceMB;
         }

         std::vector<char *> resizeArgv;
         resizeArgv.push_back((char *)"btrfs");
         resizeArgv.push_back((char *)"filesystem");
         resizeArgv.push_back((char *)"resize");
         resizeArgv.push_back((char *)"max");
         resizeArgv.push_back((char *)container->storageRootPath.c_str());
         resizeArgv.push_back(nullptr);
         if (runExternalCommand("btrfs_filesystem_resize", "btrfs", resizeArgv, nullptr, failureReport) == false)
         {
            return false;
         }
      }

      String quotaFailure;
      bool strictQuota = (targetStorageMB < currentStorageMB);
      if (applyLoopBackedStorageQuota(container, targetStorageMB, strictQuota, &quotaFailure) == false)
      {
         if (failureReport && quotaFailure.size() > 0)
         {
            failureReport->assign(quotaFailure);
         }
         return false;
      }

      return true;
   }

   static void teardownContainerStorage(Container *container)
   {
      if (container == nullptr || container->plan.config.storageMB == 0)
      {
         return;
      }

      if (container->storageUsesLoopFilesystem)
      {
         if (container->storageRootPath.size() > 0)
         {
            (void)umount2(container->storageRootPath.c_str(), MNT_DETACH);
         }

         for (Container::StorageLoopDevice& device : container->storageLoopDevices)
         {
            detachLoopDevice(device.loopDevicePath);
            if (container->deleteStorageOnCleanUp)
            {
               (void)Filesystem::eraseFile(device.backingFilePath);
            }
         }

         if (container->deleteStorageOnCleanUp && container->storageRootPath.size() > 0)
         {
            (void)eraseDirectoryTree(container->storageRootPath);
         }

         container->storageLoopDevices.clear();
         return;
      }

      if (container->deleteStorageOnCleanUp && container->storageRootPath.size() > 0)
      {
         std::vector<char *> argv;
         argv.push_back((char *)"btrfs");
         argv.push_back((char *)"subvolume");
         argv.push_back((char *)"delete");
         argv.push_back((char *)container->storageRootPath.c_str());
         argv.push_back(nullptr);
         String ignored;
         if (runExternalCommand("btrfs_storage_subvolume_delete", "btrfs", argv, &ignored, nullptr) == false)
         {
            (void)eraseDirectoryTree(container->storageRootPath);
         }
      }
   }

   static void renameContainerStorageArtifacts(uint128_t oldUUID, uint128_t newUUID)
   {
      String oldName;
      String newName;
      oldName.assignItoa(oldUUID);
      newName.assignItoa(newUUID);

      String oldRootPath;
      String newRootPath;
      prodigyContainerStorageRootPathForName(oldName, oldRootPath);
      prodigyContainerStorageRootPathForName(newName, newRootPath);
      if (pathExists(oldRootPath))
      {
         (void)rename(oldRootPath.c_str(), newRootPath.c_str());
      }

      Vector<String> configuredMountPaths;
      collectConfiguredContainerStorageMountPaths(configuredMountPaths);
      for (const String& mountPath : configuredMountPaths)
      {
         String oldBackingPath;
         String newBackingPath;
         prodigyContainerStorageBackingFilePathForMount(mountPath, oldName, oldBackingPath);
         prodigyContainerStorageBackingFilePathForMount(mountPath, newName, newBackingPath);
         if (pathExists(oldBackingPath))
         {
            (void)rename(oldBackingPath.c_str(), newBackingPath.c_str());
         }
      }
   }

   static void seed_root_cgroupv2_subtree_controllers(void)
   {
      basics_log("seed_root_cgroupv2_subtree_controllers begin\n");
      int rootFD = Filesystem::openDirectoryAt(-1, "/sys/fs/cgroup"_ctv);
      basics_log("seed_root_cgroupv2_subtree_controllers rootFD=%d\n", rootFD);

      // leave the OS 8GB and take the rest

      // on dev box...
      // init.scope using 4.1MB
      // system.slice using 647MB (300MB of that is dropbox and 254MB is ssh)
      // proc-sys-fs-binfmt_misc.mount using 4KB
      // sys-kernel-tracing.mount using 716KB
      // kernel using 115MB
      // page tables 3MB (for 32GB memory)

      // '+cpuset +cpu +io +memory +pids +misc' (hugetlb no longer used)
      Filesystem::openWriteAtClose(-1, "/sys/fs/cgroup/cgroup.subtree_control"_ctv, "+cpuset +memory +pids"_ctv);
      basics_log("seed_root_cgroupv2_subtree_controllers wrote root subtree_control\n");

      int containersFD = Filesystem::createOpenDirectoryAt(-1, "/sys/fs/cgroup/containers.slice"_ctv);
      if (containersFD < 0)
      {
         int createErrno = errno;
         containersFD = Filesystem::openDirectoryAt(-1, "/sys/fs/cgroup/containers.slice"_ctv);
         if (containersFD < 0)
         {
            int openErrno = errno;
            if (mkdirat(AT_FDCWD, "/sys/fs/cgroup/containers.slice", S_IRWXU) != 0 && errno != EEXIST)
            {
               basics_log("seed_root_cgroupv2_subtree_controllers mkdir fallback failed errno=%d(%s)\n", errno, strerror(errno));
            }

            containersFD = open("/sys/fs/cgroup/containers.slice", O_PATH | O_DIRECTORY | O_CLOEXEC);
            if (containersFD < 0)
            {
               basics_log("seed_root_cgroupv2_subtree_controllers failed to open containers.slice createErrno=%d(%s) openErrno=%d(%s) fallbackErrno=%d(%s)\n",
                  createErrno, strerror(createErrno), openErrno, strerror(openErrno), errno, strerror(errno));
            }
         }
      }
      basics_log("seed_root_cgroupv2_subtree_controllers containersFD=%d\n", containersFD);

      Filesystem::openWriteAtClose(-1, "/sys/fs/cgroup/containers.slice/cgroup.subtree_control"_ctv, "+cpuset +memory +pids"_ctv);
      Filesystem::openWriteAtClose(-1, "/sys/fs/cgroup/containers.slice/cgroup.max.depth"_ctv, "2"_ctv);
      basics_log("seed_root_cgroupv2_subtree_controllers wrote containers controls\n");

      String cpusEffective;
      Filesystem::openReadAtClose(-1, "/sys/fs/cgroup/cpuset.cpus.effective"_ctv, cpusEffective);
      if (cpusEffective.size() == 0)
      {
         long nCores = sysconf(_SC_NPROCESSORS_ONLN);
         if (nCores < 1) nCores = 1;
         cpusEffective.snprintf<"0-{itoa}"_ctv>(nCores - 1);
      }
      basics_log("seed_root_cgroupv2_subtree_controllers cpuset.cpus.effective=%s\n", cpusEffective.c_str());

      // Parse effective CPUs in the form "0-7" or single values like "0"
      uint16_t startIdx = 0;
      uint16_t endIdx = 0;
      {
         const char *s = cpusEffective.c_str();
         const char *dash = strchr(s, '-');
         if (dash)
         {
            startIdx = (uint16_t)atoi(s);
            endIdx   = (uint16_t)atoi(dash + 1);
         }
         else
         {
            startIdx = (uint16_t)atoi(s);
            endIdx = startIdx;
         }

         if (endIdx < startIdx)
         {
            endIdx = startIdx;
         }

         if (endIdx > 255)
         {
            endIdx = 255;
         }
      }

      thisNeuron->lcoreCount = endIdx + 1; // CPUs are 0-indexed
      // Initialize all cores as available (0)
      for (uint16_t i = 0; i < 256; ++i) thisNeuron->lcores[i] = 0;
      // Reserve the first nReservedCores for the OS by marking them non-zero (unavailable)
      for (uint16_t i = 0; i < nReservedCores && i < thisNeuron->lcoreCount; ++i) thisNeuron->lcores[i] = 0xFFFF;

      // Remove OS-reserved cores from the containers slice: set e.g. "2-<end>"
      String cpusRange;
      uint16_t firstContainerCore = (nReservedCores < thisNeuron->lcoreCount) ? nReservedCores : thisNeuron->lcoreCount - 1;
      cpusRange.snprintf<"{itoa}-{itoa}"_ctv>(firstContainerCore, endIdx);
      Filesystem::openWriteAtClose(-1, "/sys/fs/cgroup/containers.slice/cpuset.cpus"_ctv, cpusRange);
      Filesystem::openWriteAtClose(-1, "/sys/fs/cgroup/containers.slice/cpuset.cpus.partition"_ctv, "isolated"_ctv);
      basics_log("seed_root_cgroupv2_subtree_controllers complete range=%s lcoreCount=%u\n", cpusRange.c_str(), unsigned(thisNeuron->lcoreCount));

      if (containersFD >= 0) close(containersFD);
      if (rootFD >= 0) close(rootFD);
   }

   static int mount2(StringType auto&& source, StringType auto&& target, uint64_t flags, int pid = -1)
   {
      int fd_userns = -1;

      if (pid > -1)
      {
         String path;
         path.snprintf<"/proc/{itoa}/ns/user"_ctv>(pid);
         fd_userns = Filesystem::openFileAt(-1, path, O_RDONLY);
      }

      if (fd_userns < 0 && (flags & MOUNT_ATTR_IDMAP))
      {
         fd_userns = Filesystem::openFileAt(-1, "/proc/self/ns/user"_ctv, O_RDONLY);
      }

      int fd_tree = syscall(SYS_open_tree, -1, source.c_str(), OPEN_TREE_CLONE | AT_RECURSIVE);
      if (fd_tree < 0)
      {
         if (fd_userns > -1) close(fd_userns);
         return -1;
      }

      struct mount_attr attr;
      memset(&attr, 0, sizeof(attr));
      attr.attr_set = flags;

      if (fd_userns > -1) attr.userns_fd = fd_userns;

      int setattrResult = syscall(SYS_mount_setattr, fd_tree, "", AT_EMPTY_PATH | AT_RECURSIVE, &attr, sizeof(struct mount_attr));
      if (fd_userns > -1) close(fd_userns);

      if (setattrResult != 0)
      {
         close(fd_tree);
         return -1;
      }

      int moveResult = syscall(SYS_move_mount, fd_tree, "", -1, target.c_str(), MOVE_MOUNT_F_EMPTY_PATH);

      close(fd_tree);

      return moveResult;
   }

   // https://github.com/torvalds/linux/blob/master/Documentation/admin-guide/cgroup-v2.rst
   static int create_cgroupv2(const Container *container)
   {
      String path;
      path.assign("/sys/fs/cgroup/containers.slice/"_ctv);
      path.append(container->name);
      path.append(".slice"_ctv);

      int middirfd = Filesystem::createOpenDirectoryAt(-1, path);
      if (middirfd < 0)
      {
         int createErrno = errno;
         if (mkdir(path.c_str(), S_IRWXU) != 0 && errno != EEXIST)
         {
            basics_log("create_cgroupv2 mkdir fallback failed path=%s errno=%d(%s)\n", path.c_str(), errno, strerror(errno));
         }

         middirfd = open(path.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC);
         if (middirfd < 0)
         {
            basics_log("create_cgroupv2 failed to open %s createErrno=%d(%s) fallbackErrno=%d(%s)\n",
               path.c_str(), createErrno, strerror(createErrno), errno, strerror(errno));
            return -1;
         }
      }

      Filesystem::openWriteAtClose(middirfd, "cgroup.max.descendants"_ctv, "1"_ctv);
      Filesystem::openWriteAtClose(middirfd, "cgroup.max.depth"_ctv, "1"_ctv);

      if (applicationUsesSharedCPUs(container->plan.config))
      {
         uint16_t firstContainerCore = (nReservedCores < thisNeuron->lcoreCount) ? nReservedCores : (thisNeuron->lcoreCount - 1);
         path.snprintf<"{itoa}-{itoa}"_ctv>(firstContainerCore, uint16_t(thisNeuron->lcoreCount - 1));
      }
      else
      {
         path.snprintf<"{itoa}-{itoa}"_ctv>(container->lcores[0], container->lcores[container->plan.config.nLogicalCores - 1]);
      }
      Filesystem::openWriteAtClose(middirfd, "cpuset.cpus"_ctv, path);

      // it seems that CPU pinning is unnecessary when we isolate like this, because essentially processes will never be scrambled
      // we could pin, just to be sure, but that would force us to provide CPU core numbers into the main function of each application
      // and then change those pins when we need to defrag processes x cores.
      // 
      // but any application that creates threads, would create them all upfront, so we wouldn't even need to save the cores.. just create
      // and pin in main then forget the numbers... then if and when we get defraged our pins get changed invisibily underneath us by the OS
      // if every container thread was pinned one-to-one onto isolated cores, we
      // could consider exposing an isolated cpuset partition here.
      // {
      //    // When set to "isolated", the CPUs in that partition root will be in an isolated state without any load balancing from the scheduler. Tasks placed in such a partition with multiple CPUs should be carefully distributed and bound to each of the individual CPUs for optimal performance.
      //    Filesystem::openWriteAtClose(middirfd, "cpuset.cpus.partition"_ctv, "isolated"_ctv);
      // }
      // else
      // {
        
      // }
      
      Filesystem::openWriteAtClose(middirfd, "cpuset.cpus.partition"_ctv, "root"_ctv);

      String maxPids_string;
      maxPids_string.assignItoa(prodigyContainerRuntimeLimits.maxPids);
      Filesystem::openWriteAtClose(middirfd, "pids.max"_ctv, maxPids_string);

      path.snprintf<"{itoa}M"_ctv>(container->plan.config.memoryMB);
      Filesystem::openWriteAtClose(middirfd, "memory.low"_ctv, path);
      Filesystem::openWriteAtClose(middirfd, "memory.high"_ctv, path);

      // Hugepages disabled; no hugetlb configuration

      int leafdirfd = Filesystem::createOpenDirectoryAt(middirfd, "leaf"_ctv);
      if (leafdirfd < 0)
      {
         int createErrno = errno;
         if (mkdirat(middirfd, "leaf", S_IRWXU) != 0 && errno != EEXIST)
         {
            basics_log("create_cgroupv2 mkdir leaf fallback failed path=%s/leaf errno=%d(%s)\n", path.c_str(), errno, strerror(errno));
         }
         leafdirfd = Filesystem::openDirectoryAt(middirfd, "leaf"_ctv);
         if (leafdirfd < 0)
         {
            basics_log("create_cgroupv2 failed to open leaf for %s createErrno=%d(%s) fallbackErrno=%d(%s)\n",
               path.c_str(), createErrno, strerror(createErrno), errno, strerror(errno));
            Filesystem::close(middirfd);
            return -1;
         }
      }
     
      Filesystem::openWriteAtClose(leafdirfd, "cgroup.freeze"_ctv, "1"_ctv);

      // maybe the scheduler should read the cgroup's memory.stat to report on resource usage by containers.. instead of the applications doing it

      Filesystem::close(middirfd);

      return leafdirfd;
   }

   static void freezeRunningContainer(int fd)
   {
      Filesystem::openWriteAtClose(fd, "cgroup.freeze"_ctv, "1"_ctv);

      String workingString;
      workingString.reserve(1);
      workingString.resize(1);

      // wait for it to be frozen
      do
      {
         usleep(10); // wait 10 microseconds
         read(fd, workingString.data(), 1);
      } 
      while (workingString != "1"_ctv);
   }

   static void unfreezeRunningContainer(int fd)
   {
      Filesystem::openWriteAtClose(fd, "cgroup.freeze"_ctv, "0"_ctv);
   }

   // master scheduler garauntees this machine has enough cores
   static void allocateCores(Container *container)
   {
      uint16_t span;

      restart:

      span = 0;

      // pack them tightly oriented about lower core indexes
      for (uint16_t index = nReservedCores; index < thisNeuron->lcoreCount; index++)
      {
         if (thisNeuron->lcores[index] == 0) // available
         {
            container->lcores[span] = index;
            
            if (++span == container->plan.config.nLogicalCores) break;
         }
         else span = 0;
      }

      if (span != container->plan.config.nLogicalCores) // we need to defrag
      {
         uint16_t holeIndex = 0; // it's never 0 because the bottom logical core is always reserved for the operating system 

         // compact leftwise
         for (uint16_t index = nReservedCores; index < thisNeuron->lcoreCount;)
         {  
            if (thisNeuron->lcores[index] == 0) // hole
            {
               // we found our first hole, this is our starting point to compact into
               if (holeIndex == 0) holeIndex = index;

               index++;
            }
            else // has a process into it
            {
               // shift the process to the hole index, then reset the new hole index to the new process tail

               uint16_t nShift = index - holeIndex;

               for (auto& [uuid, container] : thisNeuron->containers)
               {
                  if (container->lcores[0] == index)
                  {
                     String workingString;

                  // update bookkeeping 
                     for (uint16_t subIndex = 0; subIndex < container->plan.config.nLogicalCores; subIndex++)
                     {
                        container->lcores[subIndex] = index + subIndex;
                        thisNeuron->lcores[index + subIndex] = container->plan.config.nLogicalCores;
                     }

                     String path;
                     path.assign("/sys/fs/cgroup/containers.slice/"_ctv);
                     path.append(container->name);
                     path.append(".slice"_ctv);

                     int slicefd = Filesystem::createOpenDirectoryAt(-1, path);

                  // change the cores the cgroup owns
                     workingString.snprintf<"{itoa}-{itoa}"_ctv>(container->lcores[0], container->lcores[container->plan.config.nLogicalCores - 1]);
                     Filesystem::openWriteAtClose(slicefd, "cpuset.cpus"_ctv, workingString);

                   // if any pinned threads, shift them by nShift
                     int leaffd = Filesystem::openDirectoryAt(slicefd, "leaf"_ctv);
                     Filesystem::openReadAtClose(leaffd, "cgroup.threads"_ctv, workingString);

                     uint64_t head = 0;
                     uint16_t threadIndex = 0;

                     // read over by linebreaks, then translate into pid_t numbers
                     for (uint64_t charIndex = 0; charIndex < workingString.size(); charIndex++)
                     {
                        if (workingString[charIndex] == '\n')
                        {
                           pid_t tid = workingString.toNumber<uint32_t>(head, charIndex - head);

                           cpu_set_t currentSet;
                           CPU_ZERO(&currentSet);
                           sched_getaffinity(tid, sizeof(currentSet), &currentSet);

                           if (bool isPinned = (CPU_COUNT(&currentSet) == 1); isPinned)
                           {
                              int currentCore = __builtin_ffsl(*(unsigned long *)(&currentSet)) - 1; // Find first set bit (the pinned core)
                              int newCore = currentCore - nShift;

                              cpu_set_t set;
                              CPU_ZERO(&set);
                              CPU_SET(newCore, &set);
                              sched_setaffinity(tid, sizeof(set), &set);
                           }                 
                        }
                     }

                     holeIndex += container->plan.config.nLogicalCores;
                     index = holeIndex;

                     break;
                  }
               }
            }
         }

         goto restart;
      }
      else
      {
         for (uint16_t index = 0; index < container->plan.config.nLogicalCores; index++)
         {
            thisNeuron->lcores[container->lcores[index]] = container->plan.config.nLogicalCores;
         }
      }
   }

   static bool openContainerSliceFD(const Container *container, int& sliceFD, String *pathOut = nullptr)
   {
      String path;
      path.assign("/sys/fs/cgroup/containers.slice/"_ctv);
      path.append(container->name);
      path.append(".slice"_ctv);

      sliceFD = Filesystem::openDirectoryAt(-1, path);
      if (sliceFD < 0)
      {
         return false;
      }

      if (pathOut)
      {
         pathOut->assign(path);
      }

      return true;
   }

   static bool applyContainerCPUCoreTarget(Container *container, uint16_t targetCores, String *failureReport = nullptr)
   {
      if (targetCores == 0 || targetCores > 256)
      {
         if (failureReport) failureReport->snprintf<"invalid target core count {itoa}"_ctv>(targetCores);
         return false;
      }

      uint16_t currentCores = uint16_t(container->plan.config.nLogicalCores);
      if (currentCores == targetCores)
      {
         return true;
      }

      if (currentCores == 0 || currentCores > 256)
      {
         if (failureReport) failureReport->snprintf<"invalid current core count {itoa}"_ctv>(currentCores);
         return false;
      }

      if (applicationUsesSharedCPUs(container->plan.config))
      {
         int sliceFD = -1;
         if (openContainerSliceFD(container, sliceFD) == false)
         {
            if (failureReport) failureReport->assign("failed to open container cgroup slice"_ctv);
            return false;
         }

         String cpuset;
         uint16_t firstContainerCore = (nReservedCores < thisNeuron->lcoreCount) ? nReservedCores : (thisNeuron->lcoreCount - 1);
         cpuset.snprintf<"{itoa}-{itoa}"_ctv>(firstContainerCore, uint16_t(thisNeuron->lcoreCount - 1));
         Filesystem::openWriteAtClose(sliceFD, "cpuset.cpus"_ctv, cpuset);
         close(sliceFD);
         return true;
      }

      uint16_t lowCore = container->lcores[0];

      if (targetCores > currentCores)
      {
         for (uint16_t index = currentCores; index < targetCores; index++)
         {
            uint16_t core = uint16_t(lowCore + index);
            if (core >= thisNeuron->lcoreCount)
            {
               if (failureReport) failureReport->snprintf<"target core {itoa} exceeds machine core range"_ctv>(core);
               return false;
            }

            if (thisNeuron->lcores[core] != 0)
            {
               if (failureReport) failureReport->snprintf<"target core {itoa} unavailable"_ctv>(core);
               return false;
            }
         }
      }

      int sliceFD = -1;
      if (openContainerSliceFD(container, sliceFD) == false)
      {
         if (failureReport) failureReport->assign("failed to open container cgroup slice"_ctv);
         return false;
      }

      String cpuset;
      cpuset.snprintf<"{itoa}-{itoa}"_ctv>(lowCore, uint16_t(lowCore + targetCores - 1));
      Filesystem::openWriteAtClose(sliceFD, "cpuset.cpus"_ctv, cpuset);
      close(sliceFD);

      if (targetCores > currentCores)
      {
         for (uint16_t index = currentCores; index < targetCores; index++)
         {
            container->lcores[index] = uint16_t(lowCore + index);
         }
      }

      for (uint16_t index = 0; index < targetCores; index++)
      {
         thisNeuron->lcores[container->lcores[index]] = targetCores;
      }

      for (uint16_t index = targetCores; index < currentCores; index++)
      {
         thisNeuron->lcores[container->lcores[index]] = 0;
      }

      return true;
   }

   static bool applyContainerMemoryTarget(Container *container, uint32_t targetMemoryMB, String *failureReport = nullptr)
   {
      if (targetMemoryMB == 0)
      {
         if (failureReport) failureReport->assign("target memory must be positive"_ctv);
         return false;
      }

      int sliceFD = -1;
      if (openContainerSliceFD(container, sliceFD) == false)
      {
         if (failureReport) failureReport->assign("failed to open container cgroup slice"_ctv);
         return false;
      }

      String memoryLimit;
      memoryLimit.snprintf<"{itoa}M"_ctv>(targetMemoryMB);
      Filesystem::openWriteAtClose(sliceFD, "memory.low"_ctv, memoryLimit);
      Filesystem::openWriteAtClose(sliceFD, "memory.high"_ctv, memoryLimit);
      close(sliceFD);

      return true;
   }

   static bool applyContainerResourceTargets(Container *container, uint16_t targetCores, uint32_t targetMemoryMB, uint32_t targetStorageMB, String *failureReport = nullptr)
   {
      if (targetStorageMB == 0)
      {
         if (failureReport) failureReport->assign("target storage must be positive"_ctv);
         return false;
      }

      uint16_t oldCores = uint16_t(container->plan.config.nLogicalCores);
      if (applyContainerCPUCoreTarget(container, targetCores, failureReport) == false)
      {
         return false;
      }

      if (applyContainerMemoryTarget(container, targetMemoryMB, failureReport) == false)
      {
         String rollbackFailure;
         (void)applyContainerCPUCoreTarget(container, oldCores, &rollbackFailure);
         return false;
      }

      if (resizeContainerStorage(container, targetStorageMB, failureReport) == false)
      {
         String rollbackFailure;
         (void)applyContainerMemoryTarget(container, container->plan.config.memoryMB, &rollbackFailure);
         (void)applyContainerCPUCoreTarget(container, oldCores, &rollbackFailure);
         return false;
      }

      container->plan.config.nLogicalCores = targetCores;
      container->plan.config.memoryMB = targetMemoryMB;
      container->plan.config.storageMB = targetStorageMB;
      return true;
   }

   static bool cleanupFailedCreateArtifactRoot(Container *container, String *failureReport = nullptr)
   {
      if (container == nullptr || container->artifactRootPath.size() == 0)
      {
         return true;
      }

      String artifactRootPath = {};
      artifactRootPath.assign(container->artifactRootPath);
      container->artifactRootPath.clear();
      container->rootfsPath.clear();
      return deleteContainerArtifactTree(artifactRootPath, failureReport);
   }

   static void cleanupContainerAfterFailedCreate(Container *container)
   {
      if (container == nullptr)
      {
         return;
      }

      if (container->resourceDeltaTimer)
      {
         Ring::queueCancelTimeout(container->resourceDeltaTimer);
         container->resourceDeltaTimer = nullptr;
      }
      container->resourceDeltaMode = Container::ResourceDeltaMode::none;

      if (applicationUsesIsolatedCPUs(container->plan.config))
      {
         for (uint16_t index = 0; index < container->plan.config.nLogicalCores; index++)
         {
            uint16_t lcore = container->lcores[index];
            if (lcore < thisNeuron->lcoreCount && lcore < 256)
            {
               thisNeuron->lcores[lcore] = 0;
            }
         }
      }

      if (thisNeuron != nullptr)
      {
         auto it = thisNeuron->containers.find(container->plan.uuid);
         if (it != thisNeuron->containers.end() && it->second == container)
         {
            container->cleanupNetwork();
            thisNeuron->popContainer(container);
         }
      }

      if (container->pidfd > 0) close(container->pidfd);
      if (container->cgroup > 0) close(container->cgroup);

      // Best-effort external teardown (btrfs/cgroup shell calls) used to be skipped here.
      // Loop-backed storage leaves mounted filesystems and loop devices behind if we do nothing,
      // so this path now tears down only the explicit storage backend state we created.
      teardownContainerStorage(container);

      String failedArtifactRootPath = {};
      failedArtifactRootPath.assign(container->artifactRootPath);
      String artifactCleanupFailure = {};
      if (cleanupFailedCreateArtifactRoot(container, &artifactCleanupFailure) == false)
      {
         basics_log("cleanupContainerAfterFailedCreate artifact cleanup failed uuid=%llu artifactRoot=%s reason=%s\n",
            (unsigned long long)container->plan.uuid,
            failedArtifactRootPath.c_str(),
            artifactCleanupFailure.c_str());
      }

      ContainerRegistry::pop(container);
      delete container;
   }

   static void createContainer(ContainerPlan& plan, const String& compressedContainerPath, Container*& container)
   {
	      container = new Container();
	      container->plan = plan;
	      container->name.assignItoa(plan.uuid);
         container->userID = 65535 * uint32_t(container->plan.fragment);
	      container->rBuffer.reserve(8_KB);
	      container->wBuffer.reserve(16_KB);
      if (applicationUsesIsolatedCPUs(container->plan.config))
      {
	      allocateCores(container);
      }

      if (container->plan.addresses.size() > 0)
      {
         char private6Text[INET6_ADDRSTRLEN] = {0};
         if (inet_ntop(AF_INET6, container->plan.addresses[0].network.v6, private6Text, sizeof(private6Text)) == nullptr)
         {
            strcpy(private6Text, "<invalid>");
         }

         basics_log(
            "createContainer plan deploymentID=%llu appID=%u addresses=%u private6=%s/%u\n",
            (unsigned long long)plan.config.deploymentID(),
            unsigned(plan.config.applicationID),
            unsigned(container->plan.addresses.size()),
            private6Text,
            unsigned(container->plan.addresses[0].cidr));
      }
      else
      {
         basics_log(
            "createContainer plan deploymentID=%llu appID=%u addresses=0\n",
            (unsigned long long)plan.config.deploymentID(),
            unsigned(plan.config.applicationID));
      }

      IPPrefix containerNetwork6 = thisNeuron->generateAddress(container_network_subnet6, plan.fragment, 128);
      addAddressIfMissing(container->plan.addresses, containerNetwork6);
      basics_log(
         "createContainer networking needsExternal4=%d needsExternal6=%d directAddresses=%u\n",
         int(needsAnyExternalAddressFamily(plan, ExternalAddressFamily::ipv4)),
         int(needsAnyExternalAddressFamily(plan, ExternalAddressFamily::ipv6)),
         unsigned(container->plan.addresses.size()));

      String rejectedArtifactJanitorFailure = {};
      if (cleanupRejectedOrphanedContainerArtifactsAtPath("/containers"_ctv, &rejectedArtifactJanitorFailure) == false
         && rejectedArtifactJanitorFailure.size() > 0)
      {
         basics_log("createContainer rejected/orphaned artifact janitor encountered errors reason=%s\n",
            rejectedArtifactJanitorFailure.c_str());
      }

      // this must come after the name and cores assignments
      container->cgroup = create_cgroupv2(container);
      if (container->cgroup < 0)
      {
         basics_log("createContainer proceeding without cgroup uuid=%llu\n", (unsigned long long)container->plan.uuid);
      }

      struct DeploymentExtractionLock {
         int fd = -1;

         ~DeploymentExtractionLock()
         {
            if (fd >= 0)
            {
               (void)flock(fd, LOCK_UN);
               (void)close(fd);
            }
         }
      } extractionLock;

      String extractionLockPath;
      extractionLockPath.snprintf<"/containers/store/.extract.{itoa}.lock"_ctv>(plan.config.deploymentID());
      extractionLock.fd = open(extractionLockPath.c_str(), O_CREAT | O_RDWR | O_CLOEXEC, 0644);
      if (extractionLock.fd < 0)
      {
         basics_log("createContainer failed to open extraction lock path=%s errno=%d(%s)\n",
            extractionLockPath.c_str(),
            errno,
            strerror(errno));
         cleanupContainerAfterFailedCreate(container);
         container = nullptr;
         return;
      }

      if (flock(extractionLock.fd, LOCK_EX) != 0)
      {
         basics_log("createContainer failed to lock extraction path=%s errno=%d(%s)\n",
            extractionLockPath.c_str(),
            errno,
            strerror(errno));
         cleanupContainerAfterFailedCreate(container);
         container = nullptr;
         return;
      }

      String receiveScratchPath = {};
      receiveScratchPath.assign("/containers/store/.receive."_ctv);
      String deploymentIDText = {};
      deploymentIDText.assignItoa(plan.config.deploymentID());
      receiveScratchPath.append(deploymentIDText);
      receiveScratchPath.append("."_ctv);
      receiveScratchPath.append(container->name);
      if (createDirectoryTree(receiveScratchPath) == false)
      {
         basics_log("createContainer failed to create receive scratch path=%s errno=%d(%s)\n",
            receiveScratchPath.c_str(),
            errno,
            strerror(errno));
         cleanupContainerAfterFailedCreate(container);
         container = nullptr;
         return;
      }

      struct ReceiveScratchCleanup {
         String scratchPath = {};
         bool released = false;

         ~ReceiveScratchCleanup()
         {
            if (released == false)
            {
               ContainerManager::cleanupContainerReceiveScratch(scratchPath);
            }
         }
      } receiveScratchCleanup;
      receiveScratchCleanup.scratchPath = receiveScratchPath;

      // Replace shell pipeline with explicit posix_spawn commands:
      // 1) zstd -d -c <compressed> | 2) btrfs receive <scratch>
      {
         // Guardian sets SIGCHLD to SIG_IGN globally; restore default disposition for
         // explicit child supervision in this extraction pipeline.
         struct sigaction oldSigChld {};
         struct sigaction defaultSigChld {};
         sigemptyset(&defaultSigChld.sa_mask);
         defaultSigChld.sa_handler = SIG_DFL;
         defaultSigChld.sa_flags = 0;
         sigaction(SIGCHLD, &defaultSigChld, &oldSigChld);

         int pipefd[2];
         if (pipe(pipefd) != 0)
         {
            basics_log("createContainer pipe failed errno=%d(%s)\n", errno, strerror(errno));
            sigaction(SIGCHLD, &oldSigChld, nullptr);
            cleanupContainerAfterFailedCreate(container);
            container = nullptr;
            return;
         }

         // Spawn btrfs receive, stdin = pipe read, target = unique scratch parent
         pid_t recv_pid = -1; pid_t zstd_pid = -1;
         {
            posix_spawn_file_actions_t fa; posix_spawn_file_actions_init(&fa);
            posix_spawn_file_actions_adddup2(&fa, pipefd[0], STDIN_FILENO);
            posix_spawn_file_actions_addclose(&fa, pipefd[1]);
            String receiveScratchPathText = {};
            receiveScratchPathText.assign(receiveScratchPath);
            char *const argv[] = { (char*)"btrfs", (char*)"receive", (char*)receiveScratchPathText.c_str(), nullptr };
            int rc = posix_spawnp(&recv_pid, "btrfs", &fa, nullptr, argv, environ);
            posix_spawn_file_actions_destroy(&fa);
            if (rc != 0)
            {
               basics_log("createContainer spawn btrfs receive failed: %s\n", strerror(rc));
            }
         }

         // Spawn zstd -d -c <compressed>, stdout = pipe write
         {
            posix_spawn_file_actions_t fa; posix_spawn_file_actions_init(&fa);
            posix_spawn_file_actions_adddup2(&fa, pipefd[1], STDOUT_FILENO);
            posix_spawn_file_actions_addclose(&fa, pipefd[0]);
            String input = compressedContainerPath; // path to compressed image
            char *const argv[] = { (char*)"zstd", (char*)"-d", (char*)"-c", (char*)input.c_str(), nullptr };
            int rc = posix_spawnp(&zstd_pid, "zstd", &fa, nullptr, argv, environ);
            posix_spawn_file_actions_destroy(&fa);
            if (rc != 0)
            {
               basics_log("createContainer spawn zstd failed: %s\n", strerror(rc));
            }
         }

         // Close both pipe ends in parent
         close(pipefd[0]);
         close(pipefd[1]);

         // Wait for children
         int zstd_status = 0;
         int recv_status = 0;

         auto waitForSpawned = [&] (pid_t pid, int& status, const char *label) -> bool {
            if (pid <= 0) return false;

            while (true)
            {
               pid_t waited = waitpid(pid, &status, 0);
               if (waited == pid) break;

               if (waited < 0 && errno == EINTR)
               {
                  continue;
               }

               basics_log("createContainer waitpid failed for %s pid=%d errno=%d(%s)\n",
                  label,
                  int(pid),
                  errno,
                  strerror(errno));
               return false;
            }

            if (WIFEXITED(status))
            {
               int code = WEXITSTATUS(status);
               if (code == 0) return true;

               basics_log("createContainer %s exited nonzero code=%d\n", label, code);
               return false;
            }

            if (WIFSIGNALED(status))
            {
               basics_log("createContainer %s terminated by signal=%d\n", label, WTERMSIG(status));
               return false;
            }

            basics_log("createContainer %s ended with unknown wait status=0x%x\n", label, unsigned(status));
            return false;
         };

         bool zstd_ok = waitForSpawned(zstd_pid, zstd_status, "zstd");
         bool recv_ok = waitForSpawned(recv_pid, recv_status, "btrfs_receive");

         sigaction(SIGCHLD, &oldSigChld, nullptr);

         if (zstd_ok == false || recv_ok == false)
         {
            basics_log("createContainer image extraction failed zstd_ok=%d recv_ok=%d\n", int(zstd_ok), int(recv_ok));
            cleanupContainerAfterFailedCreate(container);
            container = nullptr;
            return;
         }
      }

      String receivedSubvolumeName = {};
      String receivedSubvolumePath = {};
      String receiveScratchSelectionFailure = {};
      if (selectReceivedContainerArtifactFromScratch(
            receiveScratchPath,
            receivedSubvolumeName,
            receivedSubvolumePath,
            &receiveScratchSelectionFailure) == false)
      {
         basics_log("createContainer receive scratch selection failed deploymentID=%llu scratch=%s reason=%s\n",
            (unsigned long long)plan.config.deploymentID(),
            receiveScratchPath.c_str(),
            receiveScratchSelectionFailure.c_str());
         cleanupContainerAfterFailedCreate(container);
         container = nullptr;
         return;
      }

      String artifactShapeFailure = {};
      if (validateContainerArtifactShape(receivedSubvolumePath, &artifactShapeFailure) == false)
      {
         basics_log("createContainer artifact shape validation failed deploymentID=%llu artifactRoot=%s reason=%s\n",
            (unsigned long long)plan.config.deploymentID(),
            receivedSubvolumePath.c_str(),
            artifactShapeFailure.c_str());
         cleanupContainerAfterFailedCreate(container);
         container = nullptr;
         return;
      }

      String artifactLimitFailure = {};
      if (validateContainerArtifactResourceLimits(
            receivedSubvolumePath,
            storageBytesForMB(plan.config.filesystemMB),
            maxContainerArtifactEntries,
            maxContainerArtifactRegularFileBytes,
            &artifactLimitFailure) == false)
      {
         basics_log("createContainer artifact resource limits failed deploymentID=%llu artifactRoot=%s reason=%s\n",
            (unsigned long long)plan.config.deploymentID(),
            receivedSubvolumePath.c_str(),
            artifactLimitFailure.c_str());
         cleanupContainerAfterFailedCreate(container);
         container = nullptr;
         return;
      }

      String artifactWritableFailure = {};
      if (setContainerArtifactSubvolumeWritable(receivedSubvolumePath, &artifactWritableFailure) == false)
      {
         basics_log("createContainer failed to make received artifact writable deploymentID=%llu artifactRoot=%s reason=%s\n",
            (unsigned long long)plan.config.deploymentID(),
            receivedSubvolumePath.c_str(),
            artifactWritableFailure.c_str());
         cleanupContainerAfterFailedCreate(container);
         container = nullptr;
         return;
      }

      String pendingMarkerFailure = {};
      if (writeContainerCreatePendingMarker(receivedSubvolumePath, getpid(), &pendingMarkerFailure) == false)
      {
         basics_log("createContainer failed to create pending-create marker deploymentID=%llu artifactRoot=%s reason=%s\n",
            (unsigned long long)plan.config.deploymentID(),
            receivedSubvolumePath.c_str(),
            pendingMarkerFailure.c_str());
         cleanupContainerAfterFailedCreate(container);
         container = nullptr;
         return;
      }

      container->artifactRootPath.assign(receivedSubvolumePath);
      container->rootfsPath.assign(receivedSubvolumePath);
      container->rootfsPath.append("/rootfs"_ctv);

      String launchMetadataFailure = {};
      if (loadContainerLaunchMetadata(container, &launchMetadataFailure) == false)
      {
         basics_log("createContainer launch metadata load failed uuid=%llu artifactRoot=%s reason=%s\n",
            (unsigned long long)container->plan.uuid,
            container->artifactRootPath.c_str(),
            launchMetadataFailure.c_str());
         cleanupContainerAfterFailedCreate(container);
         container = nullptr;
         return;
      }

      int rootfd = -1;
      String rootfsFailure = {};
      if (openVerifiedContainerRootfs(container, rootfd, &rootfsFailure) == false)
      {
         basics_log("createContainer rootfs missing uuid=%llu rootfs=%s errno=%d(%s)\n",
            (unsigned long long)container->plan.uuid,
            container->rootfsPath.c_str(),
            errno,
            strerror(errno));
         if (rootfsFailure.size() > 0)
         {
            basics_log("createContainer rootfs validation failure uuid=%llu reason=%s\n",
               (unsigned long long)container->plan.uuid,
               rootfsFailure.c_str());
         }
         cleanupContainerAfterFailedCreate(container);
         container = nullptr;
         return;
      }

      if (assignContainerRootfsOwnership(rootfd, uid_t(container->userID), gid_t(container->userID), &rootfsFailure) == false)
      {
         basics_log("createContainer rootfs chown failed uuid=%llu path=%s userID=%u reason=%s\n",
            (unsigned long long)container->plan.uuid,
            container->rootfsPath.c_str(),
            unsigned(container->userID),
            rootfsFailure.c_str());
         cleanupContainerAfterFailedCreate(container);
         container = nullptr;
         close(rootfd);
         return;
      }

      if (validateContainerLaunchTargetsInRootfs(container, rootfd, &rootfsFailure) == false)
      {
         basics_log("createContainer launch target validation failed uuid=%llu artifactRoot=%s reason=%s\n",
            (unsigned long long)container->plan.uuid,
            receivedSubvolumePath.c_str(),
            rootfsFailure.c_str());
         cleanupContainerAfterFailedCreate(container);
         container = nullptr;
         close(rootfd);
         return;
      }

      if (prepareContainerRootFSMountTargets(container, rootfd, &rootfsFailure) == false)
      {
         basics_log("createContainer mount target preparation failed uuid=%llu artifactRoot=%s reason=%s\n",
            (unsigned long long)container->plan.uuid,
            receivedSubvolumePath.c_str(),
            rootfsFailure.c_str());
         cleanupContainerAfterFailedCreate(container);
         container = nullptr;
         close(rootfd);
         return;
      }

      close(rootfd);

      if (plan.config.storageMB > 0)
      {
         String storageFailure;
         if (prepareContainerStorage(container, &storageFailure) == false)
         {
            basics_log("createContainer storage prepare failed uuid=%llu reason=%s\n",
               (unsigned long long)container->plan.uuid,
               (storageFailure.size() ? storageFailure.c_str() : "unknown"));
            cleanupContainerAfterFailedCreate(container);
            container = nullptr;
            return;
         }
      }

      String finalArtifactRootPath = {};
      finalArtifactRootPath.assign("/containers/"_ctv);
      finalArtifactRootPath.append(container->name);
      bool artifactMoveUsedSnapshotFallback = false;
      String artifactMoveFailure = {};
      if (moveContainerArtifactSubvolumeIntoPlace(
            receivedSubvolumePath,
            finalArtifactRootPath,
            artifactMoveUsedSnapshotFallback,
            &artifactMoveFailure) == false)
      {
         basics_log("createContainer subvolume move failed from %s to %s reason=%s\n",
            receivedSubvolumePath.c_str(),
            finalArtifactRootPath.c_str(),
            artifactMoveFailure.c_str());
         cleanupContainerAfterFailedCreate(container);
         container = nullptr;
         return;
      }

      if (artifactMoveUsedSnapshotFallback)
      {
         basics_log("createContainer subvolume move used snapshot fallback from %s to %s\n",
            receivedSubvolumePath.c_str(),
            finalArtifactRootPath.c_str());
      }

      receiveScratchCleanup.released = true;
      (void)eraseDirectoryTree(receiveScratchPath);

      container->artifactRootPath.assign(finalArtifactRootPath);
      container->rootfsPath.assign(finalArtifactRootPath);
      container->rootfsPath.append("/rootfs"_ctv);

      {
         String containerRootPath;
         containerRootPath.assign(container->rootfsPath);

         struct stat rootStat {};
         int rootStatResult = stat(containerRootPath.c_str(), &rootStat);
         int rootStatErrno = errno;

         basics_log("createContainer finalized uuid=%llu deploymentID=%llu artifactRoot=%s rootfs=%s stat=%d errno=%d(%s) receivedScratchArtifact=%s\n",
            (unsigned long long)container->plan.uuid,
            (unsigned long long)plan.config.deploymentID(),
            container->artifactRootPath.c_str(),
            containerRootPath.c_str(),
            rootStatResult,
            rootStatErrno,
            strerror(rootStatErrno),
            receivedSubvolumePath.c_str());
      }

      return;
   }

   static void seedDynamicData(Container *container)
   {
      // seed dynamic data to neuron socket
      // otherwise we need to write 2 pathways in every application to handle dynamic data through main() and neuron socket. this makes more sense

      uint32_t advertisementPairingCount = 0;
      uint32_t subscriptionPairingCount = 0;

      for (const auto& [secret, pairings] : container->plan.advertisementPairings)
      {
         for (const AdvertisementPairing& pairing : pairings)
         {
            advertisementPairingCount += 1;
            String payload;
            uint16_t applicationID = uint16_t(pairing.service >> 48);
            if (ProdigyWire::serializeAdvertisementPairingPayload(
               payload,
               pairing.secret,
               pairing.address,
               pairing.service,
               applicationID,
               true))
            {
               ProdigyWire::constructPackedFrame(container->wBuffer, ContainerTopic::advertisementPairing, payload);
            }
         }
      }

      for (const auto& [secret, pairings] : container->plan.subscriptionPairings)
      {
         for (const SubscriptionPairing& pairing : pairings)
         {
            subscriptionPairingCount += 1;
            // Service encoding carries application prefix in upper 16 bits.
            uint16_t applicationID = uint16_t(pairing.service >> 48);
            String payload;
            if (ProdigyWire::serializeSubscriptionPairingPayload(
               payload,
               pairing.secret,
               pairing.address,
               pairing.service,
               pairing.port,
               applicationID,
               true))
            {
               ProdigyWire::constructPackedFrame(container->wBuffer, ContainerTopic::subscriptionPairing, payload);
            }
         }
      }

      Message::appendEcho(container->wBuffer, ContainerTopic::none); // so they can know they've received the last of the initial inputs
      appendContainerTrace(container,
         "seedDynamicData adv=%u sub=%u queuedBytes=%u pendingSend=%d pendingRecv=%d isFixed=%d fslot=%d registeredFD=%d\n",
         unsigned(advertisementPairingCount),
         unsigned(subscriptionPairingCount),
         unsigned(container->wBuffer.size()),
         int(container->pendingSend),
         int(container->pendingRecv),
         int(container->isFixedFile),
         container->fslot,
         (container->isFixedFile && container->fslot >= 0 ? Ring::getFDFromFixedFileSlot(container->fslot) : container->fd));
      basics_log(
         "seedDynamicData uuid=%llu deploymentID=%llu appID=%u advertises=%u advPairings=%u subPairings=%u queuedBytes=%u\n",
         (unsigned long long)container->plan.uuid,
         (unsigned long long)container->plan.config.deploymentID(),
         unsigned(container->plan.config.applicationID),
         unsigned(container->plan.advertisements.size()),
         unsigned(advertisementPairingCount),
         unsigned(subscriptionPairingCount),
         unsigned(container->wBuffer.size()));
      Ring::queueSend(container);
      appendContainerTrace(container,
         "seedDynamicData queued-send pendingSend=%d pendingSendBytes=%u outstanding=%llu isFixed=%d fslot=%d registeredFD=%d\n",
         int(container->pendingSend),
         unsigned(container->pendingSendBytes),
         (unsigned long long)container->queuedSendOutstandingBytes(),
         int(container->isFixedFile),
         container->fslot,
         (container->isFixedFile && container->fslot >= 0 ? Ring::getFDFromFixedFileSlot(container->fslot) : container->fd));
   }

   static bool mapIDs(Container *container, String *failureReport = nullptr)
   {
      String path;
      String idWrite;
      // posix says the minimum number of userids should be 65535
      idWrite.snprintf<"0 {itoa} 65535\n"_ctv>(container->userID);

      String pid_string;
      pid_string.assignItoa(container->pid);

      auto writeMapping = [&] (const char *mappingName, String& mappingPath, StringType auto&& payload) -> bool
      {
         String mappingNameText = {};
         if (mappingName != nullptr)
         {
            mappingNameText.assign(mappingName);
         }

         int written = Filesystem::openWriteAtClose(-1, mappingPath, payload);
         if (written == int(payload.size()))
         {
            return true;
         }

         int mappingErrno = errno;
         basics_log("mapIDs failed uuid=%llu pid=%d userID=%u mapping=%s path=%s written=%d expected=%zu errno=%d(%s)\n",
            (unsigned long long)container->plan.uuid,
            int(container->pid),
            unsigned(container->userID),
            mappingName,
            mappingPath.c_str(),
            written,
            size_t(payload.size()),
            mappingErrno,
            strerror(mappingErrno));

         if (failureReport)
         {
            failureReport->snprintf<"mapIDs failed for container {itoa} mapping={} errno={}"_ctv>(
               container->plan.uuid,
               mappingNameText,
               String(strerror(mappingErrno)));
         }

         return false;
      };

      path.snprintf<"/proc/{}/uid_map"_ctv>(pid_string);
      if (writeMapping("uid_map", path, idWrite) == false)
      {
         return false;
      }

      path.snprintf<"/proc/{}/setgroups"_ctv>(pid_string);
      if (writeMapping("setgroups", path, "deny"_ctv) == false)
      {
         return false;
      }

      path.snprintf<"/proc/{}/gid_map"_ctv>(pid_string);
      if (writeMapping("gid_map", path, idWrite) == false)
      {
         return false;
      }

      return true;
   }

   static bool mountRootFSInCurrentNamespace(Container *container, bool isRestart, int idMapPID)
   {
      (void)isRestart;
      String path;
      String path2;
      String containerRoot;
      bool useIDMapMounts = (idMapPID > 0);
      containerRoot.assign(container->rootfsPath);

      int containersAccess = access("/containers", F_OK);
      int containersAccessErrno = errno;

      String rootfsFailure = {};
      int rootfd = -1;
      if (openVerifiedContainerRootfs(container, rootfd, &rootfsFailure) == false)
      {
         int openErrno = errno;
         basics_log("mountRootFS failed to open container root uuid=%llu path=%s containersAccess=%d(%d) openErrno=%d(%s)\n",
            (unsigned long long)container->plan.uuid,
            containerRoot.c_str(),
            containersAccess,
            containersAccessErrno,
            openErrno,
            strerror(openErrno));
         if (rootfsFailure.size() > 0)
         {
            basics_log("mountRootFS secure rootfs validation failed uuid=%llu reason=%s\n",
               (unsigned long long)container->plan.uuid,
               rootfsFailure.c_str());
         }
         return false;
      }

      int oldrootFD = -1;
      if (openContainerDirectoryTreeAt(rootfd, "oldroot"_ctv, true, S_IRWXU, oldrootFD) == false)
      {
         basics_log("mountRootFS failed to create oldroot uuid=%llu path=%s errno=%d(%s)\n",
            (unsigned long long)container->plan.uuid,
            containerRoot.c_str(),
            errno,
            strerror(errno));
         close(rootfd);
         return false;
      }
      close(oldrootFD);

      // this mount has to be first otherwise the others screw up the id mapping
      path.assign(containerRoot);
      if (mount2(path, path, MOUNT_ATTR_IDMAP | MOUNT_ATTR_NOSUID, idMapPID) != 0)
      {
         int idmapErrno = errno;
         if (idmapErrno == EPERM || idmapErrno == EOPNOTSUPP || idmapErrno == EINVAL)
         {
            if (mount2(path, path, MOUNT_ATTR_NOSUID) != 0)
            {
               basics_log("mountRootFS idmap fallback mount failed uuid=%llu path=%s idmapErrno=%d(%s) fallbackErrno=%d(%s)\n",
                  (unsigned long long)container->plan.uuid,
                  path.c_str(),
                  idmapErrno,
                  strerror(idmapErrno),
                  errno,
                  strerror(errno));
               close(rootfd);
               return false;
            }

            useIDMapMounts = false;
         }
         else
         {
            basics_log("mountRootFS idmap mount failed uuid=%llu path=%s errno=%d(%s)\n",
               (unsigned long long)container->plan.uuid,
               path.c_str(),
               idmapErrno,
               strerror(idmapErrno));
            close(rootfd);
            return false;
         }
      }

      close(rootfd);
      rootfd = -1;

      String postMountRootfsFailure = {};
      if (openVerifiedContainerRootfs(container, rootfd, &postMountRootfsFailure) == false)
      {
         basics_log("mountRootFS failed to reopen container root uuid=%llu path=%s errno=%d(%s) reason=%s\n",
            (unsigned long long)container->plan.uuid,
            containerRoot.c_str(),
            errno,
            strerror(errno),
            postMountRootfsFailure.c_str());
         return false;
      }

      String launchTargetFailure = {};
      if (validateContainerLaunchTargetsInRootfs(container, rootfd, &launchTargetFailure) == false)
      {
         basics_log("mountRootFS launch target validation failed uuid=%llu root=%s reason=%s\n",
            (unsigned long long)container->plan.uuid,
            containerRoot.c_str(),
            launchTargetFailure.size() > 0 ? launchTargetFailure.c_str() : "unknown");
         close(rootfd);
         return false;
      }

      close(rootfd);

      String deviceMountFailure = {};
      if (bindMountHostDeviceIntoRootFS("/dev/null"_ctv, containerRoot, &deviceMountFailure) == false
         || bindMountHostDeviceIntoRootFS("/dev/zero"_ctv, containerRoot, &deviceMountFailure) == false
         || bindMountHostDeviceIntoRootFS("/dev/random"_ctv, containerRoot, &deviceMountFailure) == false
         || bindMountHostDeviceIntoRootFS("/dev/urandom"_ctv, containerRoot, &deviceMountFailure) == false)
      {
         basics_log("mountRootFS host device mount failed uuid=%llu root=%s reason=%s\n",
            (unsigned long long)container->plan.uuid,
            containerRoot.c_str(),
            deviceMountFailure.c_str());
         return false;
      }

      if (container->plan.config.storageMB > 0)
      {
         if (container->storagePayloadPath.size() > 0)
         {
            path.assign(container->storagePayloadPath);
         }
         else
         {
            path.assign("/containers/storage/"_ctv);
            path.append(container->name);
         }
         path2.assign(containerRoot);
         path2.append("/storage"_ctv);
         int storageMountResult = 0;
         int storageMountErrno = 0;

         auto bindMountStorageFallback = [&] () -> bool
         {
            if (mount(path.c_str(), path2.c_str(), NULL, MS_BIND | MS_REC, NULL) != 0)
            {
               return false;
            }

            if (mount(NULL, path2.c_str(), NULL, MS_BIND | MS_REMOUNT | MS_NOSUID, NULL) != 0)
            {
               return false;
            }

            return true;
         };

         if (useIDMapMounts)
         {
            storageMountResult = mount2(path, path2, MOUNT_ATTR_IDMAP | MOUNT_ATTR_NOSUID, idMapPID);
         }
         else
         {
            storageMountResult = mount2(path, path2, MOUNT_ATTR_NOSUID);
            storageMountErrno = errno;
            if (storageMountResult != 0 && (storageMountErrno == EPERM || storageMountErrno == EOPNOTSUPP || storageMountErrno == EINVAL))
            {
               if (bindMountStorageFallback())
               {
                  storageMountResult = 0;
               }
            }
         }

         if (storageMountResult != 0)
         {
            basics_log("mountRootFS storage mount failed uuid=%llu source=%s target=%s idmap=%d errno=%d(%s); using container-local /storage fallback\n",
               (unsigned long long)container->plan.uuid,
               path.c_str(),
               path2.c_str(),
               int(useIDMapMounts),
               errno,
               strerror(errno));
         }
      }

      // Only host DNS configuration is projected into the container rootfs.
      // Trust stores and other host service state must come from the artifact itself.
      path.assign(containerRoot);
      path.append("/etc/resolv.conf"_ctv);
      if (useIDMapMounts)
      {
         mount2("/etc/resolv.conf"_ctv, path, MOUNT_ATTR_RDONLY | MOUNT_ATTR_IDMAP | MOUNT_ATTR_NOSUID, idMapPID);
      }
      else
      {
         mount2("/etc/resolv.conf"_ctv, path, MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID);
      }

      String gpuMountFailure = {};
      int gpuRootFD = -1;
      if (openVerifiedContainerRootfs(container, gpuRootFD, &gpuMountFailure) == false)
      {
         basics_log("mountRootFS gpu rootfs validation failed uuid=%llu root=%s reason=%s\n",
            (unsigned long long)container->plan.uuid,
            containerRoot.c_str(),
            gpuMountFailure.c_str());
         return false;
      }
      if (mountAssignedGPUDevicesInCurrentNamespace(container, containerRoot, gpuRootFD, &gpuMountFailure) == false)
      {
         close(gpuRootFD);
         basics_log("mountRootFS gpu device mount failed uuid=%llu root=%s reason=%s\n",
            (unsigned long long)container->plan.uuid,
            containerRoot.c_str(),
            gpuMountFailure.c_str());
         return false;
      }
      close(gpuRootFD);

      // we need to mount proc first here, then we mount over it in the child and it's correct
      // it used to just work only mounting /proc in the child... but won't now... doesn't matter beyond the vanity of the mount tree lol
      path.assign(containerRoot);
      path.append("/proc"_ctv);
      if (mount(NULL, path.c_str(), "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) != 0)
      {
         basics_log("mountRootFS mount /proc failed uuid=%llu path=%s errno=%d(%s)\n",
            (unsigned long long)container->plan.uuid,
            path.c_str(),
            errno,
            strerror(errno));
         return false;
      }
         
      path.assign(containerRoot);
      path2.assign(containerRoot);
      path2.append("/oldroot"_ctv);
      if (syscall(SYS_pivot_root, path.c_str(), path2.c_str()) != 0)
      {
         basics_log("mountRootFS pivot_root failed uuid=%llu newroot=%s putold=%s errno=%d(%s)\n",
            (unsigned long long)container->plan.uuid,
            path.c_str(),
            path2.c_str(),
            errno,
            strerror(errno));
         return false;
      }

      umount2("/oldroot", MNT_DETACH);
      rmdir("/oldroot");

      return true;
   }

   static bool restrictToCapabilities(Container *container, String *failureReport = nullptr)
   {
      cap_iab_t iab_caps = cap_iab_init();
      if (iab_caps == nullptr)
      {
         if (failureReport)
         {
            failureReport->snprintf<"restrictToCapabilities cap_iab_init failed for container {itoa}: {}"_ctv>(
               container->plan.uuid,
               String(strerror(errno)));
         }
         return false;
      }

      for (int index = 0; index < cap_max_bits(); index++)
      {
         if (container->plan.config.capabilities.contains(index)) continue;

         if (cap_iab_set_vector(iab_caps, CAP_IAB_BOUND, index, CAP_SET) != 0)
         {
            if (failureReport)
            {
               failureReport->snprintf<"restrictToCapabilities failed to bound capability {itoa} for container {itoa}: {}"_ctv>(
                  uint32_t(index),
                  container->plan.uuid,
                  String(strerror(errno)));
            }
            cap_free(iab_caps);
            return false;
         }
      }

      for (int capability : container->plan.config.capabilities)
      {
         if (cap_iab_set_vector(iab_caps, CAP_IAB_AMB, capability, CAP_SET) != 0)
         {
            if (failureReport)
            {
               failureReport->snprintf<"restrictToCapabilities failed to allow ambient capability {itoa} for container {itoa}: {}"_ctv>(
                  uint32_t(capability),
                  container->plan.uuid,
                  String(strerror(errno)));
            }
            cap_free(iab_caps);
            return false;
         }
      }

      if (cap_iab_set_proc(iab_caps) != 0)
      {
         if (failureReport)
         {
            failureReport->snprintf<"restrictToCapabilities cap_iab_set_proc failed for container {itoa}: {}"_ctv>(
               container->plan.uuid,
               String(strerror(errno)));
         }
         cap_free(iab_caps);
         return false;
      }
      cap_free(iab_caps);

      cap_t procCaps = cap_init();
      if (procCaps == nullptr)
      {
         if (failureReport)
         {
            failureReport->snprintf<"restrictToCapabilities cap_init failed for container {itoa}: {}"_ctv>(
               container->plan.uuid,
               String(strerror(errno)));
         }
         return false;
      }

      for (int capability : container->plan.config.capabilities)
      {
         cap_value_t value = cap_value_t(capability);
         if (cap_set_flag(procCaps, CAP_PERMITTED, 1, &value, CAP_SET) != 0
            || cap_set_flag(procCaps, CAP_EFFECTIVE, 1, &value, CAP_SET) != 0
            || cap_set_flag(procCaps, CAP_INHERITABLE, 1, &value, CAP_SET) != 0)
         {
            if (failureReport)
            {
               failureReport->snprintf<"restrictToCapabilities failed to configure process capability {itoa} for container {itoa}: {}"_ctv>(
                  uint32_t(capability),
                  container->plan.uuid,
                  String(strerror(errno)));
            }
            cap_free(procCaps);
            return false;
         }
      }

      if (cap_set_proc(procCaps) != 0)
      {
         if (failureReport)
         {
            failureReport->snprintf<"restrictToCapabilities cap_set_proc failed for container {itoa}: {}"_ctv>(
               container->plan.uuid,
               String(strerror(errno)));
         }
         cap_free(procCaps);
         return false;
      }

      cap_free(procCaps);
      return true;
   }

public:

   static bool restrictContainerSyscalls(Container *container)
   {
      scmp_filter_ctx seccomp = seccomp_init(SCMP_ACT_ALLOW);
      if (seccomp == nullptr)
      {
         basics_log("restrictContainerSyscalls seccomp_init failed uuid=%llu errno=%d(%s)\n",
            (unsigned long long)container->plan.uuid,
            errno,
            strerror(errno));
         return false;
      }

      auto denySyscallByName = [&] (const char *name) -> bool
      {
         int32_t syscallNumber = seccomp_syscall_resolve_name(name);
         if (syscallNumber == __NR_SCMP_ERROR)
         {
            return true;
         }

         int addRuleResult = seccomp_rule_add(seccomp, SCMP_ACT_ERRNO(EPERM), syscallNumber, 0);
         if (addRuleResult != 0)
         {
            basics_log("restrictContainerSyscalls seccomp_rule_add failed uuid=%llu syscall=%s rc=%d\n",
               (unsigned long long)container->plan.uuid,
               name,
               addRuleResult);
            return false;
         }

         return true;
      };

      constexpr const char *alwaysDeniedSyscalls[] = {
         "bpf",
         "perf_event_open",
         "ptrace",
         "process_vm_readv",
         "process_vm_writev",
         "process_madvise",
         "kcmp",
         "pidfd_open",
         "pidfd_getfd",
         "pidfd_send_signal",
         "kexec_load",
         "kexec_file_load",
         "init_module",
         "finit_module",
         "delete_module",
         "syslog",
         "reboot",
         "swapon",
         "swapoff",
         "mount",
         "umount2",
         "pivot_root",
         "move_mount",
         "open_tree",
         "fsopen",
         "fsconfig",
         "fsmount",
         "mount_setattr",
         "setns",
         "unshare",
         "userfaultfd",
         "name_to_handle_at",
         "open_by_handle_at",
         "iopl",
         "ioperm",
         "settimeofday",
         "clock_settime",
         "clock_adjtime",
         "adjtimex",
         "acct",
         "quotactl",
         "quotactl_fd",
         "add_key",
         "request_key",
         "keyctl"
      };

      for (const char *name : alwaysDeniedSyscalls)
      {
         if (denySyscallByName(name) == false)
         {
            seccomp_release(seccomp);
            return false;
         }
      }

      if (applicationUsesSharedCPUs(container->plan.config))
      {
         // Shared CPU mode stays OS-scheduled and must not let the workload pin itself.
         if (denySyscallByName("sched_setaffinity") == false)
         {
            seccomp_release(seccomp);
            return false;
         }
      }

      int loadResult = seccomp_load(seccomp);
      seccomp_release(seccomp);
      if (loadResult != 0)
      {
         basics_log("restrictContainerSyscalls seccomp_load failed uuid=%llu rc=%d\n",
            (unsigned long long)container->plan.uuid,
            loadResult);
         return false;
      }

      return true;
   }

private:

   static bool applyContainerPostMountExecutionSecurityPolicy(Container *container, String *failureReport = nullptr)
   {
      if (restrictToCapabilities(container, failureReport) == false)
      {
         return false;
      }

      if (restrictContainerSyscalls(container) == false)
      {
         if (failureReport)
         {
            failureReport->snprintf<"restrictContainerSyscalls failed for container {itoa}"_ctv>(
               container->plan.uuid);
         }
         return false;
      }

      return true;
   }

public:

   static bool adjustRunningContainerResources(Container *container, uint16_t targetCores, uint32_t targetMemoryMB, uint32_t targetStorageMB, String *failureReport = nullptr)
   {
      return applyContainerResourceTargets(container, targetCores, targetMemoryMB, targetStorageMB, failureReport);
   }

   static bool startContainer(Container *container, bool isRestart = false, String *failureReport = nullptr)
   {
      ensureSigchldIsWaitable();

      if (container->artifactRootPath.size() == 0)
      {
         container->artifactRootPath.assign("/containers/"_ctv);
         container->artifactRootPath.append(container->name);
      }

      if (container->rootfsPath.size() == 0)
      {
         container->rootfsPath.assign(container->artifactRootPath);
         container->rootfsPath.append("/rootfs"_ctv);
      }

      if (container->executePath.size() == 0 || container->executeArchitecture == MachineCpuArchitecture::unknown)
      {
         String launchMetadataFailure = {};
         if (loadContainerLaunchMetadata(container, &launchMetadataFailure) == false)
         {
            if (failureReport)
            {
               failureReport->snprintf<"launch metadata load failed for container {itoa}: {}"_ctv>(
                  container->plan.uuid,
                  launchMetadataFailure);
            }

            return false;
         }
      }

      if (isRestart && container->cgroup >= 0) Filesystem::openWriteAtClose(container->cgroup, "cgroup.freeze"_ctv, "1"_ctv);

      int socs[2];
      if (socketpair(AF_UNIX, SOCK_STREAM, 0, socs) != 0)
      {
         if (failureReport)
         {
            failureReport->snprintf<"socketpair failed for container {itoa}: {}"_ctv>(container->plan.uuid, String(strerror(errno)));
         }
         return false;
      }

      int startupSync[2];
      if (pipe2(startupSync, O_CLOEXEC) != 0)
      {
         if (failureReport)
         {
            failureReport->snprintf<"pipe2(startupSync) failed for container {itoa}: {}"_ctv>(container->plan.uuid, String(strerror(errno)));
         }
         close(socs[0]);
         close(socs[1]);
         return false;
      }

      struct StartupSyncPayload
      {
         uint8_t startSignal = 0;
         pid_t idMapPID = -1;
      };

      struct clone_args args;
      memset(&args, 0, sizeof(args));
      args.pidfd = (uint64_t)&container->pidfd;
      args.exit_signal = SIGCHLD;
      args.flags = CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_PIDFD;

      bool useUserNamespace = true;

      if (useUserNamespace)
      {
         args.flags |= CLONE_NEWUSER;
      }

      if (container->plan.useHostNetworkNamespace == false)
      {
         args.flags |= CLONE_NEWNET;
         container->netdevs.setNames(String{container->plan.fragment});
      }

      if (container->cgroup >= 0)
      {
         args.flags |= CLONE_INTO_CGROUP;
         args.cgroup = uint64_t(container->cgroup);
      }
      else
      {
         args.cgroup = 0;
      }

      container->pid = syscall(SYS_clone3, &args, sizeof(struct clone_args));

      if (container->pid < 0)
      {
         if (failureReport)
         {
            failureReport->snprintf<"clone3 failed for container {itoa}: {}"_ctv>(container->plan.uuid, String(strerror(errno)));
         }

         close(startupSync[0]);
         close(startupSync[1]);
         close(socs[0]);
         close(socs[1]);
         return false;
      }

      if (container->pid == 0) // child
      {
         close(startupSync[1]);
         close(socs[0]);

         String privilegedFDCloseFailure = {};
         if (closeContainerChildPrivilegedFDs(container, &privilegedFDCloseFailure) == false)
         {
            basics_log("startContainer failed to close inherited privileged fds uuid=%llu reason=%s\n",
               (unsigned long long)container->plan.uuid,
               privilegedFDCloseFailure.c_str());
            _exit(containerStartupFailureExitCode);
         }

         StartupSyncPayload startupPayload;
         ssize_t startupRead = read(startupSync[0], &startupPayload, sizeof(startupPayload));
         close(startupSync[0]);
         bool childUsesUserNamespace = useUserNamespace;

         if (startupRead != ssize_t(sizeof(startupPayload)) || startupPayload.startSignal != 1 || (childUsesUserNamespace && startupPayload.idMapPID <= 0))
         {
            _exit(containerStartupFailureExitCode);
         }

         setuid(0);
         setgid(0);

         String noNewPrivsFailure = {};
         if (setContainerNoNewPrivileges(container, &noNewPrivsFailure) == false)
         {
            basics_log("startContainer failed to set no_new_privs uuid=%llu reason=%s\n",
               (unsigned long long)container->plan.uuid,
               noNewPrivsFailure.c_str());
            _exit(containerStartupFailureExitCode);
         }

         if (mountRootFSInCurrentNamespace(container, isRestart, startupPayload.idMapPID) == false)
         {
            _exit(containerStartupFailureExitCode);
         }

         if (sethostname("x", 1) != 0)
         {
            basics_log("startContainer sethostname failed uuid=%llu errno=%d(%s)\n",
               (unsigned long long)container->plan.uuid,
               errno,
               strerror(errno));
            _exit(containerStartupFailureExitCode);
         }

         if (setdomainname("x", 1) != 0)
         {
            basics_log("startContainer setdomainname failed uuid=%llu errno=%d(%s)\n",
               (unsigned long long)container->plan.uuid,
               errno,
               strerror(errno));
            _exit(containerStartupFailureExitCode);
         }

         String policyFailure = {};
         if (applyContainerPostMountExecutionSecurityPolicy(container, &policyFailure) == false)
         {
            basics_log("startContainer failed to apply post-mount security policy uuid=%llu reason=%s\n",
               (unsigned long long)container->plan.uuid,
               policyFailure.c_str());
            _exit(containerStartupFailureExitCode);
         }

         if (chdir(container->executeCwd.c_str()) != 0)
         {
            basics_log("startContainer chdir failed uuid=%llu cwd=%s errno=%d(%s)\n",
               (unsigned long long)container->plan.uuid,
               container->executeCwd.c_str(),
               errno,
               strerror(errno));
            _exit(containerStartupFailureExitCode);
         }

         int execNeuronFD = socs[1];
         String execDescriptorFailure = {};
         if (moveContainerExecDescriptorAboveMinimum(execNeuronFD, &execDescriptorFailure) == false)
         {
            basics_log("startContainer failed to move inherited neuron fd uuid=%llu reason=%s\n",
               (unsigned long long)container->plan.uuid,
               execDescriptorFailure.c_str());
            _exit(containerStartupFailureExitCode);
         }

         ContainerParameters parameters;
         parameters.uuid = container->plan.uuid;
         parameters.neuronFD = execNeuronFD;
         parameters.justCrashed = isRestart;

         parameters.memoryMB = container->plan.config.memoryMB;
         parameters.storageMB = container->plan.config.storageMB;
         parameters.nLogicalCores = uint16_t(applicationSharedCPUCoreHint(container->plan.config));
         parameters.cpuMode = container->plan.config.cpuMode;
         parameters.requestedCPUMillis = applicationRequestedCPUMillis(container->plan.config);
         if (applicationUsesIsolatedCPUs(container->plan.config))
         {
            parameters.lowCPU = container->lcores[0];
            parameters.highCPU = container->lcores[container->plan.config.nLogicalCores - 1];
         }
         else
         {
            parameters.lowCPU = -1;
            parameters.highCPU = -1;
         }

         for (const auto& [service, advertisement] : container->plan.advertisements)
         {
            parameters.advertisesOnPorts[service] = advertisement.port;
         }

         parameters.subscriptionPairings = container->plan.subscriptionPairings;
         parameters.advertisementPairings = container->plan.advertisementPairings;
         parameters.wormholes = container->plan.wormholes;
         parameters.whiteholes = container->plan.whiteholes;
         parameters.statefulMeshRoles = container->plan.statefulMeshRoles;
         for (const IPPrefix& address : container->plan.addresses)
         {
            if (address.network.is6)
            {
               parameters.private6 = address;
               break;
            }
         }

         parameters.flags.clear();
         parameters.flags.push_back(container->plan.shardGroup);

         parameters.hasCredentialBundle = container->plan.hasCredentialBundle;
         if (parameters.hasCredentialBundle)
         {
            parameters.credentialBundle = container->plan.credentialBundle;
         }

         if (parameters.hasCredentialBundle
            || container->plan.wormholes.empty() == false
            || container->plan.config.applicationID == 6)
         {
            basics_log(
               "startContainer params appID=%u uuid=%llu hasCredentialBundle=%u tlsIdentities=%u apiCredentials=%u wormholes=%u whiteholes=%u\n",
               unsigned(container->plan.config.applicationID),
               (unsigned long long)container->plan.uuid,
               unsigned(parameters.hasCredentialBundle),
               unsigned(parameters.credentialBundle.tlsIdentities.size()),
               unsigned(parameters.credentialBundle.apiCredentials.size()),
               unsigned(parameters.wormholes.size()),
               unsigned(parameters.whiteholes.size()));
         }

         if (container->plan.useHostNetworkNamespace == false && container->plan.whiteholes.empty() == false)
         {
            enableWhiteholeNonlocalBind(container->plan);
         }

         bool needsLegacyStatefulRoles = (parameters.statefulMeshRoles.client != 0 ||
            parameters.statefulMeshRoles.sibling != 0 ||
            parameters.statefulMeshRoles.cousin != 0 ||
            parameters.statefulMeshRoles.seeding != 0 ||
            parameters.statefulMeshRoles.sharding != 0);

         // SDK startup payloads use ProdigyWire, but wormhole/whitehole startup
         // data and runtime stateful role payloads still rely on the legacy
         // Bitsery payload until the SDK wire format grows those fields.
         String serializedParameters;
         if (parameters.wormholes.empty() == false || parameters.whiteholes.empty() == false || needsLegacyStatefulRoles)
         {
            BitseryEngine::serialize(serializedParameters, parameters);
         }
         else if (ProdigyWire::serializeContainerParameters(serializedParameters, parameters) == false)
         {
            _exit(containerStartupFailureExitCode);
         }

         int pfd = Memfd::create("container.params"_ctv);
         int execParamsFD = -1;
         if (pfd >= 0)
         {
            Memfd::writeAll(pfd, serializedParameters);
            // Move the inherited params memfd above the normal low-fd range so
            // the child can close everything else before exec without relying
            // on a fragile fixed descriptor number.
            execParamsFD = pfd;
            if (moveContainerExecDescriptorAboveMinimum(execParamsFD, &execDescriptorFailure) == false)
            {
               basics_log("startContainer failed to move inherited params fd uuid=%llu reason=%s\n",
                  (unsigned long long)container->plan.uuid,
                  execDescriptorFailure.c_str());
               _exit(containerStartupFailureExitCode);
            }

            String paramsFDText = {};
            paramsFDText.assignItoa(uint64_t(execParamsFD));
            setenv("PRODIGY_PARAMS_FD", paramsFDText.c_str(), 1);
         }

         // The parent process is launched under stdbuf in tests, which injects
         // LD_PRELOAD for line-buffering. That path does not exist in container
         // root filesystems and can destabilize startup.
         unsetenv("LD_PRELOAD");
         unsetenv("_STDBUF_I");
         unsetenv("_STDBUF_O");
         unsetenv("_STDBUF_E");

         for (const String& assignment : container->executeEnv)
         {
            uint64_t equalsIndex = 0;
            bool foundEquals = false;
            for (; equalsIndex < assignment.size(); ++equalsIndex)
            {
               if (assignment[equalsIndex] == '=')
               {
                  foundEquals = true;
                  break;
               }
            }

            if (foundEquals == false || equalsIndex == 0)
            {
               _exit(containerStartupFailureExitCode);
            }

            String key = {};
            key.append(reinterpret_cast<const char *>(assignment.data()), size_t(equalsIndex));

            String value = {};
            value.append(reinterpret_cast<const char *>(assignment.data() + equalsIndex + 1), size_t(assignment.size() - equalsIndex - 1));

            if (setenv(key.c_str(), value.c_str(), 1) != 0)
            {
               basics_log("startContainer setenv failed uuid=%llu key=%s errno=%d(%s)\n",
                  (unsigned long long)container->plan.uuid,
                  key.c_str(),
                  errno,
                  strerror(errno));
               _exit(containerStartupFailureExitCode);
            }
         }

         if (closeAllContainerExecDescriptorsExcept(execNeuronFD, execParamsFD, &execDescriptorFailure) == false)
         {
            basics_log("startContainer failed to sanitize inherited exec fds uuid=%llu reason=%s\n",
               (unsigned long long)container->plan.uuid,
               execDescriptorFailure.c_str());
            _exit(containerStartupFailureExitCode);
         }

         extern char **environ;
         Vector<char *> args;
         args.reserve(container->executeArgs.size() + 2);
         args.push_back(const_cast<char *>(container->executePath.c_str()));
         for (String& arg : container->executeArgs)
         {
            args.push_back(const_cast<char *>(arg.c_str()));
         }
         args.push_back(nullptr);

         const char *argv0 = container->executePath.c_str();
         int binaryAccess = access(argv0, X_OK);
         int binaryAccessErrno = errno;
         int ldAccess = access("/lib64/ld-linux-x86-64.so.2", R_OK);
         int ldAccessErrno = errno;
         int usrLdAccess = access("/usr/lib64/ld-linux-x86-64.so.2", R_OK);
         int usrLdAccessErrno = errno;
         execve(argv0, args.data(), environ);
         basics_log("startContainer execve failed uuid=%llu path=%s errno=%d(%s)\n",
            (unsigned long long)container->plan.uuid,
            argv0,
            errno,
            strerror(errno));
         basics_log("startContainer pre-exec access uuid=%llu bin=%d(%d) ld=%d(%d) usrld=%d(%d)\n",
            (unsigned long long)container->plan.uuid,
            binaryAccess,
            binaryAccessErrno,
            ldAccess,
            ldAccessErrno,
            usrLdAccess,
            usrLdAccessErrno);

         // when PID 1, process only receive receives signals it has set a mask for.... so this doesn't really matter for us?
         _exit(containerStartupFailureExitCode);
      }
      else // host, clone doesn't return until child calls exec
      {
         close(startupSync[0]);
         close(socs[1]);
         if (useUserNamespace && mapIDs(container, failureReport) == false)
         {
            close(startupSync[1]);
            close(socs[0]);

            kill(container->pid, SIGKILL);
            waitpid(container->pid, nullptr, 0);

            if (container->pidfd > 0)
            {
               close(container->pidfd);
               container->pidfd = -1;
            }

            return false;
         }

         container->setUnixPairHalf(socs[0]);

         if (container->plan.requiresDatacenterUniqueTag)
         {
            Message::construct(container->wBuffer, ContainerTopic::datacenterUniqueTag, thisNeuron->datacenterUniqueTag());
         }

         if (container->plan.useHostNetworkNamespace == false)
         {
            if (container->setupNetwork(failureReport) == false)
            {
               close(startupSync[1]);
               close(socs[0]);

               kill(container->pid, SIGKILL);
               waitpid(container->pid, nullptr, 0);

               if (container->pidfd > 0)
               {
                  close(container->pidfd);
                  container->pidfd = -1;
               }

               return false;
            }
         }
         else
         {
            for (const IPPrefix& prefix : container->plan.addresses)
            {
               thisNeuron->eth.addIP(prefix);
            }

            // Host-netns containers still need datacenter-scoped mesh routes for
            // container-to-container probes and other mesh-targeted traffic.
            installDatacenterMeshRoutes(thisNeuron->eth, thisNeuron->lcsubnet6.dpfx);
         }

         if (applicationUsesIsolatedCPUs(container->plan.config))
         {
            // Apply an explicit affinity mask as a safety backstop even when cgroup
            // constraints are unavailable; this keeps container CPU usage bounded to
            // the scheduler-assigned logical cores.
            cpu_set_t affinity;
            CPU_ZERO(&affinity);

            uint16_t nAffinityCores = container->plan.config.nLogicalCores;
            for (uint16_t index = 0; index < nAffinityCores; index++)
            {
               uint16_t lcore = container->lcores[index];
               if (lcore < CPU_SETSIZE)
               {
                  CPU_SET(lcore, &affinity);
               }
            }

            if (CPU_COUNT(&affinity) > 0)
            {
               if (sched_setaffinity(container->pid, sizeof(affinity), &affinity) != 0)
               {
                  basics_log("startContainer sched_setaffinity failed pid=%d errno=%d(%s)\n",
                     int(container->pid), errno, strerror(errno));
               }
            }
         }

         thisNeuron->pushContainer(container);
         appendContainerTrace(container,
            "startContainer after-push pendingSend=%d pendingRecv=%d outstanding=%llu isFixed=%d fslot=%d registeredFD=%d fd=%d\n",
            int(container->pendingSend),
            int(container->pendingRecv),
            (unsigned long long)container->queuedSendOutstandingBytes(),
            int(container->isFixedFile),
            container->fslot,
            (container->isFixedFile && container->fslot >= 0 ? Ring::getFDFromFixedFileSlot(container->fslot) : container->fd),
            container->fd);
         Ring::queueRecv(container);
         appendContainerTrace(container,
            "startContainer after-queueRecv pendingSend=%d pendingRecv=%d outstanding=%llu\n",
            int(container->pendingSend),
            int(container->pendingRecv),
            (unsigned long long)container->queuedSendOutstandingBytes());
         Ring::queueWaitid(container, P_PID, container->pid);
         seedDynamicData(container);

         StartupSyncPayload startupPayload;
         startupPayload.startSignal = 1;
         startupPayload.idMapPID = useUserNamespace ? container->pid : -1;
         ssize_t startupWrite = write(startupSync[1], &startupPayload, sizeof(startupPayload));
         close(startupSync[1]);
         if (startupWrite != ssize_t(sizeof(startupPayload)))
         {
            if (failureReport)
            {
               failureReport->snprintf<"startup sync write failed for container {itoa}: {}"_ctv>(container->plan.uuid, String(strerror(errno)));
            }
            return false;
         }

         String pendingMarkerFailure = {};
         if (clearContainerCreatePendingMarker(container->artifactRootPath, &pendingMarkerFailure) == false)
         {
            basics_log("startContainer failed to clear pending-create marker uuid=%llu artifactRoot=%s reason=%s\n",
               (unsigned long long)container->plan.uuid,
               container->artifactRootPath.c_str(),
               pendingMarkerFailure.c_str());
         }

         if (container->cgroup >= 0)
         {
            Filesystem::openWriteAtClose(container->cgroup, "cgroup.freeze"_ctv, "0"_ctv);
         }

         Ring::queueRecv(container, container->plan.config.msTilHealthy);
         appendContainerTrace(container,
            "startContainer after-health-timeout pendingSend=%d pendingRecv=%d pendingSendBytes=%u outstanding=%llu isFixed=%d fslot=%d registeredFD=%d\n",
            int(container->pendingSend),
            int(container->pendingRecv),
            unsigned(container->pendingSendBytes),
            (unsigned long long)container->queuedSendOutstandingBytes(),
            int(container->isFixedFile),
            container->fslot,
            (container->isFixedFile && container->fslot >= 0 ? Ring::getFDFromFixedFileSlot(container->fslot) : container->fd));
         return true;
      }

      return false;
   }

   static void spinContainer(ContainerPlan plan, uint128_t replaceContainerUUID, const NeuronContainerMetricPolicy& metricPolicy) // copy this into here in case we suspend
   {
      if (rootCgroupSeeded == false)
      {
         seed_root_cgroupv2_subtree_controllers();
         rootCgroupSeeded = true;
      }

      if (replaceContainerUUID > 0)
      {
         if (auto it = thisNeuron->containers.find(replaceContainerUUID); it != thisNeuron->containers.end())
         {
            // updating in place
            CoroutineStack *coro = new CoroutineStack();

            Container *old = it->second;
            old->deleteStorageOnCleanUp = false;
            old->resumeAfterShutdown = coro;
            old->stop();

            co_await coro->suspend();

            delete coro;

            renameContainerStorageArtifacts(replaceContainerUUID, plan.uuid);
         }
      }

      uint64_t deploymentID = plan.config.deploymentID();
      String compressedContainerPath = ContainerStore::pathForContainerImage(deploymentID);
      std::fprintf(stderr, "spinContainer begin deploymentID=%llu replaceUUID=%llu path=%s contains=%d\n",
         (unsigned long long)deploymentID,
         (unsigned long long)replaceContainerUUID,
         compressedContainerPath.c_str(),
         int(ContainerStore::contains(deploymentID)));
      std::fflush(stderr);
      if (ContainerStore::contains(deploymentID) == false)
      {
         CoroutineStack pullWaiter;
         uint32_t suspendIndex = pullWaiter.nextSuspendIndex();
         thisNeuron->downloadContainer(&pullWaiter, deploymentID);
         co_await pullWaiter.suspendAtIndex(suspendIndex);
         std::fprintf(stderr, "spinContainer download resumed deploymentID=%llu path=%s contains=%d readable=%d\n",
            (unsigned long long)deploymentID,
            compressedContainerPath.c_str(),
            int(ContainerStore::contains(deploymentID)),
            int(access(compressedContainerPath.c_str(), R_OK) == 0));
         std::fflush(stderr);
      }

      if (access(compressedContainerPath.c_str(), R_OK) != 0)
      {
         std::fprintf(stderr, "spinContainer missing image deploymentID=%llu path=%s errno=%d(%s)\n",
            (unsigned long long)deploymentID,
            compressedContainerPath.c_str(),
            errno,
            strerror(errno));
         std::fflush(stderr);
         co_return;
      }

      String blobVerificationFailure = {};
      if (verifyCompressedContainerBlob(
         compressedContainerPath,
         plan.config.containerBlobSHA256,
         plan.config.containerBlobBytes,
         &blobVerificationFailure) == false)
      {
         std::fprintf(stderr, "spinContainer rejected image deploymentID=%llu path=%s reason=%s\n",
            (unsigned long long)deploymentID,
            compressedContainerPath.c_str(),
            (blobVerificationFailure.size() > 0 ? blobVerificationFailure.c_str() : "unknown"));
         std::fflush(stderr);
         co_return;
      }

      ContainerRegistry::retain(deploymentID);

      Container *container = nullptr;
      createContainer(plan, compressedContainerPath, container);
      if (container == nullptr)
      {
         std::fprintf(stderr, "spinContainer createContainer returned null deploymentID=%llu\n",
            (unsigned long long)deploymentID);
         std::fflush(stderr);
         co_return;
      }

      container->neuronScalingDimensionsMask = metricPolicy.scalingDimensionsMask;
      container->neuronMetricsCadenceMs = metricPolicy.metricsCadenceMs;

      String failureReport;
      if (startContainer(container, false, &failureReport) == false)
      {
         if (failureReport.size() == 0) failureReport.assign("startContainer failed"_ctv);
         cleanupContainerAfterFailedCreate(container);
         std::fprintf(stderr, "spinContainer start failed deploymentID=%llu appID=%u reason=%s\n",
            (unsigned long long)plan.config.deploymentID(),
            unsigned(plan.config.applicationID),
            failureReport.c_str());
         std::fflush(stderr);
         co_return;
      }

      std::fprintf(stderr, "spinContainer start ok deploymentID=%llu appID=%u containerUUID=%llu pid=%d\n",
         (unsigned long long)plan.config.deploymentID(),
         unsigned(plan.config.applicationID),
         (unsigned long long)container->plan.uuid,
         int(container->pid));
      std::fflush(stderr);
   }

   static void killContainer(Container *container)
   {
      if (container->cgroup >= 0)
      {
         Filesystem::openWriteAtClose(container->cgroup, "cgroup.kill"_ctv, "1"_ctv);
      }
   }

   static void restartContainer(Container *container)
   {
      container->plan.state = ContainerState::scheduled;

   // destroy any advertisements or subscriptions which should not exist at state schedule

      for (auto it = container->plan.advertisementPairings.begin(); it != container->plan.advertisementPairings.end();)
      {
         uint64_t service = it->first;
         const Advertisement& advertisement = container->plan.advertisements[service];

         if (advertisement.startAt != ContainerState::scheduled) // delete all of these
         {
            it = container->plan.advertisementPairings.erase(it);
         }
         else
         {
            it++;
         }
      }

      for (auto it = container->plan.subscriptionPairings.begin(); it != container->plan.subscriptionPairings.end();)
      {
         uint64_t service = it->first;
         const Subscription& subscription = container->plan.subscriptions[service];

         if (subscription.startAt != ContainerState::scheduled) // delete all of these
         {
            it = container->plan.subscriptionPairings.erase(it);
         }
         else
         {
            it++;
         }
      }

      if (container->pidfd > 0) close(container->pidfd);

      container->cleanupNetwork();

      String failureReport;
      if (startContainer(container, true, &failureReport) == false)
      {
         if (failureReport.size() == 0) failureReport.assign("restart startContainer failed"_ctv);
         basics_log("restartContainer start failed uuid=%llu reason=%s\n",
            (unsigned long long)container->plan.uuid,
            failureReport.c_str());
         destroyContainer(container);
      }
   }

	   static void finalizeContainerDestroy(Container *container)
	   {
	      if (container == nullptr || container->pendingDestroy == false)
	      {
	         return;
	      }

         if (container->pendingKillAckToBrain && thisNeuron != nullptr)
         {
            thisNeuron->queueContainerKillAck(container->plan.uuid);
            std::fprintf(stderr, "destroyContainer finalize-kill-ack uuid=%llu\n",
               (unsigned long long)container->plan.uuid);
            std::fflush(stderr);
            container->pendingKillAckToBrain = false;
         }

	      ContainerRegistry::pop(container);
	      thisNeuron->popContainer(container);
	      delete container;
	   }

	   static void destroyContainer(Container *container)
	   {
	      if (container == nullptr || container->pendingDestroy)
	      {
	         return;
	      }

	      container->pendingDestroy = true;
	      String path;

         int processAlive = 0;
         if (container->pid > 0 && kill(container->pid, 0) == 0)
         {
            processAlive = 1;
         }

         basics_log("destroyContainer begin uuid=%llu pid=%d processAlive=%d killedOnPurpose=%d restartOnFailure=%d state=%u fd=%d fslot=%d artifactRoot=%s rootfs=%s\n",
            (unsigned long long)container->plan.uuid,
            int(container->pid),
            processAlive,
            int(container->killedOnPurpose),
            int(container->plan.restartOnFailure),
            unsigned(container->plan.state),
            container->fd,
            container->fslot,
            container->artifactRootPath.c_str(),
            container->rootfsPath.c_str());

         auto logDestroyFilePreview = [&] (StringType auto&& relativePath, const char *label) -> void
         {
            if (container->artifactRootPath.size() == 0)
            {
               return;
            }

            String fullPath = {};
            fullPath.assign(container->artifactRootPath);
            fullPath.append(relativePath);

            String contents = {};
            Filesystem::openReadAtClose(-1, fullPath, contents);
            if (contents.size() == 0)
            {
               return;
            }

            uint64_t previewBytes = contents.size();
            if (previewBytes > 768)
            {
               previewBytes = 768;
            }

            String preview = {};
            preview.reserve(previewBytes + 1);

            for (uint64_t idx = 0; idx < previewBytes; ++idx)
            {
               char c = contents[idx];
               if (c < 32 || c > 126)
               {
                  c = '.';
               }
               preview.append(&c, 1);
            }

            char terminalNull = '\0';
            preview.append(&terminalNull, 1);

            basics_log("destroyContainer %s uuid=%llu bytes=%u preview=%s\n",
               label,
               (unsigned long long)container->plan.uuid,
               unsigned(contents.size()),
               preview.c_str());
         };

         logDestroyFilePreview("/bootstage.txt"_ctv, "bootstage");
         logDestroyFilePreview("/crashreport.txt"_ctv, "crashreport");
         logDestroyFilePreview("/readytrace.log"_ctv, "readytrace");

      container->cleanupNetwork();

      if (container->killedOnPurpose == false
         && container->failedArtifactsPreserved == false
         && container->infop.si_pid > 0)
      {
         String retainedBundlePath = {};
         String retainedBundleFailure = {};
         if (preserveFailedContainerArtifactsIfNeededWithDefaultRoot(
               container,
               Time::now<TimeResolution::ms>(),
               &retainedBundlePath,
               &retainedBundleFailure) == false)
         {
            basics_log("destroyContainer failed-container artifact retention failed uuid=%llu reason=%s\n",
               (unsigned long long)container->plan.uuid,
               retainedBundleFailure.c_str());
         }
         else if (retainedBundlePath.size() > 0)
         {
            basics_log("destroyContainer failed-container artifacts retained uuid=%llu path=%s\n",
               (unsigned long long)container->plan.uuid,
               retainedBundlePath.c_str());
         }
      }

      if (container->resourceDeltaTimer)
      {
         Ring::queueCancelTimeout(container->resourceDeltaTimer);
         container->resourceDeltaTimer = nullptr;
      }
      container->resourceDeltaMode = Container::ResourceDeltaMode::none;

   // reclaim resources

	      if (container->pidfd > 0)
	      {
	         close(container->pidfd);
	         container->pidfd = -1;
	      }
	      if (container->cgroup > 0)
	      {
	         close(container->cgroup);
	         container->cgroup = -1;
	      }

	      bool waitingForCloseEvent = false;

	      if (Ring::socketIsClosing(container) == false)
	      {
	         if (container->isFixedFile == false)
	         {
	            if (container->fslot >= 0)
	            {
	               basics_log("destroyContainer expected fixed-file socket uuid=%llu fd=%d fslot=%d\n",
	                  (unsigned long long)container->plan.uuid, container->fd, container->fslot);
	               std::abort();
	            }
	         }
	         else if (container->fslot >= 0)
	         {
	            Ring::queueCancelAll(container);
	            Ring::queueClose(container);
	            waitingForCloseEvent = true;
	         }
	      }
	      else
	      {
	         waitingForCloseEvent = true;
	      }

      if (applicationUsesIsolatedCPUs(container->plan.config))
      {
	      for (uint16_t index = 0; index < container->plan.config.nLogicalCores; index++)
	      {
	         thisNeuron->lcores[container->lcores[index]] = 0;
	      }
      }

   // destroy subvolume
      String containerSubvolumePath = {};
      containerSubvolumePath.assign("/containers/"_ctv);
      containerSubvolumePath.append(container->name);

      std::fprintf(stderr, "destroyContainer subvolume-delete-begin uuid=%llu path=%s waitingForCloseEvent=%d\n",
         (unsigned long long)container->plan.uuid,
         containerSubvolumePath.c_str(),
         int(waitingForCloseEvent));
      std::fflush(stderr);

      std::vector<char *> argv;
      argv.push_back((char *)"btrfs");
      argv.push_back((char *)"subvolume");
      argv.push_back((char *)"delete");
      argv.push_back((char *)containerSubvolumePath.c_str());
      argv.push_back(nullptr);

      String destroyOutput = {};
      String destroyFailure = {};
      if (runExternalCommand("btrfs_container_subvolume_delete", "btrfs", argv, &destroyOutput, &destroyFailure) == false)
      {
         basics_log("destroyContainer subvolume delete failed uuid=%llu path=%s reason=%s output=%s\n",
            (unsigned long long)container->plan.uuid,
            containerSubvolumePath.c_str(),
            destroyFailure.c_str(),
            destroyOutput.c_str());
      }

      std::fprintf(stderr, "destroyContainer subvolume-delete-end uuid=%llu path=%s outputBytes=%u\n",
         (unsigned long long)container->plan.uuid,
         containerSubvolumePath.c_str(),
         unsigned(destroyOutput.size()));
      std::fflush(stderr);

      teardownContainerStorage(container);

      std::fprintf(stderr, "destroyContainer storage-teardown-end uuid=%llu waitingForCloseEvent=%d\n",
         (unsigned long long)container->plan.uuid,
         int(waitingForCloseEvent));
      std::fflush(stderr);

   // destroy cgroup tree
      path.assign("/sys/fs/cgroup/containers.slice/"_ctv);
      path.append(container->name);
      path.append(".slice"_ctv);
      rmdir(path.c_str());

      std::fprintf(stderr, "destroyContainer cgroup-teardown-end uuid=%llu waitingForCloseEvent=%d\n",
         (unsigned long long)container->plan.uuid,
         int(waitingForCloseEvent));
      std::fflush(stderr);

	      if (waitingForCloseEvent)
	      {
	         return;
	      }

      std::fprintf(stderr, "destroyContainer finalize-immediate uuid=%llu\n",
         (unsigned long long)container->plan.uuid);
      std::fflush(stderr);

	      finalizeContainerDestroy(container);
	   }

// approve in master before distributing
// in the future we can provide a way to dynamically update the allowed capabilities, but these should rarely change
   static bool approveCapabilities(ContainerPlan& plan)
   {
      for (int capability : plan.config.capabilities)
      {
         switch (capability)
         {
            case CAP_NET_BIND_SERVICE: // ports below 1024
            case CAP_IPC_LOCK:         // allocate hugepages
            {
               continue;
            }
            default:
            {
               return false;
            }
         }
      }

      return true;
   }
};
