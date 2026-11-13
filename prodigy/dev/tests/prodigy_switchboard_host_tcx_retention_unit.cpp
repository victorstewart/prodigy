// Copyright 2026 Victor Stewart
// SPDX-License-Identifier: Apache-2.0
//
// This executable is intentionally privileged. Its wrapper supplies an empty
// private bpffs mounted at /sys/fs/bpf and a private network namespace.
#include <net/if.h>
#include <arpa/inet.h>
#include <networking/includes.h>
#include <services/debug.h>

#include <ebpf/program.h>
#include <networking/netlink.h>
#include <networking/veth.h>

#include <bpf/bpf.h>
#include <prodigy/neuron/neuron.h>
#include <switchboard/host.tcx.retention.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <poll.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

class TestSuite {
public:
  int failed = 0;

  void expect(bool condition, const char *name)
  {
    std::fprintf(stderr, "%s: %s\n", condition ? "PASS" : "FAIL", name);
    failed += condition ? 0 : 1;
  }
};

static bool verifiedDisposableKVMBoundary()
{
  struct stat markerStat = {};
  if (::stat("/run/prodigy-disposable-linux", &markerStat) != 0 ||
      !S_ISREG(markerStat.st_mode) || markerStat.st_uid != 0 ||
      (markerStat.st_mode & (S_IWGRP | S_IWOTH)) != 0)
    return false;

  FILE *marker = std::fopen("/run/prodigy-disposable-linux", "r");
  char markerText[64] = {};
  size_t markerBytes = marker ? std::fread(markerText, 1, sizeof(markerText), marker) : 0;
  if (marker) std::fclose(marker);
  if (markerBytes > 0 && markerText[markerBytes - 1] == '\n') --markerBytes;
  constexpr const char expectedMarker[] = "prodigy-disposable-linux-v1";
  if (markerBytes != sizeof(expectedMarker) - 1 ||
      std::memcmp(markerText, expectedMarker, sizeof(expectedMarker) - 1) != 0)
    return false;

  FILE *virt = ::popen("/usr/bin/systemd-detect-virt --vm", "r");
  char virtualization[32] = {};
  const bool kvm = virt && std::fgets(virtualization, sizeof(virtualization), virt) &&
                   std::strcmp(virtualization, "kvm\n") == 0;
  const int virtStatus = virt ? ::pclose(virt) : -1;
  return kvm && virtStatus == 0;
}

static bool createPrivateVeth(VethPair& pair, const char *hostName = "hosttcx0", const char *peerName = "hosttcx1")
{
  pair.host.ifidx = 0;
  pair.peer.ifidx = 0;
  std::memset(pair.host.mac, 0, sizeof(pair.host.mac));
  std::memset(pair.peer.mac, 0, sizeof(pair.peer.mac));
  pair.host.name.assign(hostName);
  pair.peer.name.assign(peerName);
  pair.socket.configure();
  pair.createPair(-1);
  if (pair.host.ifidx == 0 || pair.peer.ifidx == 0) return false;
  pair.host.socket.configure();
  pair.peer.socket.configure();
  pair.host.bringUp();
  pair.peer.bringUp();
  return true;
}

static bool attachHostRouters(NetDevice& device, String& ingressObjectPath, String& egressObjectPath)
{
  BPFProgram *egress = device.attachBPF(BPF_TCX_EGRESS, egressObjectPath, "host_egress"_ctv,
                                        [](struct bpf_object *object, Vector<int>&) {
                                          switchboardConfigureDevelopmentWhiteholeMapAllocation(object);
                                        });
  if (egress == nullptr || switchboardPinWormholeFlowMaps(egress, device.ifidx,
                                                        SwitchboardWormholeMapConsumer::forwarding) == false) return false;

  BPFProgram *ingress = device.attachBPF(BPF_TCX_INGRESS, ingressObjectPath, "host_ingress"_ctv,
                                         [&device](struct bpf_object *object, Vector<int>& innerMapFDs) {
                                           switchboardConfigureDevelopmentWhiteholeMapAllocation(object);
                                           (void)switchboardReusePinnedWormholeFlowMaps(object, device.ifidx, innerMapFDs);
                                         });
  return ingress != nullptr && switchboardProgramUsesPinnedWormholeFlowMaps(ingress, device.ifidx);
}

static bool pinWrongDirectionLink(uint32_t ifindex)
{
  BPFProgram::TCXIdentity ingress = {};
  if (BPFProgram::openTCXIdentity(ifindex, BPF_TCX_INGRESS, 0, ingress) == false) return false;
  String wrongPath = {};
  switchboardHostTCXRetentionPath(wrongPath, "/sys/fs/bpf"_ctv, ifindex, SwitchboardHostTCXDirection::egress);
  const bool pinned = bpf_obj_pin(ingress.linkFD, wrongPath.c_str()) == 0;
  BPFProgram::closeTCXIdentity(ingress);
  return pinned;
}

class CrashRetentionNeuron final : public Neuron {
public:
  bool retainPrimaryForCrashTest(const String& device, bool& created)
  {
    eth.setDevice(device);
    return retainExactHostTCXForUnexpectedRestart(eth, retainedPrimaryHostTCX,
                                                   retainedPrimaryHostTCXPresent, nullptr, &created);
  }

  const SwitchboardHostTCXRetentionPair& retainedPrimaryForCrashTest(void) const
  {
    return retainedPrimaryHostTCX;
  }

  void releasePrimaryForCrashTest(void)
  {
    releaseExactHostTCXForGracefulShutdown(retainedPrimaryHostTCX,
                                            retainedPrimaryHostTCXPresent, "crash-test-primary");
  }
};

struct CrashRetentionReceipt {
  uint32_t ifindex = 0;
  SwitchboardHostTCXRetentionPair pair = {};
  uint8_t retained = 0;
};

static bool writeCrashRetentionReceipt(int fd, const CrashRetentionReceipt& receipt)
{
  size_t written = 0;
  while (written < sizeof(receipt))
  {
    const ssize_t result = ::write(fd, reinterpret_cast<const char *>(&receipt) + written, sizeof(receipt) - written);
    if (result < 0 && errno == EINTR) continue;
    if (result <= 0) return false;
    written += size_t(result);
  }
  return true;
}

static bool readCrashRetentionReceipt(int fd, CrashRetentionReceipt& receipt)
{
  size_t read = 0;
  while (read < sizeof(receipt))
  {
    pollfd poller = {.fd = fd, .events = POLLIN, .revents = 0};
    const int ready = ::poll(&poller, 1, 2'000);
    if (ready < 0 && errno == EINTR) continue;
    if (ready <= 0 || (poller.revents & (POLLERR | POLLNVAL))) return false;
    const ssize_t result = ::read(fd, reinterpret_cast<char *>(&receipt) + read, sizeof(receipt) - read);
    if (result < 0 && errno == EINTR) continue;
    if (result <= 0) return false;
    read += size_t(result);
  }
  return true;
}

static bool waitForCrashRetentionChild(pid_t child, int& status)
{
  for (uint32_t attempt = 0; attempt != 200; ++attempt)
  {
    const pid_t waited = ::waitpid(child, &status, WNOHANG);
    if (waited == child) return true;
    if (waited < 0 && errno != EINTR) return false;
    ::usleep(10'000);
  }
  return false;
}

static bool sameRetentionPair(const SwitchboardHostTCXRetentionPair& left,
                              const SwitchboardHostTCXRetentionPair& right)
{
  return switchboardHostTCXIdentityEquals(left.ingress, right.ingress) &&
         switchboardHostTCXIdentityEquals(left.egress, right.egress);
}

static bool testCrashRetainsAndNewNeuronAdopts(TestSuite& suite,
                                               String& ingressObjectPath,
                                               String& egressObjectPath)
{
  int pipeFDs[2] = {-1, -1};
  if (::pipe2(pipeFDs, O_CLOEXEC) != 0)
  {
    suite.expect(false, "host_tcx_retention_crash_opens_private_receipt_pipe");
    return false;
  }
  const pid_t parent = ::getpid();
  const pid_t child = ::fork();
  if (child == 0)
  {
    if (::prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || ::getppid() != parent) _exit(EXIT_FAILURE);
    ::close(pipeFDs[0]);
    CrashRetentionReceipt receipt = {};
    VethPair childPair = {};
    // Keep the exact owning Neuron and its veth/router FDs live until the
    // parent sends SIGKILL. `_exit` then avoids its graceful pin release.
    CrashRetentionNeuron neuron = {};
    bool created = false;
    if (createPrivateVeth(childPair, "hosttcx2", "hosttcx3") &&
        attachHostRouters(childPair.host, ingressObjectPath, egressObjectPath))
    {
      receipt.retained = neuron.retainPrimaryForCrashTest(childPair.host.name, created) && created;
      receipt.ifindex = childPair.host.ifidx;
      receipt.pair = neuron.retainedPrimaryForCrashTest();
    }
    const bool sent = writeCrashRetentionReceipt(pipeFDs[1], receipt);
    ::close(pipeFDs[1]);
    if (!sent || !receipt.retained) _exit(EXIT_FAILURE);
    for (;;) ::pause();
  }
  ::close(pipeFDs[1]);
  CrashRetentionReceipt receipt = {};
  const bool received = child > 0 && readCrashRetentionReceipt(pipeFDs[0], receipt);
  ::close(pipeFDs[0]);
  suite.expect(received && receipt.retained && receipt.ifindex != 0,
               "host_tcx_retention_crash_child_retains_exact_pair_before_kill");
  if (!received || !receipt.retained || receipt.ifindex == 0)
  {
    if (child > 0) { (void)::kill(child, SIGKILL); int status = 0; (void)waitForCrashRetentionChild(child, status); }
    return false;
  }
  suite.expect(::kill(child, SIGKILL) == 0, "host_tcx_retention_crash_kills_retaining_process");
  int status = 0;
  const bool reaped = waitForCrashRetentionChild(child, status);
  suite.expect(reaped && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL,
               "host_tcx_retention_crash_child_exits_without_graceful_release");
  if (!reaped) return false;

  EthDevice adoptedDevice = {};
  adoptedDevice.setDevice("hosttcx2"_ctv);
  suite.expect(adoptedDevice.ifidx == receipt.ifindex &&
               switchboardHostTCXVerifyRetainedPair(adoptedDevice, "/sys/fs/bpf"_ctv, receipt.pair),
               "host_tcx_retention_crash_pins_keep_exact_links_and_maps_alive");

  CrashRetentionNeuron successor = {};
  bool created = true;
  const bool adopted = adoptedDevice.ifidx == receipt.ifindex &&
      successor.retainPrimaryForCrashTest(adoptedDevice.name, created);
  suite.expect(adopted && created == false && sameRetentionPair(successor.retainedPrimaryForCrashTest(), receipt.pair),
               "host_tcx_retention_crash_new_neuron_adopts_without_new_link_ids");
  successor.releasePrimaryForCrashTest();
  SwitchboardHostTCXRetentionPair afterRelease = {};
  bool present = true;
  BPFProgram::TCXIdentity ingress = {}, egress = {};
  const bool released = switchboardHostTCXReadRetainedPair(adoptedDevice, "/sys/fs/bpf"_ctv, afterRelease, present) && !present &&
      !BPFProgram::openTCXIdentity(receipt.ifindex, BPF_TCX_INGRESS, receipt.pair.ingress.programID, ingress) &&
      !BPFProgram::openTCXIdentity(receipt.ifindex, BPF_TCX_EGRESS, receipt.pair.egress.programID, egress);
  BPFProgram::closeTCXIdentity(ingress);
  BPFProgram::closeTCXIdentity(egress);
  suite.expect(released, "host_tcx_retention_crash_graceful_release_removes_last_exact_links");
  return received && reaped && adopted && created == false && released;
}

int main(int argc, char **argv)
{
  if (argc != 3)
  {
    std::fprintf(stderr, "usage: %s <host.ingress.router.dev.ebpf.o> <host.egress.router.ebpf.o>\n", argv[0]);
    return 2;
  }

  TestSuite suite = {};
  struct stat ownNet = {}, initNet = {}, ownMount = {}, initMount = {};
  const char *boundary = std::getenv("PRODIGY_DEV_TEST_BOUNDARY");
  const bool supportedGuest = boundary &&
      (std::strcmp(boundary, "apple-container") == 0 ||
       (std::strcmp(boundary, "disposable-kvm") == 0 && verifiedDisposableKVMBoundary()));
  suite.expect(supportedGuest &&
               ::stat("/proc/self/ns/net", &ownNet) == 0 && ::stat("/proc/1/ns/net", &initNet) == 0 &&
               ::stat("/proc/self/ns/mnt", &ownMount) == 0 && ::stat("/proc/1/ns/mnt", &initMount) == 0 &&
               (ownNet.st_dev != initNet.st_dev || ownNet.st_ino != initNet.st_ino) &&
               (ownMount.st_dev != initMount.st_dev || ownMount.st_ino != initMount.st_ino),
               "host_tcx_retention_requires_guest_and_private_namespaces");
  suite.expect(::geteuid() == 0, "host_tcx_retention_requires_privileged_wrapper");
  suite.expect(switchboardHostTCXValidBPFFSRoot("/sys/fs/bpf"_ctv), "host_tcx_retention_requires_private_bpffs");
  if (suite.failed != 0) return 1;

  (void)::setenv("PRODIGY_DEV_MODE", "1", 1);
  VethPair pair = {};
  suite.expect(createPrivateVeth(pair), "host_tcx_retention_creates_private_veth");
  if (suite.failed != 0) return 1;

  String ingressObjectPath = {};
  String egressObjectPath = {};
  ingressObjectPath.assign(argv[1]);
  egressObjectPath.assign(argv[2]);
  SwitchboardHostTCXRetentionPair retained = {};
  bool present = true;
  suite.expect(switchboardHostTCXReadRetainedPair(pair.host, "/sys/fs/bpf"_ctv, retained, present) && present == false,
               "host_tcx_retention_admits_cold_missing_pins");
  suite.expect(switchboardHostTCXPairCleanlyAbsent(pair.host.ifidx, "/sys/fs/bpf"_ctv),
               "host_tcx_retention_accepts_cleanly_absent_primary_pair");
  // A failed attach-point query is not absence.  UINT32_MAX cannot name this
  // private veth and reaches the read-only kernel query after the pin checks.
  suite.expect(!switchboardHostTCXPairCleanlyAbsent(uint32_t(-1), "/sys/fs/bpf"_ctv),
               "host_tcx_retention_rejects_unqueryable_interface_as_absent");
  suite.expect(attachHostRouters(pair.host, ingressObjectPath, egressObjectPath), "host_tcx_retention_attaches_real_host_pair");
  if (suite.failed != 0) return 1;
  suite.expect(!switchboardHostTCXPairCleanlyAbsent(pair.host.ifidx, "/sys/fs/bpf"_ctv),
               "host_tcx_retention_rejects_live_unretained_pair_as_absent");

  String ingressPin = {};
  switchboardHostTCXRetentionPath(ingressPin, "/sys/fs/bpf"_ctv, pair.host.ifidx, SwitchboardHostTCXDirection::ingress);
  suite.expect(::mkdir(ingressPin.c_str(), 0700) == 0, "host_tcx_retention_creates_wrong_type_pin_path");
  suite.expect(switchboardHostTCXReadRetainedPair(pair.host, "/sys/fs/bpf"_ctv, retained, present) == false,
               "host_tcx_retention_rejects_wrong_type_pin_path");
  suite.expect(switchboardHostTCXRetainCurrentPair(pair.host, "/sys/fs/bpf"_ctv, retained) == false,
               "host_tcx_retention_rejects_wrong_type_pin_during_admission");
  suite.expect(::rmdir(ingressPin.c_str()) == 0, "host_tcx_retention_removes_wrong_type_pin_path");

  suite.expect(pinWrongDirectionLink(pair.host.ifidx), "host_tcx_retention_pins_wrong_direction_link_for_negative_case");
  suite.expect(switchboardHostTCXReadRetainedPair(pair.host, "/sys/fs/bpf"_ctv, retained, present) == false,
               "host_tcx_retention_rejects_partial_or_mismatched_pin");
  suite.expect(switchboardHostTCXRetainCurrentPair(pair.host, "/sys/fs/bpf"_ctv, retained) == false,
               "host_tcx_retention_rejects_mismatched_pin_during_admission");
  String egressPin = {};
  switchboardHostTCXRetentionPath(egressPin, "/sys/fs/bpf"_ctv, pair.host.ifidx, SwitchboardHostTCXDirection::egress);
  suite.expect(::unlink(egressPin.c_str()) == 0, "host_tcx_retention_removes_mismatched_pin");

  suite.expect(switchboardHostTCXRetainCurrentPair(pair.host, "/sys/fs/bpf"_ctv, retained),
               "host_tcx_retention_retains_exact_live_pair");
  suite.expect(!switchboardHostTCXPairCleanlyAbsent(pair.host.ifidx, "/sys/fs/bpf"_ctv),
               "host_tcx_retention_rejects_complete_retained_pair_as_absent");
  suite.expect(switchboardHostTCXVerifyRetainedPair(pair.host, "/sys/fs/bpf"_ctv, retained),
               "host_tcx_retention_verifies_exact_live_pair");

  // The runtime owner attaches the exact primary program FDs on a second
  // ifindex; it never creates a second map authority or retention pins.
  BPFProgram primaryIngress = {}, primaryEgress = {};
  EthDevice primaryEth = {}, overlayEth = {};
  primaryEth.setDevice(pair.host.name);
  overlayEth.setDevice(pair.peer.name);
  const bool primaryOpen =
      primaryIngress.loadPreattached(BPF_TCX_INGRESS, pair.host.ifidx, retained.ingress.programID, ingressObjectPath) &&
      primaryEgress.loadPreattached(BPF_TCX_EGRESS, pair.host.ifidx, retained.egress.programID, egressObjectPath);
  suite.expect(primaryOpen, "host_tcx_retention_opens_primary_pair_for_shared_overlay_links");
  String overlayFailure = {};
  {
    Switchboard overlayRouting(primaryEth);
    const bool configured = primaryOpen &&
        overlayRouting.configurePrivateOverlayHostRouting(overlayEth, &primaryIngress, &primaryEgress, &overlayFailure);
    suite.expect(configured, "host_tcx_retention_runtime_owner_attaches_shared_programs_on_second_ifindex");
    BPFProgram::TCXIdentity overlayIngressIdentity = {}, overlayEgressIdentity = {};
    suite.expect(configured &&
                 BPFProgram::openTCXIdentity(pair.peer.ifidx, BPF_TCX_INGRESS, retained.ingress.programID, overlayIngressIdentity) &&
                 BPFProgram::openTCXIdentity(pair.peer.ifidx, BPF_TCX_EGRESS, retained.egress.programID, overlayEgressIdentity),
                 "host_tcx_retention_runtime_owner_preserves_exact_overlay_identity");
    const uint32_t overlayIngressLinkID = overlayIngressIdentity.linkID;
    const uint32_t overlayEgressLinkID = overlayEgressIdentity.linkID;
    BPFProgram::closeTCXIdentity(overlayIngressIdentity);
    BPFProgram::closeTCXIdentity(overlayEgressIdentity);
    suite.expect(configured &&
                 overlayRouting.configurePrivateOverlayHostRouting(overlayEth, &primaryIngress, &primaryEgress, &overlayFailure) &&
                 BPFProgram::openTCXIdentity(pair.peer.ifidx, BPF_TCX_INGRESS, retained.ingress.programID, overlayIngressIdentity) &&
                 BPFProgram::openTCXIdentity(pair.peer.ifidx, BPF_TCX_EGRESS, retained.egress.programID, overlayEgressIdentity) &&
                 overlayIngressIdentity.linkID == overlayIngressLinkID && overlayEgressIdentity.linkID == overlayEgressLinkID,
                 "host_tcx_retention_runtime_owner_reconfigure_does_not_stack_overlay_links");
    BPFProgram::closeTCXIdentity(overlayIngressIdentity);
    BPFProgram::closeTCXIdentity(overlayEgressIdentity);
    {
      Switchboard adoptedOverlayRouting(primaryEth);
      suite.expect(configured &&
                   adoptedOverlayRouting.configurePrivateOverlayHostRouting(overlayEth, &primaryIngress, &primaryEgress, &overlayFailure) &&
                   BPFProgram::openTCXIdentity(pair.peer.ifidx, BPF_TCX_INGRESS, retained.ingress.programID, overlayIngressIdentity) &&
                   BPFProgram::openTCXIdentity(pair.peer.ifidx, BPF_TCX_EGRESS, retained.egress.programID, overlayEgressIdentity) &&
                   overlayIngressIdentity.linkID == overlayIngressLinkID && overlayEgressIdentity.linkID == overlayEgressLinkID,
                   "host_tcx_retention_runtime_owner_adopts_existing_overlay_links");
      BPFProgram::closeTCXIdentity(overlayIngressIdentity);
      BPFProgram::closeTCXIdentity(overlayEgressIdentity);
    }
    suite.expect(BPFProgram::openTCXIdentity(pair.peer.ifidx, BPF_TCX_INGRESS, retained.ingress.programID, overlayIngressIdentity) &&
                 BPFProgram::openTCXIdentity(pair.peer.ifidx, BPF_TCX_EGRESS, retained.egress.programID, overlayEgressIdentity) &&
                 overlayIngressIdentity.linkID == overlayIngressLinkID && overlayEgressIdentity.linkID == overlayEgressLinkID,
                 "host_tcx_retention_adopted_owner_close_preserves_original_overlay_links");
    BPFProgram::closeTCXIdentity(overlayIngressIdentity);
    BPFProgram::closeTCXIdentity(overlayEgressIdentity);
  BPFProgram overlayEgress = {}, overlayIngress = {};
  const bool overlayOpened = configured &&
      overlayEgress.loadPreattached(BPF_TCX_EGRESS, pair.peer.ifidx, retained.egress.programID, egressObjectPath) &&
      overlayIngress.loadPreattached(BPF_TCX_INGRESS, pair.peer.ifidx, retained.ingress.programID, ingressObjectPath);
  suite.expect(overlayOpened, "host_tcx_retention_adopts_shared_overlay_programs");
  suite.expect(overlayOpened && switchboardAliasPinnedWormholeFlowMaps(pair.host.ifidx, pair.peer.ifidx) &&
               switchboardProgramUsesPinnedWormholeFlowMaps(&overlayEgress, pair.peer.ifidx,
                                                             SwitchboardWormholeMapConsumer::forwarding),
               "host_tcx_retention_aliases_primary_overlay_maps_per_ifindex");
  SwitchboardHostTCXRetentionPair overlayRetained = {};
  bool overlayRetentionPresent = true;
  suite.expect(overlayOpened &&
               switchboardHostTCXReadRetainedPair(pair.peer, "/sys/fs/bpf"_ctv, overlayRetained, overlayRetentionPresent) &&
               overlayRetentionPresent == false,
               "host_tcx_retention_runtime_owner_does_not_create_overlay_retention_pins");
  overlayEgress.close();
  overlayIngress.close();
  }
  BPFProgram::TCXIdentity afterOverlayIngress = {}, afterOverlayEgress = {};
  suite.expect(BPFProgram::openTCXIdentity(pair.peer.ifidx, BPF_TCX_INGRESS, retained.ingress.programID, afterOverlayIngress) == false &&
               BPFProgram::openTCXIdentity(pair.peer.ifidx, BPF_TCX_EGRESS, retained.egress.programID, afterOverlayEgress) == false,
               "host_tcx_retention_runtime_owner_close_releases_overlay_links");
  BPFProgram::closeTCXIdentity(afterOverlayIngress);
  BPFProgram::closeTCXIdentity(afterOverlayEgress);
  primaryIngress.close();
  primaryEgress.close();

  // Exercise kernel-ID adoption, not the original object which also owns
  // declared maps that this program does not consume.
  BPFProgram reopenedEgress = {};
  suite.expect(reopenedEgress.loadPreattached(BPF_TCX_EGRESS, pair.host.ifidx,
                                             retained.egress.programID, egressObjectPath),
               "host_tcx_retention_reopens_exact_egress_program_and_link");
  bool consumesGrants = false;
  reopenedEgress.openMap("wh_pair_grants"_ctv, [&](int fd) { consumesGrants = fd >= 0; });
  suite.expect(!consumesGrants, "host_tcx_retention_host_egress_does_not_consume_grants");
  suite.expect(!switchboardProgramUsesPinnedWormholeFlowMaps(&reopenedEgress, pair.host.ifidx),
               "host_tcx_retention_admission_role_still_requires_grants");
  suite.expect(switchboardProgramUsesPinnedWormholeFlowMaps(&reopenedEgress, pair.host.ifidx,
                                                          SwitchboardWormholeMapConsumer::forwarding),
               "host_tcx_retention_reopened_egress_preserves_consumed_maps");
  suite.expect(switchboardPinWormholeFlowMaps(&reopenedEgress, pair.host.ifidx,
                                            SwitchboardWormholeMapConsumer::forwarding),
               "host_tcx_retention_reopened_egress_reuses_authoritative_pins");
  String grantPin = {};
  switchboardPairAdmissionGrantPinPath(grantPin, pair.host.ifidx);
  int grantFD = bpf_obj_get(grantPin.c_str());
  suite.expect(grantFD >= 0 && ::unlink(grantPin.c_str()) == 0,
               "host_tcx_retention_temporarily_removes_private_grant_pin");
  suite.expect(!switchboardPinWormholeFlowMaps(&reopenedEgress, pair.host.ifidx,
                                             SwitchboardWormholeMapConsumer::forwarding),
               "host_tcx_retention_reopened_forwarder_cannot_create_missing_grant_authority");
  int unexpectedGrantFD = bpf_obj_get(grantPin.c_str());
  suite.expect(unexpectedGrantFD < 0 && errno == ENOENT,
               "host_tcx_retention_failed_pin_reuse_does_not_create_authority");
  if (unexpectedGrantFD >= 0) ::close(unexpectedGrantFD);
  suite.expect(grantFD >= 0 && bpf_obj_pin(grantFD, grantPin.c_str()) == 0,
               "host_tcx_retention_restores_original_private_grant_pin");
  if (grantFD >= 0) ::close(grantFD);
  suite.expect(switchboardPinWormholeFlowMaps(&reopenedEgress, pair.host.ifidx,
                                            SwitchboardWormholeMapConsumer::forwarding),
               "host_tcx_retention_reuses_same_pins_after_authority_restored");
  suite.expect(switchboardHostTCXVerifyRetainedPair(pair.host, "/sys/fs/bpf"_ctv, retained),
               "host_tcx_retention_reopening_and_pin_reuse_preserve_identity");
  reopenedEgress.close();

  SwitchboardHostTCXRetentionPair wrong = retained;
  wrong.ingress.linkID += 1;
  suite.expect(switchboardHostTCXVerifyRetainedPair(pair.host, "/sys/fs/bpf"_ctv, wrong) == false,
               "host_tcx_retention_rejects_wrong_link_identity");
  wrong = retained;
  wrong.egress.wormholeFlowMapID += 1;
  suite.expect(switchboardHostTCXVerifyRetainedPair(pair.host, "/sys/fs/bpf"_ctv, wrong) == false,
               "host_tcx_retention_rejects_wrong_map_identity");
  wrong = retained;
  wrong.ingress.programTag[0] ^= 0x80;
  suite.expect(switchboardHostTCXVerifyRetainedPair(pair.host, "/sys/fs/bpf"_ctv, wrong) == false,
               "host_tcx_retention_rejects_wrong_program_tag");
  wrong = retained;
  wrong.egress.interfaceIndex += 1;
  suite.expect(switchboardHostTCXVerifyRetainedPair(pair.host, "/sys/fs/bpf"_ctv, wrong) == false,
               "host_tcx_retention_rejects_wrong_interface");
  suite.expect(switchboardHostTCXVerifyRetainedPair(pair.host, "/sys/fs/bpf"_ctv, retained),
               "host_tcx_retention_negative_checks_do_not_mutate_pair");

  BPFProgram::TCXIdentity borrowed = {};
  suite.expect(BPFProgram::openTCXIdentity(pair.host.ifidx, BPF_TCX_INGRESS, retained.ingress.programID, borrowed),
               "host_tcx_retention_opens_borrowed_live_link");
  BPFProgram::closeTCXIdentity(borrowed);
  suite.expect(switchboardHostTCXVerifyRetainedPair(pair.host, "/sys/fs/bpf"_ctv, retained),
               "host_tcx_retention_close_borrowed_link_keeps_pair_live");

  suite.expect(switchboardHostTCXReleaseExact("/sys/fs/bpf"_ctv, retained.ingress),
               "host_tcx_retention_releases_exact_ingress_pin");
  suite.expect(!switchboardHostTCXPairCleanlyAbsent(pair.host.ifidx, "/sys/fs/bpf"_ctv),
               "host_tcx_retention_rejects_partial_retention_pin_as_absent");
  suite.expect(switchboardHostTCXReleaseExact("/sys/fs/bpf"_ctv, retained.egress),
               "host_tcx_retention_releases_exact_egress_pin");
  present = true;
  suite.expect(switchboardHostTCXReadRetainedPair(pair.host, "/sys/fs/bpf"_ctv, retained, present) && present == false,
               "host_tcx_retention_release_restores_cold_state");

  // Preserve private map FDs only long enough to construct the two partial
  // states below.  Neither state may be mistaken for a clean absent pair.
  String flowPin = {}, pendingPin = {};
  switchboardHostTCXMapPinPath(flowPin, "/sys/fs/bpf"_ctv, pair.host.ifidx, false);
  switchboardHostTCXMapPinPath(pendingPin, "/sys/fs/bpf"_ctv, pair.host.ifidx, true);
  const int flowFD = bpf_obj_get(flowPin.c_str());
  const int pendingFD = bpf_obj_get(pendingPin.c_str());
  suite.expect(flowFD >= 0 && pendingFD >= 0,
               "host_tcx_retention_opens_authoritative_maps_for_partial_absence_cases");
  pair.host.detachBPF(BPF_TCX_INGRESS);
  suite.expect(!switchboardHostTCXPairCleanlyAbsent(pair.host.ifidx, "/sys/fs/bpf"_ctv),
               "host_tcx_retention_rejects_egress_only_live_direction_as_absent");
  pair.host.detachBPF(BPF_TCX_EGRESS);
  suite.expect(BPFProgram::openTCXIdentity(pair.host.ifidx, BPF_TCX_INGRESS, retained.ingress.programID, borrowed) == false,
               "host_tcx_retention_explicit_detach_removes_live_ingress_link");
  const bool mapPinsRemoved = (::unlink(flowPin.c_str()) == 0 || errno == ENOENT) &&
                              (::unlink(pendingPin.c_str()) == 0 || errno == ENOENT);
  suite.expect(mapPinsRemoved && flowFD >= 0 && pendingFD >= 0 &&
               bpf_obj_pin(flowFD, flowPin.c_str()) == 0 && bpf_obj_pin(pendingFD, pendingPin.c_str()) == 0,
               "host_tcx_retention_constructs_map_only_partial_absence_state");
  suite.expect(!switchboardHostTCXPairCleanlyAbsent(pair.host.ifidx, "/sys/fs/bpf"_ctv),
               "host_tcx_retention_rejects_map_only_state_as_absent");
  suite.expect(::unlink(flowPin.c_str()) == 0 && ::unlink(pendingPin.c_str()) == 0 &&
               switchboardHostTCXPairCleanlyAbsent(pair.host.ifidx, "/sys/fs/bpf"_ctv),
               "host_tcx_retention_accepts_only_complete_interface_bound_absence");
  if (flowFD >= 0) ::close(flowFD);
  if (pendingFD >= 0) ::close(pendingFD);

  (void)testCrashRetainsAndNewNeuronAdopts(suite, ingressObjectPath, egressObjectPath);

  return suite.failed == 0 ? 0 : 1;
}
