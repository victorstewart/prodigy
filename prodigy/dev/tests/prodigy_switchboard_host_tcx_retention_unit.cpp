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
#include <switchboard/host.tcx.retention.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/stat.h>
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

static bool createPrivateVeth(VethPair& pair)
{
  pair.host.ifidx = 0;
  pair.peer.ifidx = 0;
  std::memset(pair.host.mac, 0, sizeof(pair.host.mac));
  std::memset(pair.peer.mac, 0, sizeof(pair.peer.mac));
  pair.host.name.assign("hosttcx0"_ctv);
  pair.peer.name.assign("hosttcx1"_ctv);
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
  if (egress == nullptr || switchboardPinWormholeFlowMaps(egress, device.ifidx) == false) return false;

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
  suite.expect(boundary && std::strcmp(boundary, "apple-container") == 0 &&
               ::stat("/proc/self/ns/net", &ownNet) == 0 && ::stat("/proc/1/ns/net", &initNet) == 0 &&
               ::stat("/proc/self/ns/mnt", &ownMount) == 0 && ::stat("/proc/1/ns/mnt", &initMount) == 0 &&
               ownNet.st_ino != initNet.st_ino && ownMount.st_ino != initMount.st_ino,
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
  suite.expect(attachHostRouters(pair.host, ingressObjectPath, egressObjectPath), "host_tcx_retention_attaches_real_host_pair");
  if (suite.failed != 0) return 1;

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
  suite.expect(switchboardHostTCXVerifyRetainedPair(pair.host, "/sys/fs/bpf"_ctv, retained),
               "host_tcx_retention_verifies_exact_live_pair");

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
  suite.expect(switchboardHostTCXReleaseExact("/sys/fs/bpf"_ctv, retained.egress),
               "host_tcx_retention_releases_exact_egress_pin");
  present = true;
  suite.expect(switchboardHostTCXReadRetainedPair(pair.host, "/sys/fs/bpf"_ctv, retained, present) && present == false,
               "host_tcx_retention_release_restores_cold_state");
  pair.host.detachBPF(BPF_TCX_INGRESS);
  pair.host.detachBPF(BPF_TCX_EGRESS);
  suite.expect(BPFProgram::openTCXIdentity(pair.host.ifidx, BPF_TCX_INGRESS, retained.ingress.programID, borrowed) == false,
               "host_tcx_retention_explicit_detach_removes_live_ingress_link");

  return suite.failed == 0 ? 0 : 1;
}
