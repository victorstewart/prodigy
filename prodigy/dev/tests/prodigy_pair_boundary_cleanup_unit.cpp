#include <prodigy/mothership/mothership.virtual.datacenter.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <sys/wait.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

class TestSuite {
public:
  int failed = 0;
  void expect(bool condition, const char *name)
  {
    if (!condition)
    {
      std::fprintf(stderr, "FAIL: %s\n", name);
      ++failed;
    }
  }
};

static void testPairOwnedLinkCleanupRace(TestSuite& suite)
{
  std::string sourcePath = __FILE__;
  const size_t root = sourcePath.rfind("/dev/tests/");
  suite.expect(root != std::string::npos, "pair_cleanup_fixture_locates_provider_owner");
  if (root == std::string::npos) return;
  sourcePath.resize(root);
  sourcePath += "/mothership/mothership.virtual.datacenter.provider.sh";
  std::ifstream source(sourcePath);
  if (!source)
  {
    suite.expect(false, "pair_cleanup_fixture_reads_provider_owner");
    return;
  }
  std::string text((std::istreambuf_iterator<char>(source)), std::istreambuf_iterator<char>());
  const size_t begin = text.find("pair_link_identity()\n{\n");
  const size_t end = text.find("\npair_require_no_clients()\n", begin);
  suite.expect(begin != std::string::npos && end != std::string::npos,
               "pair_cleanup_fixture_extracts_owned_link_owner");
  if (begin == std::string::npos || end == std::string::npos) return;

  // Execute the real identity/remove helper with only a mocked `ip` command.
  // The race case models the kernel dropping the source veth peer after the
  // initial probe but before its JSON identity query.  A still-present foreign
  // link must remain an error and must never receive `link del`.
  std::string script = "set -euo pipefail\n" + text.substr(begin, end - begin) + R"TEST(
pair_dir="$PWD/pair"
mkdir -p "$pair_dir"
printf '[1,2,"02:aa:bb:cc:dd:ee"]\n' > "$pair_dir/source-link"
cat > "$PWD/ip" <<'IP'
#!/usr/bin/env bash
set -euo pipefail
mode="$(<"$PWD/mode")"
args="$*"
if [[ "$args" == *"-j link show pairSource0"* ]]; then
  case "$mode" in
    vanished) echo 'Device "pairSource0" does not exist.' >&2; exit 1 ;;
    replacement) printf '[{"ifindex":9,"link_index":8,"address":"02:ff:ff:ff:ff:ff"}]\n'; exit 0 ;;
    owned|disappear_delete) printf '[{"ifindex":1,"link_index":2,"address":"02:aa:bb:cc:dd:ee"}]\n'; exit 0 ;;
  esac
fi
if [[ "$args" == *"-j link show"* ]]; then
  count=0; [[ ! -r "$PWD/inventory-count" ]] || count="$(<"$PWD/inventory-count")"
  count=$((count + 1)); printf '%s\n' "$count" > "$PWD/inventory-count"
  case "$mode" in
    lookup_error) echo 'RTNETLINK answers: Permission denied' >&2; exit 2 ;;
    malformed) printf '{not json}\n'; exit 0 ;;
    malformed_json) printf '[{}]\n'; exit 0 ;;
    vanished|disappear_delete) [[ "$count" == 1 ]] && printf '[{"ifname":"pairSource0"}]\n' || printf '[]\n'; exit 0 ;;
    replacement|owned) printf '[{"ifname":"pairSource0"}]\n'; exit 0 ;;
  esac
fi
if [[ "$args" == *"link del pairSource0"* ]]; then
  if [[ "$mode" == disappear_delete ]]; then
    echo 'Device "pairSource0" does not exist.' >&2; exit 1
  fi
  printf 'del\n' >> "$PWD/deletions"
  exit 0
fi
exit 1
IP
chmod 0700 "$PWD/ip"
PATH="$PWD:$PATH"
run_case() {
  local case_name="$1"
  rm -f inventory-count deletions
  printf '%s\n' "$case_name" > mode
  pair_remove_owned_link source pairSource0
}
run_case vanished
[[ ! -e deletions ]]
run_case disappear_delete
[[ ! -e deletions ]]
if run_case replacement; then exit 1; fi
[[ ! -e deletions ]]
if run_case lookup_error; then exit 1; fi
[[ ! -e deletions ]]
if run_case malformed; then exit 1; fi
[[ ! -e deletions ]]
if run_case malformed_json; then exit 1; fi
[[ ! -e deletions ]]
run_case owned
[[ "$(<deletions)" == del ]]
)TEST";
  char temporary[] = "./pair-boundary-cleanup-unit.XXXXXX";
  if (::mkdtemp(temporary) == nullptr)
  {
    suite.expect(false, "pair_cleanup_fixture_creates_owned_directory");
    return;
  }
  String path = {};
  mothershipVirtualDatacenterPath(String(temporary), "probe.sh", path);
  String failure = {};
  const bool written = mothershipVirtualDatacenterWriteFile(path, String(script.c_str()), 0700, &failure);
  const pid_t child = written ? ::fork() : -1;
  if (child == 0)
  {
    if (::chdir(temporary) != 0) _exit(125);
    ::execl("/bin/bash", "bash", "probe.sh", static_cast<char *>(nullptr));
    _exit(127);
  }
  int status = 0;
  pid_t waited = -1;
  if (child > 0) do { waited = ::waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
  suite.expect(written && child > 0 && waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
               "pair_cleanup_accepts_disappeared_owned_peer_and_refuses_surviving_replacement");
  std::error_code error;
  std::filesystem::remove_all(temporary, error);
}

static MothershipVirtualDatacenterPairBoundaryDescriptor testPairDrainBoundary()
{
  MothershipVirtualDatacenterPairBoundaryDescriptor boundary = {};
  boundary.operationID = "0x0abc"_ctv;
  boundary.sourceClusterUUID = "0x0a11"_ctv;
  boundary.targetClusterUUID = "0x0a22"_ctv;
  boundary.sourceWorkspace = "/tmp/source"_ctv;
  boundary.targetWorkspace = "/tmp/target"_ctv;
  boundary.sourceRuntimeIdentity = "1001"_ctv;
  boundary.targetRuntimeIdentity = "1002"_ctv;
  boundary.sourceParentNamespace = "pvd-p-1001"_ctv;
  boundary.targetParentNamespace = "pvd-p-1002"_ctv;
  boundary.sourceMachineIndex = 1; boundary.targetMachineIndex = 2;
  boundary.sourceMachinePrivate4 = "10.0.0.10"_ctv;
  boundary.targetMachinePrivate4 = "10.0.1.11"_ctv;
  boundary.endpointIPv4 = "198.18.0.1"_ctv; boundary.endpointPort = 19090;
  return boundary;
}

static void testPairDrainObservationParser(TestSuite& suite)
{
  const auto boundary = testPairDrainBoundary();
  const std::string valid =
      "PAIR_BOUNDARY operationID=0x0abc sourceClusterUUID=0x0a11 targetClusterUUID=0x0a22 "
      "sourceRuntimeIdentity=1001 targetRuntimeIdentity=1002 sourceMachineIndex=1 targetMachineIndex=2 "
      "selected=2 drainCapability=1 sourceFlows=0 targetFlows=17\n";
  MothershipVirtualDatacenterPairDrainObservation observation = {};
  String failure = {};
  suite.expect(mothershipVirtualDatacenterParsePairDrainObservation(String(valid.c_str()), boundary, observation, &failure) &&
               mothershipVirtualDatacenterPairDrainObservationBoundValid(boundary, observation, &failure) &&
               observation.selectedTarget && observation.drainCapability && observation.sourceFlows == 0 && observation.targetFlows == 17,
               "pair_drain_parser_accepts_bound_zero_source_observation");
  String encoded = {}; auto serialized = observation;
  BitseryEngine::serialize(encoded, serialized);
  MothershipVirtualDatacenterPairDrainObservation decoded = {};
  suite.expect(BitseryEngine::deserializeSafe(encoded, decoded) &&
               mothershipVirtualDatacenterPairDrainObservationBoundValid(boundary, decoded, &failure) && decoded.targetFlows == 17,
               "pair_drain_observation_serializes_for_durable_receipt");
  auto reject = [&](const std::string& candidate, const char *name) {
    MothershipVirtualDatacenterPairDrainObservation rejected = {};
    suite.expect(!mothershipVirtualDatacenterParsePairDrainObservation(String(candidate.c_str()), boundary, rejected, &failure) &&
                 rejected.operationID.empty(), name);
  };
  reject(valid.substr(0, valid.find(" targetFlows=")) + "\n", "pair_drain_parser_rejects_missing_field");
  reject(valid + "sourceFlows=0\n", "pair_drain_parser_rejects_duplicate_or_trailing_field");
  reject(valid.substr(0, valid.size() - 1) + "\r", "pair_drain_parser_rejects_cr_without_lf");
  reject(valid + "junk", "pair_drain_parser_rejects_data_after_newline");
  std::string wrongOperation = valid; wrongOperation.replace(wrongOperation.find("0x0abc"), 6, "0x0abd");
  reject(wrongOperation, "pair_drain_parser_rejects_wrong_operation");
  std::string wrongRuntime = valid; wrongRuntime.replace(wrongRuntime.find("targetRuntimeIdentity=1002"), 26, "targetRuntimeIdentity=1003");
  reject(wrongRuntime, "pair_drain_parser_rejects_wrong_runtime");
  std::string overflow = valid; overflow.replace(overflow.find("targetFlows=17"), 14, "targetFlows=18446744073709551616");
  reject(overflow, "pair_drain_parser_rejects_overflow_counter");
  std::string notDrained = valid; notDrained.replace(notDrained.find("sourceFlows=0"), 13, "sourceFlows=1");
  MothershipVirtualDatacenterPairDrainObservation nonzero = {};
  suite.expect(mothershipVirtualDatacenterParsePairDrainObservation(String(notDrained.c_str()), boundary, nonzero, &failure) &&
               nonzero.sourceFlows != 0,
               "pair_drain_parser_reports_nonzero_source_for_caller_to_reject");
}

static void testPairGuestResetFenceParser(TestSuite& suite)
{
  const auto boundary = testPairDrainBoundary();
  String descriptor = {};
  suite.expect(mothershipVirtualDatacenterPairDescriptorSHA256(boundary, descriptor) && descriptor.size() == 64,
               "pair_guest_reset_descriptor_digest_is_available");
  const std::string oldBoot = "01234567-89ab-cdef-0123-456789abcdef";
  const std::string newBoot = "fedcba98-7654-3210-fedc-ba9876543210";
  const String oldBootValue(oldBoot.c_str());
  const String newBootValue(newBoot.c_str());
  const std::string arm = "PAIR_GUEST_RESET operationID=0x0abc descriptorSHA256=" + std::string(descriptor.c_str()) +
      " bootID=" + oldBoot + " guestID=pvd-guest_1\n";
  const std::string completion = "PAIR_GUEST_RESET_COMPLETE operationID=0x0abc descriptorSHA256=" + std::string(descriptor.c_str()) +
      " bootID=" + oldBoot + " guestID=pvd-guest_1 completedBootID=" + newBoot + "\n";
  MothershipVirtualDatacenterPairGuestResetFence fence = {};
  String completed = {};
  suite.expect(mothershipVirtualDatacenterParsePairGuestResetObservation(String(arm.c_str()), boundary, fence) &&
               mothershipVirtualDatacenterPairGuestResetFenceValid(fence, boundary) && fence.bootID.equals(oldBootValue) &&
               fence.guestID.equals("pvd-guest_1"_ctv),
               "pair_guest_reset_arm_parser_accepts_exact_bound_fence");
  suite.expect(mothershipVirtualDatacenterParsePairGuestResetObservation(String(completion.c_str()), boundary, fence, &completed) &&
               completed.equals(newBootValue) && completed != fence.bootID,
               "pair_guest_reset_completion_parser_requires_changed_kernel_boot");

  auto rejectArm = [&](const std::string& candidate, const char *name) {
    MothershipVirtualDatacenterPairGuestResetFence rejected = {};
    suite.expect(!mothershipVirtualDatacenterParsePairGuestResetObservation(String(candidate.c_str()), boundary, rejected) &&
                 rejected.operationID.empty(), name);
  };
  auto rejectCompletion = [&](const std::string& candidate, const char *name) {
    MothershipVirtualDatacenterPairGuestResetFence rejected = {};
    String rejectedBoot = {};
    suite.expect(!mothershipVirtualDatacenterParsePairGuestResetObservation(
                     String(candidate.c_str()), boundary, rejected, &rejectedBoot) && rejected.operationID.empty(), name);
  };
  std::string wrongOperation = arm; wrongOperation.replace(wrongOperation.find("operationID=0x0abc"), 18, "operationID=0x0abd");
  rejectArm(wrongOperation, "pair_guest_reset_parser_rejects_operation_nonce_substitution");
  std::string wrongDescriptor = arm; wrongDescriptor.replace(wrongDescriptor.find(std::string(descriptor.c_str())), descriptor.size(), 64, '0');
  rejectArm(wrongDescriptor, "pair_guest_reset_parser_rejects_descriptor_nonce_substitution");
  std::string zeroBoot = arm; zeroBoot.replace(zeroBoot.find(oldBoot), oldBoot.size(), "00000000-0000-0000-0000-000000000000");
  rejectArm(zeroBoot, "pair_guest_reset_parser_rejects_zero_boot");
  rejectArm("PAIR_GUEST_RESET operationID=0x0abc descriptorSHA256=" + std::string(descriptor.c_str()) +
            " bootID=" + oldBoot + "\n", "pair_guest_reset_parser_rejects_missing_guest");
  rejectArm(arm + "trailing", "pair_guest_reset_parser_rejects_trailing_bytes");
  rejectArm(arm.substr(0, arm.size() - 1) + "\r", "pair_guest_reset_parser_rejects_cr_without_lf");
  std::string sameBoot = completion; sameBoot.replace(sameBoot.find(newBoot), newBoot.size(), oldBoot);
  rejectCompletion(sameBoot, "pair_guest_reset_completion_parser_rejects_equal_boot");
  auto conflictingBoundary = boundary;
  conflictingBoundary.targetMachineIndex += 1;
  MothershipVirtualDatacenterPairGuestResetFence conflictingFence = {};
  suite.expect(!mothershipVirtualDatacenterParsePairGuestResetObservation(
                   String(arm.c_str()), conflictingBoundary, conflictingFence) && conflictingFence.operationID.empty(),
               "pair_guest_reset_parser_rejects_conflicting_descriptor_binding");
}

static void testPairGuestResetAbsenceProofFailsClosed(TestSuite& suite)
{
  std::string sourcePath = __FILE__;
  const size_t root = sourcePath.rfind("/dev/tests/");
  suite.expect(root != std::string::npos, "pair_guest_reset_fixture_locates_provider_owner");
  if (root == std::string::npos) return;
  sourcePath.resize(root);
  sourcePath += "/mothership/mothership.virtual.datacenter.provider.sh";
  std::ifstream source(sourcePath);
  if (!source)
  {
    suite.expect(false, "pair_guest_reset_fixture_reads_provider_owner");
    return;
  }
  std::string text((std::istreambuf_iterator<char>(source)), std::istreambuf_iterator<char>());
  const size_t begin = text.find("pair_guest_reset_absence_proven()\n{\n");
  const size_t end = text.find("\nworkspace_guest_reset_stop_safe()\n", begin);
  suite.expect(begin != std::string::npos && end != std::string::npos,
               "pair_guest_reset_fixture_extracts_absence_proof");
  if (begin == std::string::npos || end == std::string::npos) return;

  // Exercise the provider's real absence proof with only the kernel identity
  // and filesystem primitives mocked.  Any namespace, link, or cgroup command
  // is a test failure: a changed boot proves old guest resources are absent;
  // it never authorizes cleanup against the replacement guest.
  std::string script = "set -euo pipefail\n" + text.substr(begin, end - begin) + R"TEST(
pair_dir="$PWD/pair"
pair_source_workspace="$PWD/source"
pair_target_workspace="$PWD/target"
pair_id=0x0abc
fixture_old_boot=01234567-89ab-cdef-0123-456789abcdef
fixture_new_boot=fedcba98-7654-3210-fedc-ba9876543210
fixture_guest=pvd-guest_1
mkdir -p "$pair_dir" "$pair_source_workspace" "$pair_target_workspace" "$PWD/mockbin"
printf 'reset-required\n' > "$pair_dir/phase"
printf 'bootID=%s\nguestID=%s\n' "$fixture_old_boot" "$fixture_guest" > "$pair_dir/guest-reset.fence"
for command in ip nsenter unshare mount umount cgdelete; do
  cat > "$PWD/mockbin/$command" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$0 $*" >> "$PWD/forbidden"
exit 88
MOCK
  chmod 0700 "$PWD/mockbin/$command"
done
PATH="$PWD/mockbin:$PATH"
pair_owner_dead() { [[ "$mode" != live ]]; }
pair_guest_reset_identity() { printf '%s\t%s\n' "$fixture_current_boot" "$fixture_guest"; }
pair_fence_exact() { [[ "$mode" != partial && "$mode" != mismatch && "$1" == "$fixture_old_boot" && "$2" == "$fixture_guest" ]]; }
pair_workspace_provider_dead() { [[ "$mode" != mismatch ]]; }
pair_regular_root_receipt() { [[ -f "$1" && ! -L "$1" ]]; }
pair_fence_text() { printf 'bootID=%s\nguestID=%s\n' "$1" "$2"; }
pair_descriptor_sha256() { printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n'; }
pair_receipt_exact() { [[ -f "$1" && ! -L "$1" && "$(<"$1")" == "$2" ]]; }
pair_write() { printf '%s\n' "$2" > "$1"; printf 'write\n' >> "$PWD/writes"; }
run_case() {
  mode="$1"
  fixture_current_boot="$2"
  rm -f forbidden writes "$pair_dir/guest-reset-absence"
  pair_guest_reset_absence_proven
}
if run_case sameboot "$fixture_old_boot"; then exit 1; fi
[[ ! -e "$pair_dir/guest-reset-absence" && ! -e writes ]]
if run_case live "$fixture_new_boot"; then exit 1; fi
[[ ! -e "$pair_dir/guest-reset-absence" && ! -e writes ]]
if run_case partial "$fixture_new_boot"; then exit 1; fi
[[ ! -e "$pair_dir/guest-reset-absence" && ! -e writes ]]
if run_case mismatch "$fixture_new_boot"; then exit 1; fi
[[ ! -e "$pair_dir/guest-reset-absence" && ! -e writes ]]
run_case changed "$fixture_new_boot"
grep -qx write writes
[[ "$(<"$pair_dir/guest-reset-absence")" == *"bootID=$fixture_old_boot"* && "$(<"$pair_dir/guest-reset-absence")" == *"currentBootID=$fixture_new_boot"* ]]
[[ ! -e forbidden ]]
)TEST";
  char temporary[] = "./pair-guest-reset-unit.XXXXXX";
  if (::mkdtemp(temporary) == nullptr)
  {
    suite.expect(false, "pair_guest_reset_fixture_creates_owned_directory");
    return;
  }
  String path = {};
  mothershipVirtualDatacenterPath(String(temporary), "probe.sh", path);
  String failure = {};
  const bool written = mothershipVirtualDatacenterWriteFile(path, String(script.c_str()), 0700, &failure);
  const pid_t child = written ? ::fork() : -1;
  if (child == 0)
  {
    if (::chdir(temporary) != 0) _exit(125);
    ::execl("/bin/bash", "bash", "probe.sh", static_cast<char *>(nullptr));
    _exit(127);
  }
  int status = 0;
  pid_t waited = -1;
  if (child > 0) do { waited = ::waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
  suite.expect(written && child > 0 && waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
               "pair_guest_reset_absence_proof_rejects_same_boot_live_partial_and_mismatch_without_kernel_cleanup");
  std::error_code error;
  std::filesystem::remove_all(temporary, error);
}

static void testPairGuestResetCompletionAndWorkspaceCleanupGuards(TestSuite& suite)
{
  std::string sourcePath = __FILE__;
  const size_t root = sourcePath.rfind("/dev/tests/");
  if (root == std::string::npos) { suite.expect(false, "pair_guest_reset_guards_locate_provider"); return; }
  sourcePath.resize(root); sourcePath += "/mothership/mothership.virtual.datacenter.provider.sh";
  std::ifstream source(sourcePath);
  if (!source) { suite.expect(false, "pair_guest_reset_guards_read_provider"); return; }
  std::string text((std::istreambuf_iterator<char>(source)), std::istreambuf_iterator<char>());
  const auto extract = [&](const char *first, const char *after) {
    const size_t begin = text.find(first), end = text.find(after, begin);
    return begin == std::string::npos || end == std::string::npos ? std::string{} : text.substr(begin, end - begin);
  };
  const std::string completion = extract("pair_guest_reset_completion_line()\n{\n", "\nworkspace_has_mountpoint_beneath()\n");
  const std::string cleanup = extract("workspace_has_mountpoint_beneath()\n{\n", "\nworkspace_guest_reset_stop_safe()\n");
  suite.expect(!completion.empty() && !cleanup.empty(), "pair_guest_reset_guards_extract_provider_helpers");
  if (completion.empty() || cleanup.empty()) return;
  const std::string script = "set -euo pipefail\n" + completion + cleanup + R"TEST(
pair_dir="$PWD/pair"
mkdir -p "$pair_dir" "$PWD/mockbin" "$PWD/workspace"
fixture_armed=01234567-89ab-cdef-0123-456789abcdef
fixture_completed=fedcba98-7654-3210-fedc-ba9876543210
fixture_later=11111111-2222-3333-4444-555555555555
fixture_guest=pvd-guest_1
printf 'removed\n' > "$pair_dir/phase"
printf 'bootID=%s\nguestID=%s\n' "$fixture_armed" "$fixture_guest" > "$pair_dir/guest-reset.fence"
printf 'FENCE\ncurrentBootID=%s\n' "$fixture_completed" > "$pair_dir/guest-reset-absence"
pair_id=0x0abc
pair_guest_reset_identity() { printf '%s\t%s\n' "$fixture_later" "$fixture_guest"; }
pair_fence_text() { printf FENCE; }
pair_descriptor_sha256() { printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n'; }
pair_fence_exact() { return 0; }
pair_fence_removed_exact() { return 0; }
pair_regular_root_receipt() { [[ -f "$1" && ! -L "$1" ]]; }
pair_receipt_exact() { return 0; }
line="$(pair_guest_reset_completion_line)"
[[ "$line" == *"bootID=$fixture_armed"* && "$line" == *"completedBootID=$fixture_completed"* && "$line" != *"completedBootID=$fixture_later"* ]]
workspace_guest_reset_stop_safe() { return 0; }
cat > "$PWD/mockbin/findmnt" <<'MOCK'
#!/usr/bin/env bash
exit 1
MOCK
cat > "$PWD/mockbin/rm" <<'MOCK'
#!/usr/bin/env bash
printf 'rm\n' >> "$PWD/forbidden"
exit 99
MOCK
chmod 0700 "$PWD/mockbin/findmnt" "$PWD/mockbin/rm"
PATH="$PWD/mockbin:$PATH"
if workspace_reset_only_cleanup "$PWD/workspace" "$PWD/no-parent/socket"; then exit 1; fi
[[ ! -e forbidden && -d "$PWD/workspace" ]]
)TEST";
  char temporary[] = "./pair-guest-reset-guards.XXXXXX";
  if (::mkdtemp(temporary) == nullptr) { suite.expect(false, "pair_guest_reset_guards_create_directory"); return; }
  String path = {}, failure = {};
  mothershipVirtualDatacenterPath(String(temporary), "probe.sh", path);
  const bool written = mothershipVirtualDatacenterWriteFile(path, String(script.c_str()), 0700, &failure);
  const pid_t child = written ? ::fork() : -1;
  if (child == 0) { if (::chdir(temporary) != 0) _exit(125); ::execl("/bin/bash", "bash", "probe.sh", static_cast<char *>(nullptr)); _exit(127); }
  int status = 0; pid_t waited = -1;
  if (child > 0) do { waited = ::waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
  suite.expect(written && child > 0 && waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
               "pair_guest_reset_replays_retained_completion_and_rejects_findmnt_failure_before_cleanup");
  std::error_code error;
  std::filesystem::remove_all(temporary, error);
}


static void testPairGuestResetMarkerAndWorkspaceFenceSubstitution(TestSuite& suite)
{
  std::string sourcePath = __FILE__;
  const size_t root = sourcePath.rfind("/dev/tests/");
  if (root == std::string::npos) { suite.expect(false, "pair_guest_reset_substitution_locates_provider"); return; }
  sourcePath.resize(root); sourcePath += "/mothership/mothership.virtual.datacenter.provider.sh";
  std::ifstream source(sourcePath);
  if (!source) { suite.expect(false, "pair_guest_reset_substitution_reads_provider"); return; }
  std::string text((std::istreambuf_iterator<char>(source)), std::istreambuf_iterator<char>());
  const auto extract = [&](const char *first, const char *after) {
    const size_t begin = text.find(first), end = text.find(after, begin);
    return begin == std::string::npos || end == std::string::npos ? std::string{} : text.substr(begin, end - begin);
  };
  const std::string identityValid = extract("pair_guest_reset_identity_valid()\n{\n", "\npair_guest_reset_identity()\n");
  const std::string marker = extract("pair_workspace_reset_flagged()\n{\n", "\npair_arm_guest_reset()\n");
  std::string stop = extract("workspace_guest_reset_stop_safe()\n{\n", "\npair_owner_live()\n");
  const std::string productionPairPath = "pair_path=\"/mnt/prodigy-vdc-pairs/${operation}\"";
  const std::string fixturePairPath = "pair_path=\"$PWD/pairs/${operation}\"";
  const size_t pairPath = stop.find(productionPairPath);
  if (pairPath != std::string::npos) stop.replace(pairPath, productionPairPath.size(), fixturePairPath);
  suite.expect(!identityValid.empty() && !marker.empty() && !stop.empty() && pairPath != std::string::npos,
               "pair_guest_reset_substitution_extracts_marker_and_stop_guards");
  if (identityValid.empty() || marker.empty() || stop.empty() || pairPath == std::string::npos) return;
  const std::string script = "set -euo pipefail\n" + identityValid + marker + stop + R"TEST(
pair_guest_reset_identity_valid 01234567-89ab-cdef-0123-456789abcdef pvd-guest_1
if pair_guest_reset_identity_valid 01234567-89ab-cdef-0123-456789abcdeg pvd-guest_1; then exit 1; fi
if pair_guest_reset_identity_valid 00000000-0000-0000-0000-000000000000 pvd-guest_1; then exit 1; fi
workspace="$PWD/workspace"
fixture_peer="$PWD/peer"
pair_dir="$PWD/pairs/0x0abc"
mkdir -p "$workspace" "$fixture_peer" "$pair_dir"
pair_workspace_fence_path() { printf '%s/virtual-datacenter.pair-guest-reset\n' "$1"; }
pair_regular_root_receipt() { [[ -f "$1" && ! -L "$1" ]]; }
printf malformed > "$(pair_workspace_fence_path "$workspace")"
pair_workspace_reset_flagged "$workspace"
rm -f "$(pair_workspace_fence_path "$workspace")"
printf target > "$PWD/marker-target"
ln -s "$PWD/marker-target" "$(pair_workspace_fence_path "$workspace")"
pair_workspace_reset_flagged "$workspace"
rm -f "$(pair_workspace_fence_path "$workspace")"
fixture_armed=01234567-89ab-cdef-0123-456789abcdef
fixture_completed=fedcba98-7654-3210-fedc-ba9876543210
fixture_guest=pvd-guest_1
printf 'operationID=0x0abc\nbootID=%s\nguestID=%s\nsubstituted=1\n' "$fixture_armed" "$fixture_guest" > "$(pair_workspace_fence_path "$workspace")"
printf 'removed\n' > "$pair_dir/phase"
for n in $(seq 1 14); do printf 'descriptor-%s\n' "$n"; done > "$pair_dir/descriptor"
printf 'FENCE\ncurrentBootID=%s\n' "$fixture_completed" > "$pair_dir/guest-reset-absence"
pair_guest_reset_identity() { printf '%s\t%s\n' "$fixture_completed" "$fixture_guest"; }
pair_fence_exact() { return 0; }
pair_fence_removed_exact() { return 0; }
pair_parse() { pair_source_workspace="$workspace"; pair_target_workspace="$fixture_peer"; return 0; }
pair_descriptor() { cat "$pair_dir/descriptor"; }
pair_fence_text() { printf FENCE; }
pair_receipt_exact() { [[ "$1" != "$(pair_workspace_fence_path "$workspace")" ]]; }
if workspace_guest_reset_stop_safe "$workspace"; then exit 1; fi
)TEST";
  char temporary[] = "./pair-guest-reset-substitution.XXXXXX";
  if (::mkdtemp(temporary) == nullptr) { suite.expect(false, "pair_guest_reset_substitution_creates_directory"); return; }
  String path = {}, failure = {};
  mothershipVirtualDatacenterPath(String(temporary), "probe.sh", path);
  const bool written = mothershipVirtualDatacenterWriteFile(path, String(script.c_str()), 0700, &failure);
  const pid_t child = written ? ::fork() : -1;
  if (child == 0) { if (::chdir(temporary) != 0) _exit(125); ::execl("/bin/bash", "bash", "probe.sh", static_cast<char *>(nullptr)); _exit(127); }
  int status = 0; pid_t waited = -1;
  if (child > 0) do { waited = ::waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
  suite.expect(written && child > 0 && waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
               "pair_guest_reset_blocks_suspect_markers_and_workspace_fence_substitution");
  std::error_code error;
  std::filesystem::remove_all(temporary, error);
}


static void testPairResetTombstoneCleanup(TestSuite& suite)
{
  std::string sourcePath = __FILE__;
  const size_t root = sourcePath.rfind("/dev/tests/");
  if (root == std::string::npos) { suite.expect(false, "pair_tombstone_locates_provider"); return; }
  sourcePath.resize(root); sourcePath += "/mothership/mothership.virtual.datacenter.provider.sh";
  std::ifstream source(sourcePath);
  if (!source) { suite.expect(false, "pair_tombstone_reads_provider"); return; }
  std::string text((std::istreambuf_iterator<char>(source)), std::istreambuf_iterator<char>());
  const size_t begin = text.find("workspace_reset_tombstone_cleanup()\n{\n");
  const size_t end = text.find("\nworkspace_reset_only_cleanup()\n", begin);
  suite.expect(begin != std::string::npos && end != std::string::npos, "pair_tombstone_extracts_helper");
  if (begin == std::string::npos || end == std::string::npos) return;
  const std::string script = "set -euo pipefail\n" + text.substr(begin, end - begin) + R"TEST(
pair_regular_root_receipt() { [[ -f "$1" && ! -L "$1" ]]; }
make_case() {
  fixture_case="$1"; fixture_workspace="$PWD/$fixture_case/workspace"; fixture_parent="$fixture_workspace/control"; fixture_socket="$fixture_parent/mothership.sock"
  mkdir -p "$fixture_parent"; chmod 0700 "$fixture_parent"
  python3 - "$fixture_workspace/test-cluster-manifest.json" "$fixture_workspace" "$fixture_socket" <<'PYMANIFEST'
import json,sys
open(sys.argv[1],'w').write(json.dumps({'workspaceRoot':sys.argv[2],'controlSocketPath':sys.argv[3]}))
PYMANIFEST
}
make_socket() { python3 - "$fixture_socket" <<'PYSOCKET'
import socket,sys
s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); s.close()
PYSOCKET
}
make_case stale; make_socket; workspace_reset_tombstone_cleanup "$fixture_workspace" "$fixture_socket"; [[ ! -e "$fixture_parent" ]]
make_case absent; rmdir "$fixture_parent"; workspace_reset_tombstone_cleanup "$fixture_workspace" "$fixture_socket"
make_case symlink; rmdir "$fixture_parent"; mkdir "$PWD/symlink-target"; ln -s "$PWD/symlink-target" "$fixture_parent"; if workspace_reset_tombstone_cleanup "$fixture_workspace" "$fixture_socket"; then exit 1; fi
make_case unexpected; touch "$fixture_parent/unexpected"; if workspace_reset_tombstone_cleanup "$fixture_workspace" "$fixture_socket"; then exit 1; fi
make_case mismatch; printf '{}' > "$fixture_workspace/test-cluster-manifest.json"; if workspace_reset_tombstone_cleanup "$fixture_workspace" "$fixture_socket"; then exit 1; fi
make_case foreign; chown 65534 "$fixture_parent"; [[ "$(stat -c %u "$fixture_parent")" == 65534 ]]; if workspace_reset_tombstone_cleanup "$fixture_workspace" "$fixture_socket"; then exit 1; fi
make_case live
python3 - "$fixture_socket" <<'PYLIVE' &
import socket,sys,time
s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); time.sleep(20)
PYLIVE
fixture_pid=$!; sleep 1
if workspace_reset_tombstone_cleanup "$fixture_workspace" "$fixture_socket"; then kill "$fixture_pid"; exit 1; fi
kill "$fixture_pid"; wait "$fixture_pid" || true
)TEST";
  char temporary[] = "/tmp/pgt.XXXXXX";
  if (::mkdtemp(temporary) == nullptr) { suite.expect(false, "pair_tombstone_creates_directory"); return; }
  String path = {}, failure = {};
  mothershipVirtualDatacenterPath(String(temporary), "probe.sh", path);
  const bool written = mothershipVirtualDatacenterWriteFile(path, String(script.c_str()), 0700, &failure);
  const pid_t child = written ? ::fork() : -1;
  if (child == 0) { if (::chdir(temporary) != 0) _exit(125); ::execl("/bin/bash", "bash", "probe.sh", static_cast<char *>(nullptr)); _exit(127); }
  int status = 0; pid_t waited = -1;
  if (child > 0) do { waited = ::waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
  suite.expect(written && child > 0 && waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
               "pair_tombstone_removes_stale_socket_and_rejects_live_or_ambiguous_state");
  std::error_code error;
  std::filesystem::remove_all(temporary, error);
}

int main()
{
  TestSuite suite;
  testPairOwnedLinkCleanupRace(suite);
  testPairDrainObservationParser(suite);
  testPairGuestResetFenceParser(suite);
  testPairGuestResetAbsenceProofFailsClosed(suite);
  testPairGuestResetCompletionAndWorkspaceCleanupGuards(suite);
  testPairGuestResetMarkerAndWorkspaceFenceSubstitution(suite);
  testPairResetTombstoneCleanup(suite);
  return suite.failed ? 1 : 0;
}
