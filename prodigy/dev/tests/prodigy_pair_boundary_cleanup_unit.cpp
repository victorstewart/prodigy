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

int main()
{
  TestSuite suite;
  testPairOwnedLinkCleanupRace(suite);
  return suite.failed ? 1 : 0;
}
