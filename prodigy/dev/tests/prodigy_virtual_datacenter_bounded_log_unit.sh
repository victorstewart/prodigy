#!/usr/bin/env bash
set -euo pipefail

provider="$1"
tmpdir="$(mktemp -d)"
cleanup()
{
   rm -rf -- "${tmpdir}"
}
trap cleanup EXIT

live_log_path="${tmpdir}/live-machine.log"
python3 - "${provider}" "${live_log_path}" <<'PY'
from pathlib import Path
import subprocess
import sys
import time

provider, log_path = sys.argv[1:]
prefix = b"live-log"
process = subprocess.Popen(
    ["bash", provider, "--bounded-log", log_path, "2", "16", "8"],
    stdin=subprocess.PIPE,
)
assert process.stdin is not None
try:
    process.stdin.write(prefix)
    process.stdin.flush()
    first = Path(log_path + ".first")
    current = Path(log_path)
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if first.exists() and current.exists() and first.read_bytes() == prefix and current.read_bytes() == prefix:
            break
        time.sleep(0.01)
    else:
        raise AssertionError("bounded logger did not persist a live short prefix before EOF")
finally:
    process.stdin.close()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)
        raise
assert process.returncode == 0
PY

log_path="${tmpdir}/machine1.log"
python3 - <<'PY' | bash "${provider}" --bounded-log "${log_path}" 2 16 8
import sys
sys.stdout.buffer.write(bytes(range(80)))
PY

python3 - "${log_path}" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
assert Path(f"{path}.first").stat().st_size == 8
assert path.stat().st_size == 16
assert Path(f"{path}.1").stat().st_size == 16
assert Path(f"{path}.2").stat().st_size == 16
assert not Path(f"{path}.3").exists()
assert Path(f"{path}.first").read_bytes() == bytes(range(8))
assert Path(f"{path}.2").read_bytes() == bytes(range(32, 48))
assert Path(f"{path}.1").read_bytes() == bytes(range(48, 64))
assert path.read_bytes() == bytes(range(64, 80))
PY

printf 'virtual datacenter bounded log unit passed\n'
