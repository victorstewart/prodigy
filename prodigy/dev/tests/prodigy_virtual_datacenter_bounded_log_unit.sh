#!/usr/bin/env bash
set -euo pipefail

provider="$1"
tmpdir="$(mktemp -d)"
cleanup()
{
   rm -rf -- "${tmpdir}"
}
trap cleanup EXIT

log_path="${tmpdir}/machine1.log"
python3 - <<'PY' | bash "${provider}" --bounded-log "${log_path}" 2 16 8
import sys
sys.stdout.buffer.write(bytes(range(80)))
PY

[[ "$(stat -c %s "${log_path}.first")" -eq 8 ]]
[[ "$(stat -c %s "${log_path}")" -eq 16 ]]
[[ "$(stat -c %s "${log_path}.1")" -eq 16 ]]
[[ "$(stat -c %s "${log_path}.2")" -eq 16 ]]
[[ ! -e "${log_path}.3" ]]

python3 - "${log_path}" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
assert Path(f"{path}.first").read_bytes() == bytes(range(8))
assert Path(f"{path}.2").read_bytes() == bytes(range(32, 48))
assert Path(f"{path}.1").read_bytes() == bytes(range(48, 64))
assert path.read_bytes() == bytes(range(64, 80))
PY

printf 'virtual datacenter bounded log unit passed\n'
