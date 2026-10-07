#!/usr/bin/env python3
"""Run the lifecycle qualification's embedded evidence validators against fixtures."""
import json
import contextlib
import io
import pathlib
import re
import sys
import subprocess
import tempfile
import time
from unittest.mock import patch


shell = pathlib.Path(__file__).with_name('prodigy_dev_cousin_lifecycle_qualification.sh')
source = shell.read_text()


def block(name):
    found = re.search(r"<<'" + name + r"'(?: \|\| return)?\n(.*?)\n" + name, source, re.S)
    assert found, name
    return compile(found.group(1), f'{shell}:{name}', 'exec')


lifecycle = block('PY_LIFECYCLE')
peer = block('PY_PEER')
restart = block('PY_RESTART')
restart_report = block('PY_RESTART_REPORT')
health = block('PY_HEALTH')


def run(code, argv, now=None):
    with patch.object(sys, 'argv', argv):
        with contextlib.redirect_stdout(io.StringIO()):
            if now is None:
                exec(code, {'__name__': '__main__'})
            else:
                with patch.object(time, 'CLOCK_BOOTTIME', 7, create=True), \
                     patch.object(time, 'clock_gettime_ns', return_value=now * 1_000_000):
                    exec(code, {'__name__': '__main__'})


def fails(code, argv, now=None):
    try:
        run(code, argv, now)
    except AssertionError:
        return
    raise AssertionError('embedded validator unexpectedly accepted invalid fixture')


def write(root, relative, data):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data)


begin_ms = 1_000_000
end_ms = begin_ms + 60_000


def partition_fixture(root, profile, event_lines):
    write(root, 'cousin-lifecycle-partition.log',
          f'PAIR_CONTROL_FAULT operationID=abc123 clock=CLOCK_BOOTTIME delayMs=15000 durationMs=60000 '
          f'beginNs={begin_ms * 1_000_000} endNs={end_ms * 1_000_000}\n')
    write(root, 'cousin-native-logs/second-0-target.log',
          f'cousin_session_probe.scaleMetric monotonicMs={begin_ms + 1000}\n' + event_lines)


def horizontal_events(offset=2000):
    return ''.join(
        f'cousin_session_probe.ready uuid={uuid} group=1 monotonicMs={begin_ms + offset + index}\n'
        for index, uuid in enumerate(('a', 'b', 'c')))


def vertical_events(offset=2000):
    return ''.join(
        f'cousin_session_probe.resources uuid={uuid} cores=1 memoryMB=384 storageMB=64 downscale=0 accepted=1 '
        f'monotonicMs={begin_ms + offset + index}\n'
        for index, uuid in enumerate(('a', 'b', 'c')))


def session_fixture(root, *, old_pid=101, close_ms=begin_ms + 12_000,
                    after_session='new', after_request_ms=begin_ms + 20_000):
    peer_hex = '0000000000000000000000000000000a'
    write(root, 'cousin-native-session-after-scale.json', json.dumps({
        'sourceLog': 'first-1-source', 'sessionUUID': 'old',
        'rounds': [{'peer': peer_hex, 'monotonicMs': str(begin_ms + 19_000)}],
    }))
    write(root, 'cousin-native-session-qualified.json', json.dumps({
        'sourceLog': 'first-1-source', 'sessionUUID': after_session,
        'request': {'monotonicMs': str(after_request_ms)}, 'rounds': [{'peer': peer_hex}],
        'renewalObservedMs': 12000, 'renewalGenerations': [2],
    }))
    write(root, 'cousin-native-logs/first-1-source.log',
          f'cousin_session_probe.activate session=old monotonicMs={begin_ms}\n'
          f'cousin_session_probe.round session=old peer={peer_hex} monotonicMs={begin_ms + 19_000}\n'
          f'cousin_session_probe.closed session=old monotonicMs={close_ms}\n')
    write(root, 'cousin-native-logs/second-3-10.log', 'probe\n')
    write(root, 'second-workspace/test-cluster-manifest.json', json.dumps({
        'nodes': [{'index': 3, 'pid': old_pid}],
    }))
    write(root, 'cousin-lifecycle-restarted-report.json', json.dumps({
        'runtimeContainerUUIDs': ['11', '12', '13', '14', '15', '16'],
    }))
    write(root, 'cousin-native-logs/second-3-11.log',
          f'cousin_session_probe.ready uuid=0000000000000000000000000000000b monotonicMs={begin_ms + 11_000}\n')
    write(root, 'cousin-lifecycle-restart-monotonic-ms', f'{begin_ms + 10_000}\n')
    write(root, 'cousin-lifecycle-restarted-monotonic-ms', f'{begin_ms + 10_000}\n')


def restart_report_fixture(root, *, runtime_uuids=('11', '12', '13', '14', '15', '16')):
    rows = ''.join(f'\tcontainerRuntime: cores=1 memMB=256 storMB=128 uuid={uuid}\n' for uuid in runtime_uuids)
    write(root, 'application.log', '\tisStateful: true\tnShardGroups: 2\n\tnHealthy: 6\n\tnDeployed: 6\n' + rows)
    write(root, 'cousin-lifecycle-restart-selected.json', json.dumps({
        'machineIndex': 3, 'machinePID': 101, 'peerContainerUUID': '10',
        'sessionUUID': 'old', 'sessionActivatedMonotonicMs': begin_ms,
        'selectedMonotonicMs': begin_ms + 20_000,
    }))


def selected_fixture(root):
    peer_hex = '0000000000000000000000000000000a'
    write(root, 'cousin-native-session-qualified.json', json.dumps({
        'sourceLog': 'first-1-source', 'sessionUUID': 'old',
        'rounds': [{'peer': peer_hex, 'monotonicMs': str(begin_ms + 19_000)}],
    }))
    write(root, 'cousin-native-logs/first-1-source.log',
          f'cousin_session_probe.activate session=old monotonicMs={begin_ms}\n'
          f'cousin_session_probe.round session=old peer={peer_hex} monotonicMs={begin_ms + 19_000}\n')
    write(root, 'cousin-native-logs/second-3-10.log', 'probe\n')
    write(root, 'second-workspace/test-cluster-manifest.json', json.dumps({
        'nodes': [{'index': 3, 'pid': 101}],
    }))


with tempfile.TemporaryDirectory(prefix='cousin-lifecycle-observe-') as directory:
    root = pathlib.Path(directory)
    partition_fixture(root, 'horizontal', horizontal_events())
    run(lifecycle, ['-', str(root), 'horizontal'])
    receipt = json.loads((root / 'cousin-lifecycle-scaled.json').read_text())
    assert receipt['profile'] == 'horizontal' and receipt['metricSamples'] == 1
    assert {row['uuid'] for row in receipt['scaleEvents']} == {'a', 'b', 'c'}

with tempfile.TemporaryDirectory(prefix='cousin-lifecycle-observe-') as directory:
    root = pathlib.Path(directory)
    partition_fixture(root, 'vertical', vertical_events())
    run(lifecycle, ['-', str(root), 'vertical'])
    assert json.loads((root / 'cousin-lifecycle-scaled.json').read_text())['profile'] == 'vertical'

for profile, events in [
        ('horizontal', f'cousin_session_probe.scaleMetric monotonicMs={begin_ms - 1}\n' + horizontal_events()),
        ('horizontal', horizontal_events(offset=-1000)),
        ('vertical', vertical_events().replace('accepted=1', 'accepted=0')),
        ('horizontal', horizontal_events()[:-len('cousin_session_probe.ready uuid=c group=1 monotonicMs=1002002\n')]),
]:
    with tempfile.TemporaryDirectory(prefix='cousin-lifecycle-observe-') as directory:
        root = pathlib.Path(directory)
        partition_fixture(root, profile, events)
        fails(lifecycle, ['-', str(root), profile])

with tempfile.TemporaryDirectory(prefix='cousin-lifecycle-observe-') as directory:
    root = pathlib.Path(directory)
    partition_fixture(root, 'horizontal', horizontal_events())
    write(root, 'cousin-lifecycle-partition.log',
          f'PAIR_CONTROL_FAULT operationID=abc123 delayMs=15000 durationMs=60000 '
          f'beginNs={begin_ms * 1_000_000} endNs={end_ms * 1_000_000}\n')
    fails(lifecycle, ['-', str(root), 'horizontal'])

with tempfile.TemporaryDirectory(prefix='cousin-lifecycle-observe-') as directory:
    root = pathlib.Path(directory)
    selected_fixture(root)
    run(peer, ['-', str(root)], now=begin_ms + 20_000)
    selected = json.loads((root / 'cousin-lifecycle-restart-selected.json').read_text())
    assert selected['machineIndex'] == 3 and selected['machinePID'] == 101 and selected['peerContainerUUID'] == '10'

with tempfile.TemporaryDirectory(prefix='cousin-lifecycle-observe-') as directory:
    root = pathlib.Path(directory)
    selected_fixture(root)
    stale_peer_hex = '0000000000000000000000000000000a'
    write(root, 'cousin-native-session-qualified.json', json.dumps({
        'sourceLog': 'first-1-source', 'sessionUUID': 'old',
        'rounds': [{'peer': stale_peer_hex, 'monotonicMs': str(begin_ms + 16_999)}],
    }))
    write(root, 'cousin-native-logs/first-1-source.log',
          f'cousin_session_probe.activate session=old monotonicMs={begin_ms}\n'
          f'cousin_session_probe.round session=old peer={stale_peer_hex} monotonicMs={begin_ms + 16_999}\n')
    fails(peer, ['-', str(root)], now=begin_ms + 20_000)

for runtime_uuids in [
        ('11', '12', '13', '14', '15', '16'),
        ('10', '12', '13', '14', '15', '16'),
        ('11', '11', '13', '14', '15', '16'),
]:
    with tempfile.TemporaryDirectory(prefix='cousin-lifecycle-restart-report-') as directory:
        root = pathlib.Path(directory)
        restart_report_fixture(root, runtime_uuids=runtime_uuids)
        if '10' not in runtime_uuids and len(set(runtime_uuids)) == 6:
            run(restart_report, ['-', str(root), str(root/'application.log'), '2', '6'])
            assert json.loads((root/'cousin-lifecycle-restarted-report.json').read_text())['runtimeContainerUUIDs'] == list(runtime_uuids)
        else:
            fails(restart_report, ['-', str(root), str(root/'application.log'), '2', '6'])

for old_pid, close_ms, after_session, request_ms in [
        (202, begin_ms + 12_000, 'new', begin_ms + 20_000),
        (101, begin_ms + 12_000, 'new', begin_ms + 20_000),
        (202, begin_ms + 30_000, 'new', begin_ms + 20_000),
        (202, begin_ms + 12_000, 'old', begin_ms + 20_000),
        (202, begin_ms + 12_000, 'new', begin_ms + 10_000),
]:
    with tempfile.TemporaryDirectory(prefix='cousin-lifecycle-observe-') as directory:
        root = pathlib.Path(directory)
        session_fixture(root, old_pid=old_pid, close_ms=close_ms,
                        after_session=after_session, after_request_ms=request_ms)
        write(root, 'cousin-lifecycle-restart-selected.json', json.dumps({
            'machineIndex': 3, 'machinePID': 101, 'peerContainerUUID': '10',
            'sessionUUID': 'old', 'sessionActivatedMonotonicMs': begin_ms,
            'selectedMonotonicMs': begin_ms + 20_000,
        }))
        if old_pid == 101:
            fails(restart, ['-', str(root)])
        else:
            if close_ms < begin_ms + 30_000 and after_session == 'new' and request_ms > begin_ms + 10_000:
                run(restart, ['-', str(root)])
                write(root, 'cousin-native-logs/second-3-11.log',
                      f'cousin_session_probe.ready uuid=0000000000000000000000000000000b monotonicMs={begin_ms}\n')
                fails(restart, ['-', str(root)])
                (root / 'cousin-native-logs/second-3-11.log').unlink()
                fails(restart, ['-', str(root)])
            else:
                fails(restart, ['-', str(root)])

for profile, groups, containers, memory in [('horizontal', 2, 6, 256), ('vertical', 1, 3, 384)]:
    with tempfile.TemporaryDirectory(prefix='cousin-lifecycle-health-') as directory:
        root = pathlib.Path(directory)
        report = root / 'application.log'
        data = f'\tisStateful: true\tnShardGroups: {groups}\n\tnHealthy: {containers}\n\tnDeployed: {containers}\n\tnCrashes: 0\n'
        data += f'\tcontainerRuntime: cores=1 memMB={memory} storMB=128 uuid=1\n' * containers
        report.write_text(data)
        run(health, ['-', str(report), str(groups), str(containers), profile])
        report.write_text(data.replace(f'memMB={memory}', 'memMB=1'))
        fails(health, ['-', str(report), str(groups), str(containers), profile])
        report.write_text(data.replace(f'nHealthy: {containers}', 'nHealthy: 0'))
        fails(health, ['-', str(report), str(groups), str(containers), profile])

# Bash disables errexit throughout a function invoked as a condition. Exercise
# the real shell helper in that context, rejecting each evidence stage in turn.
for rejected_stage in (1, 2, 3, 4, 5):
    with tempfile.TemporaryDirectory(prefix='cousin-lifecycle-shell-') as directory:
        root = pathlib.Path(directory)
        write(root, 'cousin-native-session-qualified.json', '{}\n')
        script = r'''
set -Eeuo pipefail
source "$1"
ROOT=$2
TEST_DIR=$2
rejected_stage=$3
SECOND=fixture
printf '0\n' > "$ROOT/stage"
ok() { return 0; }
prodigy_dev_cousin_mark_time() { return 0; }
wait_ready() { return 0; }
m() { printf 'm %s\n' "$1" >> "$ROOT/actions"; }
python3() {
  if [[ $1 != - ]]; then return 0; fi
  local stage
  stage=$(cat "$ROOT/stage")
  stage=$((stage + 1))
  printf '%s\n' "$stage" > "$ROOT/stage"
  printf 'validate %s\n' "$stage" >> "$ROOT/actions"
  if [[ $stage == "$rejected_stage" ]]; then
    if [[ $stage == 4 ]]; then SECONDS=$((SECONDS + 60)); fi
    return 73
  fi
  if [[ $stage == 3 ]]; then printf '1\n'; fi
  return 0
}
true &
PAIR_PARTITION_PID=$!
if prodigy_dev_qualify_cousin_lifecycle horizontal fixture; then
  exit 0
else
  exit "$?"
fi
'''
        result = subprocess.run(['bash', '-c', script, 'lifecycle-shell-test', str(shell),
                                 str(root), str(rejected_stage)], capture_output=True, text=True)
        expected_code = 1 if rejected_stage == 4 else 73
        assert result.returncode == expected_code, (rejected_stage, result.returncode, result.stdout, result.stderr)
        assert (root / 'actions').read_text().splitlines()[-1] == f'validate {rejected_stage}'
        assert 'PASS:' not in result.stdout

print(json.dumps({'passed': True}))
