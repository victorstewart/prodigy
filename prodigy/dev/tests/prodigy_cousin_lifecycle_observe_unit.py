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
source_select = block('PY_SOURCE_SELECT')
source_report = block('PY_SOURCE_REPORT')
source_recover = block('PY_SOURCE_RECOVER')
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


def endpoints(root):
    write(root, 'cousin-endpoints.json', json.dumps({'sourceApplicationID': 1, 'destinationApplicationID': 2}))


def fixture_logs(root, side, events, metric=True):
    deployment = (1 << 48) | 1 if side == 'source' else (2 << 48) | 1
    for index, event in enumerate(events.splitlines()):
        if not event: continue
        match = re.search(r'uuid=([0-9a-f]+)', event)
        uuid = match.group(1) if match else f'{index + 1:032x}'
        ready = (event if event.startswith('cousin_session_probe.ready ') else
                 f'cousin_session_probe.ready uuid={uuid} deployment={deployment} source={1 if side == "source" else 0} group=0 monotonicMs={begin_ms-1}')
        if event.startswith('cousin_session_probe.ready ') and side == 'source':
            ready = ready.replace('source=0', 'source=1')
            event = ready
        prefix = f'cousin_session_probe.scaleMetric monotonicMs={begin_ms + 1000}\n' if metric else ''
        write(root, f'cousin-native-logs/{"first" if side == "source" else "second"}-{index}-{uuid}.log', prefix + ready + '\n' + ('' if event == ready else event + '\n'))


def partition_fixture(root, profile, event_lines):
    endpoints(root)
    write(root, 'cousin-lifecycle-partition.log',
          f'PAIR_CONTROL_FAULT operationID=abc123 clock=CLOCK_BOOTTIME delayMs=15000 durationMs=60000 '
          f'beginNs={begin_ms * 1_000_000} endNs={end_ms * 1_000_000}\n')
    fixture_logs(root, 'destination', event_lines)


def horizontal_events(offset=2000, deployment=(2 << 48) | 1):
    return ''.join(
        f'cousin_session_probe.ready uuid={uuid:032x} deployment={deployment} source=0 group=1 monotonicMs={begin_ms + offset + index}\n'
        for index, uuid in enumerate((1, 2, 3)))


def vertical_events(offset=2000):
    return ''.join(
        f'cousin_session_probe.resources uuid={uuid:032x} cores=1 memoryMB=384 storageMB=64 downscale=0 accepted=1 '
        f'monotonicMs={begin_ms + offset + index}\n'
        for index, uuid in enumerate((1, 2, 3)))


def paired_events(source_kind, destination_kind, offset=2000):
    event = {'horizontal': horizontal_events, 'vertical': vertical_events}
    return event[source_kind](offset, (1 << 48) | 1) if source_kind == 'horizontal' else event[source_kind](offset), event[destination_kind](offset + 100, (2 << 48) | 1) if destination_kind == 'horizontal' else event[destination_kind](offset + 100)


def paired_fixture(root, profile, source_events, destination_events, metrics=True):
    endpoints(root)
    write(root, 'cousin-lifecycle-partition.log',
          f'PAIR_CONTROL_FAULT operationID=abc123 clock=CLOCK_BOOTTIME delayMs=15000 durationMs=60000 '
          f'beginNs={begin_ms * 1_000_000} endNs={end_ms * 1_000_000}\n')
    fixture_logs(root, 'source', source_events, metrics)
    fixture_logs(root, 'destination', destination_events, metrics)


def session_fixture(root, *, old_pid=101, close_ms=begin_ms + 12_000,
                    after_session='new', after_request_ms=begin_ms + 20_000, after_peer='0000000000000000000000000000000b'):
    endpoints(root)
    peer_hex = '0000000000000000000000000000000a'
    write(root, 'cousin-native-session-after-scale.json', json.dumps({
        'sourceLog': 'first-1-source', 'sessionUUID': 'old',
        'rounds': [{'peer': peer_hex, 'monotonicMs': str(begin_ms + 19_000)}],
    }))
    write(root, 'cousin-native-session-qualified.json', json.dumps({
        'sourceLog': 'first-1-source', 'sessionUUID': after_session,
        'request': {'monotonicMs': str(after_request_ms)}, 'rounds': [{'peer': after_peer}],
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
        'runtimeContainerUUIDs': ['11', '12', '13', '14', '15', '16'], 'memoryMB': '256',
    }))
    write(root, 'cousin-native-logs/second-3-11.log',
          f'cousin_session_probe.ready uuid=0000000000000000000000000000000b deployment={(2 << 48) | 1} source=0 cores=1 memoryMB=256 storageMB=64 monotonicMs={begin_ms + 11_000}\n')
    write(root, 'second-workspace/fault-events.log',
          f'fault-crash runtime=fixture machine=3 atMs=1 monotonicMs={begin_ms + 10_500}\n')
    write(root, 'cousin-lifecycle-restart-monotonic-ms', f'{begin_ms + 10_000}\n')
    write(root, 'cousin-lifecycle-restarted-monotonic-ms', f'{begin_ms + 10_000}\n')


def source_fault_fixture(root, *, old_pid=101, replacement_pid=202, old_uuid='10',
                         after_session='new', request_ms=begin_ms + 20_000):
    write(root, 'cousin-native-session-after-scale.json', json.dumps({
        'sourceLog': 'first-1-16', 'sessionUUID': 'old',
        'rounds': [{'peer': '0000000000000000000000000000000a'}],
    }))
    write(root, 'cousin-native-logs/first-1-16.log',
          f'cousin_session_probe.ready uuid={int(old_uuid, 16):032x} deployment={(1 << 48) | 1} source=1 monotonicMs={begin_ms}\n'
          f'cousin_session_probe.activate session=old monotonicMs={begin_ms}\n')
    write(root, 'cousin-native-logs/second-3-10.log',
          f'cousin_session_probe.ready uuid=0000000000000000000000000000000a deployment={(2 << 48) | 1} source=0 monotonicMs={begin_ms}\n'
          f'cousin_session_probe.closed session=old monotonicMs={begin_ms + 10_750}\n')
    endpoints(root)
    write(root, 'first-workspace/test-cluster-manifest.json', json.dumps({
        'nodes': [{'index': 1, 'pid': old_pid}],
    }))
    write(root, 'source-application.log',
          'nHealthy: 3\nnDeployed: 3\n' + '\n'.join(f'containerRuntime: cores=1 memMB=384 storMB=128 uuid={uuid}'
                    for uuid in ('16', '12', '13')) + '\n')
    write(root, 'cousin-lifecycle-source-report.json', json.dumps({'runtimeContainerUUIDs': ['16', '12', '13']}))
    write(root, 'cousin-native-session-qualified.json', json.dumps({
        'sourceLog': 'first-1-16', 'sessionUUID': after_session, 'request': {'monotonicMs': str(request_ms)},
    }))
    write(root, 'cousin-lifecycle-source-restart-monotonic-ms', f'{begin_ms + 10_000}\n')
    write(root, 'first-workspace/fault-events.log',
          f'fault-crash runtime=fixture machine=1 atMs=1 monotonicMs={begin_ms + 10_500}\n')
    # The replacement becomes ready after the crash and before its healthy
    # report; post-report activity must still belong to the reported UUIDs.
    write(root, 'cousin-lifecycle-source-restarted-monotonic-ms', f'{begin_ms + 11_500}\n')
    return replacement_pid


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
    assert receipt['profile'] == 'horizontal' and receipt['metricSamples'] == 3
    assert {row['uuid'] for row in receipt['scaleEvents']} == {f'{value:032x}' for value in (1, 2, 3)}

with tempfile.TemporaryDirectory(prefix='cousin-lifecycle-observe-') as directory:
    root = pathlib.Path(directory)
    partition_fixture(root, 'vertical', vertical_events())
    run(lifecycle, ['-', str(root), 'vertical'])
    assert json.loads((root / 'cousin-lifecycle-scaled.json').read_text())['profile'] == 'vertical'

for profile, source_kind, destination_kind in [
        ('source-horizontal-destination-vertical', 'horizontal', 'vertical'),
        ('source-vertical-destination-horizontal', 'vertical', 'horizontal'),
]:
    with tempfile.TemporaryDirectory(prefix='cousin-lifecycle-paired-') as directory:
        root = pathlib.Path(directory)
        source_events, destination_events = paired_events(source_kind, destination_kind)
        paired_fixture(root, profile, source_events, destination_events)
        run(lifecycle, ['-', str(root), profile])
        receipt = json.loads((root / 'cousin-lifecycle-scaled.json').read_text())
        assert receipt['profile'] == profile
        assert len({row['uuid'] for row in receipt['scaleEvents'] if row['side'] == 'source'}) == 3
        assert len({row['uuid'] for row in receipt['scaleEvents'] if row['side'] == 'destination'}) == 3

# The role is determined by which cluster log carried the evidence. Swapping it,
# omitting one side, omitting ordinary metrics, or moving a changed-side event
# outside the provider interval must be rejected.
for profile, source_kind, destination_kind in [
        ('source-horizontal-destination-vertical', 'horizontal', 'vertical'),
        ('source-vertical-destination-horizontal', 'vertical', 'horizontal'),
]:
    source_events, destination_events = paired_events(source_kind, destination_kind)
    invalid = [
        (destination_events, source_events, True),
        (source_events, '', True),
        (source_events, destination_events, False),
        (source_events.replace(f'monotonicMs={begin_ms + 2000}', f'monotonicMs={begin_ms - 1}', 1), destination_events, True),
    ]
    for bad_source, bad_destination, metrics in invalid:
        with tempfile.TemporaryDirectory(prefix='cousin-lifecycle-paired-') as directory:
            root = pathlib.Path(directory)
            paired_fixture(root, profile, bad_source, bad_destination, metrics)
            fails(lifecycle, ['-', str(root), profile])

# Endpoint identity is checked even when the ready line predates the fault.
for mutate in ('wrong-source-role', 'wrong-vertical-deployment'):
    with tempfile.TemporaryDirectory(prefix='cousin-lifecycle-identity-') as directory:
        root = pathlib.Path(directory)
        source_events, destination_events = paired_events('vertical', 'horizontal')
        paired_fixture(root, 'source-vertical-destination-horizontal', source_events, destination_events)
        path = next((root / 'cousin-native-logs').glob('first-*.log'))
        text = path.read_text()
        if mutate == 'wrong-source-role':
            path.write_text(text.replace('source=1', 'source=0', 1))
        else:
            path.write_text(text.replace(f'deployment={(1 << 48) | 1}', 'deployment=7', 1))
        fails(lifecycle, ['-', str(root), 'source-vertical-destination-horizontal'])

# A ready event from a different deployment cannot satisfy the changed-side proof.
with tempfile.TemporaryDirectory(prefix='cousin-lifecycle-deployment-') as directory:
    root = pathlib.Path(directory)
    source_events, destination_events = paired_events('horizontal', 'vertical')
    paired_fixture(root, 'source-horizontal-destination-vertical',
                   source_events.replace(f'deployment={(1 << 48) | 1}', 'deployment=7'), destination_events)
    fails(lifecycle, ['-', str(root), 'source-horizontal-destination-vertical'])

for profile, events in [
        ('horizontal', f'cousin_session_probe.scaleMetric monotonicMs={begin_ms - 1}\n' + horizontal_events()),
        ('horizontal', horizontal_events(offset=-1000)),
        ('vertical', vertical_events().replace('accepted=1', 'accepted=0')),
        ('horizontal', horizontal_events()[:-len('cousin_session_probe.ready uuid=c deployment=562949953421313 group=1 monotonicMs=1002002\n')]),
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

with tempfile.TemporaryDirectory(prefix='cousin-lifecycle-source-fault-') as directory:
    root = pathlib.Path(directory)
    replacement_pid = source_fault_fixture(root)
    run(source_select, ['-', str(root)])
    selected = json.loads((root / 'cousin-lifecycle-source-selected.json').read_text())
    assert selected == {'machineIndex': 1, 'machinePID': 101, 'containerUUID': '00000000000000000000000000000010', 'sessionUUID': 'old',
                        'sessionActivatedMonotonicMs': begin_ms, 'peerContainerUUID': '0000000000000000000000000000000a'}
    write(root, 'first-workspace/test-cluster-manifest.json', json.dumps({'nodes': [{'index': 1, 'pid': replacement_pid}]}))
    write(root, 'cousin-native-logs/first-1-16.log',
          f'cousin_session_probe.ready uuid=00000000000000000000000000000010 deployment={(1 << 48) | 1} source=1 memoryMB=384 monotonicMs={begin_ms + 11_000}\n'
          f'cousin_session_probe.request request=new source=fd00::1 sourcePort=45000 monotonicMs={begin_ms + 12_000}\n'
          f'cousin_session_probe.round request=new session=new peer=0000000000000000000000000000000a payload=exact monotonicMs={begin_ms + 12_100}\n')
    run(source_report, ['-', str(root), str(root / 'source-application.log'), '3', '384'])
    assert '16' in json.loads((root / 'cousin-lifecycle-source-report.json').read_text())['runtimeContainerUUIDs']
    run(source_recover, ['-', str(root)])
    recovered = json.loads((root / 'cousin-lifecycle-source-restarted.json').read_text())
    assert recovered['replacementPID'] == replacement_pid and recovered['newSessionUUID'] == 'new'

# Each mutation below leaves the otherwise-valid recovered source fixture intact.
for mode in ('active-orphan', 'native-memory-mismatch', 'precrash-resource', 'wrong-selected-machine'):
    with tempfile.TemporaryDirectory(prefix='cousin-lifecycle-source-oracle-') as directory:
        root=pathlib.Path(directory); source_fault_fixture(root); run(source_select,['-',str(root)])
        write(root,'first-workspace/test-cluster-manifest.json',json.dumps({'nodes':[{'index':1,'pid':202}]}))
        ready_machine=2 if mode=='wrong-selected-machine' else 1
        memory=256 if mode=='native-memory-mismatch' else 384
        write(root,f'cousin-native-logs/first-{ready_machine}-16.log',f'cousin_session_probe.ready uuid=00000000000000000000000000000010 deployment={(1<<48)|1} source=1 memoryMB={memory} monotonicMs={begin_ms+11_000}\n' f'cousin_session_probe.request request=new source=fd00::1 sourcePort=45000 monotonicMs={begin_ms+12_000}\n')
        if mode=='active-orphan':
            write(root,'cousin-native-logs/first-1-14.log',f'cousin_session_probe.ready uuid=0000000000000000000000000000000e deployment={(1<<48)|1} source=1 memoryMB=384 monotonicMs={begin_ms+11_000}\n' f'cousin_session_probe.request request=orphan source=fd00::1 sourcePort=45000 monotonicMs={begin_ms+12_000}\n')
        if mode=='precrash-resource':
            write(root,'cousin-native-logs/first-1-16.log',f'cousin_session_probe.ready uuid=00000000000000000000000000000010 deployment={(1<<48)|1} source=1 memoryMB=256 monotonicMs={begin_ms+11_000}\n' f'cousin_session_probe.resources uuid=00000000000000000000000000000010 cores=1 memoryMB=384 storageMB=64 accepted=1 monotonicMs={begin_ms+9_000}\n' f'cousin_session_probe.request request=new source=fd00::1 sourcePort=45000 monotonicMs={begin_ms+12_000}\n')
        fails(source_recover,['-',str(root)])

# Selection must remain source-only, and recovery rejects a stale selected
# identity, unchanged process incarnation, old session, pre-fault request, or
# a retained identity without fresh post-fault readiness and activity.
for mode in ('wrong-role', 'stale-report', 'same-pid', 'same-session', 'pre-fault-request', 'stale-ready', 'dispatch-ready',
             'missing-close', 'late-close', 'wrong-close-session', 'wrong-close-peer'):
    with tempfile.TemporaryDirectory(prefix='cousin-lifecycle-source-fault-') as directory:
        root = pathlib.Path(directory)
        source_fault_fixture(root, after_session='old' if mode == 'same-session' else 'new',
                             request_ms=begin_ms + 10_000 if mode == 'pre-fault-request' else begin_ms + 20_000)
        if mode == 'wrong-role':
            write(root, 'cousin-native-logs/first-1-16.log',
                  f'cousin_session_probe.ready uuid=10 deployment={(1 << 48) | 1} source=0 monotonicMs={begin_ms}\n')
            fails(source_select, ['-', str(root)])
            continue
        run(source_select, ['-', str(root)])
        close_path = root / 'cousin-native-logs/second-3-10.log'
        close_data = close_path.read_text()
        if mode == 'missing-close':
            close_path.write_text(close_data.splitlines()[0] + '\n')
        elif mode == 'late-close':
            close_path.write_text(close_data.replace(str(begin_ms + 10_750), str(begin_ms + 30_000)))
        elif mode == 'wrong-close-session':
            close_path.write_text(close_data.replace('session=old', 'session=other'))
        elif mode == 'wrong-close-peer':
            close_path.write_text(close_data.replace('uuid=0000000000000000000000000000000a', 'uuid=0000000000000000000000000000000c'))
        if mode == 'stale-report':
            write(root, 'source-application.log',
                  'nHealthy: 3\nnDeployed: 3\n' + 'containerRuntime: cores=1 memMB=256 storMB=128 uuid=10\n' * 3)
            fails(source_report, ['-', str(root), str(root / 'source-application.log'), '3', '384'])
            continue
        pid = 101 if mode == 'same-pid' else 202
        write(root, 'first-workspace/test-cluster-manifest.json', json.dumps({'nodes': [{'index': 1, 'pid': pid}]}))
        ready_ms = begin_ms if mode == 'stale-ready' else begin_ms + 10_250 if mode == 'dispatch-ready' else begin_ms + 11_000
        activity = '' if mode == 'stale-ready' else f'cousin_session_probe.request request=new source=fd00::1 sourcePort=45000 monotonicMs={begin_ms + 12_000}\n'
        write(root, 'cousin-native-logs/first-1-16.log',
              f'cousin_session_probe.ready uuid=00000000000000000000000000000010 deployment={(1 << 48) | 1} source=1 memoryMB=384 monotonicMs={ready_ms}\n' + activity)
        fails(source_recover, ['-', str(root)])


for runtime_uuids in [
        ('11', '12', '13', '14', '15', '16'),
        ('10', '12', '13', '14', '15', '16'),
        ('11', '11', '13', '14', '15', '16'),
]:
    with tempfile.TemporaryDirectory(prefix='cousin-lifecycle-restart-report-') as directory:
        root = pathlib.Path(directory)
        restart_report_fixture(root, runtime_uuids=runtime_uuids)
        if len(set(runtime_uuids)) == 6:
            run(restart_report, ['-', str(root), str(root/'application.log'), '2', '6', '256'])
            assert json.loads((root/'cousin-lifecycle-restarted-report.json').read_text())['runtimeContainerUUIDs'] == list(runtime_uuids)
        else:
            fails(restart_report, ['-', str(root), str(root/'application.log'), '2', '6', '256'])

# Current UUIDs are insufficient when the recovered target silently shrinks.
for changed in ('cores=2', 'memMB=128', 'storMB=64'):
    with tempfile.TemporaryDirectory(prefix='cousin-lifecycle-restart-resources-') as directory:
        root = pathlib.Path(directory)
        restart_report_fixture(root)
        path = root / 'application.log'
        original = {'cores': 'cores=1', 'memMB': 'memMB=256', 'storMB': 'storMB=128'}[changed.split('=')[0]]
        path.write_text(path.read_text().replace(original, changed, 1))
        fails(restart_report, ['-', str(root), str(path), '2', '6', '256'])

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

# A stateful cold restart may retain the selected plan UUID. It is current only
# when that exact identity has a fresh ready event from the replacement machine.
with tempfile.TemporaryDirectory(prefix='cousin-lifecycle-retained-identity-') as directory:
    root = pathlib.Path(directory)
    session_fixture(root, old_pid=202)
    write(root, 'cousin-lifecycle-restart-selected.json', json.dumps({
        'machineIndex': 3, 'machinePID': 101, 'peerContainerUUID': '10',
        'sessionUUID': 'old', 'sessionActivatedMonotonicMs': begin_ms,
        'selectedMonotonicMs': begin_ms + 20_000,
    }))
    write(root, 'cousin-lifecycle-restarted-report.json', json.dumps({
        'runtimeContainerUUIDs': ['10', '11', '13', '14', '15', '16'], 'memoryMB': '256',
    }))
    fails(restart, ['-', str(root)])
    write(root, 'cousin-native-logs/second-3-10.log',
          f'cousin_session_probe.ready uuid=0000000000000000000000000000000a deployment={(2 << 48) | 1} '
          f'source=0 cores=1 memoryMB=256 storageMB=64 monotonicMs={begin_ms + 10_250}\n')
    fails(restart, ['-', str(root)])
    write(root, 'cousin-native-logs/second-3-10.log',
          f'cousin_session_probe.ready uuid=0000000000000000000000000000000a deployment={(2 << 48) | 1} '
          f'source=0 cores=1 memoryMB=256 storageMB=64 monotonicMs={begin_ms + 11_000}\n')
    run(restart, ['-', str(root)])
    retained = json.loads((root/'cousin-lifecycle-restarted.json').read_text())
    assert retained['selectedIdentityRetained'] is True

for change in ('memoryMB=128', 'source=1', 'deployment=7', 'cores=2', 'storageMB=128'):
    with tempfile.TemporaryDirectory(prefix='cousin-lifecycle-native-target-') as directory:
        root = pathlib.Path(directory)
        session_fixture(root, old_pid=202)
        write(root, 'cousin-lifecycle-restart-selected.json', json.dumps({
            'machineIndex': 3, 'machinePID': 101, 'peerContainerUUID': '10',
            'sessionUUID': 'old', 'sessionActivatedMonotonicMs': begin_ms,
            'selectedMonotonicMs': begin_ms + 20_000,
        }))
        path = root / 'cousin-native-logs/second-3-11.log'
        key = change.split('=')[0]
        path.write_text(re.sub(r'\b'+key+r'=\w+', change, path.read_text()))
        fails(restart, ['-', str(root)])

with tempfile.TemporaryDirectory(prefix='cousin-lifecycle-retained-vertical-target-') as directory:
    root = pathlib.Path(directory)
    session_fixture(root, old_pid=202)
    write(root, 'cousin-lifecycle-restart-selected.json', json.dumps({
        'machineIndex': 3, 'machinePID': 101, 'peerContainerUUID': '10',
        'sessionUUID': 'old', 'sessionActivatedMonotonicMs': begin_ms,
        'selectedMonotonicMs': begin_ms + 20_000,
    }))
    path = root / 'cousin-native-logs/second-3-11.log'
    path.write_text(path.read_text().replace('memoryMB=256', 'memoryMB=384'))
    report = root / 'cousin-lifecycle-restarted-report.json'
    report.write_text(report.read_text().replace('"256"', '"384"'))
    run(restart, ['-', str(root)])
    path.write_text(path.read_text().replace('memoryMB=384', 'memoryMB=256'))
    fails(restart, ['-', str(root)])

# A fresh session UUID alone cannot turn an old/unreported peer into current evidence.
for peer in ('0000000000000000000000000000000a', '000000000000000000000000000000ff'):
    with tempfile.TemporaryDirectory(prefix='cousin-lifecycle-stale-peer-') as directory:
        root = pathlib.Path(directory)
        session_fixture(root, old_pid=202, after_peer=peer)
        write(root, 'cousin-lifecycle-restart-selected.json', json.dumps({
            'machineIndex': 3, 'machinePID': 101, 'peerContainerUUID': '10',
            'sessionUUID': 'old', 'sessionActivatedMonotonicMs': begin_ms,
            'selectedMonotonicMs': begin_ms + 20_000,
        }))
        fails(restart, ['-', str(root)])


for profile, groups, containers, memory in [('horizontal', 2, 6, 256), ('vertical', 1, 3, 384)]:
    with tempfile.TemporaryDirectory(prefix='cousin-lifecycle-health-') as directory:
        root = pathlib.Path(directory)
        report = root / 'application.log'
        data = f'\tisStateful: true\tnShardGroups: {groups}\n\tnHealthy: {containers}\n\tnDeployed: {containers}\n\tnCrashes: 0\n'
        data += f'\tcontainerRuntime: cores=1 memMB={memory} storMB=128 uuid=1\n' * containers
        report.write_text(data)
        run(health, ['-', str(report), str(groups), str(containers), str(memory)])
        report.write_text(data.replace(f'memMB={memory}', 'memMB=1'))
        fails(health, ['-', str(report), str(groups), str(containers), str(memory)])
        report.write_text(data.replace(f'nHealthy: {containers}', 'nHealthy: 0'))
        fails(health, ['-', str(report), str(groups), str(containers), str(memory)])

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

# The real client helper may resume only an exact, explicitly pending operation.
pair_shell=shell.with_name('prodigy_dev_pair_enrollment_qualification.sh').read_text()
enroll_helper=pair_shell.split('enrollment_complete() {',1)[1].split('revocation_complete() {',1)[0]
enroll_helper='enrollment_complete() {'+enroll_helper
for mode in ('ready','resume','still-pending','wrong-operation','rejected','transport','unqualified-success'):
    with tempfile.TemporaryDirectory(prefix='cousin-enroll-resume-') as directory:
        root=pathlib.Path(directory)
        success='enrollClusterPair success=1 operationUUID=000000000000000000000000000000ab resumed=1 firstQualified=1 firstProjection=1 secondQualified=1 secondProjection=1 pending=0 failure='
        pending='enrollClusterPair success=0 operationUUID=000000000000000000000000000000ab resumed=0 firstQualified=1 firstProjection=1 secondQualified=1 secondProjection=0 pending=1 failure=cluster pair enrollment remains pending qualified active projection; retry the same operation UUID'
        first=success if mode in ('ready','unqualified-success') else pending
        if mode=='wrong-operation': first=first.replace('000000ab','000000cd')
        if mode=='rejected': first=first.replace('cluster pair enrollment remains pending qualified active projection; retry the same operation UUID','conflicting immutable operation')
        if mode=='transport': first='connection unavailable'
        if mode=='unqualified-success': first=first.replace('secondProjection=1','secondProjection=0')
        (root/'first').write_text(first+'\n')
        (root/'second').write_text((pending if mode=='still-pending' else success)+'\n')
        script='set -Eeuo pipefail\n'+enroll_helper+r'''
ROOT=$1 FIRST=first SECOND=second OPERATION=0xab
ok() { rg -q "$2 success=1" "$1"; }
m() {
  [[ "$2" == 45 && "$4" == enrollClusterPair && "$5" == first && "$6" == second && "$7" == 0xab ]]
  printf '%s\n' "$1" >> "$ROOT/calls"
  if [[ "$1" == enroll ]]; then cat "$ROOT/first" > "$3"; else cat "$ROOT/second" > "$3"; fi
  rg -q 'success=1' "$3"
}
enroll_pair
'''
        result=subprocess.run(['bash','-c',script,'enroll-resume-test',str(root)],capture_output=True,text=True)
        assert (result.returncode==0)==(mode in ('ready','resume')),(mode,result.stderr)
        calls=(root/'calls').read_text().splitlines()
        assert calls==(['enroll','enroll-resume'] if mode in ('resume','still-pending') else ['enroll']),mode

print(json.dumps({'passed': True}))
