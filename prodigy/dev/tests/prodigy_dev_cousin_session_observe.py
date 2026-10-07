#!/usr/bin/env python3
"""Read-only native application evidence while the harness forbids Mothership calls."""
import json
import pathlib
import re
import sys
import time

root = pathlib.Path(sys.argv[1])
mode = sys.argv[2]
assert mode in ('qualify', 'revoked', 'snapshot')
marker_name = 'cousin-revoked' if mode == 'revoked' else 'cousin-offline-start'
if mode == 'qualify' and len(sys.argv) > 3:
    marker_name = sys.argv[3]
    assert re.fullmatch(r'cousin-[a-z-]+', marker_name)
minimum_destination_groups = int(sys.argv[4]) if mode == 'qualify' and len(sys.argv) > 4 else 0
marker = int((root / (marker_name + '-monotonic-ms')).read_text())
wall_marker = int((root / (marker_name + '-ms')).read_text())
revoke_request_marker = (int((root / 'cousin-revocation-request-monotonic-ms').read_text())
                         if mode == 'revoked' else None)
output = root / 'cousin-native-logs'
output.mkdir(exist_ok=True)
transit = json.loads((root / 'cousin-service-transit.json').read_text())
qualified = json.loads((root / 'cousin-native-session-qualified.json').read_text()) if mode == 'revoked' else None


def logs():
    result = {}
    for side in ('first', 'second'):
        manifest = json.loads((root / f'{side}-workspace/test-cluster-manifest.json').read_text())
        for node in manifest['nodes']:
            # /proc exposes the already-owned machine mount view. Observation
            # never enters it to run a command or changes any runtime resource.
            base = pathlib.Path(f"/proc/{node['pid']}/root/containers")
            for path in base.glob('*/rootfs/logs/stdout.log'):
                try:
                    data = path.read_text(errors='replace')
                except (FileNotFoundError, PermissionError):
                    continue
                if 'cousin_session_probe.' not in data:
                    continue
                key = f"{side}-{node['index']}-{path.parts[-4]}"
                result[key] = data
                (output / f'{key}.log').write_text(data)
    return result


def records(data, kind):
    return [dict(re.findall(r'(\w+)=([^\s]+)', line)) for line in data.splitlines()
            if line.startswith(f'cousin_session_probe.{kind} ')]


if mode == 'snapshot':
    logs()
    raise SystemExit(0)

deadline = time.monotonic() + (90 if mode == 'qualify' else 13)
while True:
    observed = logs()
    if mode == 'qualify':
        for name, data in observed.items():
            if not name.startswith('first-'):
                continue
            requests = {row['request']: row for row in records(data, 'request')
                        if int(row['monotonicMs']) > marker and row.get('source') == transit['sourceWhiteholeIPv6']
                        and int(row.get('sourcePort', '0')) == transit['sourceTCPPort']}
            sessions = {}
            for row in records(data, 'round'):
                if row.get('payload') != 'exact' or row.get('request') not in requests:
                    continue
                sessions.setdefault(row['session'], []).append(row)
            for session, rows in sessions.items():
                bindings = [row for row in records(data, 'binding') if row.get('session') == session]
                if minimum_destination_groups and not any(
                        int(row.get('destinationGroups', '0')) == minimum_destination_groups for row in bindings):
                    continue
                rows.sort(key=lambda row: int(row['monotonicMs']))
                span = int(rows[-1]['monotonicMs']) - int(rows[0]['monotonicMs'])
                renewals = [row for row in records(data, 'renew')
                            if row.get('session') == session and int(row['monotonicMs']) > marker and
                            int(row.get('generation', '0')) > 1]
                if span >= 12000 and len(rows) >= 6 and len({row['peer'] for row in rows}) == 1 and renewals:
                    receipt = {'offlineStartMs': wall_marker, 'offlineStartMonotonicMs': marker, 'sourceLog': name, 'request': requests[rows[0]['request']],
                               'sessionUUID': session, 'sourceTuple': [transit['sourceWhiteholeIPv6'], transit['sourceTCPPort']], 'rounds': rows, 'renewalObservedMs': span,
                               'renewalGenerations': sorted({int(row['generation']) for row in renewals}),
                               'bindings': bindings,
                               'mothershipCallsDuringObservation': 0}
                    (root / 'cousin-native-session-qualified.json').write_text(json.dumps(receipt, indent=2) + '\n')
                    print('PASS: new offline COUSIN request and exact AEGIS echo through lease renewal', flush=True)
                    raise SystemExit(0)
    else:
        if qualified['sourceLog'] not in observed:
            raise SystemExit('FAIL: qualified application log disappeared during revocation observation')
        data = observed[qualified['sourceLog']]
        session = qualified['sessionUUID']
        revoked = [row for row in records(data, 'revoke')
                   if row.get('session') == session and int(row['monotonicMs']) >= revoke_request_marker]
        closed = [row for row in records(data, 'closed')
                  if row.get('session') == session and int(row['monotonicMs']) >= revoke_request_marker]
        retry_requests = [row for row in records(data, 'request')
                          if int(row['monotonicMs']) > marker and row.get('source') == transit['sourceWhiteholeIPv6'] and
                          int(row.get('sourcePort', '0')) == transit['sourceTCPPort']]
        retry_ids = {row['request'] for row in retry_requests}
        retry_rejections = [row for row in records(data, 'reject') if row.get('request') in retry_ids]
        late = [row for name, data in observed.items() if name.startswith('first-')
                for row in records(data, 'round') if int(row['monotonicMs']) > marker + 1000]
        if late:
            raise SystemExit(f'FAIL: revoked permission continued payload delivery: {late}')
        revocation_evidence = bool(revoked and closed and retry_requests and retry_rejections)
    if time.monotonic() >= deadline:
        if mode == 'revoked':
            if not revocation_evidence:
                raise SystemExit('FAIL: no qualified-session revoke/close plus explicit rejection of a post-revocation request')
            observed_for_ms = time.clock_gettime_ns(time.CLOCK_BOOTTIME) // 1_000_000 - marker
            (root / 'cousin-native-session-revoked.json').write_text(json.dumps(
                {'revokedMs': wall_marker, 'revokedMonotonicMs': marker, 'observedForMs': observed_for_ms,
                 'sessionUUID': session, 'revocationGenerations': sorted({int(row['generation']) for row in revoked}),
                 'postRevocationRequestUUIDs': sorted(retry_ids),
                 'postRevocationRejectedRequestUUIDs': sorted({row['request'] for row in retry_rejections}),
                 'lateSuccessfulPayloads': 0}, indent=2) + '\n')
            print('PASS: permission revocation closed the qualified session and rejected a new request', flush=True)
            raise SystemExit(0)
        raise SystemExit('FAIL: no post-offline request completed exact payload exchange and >12s renewal')
    time.sleep(.2)
