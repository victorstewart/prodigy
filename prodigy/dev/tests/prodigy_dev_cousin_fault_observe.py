#!/usr/bin/env python3
"""Read-only fault witnesses and bounded native graph evidence."""
import copy
import json
import pathlib
import re
import sys

from prodigy_dev_cousin_multicluster_observe import observe, records


def pair_interval(text, operation, direction, duration=45000):
    lines = re.findall(r'PAIR_CONTROL_FAULT [^\r\n]*', text)
    middle = '' if direction == 'both' else (' direction=' + direction +
        (' installRule=first0-to-second0-DROP restoreRule=first0-to-second0-ABSENT'
         if direction == 'first-to-second' else
         ' installRule=second0-to-first0-DROP restoreRule=second0-to-first0-ABSENT'))
    pattern = (r'PAIR_CONTROL_FAULT operationID=' + re.escape(operation) +
               r' clock=CLOCK_BOOTTIME delayMs=0 durationMs=' + str(duration) +
               re.escape(middle) + r' beginNs=([0-9]+) endNs=([0-9]+)')
    if len(lines) != 1 or not (match := re.fullmatch(pattern, lines[0])):
        raise ValueError('missing or mismatched exact pair fault receipt')
    begin, end = map(int, match.groups())
    if begin <= 0 or not duration * 1_000_000 <= end - begin <= (duration + 5000) * 1_000_000:
        raise ValueError('unbounded pair fault receipt')
    return (begin + 999999) // 1000000, end // 1000000


def region_interval(text, duration=45000):
    events = []
    for line in text.splitlines():
        if not line.startswith('fault-link '):
            continue
        match = re.fullmatch(r'fault-link runtime=([0-9]+) link=(vp[123]) state=(down|up) '
                             r'atMs=([0-9]+) monotonicMs=([0-9]+)', line)
        if not match:
            raise ValueError('malformed region link witness')
        events.append(match.groups())
    if len(events) != 6 or len({x[0] for x in events}) != 1:
        raise ValueError('region witness must bind six mutations to one runtime')
    groups = {state: {link: int(mono) for _, link, mode, _, mono in events if mode == state}
              for state in ('down', 'up')}
    if any(set(group) != {'vp1', 'vp2', 'vp3'} for group in groups.values()):
        raise ValueError('region witness missing selected link state')
    begin, end = max(groups['down'].values()), min(groups['up'].values())
    if begin <= 0 or not duration <= end - begin <= duration + 5000:
        raise ValueError('region outage interval does not bind requested duration')
    return begin, end


def seal_audit(root, phase):
    begin = int((root / (phase + '-sealed-ms')).read_text())
    end = int((root / (phase + '-completed-ms')).read_text())
    calls = []
    for path in (root / 'receipts').glob('*.json'):
        row = json.loads(path.read_text())
        if row['startedMs'] < end and row['endedMs'] > begin:
            if row['label'] != phase or row['operation'] not in ('testClusterPairControl', 'faultTestCluster'):
                raise ValueError('ordinary Mothership call overlaps sealed observation: ' + row['label'])
            calls.append(row)
    if len(calls) != 1 or calls[0]['status'] != 0:
        raise ValueError('sealed observation lacks its one explicit successful fault request')
    return {'beginWallMs': begin, 'endWallMs': end, 'ordinaryCalls': 0, 'explicitFaultRequests': calls}


def qualify(root, phase, mode, operation='', direction='both'):
    spec = json.loads((root / (phase + '-before-spec.json')).read_text())
    if mode == 'pair':
        begin, end = pair_interval((root / (phase + '.log')).read_text(), operation, direction)
        surviving = {'ac', 'ca', 'bc', 'cb'}
        disrupted = {'ab', 'ba'}
    elif mode == 'region':
        begin, end = region_interval((root / (phase + '-events.log')).read_text())
        surviving = {'ab', 'ba'}
        disrupted = {'ac', 'ca', 'bc', 'cb'}
    else:
        raise ValueError('unsupported fault mode')
    sealed = int((root / (phase + '-sealed-monotonic-ms')).read_text())
    window_start = max(begin + 1000, sealed)
    if end - window_start < 12000:
        raise ValueError('fault lacks a sealed twelve-second interval')
    routes = {x['name']: x for x in spec['routes']}
    if set(routes) != surviving | disrupted:
        raise ValueError('fault requires the exact current six-route graph')
    losses = []
    for name in sorted(disrupted):
        route = routes[name]
        text = pathlib.Path(route['sourceLog']).read_text()
        if any(window_start <= int(row.get('monotonicMs', '-1')) <= end
               for row in records(text, 'round') if row.get('payload') == 'exact'):
            raise ValueError('disrupted route still carried exact payload: ' + name)
        losses.append({'name': name, 'latePayloads': 0})
        (root / 'cousin-native-logs' / (phase + '-' + name + '-source.log')).write_text(text)
    bounded = copy.deepcopy(spec)
    bounded.update(routes=[routes[name] for name in sorted(surviving)], timeoutSeconds=0,
                   outputName=phase + '-surviving.json')
    for route in bounded['routes']:
        route.update(afterMonotonicMs=window_start, beforeMonotonicMs=end, requireFreshRequest=False)
    observe(root, bounded)
    audit = seal_audit(root, phase)
    receipt = {'mode': mode, 'direction': direction, 'faultBeginMonotonicMs': begin,
               'faultEndMonotonicMs': end, 'observationBeginMonotonicMs': window_start,
               'disrupted': losses, 'mothershipAudit': audit}
    (root / (phase + '-qualified.json')).write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__':
    try:
        qualify(pathlib.Path(sys.argv[1]), *sys.argv[2:])
    except (ValueError, KeyError) as error:
        raise SystemExit('FAIL: ' + str(error))
