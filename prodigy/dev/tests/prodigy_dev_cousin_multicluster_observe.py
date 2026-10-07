#!/usr/bin/env python3
"""Read-only oracle for simultaneous, identity-bound native COUSIN routes."""
import json
import pathlib
import re
import sys
import time


def records(data, kind):
    prefix = 'cousin_session_probe.' + kind + ' '
    return [dict(re.findall(r'(\w+)=([^\s]+)', line))
            for line in data.splitlines() if line.startswith(prefix)]


def candidates(root, route, minimum):
    evidence = root / 'cousin-native-logs'
    evidence.mkdir(exist_ok=True)
    source = route['sourceUUID'].lower()
    targets = route['destinationLogs']
    peers = {x['uuid'].lower() for x in targets}
    if not peers or peers != {x.lower() for x in route['destinationUUIDs']}:
        raise ValueError('supplied peers differ from declared destination logs')
    source_path = root / route['sourceLog']
    if not source_path.exists():
        return []
    data = source_path.read_text(errors='replace')
    source_copy = route['name'] + '-source.log'
    (evidence / source_copy).write_text(data)
    if not any(x.get('uuid', '').lower() == source and x.get('source') == '1'
               and x.get('deployment') == str(route['sourceDeploymentID'])
               for x in records(data, 'ready')):
        raise ValueError('source identity does not bind route ' + route['name'])
    destination_data = {}
    for target in targets:
        path = root / target['path']
        if not path.exists():
            return []
        text = path.read_text(errors='replace')
        uuid = target['uuid'].lower()
        (evidence / (route['name'] + '-destination-' + uuid + '.log')).write_text(text)
        if not any(x.get('uuid', '').lower() == uuid and x.get('source') == '0'
                   and x.get('deployment') == str(target['deploymentID'])
                   for x in records(text, 'ready')):
            raise ValueError('destination identity does not bind route ' + route['name'])
        destination_data[uuid] = text
    rounds = records(data, 'round')
    renewals = records(data, 'renew')
    result = []
    for request in records(data, 'request'):
        request_id = request.get('request')
        start = int(request.get('monotonicMs', '-1'))
        if (not request_id or start < int(route['afterMonotonicMs']) or
                (request.get('source'), request.get('sourcePort')) != tuple(map(str, route['sourceTuple']))):
            continue
        payloads = [x for x in rounds if x.get('request') == request_id
                    and x.get('payload') == 'exact' and x.get('peer', '').lower() in peers
                    and int(x.get('monotonicMs', '-1')) >= start]
        for session in {x['session'] for x in payloads if x.get('session')}:
            samples = [x for x in payloads if x['session'] == session]
            session_peers = {x['peer'].lower() for x in samples}
            if len(session_peers) != 1 or len(samples) < 6:
                continue
            begin = min(int(x['monotonicMs']) for x in samples)
            end = max(int(x['monotonicMs']) for x in samples)
            generations = {int(x['generation']) for x in renewals
                           if x.get('request') == request_id and x.get('session') == session
                           and start <= int(x.get('monotonicMs', '-1')) <= end
                           and x.get('generation', '').isdigit()}
            peer = next(iter(session_peers))
            echoes = [x for x in records(destination_data[peer], 'echo')
                      if x.get('session') == session and x.get('peer', '').lower() == source
                      and x.get('payload') == 'exact']
            if end - begin >= minimum and any(x > 1 for x in generations) and echoes:
                result.append({'name': route['name'], 'sourceUUID': source, 'sourceLog': source_copy,
                               'requestUUID': request_id, 'sessionUUID': session, 'peerUUIDs': [peer],
                               'firstMonotonicMs': begin, 'lastMonotonicMs': end,
                               'renewalGenerations': sorted(generations), 'rounds': samples})
    return result


def observe(root, spec):
    routes = spec['routes']
    if len(routes) not in (2, 4, 6) or len({x['name'] for x in routes}) != len(routes):
        raise ValueError('graph must declare 2, 4, or 6 uniquely named directions')
    minimum = int(spec.get('minimumWindowMs', 12000))
    deadline = time.monotonic() + int(spec.get('timeoutSeconds', 240))
    while True:
        choices = [candidates(root, route, minimum) for route in routes]
        # Pick any common interval, including a completed session when a newer
        # session has started. Selecting only the newest session loses evidence.
        starts = sorted({x['firstMonotonicMs'] for group in choices for x in group})
        for start in starts:
            selection = [next((x for x in group if x['firstMonotonicMs'] <= start
                               and x['lastMonotonicMs'] >= start + minimum), None) for group in choices]
            if all(selection):
                overlap = min(x['lastMonotonicMs'] for x in selection) - start
                output = {'routes': selection, 'sharedWindowMs': overlap,
                          'mothershipCallsDuringObservation': 0}
                (root / spec.get('outputName', 'cousin-native-graph-qualified.json')).write_text(
                    json.dumps(output, indent=2) + '\n')
                print('PASS: exact directed COUSIN graph payloads share lease-renewal window', flush=True)
                return
        if time.monotonic() >= deadline:
            raise ValueError('missing exact directed graph routes with a shared renewal interval')
        time.sleep(.2)


if __name__ == '__main__':
    try:
        observe(pathlib.Path(sys.argv[1]), json.loads(pathlib.Path(sys.argv[2]).read_text()))
    except (ValueError, KeyError) as error:
        raise SystemExit('FAIL: ' + str(error))
