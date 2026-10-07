#!/usr/bin/env python3
"""Independent positive and adversarial fixtures for the native graph oracle."""
import copy
import json
import pathlib
import subprocess
import sys
import tempfile

OBSERVER = pathlib.Path(__file__).with_name('prodigy_dev_cousin_multicluster_observe.py')


def source_log(uuid, peer, request, start=1000, renew=True):
    text = f'cousin_session_probe.ready uuid={uuid} deployment=9 source=1\n'
    text += f'cousin_session_probe.request request={request} source=fd00::1 sourcePort=45000 monotonicMs={start}\n'
    for index in range(7):
        text += (f'cousin_session_probe.round request={request} session=s{request} peer={peer} '
                 f'payload=exact monotonicMs={start+100+index*2200}\n')
    if renew:
        text += f'cousin_session_probe.renew request={request} session=s{request} generation=2 monotonicMs={start+3000}\n'
    return text


with tempfile.TemporaryDirectory() as directory:
    root = pathlib.Path(directory)
    routes = []
    files = {}
    for index in range(6):
        source, peer = f'{index+1:032x}', f'{index+17:032x}'
        # Match native paths: every application log is named stdout.log.
        source_path = root / f'r{index}/stdout.log'
        destination_path = root / f'd{index}/stdout.log'
        files[source_path] = source_log(source, peer, f'r{index}')
        files[destination_path] = (f'cousin_session_probe.ready uuid={peer} deployment=19 source=0\n'
                                   f'cousin_session_probe.echo peer={source} session=sr{index} payload=exact\n')
        routes.append({'name': f'r{index}', 'sourceLog': str(source_path), 'sourceUUID': source,
                       'sourceDeploymentID': 9, 'sourceTuple': ['fd00::1', 45000],
                       'destinationUUIDs': [peer], 'destinationLogs': [
                           {'path': str(destination_path), 'uuid': peer, 'deploymentID': 19}],
                       'afterMonotonicMs': 0})
    baseline = {'routes': routes, 'minimumWindowMs': 12000, 'timeoutSeconds': 0}

    def run(label, expected, mutate=lambda spec: None):
        for path, text in files.items():
            path.parent.mkdir(exist_ok=True)
            path.write_text(text)
        spec = copy.deepcopy(baseline)
        mutate(spec)
        path = root / 'spec.json'
        path.write_text(json.dumps(spec))
        result = subprocess.run([sys.executable, '-B', str(OBSERVER), str(root), str(path)],
                                capture_output=True, text=True)
        assert (result.returncode == 0) == expected, (label, result.stdout, result.stderr)

    def change_source(spec, old, new):
        path = pathlib.Path(spec['routes'][0]['sourceLog'])
        path.write_text(path.read_text().replace(old, new))

    def change_destination(spec, old, new):
        path = pathlib.Path(spec['routes'][0]['destinationLogs'][0]['path'])
        path.write_text(path.read_text().replace(old, new))

    run('six routes', True)
    assert len(list((root / 'cousin-native-logs').glob('*.log'))) == 12
    run('reciprocal stage', True, lambda s: s.update(routes=s['routes'][:2]))
    run('surviving stage', True, lambda s: s.update(routes=s['routes'][2:]))
    run('missing route', False, lambda s: pathlib.Path(s['routes'][0]['sourceLog']).unlink())
    run('unsupported route count', False, lambda s: s['routes'].pop())
    run('duplicate route', False, lambda s: s['routes'][0].update(name='r1'))
    run('forged source', False, lambda s: s['routes'][0].update(sourceUUID='f'*32))
    run('forged peer set', False, lambda s: s['routes'][0].update(destinationUUIDs=['f'*32]))
    run('source deployment', False, lambda s: s['routes'][0].update(sourceDeploymentID=10))
    run('source tuple', False, lambda s: s['routes'][0].update(sourceTuple=['fd00::2',45000]))
    run('stale request', False, lambda s: s['routes'][0].update(afterMonotonicMs=2000))
    run('destination deployment', False, lambda s: change_destination(s, 'deployment=19', 'deployment=20'))
    run('destination role', False, lambda s: change_destination(s, 'source=0', 'source=1'))
    run('missing renewal', False, lambda s: change_source(s, '.renew ', '.notrenew '))
    run('wrong renewal request', False, lambda s: change_source(s, '.renew request=r0 ', '.renew request=other '))
    run('no shared interval', False, lambda s: pathlib.Path(s['routes'][0]['sourceLog']).write_text(
        source_log(f'{1:032x}',f'{17:032x}','r0',20000)))
    run('wrong payload', False, lambda s: change_source(s, 'payload=exact', 'payload=wrong'))
    run('wrong destination echo', False, lambda s: change_destination(s, 'payload=exact', 'payload=wrong'))
    run('wrong echo session', False, lambda s: change_destination(s, 'session=sr0', 'session=other'))
    run('wrong echo peer', False, lambda s: change_destination(s, f'peer={1:032x}', 'peer='+'f'*32))
    run('retain earlier shared session', True, lambda s: pathlib.Path(s['routes'][0]['sourceLog']).write_text(
        files[pathlib.Path(s['routes'][0]['sourceLog'])] + source_log(f'{1:032x}',f'{17:032x}','later',20000)))
print('PASS: graph observer positive stages and independent adversarial cases')
