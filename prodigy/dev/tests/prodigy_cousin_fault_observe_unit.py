#!/usr/bin/env python3
"""Independent provider-witness fixtures; graph windows have a separate unit."""
import json
import pathlib
import tempfile
from prodigy_dev_cousin_fault_observe import pair_interval, region_interval, seal_audit


def reject(fn, *args):
    try:
        fn(*args)
    except ValueError:
        return
    raise AssertionError('invalid witness accepted')


for direction in ('both', 'first-to-second', 'second-to-first'):
    field = '' if direction == 'both' else (' direction=' + direction +
        (' installRule=first0-to-second0-DROP restoreRule=first0-to-second0-ABSENT'
         if direction == 'first-to-second' else
         ' installRule=second0-to-first0-DROP restoreRule=second0-to-first0-ABSENT'))
    receipt = ('PAIR_CONTROL_FAULT operationID=0x1234 clock=CLOCK_BOOTTIME delayMs=0 durationMs=45000' +
               field + ' beginNs=1000000000 endNs=46000000000')
    assert pair_interval(receipt, '0x1234', direction) == (1000, 46000)
    reject(pair_interval, receipt, '0x1235', direction)
    reject(pair_interval, receipt + '\n' + receipt, '0x1234', direction)
    for old, new in [('CLOCK_BOOTTIME','CLOCK_REALTIME'), ('delayMs=0','delayMs=1'),
                     ('durationMs=45000','durationMs=44999'), ('46000000000','45999999999'),
                     ('46000000000','51000000001')]:
        reject(pair_interval, receipt.replace(old, new), '0x1234', direction)
    reject(pair_interval, receipt + ' extra=1', '0x1234', direction)
    if direction != 'both':
        reject(pair_interval, receipt.replace('restoreRule=', 'restoredRule='), '0x1234', direction)
        reject(pair_interval, receipt.replace('DROP', 'ABSENT', 1), '0x1234', direction)
    reject(pair_interval, receipt, '0x1234', 'invalid')

lines = [f'fault-link runtime=12 link=vp{i} state={state} atMs={at+100000} monotonicMs={at}'
         for state, base in [('down',1000),('up',46002)] for i in (1,2,3) for at in [base+i]]
receipt = '\n'.join(lines)
assert region_interval(receipt) == (1003,46003)
reject(region_interval, '\n'.join(lines[:-1]))
reject(region_interval, receipt + '\n' + lines[0])
reject(region_interval, receipt.replace('link=vp3','link=vp2'))
reject(region_interval, receipt.replace('runtime=12','runtime=13',1))
reject(region_interval, receipt.replace('monotonicMs=46003','monotonicMs=1003'))
reject(region_interval, receipt.replace('monotonicMs=', 'other='))
with tempfile.TemporaryDirectory() as directory:
    root=pathlib.Path(directory); (root/'receipts').mkdir()
    (root/'f-sealed-ms').write_text('1000'); (root/'f-completed-ms').write_text('50000')
    row={'label':'f','operation':'testClusterPairControl','status':0,'startedMs':900,'endedMs':49000}
    (root/'receipts/f.json').write_text(json.dumps(row))
    assert seal_audit(root,'f')['ordinaryCalls']==0
    (root/'receipts/ordinary.json').write_text(json.dumps(dict(row,label='report',operation='clusterReport')))
    reject(seal_audit,root,'f')
print('PASS: exact bounded fault witnesses and sealed Mothership observation audit')

# Exercise the real fault qualification path, independently constructing six
# native streams and checking both surviving and disrupted route evidence.
from prodigy_dev_cousin_fault_observe import qualify
with tempfile.TemporaryDirectory() as directory:
    root=pathlib.Path(directory); (root/'receipts').mkdir(); (root/'cousin-native-logs').mkdir()
    (root/'f-sealed-ms').write_text('1000'); (root/'f-completed-ms').write_text('50000')
    (root/'f-sealed-monotonic-ms').write_text('1000')
    row={'label':'f','operation':'testClusterPairControl','status':0,'startedMs':900,'endedMs':49000}
    (root/'receipts/f.json').write_text(json.dumps(row))
    (root/'f.log').write_text('PAIR_CONTROL_FAULT operationID=0x1234 clock=CLOCK_BOOTTIME delayMs=0 durationMs=45000 beginNs=1000000000 endNs=46000000000\n')
    routes=[]
    for i,name in enumerate(('ab','ba','ac','ca','bc','cb')):
        uuid,peer=f'{i+1:032x}',f'{i+17:032x}'
        source=root/(name+'-native.log');dest=root/(name+'-echo.log')
        source.write_text(f'cousin_session_probe.ready uuid={uuid} deployment=9 source=1\n'
                          f'cousin_session_probe.request request=r{i} source=fd00::1 sourcePort=45000 monotonicMs=500\n'+
                          ''.join(f'cousin_session_probe.round request=r{i} session=s{i} peer={peer} payload=exact monotonicMs={2000+j*2200}\n' for j in range(7) if i>=2)+
                          f'cousin_session_probe.renew request=r{i} session=s{i} generation=2 monotonicMs=5000\n')
        dest.write_text(f'cousin_session_probe.ready uuid={peer} deployment=19 source=0\n'
                        f'cousin_session_probe.echo peer={uuid} session=s{i} monotonicMs=5000 payload=exact\n')
        routes.append({'name':name,'sourceLog':str(source),'sourceUUID':uuid,'sourceDeploymentID':9,
                       'sourceTuple':['fd00::1',45000],'destinationUUIDs':[peer],
                       'destinationLogs':[{'path':str(dest),'uuid':peer,'deploymentID':19}],'afterMonotonicMs':0})
    (root/'f-before-spec.json').write_text(json.dumps({'routes':routes,'minimumWindowMs':12000,'timeoutSeconds':0}))
    qualify(root,'f','pair','0x1234','both')
    with (root/'ab-native.log').open('a') as out:
        out.write('cousin_session_probe.round request=r0 session=s0 peer=11 payload=exact monotonicMs=20000\n')
    reject(qualify,root,'f','pair','0x1234','both')

# Use the native driver's embedded controller oracle, with independent report,
# manifest and provider-crash fixtures. No fake lifecycle actions are performed.
import re
import subprocess
import sys
source=pathlib.Path(__file__).with_name('prodigy_dev_cousin_fault_qualification.sh').read_text()
assert 'if [[ $# == 2 ]]; then' in source
assert 'faultTestClusters' in source
assert '"${CLUSTERS[$first_label]}" "$first_index"' in source
quorum=re.search(r"<<'PY_QUORUM'\n(.*?)\nPY_QUORUM",source,re.S).group(1)
during=re.search(r"<<'PY_DURING'\n(.*?)\nPY_DURING",source,re.S).group(1)
master=re.search(r"<<'PY_MASTER'\n(.*?)\nPY_MASTER",source,re.S).group(1)

# Execute the driver's exact per-label membership ledger rather than mirroring
# its parsing. A later observation may cover a subset, but every label must
# retain the identities captured once at initial qualification.
with tempfile.TemporaryDirectory() as directory:
    root=pathlib.Path(directory)
    memberships={'a':('0xa1','0xa2','0xa3'), 'b':('0xb1','0xb2','0xb3'), 'c':('0xc1','0xc2','0xc3')}
    def report(phase,label,ids):
        (root/f'{phase}-{label}-cluster-report.log').write_text(
            ''.join(f'Machine: state=healthy\n identity uuid={identity} state=owned\n' for identity in ids))
    def execute(phase, labels, expected):
        result=subprocess.run([sys.executable,'-c',quorum,str(root),phase,*labels],capture_output=True,text=True)
        assert (result.returncode==0)==expected,(phase,labels,result.stderr)
    for label,ids in memberships.items(): report('initial',label,ids)
    execute('initial',('a','b','c'),True)
    assert json.loads((root/'initial-quorums.json').read_text())=={
        label:sorted(str(int(identity,16)) for identity in ids) for label,ids in memberships.items()}
    for label in ('a','b'):
        report('subset',label,memberships[label])
    execute('subset',('a','b'),True)
    for label,ids in memberships.items(): report('recovered',label,ids)
    execute('recovered',('a','b','c'),True)

    report('foreign','a',('0xd1','0xd2','0xd3'))
    execute('foreign',('a',),False)
    report('swapped','a',memberships['b']); report('swapped','b',memberships['a'])
    execute('swapped',('a','b'),False)
    report('duplicates','a',('0xa1','0xa1','0xa2'))
    execute('duplicates',('a',),False)
    report('invalid-count','a',('0xa1','0xa2','0xa3','0xa4'))
    execute('invalid-count',('a',),False)

with tempfile.TemporaryDirectory() as directory:
    root=pathlib.Path(directory)
    (root/'missing-a-cluster-report.log').write_text('Machine:\n identity uuid=0xa1 state=owned\nMachine:\n identity uuid=0xa2 state=owned\nMachine:\n identity uuid=0xa3 state=owned\n')
    result=subprocess.run([sys.executable,'-c',quorum,str(root),'missing','a'],capture_output=True,text=True)
    assert result.returncode != 0, result.stderr

with tempfile.TemporaryDirectory() as directory:
    root=pathlib.Path(directory)
    before=root/'before.log'; active=root/'active.log'; selected=root/'selected.json'
    output=root/'during-qualified.json'; receipt=root/'receipt.json'
    def reset_during():
        before.write_text(
            'Machine: state=healthy role=brain\n identity uuid=0xa\n lifecycle controlPlaneReachable=1 runtimeReady=1 currentMaster=1\n'
            'Machine: state=healthy role=brain\n identity uuid=0xb\n lifecycle controlPlaneReachable=1 runtimeReady=1 currentMaster=0\n'
            'Machine: state=healthy role=brain\n identity uuid=0xc\n lifecycle controlPlaneReachable=1 runtimeReady=1 currentMaster=0\n')
        active.write_text(
            'Machine: state=unresponsive role=brain\n identity uuid=0xa\n lifecycle controlPlaneReachable=0 runtimeReady=0 currentMaster=0\n'
            'Machine: state=healthy role=brain\n identity uuid=0xb\n lifecycle controlPlaneReachable=1 runtimeReady=0 currentMaster=1\n'
            'Machine: state=healthy role=brain\n identity uuid=0xc\n lifecycle controlPlaneReachable=1 runtimeReady=0 currentMaster=0\n')
        selected.write_text(json.dumps({'index':1,'uuid':'0xa','boot':'100','pid':22}))
        receipt.write_text(json.dumps({'label':'report-f-a-during','operation':'clusterReport','status':0,
                                       'startedMs':1001,'endedMs':10900}))
        if output.exists(): output.unlink()
    def check_during(expected, edit=lambda:None):
        reset_during(); edit()
        result=subprocess.run([sys.executable,'-c',during,str(before),str(active),str(selected),str(output),
                               str(receipt),'1000','11500'],capture_output=True,text=True)
        assert (result.returncode==0)==expected,result.stderr
        return json.loads(output.read_text()) if expected else None
    valid=check_during(True)
    assert valid['survivingMaster']=='0xb' and valid['survivors']['0xb']['runtimeReady']==0
    check_during(False,lambda:active.write_text(active.read_text().replace(
        'state=unresponsive role=brain\n identity uuid=0xa\n lifecycle controlPlaneReachable=0',
        'state=healthy role=brain\n identity uuid=0xa\n lifecycle controlPlaneReachable=1')))
    check_during(False,lambda:active.write_text(active.read_text().replace(
        'identity uuid=0xc\n lifecycle controlPlaneReachable=1',
        'identity uuid=0xc\n lifecycle controlPlaneReachable=0')))
    check_during(False,lambda:active.write_text(active.read_text().replace('runtimeReady=0 currentMaster=1','runtimeReady=0 currentMaster=0')))
    check_during(False,lambda:receipt.write_text(json.dumps(
        {'operation':'clusterReport','status':0,'startedMs':999,'endedMs':10900})))
    check_during(False,lambda:receipt.write_text(json.dumps(
        {'operation':'clusterReport','status':0,'startedMs':1001,'endedMs':11500})))
    check_during(False,lambda:active.write_text(active.read_text().replace('identity uuid=0xc','identity uuid=0xd')))

with tempfile.TemporaryDirectory() as directory:
    root=pathlib.Path(directory)
    def fixture(label, workspace, old, new, timestamp):
        (root/workspace).mkdir(exist_ok=True)
        selected={'index':1,'uuid':old,'boot':'100','pid':22}
        (root/f'f-{label}-selected.json').write_text(json.dumps(selected))
        before=''.join(f'Machine: state=healthy role=brain\n identity uuid={uuid}\n'
                       for uuid in (old,new,'0xff'))
        (root/f'f-{label}-before-cluster-report.log').write_text(before)
        report=''.join(f'Machine: state=healthy role=brain\n identity uuid={uuid}\n lifecycle controlPlaneReachable=1 runtimeReady=1 currentMaster={int(i==1)} bootTimeMs={boot}\n'
                       for i,(uuid,boot) in enumerate([(old,200),(new,100),('0xff',100)]))
        (root/f'f-{label}-after-cluster-report.log').write_text(report)
        (root/f'f-{label}-during-qualified.json').write_text(json.dumps(
            {'selected':selected,'survivingMaster':new}))
        (root/workspace/'test-cluster-manifest.json').write_text(json.dumps({'nodes':[{'index':1,'pid':23}]}))
        (root/workspace/'fault-events.log').write_text(f'fault-crash runtime=10 machine=1 atMs=100000 monotonicMs={timestamp}\n')
    def reset():
        (root/'f-started-monotonic-ms').write_text('1000')
        fixture('a','first-workspace','0xaa','0xab',1001)
        fixture('b','second-workspace','0xba','0xbb',1002)
        receipts=root/'receipts'; receipts.mkdir(exist_ok=True)
        for path in receipts.iterdir(): path.unlink()
        (receipts/'f-faults-1000.json').write_text(json.dumps(
            {'label':'f-faults','operation':'faultTestClusters','status':0,
             'startedMs':1000,'endedMs':13000}))
    def check(expected, edit=lambda:None):
        reset();edit()
        result=subprocess.run([sys.executable,'-c',master,str(root),'f','a','b'],capture_output=True,text=True)
        assert (result.returncode==0)==expected,result.stderr
    def replace(path,old,new):
        p=root/path;p.write_text(p.read_text().replace(old,new))
    check(True)
    check(False,lambda:replace('f-a-after-cluster-report.log','bootTimeMs=200','bootTimeMs=100'))
    check(False,lambda:replace('first-workspace/test-cluster-manifest.json','23','22'))
    check(False,lambda:replace('second-workspace/fault-events.log','monotonicMs=1002','monotonicMs=15000'))
    check(False,lambda:replace('first-workspace/fault-events.log','machine=1','machine=2'))
    check(False,lambda:replace('f-a-after-cluster-report.log','currentMaster=0 bootTimeMs=200','currentMaster=1 bootTimeMs=200'))
    check(False,lambda:(root/'receipts'/'f-faults-1000.json').write_text(json.dumps(
        {'label':'f-faults','operation':'faultTestCluster','status':0})))
    check(False,lambda:(root/'receipts'/'f-a-fault-1001.json').write_text(json.dumps(
        {'label':'f-a-fault','operation':'faultTestCluster','status':0})))
    check(False,lambda:(root/'receipts'/'f-faults-1000.json').write_text(json.dumps(
        {'label':'f-faults','operation':'faultTestClusters','status':1})))
print('PASS: native graph outage and independent/concurrent controller recovery oracles')
