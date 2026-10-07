#!/usr/bin/env python3
"""Exercise the actual offline evidence checker with positive and negative logs."""
import ast,json,pathlib,sys,tempfile,time
from unittest.mock import patch
source=pathlib.Path(__file__).with_name('prodigy_dev_cousin_session_observe.py')
tree=ast.parse(source.read_text(),filename=str(source))
for node in tree.body:
 if isinstance(node,ast.FunctionDef) and node.name=='logs':
  node.body=[ast.Return(ast.Name('_fixture_logs',ast.Load()))]
ast.fix_missing_locations(tree); code=compile(tree,str(source),'exec')
request='cousin_session_probe.request request=r source=fd00::1 sourcePort=45000 monotonicMs=1100\n'
rounds=''.join(f'cousin_session_probe.round request=r session=s peer=p payload=exact monotonicMs={1200+i*2200}\n' for i in range(7))
renew='cousin_session_probe.renew request=r session=s generation=2 monotonicMs=4500\n'
revoke='cousin_session_probe.revoke request=r session=s generation=3 monotonicMs=15100\ncousin_session_probe.closed session=s monotonicMs=15100\n'
retry='cousin_session_probe.request request=r2 source=fd00::1 sourcePort=45000 monotonicMs=16100\n'
reject='cousin_session_probe.reject request=r2 generation=1 monotonicMs=16101\n'
cases=[('qualifies_with_renewal','qualify',request+rounds+renew,0),('rejects_traffic_without_renewal','qualify',request+rounds,1),('revocation_events_before_completion_marker','revoked',revoke+retry+reject,0),('rejects_silence_without_explicit_denial','revoked',revoke+retry,1),('rejects_post_revoke_payload','revoked',revoke+retry+reject+'cousin_session_probe.round request=r session=s payload=exact monotonicMs=18000\n',1)]
results=[]
binding='cousin_session_probe.binding session=s destinationGroups=2 monotonicMs=1200\n'
cases += [('accepts_current_scaled_binding','qualify',request+rounds+renew+binding,0),('rejects_stale_group_binding','qualify',request+rounds+renew+binding.replace('destinationGroups=2','destinationGroups=1'),1)]
for name,mode,log,wanted in cases:
 with tempfile.TemporaryDirectory(prefix='cousin-observer-fixture-') as directory:
  root=pathlib.Path(directory)
  for marker,value in [('cousin-offline-start',1000),('cousin-revocation-request',15000),('cousin-revoked',16000)]:
   (root/(marker+'-ms')).write_text(str(value)); (root/(marker+'-monotonic-ms')).write_text(str(value))
  (root/'cousin-service-transit.json').write_text(json.dumps({'sourceWhiteholeIPv6':'fd00::1','sourceTCPPort':45000}))
  (root/'cousin-native-session-qualified.json').write_text(json.dumps({'sourceLog':'first-1-c','sessionUUID':'s'}))
  args=[str(source),str(root),mode]
  if name in ('accepts_current_scaled_binding','rejects_stale_group_binding'): args += ['cousin-offline-start','2']
  with patch.object(time,'CLOCK_BOOTTIME',7,create=True),patch.object(sys,'argv',args),patch.object(time,'monotonic',side_effect=[0,91]),patch.object(time,'clock_gettime_ns',return_value=30000*1000000):
   try: exec(code,{'__name__':'__main__','_fixture_logs':{'first-1-c':log}})
   except SystemExit as result:
    actual=0 if result.code in (None,0) else 1
   else: raise AssertionError('observer did not exit')
  assert actual==wanted,(name,actual,wanted)
  results.append({'case':name,'passed':True})
print(json.dumps(results))
