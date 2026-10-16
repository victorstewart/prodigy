#!/usr/bin/env python3
import hashlib, json, pathlib, subprocess, sys, tempfile
ROOT=pathlib.Path(__file__).parent; OBSERVER=ROOT/'prodigy_g6_physical_observe.py'; COMMIT='a'*40; ARTIFACT='b'*64; BYO_BINARY='d'*64
def event(method, detail, status='pass'):
 return {'schemaVersion':1,'candidateCommit':COMMIT,'artifactSHA256':ARTIFACT,'row':'cloud-to-cloud','monotonicNs':1,'observedAt':'2026-10-13T00:00:00Z','method':method,'status':status,'detail':detail}
def snapshot(commands):
 body={'schemaVersion':1,'capturedAt':'2026-10-13T00:00:00Z','commands':commands}; body['sha256']=hashlib.sha256(json.dumps(body,sort_keys=True,separators=(',',':')).encode()).hexdigest(); return body
CHALLENGE='c'*64
events=[event('tcp-connect-bidirectional',{'connectSucceeded':True,'payloadMatched':True,'role':'client'}),event('tcp-connect-bidirectional',{'receivedBytes':1,'sentBytes':1,'role':'server'}),event('tcp-ipv4',{'family':2,'connectSucceeded':True,'payloadMatched':True,'sentBytes':1,'receivedBytes':1}),event('cousin-ipv6-session',{'family':10,'connectSucceeded':True}),event('ingress-relay-reverse-connect',{'reverseIngress':True,'connectSucceeded':True}),event('tcp-payload-path-mtu',{'pmtuProven':True,'pathMtu':1500}),event('dns-ttl-cache-expiry',{'firstTTL':30,'secondTTL':30,'cacheExpired':True}),event('tls13-sni-mutual-identity',{'negotiatedVersion':'TLSv1.3','sni':'g6.example','serverAcceptedClientIdentity':True}),event('prodigy-service-lookup',{'service':'g6','resolvedAddress':'2001:db8::1','lookupSource':'prodigy'}),event('host-network-before-after',{'before':snapshot({'ip-route':'x'}),'after':snapshot({'ip-route':'x'})}),event('byo-ipv6-wormhole-ingress',{'challenge':CHALLENGE,'challengeMatched':True,'family':10,'peerAddress':'2602:fac0::1','peerIsByoPrefix':True,'targetAddress':'2602:fac0::1','targetPort':443}),event('byo-ipv6-whitehole-egress-source',{'challenge':CHALLENGE,'challengeMatched':True,'expectedSourceAddress':'2602:fac0::2','family':10,'peerAddress':'2602:fac0::2','peerIsByoPrefix':True,'listenPort':443})]
with tempfile.TemporaryDirectory() as directory:
 path=pathlib.Path(directory)/'evidence.jsonl'; path.write_text(''.join(json.dumps(x,sort_keys=True,separators=(',',':'))+'\n' for x in events))
 whitehole_log=pathlib.Path(directory)/'container.log'; whitehole_log.write_text(f'g6_byo_trace assigned=2602:fac0::2 observed=2602:fac0::2 challenge={CHALLENGE} candidateCommit={COMMIT} row=cloud-to-cloud binarySHA256={BYO_BINARY}\n')
 command=[sys.executable,str(OBSERVER),'--commit',COMMIT,'--artifact',ARTIFACT,'--row','cloud-to-cloud','--challenge',CHALLENGE,str(path)]
 assert subprocess.run(command,text=True,capture_output=True).returncode==0
 required=command[:-1]+['--require-byo-ipv6',str(path)]
 assert subprocess.run(required,text=True,capture_output=True).returncode==0
 assert subprocess.run(command[:-3]+[str(path)],text=True,capture_output=True).returncode!=0
 ingress_only=pathlib.Path(directory)/'ingress.jsonl'; ingress_only.write_text(json.dumps(events[-2])+'\n')
 ingress_required=command[:-1]+['--require-byo-ipv6','--byo-whitehole-log',str(whitehole_log),'--byo-binary-sha256',BYO_BINARY,str(ingress_only)]
 assert subprocess.run(ingress_required,text=True,capture_output=True).returncode==0
 assert subprocess.run(command[:-1]+['--require-byo-ipv6',str(ingress_only)],text=True,capture_output=True).returncode!=0
 whitehole_log.write_text(f'g6_byo_trace assigned=2602:fac0::2 observed=2602:fac0::3 challenge={CHALLENGE} candidateCommit={COMMIT} row=cloud-to-cloud binarySHA256={BYO_BINARY}\n')
 assert subprocess.run(ingress_required,text=True,capture_output=True).returncode!=0
 whitehole_log.write_text(f'g6_byo_trace assigned=2602:fac0::2 observed=2602:fac0::2 challenge={CHALLENGE} candidateCommit={COMMIT} row=cloud-to-cloud binarySHA256={BYO_BINARY}\n')
 events[-1]['detail']['peerAddress']='2001:db8::2'; path.write_text(''.join(json.dumps(x)+'\n' for x in events)); assert subprocess.run(command,text=True,capture_output=True).returncode!=0
 events[-1]['detail']['peerAddress']='2602:fac0::2'
 events[5]['detail']['pmtuProven']=False; path.write_text(''.join(json.dumps(x)+'\n' for x in events)); assert subprocess.run(command,text=True,capture_output=True).returncode!=0
print('prodigy_g6_physical_observe_unit: PASS')
