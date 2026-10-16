#!/usr/bin/env python3
"""Fail-closed verifier for canonical G6 physical-probe JSONL transcripts.

It is deliberately read-only: it reads transcripts and optional before/after
network snapshots; it never opens a socket or runs a command.
"""
import argparse, hashlib, ipaddress, json, re, sys
from datetime import datetime

SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
METHODS = {"tcp-connect-bidirectional", "ingress-relay-reverse-connect", "tcp-ipv4",
           "cousin-ipv6-session", "tcp-payload-path-mtu", "dns-ttl-cache-expiry",
           "tls13-sni-mutual-identity", "prodigy-service-lookup", "host-network-before-after"}
METHODS |= {"byo-ipv6-wormhole-ingress", "byo-ipv6-whitehole-egress-source"}
BYO_PREFIX = ipaddress.IPv6Network("2602:fac0::/40")
BYO_TRACE = re.compile(
    r"(?:^|\s)g6_byo_trace assigned=([^\s]+) observed=([^\s]+) "
    r"challenge=([0-9a-f]{64}) candidateCommit=([0-9a-f]{40}) "
    r"row=([A-Za-z0-9._-]{1,64}) binarySHA256=([0-9a-f]{64})(?:\s|$)")

def die(message): raise ValueError(message)
def stamp(value):
    try: return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError): die("observedAt must be ISO-8601 with timezone")
def identity(event, args):
    if event.get("schemaVersion") != 1 or event.get("candidateCommit") != args.commit or event.get("artifactSHA256") != args.artifact or event.get("row") != args.row: die("candidate/artifact/row identity mismatch")
    if not isinstance(event.get("monotonicNs"), int) or event["monotonicNs"] <= 0: die("missing positive monotonicNs")
    stamp(event.get("observedAt"))
def read_jsonl(path):
    events=[]
    for number,line in enumerate(open(path, encoding="utf-8"), 1):
        try: value=json.loads(line)
        except json.JSONDecodeError as error: die(f"{path}:{number}: invalid JSON: {error.msg}")
        if not isinstance(value,dict): die(f"{path}:{number}: event must be object")
        events.append(value)
    if not events: die("empty transcript")
    return events
def verify_network_snapshot(before, after):
    required={"schemaVersion", "capturedAt", "commands", "sha256"}
    for label,value in (("before",before),("after",after)):
        if set(value) != required or value["schemaVersion"] != 1 or not isinstance(value["commands"],dict) or not SHA256.fullmatch(value["sha256"]): die(f"invalid {label} host network snapshot")
        canonical=json.dumps({k:value[k] for k in ("schemaVersion","capturedAt","commands")},sort_keys=True,separators=(",",":" )).encode()
        if hashlib.sha256(canonical).hexdigest()!=value["sha256"]: die(f"{label} snapshot digest mismatch")
        stamp(value["capturedAt"])
    if before["commands"] != after["commands"]: die("host network mutation observed")
def verify_byo_whitehole_log(path, args):
    matches=[]
    for line in open(path, encoding="utf-8", errors="strict"):
        match=BYO_TRACE.search(line)
        if match: matches.append(match.groups())
    if len(matches) != 1: die("BYO Whitehole proof requires exactly one external-trace success")
    assigned,observed,challenge,commit,row,binary=matches[0]
    try:
        assigned_ip=ipaddress.IPv6Address(assigned); observed_ip=ipaddress.IPv6Address(observed)
    except ipaddress.AddressValueError: die("BYO Whitehole external trace contains an invalid IPv6 address")
    if assigned_ip not in BYO_PREFIX or observed_ip not in BYO_PREFIX or assigned_ip != observed_ip:
        die("BYO Whitehole external trace does not prove the assigned in-prefix source")
    if challenge != args.challenge or commit != args.commit or row != args.row or binary != args.byo_binary_sha256:
        die("BYO Whitehole external trace identity does not match this rollout")
    return assigned_ip.compressed
def check(event):
    method,detail,status=event.get("method"),event.get("detail"),event.get("status")
    if method not in METHODS or not isinstance(detail,dict): die("unknown method or non-object detail")
    if method == "tcp-ipv4":
        if status != "pass" or detail.get("family") != 2 or not detail.get("connectSucceeded") or detail.get("payloadMatched") is not True or detail.get("sentBytes",0) <= 0 or detail.get("receivedBytes",0) <= 0: die("IPv4 TCP transcript is incomplete")
    elif method == "cousin-ipv6-session":
        if status != "pass" or detail.get("family") != 10 or not detail.get("connectSucceeded"): die("IPv6 TCP transcript is incomplete")
    elif method == "byo-ipv6-wormhole-ingress":
        target, peer = detail.get("targetAddress"), detail.get("peerAddress")
        try: target_ok = ipaddress.IPv6Address(target) in BYO_PREFIX; peer_ok = ipaddress.IPv6Address(peer) in BYO_PREFIX
        except ipaddress.AddressValueError: target_ok = peer_ok = False
        if status != "pass" or detail.get("family") != 10 or not target_ok or not peer_ok or target != peer or detail.get("peerIsByoPrefix") is not True or detail.get("challengeMatched") is not True or not SHA256.fullmatch(detail.get("challenge", "")): die("BYO IPv6 Wormhole ingress transcript is incomplete")
    elif method == "byo-ipv6-whitehole-egress-source":
        expected, peer = detail.get("expectedSourceAddress"), detail.get("peerAddress")
        try: expected_ok = ipaddress.IPv6Address(expected) in BYO_PREFIX; peer_ok = ipaddress.IPv6Address(peer) in BYO_PREFIX
        except ipaddress.AddressValueError: expected_ok = peer_ok = False
        if status != "pass" or detail.get("family") != 10 or not expected_ok or not peer_ok or expected != peer or detail.get("peerIsByoPrefix") is not True or detail.get("challengeMatched") is not True or not SHA256.fullmatch(detail.get("challenge", "")): die("BYO IPv6 Whitehole source transcript is incomplete")
    elif method == "tcp-connect-bidirectional":
        if status != "pass" or (detail.get("role") == "client" and (not detail.get("connectSucceeded") or detail.get("payloadMatched") is not True)) or detail.get("role") not in {"client","server"}: die("TCP connect transcript is incomplete")
    elif method == "ingress-relay-reverse-connect":
        if status != "pass" or detail.get("reverseIngress") is not True or not detail.get("connectSucceeded"): die("reverse-ingress transcript is incomplete")
    elif method == "tcp-payload-path-mtu":
        # TCP send/receive alone cannot prove PMTU discovery; require explicit kernel evidence.
        if status != "pass" or detail.get("pmtuProven") is not True or not isinstance(detail.get("pathMtu"),int): die("TCP payload transcript does not prove PMTU")
    elif method == "dns-ttl-cache-expiry":
        if status != "pass" or not isinstance(detail.get("firstTTL"),int) or not isinstance(detail.get("secondTTL"),int) or detail.get("cacheExpired") is not True: die("DNS transcript does not prove TTL/cache expiry")
    elif method == "tls13-sni-mutual-identity":
        if status != "pass" or detail.get("negotiatedVersion") != "TLSv1.3" or not detail.get("sni") or detail.get("serverAcceptedClientIdentity") is not True: die("TLS transcript does not prove TLS1.3 SNI mutual identity")
    elif method == "prodigy-service-lookup":
        if status != "pass" or not detail.get("service") or not detail.get("resolvedAddress") or not detail.get("lookupSource") == "prodigy": die("service lookup transcript is incomplete")
    elif method == "host-network-before-after":
        if status != "pass" or not isinstance(detail.get("before"),dict) or not isinstance(detail.get("after"),dict): die("host-network transcript missing snapshots")
        verify_network_snapshot(detail["before"],detail["after"])
def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--commit",required=True); parser.add_argument("--artifact",required=True); parser.add_argument("--row",required=True); parser.add_argument("--challenge"); parser.add_argument("--require-byo-ipv6",action="store_true"); parser.add_argument("--byo-whitehole-log"); parser.add_argument("--byo-binary-sha256"); parser.add_argument("transcript"); args=parser.parse_args()
    if not COMMIT.fullmatch(args.commit) or not SHA256.fullmatch(args.artifact) or not args.row or (args.challenge is not None and not SHA256.fullmatch(args.challenge)) or (args.byo_binary_sha256 is not None and not SHA256.fullmatch(args.byo_binary_sha256)): die("invalid verifier identity arguments")
    methods=set(); bidirectional_roles=set(); events=read_jsonl(args.transcript)
    for event in events:
        identity(event,args); check(event); methods.add(event["method"])
        if event["method"] == "tcp-connect-bidirectional": bidirectional_roles.add(event["detail"]["role"])
    if "tcp-connect-bidirectional" in methods and bidirectional_roles != {"client","server"}: die("bidirectional TCP requires both client and server transcripts")
    proof_methods={"byo-ipv6-wormhole-ingress", "byo-ipv6-whitehole-egress-source"}
    if methods & proof_methods and (args.challenge is None or any(event["detail"].get("challenge") != args.challenge for event in events if event["method"] in proof_methods)): die("BYO IPv6 proof requires its expected one-time challenge")
    if args.byo_whitehole_log and args.byo_binary_sha256 is None: die("BYO Whitehole log verification requires its executable SHA-256")
    whitehole_address=verify_byo_whitehole_log(args.byo_whitehole_log,args) if args.byo_whitehole_log else None
    if args.require_byo_ipv6:
        if args.challenge is None or "byo-ipv6-wormhole-ingress" not in methods:
            die("BYO IPv6 rollout requires challenged Wormhole ingress")
        if "byo-ipv6-whitehole-egress-source" not in methods and whitehole_address is None:
            die("BYO IPv6 rollout requires independent Whitehole source observation")
    result={"methods":sorted(methods),"result":"pass","row":args.row}
    if whitehole_address is not None: result["whiteholeAddress"]=whitehole_address
    print(json.dumps(result,sort_keys=True,separators=(",",":")))
try: main()
except ValueError as error: raise SystemExit("FAIL: "+str(error))
