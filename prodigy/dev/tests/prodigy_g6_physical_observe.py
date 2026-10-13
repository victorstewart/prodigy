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
def check(event):
    method,detail,status=event.get("method"),event.get("detail"),event.get("status")
    if method not in METHODS or not isinstance(detail,dict): die("unknown method or non-object detail")
    if method == "tcp-ipv4":
        if status != "pass" or detail.get("family") != 2 or not detail.get("connectSucceeded") or detail.get("payloadMatched") is not True or detail.get("sentBytes",0) <= 0 or detail.get("receivedBytes",0) <= 0: die("IPv4 TCP transcript is incomplete")
    elif method == "cousin-ipv6-session":
        if status != "pass" or detail.get("family") != 10 or not detail.get("connectSucceeded"): die("IPv6 TCP transcript is incomplete")
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
    parser=argparse.ArgumentParser(); parser.add_argument("--commit",required=True); parser.add_argument("--artifact",required=True); parser.add_argument("--row",required=True); parser.add_argument("transcript"); args=parser.parse_args()
    if not COMMIT.fullmatch(args.commit) or not SHA256.fullmatch(args.artifact) or not args.row: die("invalid verifier identity arguments")
    methods=set(); bidirectional_roles=set()
    for event in read_jsonl(args.transcript):
        identity(event,args); check(event); methods.add(event["method"])
        if event["method"] == "tcp-connect-bidirectional": bidirectional_roles.add(event["detail"]["role"])
    if "tcp-connect-bidirectional" in methods and bidirectional_roles != {"client","server"}: die("bidirectional TCP requires both client and server transcripts")
    print(json.dumps({"methods":sorted(methods),"result":"pass","row":args.row},sort_keys=True,separators=(",",":")))
try: main()
except ValueError as error: raise SystemExit("FAIL: "+str(error))
