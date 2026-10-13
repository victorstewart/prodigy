#!/usr/bin/env python3
"""Positive and adversarial self-tests for the offline G6 preflight contract."""
import copy
import datetime
import importlib.util
import pathlib


VALIDATOR = pathlib.Path(__file__).with_name("prodigy_g6_preflight.py")
SPEC = importlib.util.spec_from_file_location("prodigy_g6_preflight", VALIDATOR)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
HASH = "a" * 64


def baseline():
    return {
        "schemaVersion": 1, "phase": "G6", "result": "planned", "testOnly": False,
        "candidate": {"commit": "b" * 40, "binaries": {"prodigy": HASH, "mothership": "c" * 64},
                      "bundleSHA256": "d" * 64,
                      "applicationArtifact": {"sha256": "e" * 64, "discombobulator": {
                          "kind": "app", "contractVersion": "v1", "contractHeaderSHA256": "f" * 64,
                          "buildReceiptSHA256": "1" * 64}}},
        "supportedArchitectures": ["x86_64"], "supportedProtocols": ["aegis-x25519-v1"],
        "budget": {"previousSpentUSD": 2.0, "currentEstimateUSD": 20.0, "totalCapUSD": 25.0},
        "credentialReferences": [{"reference": "keychain://g6/vultr", "containsSecret": False}],
        "clusters": [
            {"id": "lan", "region": "lan-vm-a", "siteKind": "lan", "provider": "local-kvm", "failureDomain": "lan-vm-a", "isolation": "vm-isolated", "architecture": "x86_64", "protocol": "aegis-x25519-v1", "deploymentMode": "local"},
            {"id": "vultr", "region": "ewr", "siteKind": "cloud", "provider": "vultr", "failureDomain": "vultr-ewr", "architecture": "x86_64", "protocol": "aegis-x25519-v1", "deploymentMode": "remote"},
            {"id": "cloud", "region": "ord", "siteKind": "cloud", "provider": "vultr", "failureDomain": "vultr-ord", "architecture": "x86_64", "protocol": "aegis-x25519-v1", "deploymentMode": "remote"}],
        "physicalRows": [{"kind": "vm-isolated-lan-to-vultr", "sourceCluster": "lan", "targetCluster": "vultr"},
                         {"kind": "cloud-to-cloud", "sourceCluster": "vultr", "targetCluster": "cloud"}],
        "mothershipOperations": {"owner": "Mothership", "lifecycle": ["createCluster", "clusterReport", "removeCluster"],
                                  "faults": ["faultRemoteCloudMachine", "faultLocalClusterMachine", "faultClusterNetwork"],
                                  "cleanup": ["cousinRoute", "removeCluster"]},
        "deadlinesSeconds": {"preflight": 60, "operation": 1800, "faultRecovery": 900, "cleanup": 900},
        "postCleanup": {"residualInventories": [
            {"resource": "instances", "queryReference": "vultr://instances/g6", "expectedAfterCount": 0},
            {"resource": "vpcs", "queryReference": "vultr://vpcs/g6", "expectedAfterCount": 0},
            {"resource": "blocks", "queryReference": "vultr://blocks/g6", "expectedAfterCount": 0},
            {"resource": "ips", "queryReference": "vultr://ips/g6", "expectedAfterCount": 0}]}}


def expect_reject(label, mutate):
    plan = baseline(); mutate(plan)
    try:
        MODULE.validate(plan)
    except MODULE.ContractError:
        return
    raise AssertionError(f"accepted adversarial plan: {label}")


assert MODULE.validate(baseline())  # planned is a preflight only, never a passing claim


def passing_plan():
    plan = baseline(); plan["result"] = "pass"
    plan["budget"]["actualSpentUSD"] = 19.0
    start, end, after = "2026-10-12T00:00:00Z", "2026-10-12T01:00:00Z", "2026-10-12T01:01:00Z"
    identities = {"commit": plan["candidate"]["commit"], "prodigySHA256": HASH, "mothershipSHA256": "c" * 64,
                  "bundleSHA256": "d" * 64, "applicationSHA256": "e" * 64,
                  "contractHeaderSHA256": "f" * 64, "buildReceiptSHA256": "1" * 64}
    declared = {row["kind"]: row for row in plan["physicalRows"]}
    def row(kind):
        fault_operations = {
            "nominal": "cousinRoute",
            "target-master-crash": "faultRemoteCloudMachine",
            "target-cold-restart": "faultRemoteCloudMachine",
            "source-master-interruption-after-retirement-seal":
                "faultLocalClusterMachine" if kind == "vm-isolated-lan-to-vultr" else "faultRemoteCloudMachine",
        }
        faults = [{"name": name, "owner": "Mothership", "operation": fault_operations[name],
                   "receiptSHA256": "2" * 64, "timestamp": "2026-10-12T00:30:00Z"}
                  for name in sorted(MODULE.REQUIRED_FAULT_CASES)]
        boundary_checks = [
            {"name": name,
             "operation": "faultClusterNetwork" if name in {"asymmetric-partition", "full-partition"} else "clusterReport",
             "receiptSHA256": "a" * 64, "timestamp": "2026-10-12T00:25:00Z"}
            for name in sorted(MODULE.REQUIRED_BOUNDARY_CHECKS)
        ]
        return {"kind": kind, "sourceCluster": declared[kind]["sourceCluster"], "targetCluster": declared[kind]["targetCluster"],
                "startedAt": start, "completedAt": end, "evidenceIdentities": identities,
                "mothershipCommandReceipts": [{"operation": operation, "sha256": "3" * 64, "timestamp": "2026-10-12T00:20:00Z"}
                                               for operation in sorted(MODULE.REQUIRED_ROW_OPERATIONS)],
                "faultCases": faults, "boundaryChecks": boundary_checks,
                "routeObservation": {"activeReceiptSHA256": "4" * 64, "withdrawalReceiptSHA256": "5" * 64,
                                     "staleReplayRejectionSHA256": "6" * 64},
                "trafficObservation": {"requestHistorySHA256": "7" * 64, "observedAt": "2026-10-12T00:50:00Z",
                                       "zeroSourceFlowsAt": "2026-10-12T00:35:00Z", "retiredSourceAt": "2026-10-12T00:38:00Z",
                                       "heldSourceRequests": 30, "targetRequests": 5,
                                       "zeroSourceFlows": True, "retiredSourceRejected": True}}
    def completed_row(kind):
        value = row(kind)
        value["routeObservation"].update(activeAt="2026-10-12T00:10:00Z", withdrawnAt="2026-10-12T00:40:00Z", staleReplayRejectedAt="2026-10-12T00:45:00Z")
        return value
    plan["execution"] = {"startedAt": start, "completedAt": end, "rows": [completed_row("vm-isolated-lan-to-vultr"), completed_row("cloud-to-cloud")]}
    plan["postCleanup"]["verifiedAt"] = after
    for inventory in plan["postCleanup"]["residualInventories"]:
        inventory.update(beforeSHA256="8" * 64, afterSHA256="9" * 64, observedAfterCount=0)
    return plan


assert MODULE.validate(passing_plan())
expect_reject("test-only claim", lambda p: p.update(testOnly=True))
expect_reject("test deployment", lambda p: p["clusters"][0].update(deploymentMode="test"))
expect_reject("embedded API key", lambda p: p["credentialReferences"][0].update(apiKey="not-allowed"))
expect_reject("unknown credential field", lambda p: p["credentialReferences"][0].update(auth="raw-secret"))
expect_reject("embedded token assignment", lambda p: p.update(notes="VULTR_API_KEY=not-allowed"))
expect_reject("embedded PEM", lambda p: p.update(notes="-----BEGIN PRIVATE KEY-----"))
expect_reject("overspend", lambda p: p["budget"].update(currentEstimateUSD=24.0))
expect_reject("missing cloud row", lambda p: p["physicalRows"].pop())
expect_reject("duplicate physical row", lambda p: p["physicalRows"].append(copy.deepcopy(p["physicalRows"][0])))
expect_reject("same cloud region", lambda p: p["clusters"][2].update(region="ewr"))
expect_reject("unsupported protocol", lambda p: p["clusters"][1].update(protocol="udp"))
expect_reject("declared arbitrary protocol", lambda p: (p.update(supportedProtocols=["udp"]), [cluster.update(protocol="udp") for cluster in p["clusters"]]))
expect_reject("non-Mothership owner", lambda p: p["mothershipOperations"].update(owner="harness"))
expect_reject("missing remote fault owner", lambda p: p["mothershipOperations"].update(faults=["harnessReboot"]))
expect_reject("invented operation owner", lambda p: p["mothershipOperations"]["faults"].append("unimplementedOperation"))
expect_reject("unbounded cleanup", lambda p: p["deadlinesSeconds"].update(cleanup=0))
expect_reject("plan-only pass", lambda p: p.update(result="pass"))
passing = passing_plan(); passing["execution"]["rows"][0]["faultCases"].pop()
try:
    MODULE.validate(passing)
except MODULE.ContractError:
    pass
else:
    raise AssertionError("accepted missing passing fault evidence")
passing = passing_plan(); passing["budget"]["actualSpentUSD"] = 24.0
try:
    MODULE.validate(passing)
except MODULE.ContractError:
    pass
else:
    raise AssertionError("accepted actual spend above the total cap")
passing = passing_plan(); passing["postCleanup"]["residualInventories"][0]["observedAfterCount"] = 1
try:
    MODULE.validate(passing)
except MODULE.ContractError:
    pass
else:
    raise AssertionError("accepted nonzero post-cleanup inventory")
passing = passing_plan(); passing["execution"]["rows"][0]["mothershipCommandReceipts"][0]["timestamp"] = "2026-10-11T23:59:59Z"
try:
    MODULE.validate(passing)
except MODULE.ContractError:
    pass
else:
    raise AssertionError("accepted out-of-window command receipt")
passing = passing_plan(); passing["execution"]["rows"][0]["routeObservation"]["withdrawnAt"] = "2026-10-12T00:05:00Z"
try:
    MODULE.validate(passing)
except MODULE.ContractError:
    pass
else:
    raise AssertionError("accepted withdrawal before active route")
passing = passing_plan(); passing["execution"]["rows"][0]["evidenceIdentities"]["buildReceiptSHA256"] = "0" * 64
try:
    MODULE.validate(passing)
except MODULE.ContractError:
    pass
else:
    raise AssertionError("accepted unrelated Discombobulator build receipt")
passing = passing_plan(); passing["execution"]["rows"][0]["boundaryChecks"].pop()
try:
    MODULE.validate(passing)
except MODULE.ContractError:
    pass
else:
    raise AssertionError("accepted incomplete physical boundary matrix")
passing = passing_plan(); passing["execution"]["rows"][0]["boundaryChecks"][0]["operation"] = "cousinRoute"
try:
    MODULE.validate(passing)
except MODULE.ContractError:
    pass
else:
    raise AssertionError("accepted incorrect Mothership owner for physical boundary evidence")
passing = passing_plan(); passing["execution"]["startedAt"] = "2026-10-12T00:00:00"
try:
    MODULE.validate(passing)
except MODULE.ContractError:
    pass
else:
    raise AssertionError("accepted timezone-free execution timestamp")
print("PASS: G6 preflight accepts only the non-secret physical-boundary contract")
