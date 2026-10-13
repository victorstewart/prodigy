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
SOURCE_MACHINE_UUIDS = {
    "vm-isolated-lan-to-vultr": "11111111111141118111111111111111",
    "cloud-to-cloud": "22222222222242228222222222222222",
}
CLIENT_MACHINE_UUIDS = {
    "vm-isolated-lan-to-vultr": "33333333333343338333333333333333",
    "cloud-to-cloud": "44444444444444448444444444444444",
}


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
                                  "transit": ["prepareProductionPair", "productionPair", "registerLocalVMBoundary"],
                                  "cleanup": ["cousinRoute", "removeCluster"]},
        "deadlinesSeconds": {"preflight": 60, "operation": 1800, "faultRecovery": 900, "cleanup": 900},
        "postCleanup": {"residualInventories": [
            {"resource": "instances", "accountQueryReference": "vultr://instances/account", "taskOwnedQueryReference": "vultr://instances?tag=g6-run", "preExistingIdentitySHA256": "8" * 64, "taskOwnedBeforeCleanupSHA256": "9" * 64, "expectedTaskOwnedAfterCount": 0},
            {"resource": "vpcs", "accountQueryReference": "vultr://vpcs/account", "taskOwnedQueryReference": "vultr://vpcs?tag=g6-run", "preExistingIdentitySHA256": "8" * 64, "taskOwnedBeforeCleanupSHA256": "9" * 64, "expectedTaskOwnedAfterCount": 0},
            {"resource": "blocks", "accountQueryReference": "vultr://blocks/account", "taskOwnedQueryReference": "vultr://blocks?tag=g6-run", "preExistingIdentitySHA256": "8" * 64, "taskOwnedBeforeCleanupSHA256": "9" * 64, "expectedTaskOwnedAfterCount": 0},
            {"resource": "ips", "accountQueryReference": "vultr://ips/account", "taskOwnedQueryReference": "vultr://ips?tag=g6-run", "preExistingIdentitySHA256": "8" * 64, "taskOwnedBeforeCleanupSHA256": "9" * 64, "expectedTaskOwnedAfterCount": 0}]}}


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
             "receiptSHA256": "a" * 64,
             "method": MODULE.BOUNDARY_OBSERVATION_METHODS[name],
             "observer": "read-only-physical-probe",
             "observationSHA256": format(observation_index + 10, "064x"),
             "passed": True, "timestamp": "2026-10-12T00:25:00Z"}
            for observation_index, name in enumerate(sorted(MODULE.REQUIRED_BOUNDARY_CHECKS))
        ]
        row_operations = set(MODULE.REQUIRED_ROW_OPERATIONS)
        if kind == "vm-isolated-lan-to-vultr":
            row_operations.add("registerLocalVMBoundary")
        return {"kind": kind, "sourceCluster": declared[kind]["sourceCluster"], "targetCluster": declared[kind]["targetCluster"],
                "startedAt": start, "completedAt": end, "sourceMachineUUID": SOURCE_MACHINE_UUIDS[kind], "evidenceIdentities": identities,
                "mothershipCommandReceipts": [{"operation": operation, "sha256": "3" * 64, "timestamp": "2026-10-12T00:20:00Z"}
                                               for operation in sorted(row_operations)],
                "faultCases": faults, "boundaryChecks": boundary_checks,
                "routeObservation": {"activeReceiptSHA256": "4" * 64, "withdrawalReceiptSHA256": "5" * 64,
                                     "staleReplayRejectionSHA256": "6" * 64},
                "trafficObservation": {"requestHistorySHA256": "7" * 64, "observedAt": "2026-10-12T00:50:00Z",
                                       "zeroSourceFlowsAt": "2026-10-12T00:35:00Z", "retiredSourceAt": "2026-10-12T00:38:00Z",
                                       "heldSourceRequests": 30, "targetRequests": 5,
                                       "zeroSourceFlows": True, "retiredSourceRejected": True},
                "ingressObservation": {
                    "sourceMachineUUID": SOURCE_MACHINE_UUIDS[kind], "ingressAddress": "203.0.113.10",
                    "ingressPort": 443, "providerRelayReceiptSHA256": "b" * 64,
                    "productionPairReceiptSHA256": "3" * 64,
                    "receivedAt": "2026-10-12T00:30:00Z", "requestHistorySHA256": "7" * 64,
                    "clientDestinationObservations": [{
                        "clientMachineUUID": CLIENT_MACHINE_UUIDS[kind], "destinationAddress": "203.0.113.10",
                        "destinationPort": 443, "ingressReceiptSHA256": "b" * 64,
                        "requestHistorySHA256": "7" * 64, "destinationObservationSHA256": "c" * 64,
                        "observedAt": "2026-10-12T00:32:00Z"}]}}
    def completed_row(kind):
        value = row(kind)
        value["routeObservation"].update(activeAt="2026-10-12T00:10:00Z", withdrawnAt="2026-10-12T00:40:00Z", staleReplayRejectedAt="2026-10-12T00:45:00Z")
        return value
    plan["execution"] = {"startedAt": start, "completedAt": end, "rows": [completed_row("vm-isolated-lan-to-vultr"), completed_row("cloud-to-cloud")]}
    plan["postCleanup"]["verifiedAt"] = after
    for inventory in plan["postCleanup"]["residualInventories"]:
        inventory.update(afterPreExistingIdentitySHA256="8" * 64, afterTaskOwnedIdentitySHA256="0" * 64, observedTaskOwnedAfterCount=0)
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
expect_reject("missing production transit owner", lambda p: p["mothershipOperations"].update(transit=["productionPair"]))
expect_reject("invented operation owner", lambda p: p["mothershipOperations"]["faults"].append("unimplementedOperation"))
expect_reject("unbounded cleanup", lambda p: p["deadlinesSeconds"].update(cleanup=0))
expect_reject("vague global cleanup count", lambda p: p["postCleanup"]["residualInventories"][0].update(expectedAfterCount=0))
expect_reject("same account and task inventory query", lambda p: p["postCleanup"]["residualInventories"][0].update(taskOwnedQueryReference="vultr://instances/account"))
expect_reject("plan-only pass", lambda p: p.update(result="pass"))
passing = passing_plan(); passing["execution"]["rows"][0]["faultCases"].pop()
try:
    MODULE.validate(passing)
except MODULE.ContractError:
    pass
else:
    raise AssertionError("accepted missing passing fault evidence")
passing = passing_plan()
passing["execution"]["rows"][0]["mothershipCommandReceipts"] = [
    receipt for receipt in passing["execution"]["rows"][0]["mothershipCommandReceipts"]
    if receipt["operation"] != "registerLocalVMBoundary"
]
try:
    MODULE.validate(passing)
except MODULE.ContractError:
    pass
else:
    raise AssertionError("accepted LAN evidence without local-VM boundary registration")
passing = passing_plan(); passing["budget"]["actualSpentUSD"] = 24.0
try:
    MODULE.validate(passing)
except MODULE.ContractError:
    pass
else:
    raise AssertionError("accepted actual spend above the total cap")
passing = passing_plan(); passing["postCleanup"]["residualInventories"][0]["observedTaskOwnedAfterCount"] = 1
try:
    MODULE.validate(passing)
except MODULE.ContractError:
    pass
else:
    raise AssertionError("accepted nonzero task-owned post-cleanup inventory")
passing = passing_plan(); passing["postCleanup"]["residualInventories"][0]["afterPreExistingIdentitySHA256"] = "0" * 64
try:
    MODULE.validate(passing)
except MODULE.ContractError:
    pass
else:
    raise AssertionError("accepted deletion or mutation of pre-existing inventory")
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
passing = passing_plan(); passing["execution"]["rows"][0]["boundaryChecks"][0]["method"] = "tcp-connect-bidirectional"
try:
    MODULE.validate(passing)
except MODULE.ContractError:
    pass
else:
    raise AssertionError("accepted a boundary claim with the wrong observation method")
passing = passing_plan(); passing["execution"]["rows"][0]["boundaryChecks"][0]["observationSHA256"] = "a" * 64
try:
    MODULE.validate(passing)
except MODULE.ContractError:
    pass
else:
    raise AssertionError("accepted a Mothership receipt relabeled as physical observation evidence")
passing = passing_plan()
passing["execution"]["rows"][0]["boundaryChecks"][1]["observationSHA256"] = \
    passing["execution"]["rows"][0]["boundaryChecks"][0]["observationSHA256"]
try:
    MODULE.validate(passing)
except MODULE.ContractError:
    pass
else:
    raise AssertionError("accepted one physical observation reused for two boundary claims")
passing = passing_plan(); passing["execution"]["rows"][0]["boundaryChecks"][0]["passed"] = False
try:
    MODULE.validate(passing)
except MODULE.ContractError:
    pass
else:
    raise AssertionError("accepted a failed physical boundary observation")
passing = passing_plan(); passing["execution"]["rows"][0].pop("ingressObservation")
try:
    MODULE.validate(passing)
except MODULE.ContractError:
    pass
else:
    raise AssertionError("accepted passing row without ingress receipt evidence")
passing = passing_plan(); passing["execution"]["rows"][0]["ingressObservation"]["ingressAddress"] = "127.0.0.1"
try:
    MODULE.validate(passing)
except MODULE.ContractError:
    pass
else:
    raise AssertionError("accepted loopback ingress evidence")
passing = passing_plan(); passing["execution"]["rows"][0]["ingressObservation"]["ingressAddress"] = "0.0.0.0"
try:
    MODULE.validate(passing)
except MODULE.ContractError:
    pass
else:
    raise AssertionError("accepted wildcard ingress evidence")
passing = passing_plan(); passing["execution"]["rows"][0]["ingressObservation"]["sourceMachineUUID"] = SOURCE_MACHINE_UUIDS["cloud-to-cloud"]
try:
    MODULE.validate(passing)
except MODULE.ContractError:
    pass
else:
    raise AssertionError("accepted ingress evidence for a different source machine")
passing = passing_plan(); passing["execution"]["rows"][0]["ingressObservation"]["clientDestinationObservations"][0]["destinationAddress"] = "203.0.113.11"
try:
    MODULE.validate(passing)
except MODULE.ContractError:
    pass
else:
    raise AssertionError("accepted client destination that did not reach the ingress relay")
passing = passing_plan(); passing["execution"]["rows"][0]["ingressObservation"]["clientDestinationObservations"][0]["ingressReceiptSHA256"] = "0" * 64
try:
    MODULE.validate(passing)
except MODULE.ContractError:
    pass
else:
    raise AssertionError("accepted client destination without provider relay receipt linkage")
passing = passing_plan(); passing["execution"]["rows"][0]["ingressObservation"]["productionPairReceiptSHA256"] = "0" * 64
try:
    MODULE.validate(passing)
except MODULE.ContractError:
    pass
else:
    raise AssertionError("accepted ingress evidence without production-pair admission linkage")
passing = passing_plan(); passing["execution"]["rows"][0]["ingressObservation"]["requestHistorySHA256"] = "0" * 64
try:
    MODULE.validate(passing)
except MODULE.ContractError:
    pass
else:
    raise AssertionError("accepted arbitrary traffic history unrelated to ingress evidence")
passing = passing_plan(); passing["execution"]["rows"][0]["ingressObservation"]["receivedAt"] = "2026-10-12T00:36:00Z"
try:
    MODULE.validate(passing)
except MODULE.ContractError:
    pass
else:
    raise AssertionError("accepted ingress receipt after source drain")
passing = passing_plan(); passing["execution"]["startedAt"] = "2026-10-12T00:00:00"
try:
    MODULE.validate(passing)
except MODULE.ContractError:
    pass
else:
    raise AssertionError("accepted timezone-free execution timestamp")
print("PASS: G6 preflight accepts only the non-secret physical-boundary contract")
