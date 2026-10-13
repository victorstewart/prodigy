#!/usr/bin/env python3
"""Fail-closed, offline validation for a proposed or completed G6 evidence plan.

This is deliberately an evidence-contract validator.  It neither opens a network
connection nor invokes Mothership, a provider, or a runtime harness.
"""
import argparse
import datetime
import json
import re
import sys


SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SECRET_VALUE = re.compile(
    r"(?is)(-----BEGIN[^\n]*PRIVATE KEY|\bBearer\s+|\bAKIA[0-9A-Z]{16}\b|\bsk-[A-Za-z0-9_-]+|(?:api[_-]?key|access[_-]?token|token)\s*=)"
)
SECRET_FIELD = re.compile(r"(?i)(api[_-]?key|access[_-]?token|private[_-]?key|secret|password|credentialmaterial|^material$)")
REQUIRED_LIFECYCLE = {"createCluster", "clusterReport", "removeCluster"}
REQUIRED_RESIDUALS = {"instances", "vpcs", "blocks", "ips"}
REQUIRED_FAULT_CASES = {"nominal", "target-master-crash", "target-cold-restart", "source-master-interruption-after-retirement-seal"}
REQUIRED_ROW_OPERATIONS = {"createCluster", "clusterReport", "cousinRoute", "removeCluster"}
REQUIRED_FAULT_OPERATIONS = {"faultRemoteCloudMachine", "faultLocalClusterMachine", "faultClusterNetwork"}
REQUIRED_BOUNDARY_CHECKS = {
    "bidirectional-endpoint-reachability", "asymmetric-partition", "full-partition",
    "nat-directionality", "ipv4-route", "ipv6-route", "mtu-pmtu",
    "dns-ttl-cache", "tls-sni-client-identity", "service-discovery",
    "no-host-network-mutation",
}
REQUIRED_PROTOCOLS = {"aegis-x25519-v1"}
SUPPORTED_ARCHITECTURES = {"x86_64", "aarch64", "riscv64"}


class ContractError(ValueError):
    pass


def fail(message):
    raise ContractError(message)


def mapping(value, path):
    if not isinstance(value, dict):
        fail(f"{path} must be an object")
    return value


def object_with_keys(value, path, required, optional=()):
    value = mapping(value, path)
    required, allowed = set(required), set(required) | set(optional)
    unknown, missing = set(value) - allowed, required - set(value)
    if unknown:
        fail(f"{path} contains unsupported fields: {', '.join(sorted(unknown))}")
    if missing:
        fail(f"{path} is missing required fields: {', '.join(sorted(missing))}")
    return value


def list_of(value, path):
    if not isinstance(value, list):
        fail(f"{path} must be an array")
    return value


def string_set(value, path, allow_empty=False):
    values = list_of(value, path)
    if not allow_empty and not values:
        fail(f"{path} must be nonempty")
    result = set()
    for index, item in enumerate(values):
        result.add(text(item, f"{path}[{index}]"))
    if len(result) != len(values):
        fail(f"{path} must not contain duplicates")
    return result


def text(value, path):
    if not isinstance(value, str) or not value:
        fail(f"{path} must be a nonempty string")
    return value


def exact_hash(value, path):
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        fail(f"{path} must be a lower-case SHA-256")
    return value


def no_secret_material(value, path="$"):
    """Reject secret-shaped fields or values anywhere, including unknown fields."""
    if isinstance(value, dict):
        for key, child in value.items():
            key = text(key, f"{path}.key")
            child_path = f"{path}.{key}"
            if key == "containsSecret" and child is False:
                continue
            if SECRET_FIELD.search(key):
                fail(f"{child_path} may not embed secret material; use a credential reference")
            no_secret_material(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            no_secret_material(child, f"{path}[{index}]")
    elif isinstance(value, str) and SECRET_VALUE.search(value):
        fail(f"{path} contains secret-shaped material")


def positive_deadline(value, path):
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0 or value > 86_400:
        fail(f"{path} must be an integer between 1 and 86400 seconds")


def timestamp(value, path):
    value = text(value, path)
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        fail(f"{path} must be an ISO-8601 timestamp")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        fail(f"{path} must include an explicit timezone")
    return parsed


def validate(plan):
    plan = object_with_keys(
        plan, "plan",
        {"schemaVersion", "phase", "result", "testOnly", "candidate",
         "supportedArchitectures", "supportedProtocols", "budget",
         "credentialReferences", "clusters", "physicalRows", "mothershipOperations",
         "deadlinesSeconds", "postCleanup"},
        {"execution"},
    )
    no_secret_material(plan)
    if plan.get("schemaVersion") != 1:
        fail("schemaVersion must be 1")
    if plan.get("phase") != "G6" or plan.get("result") not in {"planned", "pass"}:
        fail("phase must be G6 and result must be planned or pass")
    if plan.get("testOnly") is not False:
        fail("testOnly must be explicitly false for a G6 passing claim")

    candidate = object_with_keys(
        plan.get("candidate"), "candidate",
        {"commit", "binaries", "bundleSHA256", "applicationArtifact"},
    )
    commit = candidate.get("commit")
    if not isinstance(commit, str) or not COMMIT.fullmatch(commit):
        fail("candidate.commit must be an exact lower-case Git commit")
    binaries = object_with_keys(candidate.get("binaries"), "candidate.binaries", {"prodigy", "mothership"})
    for name in ("prodigy", "mothership"):
        exact_hash(binaries.get(name), f"candidate.binaries.{name}")
    exact_hash(candidate.get("bundleSHA256"), "candidate.bundleSHA256")
    app = object_with_keys(
        candidate.get("applicationArtifact"), "candidate.applicationArtifact",
        {"sha256", "discombobulator"},
    )
    exact_hash(app.get("sha256"), "candidate.applicationArtifact.sha256")
    discombobulator = object_with_keys(
        app.get("discombobulator"), "candidate.applicationArtifact.discombobulator",
        {"kind", "contractVersion", "contractHeaderSHA256", "buildReceiptSHA256"},
    )
    if discombobulator.get("kind") != "app":
        fail("application artifact must be a Discombobulator --kind app artifact")
    text(discombobulator.get("contractVersion"), "candidate.applicationArtifact.discombobulator.contractVersion")
    exact_hash(discombobulator.get("contractHeaderSHA256"), "candidate.applicationArtifact.discombobulator.contractHeaderSHA256")
    exact_hash(discombobulator.get("buildReceiptSHA256"), "candidate.applicationArtifact.discombobulator.buildReceiptSHA256")

    architectures = string_set(plan.get("supportedArchitectures"), "supportedArchitectures")
    protocols = string_set(plan.get("supportedProtocols"), "supportedProtocols")
    if not architectures.issubset(SUPPORTED_ARCHITECTURES):
        fail("supported architectures contain an unknown Prodigy target")
    if protocols != REQUIRED_PROTOCOLS:
        fail("G6 lifecycle evidence requires the aegis-x25519-v1 transport profile")

    budget = object_with_keys(
        plan.get("budget"), "budget",
        {"previousSpentUSD", "currentEstimateUSD", "totalCapUSD"},
        {"actualSpentUSD"},
    )
    previous, current, cap = (budget.get("previousSpentUSD"), budget.get("currentEstimateUSD"), budget.get("totalCapUSD"))
    if any(not isinstance(x, (int, float)) or isinstance(x, bool) or x < 0 for x in (previous, current, cap)):
        fail("budget values must be nonnegative numbers")
    if cap > 25 or previous + current > cap:
        fail("previous spend plus current estimate must not exceed a total cap of $25")
    if plan["result"] == "pass":
        actual = budget.get("actualSpentUSD")
        if not isinstance(actual, (int, float)) or isinstance(actual, bool) or actual < 0:
            fail("passing evidence requires nonnegative budget.actualSpentUSD")
        if previous + actual > cap:
            fail("previous spend plus actual spend must not exceed the total cap")

    credentials = list_of(plan.get("credentialReferences"), "credentialReferences")
    if not credentials:
        fail("at least one non-secret credential reference is required")
    for index, credential in enumerate(credentials):
        credential = object_with_keys(
            credential, f"credentialReferences[{index}]", {"reference", "containsSecret"})
        text(credential.get("reference"), f"credentialReferences[{index}].reference")
        if credential.get("containsSecret") is not False:
            fail(f"credentialReferences[{index}].containsSecret must be false")

    clusters = list_of(plan.get("clusters"), "clusters")
    if len(clusters) != 3:
        fail("G6 requires exactly three declared physical clusters")
    ids, regions, failure_domains = set(), set(), set()
    cluster_by_id = {}
    for index, cluster in enumerate(clusters):
        cluster = object_with_keys(
            cluster, f"clusters[{index}]",
            {"id", "region", "siteKind", "provider", "failureDomain", "architecture", "protocol", "deploymentMode"},
            {"isolation", "evidenceClass"},
        )
        if cluster.get("deploymentMode") == "test" or cluster.get("evidenceClass") == "test-only":
            fail("test-only cluster evidence cannot pass G6")
        identifier = text(cluster.get("id"), f"clusters[{index}].id")
        region = text(cluster.get("region"), f"clusters[{index}].region")
        site_kind = text(cluster.get("siteKind"), f"clusters[{index}].siteKind")
        provider = text(cluster.get("provider"), f"clusters[{index}].provider")
        failure_domain = text(cluster.get("failureDomain"), f"clusters[{index}].failureDomain")
        architecture = text(cluster.get("architecture"), f"clusters[{index}].architecture")
        protocol = text(cluster.get("protocol"), f"clusters[{index}].protocol")
        if architecture not in architectures or protocol not in protocols:
            fail(f"clusters[{index}] uses an unsupported architecture or protocol")
        if site_kind == "lan":
            if cluster.get("deploymentMode") != "local" or cluster.get("isolation") != "vm-isolated":
                fail("LAN cluster must use a VM-isolated local Mothership path")
        elif site_kind == "cloud":
            if cluster.get("deploymentMode") != "remote":
                fail("cloud clusters must use remote Mothership deployment")
        else:
            fail(f"clusters[{index}].siteKind must be lan or cloud")
        ids.add(identifier); regions.add(region); failure_domains.add(failure_domain); cluster_by_id[identifier] = cluster
    if len(ids) != 3 or len(regions) != 3 or len(failure_domains) != 3:
        fail("clusters must have distinct IDs, regions, and failure domains")
    if sum(cluster["siteKind"] == "lan" for cluster in cluster_by_id.values()) != 1 or sum(cluster["siteKind"] == "cloud" for cluster in cluster_by_id.values()) != 2:
        fail("clusters must declare one VM-isolated LAN and two cloud sites")

    rows = list_of(plan.get("physicalRows"), "physicalRows")
    if len(rows) != 2:
        fail("G6 requires exactly two physical boundary rows")
    row_kinds = set()
    for index, row in enumerate(rows):
        row = object_with_keys(
            row, f"physicalRows[{index}]", {"kind", "sourceCluster", "targetCluster"})
        kind = text(row.get("kind"), f"physicalRows[{index}].kind")
        source, target = text(row.get("sourceCluster"), f"physicalRows[{index}].sourceCluster"), text(row.get("targetCluster"), f"physicalRows[{index}].targetCluster")
        if source not in cluster_by_id or target not in cluster_by_id or source == target:
            fail(f"physicalRows[{index}] must bind two declared distinct clusters")
        left, right = cluster_by_id[source], cluster_by_id[target]
        if kind == "vm-isolated-lan-to-vultr":
            if left["siteKind"] != "lan" or right["siteKind"] != "cloud" or right["provider"] != "vultr":
                fail("LAN-to-Vultr row has incorrect physical boundary binding")
        elif kind == "cloud-to-cloud":
            if left["siteKind"] != "cloud" or right["siteKind"] != "cloud" or left["region"] == right["region"] or left["failureDomain"] == right["failureDomain"]:
                fail("cloud-to-cloud row must span two cloud clusters in distinct regions")
        else:
            fail(f"physicalRows[{index}].kind is unsupported")
        row_kinds.add(kind)
    if row_kinds != {"vm-isolated-lan-to-vultr", "cloud-to-cloud"}:
        fail("both required physical G6 rows must be present exactly once")

    operations = object_with_keys(
        plan.get("mothershipOperations"), "mothershipOperations",
        {"owner", "lifecycle", "faults", "cleanup"},
    )
    if operations.get("owner") != "Mothership":
        fail("Mothership must own all lifecycle, fault, and cleanup operations")
    lifecycle = string_set(operations.get("lifecycle"), "mothershipOperations.lifecycle")
    if lifecycle != REQUIRED_LIFECYCLE:
        fail("Mothership lifecycle operations must be exactly createCluster, clusterReport, and removeCluster")
    faults = string_set(operations.get("faults"), "mothershipOperations.faults")
    cleanup_operations = string_set(operations.get("cleanup"), "mothershipOperations.cleanup")
    if faults != REQUIRED_FAULT_OPERATIONS:
        fail("Mothership faults must be exactly the remote machine, local machine, and network-boundary owners")
    if cleanup_operations != {"cousinRoute", "removeCluster"}:
        fail("Mothership cleanup must be exactly cousinRoute and removeCluster")

    deadlines = object_with_keys(
        plan.get("deadlinesSeconds"), "deadlinesSeconds",
        {"preflight", "operation", "faultRecovery", "cleanup"},
    )
    for name in ("preflight", "operation", "faultRecovery", "cleanup"):
        positive_deadline(deadlines.get(name), f"deadlinesSeconds.{name}")

    cleanup = object_with_keys(
        plan.get("postCleanup"), "postCleanup", {"residualInventories"}, {"verifiedAt"})
    inventories = list_of(cleanup.get("residualInventories"), "postCleanup.residualInventories")
    found = set()
    for index, inventory in enumerate(inventories):
        inventory = object_with_keys(
            inventory, f"postCleanup.residualInventories[{index}]",
            {"resource", "accountQueryReference", "taskOwnedQueryReference",
             "preExistingIdentitySHA256", "taskOwnedBeforeCleanupSHA256",
             "expectedTaskOwnedAfterCount"},
            {"afterPreExistingIdentitySHA256", "afterTaskOwnedIdentitySHA256",
             "observedTaskOwnedAfterCount"},
        )
        resource = text(inventory.get("resource"), f"postCleanup.residualInventories[{index}].resource")
        account_query = text(inventory.get("accountQueryReference"), f"postCleanup.residualInventories[{index}].accountQueryReference")
        task_query = text(inventory.get("taskOwnedQueryReference"), f"postCleanup.residualInventories[{index}].taskOwnedQueryReference")
        if account_query == task_query:
            fail("account and task-owned inventory queries must be distinct")
        exact_hash(inventory.get("preExistingIdentitySHA256"), f"postCleanup.residualInventories[{index}].preExistingIdentitySHA256")
        exact_hash(inventory.get("taskOwnedBeforeCleanupSHA256"), f"postCleanup.residualInventories[{index}].taskOwnedBeforeCleanupSHA256")
        if inventory.get("expectedTaskOwnedAfterCount") != 0:
            fail(f"post-cleanup task-owned {resource} residual must require zero")
        if resource in found:
            fail("post-cleanup inventories must not duplicate resource classes")
        found.add(resource)
    if found != REQUIRED_RESIDUALS:
        fail("post-cleanup inventories must be exactly instances, VPCs, blocks, and IPs")
    if plan["result"] == "pass":
        validate_execution(plan, candidate, rows, cleanup, operations)
    return True


def validate_execution(plan, candidate, declared_rows, cleanup, mothership_operations):
    execution = object_with_keys(plan.get("execution"), "execution", {"startedAt", "completedAt", "rows"})
    started, completed = timestamp(execution.get("startedAt"), "execution.startedAt"), timestamp(execution.get("completedAt"), "execution.completedAt")
    if completed <= started:
        fail("execution completion must follow start")
    row_evidence = list_of(execution.get("rows"), "execution.rows")
    declared_by_kind = {row["kind"]: row for row in declared_rows}
    declared_kinds = set(declared_by_kind)
    if len(row_evidence) != len(declared_kinds):
        fail("passing evidence requires one execution record for every physical row")
    observed_kinds = set()
    expected_identities = {"commit": candidate["commit"], "prodigySHA256": candidate["binaries"]["prodigy"],
                           "mothershipSHA256": candidate["binaries"]["mothership"], "bundleSHA256": candidate["bundleSHA256"],
                           "applicationSHA256": candidate["applicationArtifact"]["sha256"],
                           "contractHeaderSHA256": candidate["applicationArtifact"]["discombobulator"]["contractHeaderSHA256"],
                           "buildReceiptSHA256": candidate["applicationArtifact"]["discombobulator"]["buildReceiptSHA256"]}
    declared_fault_operations = set(mothership_operations["faults"])
    declared_operations = declared_fault_operations | set(mothership_operations["lifecycle"]) | set(mothership_operations["cleanup"])
    for index, row in enumerate(row_evidence):
        row = object_with_keys(
            row, f"execution.rows[{index}]",
            {"kind", "sourceCluster", "targetCluster", "startedAt", "completedAt",
             "evidenceIdentities", "mothershipCommandReceipts", "faultCases",
             "boundaryChecks", "routeObservation", "trafficObservation"},
        )
        kind = text(row.get("kind"), f"execution.rows[{index}].kind")
        if kind not in declared_kinds or kind in observed_kinds:
            fail("execution rows must bind each declared physical row exactly once")
        observed_kinds.add(kind)
        declared = declared_by_kind[kind]
        if row.get("sourceCluster") != declared["sourceCluster"] or row.get("targetCluster") != declared["targetCluster"]:
            fail("execution row cluster identities must match the declared physical row")
        row_started, row_completed = timestamp(row.get("startedAt"), f"execution.rows[{index}].startedAt"), timestamp(row.get("completedAt"), f"execution.rows[{index}].completedAt")
        if row_completed <= row_started or row_started < started or row_completed > completed:
            fail("execution row timestamps must be bounded by the execution interval")
        identities = object_with_keys(
            row.get("evidenceIdentities"), f"execution.rows[{index}].evidenceIdentities",
            set(expected_identities),
        )
        if identities != expected_identities:
            fail("execution evidence identities must exactly bind the candidate")
        receipts = list_of(row.get("mothershipCommandReceipts"), f"execution.rows[{index}].mothershipCommandReceipts")
        operations = set()
        for receipt_index, receipt in enumerate(receipts):
            receipt = object_with_keys(
                receipt, f"execution.rows[{index}].mothershipCommandReceipts[{receipt_index}]",
                {"operation", "sha256", "timestamp"},
            )
            operations.add(text(receipt.get("operation"), f"execution.rows[{index}].mothershipCommandReceipts[{receipt_index}].operation"))
            exact_hash(receipt.get("sha256"), f"execution.rows[{index}].mothershipCommandReceipts[{receipt_index}].sha256")
            observed_at = timestamp(receipt.get("timestamp"), f"execution.rows[{index}].mothershipCommandReceipts[{receipt_index}].timestamp")
            if observed_at < row_started or observed_at > row_completed:
                fail("Mothership command receipt timestamp falls outside its row execution interval")
        if not REQUIRED_ROW_OPERATIONS.issubset(operations):
            fail("each passing row requires Mothership create/report/route/remove receipts")
        faults = list_of(row.get("faultCases"), f"execution.rows[{index}].faultCases")
        names = set()
        for fault_index, fault in enumerate(faults):
            fault = object_with_keys(
                fault, f"execution.rows[{index}].faultCases[{fault_index}]",
                {"name", "owner", "operation", "receiptSHA256", "timestamp"},
            )
            name = text(fault.get("name"), f"execution.rows[{index}].faultCases[{fault_index}].name")
            if name in names:
                fail("fault cases must not contain duplicates")
            names.add(name)
            if fault.get("owner") != "Mothership":
                fail("every physical fault case must be owned by Mothership")
            operation = text(fault.get("operation"), f"execution.rows[{index}].faultCases[{fault_index}].operation")
            expected_operation = {
                "nominal": "cousinRoute",
                "target-master-crash": "faultRemoteCloudMachine",
                "target-cold-restart": "faultRemoteCloudMachine",
                "source-master-interruption-after-retirement-seal":
                    "faultLocalClusterMachine" if kind == "vm-isolated-lan-to-vultr" else "faultRemoteCloudMachine",
            }.get(name)
            if operation != expected_operation or operation not in declared_operations:
                fail("fault case operation does not match its physical Mothership owner")
            exact_hash(fault.get("receiptSHA256"), f"execution.rows[{index}].faultCases[{fault_index}].receiptSHA256")
            observed_at = timestamp(fault.get("timestamp"), f"execution.rows[{index}].faultCases[{fault_index}].timestamp")
            if observed_at < row_started or observed_at > row_completed:
                fail("fault receipt timestamp falls outside its row execution interval")
        if names != REQUIRED_FAULT_CASES:
            fail("each passing row requires every G5 nominal and fault case")

        boundary_checks = list_of(row.get("boundaryChecks"), f"execution.rows[{index}].boundaryChecks")
        boundary_names = set()
        for check_index, check in enumerate(boundary_checks):
            check = object_with_keys(
                check, f"execution.rows[{index}].boundaryChecks[{check_index}]",
                {"name", "operation", "receiptSHA256", "timestamp"},
            )
            name = text(check.get("name"), f"execution.rows[{index}].boundaryChecks[{check_index}].name")
            if name in boundary_names:
                fail("physical boundary checks must not contain duplicates")
            boundary_names.add(name)
            operation = text(check.get("operation"), f"execution.rows[{index}].boundaryChecks[{check_index}].operation")
            expected_operation = "faultClusterNetwork" if name in {"asymmetric-partition", "full-partition"} else "clusterReport"
            if operation != expected_operation or operation not in declared_operations:
                fail("physical boundary evidence must use its exact Mothership operation owner")
            exact_hash(check.get("receiptSHA256"), f"execution.rows[{index}].boundaryChecks[{check_index}].receiptSHA256")
            observed_at = timestamp(check.get("timestamp"), f"execution.rows[{index}].boundaryChecks[{check_index}].timestamp")
            if observed_at < row_started or observed_at > row_completed:
                fail("physical boundary check timestamp falls outside its row execution interval")
        if boundary_names != REQUIRED_BOUNDARY_CHECKS:
            fail("each passing row requires the complete physical network-boundary matrix")

        route = object_with_keys(
            row.get("routeObservation"), f"execution.rows[{index}].routeObservation",
            {"activeReceiptSHA256", "withdrawalReceiptSHA256", "staleReplayRejectionSHA256",
             "activeAt", "withdrawnAt", "staleReplayRejectedAt"},
        )
        for name in ("activeReceiptSHA256", "withdrawalReceiptSHA256", "staleReplayRejectionSHA256"):
            exact_hash(route.get(name), f"execution.rows[{index}].routeObservation.{name}")
        route_times = {}
        for name in ("activeAt", "withdrawnAt", "staleReplayRejectedAt"):
            observed_at = timestamp(route.get(name), f"execution.rows[{index}].routeObservation.{name}")
            if observed_at < row_started or observed_at > row_completed:
                fail("route observation timestamp falls outside its row execution interval")
            route_times[name] = observed_at
        traffic = object_with_keys(
            row.get("trafficObservation"), f"execution.rows[{index}].trafficObservation",
            {"requestHistorySHA256", "observedAt", "zeroSourceFlowsAt", "retiredSourceAt",
             "heldSourceRequests", "targetRequests", "zeroSourceFlows", "retiredSourceRejected"},
        )
        exact_hash(traffic.get("requestHistorySHA256"), f"execution.rows[{index}].trafficObservation.requestHistorySHA256")
        traffic_at = timestamp(traffic.get("observedAt"), f"execution.rows[{index}].trafficObservation.observedAt")
        zero_flows_at = timestamp(traffic.get("zeroSourceFlowsAt"), f"execution.rows[{index}].trafficObservation.zeroSourceFlowsAt")
        retired_at = timestamp(traffic.get("retiredSourceAt"), f"execution.rows[{index}].trafficObservation.retiredSourceAt")
        if traffic_at < row_started or traffic_at > row_completed or zero_flows_at < row_started or retired_at > row_completed:
            fail("traffic observation timestamp falls outside its row execution interval")
        if not isinstance(traffic.get("heldSourceRequests"), int) or traffic["heldSourceRequests"] <= 0 or not isinstance(traffic.get("targetRequests"), int) or traffic["targetRequests"] <= 0 or traffic.get("zeroSourceFlows") is not True or traffic.get("retiredSourceRejected") is not True:
            fail("traffic observation must prove held-source, target traffic, zero drain, and retirement rejection")
        if not (route_times["activeAt"] < zero_flows_at <= retired_at <= route_times["withdrawnAt"] <
                route_times["staleReplayRejectedAt"] <= traffic_at):
            fail("route, drain, retirement, withdrawal, stale replay, and traffic evidence must be monotonic")
    verified = timestamp(cleanup.get("verifiedAt"), "postCleanup.verifiedAt")
    if verified < completed:
        fail("post-cleanup verification must occur after execution")
    for index, inventory in enumerate(cleanup["residualInventories"]):
        before = inventory["preExistingIdentitySHA256"]
        after = inventory.get("afterPreExistingIdentitySHA256")
        exact_hash(after, f"postCleanup.residualInventories[{index}].afterPreExistingIdentitySHA256")
        if after != before:
            fail("post-cleanup evidence must preserve the exact pre-existing inventory identity set")
        exact_hash(inventory.get("afterTaskOwnedIdentitySHA256"), f"postCleanup.residualInventories[{index}].afterTaskOwnedIdentitySHA256")
        if inventory.get("observedTaskOwnedAfterCount") != 0:
            fail("passing cleanup evidence must observe zero task-owned residual resources")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", help="G6 plan/manifest JSON; validation is offline")
    args = parser.parse_args()
    try:
        with open(args.plan, encoding="utf-8") as source:
            validate(json.load(source))
    except (OSError, json.JSONDecodeError, ContractError) as error:
        print(f"G6_PREFLIGHT_REJECTED: {error}", file=sys.stderr)
        return 1
    print("G6_PREFLIGHT_ACCEPTED: offline contract validation only")
    return 0


if __name__ == "__main__":
    sys.exit(main())
