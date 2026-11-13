#!/usr/bin/env python3
"""Qualify an already deployed, routed Truth group on two or three Mothership test clusters."""

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re
import select
import subprocess
import time


def fields(line):
    return dict(re.findall(r"(\w+)=([^\s]+)", line))


def probe_passed(report, logs, version, endpoints):
    # Only accept a receipt from a running container in this specific version.
    block = re.search(rf"(?ms)^\s*versionID: {version}\s*$\n(.*?)(?=^\s*versionID: |\Z)", report)
    if not block or not re.search(r"(?m)^\s*nHealthy: [1-9]\d*\s*$", block[1]):
        return False
    containers = {int(uuid) for uuid in re.findall(r"(?m)^\s*containerRuntime: [^\n]*?\buuid=(\d+)", block[1])}
    current = None
    for line in logs:
        if line.startswith("container="):
            row = fields(line)
            current = int(row["container"], 16) if row.get("state") == "running" else None
        elif current in containers and line == (
                "PASS truth.client.probe tokgen=16 pubidgen=14 stable-replay=identical "
                f"distinct-endpoints={endpoints}"):
            return True
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mothership", type=Path)
    parser.add_argument("group")
    parser.add_argument("deployment")
    parser.add_argument("singleton", help="disposable singleton test cluster to isolate")
    parser.add_argument("outage_ms", type=int, help="longer than the configured replacement grace")
    parser.add_argument("--timeout", type=int, default=240)
    parser.add_argument("--probe-name", required=True, help="registered name of the lightweight Truth probe")
    parser.add_argument("--probe-plan", type=Path, required=True, help="stateless probe JSON with the first unused versionID")
    parser.add_argument("--probe-artifact", type=Path, required=True)
    parser.add_argument("--sites", type=int, choices=(2, 3), default=2,
                        help="initial voter-site topology (default: 2 for the existing 2+1 qualification)")
    parser.add_argument("--probe-endpoints", type=int, choices=(1, 2), default=2,
                        help="expected probe subscription count; 1 requires an artifact built with TRUTH_PROBE_MIN_ENDPOINTS=1")
    options = parser.parse_args()
    if options.sites == 2 and options.probe_endpoints != 2:
        parser.error("--probe-endpoints 1 is supported only with --sites 3")
    if options.sites == 3 and options.probe_endpoints != 1:
        parser.error("--sites 3 requires --probe-endpoints 1 and a TRUTH_PROBE_MIN_ENDPOINTS=1 probe artifact")
    plan = json.loads(options.probe_plan.read_text())
    version = plan["config"]["versionID"]
    probe_versions = 3 if options.sites == 2 else 8
    if (plan["config"]["type"] != "ApplicationType::stateless" or not 0 < version <= (1 << 48) - probe_versions or
            not options.probe_artifact.is_file()):
        parser.error(f"provide a stateless probe plan, {probe_versions} unused successive version IDs, and a built probe artifact")
    if options.outage_ms <= 0 or options.timeout * 1000 <= options.outage_ms:
        parser.error("timeout must exceed the positive fault duration")
    binary = str(options.mothership.resolve())

    def call(*args):
        p = subprocess.run([binary, *args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True, timeout=30, check=False)
        return p.stdout.splitlines() if p.returncode == 0 else []

    def inspect(member):
        lines = call("globalSingleWriterControl", options.group, "inspect", str(member))
        reports = [fields(s) for s in lines if s.startswith("globalSingleWriterControl success=1 ")]
        rows = {int(m["member"]): m for m in (fields(s) for s in lines if s.startswith("globalSingleWriterCommittedMember "))}
        return (reports[0], rows) if len(reports) == 1 else ({}, {})

    def inventory(cluster=None):
        lines = call("deploymentIdentity", cluster or options.singleton, options.deployment)
        report = next((fields(s) for s in lines if s.startswith("deploymentIdentity success=1 ")), {})
        return report.get("clusterUUID"), {fields(s)["containerUUID"] for s in lines if s.startswith("deploymentIdentityMember ")}

    deadline = time.monotonic() + options.timeout
    def wait_for(description, observation, reconcile=True):
        while time.monotonic() < deadline:
            if reconcile:
                call("reconcileGlobalSingleWriter", options.group)
            result = observation()
            if result:
                print(description, flush=True)
                return result
            time.sleep(0.5)
        raise RuntimeError(f"timed out waiting for {description}")

    def run_probe(cluster, phase, fault=None):
        nonlocal version
        plan["config"]["versionID"] = version
        lines = call("deploy", cluster, json.dumps(plan), str(options.probe_artifact.resolve()), "--submit-only")
        if not any(line.startswith("deploy accepted=1 ") for line in lines):
            raise RuntimeError(f"{phase}: probe version {version} deployment did not succeed")

        def ready():
            if fault is not None and fault.poll() is not None:
                raise RuntimeError("fault finished before a fresh generator write and replay completed")
            report = "\n".join(call("applicationReport", cluster, options.probe_name))
            logs = call("containerLogs", cluster, options.probe_name, "65536")
            return probe_passed(report, logs, version, options.probe_endpoints)

        wait_for(f"{phase}: probe version {version} committed both generators and replayed them with {options.probe_endpoints} endpoint(s)",
                 ready, reconcile=False)
        version += 1

    def quorum(seed):
        report, _ = inspect(seed)
        leader = int(report.get("leader", 0))
        if not leader:
            return None
        report, members = inspect(leader)
        if int(report.get("leader", 0)) != leader or not report.get("digest"):
            return None
        voters = {i for i, m in members.items() if m["role"] == "voter"}
        live = {i for i in voters if members[i]["reachable"] == "1"}
        return report, members, voters, live

    def unanimous(voters, expected):
        """Require every current voter to report the same committed configuration."""
        for member in voters:
            replica, _ = inspect(member)
            if any(replica.get(k) != expected.get(k) for k in ("leader", "term", "config", "digest")):
                return False
        return True

    # Read-only preflight. An unjoined singleton must never count as a passing
    # initial condition, even when the other two voters can already write.
    site, containers = inventory()
    if not site or len(containers) != 1:
        raise RuntimeError("fault target must report exactly one live Truth container")
    initial = quorum(1)
    if not initial:
        raise RuntimeError("genesis member 1 cannot identify an elected writer")
    report, members, voters, live = initial
    initial_sites = {m["cluster"] for m in members.values()}
    expected_distribution = [1, 2] if options.sites == 2 else [1, 1, 1]
    if (len(voters) != 3 or len(members) != 3 or voters != live or
            sorted(Counter(m["cluster"] for m in members.values()).values()) != expected_distribution):
        raise RuntimeError(f"preflight requires three communicating voters in a {options.sites}-site placement")
    old = [i for i in voters if members[i]["cluster"] == site and members[i]["container"] in containers]
    if len(old) != 1:
        raise RuntimeError("fault target does not match the singleton in committed membership")
    old = old[0]
    survivors = voters - {old}
    seed = min(survivors)
    if not unanimous(voters, report):
        raise RuntimeError("preflight requires the same committed configuration on all three voters")

    majority_site = "0x" + members[seed]["cluster"].removeprefix("0x")
    if options.sites == 2:
        run_probe(majority_site, "healthy pair")
    else:
        for probe_site in sorted(initial_sites):
            run_probe("0x" + probe_site.removeprefix("0x"), f"healthy site {probe_site}")

    machines = [line.strip() for line in call("clusterReport", options.singleton)
                if line.strip().startswith("Machine: state=")]
    if not machines or any(not line.startswith("Machine: state=healthy ") for line in machines):
        raise RuntimeError("the singleton site must report every test machine healthy before isolation")
    machine_indices = ",".join(str(i) for i in range(1, len(machines) + 1))
    fault = subprocess.Popen([binary, "faultTestCluster", options.singleton, "link", machine_indices,
                              str(options.outage_ms), "0", "0", "0"],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
    try:
        # Admission reads the same exclusive registry as our observations.
        # Wait for its explicit release before making another CLI request.
        startup = bytearray()
        admission_deadline = min(deadline, time.monotonic() + 30)
        while b"faultTestCluster admitted=1 " not in startup:
            remaining = admission_deadline - time.monotonic()
            if remaining <= 0 or not select.select([fault.stdout], [], [], remaining)[0]:
                raise RuntimeError("timed out waiting for Mothership fault admission")
            chunk = os.read(fault.stdout.fileno(), 4096)
            if not chunk:
                raise RuntimeError("Mothership fault admission failed: " + startup.decode(errors="replace"))
            startup.extend(chunk)
            if len(startup) > 65536:
                raise RuntimeError("Mothership fault admission output exceeded its bound")
        print(startup.decode(errors="replace"), end="", flush=True)

        def fault_active():
            # Do not let reconciliation turn an unobserved/failed fault into a
            # successful replacement.  The surviving side must first elect a
            # reachable writer while retaining the old committed configuration,
            # and report the isolated voter as unreachable.
            if fault.poll() is not None:
                raise RuntimeError("fault finished before isolation was observed")
            current = quorum(seed)
            if not current:
                return None
            r, group, voting, reachable = current
            if (set(group) != voters or voting != voters or old not in group or old in reachable or
                    not survivors <= reachable or int(r.get("leader", 0)) not in survivors or
                    r.get("config") != report.get("config") or r.get("digest") != report.get("digest")):
                return None
            return r

        wait_for("fault active: singleton voter unreachable before reconciliation", fault_active, reconcile=False)

        if options.sites == 2:
            run_probe(majority_site, "two surviving voters", fault)
        else:
            for probe_site in sorted({members[i]["cluster"] for i in survivors}):
                run_probe("0x" + probe_site.removeprefix("0x"), f"surviving site {probe_site}", fault)

        def repaired():
            if fault.poll() is not None:
                raise RuntimeError("fault finished before a local replacement committed")
            current = quorum(seed)
            if not current:
                return None
            r, group, voting, reachable = current
            repaired_group = (len(voting) == len(group) == 3 and survivors < voting and old not in group and
                              voting == reachable and int(r["config"]) > int(report["config"]) and
                              all(m["cluster"] != site for m in group.values()))
            if not repaired_group:
                return None
            return unanimous(voting, r) and voting
        wait_for("majority committed a replacement voter during the outage", repaired)
    finally:
        # Mothership owns restoration of the bounded fault even on failure.
        output, _ = fault.communicate(timeout=options.outage_ms / 1000 + 60)
        print(output.decode(errors="replace"), end="", flush=True)
    if fault.returncode:
        raise RuntimeError("Mothership rejected or failed the bounded link fault")

    def returned():
        current = quorum(seed)
        if not current:
            return None
        r, group, voting, reachable = current
        observed_site, active = inventory()
        remote = [(i, m) for i, m in group.items() if i in voting and m["cluster"] == site]
        local = [(i, m) for i, m in group.items() if i in voting and m["cluster"] != site]
        expected_return_distribution = [1, 2] if options.sites == 2 else [1, 1, 1]
        if not (observed_site == site and len(remote) == 1 and len(voting) == len(group) == 3 and
                len(local) == 2 and voting == reachable and old not in group and remote[0][0] != old and
                remote[0][1]["caughtUp"] == "1" and remote[0][1]["container"] not in containers and
                active == {remote[0][1]["container"]} and
                sorted(Counter(member["cluster"] for _, member in remote + local).values()) == expected_return_distribution and
                (options.sites == 2 or {member["cluster"] for member in group.values()} == initial_sites)):
            return None
        # The final membership commit precedes physical retirement. Keep
        # reconciling until every site has exactly its committed containers;
        # otherwise the restored probe can still discover the retired sibling.
        for cluster in initial_sites:
            observed, active = inventory("0x" + cluster.removeprefix("0x"))
            expected = {member["container"] for member in group.values() if member["cluster"] == cluster}
            if observed != cluster or active != expected:
                return None
        return unanimous(voting, r)
    wait_for(f"return restored {options.sites}-site placement with a fresh caught-up remote voter and retired the old UUID", returned)
    if options.sites == 2:
        run_probe(majority_site, "restored pair")
    else:
        for probe_site in sorted(initial_sites):
            run_probe("0x" + probe_site.removeprefix("0x"), f"restored site {probe_site}")


if __name__ == "__main__":
    main()
