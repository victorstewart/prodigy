#!/usr/bin/env python3
"""Qualify an already deployed, routed 2+1 Truth group on two Mothership test clusters."""

import argparse
from collections import Counter
from pathlib import Path
import re
import subprocess
import time


def fields(line):
    return dict(re.findall(r"(\w+)=([^\s]+)", line))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mothership", type=Path)
    parser.add_argument("group")
    parser.add_argument("deployment")
    parser.add_argument("singleton", help="disposable three-machine test cluster to isolate")
    parser.add_argument("outage_ms", type=int, help="longer than the configured replacement grace")
    parser.add_argument("--timeout", type=int, default=240)
    options = parser.parse_args()
    if options.outage_ms <= 0 or options.timeout * 1000 <= options.outage_ms:
        parser.error("timeout must exceed the positive fault duration")
    binary = str(options.mothership.resolve())

    def call(*args):
        p = subprocess.run([binary, *args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True, timeout=30, check=False)
        return p.stdout.splitlines() if p.returncode == 0 else []

    def inspect(member):
        lines = call("truthGlobalControl", options.group, "inspect", str(member))
        reports = [fields(s) for s in lines if s.startswith("truthGlobalControl success=1 ")]
        rows = {int(m["member"]): m for m in (fields(s) for s in lines if s.startswith("truthCommittedMember "))}
        return (reports[0], rows) if len(reports) == 1 else ({}, {})

    def inventory():
        lines = call("deploymentIdentity", options.singleton, options.deployment)
        report = next((fields(s) for s in lines if s.startswith("deploymentIdentity success=1 ")), {})
        return report.get("clusterUUID"), {fields(s)["containerUUID"] for s in lines if s.startswith("deploymentIdentityMember ")}

    deadline = time.monotonic() + options.timeout
    def wait_for(description, observation):
        while time.monotonic() < deadline:
            call("reconcileTruth", options.group)
            result = observation()
            if result:
                print(description, flush=True)
                return result
            time.sleep(0.5)
        raise RuntimeError(f"timed out waiting for {description}")

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

    # Read-only preflight. An unjoined singleton must never count as a passing
    # 2+1 starting condition, even when the other two voters can already write.
    site, containers = inventory()
    if not site or len(containers) != 1:
        raise RuntimeError("fault target must report exactly one live Truth container")
    initial = quorum(1)
    if not initial:
        raise RuntimeError("genesis member 1 cannot identify an elected writer")
    report, members, voters, live = initial
    if len(members) != 3 or voters != live or sorted(Counter(m["cluster"] for m in members.values()).values()) != [1, 2]:
        raise RuntimeError("preflight requires three communicating voters in a 2+1 placement")
    old = [i for i in voters if members[i]["cluster"] == site and members[i]["container"] in containers]
    if len(old) != 1:
        raise RuntimeError("fault target does not match the singleton in committed membership")
    old = old[0]
    survivors = voters - {old}
    seed = min(survivors)
    for i in voters:
        replica, _ = inspect(i)
        if any(replica.get(k) != report[k] for k in ("leader", "term", "config", "digest")):
            raise RuntimeError("preflight requires the same committed configuration on all three voters")

    fault = subprocess.Popen([binary, "faultTestCluster", options.singleton, "link", "1,2,3",
                              str(options.outage_ms), "0", "0", "0"])
    try:
        def repaired():
            if fault.poll() is not None:
                raise RuntimeError("fault finished before a local replacement committed")
            current = quorum(seed)
            if not current:
                return None
            r, group, voting, reachable = current
            if not (len(voting) == len(group) == 3 and survivors < voting and old not in group and
                    voting == reachable and int(r["config"]) > int(report["config"]) and
                    all(m["cluster"] != site for m in group.values())):
                return None
            replica, _ = inspect(max(survivors))
            return replica.get("digest") == r["digest"] and voting
        wait_for("majority committed three local voters during the outage", repaired)
    finally:
        # Mothership owns restoration of the bounded fault even on failure.
        fault.wait(timeout=options.outage_ms / 1000 + 60)
    if fault.returncode:
        raise RuntimeError("Mothership rejected or failed the bounded link fault")

    def returned():
        current = quorum(seed)
        if not current:
            return None
        r, group, voting, reachable = current
        observed_site, active = inventory()
        remote = [m for i, m in group.items() if i in voting and m["cluster"] == site]
        if not (observed_site == site and len(remote) == 1 and len(voting) == len(group) == 3 and
                voting == reachable and old not in group and remote[0]["caughtUp"] == "1" and
                remote[0]["container"] not in containers and
                active == {remote[0]["container"]}):
            return None
        recovered, _ = inspect(int(remote[0]["member"]))
        return recovered.get("digest") == r["digest"]
    wait_for("return restored 2+1 with a fresh caught-up remote voter and retired the old UUID", returned)


if __name__ == "__main__":
    main()
