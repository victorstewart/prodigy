#!/usr/bin/env python3
"""Validate observed endpoint histories; never infer migration completion."""
import json
from pathlib import Path
import re
import sys

if not __debug__:
    raise SystemExit("endpoint history checks require Python assertions enabled")


def requests(path, count, deployment):
    rows = [json.loads(line.removeprefix("PAIR_BOUNDARY_REQUEST "))
            for line in path.read_text().splitlines()
            if line.startswith("PAIR_BOUNDARY_REQUEST ")]
    assert len(rows) == count, f"{path.name}: request count"
    containers = set()
    for sequence, row in enumerate(rows):
        assert row["ok"] is True and row["sequence"] == sequence
        match = re.fullmatch(r"deploymentID=(\d+) containerUUID=(0x[0-9a-f]+) request=(\d+)", row["reply"])
        assert match and int(match[1]) == deployment and int(match[3]) == sequence
        assert int(match[2], 16) != 0 and row["receivedNs"] >= row["sentNs"]
        if sequence:
            assert rows[sequence - 1]["receivedNs"] <= row["sentNs"]
        containers.add(match[2])
    assert len(containers) == 1, f"{path.name}: connection changed container"
    return rows, containers.pop()


def validate(root):
    fields = dict(line.split("=", 1) for line in (root / "scenario.txt").read_text().splitlines()
                  if line.startswith(("sourceDeploymentID=", "targetDeploymentID=")))
    source_id, target_id = int(fields["sourceDeploymentID"]), int(fields["targetDeploymentID"])
    assert source_id != target_id
    baseline, baseline_container = requests(root / "source-probe.log", 1, source_id)
    held, source_container = requests(root / "held-source.log", 30, source_id)
    target, target_container = requests(root / "target-probe.log", 5, target_id)
    assert baseline_container == source_container and source_container != target_container
    assert baseline[-1]["receivedNs"] < held[0]["sentNs"]
    assert held[0]["receivedNs"] < target[0]["sentNs"] < held[-1]["sentNs"], "no observed source/target overlap"
    assert "selected=2 drainCapability=1 sourceFlows=" in (root / "select-target.log").read_text()
    return {"sourceRequests": 31, "targetRequests": 5, "failedRequests": 0,
            "sourceConnectionSpansTargetTraffic": True, "migrationQualified": False}


if __name__ == "__main__":
    assert len(sys.argv) == 2
    print(json.dumps(validate(Path(sys.argv[1])), sort_keys=True))
