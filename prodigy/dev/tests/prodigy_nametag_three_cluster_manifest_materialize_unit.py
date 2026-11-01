#!/usr/bin/env python3
"""Focused contract for the side-effect-free live manifest materializer."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent
MATERIALIZER = ROOT / "prodigy_nametag_three_cluster_manifest_materialize.py"
TEMPLATE = ROOT / "fixtures" / "nametag_three_cluster_qualification_manifest.json"
DRIVER = ROOT / "prodigy_nametag_three_cluster_qualification.sh"


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def run(input_path: Path, output_path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, "-B", str(MATERIALIZER), "--input", str(input_path),
                           "--output", str(output_path), "--template", str(TEMPLATE)],
                          text=True, capture_output=True, check=False)


def expect_rejected(root: Path, name: str, value: dict, needle: str) -> None:
    input_path = root / f"{name}.json"
    write_json(input_path, value)
    result = run(input_path, root / f"{name}.out.json")
    assert result.returncode != 0 and needle in result.stderr, (name, result.stdout, result.stderr)


def main() -> int:
    template = json.loads(TEMPLATE.read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory(prefix="prodigy-nametag-manifest-materialize-unit.") as directory:
        root = Path(directory)
        requests = root / "requests"
        requests.mkdir()
        def request(name: str) -> str:
            path = requests / name
            path.write_text("public request only\n", encoding="utf-8")
            return str(path)

        def create_request(name: str, cluster_name: str) -> str:
            path = requests / name
            write_json(path, {"name": cluster_name, "deploymentMode": "remote", "provider": "vultr",
                              "providerScope": name.split("-", 1)[0], "architecture": "x86_64", "nBrains": 3})
            return str(path)

        paths = [copy.deepcopy(path) for path in template["topology"]["masque"]["paths"]]
        machines = []
        for site_index, site in enumerate(("ewr", "ord", "lan")):
            for slot in range(3):
                machines.append({"site": site, "slot": slot,
                                 "machineUUID": f"10000000-0000-4000-8000-{site_index * 3 + slot + 1:012d}"})
        machine_for_slot = {(machine["site"], machine["slot"]): machine["machineUUID"] for machine in machines}
        authority_paths: dict[str, str] = {}
        for path in paths:
            for authority in path["authorities"]:
                authority["machineUUID"] = machine_for_slot[(authority["site"], authority["slot"])]
                authority["peerMachineUUID"] = machine_for_slot[(authority["peer"], authority["slot"])]
                request_path = requests / f"{authority['id']}.json"
                write_json(request_path, {"configureLiveArgs": ["configure", authority["id"]],
                                          "withdrawLiveArgs": ["withdraw", authority["id"]]})
                authority_paths[authority["id"]] = str(request_path)

        commands = {command["label"]: ["live", command["label"]]
                    for command in template["commands"]
                    if command["label"] not in {"create-ewr", "enroll", "all-masters", "all-masters-resume", "chaos-baseline"} and
                    not command["label"].startswith("configure-")}
        cleanup = {command["label"]: ["cleanup", command["label"]]
                   for command in template["cleanup"] if command["label"] != "cleanup-pair-enroll" and not command["label"].startswith("cleanup-ewr-") and
                   not command["label"].startswith("cleanup-ord-")}
        cleanup["cleanup-ewr"] = ["task-ewr-20261019"]
        cleanup["cleanup-ord"] = ["task-ord-20261019"]
        input_value = {
            "mothershipTidesDBPath": str(root / "mothership.tidesdb"),
            "protectedLan": {"name": "retained-lan-current", "uuid": "20000000-0000-4000-8000-000000000001",
                             "prefixes": ["2602:fac1::/40"]},
            "topology": {"sites": [{"id": "ewr", "datacenterTag": 11, "prefix": "fd10:b00::/96"},
                                      {"id": "ord", "datacenterTag": 12, "prefix": "fd10:c00::/96"},
                                      {"id": "lan", "datacenterTag": 13, "prefix": "fd10:d00::/96"}],
                         "gatewayMachines": machines, "masque": {"paths": paths},
                         "stores": template["topology"]["stores"], "app6": template["topology"]["app6"],
                         "siteLocalPrefixOwnership": True,
                         "routeAdvertisements": [{"site": "ewr", "prefix": "fd10:b00::/96", "scope": "site-local"},
                                                 {"site": "ord", "prefix": "fd10:c00::/96", "scope": "site-local"},
                                                 {"site": "lan", "prefix": "fd10:d00::/96", "scope": "site-local"}]},
            "createRequestPaths": {"ewr": create_request("ewr-create.json", "task-ewr-20261019"),
                                   "ord": create_request("ord-create.json", "task-ord-20261019")},
            "authorityRequestPaths": authority_paths,
            "allMastersPreparationPath": request("all-masters.prepare.json"),
            "allMastersIntentOutputPath": str(root / "all-masters.intent"),
            "pairEnrollmentLiveArgs": {
                pair: {"enrollLiveArgs": ["enroll", pair], "revokeLiveArgs": ["revoke", pair]}
                for pair in ("ewr-ord", "ewr-lan", "ord-lan")
            },
            "deploymentIDs": {
                "ewr": {"pulse": 101, "hot": 102, "cold": 103, "radar": 104, "app6": 105,
                        "truth": 106, "probe": 11 * 281474976710656 + 11},
                "ord": {"pulse": 201, "hot": 202, "cold": 203, "radar": 204, "app6": 205,
                        "probe": 11 * 281474976710656 + 12},
                "lan": {"pulse": 301, "hot": 302, "cold": 303, "radar": 304, "app6": 305,
                        "probe": 11 * 281474976710656 + 13},
            },
            "commandLiveArgs": commands,
            "cleanupLiveArgs": cleanup,
            "qualification": {"allMastersOperationUUID": "1234567890abcdef1234567890abcdef",
                              "probeDeploymentIDs": {"ewr": 11 * 281474976710656 + 11,
                                                     "ord": 11 * 281474976710656 + 12,
                                                     "lan": 11 * 281474976710656 + 13}},
        }
        input_path, output_path = root / "input.json", root / "live-manifest.json"
        write_json(input_path, input_value)
        result = run(input_path, output_path)
        assert result.returncode == 0, result.stderr
        output = json.loads(output_path.read_text(encoding="utf-8"))
        assert output["execution"]["fixtureOnly"] is False
        assert output["execution"]["mothershipTidesDBPath"] == input_value["mothershipTidesDBPath"]
        assert {command["resourceID"] for command in output["commands"] if command["operation"] == "createCluster"} == {"ewr", "ord"}
        assert {resource["id"]: resource["name"] for resource in output["resources"] if resource["type"] == "cluster"} == {
            "ewr": "task-ewr-20261019", "ord": "task-ord-20261019", "lan": "lan"}
        assert output["materialization"]["createRequests"]["ewr"]["name"] == "task-ewr-20261019"
        assert len(output["materialization"]["allMastersPreparation"]["sha256"]) == 64
        assert all(len(request["sha256"]) == 64 for request in output["materialization"]["authorityRequests"].values())
        assert not any(command["resourceID"] == "lan" and command["operation"] in {"createCluster", "removeCluster"}
                       for command in output["commands"] + output["cleanup"])
        assert len(output["materialization"]["authorityRequests"]) == 18
        assert output["materialization"]["allMastersPreparation"]["path"] == input_value["allMastersPreparationPath"]
        assert output["materialization"]["allMastersIntent"]["path"] == input_value["allMastersIntentOutputPath"]
        assert {command["resourceID"] for command in output["commands"] if command["operation"] == "enrollClusterPair"} == {
            "pair-enroll-ewr-ord", "pair-enroll-ewr-lan", "pair-enroll-ord-lan"}
        assert {command["resourceID"] for command in output["cleanup"] if command["operation"] == "revokeClusterPair"} == {
            "pair-enroll-ewr-ord", "pair-enroll-ewr-lan", "pair-enroll-ord-lan"}
        assert all(command.get("liveArgsResolved") for command in output["commands"] + output["cleanup"])
        assert all(row[direction]["liveArgs"] == [] and row[direction]["liveArgsResolved"]
                   for row in output["chaos"] for direction in ("injection", "observation"))
        dry = subprocess.run(["bash", str(DRIVER), "--mothership", "/usr/bin/true", "--manifest", str(output_path),
                              "--run-dir", str(root / "dry-run"), "--dry-run"], text=True, capture_output=True, check=False)
        assert dry.returncode == 0, dry.stderr

        missing_ord = copy.deepcopy(input_value)
        del missing_ord["createRequestPaths"]["ord"]
        expect_rejected(root, "missing-ord", missing_ord, "createRequestPaths")
        duplicate_tag = copy.deepcopy(input_value)
        duplicate_tag["topology"]["sites"][1]["datacenterTag"] = 11
        expect_rejected(root, "duplicate-tag", duplicate_tag, "distinct datacenter tags")
        fewer_authorities = copy.deepcopy(input_value)
        del fewer_authorities["authorityRequestPaths"][next(iter(fewer_authorities["authorityRequestPaths"]))]
        expect_rejected(root, "fewer-authorities", fewer_authorities, "exactly all eighteen")
        placeholder = copy.deepcopy(input_value)
        placeholder["commandLiveArgs"]["preflight"] = ["todo"]
        expect_rejected(root, "placeholder", placeholder, "placeholder")
        protected_cleanup = copy.deepcopy(input_value)
        protected_cleanup["cleanupLiveArgs"]["cleanup-ord"] = ["lan"]
        expect_rejected(root, "protected-lan-cleanup", protected_cleanup, "exact task-owned cluster name")
        missing_pair = copy.deepcopy(input_value)
        del missing_pair["pairEnrollmentLiveArgs"]["ord-lan"]
        expect_rejected(root, "missing-pair", missing_pair, "pairEnrollmentLiveArgs")
        name_collision = copy.deepcopy(input_value)
        ord_path = Path(name_collision["createRequestPaths"]["ord"])
        original_ord = json.loads(ord_path.read_text(encoding="utf-8"))
        write_json(ord_path, {**original_ord, "name": "task-ewr-20261019"})
        expect_rejected(root, "create-name-collision", name_collision, "distinct exact names")
        write_json(ord_path, original_ord)
        protected_create = copy.deepcopy(input_value)
        ewr_path = Path(protected_create["createRequestPaths"]["ewr"])
        original_ewr = json.loads(ewr_path.read_text(encoding="utf-8"))
        write_json(ewr_path, {**original_ewr, "name": "retained-lan-current"})
        expect_rejected(root, "protected-lan-create", protected_create, "protected LAN")
        write_json(ewr_path, original_ewr)
        for field, invalid in (("deploymentMode", "test"), ("deploymentMode", "local"),
                               ("provider", "aws"), ("providerScope", "ord"),
                               ("architecture", "arm64"), ("nBrains", 1)):
            write_json(ewr_path, {**original_ewr, field: invalid})
            expect_rejected(root, f"invalid-ewr-{field}-{invalid}", input_value, "remote Vultr cluster in ewr")
            write_json(ewr_path, original_ewr)
    print("PASS: live campaign manifest materializer contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
