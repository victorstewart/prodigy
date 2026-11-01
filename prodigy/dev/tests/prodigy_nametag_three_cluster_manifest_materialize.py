#!/usr/bin/env python3
"""Materialize a live Nametag three-cluster campaign manifest without side effects.

The input intentionally contains only operator-reviewed request paths and public
identities.  It neither reads credentials nor invokes Mothership: the existing
qualification driver remains the sole lifecycle client.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import ipaddress
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any


UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
HEX128 = re.compile(r"^[0-9a-f]{32}$")
PLACEHOLDER = re.compile(r"^(fixture|todo|replace|<|\$\{|\[)", re.IGNORECASE)


class MaterializationError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise MaterializationError(message)


def object_at(value: Any, name: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{name} must be an object")
    return value


def list_at(value: Any, name: str) -> list[Any]:
    require(isinstance(value, list), f"{name} must be an array")
    return value


def nonempty_string(value: Any, name: str) -> str:
    require(isinstance(value, str) and value, f"{name} must be a non-empty string")
    require(not PLACEHOLDER.search(value), f"{name} may not be a placeholder")
    return value


def absolute_readable_file(value: Any, name: str) -> str:
    path = nonempty_string(value, name)
    require(os.path.isabs(path), f"{name} must be absolute")
    require(os.path.isfile(path) and os.access(path, os.R_OK), f"{name} must name a readable regular file")
    return path


def live_args(value: Any, name: str, allow_empty: bool = False) -> list[str]:
    values = list_at(value, name)
    require(allow_empty or bool(values), f"{name} may not be empty")
    return [nonempty_string(item, f"{name}[{index}]") for index, item in enumerate(values)]


def load_json(path: str, name: str) -> Any:
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        raise MaterializationError(f"cannot read {name}: {error}") from error


def sha256_file(path: str, name: str) -> str:
    try:
        with open(path, "rb") as handle:
            digest = hashlib.file_digest(handle, "sha256").hexdigest()
    except OSError as error:
        raise MaterializationError(f"cannot hash {name}: {error}") from error
    return digest


def create_request(path: str, site: str) -> dict[str, str]:
    request = object_at(load_json(path, f"{site} create request"), f"{site} create request")
    name = nonempty_string(request.get("name"), f"{site} create request.name")
    deployment_mode = nonempty_string(request.get("deploymentMode"), f"{site} create request.deploymentMode")
    require(deployment_mode == "remote" and request.get("provider") == "vultr" and
            request.get("providerScope") == site and request.get("architecture") == "x86_64" and
            request.get("nBrains") == 3,
            f"{site} create request must select a three-Brain x86_64 remote Vultr cluster in {site}")
    return {"path": path, "sha256": sha256_file(path, f"{site} create request"), "name": name}


def canonical_site(value: Any, name: str) -> dict[str, Any]:
    site = object_at(value, name)
    identifier = nonempty_string(site.get("id"), f"{name}.id")
    require(identifier in {"ewr", "ord", "lan"}, f"{name}.id must be ewr, ord, or lan")
    tag = site.get("datacenterTag")
    require(isinstance(tag, int) and not isinstance(tag, bool) and 0 < tag < 256,
            f"{name}.datacenterTag must be an integer in 1..255")
    prefix = nonempty_string(site.get("prefix"), f"{name}.prefix")
    try:
        network = ipaddress.ip_network(prefix, strict=True)
    except ValueError as error:
        raise MaterializationError(f"{name}.prefix is not a canonical network: {error}") from error
    require(network.version == 6 and network.prefixlen == 96 and str(network) == prefix,
            f"{name}.prefix must be a canonical IPv6 /96")
    return {"id": identifier, "datacenterTag": tag, "prefix": prefix}


def validate_topology(value: Any) -> dict[str, Any]:
    topology = object_at(value, "topology")
    sites = [canonical_site(site, f"topology.sites[{index}]")
             for index, site in enumerate(list_at(topology.get("sites"), "topology.sites"))]
    require(len(sites) == 3 and {site["id"] for site in sites} == {"ewr", "ord", "lan"},
            "topology.sites must contain EWR, ORD, and LAN exactly once")
    require(len({site["datacenterTag"] for site in sites}) == 3, "topology.sites must use distinct datacenter tags")
    require(len({site["prefix"] for site in sites}) == 3, "topology.sites must use distinct prefixes")

    machines = list_at(topology.get("gatewayMachines"), "topology.gatewayMachines")
    require(len(machines) == 9, "topology.gatewayMachines must contain nine task-owned machines")
    machine_for_slot: dict[tuple[str, int], str] = {}
    for index, machine_value in enumerate(machines):
        machine = object_at(machine_value, f"topology.gatewayMachines[{index}]")
        site = nonempty_string(machine.get("site"), f"topology.gatewayMachines[{index}].site")
        slot = machine.get("slot")
        uuid = nonempty_string(machine.get("machineUUID"), f"topology.gatewayMachines[{index}].machineUUID")
        require(site in {"ewr", "ord", "lan"} and isinstance(slot, int) and 0 <= slot < 3 and UUID.fullmatch(uuid),
                f"topology.gatewayMachines[{index}] is invalid")
        key = (site, slot)
        require(key not in machine_for_slot, f"topology.gatewayMachines duplicates {site} slot {slot}")
        machine_for_slot[key] = uuid
    require(set(machine_for_slot) == {(site, slot) for site in ("ewr", "ord", "lan") for slot in range(3)},
            "topology.gatewayMachines must cover every site slot")
    require(len(set(machine_for_slot.values())) == 9, "topology.gatewayMachines must use unique machine UUIDs")

    masque = object_at(topology.get("masque"), "topology.masque")
    paths = list_at(masque.get("paths"), "topology.masque.paths")
    require(len(paths) == 9, "topology.masque.paths must contain all nine pair paths")
    expected_paths = {(left, right, slot) for left, right in (("ewr", "ord"), ("ewr", "lan"), ("ord", "lan")) for slot in range(3)}
    seen_paths: set[tuple[str, str, int]] = set()
    authority_ids: set[str] = set()
    for index, path_value in enumerate(paths):
        path = object_at(path_value, f"topology.masque.paths[{index}]")
        path_sites = list_at(path.get("sites"), f"topology.masque.paths[{index}].sites")
        slot = path.get("slot")
        require(len(path_sites) == 2 and tuple(path_sites) in {("ewr", "ord"), ("ewr", "lan"), ("ord", "lan")} and
                isinstance(slot, int) and 0 <= slot < 3,
                f"topology.masque.paths[{index}] has an invalid pair or slot")
        key = (path_sites[0], path_sites[1], slot)
        require(key not in seen_paths, f"topology.masque.paths duplicates {path_sites[0]}-{path_sites[1]} slot {slot}")
        seen_paths.add(key)
        require(path.get("path") == f"{path_sites[0]}-{path_sites[1]}-{slot}",
                f"topology.masque.paths[{index}].path is not canonical")
        authorities = list_at(path.get("authorities"), f"topology.masque.paths[{index}].authorities")
        require(len(authorities) == 2, f"topology.masque.paths[{index}] must contain both directional authorities")
        directions: set[tuple[str, str]] = set()
        for authority_index, authority_value in enumerate(authorities):
            authority = object_at(authority_value, f"topology.masque.paths[{index}].authorities[{authority_index}]")
            identifier = nonempty_string(authority.get("id"), "authority.id")
            site = nonempty_string(authority.get("site"), "authority.site")
            peer = nonempty_string(authority.get("peer"), "authority.peer")
            machine = nonempty_string(authority.get("machineUUID"), "authority.machineUUID")
            peer_machine = nonempty_string(authority.get("peerMachineUUID"), "authority.peerMachineUUID")
            interface = nonempty_string(authority.get("interface"), "authority.interface")
            require(site in path_sites and peer in path_sites and site != peer and authority.get("slot") == slot and
                    machine == machine_for_slot[(site, slot)] and peer_machine == machine_for_slot[(peer, slot)] and
                    identifier == f"{path_sites[0]}-{path_sites[1]}-{slot}-{site}",
                    f"topology.masque.paths[{index}] authority does not match its path")
            require(identifier not in authority_ids, f"duplicate directional authority {identifier}")
            authority_ids.add(identifier)
            directions.add((site, peer))
        require(directions == {(path_sites[0], path_sites[1]), (path_sites[1], path_sites[0])},
                f"topology.masque.paths[{index}] does not have reciprocal directions")
    require(seen_paths == expected_paths and len(authority_ids) == 18,
            "topology.masque must contain nine canonical paths and eighteen authorities")

    result = copy.deepcopy(topology)
    result["sites"] = sites
    return result


def materialize(input_value: Any, template_value: Any) -> dict[str, Any]:
    source = object_at(input_value, "input")
    template = object_at(template_value, "template")
    result = copy.deepcopy(template)
    topology = validate_topology(source.get("topology"))

    protected_lan = object_at(source.get("protectedLan"), "protectedLan")
    lan_name = nonempty_string(protected_lan.get("name"), "protectedLan.name")
    lan_uuid = nonempty_string(protected_lan.get("uuid"), "protectedLan.uuid")
    lan_prefixes = [nonempty_string(prefix, f"protectedLan.prefixes[{index}]")
                    for index, prefix in enumerate(list_at(protected_lan.get("prefixes"), "protectedLan.prefixes"))]
    require(lan_prefixes, "protectedLan.prefixes may not be empty")

    create_requests = object_at(source.get("createRequestPaths"), "createRequestPaths")
    ewr_create = absolute_readable_file(create_requests.get("ewr"), "createRequestPaths.ewr")
    ord_create = absolute_readable_file(create_requests.get("ord"), "createRequestPaths.ord")
    require(set(create_requests) == {"ewr", "ord"}, "createRequestPaths must contain only EWR and ORD")
    create_targets = {"ewr": create_request(ewr_create, "ewr"), "ord": create_request(ord_create, "ord")}
    require(create_targets["ewr"]["name"] != create_targets["ord"]["name"],
            "EWR and ORD create requests must use distinct exact names")
    require(all(target["name"] not in {"lan", lan_name, lan_uuid} and target["name"] not in lan_prefixes
                for target in create_targets.values()),
            "create request may not target protected LAN")

    authority_paths = object_at(source.get("authorityRequestPaths"), "authorityRequestPaths")
    authority_ids = {authority["id"] for path in topology["masque"]["paths"] for authority in path["authorities"]}
    require(set(authority_paths) == authority_ids, "authorityRequestPaths must cover exactly all eighteen authorities")
    authority_requests: dict[str, dict[str, list[str]]] = {}
    for identifier in sorted(authority_ids):
        path = absolute_readable_file(authority_paths[identifier], f"authorityRequestPaths.{identifier}")
        request = object_at(load_json(path, f"authority request {identifier}"), f"authority request {identifier}")
        require(set(request) == {"configureLiveArgs", "withdrawLiveArgs"},
                f"authority request {identifier} must contain exact configure and withdraw arguments")
        authority_requests[identifier] = {
            "path": path,
            "sha256": sha256_file(path, f"authority request {identifier}"),
            "configureLiveArgs": live_args(request["configureLiveArgs"], f"authority request {identifier}.configureLiveArgs"),
            "withdrawLiveArgs": live_args(request["withdrawLiveArgs"], f"authority request {identifier}.withdrawLiveArgs"),
        }

    tidesdb_path = nonempty_string(source.get("mothershipTidesDBPath"), "mothershipTidesDBPath")
    require(os.path.isabs(tidesdb_path), "mothershipTidesDBPath must be absolute")
    qualification = object_at(source.get("qualification"), "qualification")
    all_masters = nonempty_string(qualification.get("allMastersOperationUUID"), "qualification.allMastersOperationUUID")
    require(HEX128.fullmatch(all_masters), "qualification.allMastersOperationUUID must be canonical lowercase hex")
    probes = object_at(qualification.get("probeDeploymentIDs"), "qualification.probeDeploymentIDs")
    require(set(probes) == {"ewr", "ord", "lan"}, "qualification.probeDeploymentIDs must contain EWR, ORD, and LAN")
    for site, deployment in probes.items():
        require(isinstance(deployment, int) and not isinstance(deployment, bool) and deployment > 0 and
                deployment // 281474976710656 == 11,
                f"qualification.probeDeploymentIDs.{site} must be an App11 deployment ID")

    deployment_ids = object_at(source.get("deploymentIDs"), "deploymentIDs")
    require(set(deployment_ids) == {"ewr", "ord", "lan"}, "deploymentIDs must contain EWR, ORD, and LAN")
    common_deployments = {"pulse", "hot", "cold", "radar", "app6", "probe"}
    all_deployments: list[int] = []
    for site in ("ewr", "ord", "lan"):
        site_deployments = object_at(deployment_ids[site], f"deploymentIDs.{site}")
        required = common_deployments | ({"truth"} if site == "ewr" else set())
        require(set(site_deployments) == required,
                f"deploymentIDs.{site} does not match the all-masters deployment set")
        for name, deployment in site_deployments.items():
            require(isinstance(deployment, int) and not isinstance(deployment, bool) and deployment > 0,
                    f"deploymentIDs.{site}.{name} must be a positive integer")
            all_deployments.append(deployment)
        require(site_deployments["probe"] == probes[site],
                f"deploymentIDs.{site}.probe must match qualification.probeDeploymentIDs.{site}")
    require(len(set(all_deployments)) == len(all_deployments), "deploymentIDs must be globally unique")
    # The intent is deliberately produced only after create/enroll have made the
    # cluster and pair UUIDs durable.  This request remains opaque here: its
    # schema and registry resolution belong to prepareNametagAllMasters.
    all_masters_preparation = absolute_readable_file(source.get("allMastersPreparationPath"),
                                                     "allMastersPreparationPath")
    all_masters_intent = nonempty_string(source.get("allMastersIntentOutputPath"),
                                         "allMastersIntentOutputPath")
    require(os.path.isabs(all_masters_intent), "allMastersIntentOutputPath must be absolute")
    require(all_masters_intent != all_masters_preparation,
            "allMastersIntentOutputPath must differ from allMastersPreparationPath")

    pair_enrollment_args = object_at(source.get("pairEnrollmentLiveArgs"), "pairEnrollmentLiveArgs")
    pair_ids = ("ewr-ord", "ewr-lan", "ord-lan")
    require(set(pair_enrollment_args) == set(pair_ids),
            "pairEnrollmentLiveArgs must contain EWR-ORD, EWR-LAN, and ORD-LAN exactly once")
    pair_enrollments: dict[str, dict[str, list[str]]] = {}
    for pair in pair_ids:
        pair_args = object_at(pair_enrollment_args[pair], f"pairEnrollmentLiveArgs.{pair}")
        require(set(pair_args) == {"enrollLiveArgs", "revokeLiveArgs"},
                f"pairEnrollmentLiveArgs.{pair} must contain exact enroll and revoke arguments")
        pair_enrollments[pair] = {
            "enroll": live_args(pair_args["enrollLiveArgs"], f"pairEnrollmentLiveArgs.{pair}.enrollLiveArgs"),
            "revoke": live_args(pair_args["revokeLiveArgs"], f"pairEnrollmentLiveArgs.{pair}.revokeLiveArgs"),
        }

    command_args = object_at(source.get("commandLiveArgs"), "commandLiveArgs")
    cleanup_args = object_at(source.get("cleanupLiveArgs"), "cleanupLiveArgs")

    result["execution"] = {
        "fixtureOnly": False,
        "liveCommandArgumentsResolved": True,
        "mothershipTidesDBPath": tidesdb_path,
    }
    result["protected"] = {"names": ["lan", lan_name], "uuids": [lan_uuid], "prefixes": lan_prefixes}
    result["topology"] = topology
    result["qualification"] = {"allMastersOperationUUID": all_masters, "probeDeploymentIDs": probes}
    result["materialization"] = {
        "allMastersPreparation": {"path": all_masters_preparation,
                                    "sha256": sha256_file(all_masters_preparation,
                                                          "allMastersPreparationPath")},
        "allMastersIntent": {"path": all_masters_intent},
        "authorityRequests": authority_requests,
        "createRequests": create_targets,
        "deploymentIDs": deployment_ids,
    }

    for resource in result["resources"]:
        if resource["type"] == "cluster" and resource["id"] in create_targets:
            resource["name"] = create_targets[resource["id"]]["name"]

    gateway_resources = [{"type": "gateway", "id": identifier, "name": identifier} for identifier in sorted(authority_ids)]
    result["resources"] = [resource for resource in result["resources"]
                           if resource["type"] != "gateway" and resource["id"] != "pair-enroll"]
    pair_resources = [{"type": "pairOperation", "id": f"pair-enroll-{pair}",
                       "name": f"pair-enroll-{pair}"} for pair in pair_ids]
    insert_at = next(index for index, resource in enumerate(result["resources"]) if resource["type"] == "permission")
    result["resources"][insert_at:insert_at] = pair_resources + gateway_resources

    commands = copy.deepcopy(result["commands"])
    create_ewr = next(command for command in commands if command["label"] == "create-ewr")
    create_ewr["liveArgs"] = ["@" + create_targets["ewr"]["path"]]
    create_ewr["liveArgsResolved"] = True
    create_ord = copy.deepcopy(create_ewr)
    create_ord.update({"label": "create-ord", "resourceID": "ord", "liveArgs": ["@" + create_targets["ord"]["path"]]})
    commands.insert(commands.index(create_ewr) + 1, create_ord)
    enroll = next(command for command in commands if command["label"] == "enroll")
    enroll_index = commands.index(enroll)
    commands.pop(enroll_index)
    enrolled_commands = []
    for pair in pair_ids:
        enrolled = copy.deepcopy(enroll)
        enrolled.update({"label": f"enroll-{pair}", "resourceID": f"pair-enroll-{pair}",
                         "liveArgs": pair_enrollments[pair]["enroll"], "liveArgsResolved": True})
        enrolled_commands.append(enrolled)
    commands[enroll_index:enroll_index] = enrolled_commands
    all_masters_labels = {"all-masters", "all-masters-resume", "chaos-baseline"}
    authority_command_labels = {f"configure-{identifier}" for identifier in authority_ids}
    enrollment_command_labels = {f"enroll-{pair}" for pair in pair_ids}
    expected_command_labels = ({command["label"] for command in commands} - {"create-ewr", "create-ord"} -
                               all_masters_labels - authority_command_labels - enrollment_command_labels)
    require(set(command_args) == expected_command_labels,
            "commandLiveArgs must contain every non-create command label exactly once")
    for command in commands:
        if command["label"] in all_masters_labels:
            command["liveArgs"] = [all_masters_intent]
            command["liveArgsResolved"] = True
        elif command["label"] in authority_command_labels:
            identifier = command["label"][len("configure-"):]
            command["liveArgs"] = authority_requests[identifier]["configureLiveArgs"]
            command["liveArgsResolved"] = True
        elif command["label"] not in {"create-ewr", "create-ord"} | enrollment_command_labels:
            command["liveArgs"] = live_args(command_args[command["label"]], f"commandLiveArgs.{command['label']}",
                                             command["operation"].startswith("nametag"))
            command["liveArgsResolved"] = True
    result["commands"] = commands

    cleanup = copy.deepcopy(result["cleanup"])
    cleanup_ewr_index = next(index for index, command in enumerate(cleanup) if command["label"] == "cleanup-ewr")
    cleanup.insert(cleanup_ewr_index, {"label": "cleanup-ord", "operation": "removeCluster", "resourceType": "cluster",
                                       "resourceID": "ord", "args": []})
    cleanup_enroll = next(command for command in cleanup if command["label"] == "cleanup-pair-enroll")
    cleanup_enroll_index = cleanup.index(cleanup_enroll)
    cleanup.pop(cleanup_enroll_index)
    cleanup[cleanup_enroll_index:cleanup_enroll_index] = [
        {**copy.deepcopy(cleanup_enroll), "label": f"cleanup-pair-enroll-{pair}",
         "resourceID": f"pair-enroll-{pair}", "liveArgs": pair_enrollments[pair]["revoke"]}
        for pair in reversed(pair_ids)
    ]
    authority_cleanup_labels = {f"cleanup-{identifier}" for identifier in authority_ids}
    enrollment_cleanup_labels = {f"cleanup-pair-enroll-{pair}" for pair in pair_ids}
    expected_cleanup_labels = ({command["label"] for command in cleanup} - authority_cleanup_labels -
                               enrollment_cleanup_labels)
    require(set(cleanup_args) == expected_cleanup_labels,
            "cleanupLiveArgs must contain every cleanup label exactly once")
    for command in cleanup:
        if command["label"] in authority_cleanup_labels:
            identifier = command["label"][len("cleanup-"):]
            command["liveArgs"] = authority_requests[identifier]["withdrawLiveArgs"]
        elif command["label"] not in enrollment_cleanup_labels:
            command["liveArgs"] = live_args(cleanup_args[command["label"]], f"cleanupLiveArgs.{command['label']}")
        command["liveArgsResolved"] = True
        require(command["resourceID"] != "lan", "cleanup may not mutate protected LAN")
        if command["operation"] == "removeCluster":
            target = create_targets[command["resourceID"]]["name"]
            require(command["liveArgs"] == [target],
                    f"{command['label']} must remove only its exact task-owned cluster name")
    result["cleanup"] = cleanup

    for row in result["chaos"]:
        for direction in ("injection", "observation"):
            row[direction]["liveArgs"] = []
            row[direction]["liveArgsResolved"] = True
    require(not any(command["operation"] in {"createCluster", "removeCluster"} and command["resourceID"] == "lan"
                    for command in result["commands"] + result["cleanup"]),
            "live campaign may not create or remove protected LAN")
    return result


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="explicit public campaign materialization JSON")
    parser.add_argument("--output", required=True, help="absolute output manifest path")
    parser.add_argument("--template", required=True, help="frozen qualification manifest template")
    args = parser.parse_args(argv)
    try:
        require(os.path.isabs(args.output), "--output must be absolute")
        result = materialize(load_json(args.input, "input"), load_json(args.template, "template"))
        directory = os.path.dirname(args.output)
        require(os.path.isdir(directory), "--output parent directory must already exist")
        fd, temporary = tempfile.mkstemp(prefix=".nametag-three-cluster-manifest.", suffix=".json", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(result, handle, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
            os.replace(temporary, args.output)
        except BaseException:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise
    except MaterializationError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
