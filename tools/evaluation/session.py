#!/usr/bin/env python3
"""Foreground example client. Mothership owns every cluster lifecycle operation."""

import fcntl
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import urllib.request
import uuid

from verify import verify

APPLICATION = "HelloProdigy"
URL = "http://198.18.0.10:8080/"
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def write_json(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def process_identity():
    return {"pid": os.getpid(), "boot": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "start": Path("/proc/self/stat").read_text().split()[21]}


def alive(state):
    try:
        return (Path("/proc/sys/kernel/random/boot_id").read_text().strip() == state["boot"]
                and Path(f"/proc/{int(state['pid'])}/stat").read_text().split()[21] == state["start"])
    except (OSError, KeyError, ValueError):
        return False


def load_active(root):
    path = root / ".run/evaluation-active.json"
    try:
        state = json.loads(path.read_text())
        run = Path(state["run"])
        if run.parent != root / ".run/evaluation" or not re.fullmatch(r"hello-[0-9a-f]{32}", state["cluster"]):
            raise ValueError("invalid session locator")
        return state
    except FileNotFoundError:
        raise RuntimeError("No evaluation session is running. Start ./try-prodigy in another terminal.")


class Client:
    def __init__(self, root, state):
        self.root, self.state = root, state
        self.run = Path(state["run"])
        self.environment = os.environ.copy()
        self.environment["PRODIGY_MOTHERSHIP_TIDESDB_PATH"] = str(self.run / "mothership.tidesdb")
        self.environment["LD_LIBRARY_PATH"] = str(root / "bin/lib")

    def command(self, operation, *arguments, timeout=30, allow_failure=False):
        command = [str(self.root / "bin/mothership"), operation, *map(str, arguments)]
        try:
            result = subprocess.run(command, env=self.environment, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, timeout=timeout,
                                    # Client state is private, but Mothership's artifact
                                    # directories must retain their normal traversal mode.
                                    umask=0o022)
            output, status = result.stdout, result.returncode
        except subprocess.TimeoutExpired as error:
            output = (error.stdout or b"").decode(errors="replace") if isinstance(error.stdout, bytes) else (error.stdout or "")
            output += f"\n{operation} exceeded {timeout} seconds.\n"
            status = 124
        with (self.run / (operation + ".log")).open("a") as log:
            log.write(output)
        if status or re.search(re.escape(operation) + r" success=0\b", output):
            if not allow_failure:
                raise RuntimeError(output[-12000:] or f"{operation} failed ({status})")
        return output

    def wait_cluster(self):
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            self.check_stop()
            report = self.command("clusterReport", self.state["cluster"], timeout=8, allow_failure=True)
            if "Machine: state=healthy " in report and "controlPlaneReachable=1 runtimeReady=1" in report:
                return
            time.sleep(.5)
        raise RuntimeError("The cluster did not become ready; see clusterReport.log.")

    def check_stop(self):
        if (self.run / "stop").exists():
            raise InterruptedError("Evaluation stopped.")

    def wait_http(self, version):
        expected = f"hello from Prodigy v{version}\n"
        deadline = time.monotonic() + 120
        next_report = time.monotonic() + 5
        while time.monotonic() < deadline:
            self.check_stop()
            if time.monotonic() >= next_report:
                report = self.command("applicationReport", self.state["cluster"], APPLICATION,
                                      timeout=8, allow_failure=True)
                if "DeploymentState::failed" in report or re.search(r"nCrashes:\s*[1-9]", report):
                    raise RuntimeError("Application deployment failed:\n" + report)
                next_report = time.monotonic() + 5
            try:
                with OPENER.open(URL, timeout=2) as response:
                    body = response.read(8192).decode()
                    if response.status == 200 and body == expected:
                        (self.run / f"http-v{version}.txt").write_text(body)
                        print(body, end="", flush=True)
                        return
            except (OSError, ValueError):
                pass
            time.sleep(.5)
        raise RuntimeError(f"The service did not return the expected v{version} HTTP response. See {self.run}.")

    def deploy(self, version):
        assets = self.root / "examples/hello-prodigy"
        plan = json.loads((assets / f"hello-prodigy-v{version}.deployment.plan.v1.json").read_text())
        plan["config"]["applicationID"] = self.state["applicationID"]
        plan["config"]["architecture"] = self.state["architecture"]
        plan["wormholes"][0]["routablePrefixUUID"] = self.state["routablePrefixUUID"]
        target = self.run / f"deployment-v{version}.json"
        write_json(target, plan)
        blob = assets / f"hello-prodigy-v{version}.{self.state['architecture']}.container.zst"
        self.command("deploy", self.state["cluster"], "@" + str(target), blob, timeout=120)
        self.wait_http(version)
        report = self.command("applicationReport", self.state["cluster"], APPLICATION)
        (self.run / f"application-v{version}.txt").write_text(report)


def start(root, manifest):
    run_base = root / ".run/evaluation"
    run_base.mkdir(parents=True, exist_ok=True)
    # The reusable guest has one synthetic public address range, shared by all bundles.
    with Path("/run/prodigy-evaluation.lock").open("w") as session_lock:
        try:
            fcntl.flock(session_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("An evaluation is already running. Use ./try-prodigy status.")
        active = root / ".run/evaluation-active.json"
        if active.exists():
            previous = load_active(root)
            if alive(previous):
                raise RuntimeError("Another evaluation session is still running.")
            # Recover only the cluster identity left by this bundle's prior session.
            Client(root, previous).command("removeCluster", previous["cluster"], timeout=90)
            active.unlink()
        name = "hello-" + uuid.uuid4().hex
        run = run_base / name
        run.mkdir(mode=0o700)
        state = {**process_identity(), "cluster": name, "run": str(run), "architecture": manifest["architecture"]}
        write_json(active, state)
        client = Client(root, state)
        created = False
        started = time.monotonic()
        def interrupted(signum, frame):
            # Let an in-flight, timeout-bounded Mothership operation finish before removal.
            (run / "stop").touch()
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(sig, interrupted)
        try:
            request = {
                "name": name, "deploymentMode": "test", "nBrains": 1,
                "machineSchemas": [{"schema": "evaluation", "kind": "vm", "vmImageURI": "test://virtual-datacenter"}],
                "resourceReservation": "smoke", "osUpdatesEnabled": False,
                "test": {"workspaceRoot": "/tmp/prodigy-evaluation-" + name,
                         "machineCount": 1, "machineLogicalCores": 2, "machineMemoryMB": 2048,
                         "machineStorageMB": 4096, "brainBootstrapFamily": "ipv4",
                         "enableFakeIpv4Boundary": True, "interContainerMTU": 9000}}
            write_json(run / "cluster.json", request)
            print("Starting a disposable one-machine Prodigy cluster…", flush=True)
            created = True  # Removal also owns recovery after partially successful creation.
            client.command("createCluster", "@" + str(run / "cluster.json"), timeout=240)
            client.wait_cluster()
            output = client.command("reserveApplicationID", name, json.dumps({"applicationName": APPLICATION}))
            match = re.search(r"reserveApplicationID success=1 .*?appID=(\d+)\b", output)
            if not match:
                raise RuntimeError("Application identity reservation failed: " + output)
            state["applicationID"] = int(match[1])
            client.command("reserveServiceID", name, json.dumps({"applicationName": APPLICATION,
                           "applicationID": state["applicationID"], "serviceName": "http", "kind": "stateless"}))
            output = client.command("registerRoutableSubnet", name, json.dumps({
                "name": "hello-prodigy-public-ipv4", "kind": "BGP", "prefix": "198.18.0.10/32",
                "usage": "wormholes", "ingressScope": "singleMachine"}))
            match = re.search(r"registerRoutableSubnet success=1 .*?uuid=(0x[0-9a-f]{32})\b", output)
            if not match:
                raise RuntimeError("Public address reservation failed: " + output)
            state["routablePrefixUUID"] = match[1]
            write_json(active, state)
            client.deploy(1)
            elapsed = round(time.monotonic() - started, 3)
            write_json(run / "timing.json", {"bundleVersion": manifest["version"], "startToFirstResponseSeconds": elapsed})
            (run / "ready").touch()
            print(f"\nService: {URL}\nIn another terminal: ./try-prodigy status\nThen: ./try-prodigy update\n"
                  "Press Ctrl-C here to remove the demo. Sessions end automatically after 30 minutes.\n"
                  f"Evidence: {run}", flush=True)
            while time.monotonic() - started < 1800:
                client.check_stop()
                time.sleep(.25)
        except InterruptedError:
            pass
        finally:
            for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
                signal.signal(sig, signal.SIG_IGN)
            with (run / "operation.lock").open("w") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                if created:
                    client.command("containerLogs", name, APPLICATION, timeout=15, allow_failure=True)
                    print("Removing the demo through Mothership…", flush=True)
                    client.command("removeCluster", name, timeout=90)
                active.unlink(missing_ok=True)
                (run / "removed").touch()
                print("Demo removed.", flush=True)


def control(root, action):
    active = root / ".run/evaluation-active.json"
    if action == "stop" and not active.exists():
        return
    state = load_active(root)
    client = Client(root, state)
    if action == "stop":
        (client.run / "stop").touch()
        if not alive(state):
            client.command("removeCluster", state["cluster"], timeout=90)
            active.unlink(missing_ok=True)
        # Includes a bounded create/update already in flight and cluster removal.
        deadline = time.monotonic() + 480
        while active.exists() and time.monotonic() < deadline:
            time.sleep(.25)
        if active.exists():
            raise RuntimeError("Demo cleanup did not finish; evidence: " + str(client.run))
        return
    if not alive(state) or not (client.run / "ready").exists():
        raise RuntimeError("The evaluation is not ready. Check its foreground terminal.")
    with (client.run / "operation.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        client.check_stop()
        if action == "status":
            report = client.command("applicationReport", state["cluster"], APPLICATION)
            print("\n".join(line for line in report.splitlines()
                            if not line.startswith("mothership control ")))
            print("Service: " + URL)
        else:
            if (client.run / "http-v2.txt").exists():
                print("Version two is already deployed.")
                return
            print("Deploying application version two…", flush=True)
            client.deploy(2)


def main():
    if len(sys.argv) != 3 or sys.argv[2] not in ("start", "status", "update", "stop"):
        raise ValueError("usage: session.py BUNDLE start|status|update|stop")
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("Use ./try-prodigy to enter the documented Linux guest boundary.")
    os.umask(0o077)
    root = Path(sys.argv[1]).resolve(strict=True)
    if sys.argv[2] == "start":
        manifest = verify(root)
        machine = os.uname().machine
        if machine != manifest["architecture"]:
            raise RuntimeError(f"Bundle architecture {manifest['architecture']} does not match guest {machine}.")
        start(root, manifest)
    else:
        control(root, sys.argv[2])


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError) as error:
        print("Evaluation: " + str(error), file=sys.stderr)
        sys.exit(1)
