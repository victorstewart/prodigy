#!/usr/bin/env python3
"""Host-local behavior test for the provider's embedded persistent traffic worker."""
import json
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

source_root = Path(__file__).resolve().parents[2]
provider = source_root / "mothership/mothership.virtual.datacenter.provider.sh"
text = provider.read_text()
worker_start = text.index("import json, socket, sys, threading, time", text.index("probe_traffic_datacenter()"))
worker_end = text.index("\nPROBE_TRAFFIC", worker_start)
worker = text[worker_start:worker_end]

class Server:
    def __init__(self, mode, delay=0.0):
        self.mode, self.delay, self.stop = mode, delay, False
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0)); self.listener.listen()
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self.accept, daemon=True); self.thread.start()
    def accept(self):
        while not self.stop:
            try:
                self.listener.settimeout(.05); conn, _ = self.listener.accept()
            except socket.timeout: continue
            except OSError: return
            threading.Thread(target=self.serve, args=(conn,), daemon=True).start()
    def serve(self, conn):
        with conn:
            buffered = b""
            while True:
                data = conn.recv(4096)
                if not data: return
                buffered += data
                while b"\n" in buffered:
                    _, buffered = buffered.split(b"\n", 1)
                    if self.delay: time.sleep(self.delay)
                    if self.mode == "timeout": continue
                    if self.mode == "eof": return
                    conn.sendall(b"pong\n" if self.mode == "pong" else b"wrong\n")
    def close(self):
        self.stop = True; self.listener.close(); self.thread.join(.2)

def run(worker_path, mode, per_client, timeout_ms, interval_ms, delay=0.0):
    server = Server(mode, delay)
    try:
        completed = subprocess.run(
            [sys.executable, str(worker_path), "127.0.0.1", str(server.port), "ping", "pong",
             str(timeout_ms), "4", str(per_client), str(interval_ms)],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)
    finally:
        server.close()
    lines = [json.loads(line) for line in completed.stdout.splitlines()]
    requests = [line for line in lines if line.get("type") == "request"]
    summaries = [line for line in lines if line.get("type") == "summary"]
    assert len(requests) == 4 * per_client, completed.stderr
    assert len(summaries) == 1 and summaries[0]["attempts"] == 4 * per_client
    return completed, requests, summaries[0]

with tempfile.TemporaryDirectory() as directory:
    worker_path = Path(directory) / "traffic-worker.py"
    worker_path.write_text(worker)
    completed, requests, summary = run(worker_path, "pong", 150, 1000, 0)
    assert completed.returncode == 0 and summary["successes"] == 600
    assert max(item["connection"] for item in requests) == 1
    assert all(item["outcome"] == "pong" and item["latencyNs"] >= 0 for item in requests)

    completed, requests, summary = run(worker_path, "unexpected", 3, 250, 0)
    assert completed.returncode != 0 and summary["failures"] == 12
    assert {item["outcome"] for item in requests} == {"unexpected"}

    completed, requests, summary = run(worker_path, "timeout", 2, 50, 0)
    assert completed.returncode != 0 and summary["failures"] == 8
    assert {item["outcome"] for item in requests} == {"timeout"}

    completed, requests, summary = run(worker_path, "eof", 1, 250, 0)
    assert completed.returncode != 0 and summary["failures"] == 4
    assert {item["outcome"] for item in requests} == {"eof"}

    started = time.monotonic()
    completed, requests, summary = run(worker_path, "timeout", 3, 20, 100, .05)
    assert completed.returncode != 0 and summary["failures"] == 12
    assert time.monotonic() - started >= .18
    assert all(item["latencyNs"] >= 15_000_000 for item in requests)

    # With scheduled deadlines, a delayed peer cannot turn 60 planned requests
    # into 60 serial timeout windows. Every sequence remains independently
    # accounted, which lets the scenario group one-minute buckets by sequence//600.
    started = time.monotonic()
    completed, requests, summary = run(worker_path, "timeout", 60, 20, 5, .05)
    assert completed.returncode != 0 and summary["attempts"] == 240 and summary["failures"] == 240
    assert {(item["client"], item["sequence"]) for item in requests} == {(client, sequence) for client in range(4) for sequence in range(60)}
    assert time.monotonic() - started < .8

print("prodigy_mothership_probe_traffic_unit: PASS")
