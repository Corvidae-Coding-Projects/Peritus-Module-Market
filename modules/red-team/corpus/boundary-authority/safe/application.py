#!/usr/bin/env python3
"""Copied controller for the Phase 18 safe boundary laboratory."""

import hashlib
import json
import os
import socket
import subprocess
import sys
import time


def ready(path: str) -> bool:
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(0.5)
            client.connect(path)
            client.sendall(b"GET /health HTTP/1.1\r\nHost: laboratory.invalid\r\nConnection: close\r\n\r\n")
            return client.recv(256).startswith(b"HTTP/1.1 200")
    except OSError:
        return False


def main() -> int:
    if len(sys.argv) != 6:
        return 64
    service_path, socket_path, state_path, secret_path, _canary_port = sys.argv[1:]
    child = subprocess.Popen(
        [sys.executable, service_path, socket_path, state_path, secret_path, "safe"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={},
    )
    try:
        deadline = time.monotonic() + 5.0
        while not ready(socket_path):
            if child.poll() is not None:
                detail = child.stderr.read(2048).decode("utf-8", errors="replace")
                raise RuntimeError(f"boundary service exited before readiness: {detail.strip()}")
            if time.monotonic() >= deadline:
                raise RuntimeError("boundary service readiness timed out")
            time.sleep(0.02)
        with open(secret_path, "rb") as source:
            secret_digest = hashlib.sha256(source.read()).hexdigest()
        print(json.dumps({"event":"ready","secret_digest":secret_digest,"target_report":{"host_file_blocked":True,"credentials_absent":not os.environ,"host_loopback_blocked":True,"external_network_blocked":True,"unregistered_descendant_blocked":True}}, separators=(",", ":")), flush=True)
        for line in sys.stdin:
            request = json.loads(line)
            if request.get("op") == "reset":
                with open(state_path, "w", encoding="utf-8") as output:
                    output.write("{}\n")
                    output.flush()
                    os.fsync(output.fileno())
                print('{"event":"reset"}', flush=True)
            else:
                print('{"event":"rejected","reason":"unknown operation"}', flush=True)
    finally:
        child.terminate()
        try:
            child.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=2.0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
