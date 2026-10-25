#!/usr/bin/env python3
"""Stateful application service used through Peritus's copied laboratory interface."""

import hashlib
import json
import os
import socket
import subprocess
import sys
import time


def store_request(socket_path: str, request: dict[str, str]) -> dict[str, object]:
    payload = json.dumps(request, separators=(",", ":")).encode() + b"\n"
    address = "\0" + socket_path[1:] if socket_path.startswith("@") else socket_path
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(2.0)
        client.connect(address)
        client.sendall(payload)
        received = bytearray()
        while b"\n" not in received:
            chunk = client.recv(65536)
            if not chunk:
                raise RuntimeError("backing service closed before a complete response")
            received.extend(chunk)
            if len(received) > 65536:
                raise RuntimeError("backing service response exceeded limit")
    return json.loads(bytes(received).split(b"\n", 1)[0])


def attempt_host_file() -> bool:
    try:
        with open("/etc/passwd", "rb") as source:
            source.read(1)
        return False
    except OSError:
        return True


def attempt_host_loopback(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.25):
            return False
    except OSError:
        return True


def attempt_external_network() -> bool:
    try:
        with socket.create_connection(("192.0.2.1", 9), timeout=0.25):
            return False
    except OSError:
        return True


def attempt_unregistered_descendant() -> bool:
    try:
        subprocess.run(["/bin/sh", "-c", "true"], check=True, timeout=1.0)
        return False
    except (OSError, subprocess.SubprocessError):
        return True


def main() -> int:
    if len(sys.argv) != 6:
        return 64
    service_path, socket_path, state_path, secret_path, canary_port = sys.argv[1:]
    child = subprocess.Popen(
        [sys.executable, service_path, socket_path, state_path],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={},
    )
    try:
        deadline = time.monotonic() + 5.0
        while True:
            if child.poll() is not None:
                stderr = child.stderr.read(2048).decode("utf-8", errors="replace")
                raise RuntimeError(
                    f"backing service exited before readiness: {stderr.strip()}"
                )
            try:
                store_request(socket_path, {"op": "status"})
                break
            except OSError:
                pass
            if time.monotonic() >= deadline:
                raise RuntimeError("backing service readiness timed out")
            time.sleep(0.02)
        with open(secret_path, "rb") as source:
            secret_digest = hashlib.sha256(source.read()).hexdigest()
        credentials_absent = all(
            name not in os.environ
            for name in (
                "AWS_SECRET_ACCESS_KEY",
                "GITHUB_TOKEN",
                "OPENAI_API_KEY",
                "ANTHROPIC_API_KEY",
                "HOME",
            )
        )
        ready = {
            "event": "ready",
            "secret_digest": secret_digest,
            "target_report": {
                "host_file_blocked": attempt_host_file(),
                "credentials_absent": credentials_absent,
                "host_loopback_blocked": attempt_host_loopback(int(canary_port)),
                "external_network_blocked": attempt_external_network(),
                "unregistered_descendant_blocked": attempt_unregistered_descendant(),
            },
        }
        print(json.dumps(ready, separators=(",", ":")), flush=True)
        for line in sys.stdin:
            if len(line) > 65536:
                return 65
            request = json.loads(line)
            operation = request.get("op")
            if operation == "round_trip":
                key = request["key"]
                value = request["value"]
                store_request(socket_path, {"op": "put", "key": key, "value": value})
                observed = store_request(socket_path, {"op": "get", "key": key})
                print(
                    json.dumps(
                        {"event": "round_trip", "key": key, "value": observed["value"]},
                        separators=(",", ":"),
                    ),
                    flush=True,
                )
            elif operation == "reset":
                store_request(socket_path, {"op": "reset"})
                print(json.dumps({"event": "reset"}, separators=(",", ":")), flush=True)
            else:
                print(
                    json.dumps({"event": "rejected", "reason": "unknown operation"}),
                    flush=True,
                )
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
