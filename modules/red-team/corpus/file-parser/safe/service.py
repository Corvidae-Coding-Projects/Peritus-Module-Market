#!/usr/bin/env python3
"""Safe Phase 16 file/archive/parser service."""

import base64
import io
import json
import os
from pathlib import Path
import socket
import sys
import tarfile
import urllib.parse

REASONS = {200: "OK", 400: "Bad Request", 404: "Not Found", 500: "Internal Server Error"}


def load(path: str) -> dict[str, str]:
    with open(path, encoding="utf-8") as source:
        value = json.load(source)
    if not isinstance(value, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in value.items()):
        raise RuntimeError("invalid copied state")
    return value


def save(path: str, value: dict[str, str]) -> None:
    temporary = path + ".next"
    with open(temporary, "w", encoding="utf-8") as output:
        json.dump(value, output, sort_keys=True, separators=(",", ":"))
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def read_request(connection: socket.socket) -> tuple[str, str, bytes]:
    received = bytearray()
    while b"\r\n\r\n" not in received:
        chunk = connection.recv(4096)
        if not chunk:
            raise RuntimeError("connection closed before request head")
        received.extend(chunk)
    head, body = bytes(received).split(b"\r\n\r\n", 1)
    lines = head.decode("ascii").split("\r\n")
    method, target, version = lines[0].split()
    if version != "HTTP/1.1":
        raise RuntimeError("unsupported HTTP version")
    headers = {}
    for line in lines[1:]:
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    length = int(headers.get("content-length", "0"))
    while len(body) < length:
        chunk = connection.recv(min(65536, length - len(body)))
        if not chunk:
            raise RuntimeError("connection closed before request body")
        body += chunk
    return method, target, body[:length]


def respond(connection: socket.socket, status: int, value: object) -> None:
    body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    head = f"HTTP/1.1 {status} {REASONS[status]}\r\ncontent-length: {len(body)}\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n"
    connection.sendall(head.encode() + body)


def contained(base: Path, requested: str) -> Path | None:
    relative = Path(requested)
    if relative.is_absolute() or ".." in relative.parts:
        return None
    candidate = base / relative
    try:
        resolved_base = base.resolve(strict=True)
        resolved_parent = candidate.parent.resolve(strict=True)
    except OSError:
        return None
    if resolved_parent != resolved_base and resolved_base not in resolved_parent.parents:
        return None
    return None if candidate.is_symlink() else candidate


def archive(root: Path, encoded: object) -> tuple[int, object]:
    if not isinstance(encoded, str):
        return 400, {"error": "invalid archive"}
    opened = tarfile.open(fileobj=io.BytesIO(base64.b64decode(encoded, validate=True)), mode="r:")
    members = opened.getmembers()
    if any(not member.isfile() or contained(root / "extract", member.name) is None for member in members):
        return 400, {"error": "unsafe archive member"}
    for member in members:
        candidate = contained(root / "extract", member.name)
        source = opened.extractfile(member)
        if candidate is None or source is None:
            raise RuntimeError("invalid admitted member")
        candidate.parent.mkdir(parents=True, exist_ok=True)
        with open(candidate, "wb") as output:
            output.write(source.read())
    return 200, {"extracted": True}


def handle(connection: socket.socket, method: str, target: str, body: bytes, state_path: str) -> None:
    path = urllib.parse.urlsplit(target).path
    if path == "/health" and method == "GET":
        respond(connection, 200, {"ok": True})
        return
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        value = {}
    if not isinstance(value, dict):
        value = {}
    root = Path(state_path).parent / "phase16"
    status, result = 404, {"error": "not found"}
    try:
        if path == "/phase16/file" and method == "POST":
            requested, content = value.get("path"), value.get("content")
            candidate = contained(root / "uploads", requested) if isinstance(requested, str) else None
            if candidate is None or not isinstance(content, str) or value.get("mode") is not None:
                status, result = 400, {"error": "unsafe file input"}
            else:
                candidate.parent.mkdir(parents=True, exist_ok=True)
                with open(candidate, "w", encoding="utf-8") as output:
                    output.write(content)
                status, result = 200, {"stored": True}
        elif path == "/phase16/temp" and method == "POST":
            status, result = 400, {"error": "predictable temporary names are rejected"}
        elif path == "/phase16/archive" and method == "POST":
            status, result = archive(root, value.get("archive"))
        elif path == "/phase16/parse" and method == "POST":
            encoded = value.get("input")
            data = base64.b64decode(encoded, validate=True) if isinstance(encoded, str) else b""
            if data == b"NATIVE":
                status, result = 400, {"error": "native control token rejected"}
            elif not data.startswith(b"PH16") or len(data) < 5 or len(data) != 5 + data[4]:
                status, result = 400, {"error": "invalid structured input"}
            else:
                status, result = 200, {"parsed_bytes": data[4]}
    except (OSError, RuntimeError, ValueError, tarfile.TarError):
        status, result = 400, {"error": "invalid input"}
    state = load(state_path)
    state["phase16_requests"] = str(int(state.get("phase16_requests", "0")) + 1)
    state["phase16_last_status"] = str(status)
    save(state_path, state)
    respond(connection, status, result)


def main() -> int:
    if len(sys.argv) != 4:
        return 64
    socket_path, state_path, _secret_path = sys.argv[1:]
    try:
        os.unlink(socket_path)
    except FileNotFoundError:
        pass
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(socket_path)
        listener.listen(8)
        while True:
            connection, _ = listener.accept()
            with connection:
                try:
                    handle(connection, *read_request(connection), state_path)
                except (OSError, RuntimeError, ValueError):
                    respond(connection, 500, {"error": "request failure"})


if __name__ == "__main__":
    raise SystemExit(main())
