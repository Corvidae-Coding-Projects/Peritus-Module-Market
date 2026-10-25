#!/usr/bin/env python3
"""Deliberately vulnerable Phase 16 file/archive/parser service."""

import base64
import ctypes
import faulthandler
import io
import json
import os
from pathlib import Path
import socket
import sys
import tarfile
import urllib.parse

VULNERABLE = True
REASONS = {200: "OK", 400: "Bad Request", 404: "Not Found", 500: "Internal Server Error", 503: "Service Unavailable"}


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
        if len(received) > 2 * 1024 * 1024:
            raise RuntimeError("request head exceeded limit")
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
    connection.sendall((f"HTTP/1.1 {status} {REASONS[status]}\r\ncontent-length: {len(body)}\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n").encode() + body)


def decoded(body: bytes) -> dict[str, object]:
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def contained(base: Path, requested: str) -> Path | None:
    candidate = base / requested
    if Path(requested).is_absolute() or ".." in Path(requested).parts:
        return None
    try:
        resolved_parent = candidate.parent.resolve(strict=True)
        resolved_base = base.resolve(strict=True)
    except OSError:
        return None
    if resolved_parent != resolved_base and resolved_base not in resolved_parent.parents:
        return None
    if candidate.is_symlink():
        return None
    return candidate


def native_fault() -> int | None:
    try:
        child = os.fork()
    except OSError:
        return None
    if child == 0:
        faulthandler.enable()
        ctypes.memmove(0, b"X", 1)
        os._exit(70)
    _, status = os.waitpid(child, 0)
    return os.WTERMSIG(status) if os.WIFSIGNALED(status) else None


def file_operation(root: Path, value: dict[str, object]) -> tuple[int, object]:
    requested, content = value.get("path"), value.get("content")
    if not isinstance(requested, str) or not isinstance(content, str):
        return 400, {"error": "invalid file input"}
    base = root / "uploads"
    target = base / requested if VULNERABLE else contained(base, requested)
    if target is None:
        return 400, {"error": "unsafe path"}
    target.parent.mkdir(parents=True, exist_ok=True)
    mode = value.get("mode")
    if VULNERABLE and isinstance(mode, int) and target.exists():
        os.chmod(target, mode)
    with open(target, "w", encoding="utf-8") as output:
        output.write(content)
    return 200, {"stored": True}


def temporary_operation(root: Path, value: dict[str, object]) -> tuple[int, object]:
    content = value.get("content")
    if not isinstance(content, str):
        return 400, {"error": "invalid temporary input"}
    if not VULNERABLE:
        return 400, {"error": "predictable temporary names are rejected"}
    with open(root / "temporary" / "predictable.tmp", "w", encoding="utf-8") as output:
        output.write(content)
    return 200, {"stored": True}


def archive_operation(root: Path, value: dict[str, object]) -> tuple[int, object]:
    encoded = value.get("archive")
    if not isinstance(encoded, str):
        return 400, {"error": "invalid archive input"}
    try:
        archive = tarfile.open(fileobj=io.BytesIO(base64.b64decode(encoded, validate=True)), mode="r:")
    except (ValueError, tarfile.TarError):
        return 400, {"error": "invalid archive"}
    base = root / "extract"
    for member in archive.getmembers():
        if not member.isfile():
            if not VULNERABLE:
                return 400, {"error": "unsupported archive member"}
            continue
        target = base / member.name if VULNERABLE else contained(base, member.name)
        if target is None:
            return 400, {"error": "unsafe archive member"}
        source = archive.extractfile(member)
        if source is None:
            return 400, {"error": "missing archive member"}
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "wb") as output:
            output.write(source.read())
    return 200, {"extracted": True}


def parser_operation(value: dict[str, object]) -> tuple[int, object]:
    encoded = value.get("input")
    if not isinstance(encoded, str):
        return 400, {"error": "invalid parser input"}
    try:
        data = base64.b64decode(encoded, validate=True)
    except ValueError:
        return 400, {"error": "invalid base64"}
    if data == b"NATIVE":
        if not VULNERABLE:
            return 400, {"error": "native control token rejected"}
        signal = native_fault()
        return (500, {"error": "native child fault", "native_signal": signal}) if signal else (503, {"error": "native instrumentation unavailable"})
    if not data.startswith(b"PH16") or len(data) < 5:
        return 400, {"error": "unknown grammar"}
    declared = data[4]
    if len(data) != 5 + declared:
        if VULNERABLE:
            raise RuntimeError("length field exceeds structured input")
        return 400, {"error": "invalid declared length"}
    return 200, {"parsed_bytes": declared}


def handle(connection: socket.socket, method: str, target: str, body: bytes, state_path: str) -> None:
    path = urllib.parse.urlsplit(target).path
    if path == "/health" and method == "GET":
        respond(connection, 200, {"ok": True})
        return
    value = decoded(body)
    root = Path(state_path).parent / "phase16"
    operations = {
        "/phase16/file": file_operation,
        "/phase16/temp": temporary_operation,
        "/phase16/archive": archive_operation,
    }
    try:
        if path in operations and method == "POST":
            status, result = operations[path](root, value)
        elif path == "/phase16/parse" and method == "POST":
            status, result = parser_operation(value)
        else:
            status, result = 404, {"error": "not found"}
    except (OSError, RuntimeError) as error:
        status, result = 500, {"error": type(error).__name__}
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
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(socket_path)
    listener.listen(8)
    while True:
        connection, _ = listener.accept()
        with connection:
            try:
                method, target, body = read_request(connection)
                handle(connection, method, target, body, state_path)
            except (OSError, RuntimeError, ValueError):
                try:
                    respond(connection, 500, {"error": "request failure"})
                except OSError:
                    pass


if __name__ == "__main__":
    raise SystemExit(main())
