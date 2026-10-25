#!/usr/bin/env python3
"""Private HTTP identity/access service for the Phase 15 safe twin."""

import hashlib
import json
import os
import socket
import sys
import urllib.parse

VULNERABLE = False
REASONS = {
    200: "OK",
    202: "Accepted",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
}
USERS = {
    "alice": {"role": "ordinary", "tenant": "red"},
    "bob": {"role": "ordinary", "tenant": "red"},
    "carol": {"role": "ordinary", "tenant": "blue"},
    "admin": {"role": "administrator", "tenant": "red"},
}
OBJECTS = {
    "red-alice": {"owner": "alice", "tenant": "red"},
    "red-bob": {"owner": "bob", "tenant": "red"},
    "blue-carol": {"owner": "carol", "tenant": "blue"},
}


def load(path: str) -> dict[str, str]:
    with open(path, encoding="utf-8") as source:
        value = json.load(source)
    if not isinstance(value, dict) or not all(
        isinstance(key, str) and isinstance(item, str) for key, item in value.items()
    ):
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


def nested(state: dict[str, str], key: str) -> dict[str, object]:
    value = json.loads(state.get(key, "{}"))
    if not isinstance(value, dict):
        raise RuntimeError(f"invalid {key}")
    return value


def store_nested(state: dict[str, str], key: str, value: dict[str, object]) -> None:
    state[key] = json.dumps(value, sort_keys=True, separators=(",", ":"))


def credential(secret: bytes, label: str) -> str:
    digest = hashlib.sha256()
    digest.update(b"peritus-phase15-v1\0")
    digest.update(secret)
    digest.update(label.encode())
    return digest.hexdigest()


def issue(state: dict[str, str], secret: bytes, username: str) -> str:
    counter = int(state.get("session_counter", "0")) + 1
    state["session_counter"] = str(counter)
    token = credential(secret, f"session:{username}:{counter}")
    sessions = nested(state, "sessions")
    sessions[token] = {"username": username, "valid": True, "expired": False}
    store_nested(state, "sessions", sessions)
    return token


def bearer(headers: dict[str, str]) -> str | None:
    value = headers.get("authorization", "")
    return value[7:] if value.startswith("Bearer ") else None


def principal(state: dict[str, str], token: str | None) -> str | None:
    record = nested(state, "sessions").get(token or "")
    if not isinstance(record, dict) or not isinstance(record.get("username"), str):
        return None
    if not VULNERABLE and (not record.get("valid") or record.get("expired")):
        return None
    return record["username"]


def invalidate(state: dict[str, str], token: str, *, expired: bool = False) -> None:
    sessions = nested(state, "sessions")
    record = sessions.get(token)
    if isinstance(record, dict):
        record["expired" if expired else "valid"] = True if expired else False
    store_nested(state, "sessions", sessions)


def invalidate_user(state: dict[str, str], username: str) -> None:
    sessions = nested(state, "sessions")
    for record in sessions.values():
        if isinstance(record, dict) and record.get("username") == username:
            record["valid"] = False
    store_nested(state, "sessions", sessions)


def read_request(connection: socket.socket) -> tuple[str, str, dict[str, str], bytes]:
    received = bytearray()
    while b"\r\n\r\n" not in received:
        chunk = connection.recv(4096)
        if not chunk:
            raise RuntimeError("connection closed before request head")
        received.extend(chunk)
        if len(received) > 262144:
            raise RuntimeError("request head exceeded limit")
    head, body = bytes(received).split(b"\r\n\r\n", 1)
    lines = head.decode("ascii").split("\r\n")
    method, target, version = lines[0].split()
    if version != "HTTP/1.1":
        raise RuntimeError("unsupported HTTP version")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    length = int(headers.get("content-length", "0"))
    while len(body) < length:
        chunk = connection.recv(min(4096, length - len(body)))
        if not chunk:
            raise RuntimeError("connection closed before request body")
        body += chunk
    return method, target, headers, body[:length]


def respond(connection: socket.socket, status: int, value: object) -> None:
    body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    head = (
        f"HTTP/1.1 {status} {REASONS[status]}\r\n"
        f"content-length: {len(body)}\r\n"
        "content-type: application/json\r\n"
        "connection: close\r\n"
        "x-content-type-options: nosniff\r\n\r\n"
    ).encode()
    connection.sendall(head + body)


def decoded(body: bytes) -> dict[str, object]:
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def handle(
    connection: socket.socket,
    method: str,
    target: str,
    headers: dict[str, str],
    body: bytes,
    state_path: str,
    secret: bytes,
) -> None:
    path = urllib.parse.urlsplit(target).path
    state = load(state_path)
    value = decoded(body)
    token = bearer(headers)
    username = principal(state, token)
    if path == "/health" and method == "GET":
        respond(connection, 200, {"ok": True})
        return
    if path == "/auth/login" and method == "POST":
        requested = value.get("username")
        password = value.get("password")
        if not isinstance(requested, str) or requested not in USERS:
            respond(connection, 401, {"error": "invalid login"})
            return
        if password != credential(secret, f"password:{requested}"):
            respond(connection, 401, {"error": "invalid login"})
            return
        if requested == "admin":
            challenge = credential(secret, "challenge:admin")
            challenges = nested(state, "challenges")
            challenges[challenge] = requested
            store_nested(state, "challenges", challenges)
            save(state_path, state)
            respond(connection, 202, {"challenge": challenge})
            return
        issued = issue(state, secret, requested)
        save(state_path, state)
        respond(connection, 200, {"token": issued})
        return
    if path == "/auth/mfa" and method == "POST":
        challenge = value.get("challenge")
        factor = value.get("factor")
        challenged = nested(state, "challenges").get(challenge or "")
        if challenged != "admin" or (
            not VULNERABLE and factor != credential(secret, "factor:admin")
        ):
            respond(connection, 403, {"error": "invalid factor"})
            return
        issued = issue(state, secret, "admin")
        save(state_path, state)
        respond(connection, 200, {"token": issued})
        return
    if path == "/auth/me" and method == "GET":
        if username is None:
            respond(connection, 401, {"error": "invalid session"})
        else:
            respond(connection, 200, {"role": USERS[username]["role"]})
        return
    if path == "/auth/logout" and method == "POST":
        if username is None or token is None:
            respond(connection, 401, {"error": "invalid session"})
            return
        if not VULNERABLE:
            invalidate(state, token)
        save(state_path, state)
        respond(connection, 200, {"logged_out": True})
        return
    if path == "/auth/rotate" and method == "POST":
        if username is None or token is None:
            respond(connection, 401, {"error": "invalid session"})
            return
        if not VULNERABLE:
            invalidate(state, token)
        replacement = issue(state, secret, username)
        save(state_path, state)
        respond(connection, 200, {"token": replacement})
        return
    if path == "/auth/expire" and method == "POST":
        if username is None or token is None:
            respond(connection, 401, {"error": "invalid session"})
            return
        invalidate(state, token, expired=True)
        save(state_path, state)
        respond(connection, 200, {"expired": True})
        return
    if path == "/auth/revoke" and method == "POST":
        if username is None or token is None:
            respond(connection, 401, {"error": "invalid session"})
            return
        invalidate(state, token)
        save(state_path, state)
        respond(connection, 200, {"revoked": True})
        return
    if path == "/auth/revoke-all" and method == "POST":
        if username is None:
            respond(connection, 401, {"error": "invalid session"})
            return
        if not VULNERABLE:
            invalidate_user(state, username)
        save(state_path, state)
        respond(connection, 200, {"revoked": "all"})
        return
    if path == "/auth/recover" and method == "POST":
        requested = value.get("username")
        if not isinstance(requested, str) or requested not in USERS:
            respond(connection, 400, {"error": "unknown account"})
            return
        recovery = credential(secret, f"recovery:{requested}")
        recoveries = nested(state, "recoveries")
        recoveries[recovery] = requested
        store_nested(state, "recoveries", recoveries)
        save(state_path, state)
        respond(connection, 200, {"recovery": recovery})
        return
    if path == "/auth/recover/complete" and method == "POST":
        recovery = value.get("recovery")
        recovered = nested(state, "recoveries").get(recovery or "")
        if not isinstance(recovered, str):
            respond(connection, 400, {"error": "invalid recovery"})
            return
        if not VULNERABLE:
            invalidate_user(state, recovered)
        state["recovery_completed"] = recovered
        save(state_path, state)
        respond(connection, 200, {"recovered": True})
        return
    if path == "/admin/report" and method == "GET":
        if not VULNERABLE and (username is None or USERS[username]["role"] != "administrator"):
            respond(connection, 403, {"error": "administrator required"})
        else:
            respond(connection, 200, {"report": "bounded"})
        return
    if path.startswith("/objects/") and method in {"GET", "PATCH"}:
        parts = path.split("/")
        object_id = parts[2] if len(parts) > 2 else ""
        object_record = OBJECTS.get(object_id)
        private = len(parts) == 4 and parts[3] == "private"
        if object_record is None or (len(parts) > 3 and not private):
            respond(connection, 404, {"error": "not found"})
            return
        allowed = username is not None and (
            USERS[username]["role"] == "administrator" or object_record["owner"] == username
        )
        if not VULNERABLE and not allowed:
            respond(connection, 401 if username is None else 403, {"error": "access denied"})
            return
        if method == "PATCH":
            state[f"object_{object_id.replace('-', '_')}"] = str(value.get("value", ""))
            save(state_path, state)
            respond(connection, 200, {"updated": True})
        else:
            respond(connection, 200, {"object": object_id, "private": private})
        return
    respond(connection, 404, {"error": "not found"})


def main() -> int:
    if len(sys.argv) != 4:
        return 64
    socket_path, state_path, secret_path = sys.argv[1:]
    with open(secret_path, "rb") as source:
        secret = source.read()
    try:
        os.unlink(socket_path)
    except FileNotFoundError:
        pass
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(socket_path)
        server.listen(8)
        while True:
            connection, _ = server.accept()
            with connection:
                connection.settimeout(2.0)
                try:
                    handle(connection, *read_request(connection), state_path, secret)
                except (OSError, RuntimeError, ValueError):
                    respond(connection, 400, {"error": "invalid request"})


if __name__ == "__main__":
    raise SystemExit(main())
