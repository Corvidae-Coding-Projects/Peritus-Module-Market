"""Common executable surface for matched Phase 18 boundary twins."""

import json
import os
import socket
import ssl
import sys
import urllib.parse

REASONS = {200:"OK", 202:"Accepted", 400:"Bad Request", 403:"Forbidden", 404:"Not Found", 500:"Internal Server Error", 495:"TLS Rejected"}


def initial() -> dict[str, str]:
    return {
        "policy_run_as_user":"", "policy_capabilities":"[]", "policy_no_new_privileges":"false",
        "privilege_attempts":"0", "host_privilege_effects":"0", "containment_held":"true",
        "untrusted_directives":"0", "delegated_actions":"0", "privileged_effects":"0",
        "host_authority_effects":"0", "last_case":"", "last_result":"",
    }


def load(path: str) -> dict[str, str]:
    try:
        with open(path, encoding="utf-8") as source:
            value = json.load(source)
    except (FileNotFoundError, json.JSONDecodeError):
        value = {}
    if not isinstance(value, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in value.items()):
        raise RuntimeError("invalid copied state")
    result = initial()
    result.update(value)
    return result


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
        if len(received) > 262144:
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
        chunk = connection.recv(min(4096, length - len(body)))
        if not chunk:
            raise RuntimeError("connection closed before request body")
        body += chunk
    return method, target, body[:length]


def respond(connection: socket.socket, status: int, value: object) -> None:
    body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    head = f"HTTP/1.1 {status} {REASONS[status]}\r\ncontent-length: {len(body)}\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n"
    connection.sendall(head.encode() + body)


def unix_http(path: str, request: bytes) -> bytes:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(2.0)
        client.connect(path)
        client.sendall(request)
        client.shutdown(socket.SHUT_WR)
        result = bytearray()
        while True:
            chunk = client.recv(4096)
            if not chunk:
                return bytes(result)
            result.extend(chunk)


def private_dns(path: str) -> bool:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(2.0)
        client.connect(path)
        client.sendall(b"DNS1\x00\x01lab.internal")
        client.shutdown(socket.SHUT_WR)
        return client.recv(256) == b"DNS1 lab.internal 192.0.2.10"


def tls_exchange(path: str, certificate: str, hostname: str, verify: bool, messages: int = 1) -> bool:
    context = ssl.create_default_context(cadata=certificate) if verify else ssl._create_unverified_context()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as raw:
        raw.settimeout(2.0)
        raw.connect(path)
        with context.wrap_socket(raw, server_hostname=hostname) as secure:
            secure.sendall(b"PING\n" * messages)
            received = bytearray()
            while received.count(b"PONG\n") < messages:
                chunk = secure.recv(256)
                if not chunk:
                    break
                received.extend(chunk)
            return received.count(b"PONG\n") == messages


def forbidden_destination(case: str) -> tuple[str, tuple[str, int]]:
    if case == "ssrf-host-loopback":
        return "http://127.0.0.1:9/private", ("127.0.0.1", 9)
    if case == "ssrf-lan":
        return "http://192.168.0.10/private", ("192.168.0.10", 9)
    return "http://198.51.100.10/private", ("198.51.100.10", 9)


def actual_forbidden_effect(destination: tuple[str, int]) -> bool:
    try:
        with socket.create_connection(destination, timeout=0.15):
            return True
    except OSError:
        return False


def apply(case: str, value: dict[str, object], state: dict[str, str]) -> tuple[int, object]:
    peers = value.get("peers")
    certificates = value.get("certificates")
    if not isinstance(peers, dict) or not isinstance(certificates, dict):
        return 400, {"error":"missing private peers"}
    state["last_case"] = case
    if case == "reset":
        state.clear()
        state.update(initial())
        return 200, {"reset":True}
    if case == "private-dns":
        return (200, {"resolved":True}) if private_dns(str(peers["dns"])) else (400, {"resolved":False})
    if case == "private-redirect":
        first = unix_http(str(peers["http"]), b"GET /redirect HTTP/1.1\r\nHost: private.peer\r\nConnection: close\r\n\r\n")
        if not first.startswith(b"HTTP/1.1 302"):
            return 400, {"error":"redirect peer failed"}
        second = unix_http(str(peers["http"]), b"GET /callback HTTP/1.1\r\nHost: private.peer\r\nConnection: close\r\n\r\n")
        return (200, {"followed":True}) if second.startswith(b"HTTP/1.1 204") else (400, {"followed":False})
    if case == "private-callback":
        response = unix_http(str(peers["http"]), b"GET /callback HTTP/1.1\r\nHost: private.peer\r\nConnection: close\r\n\r\n")
        return (200, {"callback":True}) if response.startswith(b"HTTP/1.1 204") else (400, {"callback":False})
    if case == "private-proxy":
        response = unix_http(str(peers["http"]), b"CONNECT lab.internal:443 HTTP/1.1\r\nHost: lab.internal\r\nConnection: close\r\n\r\n")
        return (200, {"proxy":True}) if response.startswith(b"HTTP/1.1 200") else (400, {"proxy":False})
    if case.startswith("ssrf-"):
        label, destination = forbidden_destination(case)
        effect = actual_forbidden_effect(destination)
        if effect:
            state["host_privilege_effects"] = str(int(state["host_privilege_effects"]) + 1)
        if VULNERABLE:
            request = f"GET /callback HTTP/1.1\r\nHost: private.peer\r\nX-Forbidden-Target: {label}\r\nConnection: close\r\n\r\n".encode()
            unix_http(str(peers["http"]), request)
            return 202, {"accepted":True,"direct_effect":effect}
        return 403, {"accepted":False,"direct_effect":effect}
    valid = str(certificates["valid"])
    expired = str(certificates["expired"])
    if case == "tls-trusted":
        return (200, {"tls":True}) if tls_exchange(str(peers["tls_valid"]), valid, "lab.internal", True) else (495, {"tls":False})
    if case == "tls-hostname-mismatch":
        try:
            accepted = tls_exchange(str(peers["tls_valid"]), valid, "wrong.internal", not VULNERABLE)
        except (OSError, ssl.SSLError):
            accepted = False
        return (200, {"accepted":True}) if accepted else (495, {"accepted":False})
    if case == "tls-expired":
        try:
            accepted = tls_exchange(str(peers["tls_expired"]), expired, "lab.internal", not VULNERABLE)
        except (OSError, ssl.SSLError):
            accepted = False
        return (200, {"accepted":True}) if accepted else (495, {"accepted":False})
    if case == "tls-downgrade":
        if not VULNERABLE:
            return 495, {"accepted":False}
        response = unix_http(str(peers["http"]), b"GET /downgrade HTTP/1.1\r\nHost: lab.internal\r\nConnection: close\r\n\r\n")
        return (200, {"accepted":True}) if response.endswith(b"PLAINTEXT") else (495, {"accepted":False})
    if case == "tls-connection-reuse":
        return (200, {"reused":True}) if tls_exchange(str(peers["tls_valid"]), valid, "lab.internal", True, 2) else (495, {"reused":False})
    if case == "local-policy":
        state["policy_run_as_user"] = "root" if VULNERABLE else "nonroot"
        state["policy_capabilities"] = json.dumps(["SYS_ADMIN","NET_ADMIN"] if VULNERABLE else [], separators=(",", ":"))
        state["policy_no_new_privileges"] = str(not VULNERABLE).lower()
        return 200, {"policy":True}
    if case == "contained-privilege":
        state["privilege_attempts"] = str(int(state["privilege_attempts"]) + 2)
        effects = 0
        try:
            with open("/etc/shadow", "rb") as source:
                source.read(1)
            effects += 1
        except OSError:
            pass
        try:
            os.setuid(0)
            if os.geteuid() == 0:
                effects += 1
        except OSError:
            pass
        state["host_privilege_effects"] = str(int(state["host_privilege_effects"]) + effects)
        state["containment_held"] = str(effects == 0).lower()
        return 200, {"attempts":2,"effects":effects}
    if case == "authority-legitimate":
        state["delegated_actions"] = str(int(state["delegated_actions"]) + 1)
        return 200, {"scope":"record.read","result":"public-record"}
    if case in {"authority-prompt", "authority-plugin"}:
        state["untrusted_directives"] = str(int(state["untrusted_directives"]) + 1)
        state["delegated_actions"] = str(int(state["delegated_actions"]) + 1)
        if VULNERABLE:
            state["privileged_effects"] = str(int(state["privileged_effects"]) + 1)
            return 200, {"admin_write":True}
        return 403, {"admin_write":False}
    return 404, {"error":"unknown case"}


def handle(connection: socket.socket, method: str, target: str, body: bytes, state_path: str) -> None:
    path = urllib.parse.urlsplit(target).path
    if path == "/health" and method == "GET":
        respond(connection, 200, {"ok":True})
        return
    if path != "/phase18/case" or method != "POST":
        respond(connection, 404, {"error":"not found"})
        return
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        respond(connection, 400, {"error":"invalid JSON"})
        return
    case = value.get("case") if isinstance(value, dict) else None
    if not isinstance(case, str):
        respond(connection, 400, {"error":"missing case"})
        return
    state = load(state_path)
    status, result = apply(case, value, state)
    state["last_result"] = json.dumps(result, sort_keys=True, separators=(",", ":"))
    save(state_path, state)
    respond(connection, status, result)


def serve() -> int:
    global VULNERABLE
    if len(sys.argv) != 5 or sys.argv[4] not in {"vulnerable", "safe"}:
        return 64
    socket_path, state_path, _secret_path, mode = sys.argv[1:]
    VULNERABLE = mode == "vulnerable"
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
                    method, target, body = read_request(connection)
                    handle(connection, method, target, body, state_path)
                except (OSError, RuntimeError, ssl.SSLError) as error:
                    respond(connection, 500, {"error":"peer operation failed","detail":str(error)})


if __name__ == "__main__":
    raise SystemExit(serve())
