#!/usr/bin/env python3
"""Private HTTP/API service for the Phase 13 safe twin."""

import base64
import hashlib
import json
import os
import socket
import sys
import urllib.parse

VULNERABLE = False
REASONS = {
    101: "Switching Protocols",
    200: "OK",
    201: "Created",
    302: "Found",
    400: "Bad Request",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    409: "Conflict",
    415: "Unsupported Media Type",
    500: "Internal Server Error",
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


def response(
    connection: socket.socket,
    status: int,
    body: bytes = b"",
    headers: dict[str, str] | None = None,
) -> None:
    fields = {
        "content-length": str(len(body)),
        "content-type": "application/json",
        "connection": "close",
        "x-content-type-options": "nosniff",
    }
    if headers:
        fields.update(headers)
    head = [f"HTTP/1.1 {status} {REASONS[status]}"]
    head.extend(f"{name}: {value}" for name, value in fields.items())
    connection.sendall(("\r\n".join(head) + "\r\n\r\n").encode() + body)


def json_response(
    connection: socket.socket,
    status: int,
    value: object,
    headers: dict[str, str] | None = None,
) -> None:
    response(
        connection,
        status,
        json.dumps(value, separators=(",", ":"), sort_keys=True).encode(),
        headers,
    )


def html_response(connection: socket.socket, body: str, headers: dict[str, str] | None = None) -> None:
    fields = {"content-type": "text/html; charset=utf-8"}
    if headers:
        fields.update(headers)
    response(connection, 200, body.encode(), fields)


def mark(state_path: str, key: str, value: str = "1") -> None:
    state = load(state_path)
    state[key] = value
    save(state_path, state)


def openapi() -> dict[str, object]:
    paths: dict[str, object] = {
        "/health": {"get": {}},
        "/items": {"get": {}, "post": {}},
        "/redirect": {
            "get": {"parameters": [{"name": "next", "in": "query"}]}
        },
        "/host-link": {"get": {}},
        "/error": {"get": {}},
        "/lookup": {
            "get": {"parameters": [{"name": "id", "in": "query"}]}
        },
        "/admin": {"delete": {}},
        "/workflow/start": {"post": {}},
        "/workflow/finish": {"post": {}},
        "/graphql": {"post": {}},
        "/rpc": {"post": {}},
        "/ws": {"get": {}},
    }
    return {"openapi": "3.1.0", "info": {"title": "Phase 13 fixture", "version": "1"}, "paths": paths}


def websocket(connection: socket.socket, headers: dict[str, str]) -> None:
    key = headers.get("sec-websocket-key", "")
    accept = base64.b64encode(
        hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
    ).decode()
    response(
        connection,
        101,
        headers={
            "upgrade": "websocket",
            "connection": "Upgrade",
            "sec-websocket-accept": accept,
        },
    )
    head = connection.recv(2)
    if len(head) != 2 or head[0] != 0x81 or not head[1] & 0x80:
        return
    length = head[1] & 0x7F
    mask = connection.recv(4)
    payload = bytearray()
    while len(payload) < length:
        payload.extend(connection.recv(length - len(payload)))
    decoded = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    connection.sendall(bytes([0x81, len(decoded)]) + decoded)


def decoded_json(body: bytes) -> object | None:
    try:
        return json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def handle(
    connection: socket.socket,
    method: str,
    target: str,
    headers: dict[str, str],
    body: bytes,
    state_path: str,
    secret_path: str,
) -> None:
    parsed = urllib.parse.urlsplit(target)
    path = parsed.path
    query = urllib.parse.parse_qs(parsed.query)
    state = load(state_path)
    if path == "/" and method == "GET":
        html_response(connection, "<h1>Phase 14 browser fixture</h1><a href='/crawl'>crawl</a>")
    elif path == "/reflected" and method == "GET":
        value = query.get("q", [""])[0]
        rendered = value if VULNERABLE else value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        html_response(connection, f"<main id='result'>{rendered}</main>")
    elif path == "/store" and method == "GET":
        html_response(connection, """<textarea id='comment'></textarea><button id='store' onclick="fetch('/store-comment',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({comment:document.querySelector('#comment').value})})">store</button>""")
    elif path == "/store-comment" and method == "POST":
        value = decoded_json(body)
        if not isinstance(value, dict) or not isinstance(value.get("comment"), str):
            json_response(connection, 400, {"error": "invalid comment"})
        else:
            state["comment"] = value["comment"]
            save(state_path, state)
            json_response(connection, 200, {"stored": True})
    elif path == "/stored" and method == "GET":
        value = state.get("comment", "")
        rendered = value if VULNERABLE else value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        html_response(connection, f"<main id='comments'>{rendered}</main>")
    elif path == "/dom" and method == "GET":
        html_response(connection, "<main id='target'></main><script src='/client.js'></script>")
    elif path == "/client.js" and method == "GET":
        assignment = "innerHTML" if VULNERABLE else "textContent"
        response(connection, 200, f"document.querySelector('#target').{assignment}=decodeURIComponent(location.hash.slice(1));".encode(), {"content-type": "application/javascript"})
    elif path == "/signal" and method == "GET":
        case = query.get("case", [""])[0]
        if case in {"reflected", "stored", "dom", "csp", "replay"}:
            mark(state_path, f"signal_{case}")
            response(connection, 200, b"ok", {"content-type": "text/plain"})
        else:
            json_response(connection, 400, {"error": "invalid signal"})
    elif path == "/csp" and method == "GET":
        policy = None if VULNERABLE else {"content-security-policy": "default-src 'self'; script-src 'none'; object-src 'none'"}
        html_response(connection, "<script>fetch('/signal?case=csp')</script><p>CSP probe</p>", policy)
    elif path == "/session" and method == "GET":
        cookie = "session=phase14; Path=/" if VULNERABLE else "session=phase14; Path=/; HttpOnly; Secure; SameSite=Strict"
        html_response(connection, "<p>session ready</p>", {"set-cookie": cookie})
    elif path == "/attack-origin" and method == "GET":
        html_response(connection, "<p>separate browser origin</p>")
    elif path == "/origin-protected" and method == "POST":
        expected = "http://" + headers.get("host", "")
        if not VULNERABLE and headers.get("origin") != expected:
            json_response(connection, 403, {"error": "origin rejected"})
        else:
            mark(state_path, "origin_mutations")
            json_response(connection, 200, {"changed": True})
    elif path == "/attack-csrf" and method == "GET":
        target = query.get("target", [""])[0].rstrip("/")
        html_response(connection, f"<form method='POST' action='{target}/transfer'><input name='amount' value='10'><button id='attack'>transfer</button></form>")
    elif path == "/transfer" and method == "POST":
        expected = "http://" + headers.get("host", "")
        if not VULNERABLE and headers.get("origin") != expected:
            json_response(connection, 403, {"error": "csrf rejected"})
        else:
            mark(state_path, "csrf_transfers")
            html_response(connection, "<p>transfer accepted</p>")
    elif path == "/form" and method == "GET":
        html_response(connection, "<input id='age' type='number' min='0'><button>submit</button>")
    elif path == "/submit" and method == "POST":
        value = decoded_json(body)
        age = value.get("age") if isinstance(value, dict) else None
        if not isinstance(age, int) or (not VULNERABLE and age < 0):
            json_response(connection, 400, {"error": "invalid age"})
        else:
            mark(state_path, "invalid_submissions")
            json_response(connection, 200, {"accepted": True})
    elif path == "/crawl" and method == "GET":
        html_response(connection, "<a href='/linked'>linked</a>")
    elif path == "/linked" and method == "GET":
        html_response(connection, "<p>linked route</p>")
    elif path == "/rendered" and method == "GET":
        html_response(connection, "<main id='links'></main><script src='/rendered.js'></script>")
    elif path == "/rendered.js" and method == "GET":
        response(connection, 200, b"document.querySelector('#links').innerHTML=\"<a href='/rendered-link'>rendered</a>\"", {"content-type": "application/javascript"})
    elif path == "/rendered-link" and method == "GET":
        html_response(connection, "<p>rendered route</p>")
    elif path == "/download-page" and method == "GET":
        html_response(connection, "<a id='download' download='phase14.bin' href='/download'>download</a>")
    elif path == "/download" and method == "GET":
        response(connection, 200, b"peritus-phase14-download\n", {"content-type": "application/octet-stream", "content-disposition": "attachment; filename=phase14.bin"})
    elif path == "/upload-page" and method == "GET":
        html_response(connection, "<form method='POST' action='/upload' enctype='multipart/form-data'><input id='upload-file' name='file' type='file'><button id='upload'>upload</button></form>")
    elif path == "/upload" and method == "POST":
        marker = b"peritus-phase14-upload\n"
        if marker not in body:
            json_response(connection, 400, {"error": "upload missing"})
        else:
            mark(state_path, "upload_digest", hashlib.sha256(marker).hexdigest())
            html_response(connection, "<p>upload accepted</p>")
    elif path == "/ws" and headers.get("upgrade", "").lower() == "websocket":
        websocket(connection, headers)
        return
    if path == "/health" and method == "GET":
        json_response(connection, 200, {"ok": True})
    elif path == "/openapi.json" and method == "GET":
        json_response(connection, 200, openapi())
    elif path == "/items" and method == "GET":
        json_response(connection, 200, {"items": json.loads(state.get("items", "[]"))})
    elif path == "/items" and method in {"POST", "PUT"}:
        if method == "PUT" and not VULNERABLE:
            json_response(connection, 405, {"error": "method not allowed"})
            return
        if headers.get("content-type") != "application/json" and not VULNERABLE:
            json_response(connection, 415, {"error": "application/json required"})
            return
        value = decoded_json(body)
        if not isinstance(value, dict) or not isinstance(value.get("name"), str):
            json_response(connection, 400, {"error": "invalid JSON item"})
            return
        items = json.loads(state.get("items", "[]"))
        items.append(value["name"])
        state["items"] = json.dumps(items, separators=(",", ":"))
        save(state_path, state)
        json_response(connection, 201, {"created": value["name"]})
    elif path == "/redirect" and method == "GET":
        destination = query.get("next", [""])[0]
        if VULNERABLE:
            response(connection, 302, headers={"location": destination})
        else:
            json_response(connection, 400, {"error": "external redirect rejected"})
    elif path == "/host-link" and method == "GET":
        forwarded = headers.get("x-forwarded-host")
        location = (
            f"https://{forwarded}/continue"
            if VULNERABLE and forwarded
            else "https://laboratory.invalid/continue"
        )
        response(connection, 302, headers={"location": location})
    elif path == "/error" and method == "GET":
        if VULNERABLE:
            response(
                connection,
                500,
                b"Traceback (most recent call last): /private/service.py: deliberate failure",
                {"content-type": "text/plain"},
            )
        else:
            json_response(connection, 500, {"error": "internal error"})
    elif path == "/lookup" and method == "GET":
        identifier = query.get("id", [""])[0]
        if VULNERABLE and "OR 1=1" in identifier:
            with open(secret_path, "rb") as source:
                secret = source.read().hex()
            json_response(connection, 200, {"record": secret})
        else:
            json_response(connection, 400, {"error": "invalid identifier"})
    elif path == "/admin" and method == "DELETE":
        if not VULNERABLE:
            json_response(connection, 403, {"error": "identity required"})
            return
        state["admin_deletes"] = str(int(state.get("admin_deletes", "0")) + 1)
        save(state_path, state)
        json_response(connection, 200, {"deleted": True})
    elif path == "/workflow/start" and method == "POST":
        state["workflow_started"] = "workflow-1"
        save(state_path, state)
        json_response(connection, 200, {"token": "workflow-1"})
    elif path == "/workflow/finish" and method == "POST":
        value = decoded_json(body)
        if not isinstance(value, dict) or value.get("token") != state.get("workflow_started"):
            json_response(connection, 400, {"error": "invalid workflow token"})
            return
        completed = int(state.get("workflow_completions", "0"))
        if completed and not VULNERABLE:
            json_response(connection, 409, {"error": "already completed"})
            return
        state["workflow_completions"] = str(completed + 1)
        save(state_path, state)
        json_response(connection, 200, {"completed": True})
    elif path == "/graphql" and method == "POST":
        value = decoded_json(body)
        query_text = value.get("query", "") if isinstance(value, dict) else ""
        if "__schema" in query_text:
            if VULNERABLE:
                json_response(connection, 200, {"data": {"__schema": {"queryType": {"name": "Query"}}}})
            else:
                json_response(connection, 403, {"error": "introspection disabled"})
        elif "ping" in query_text:
            json_response(connection, 200, {"data": {"ping": "pong"}})
        else:
            json_response(connection, 400, {"error": "invalid query"})
    elif path == "/rpc" and method == "POST":
        value = decoded_json(body)
        if isinstance(value, dict) and value.get("method") == "math.add" and value.get("params") == [2, 3]:
            json_response(connection, 200, {"jsonrpc": "2.0", "id": value.get("id"), "result": 5})
        else:
            json_response(connection, 400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32601}})
    else:
        json_response(connection, 404, {"error": "not found"})


def main() -> int:
    if len(sys.argv) != 4:
        return 64
    socket_path, state_path, secret_path = sys.argv[1:]
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
                    handle(connection, *read_request(connection), state_path, secret_path)
                except (OSError, RuntimeError, ValueError):
                    json_response(connection, 400, {"error": "invalid request"})


if __name__ == "__main__":
    raise SystemExit(main())
