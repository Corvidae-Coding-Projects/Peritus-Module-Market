#!/usr/bin/env python3
"""Interface-compatible service that preserves the three Stage 2 boundaries."""

import html
import json
import os
import socket
import sys
import urllib.parse


def load(path: str) -> dict[str, str]:
    with open(path, encoding="utf-8") as source:
        value = json.load(source)
    return value if isinstance(value, dict) else {}


def save(path: str, value: dict[str, str]) -> None:
    temporary = path + ".next"
    with open(temporary, "w", encoding="utf-8") as output:
        json.dump(value, output, sort_keys=True, separators=(",", ":"))
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def request(connection: socket.socket) -> tuple[str, str, dict[str, str], bytes]:
    received = bytearray()
    while b"\r\n\r\n" not in received:
        received.extend(connection.recv(4096))
        if len(received) > 65536:
            raise RuntimeError("request too large")
    head, body = bytes(received).split(b"\r\n\r\n", 1)
    lines = head.decode("ascii").split("\r\n")
    method, target, _version = lines[0].split()
    headers = dict(line.split(":", 1) for line in lines[1:])
    headers = {name.strip().lower(): value.strip() for name, value in headers.items()}
    length = int(headers.get("content-length", "0"))
    while len(body) < length:
        body += connection.recv(length - len(body))
    return method, target, headers, body[:length]


def respond(connection: socket.socket, status: int, body: str, content_type: str, headers=None) -> None:
    reasons = {200: "OK", 201: "Created", 400: "Bad Request", 403: "Forbidden", 404: "Not Found"}
    encoded = body.encode()
    fields = {"content-type": content_type, "content-length": str(len(encoded)), "connection": "close"}
    fields.update(headers or {})
    head = f"HTTP/1.1 {status} {reasons[status]}\r\n" + "".join(
        f"{name}: {value}\r\n" for name, value in fields.items()
    )
    connection.sendall((head + "\r\n").encode() + encoded)


def handle(connection: socket.socket, state_path: str) -> None:
    method, target, headers, body = request(connection)
    parsed = urllib.parse.urlsplit(target)
    state = load(state_path)
    if method == "GET" and parsed.path == "/health":
        respond(connection, 200, '{"status":"ok"}', "application/json")
    elif method == "GET" and parsed.path == "/":
        respond(connection, 200, "<main>ordinary application</main>", "text/html; charset=utf-8")
    elif method == "GET" and parsed.path == "/reflected":
        value = urllib.parse.parse_qs(parsed.query).get("q", [""])[0]
        respond(connection, 200, f"<main>{html.escape(value, quote=True)}</main>", "text/html; charset=utf-8")
    elif method == "GET" and parsed.path == "/lookup":
        identifier = urllib.parse.parse_qs(parsed.query).get("id", [""])[0]
        if not identifier.isdecimal():
            respond(connection, 400, '{"error":"invalid id"}', "application/json")
        else:
            respond(connection, 200, '{"record":"public"}', "application/json")
    elif method == "POST" and parsed.path == "/store-comment":
        comment = str(json.loads(body).get("comment", ""))
        state["comment"] = html.escape(comment, quote=True)
        save(state_path, state)
        respond(connection, 201, '{"stored":true}', "application/json")
    elif method == "GET" and parsed.path == "/store":
        respond(connection, 200, """<input id=comment><button id=store>store</button><script>
        store.onclick=async()=>fetch('/store-comment',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({comment:comment.value})})
        </script>""", "text/html; charset=utf-8")
    elif method == "GET" and parsed.path == "/stored":
        respond(connection, 200, f"<main>{state.get('comment', '')}</main>", "text/html; charset=utf-8")
    elif method == "GET" and parsed.path == "/signal":
        respond(connection, 200, "{}", "application/json")
    elif method == "GET" and parsed.path == "/dom":
        respond(connection, 200, "<main id=content></main><script src=/client.js></script>", "text/html; charset=utf-8")
    elif method == "GET" and parsed.path == "/client.js":
        respond(connection, 200, "content.textContent=decodeURIComponent(location.hash.slice(1))", "application/javascript")
    elif method == "GET" and parsed.path == "/csp":
        respond(connection, 200, "<main>policy</main>", "text/html; charset=utf-8", {"content-security-policy":"default-src 'self'; script-src 'self'"})
    elif method == "GET" and parsed.path == "/session":
        respond(connection, 200, "session", "text/plain", {"set-cookie":"session=stage2; Path=/; HttpOnly; Secure; SameSite=Strict"})
    elif method == "GET" and parsed.path == "/attack-origin":
        respond(connection, 200, "attacker origin", "text/plain")
    elif method == "POST" and parsed.path == "/origin-protected":
        respond(connection, 403, "{}", "application/json")
    elif method == "GET" and parsed.path == "/attack-csrf":
        target = urllib.parse.parse_qs(parsed.query).get("target", [""])[0]
        respond(connection, 200, f"<form action='{html.escape(target, quote=True)}/transfer' method=post><button id=attack>attack</button></form>", "text/html; charset=utf-8")
    elif method == "POST" and parsed.path == "/transfer":
        respond(connection, 403, "{}", "application/json")
    elif method == "GET" and parsed.path == "/form":
        respond(connection, 200, "<form></form>", "text/html; charset=utf-8")
    elif method == "POST" and parsed.path == "/submit":
        respond(connection, 400, "{}", "application/json")
    elif method == "GET" and parsed.path == "/crawl":
        respond(connection, 200, "<a href=/linked>linked</a>", "text/html; charset=utf-8")
    elif method == "GET" and parsed.path == "/linked":
        respond(connection, 200, "linked", "text/plain")
    elif method == "GET" and parsed.path == "/rendered":
        respond(connection, 200, "<main><a href=/rendered-link>rendered</a></main>", "text/html; charset=utf-8")
    elif method == "GET" and parsed.path == "/rendered.js":
        respond(connection, 200, "", "application/javascript")
    elif method == "GET" and parsed.path == "/rendered-link":
        respond(connection, 200, "rendered", "text/plain")
    elif method == "GET" and parsed.path == "/download-page":
        respond(connection, 200, "<a id=download href=/download download>download</a>", "text/html; charset=utf-8")
    elif method == "GET" and parsed.path == "/download":
        respond(connection, 200, "stage2-download", "application/octet-stream", {"content-disposition":"attachment; filename=stage2.bin"})
    elif method == "GET" and parsed.path == "/upload-page":
        respond(connection, 200, """<input id=upload-file type=file><button id=upload>upload</button><script>
        upload.onclick=()=>fetch('/upload',{method:'POST',body:upload_file.files[0]})
        </script>""", "text/html; charset=utf-8")
    elif method == "POST" and parsed.path == "/upload":
        state["upload_digest"] = "observed"
        save(state_path, state)
        respond(connection, 200, "{}", "application/json")
    elif method == "POST" and parsed.path == "/admin":
        if headers.get("x-actor") != "admin":
            respond(connection, 403, '{"error":"forbidden"}', "application/json")
        else:
            state["admin_action"] = "admin"
            save(state_path, state)
            respond(connection, 200, '{"updated":true}', "application/json")
    else:
        respond(connection, 404, '{}', "application/json")


def main() -> int:
    socket_path, state_path, _secret_path = sys.argv[1:]
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(socket_path)
    server.listen(8)
    while True:
        connection, _ = server.accept()
        with connection:
            handle(connection, state_path)


if __name__ == "__main__":
    raise SystemExit(main())
