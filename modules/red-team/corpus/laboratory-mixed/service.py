#!/usr/bin/env python3
"""Private Unix-socket JSON store for the disposable laboratory fixture."""

import json
import os
import socket
import sys


def load(path: str) -> dict[str, str]:
    with open(path, encoding="utf-8") as source:
        value = json.load(source)
    if not isinstance(value, dict) or not all(
        isinstance(key, str) and isinstance(item, str) for key, item in value.items()
    ):
        raise RuntimeError("invalid backing store state")
    return value


def save(path: str, value: dict[str, str]) -> None:
    temporary = path + ".next"
    with open(temporary, "w", encoding="utf-8") as output:
        json.dump(value, output, sort_keys=True, separators=(",", ":"))
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def respond(connection: socket.socket, value: dict[str, object]) -> None:
    connection.sendall(json.dumps(value, separators=(",", ":")).encode() + b"\n")


def main() -> int:
    if len(sys.argv) != 3:
        return 64
    socket_path, state_path = sys.argv[1:]
    abstract = socket_path.startswith("@")
    address = "\0" + socket_path[1:] if abstract else socket_path
    if not abstract:
        try:
            os.unlink(socket_path)
        except FileNotFoundError:
            pass
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(address)
        server.listen(4)
        while True:
            connection, _ = server.accept()
            with connection:
                received = bytearray()
                while b"\n" not in received:
                    chunk = connection.recv(65536)
                    if not chunk:
                        break
                    received.extend(chunk)
                    if len(received) > 65536:
                        break
                request = json.loads(bytes(received).split(b"\n", 1)[0])
                state = load(state_path)
                operation = request.get("op")
                if operation == "status":
                    respond(connection, {"ok": True, "entries": len(state)})
                elif operation == "put":
                    state[request["key"]] = request["value"]
                    save(state_path, state)
                    respond(connection, {"ok": True})
                elif operation == "get":
                    respond(connection, {"ok": True, "value": state.get(request["key"])})
                elif operation == "reset":
                    save(state_path, {})
                    respond(connection, {"ok": True})
                else:
                    respond(connection, {"ok": False, "error": "unknown operation"})


if __name__ == "__main__":
    raise SystemExit(main())
