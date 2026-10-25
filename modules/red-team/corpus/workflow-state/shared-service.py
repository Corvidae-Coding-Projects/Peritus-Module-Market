"""Common executable surface for matched Phase 17 workflow twins."""

import json
import os
import socket
import sys
import threading
import urllib.parse

REASONS = {200: "OK", 201: "Created", 400: "Bad Request", 404: "Not Found", 409: "Conflict", 429: "Too Many Requests", 503: "Service Unavailable"}


def initial() -> dict[str, str]:
    return {"balance":"100", "spent":"0", "quota_used":"0", "requests":"{}", "recoveries":"0"}


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


def requests(state: dict[str, str]) -> dict[str, dict[str, object]]:
    value = json.loads(state["requests"])
    if not isinstance(value, dict):
        raise RuntimeError("invalid request ledger")
    return value


def store_requests(state: dict[str, str], value: dict[str, dict[str, object]]) -> None:
    state["requests"] = json.dumps(value, sort_keys=True, separators=(",", ":"))


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


def decoded(body: bytes) -> dict[str, object]:
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def apply_charge(state: dict[str, str], request_id: str, amount: int) -> tuple[int, object]:
    ledger = requests(state)
    record = ledger.get(request_id)
    if record is None:
        return 404, {"error":"unknown request"}
    if not VULNERABLE:
        if record.get("status") != "approved":
            return 409, {"error":"approval required"}
        if bool(record.get("processed")):
            return 200, {"duplicate":True}
        if int(state["quota_used"]) >= 2:
            return 429, {"error":"quota exceeded"}
        if int(state["balance"]) < amount:
            return 409, {"error":"insufficient balance"}
    state["balance"] = str(int(state["balance"]) - amount)
    state["spent"] = str(int(state["spent"]) + amount)
    state["quota_used"] = str(int(state["quota_used"]) + 1)
    record["processed"] = True
    record["status"] = "charged"
    ledger[request_id] = record
    store_requests(state, ledger)
    return 200, {"charged":True}


def deterministic_race(state_path: str, request_id: str, amount: int) -> tuple[int, object]:
    starting = load(state_path)
    barrier = threading.Barrier(2)
    decisions: list[bool] = []
    guard = threading.Lock()

    def worker() -> None:
        snapshot = json.loads(json.dumps(starting))
        ledger = requests(snapshot)
        record = ledger.get(request_id, {})
        barrier.wait()
        allowed = record.get("status") == "approved" and not bool(record.get("processed")) and int(snapshot["balance"]) >= amount and int(snapshot["quota_used"]) < 2
        with guard:
            decisions.append(bool(allowed))

    first = threading.Thread(target=worker)
    second = threading.Thread(target=worker)
    first.start()
    second.start()
    first.join()
    second.join()
    commits = sum(1 for allowed in decisions if allowed)
    if not VULNERABLE:
        commits = min(commits, 1)
    state = load(state_path)
    ledger = requests(state)
    record = ledger.get(request_id)
    if record is None or commits == 0:
        return 409, {"error":"race precondition rejected"}
    state["balance"] = str(int(state["balance"]) - amount * commits)
    state["spent"] = str(int(state["spent"]) + amount * commits)
    state["quota_used"] = str(int(state["quota_used"]) + commits)
    record["processed"] = True
    record["status"] = "charged"
    ledger[request_id] = record
    store_requests(state, ledger)
    save(state_path, state)
    return 200, {"workers":2, "commits":commits, "schedule":["read-a","read-b","write-a","write-b"]}


def crash_and_recover(state_path: str, amount: int) -> tuple[int, object]:
    child = os.fork()
    if child == 0:
        if VULNERABLE:
            state = load(state_path)
            state["spent"] = str(int(state["spent"]) + amount)
            save(state_path, state)
        else:
            with open(state_path + ".journal", "w", encoding="utf-8") as journal:
                journal.write(json.dumps({"amount":amount}))
                journal.flush()
                os.fsync(journal.fileno())
        os._exit(73)
    _pid, status = os.waitpid(child, 0)
    if not VULNERABLE:
        try:
            os.unlink(state_path + ".journal")
        except FileNotFoundError:
            pass
    state = load(state_path)
    state["recoveries"] = str(int(state["recoveries"]) + 1)
    save(state_path, state)
    return 503, {"worker_exit":os.waitstatus_to_exitcode(status), "recovered":True}


def handle(connection: socket.socket, method: str, target: str, body: bytes, state_path: str) -> None:
    path = urllib.parse.urlsplit(target).path
    if path == "/health" and method == "GET":
        respond(connection, 200, {"ok":True})
        return
    if path != "/phase17/action" or method != "POST":
        respond(connection, 404, {"error":"not found"})
        return
    value = decoded(body)
    operation = value.get("op")
    request_id = value.get("request_id")
    actor = value.get("actor")
    amount = value.get("amount", 30)
    if not isinstance(operation, str) or not isinstance(request_id, str) or not isinstance(actor, str) or not isinstance(amount, int) or amount < 1 or amount > 100:
        respond(connection, 400, {"error":"invalid action"})
        return
    if operation == "race":
        status, result = deterministic_race(state_path, request_id, amount)
        respond(connection, status, result)
        return
    if operation == "crash_recover":
        status, result = crash_and_recover(state_path, amount)
        respond(connection, status, result)
        return
    state = load(state_path)
    ledger = requests(state)
    status, result = 400, {"error":"unknown action"}
    if operation == "reset":
        state = initial()
        status, result = 200, {"reset":True}
    elif operation == "create":
        if request_id in ledger:
            status, result = 409, {"error":"duplicate request"}
        else:
            ledger[request_id] = {"actor":actor, "amount":amount, "status":"pending", "processed":False}
            store_requests(state, ledger)
            status, result = 201, {"created":True}
    elif operation == "approve":
        record = ledger.get(request_id)
        if record is None:
            status, result = 404, {"error":"unknown request"}
        elif not VULNERABLE and record.get("status") == "cancelled":
            status, result = 409, {"error":"cancelled is terminal"}
        else:
            record["status"] = "approved"
            ledger[request_id] = record
            store_requests(state, ledger)
            status, result = 200, {"approved":True}
    elif operation == "cancel":
        record = ledger.get(request_id)
        if record is None:
            status, result = 404, {"error":"unknown request"}
        elif not VULNERABLE and record.get("status") == "charged":
            status, result = 409, {"error":"charged is terminal"}
        else:
            record["status"] = "cancelled"
            ledger[request_id] = record
            store_requests(state, ledger)
            status, result = 200, {"cancelled":True}
    elif operation in {"charge", "retry_commit"}:
        status, result = apply_charge(state, request_id, amount)
        if operation == "retry_commit" and status == 200 and not bool(result.get("duplicate")):
            status, result = 503, {"error":"response lost after commit"}
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
                    handle(connection, *read_request(connection), state_path)
                except (OSError, RuntimeError, ValueError):
                    respond(connection, 503, {"error":"request failure"})


if __name__ == "__main__":
    raise SystemExit(serve())
