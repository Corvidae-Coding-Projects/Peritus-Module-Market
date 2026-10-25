"""Pinned browser observation for a stored-content attack-graph edge."""

import argparse
import hashlib
import json
import socket
from pathlib import Path
from urllib.parse import urlparse


def digest(value):
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-socket", type=Path, required=True)
    parser.add_argument("--browser-executable", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--maximum-actions", type=int, required=True)
    parser.add_argument("--maximum-requests", type=int, required=True)
    args = parser.parse_args()
    args.target_origin = "https://127.0.0.1:18443"
    args.output.mkdir(parents=True, exist_ok=True)
    traffic = []
    actions = 0
    blocked = 0

    def act():
        nonlocal actions
        actions += 1
        if actions > args.maximum_actions:
            raise RuntimeError("attack-graph browser action budget exhausted")

    def exchange(request):
        parsed = urlparse(request.url)
        body = request.post_data_buffer or b""
        headers = dict(request.headers)
        headers["host"] = parsed.netloc
        headers["connection"] = "close"
        headers["content-length"] = str(len(body))
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query
        wire = f"{request.method} {target} HTTP/1.1\r\n".encode() + b"".join(
            f"{name}: {value}\r\n".encode() for name, value in headers.items()
        ) + b"\r\n" + body
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
            stream.settimeout(5)
            stream.connect(str(args.target_socket))
            stream.sendall(wire)
            received = bytearray()
            while True:
                chunk = stream.recv(65536)
                if not chunk:
                    break
                received.extend(chunk)
                if len(received) > 2 * 1024 * 1024:
                    raise RuntimeError("module attack-graph response exceeded 2 MiB")
        response_head, response_body = bytes(received).split(b"\r\n\r\n", 1)
        lines = response_head.decode("iso-8859-1").split("\r\n")
        status = int(lines[0].split()[1])
        response_headers = {}
        for line in lines[1:]:
            name, value = line.split(":", 1)
            response_headers[name.strip()] = value.strip()
        return status, response_headers, response_body

    def route_request(route):
        nonlocal blocked
        parsed = urlparse(route.request.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin == args.target_origin and len(traffic) < args.maximum_requests:
            traffic.append({"event": "request", "method": route.request.method,
                            "path": parsed.path or "/"})
            status, headers, body = exchange(route.request)
            route.fulfill(status=status, headers=headers, body=body)
        else:
            blocked += 1
            route.abort()

    def response_seen(response):
        parsed = urlparse(response.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin == args.target_origin and len(traffic) < args.maximum_requests:
            traffic.append({"event": "response", "status": response.status,
                            "path": parsed.path or "/"})

    from playwright.sync_api import sync_playwright
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True,
            # The generic worker host already supplies the outer process/filesystem/network
            # sandbox; do not ask Chromium to construct a conflicting nested namespace.
            chromium_sandbox=False,
            executable_path=str(args.browser_executable),
            args=["--disable-background-networking", "--disable-gpu", "--enable-logging=stderr"],
        )
        browser_identity = browser.version
        context = browser.new_context(service_workers="block")
        context.route("**/*", route_request)
        context.on("response", response_seen)
        page = context.new_page()
        page.set_default_timeout(5000)
        page.set_default_navigation_timeout(10000)
        act()
        response = page.goto(args.target_origin + "/stored", wait_until="networkidle")
        act()
        comments = page.locator("#comments")
        rendered_html = comments.inner_html()
        stored_text = comments.text_content() or rendered_html
        screenshot = args.output / "stored.png"
        act()
        page.screenshot(path=str(screenshot), full_page=True)
        screenshot_bytes = screenshot.read_bytes()
        context.close()
        browser.close()

    signal_observed = any(
        item.get("event") == "request" and item.get("path") == "/signal"
        for item in traffic
    )
    canonical = json.dumps(traffic, sort_keys=True, separators=(",", ":"))
    result = {
        "schema": 1,
        "browser_identity": browser_identity,
        "status": response.status if response else 0,
        "signal_observed": signal_observed,
        "stored_text": stored_text,
        "rendered_html_digest": digest(rendered_html),
        "traffic_digest": digest(canonical),
        "requests_observed": sum(1 for item in traffic if item.get("event") == "request"),
        "actions_executed": actions,
        "off_scope_requests_blocked": blocked,
        "screenshot_digest": digest(screenshot_bytes),
        "screenshot_bytes": len(screenshot_bytes),
    }
    args.result.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
