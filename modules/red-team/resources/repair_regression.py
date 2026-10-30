#!/usr/bin/env python3
"""Bounded real-browser regression matrix for a Stage 6 patched twin."""

import argparse
import hashlib
import json
import socket
import time
from pathlib import Path
from urllib.parse import quote, urlparse


DESTINATION = "unix://poc-private/target.sock"
SYNTHETIC_IDENTITY = "ordinary-user:credential-free"
ORIGIN = "https://repair.invalid"
PAYLOAD = '<img src=x onerror="fetch(\'/signal?case=stored\')">'


def digest(value):
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def fail(message):
    raise RuntimeError(message)


def exchange(socket_path, method, target, body=b"", headers=None):
    fields = dict(headers or {})
    fields["host"] = "repair.invalid"
    fields["connection"] = "close"
    fields["content-length"] = str(len(body))
    wire = f"{method} {target} HTTP/1.1\r\n".encode() + b"".join(
        f"{name}: {value}\r\n".encode() for name, value in fields.items()
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
                fail("repair regression response exceeded 2 MiB")
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
        fail("repair regression response has no valid content length")
    if declared_length < 0 or len(response_body) < declared_length:
        fail("repair regression response body is shorter than its content length")
    response_body = response_body[:declared_length]
    return status, response_headers, response_body


def case(case_id, category, dimension, expected, observed, passed, evidence):
    return {
        "id": case_id,
        "category": category,
        "dimension": dimension,
        "expected": expected,
        "observed": observed,
        "passed": passed,
        "evidence_digest": digest(evidence),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-socket", type=Path, required=True)
    parser.add_argument("--destination", required=True)
    parser.add_argument("--synthetic-identity", required=True)
    parser.add_argument("--browser-executable", type=Path, required=True)
    parser.add_argument("--maximum-actions", type=int, required=True)
    parser.add_argument("--maximum-requests", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    args = parser.parse_args()

    # Refuse transport or identity mutations before importing Playwright or contacting a target.
    if args.destination != DESTINATION:
        fail("repair regression destination must be the exact private Unix destination")
    if args.synthetic_identity != SYNTHETIC_IDENTITY:
        fail("repair regression identity must be the exact synthetic credential-free subject")
    if not args.target_socket.is_socket():
        fail("repair regression target must be one resolved private Unix socket")
    if not args.browser_executable.is_absolute() or not args.browser_executable.is_file():
        fail("repair regression browser executable is unresolved")
    if not (16 <= args.maximum_actions <= 64 and 40 <= args.maximum_requests <= 160):
        fail("repair regression bounds are outside the registered profile")

    args.output.mkdir(parents=True, exist_ok=True)
    traffic = []
    actions = 0
    blocked = 0

    def act():
        nonlocal actions
        actions += 1
        if actions > args.maximum_actions:
            fail("repair regression browser action budget exhausted")

    def route_request(route):
        nonlocal blocked
        parsed = urlparse(route.request.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin == ORIGIN and len(traffic) < args.maximum_requests:
            body = route.request.post_data_buffer or b""
            target = parsed.path or "/"
            if parsed.query:
                target += "?" + parsed.query
            traffic.append({"event": "request", "method": route.request.method, "target": target})
            status, headers, response_body = exchange(
                args.target_socket, route.request.method, target, body, route.request.headers
            )
            route.fulfill(status=status, headers=headers, body=response_body)
        else:
            blocked += 1
            route.abort()

    from playwright.sync_api import sync_playwright

    cases = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True,
            chromium_sandbox=False,
            executable_path=str(args.browser_executable),
            args=["--disable-background-networking", "--disable-gpu"],
        )
        browser_identity = browser.version
        context = browser.new_context(service_workers="block")
        context.route("**/*", route_request)
        page = context.new_page()
        page.set_default_timeout(5000)
        page.set_default_navigation_timeout(10000)

        def store(value, content_type="application/json"):
            body = json.dumps({"comment": value}, separators=(",", ":")).encode()
            return exchange(
                args.target_socket,
                "POST",
                "/store-comment",
                body,
                {"content-type": content_type},
            )[0]

        def browse(target):
            before = len([item for item in traffic if item["event"] == "request" and item["target"].startswith("/signal")])
            act()
            response = page.goto(ORIGIN + target, wait_until="networkidle")
            after = len([item for item in traffic if item["event"] == "request" and item["target"].startswith("/signal")])
            return response.status if response else 0, after > before

        # Legitimate behavior remains available and renders the exact user text.
        legitimate = "ordinary <note> & text"
        status = store(legitimate)
        page_status, signal = browse("/stored")
        text = page.locator("#comments").text_content() or ""
        passed = status == 200 and page_status == 200 and text == legitimate and not signal
        cases.append(case("legitimate-store-read", "legitimate", "behavior", "stored text without signal", f"{status}:{page_status}:{text}:{signal}", passed, text))

        # Malformed input is rejected and cannot replace the prior legitimate state.
        malformed_status, _, _ = exchange(
            args.target_socket,
            "POST",
            "/store-comment",
            b"{",
            {"content-type": "application/json"},
        )
        page_status, signal = browse("/stored")
        text = page.locator("#comments").text_content() or ""
        passed = malformed_status == 400 and page_status == 200 and text == legitimate and not signal
        cases.append(case("malformed-json", "malformed", "encoding", "HTTP 400 and unchanged state", f"{malformed_status}:{text}:{signal}", passed, text))

        mutations = [
            ("encoding-entities", "encoding", "&#60;img src=x onerror=\"fetch('/signal?case=stored')\"&#62;", "application/json", 0.0),
            ("encoding-percent", "encoding", "%3Cimg%20src%3Dx%20onerror%3Dfetch('/signal?case=stored')%3E", "application/json", 0.0),
            ("ordering-overwrite", "ordering", PAYLOAD, "application/json", 0.0),
            ("transport-content-type", "transport", PAYLOAD, "Application/JSON; charset=utf-8", 0.0),
            ("state-repeat", "state", PAYLOAD, "application/json", 0.0),
            ("timing-delayed", "timing", PAYLOAD, "application/json", 0.05),
        ]
        for case_id, dimension, payload, content_type, delay in mutations:
            if dimension == "ordering":
                store("prior benign value")
            status = store(payload, content_type)
            if dimension == "state":
                status = store(payload, content_type)
            if delay:
                time.sleep(delay)
            page_status, signal = browse("/stored")
            text = page.locator("#comments").text_content() or ""
            passed = status == 200 and page_status == 200 and not signal and payload in text
            cases.append(case(case_id, "mutation", dimension, "input retained as text without signal", f"{status}:{page_status}:{signal}:{text}", passed, text))

        # Alternate reflected and DOM entry points exercise equivalent source/browser paths.
        reflected_status, reflected_signal = browse("/reflected?q=" + quote(PAYLOAD, safe=""))
        reflected_text = page.locator("#result").text_content() or ""
        reflected_passed = reflected_status == 200 and not reflected_signal and PAYLOAD in reflected_text
        cases.append(case("alternate-reflected", "adjacent", "alternate_entry", "payload rendered as text without signal", f"{reflected_status}:{reflected_signal}:{reflected_text}", reflected_passed, reflected_text))

        dom_status, dom_signal = browse("/dom#" + quote(PAYLOAD, safe=""))
        page.wait_for_function("document.readyState === 'complete'")
        dom_text = page.locator("#target").text_content() or ""
        dom_passed = dom_status == 200 and not dom_signal and PAYLOAD in dom_text
        cases.append(case("alternate-dom", "adjacent", "equivalent_adapter_path", "payload assigned as text without signal", f"{dom_status}:{dom_signal}:{dom_text}", dom_passed, dom_text))

        # The direct HTTP representation and browser projection must agree on escaped markup.
        store(PAYLOAD)
        direct_status, _, direct_body = exchange(args.target_socket, "GET", "/stored")
        page_status, signal = browse("/stored")
        equivalent_passed = (
            direct_status == 200
            and page_status == 200
            and not signal
            and b"&lt;img" in direct_body
            and PAYLOAD in (page.locator("#comments").text_content() or "")
        )
        cases.append(case("equivalent-http-browser", "supporting_adapter", "equivalent_adapter_path", "escaped HTTP bytes and inert browser text", f"{direct_status}:{page_status}:{signal}:{direct_body.decode(errors='replace')}", equivalent_passed, direct_body))

        context.close()
        browser.close()

    if not all(item["passed"] for item in cases):
        failed = ", ".join(item["id"] for item in cases if not item["passed"])
        fail(f"repair regression cases failed: {failed}")
    if actions > args.maximum_actions or len(traffic) > args.maximum_requests:
        fail("repair regression exceeded its admitted browser or request budget")

    canonical_traffic = json.dumps(traffic, sort_keys=True, separators=(",", ":"))
    result = {
        "schema": 2,
        "browser_identity": browser_identity,
        "cases": cases,
        "actions_executed": actions,
        "requests_observed": len(traffic),
        "off_scope_requests_blocked": blocked,
        "browser_cleanup_complete": True,
        "traffic_digest": digest(canonical_traffic),
    }
    result["result_digest"] = digest(json.dumps(result, sort_keys=True, separators=(",", ":")))
    args.result.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
