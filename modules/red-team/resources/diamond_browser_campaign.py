"""Application-specific real-browser campaign for a disposable Diamond server."""

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
    parser.add_argument("--target", required=True)
    parser.add_argument("--browser-executable", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    public_origin = "http://localhost:18443"
    allowed_origins = {public_origin, args.target}
    traffic = []
    cases = []
    artifacts = []
    blocked = 0
    actions = 0
    target = urlparse(args.target)

    def exchange(request, path):
        body = request.post_data_buffer or b""
        headers = dict(request.headers)
        headers["host"] = f"localhost:{target.port}"
        if "origin" in headers:
            headers["origin"] = f"http://localhost:{target.port}"
        if "referer" in headers:
            headers["referer"] = headers["referer"].replace(public_origin, f"http://localhost:{target.port}")
        headers["connection"] = "close"
        headers["content-length"] = str(len(body))
        wire = f"{request.method} {path} HTTP/1.1\r\n".encode()
        wire += b"".join(f"{name}: {value}\r\n".encode() for name, value in headers.items())
        wire += b"\r\n" + body
        with socket.create_connection((target.hostname, target.port), timeout=5) as stream:
            stream.sendall(wire)
            received = bytearray()
            while True:
                chunk = stream.recv(65536)
                if not chunk:
                    break
                received.extend(chunk)
                if len(received) > 2 * 1024 * 1024:
                    raise RuntimeError("Diamond browser response exceeded 2 MiB")
        response_head, response_body = bytes(received).split(b"\r\n\r\n", 1)
        lines = response_head.decode("iso-8859-1").split("\r\n")
        status = int(lines[0].split()[1])
        response_headers = {}
        for line in lines[1:]:
            name, value = line.split(":", 1)
            response_headers[name.strip()] = value.strip()
        return status, response_headers, response_body

    def act():
        nonlocal actions
        actions += 1

    def route_request(route):
        nonlocal blocked
        parsed = urlparse(route.request.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin not in allowed_origins:
            blocked += 1
            route.abort()
            return
        path = parsed.path + (("?" + parsed.query) if parsed.query else "")
        traffic.append({"method": route.request.method, "path": path})
        status, headers, body = exchange(route.request, path)
        route.fulfill(status=status, headers=headers, body=body)

    def case(case_id, category, effect, paths, passed, replayed=False):
        cases.append({
            "id": case_id,
            "category": category,
            "browser_effect": effect,
            "server_effect": "response observed from the disposable Diamond process",
            "request_paths": paths,
            "passed": passed,
            "replay_digest": digest(json.dumps([case_id, category, effect, paths, passed], sort_keys=True)),
            "replayed_after_reset": replayed,
        })

    def screenshot(page, name):
        path = args.output / f"{name}.png"
        page.screenshot(path=str(path), full_page=True)
        content = path.read_bytes()
        artifacts.append({"kind": "screenshot", "digest": digest(content), "bytes": len(content), "case_id": name})

    from playwright.sync_api import sync_playwright
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
        context.tracing.start(screenshots=True, snapshots=True, sources=False)
        page = context.new_page()
        page.set_default_timeout(5000)
        page.set_default_navigation_timeout(10000)

        act()
        response = page.goto(public_origin + "/", wait_until="domcontentloaded")
        root_ok = response is not None and response.status == 200 and "Diamond <checkpoint one>" in page.locator("body").inner_text()
        case("diamond-browser-root", "navigation", "root document and escaped heading rendered", ["/"], root_ok)

        act()
        response = page.goto(public_origin + "/numbers/7", wait_until="domcontentloaded")
        typed_ok = response is not None and response.status == 200 and page.locator("body").inner_text().strip() == "21"
        case("diamond-browser-typed-route", "typed_route", "typed integer route returned 21", ["/numbers/7"], typed_ok)

        act()
        response = page.goto(public_origin + "/_diamond/login", wait_until="domcontentloaded")
        cookies = context.cookies()
        cookie = next((item for item in cookies if item["name"] == "diamond_session"), {})
        csrf = page.locator("input[name=_diamond_csrf]").input_value()
        cookie_ok = bool(cookie.get("httpOnly")) and bool(cookie.get("secure")) and cookie.get("sameSite") == "Strict"
        login_ok = response is not None and response.status == 200 and page.locator("input[name=_diamond_csrf]").count() == 1
        case("diamond-browser-login-form", "identity_ui", "login form and CSRF field rendered", ["/_diamond/login"], login_ok)
        case("diamond-browser-cookie-policy", "cookie_policy", "browser parsed HttpOnly Secure SameSite=Strict session cookie", ["/_diamond/login"], cookie_ok)

        payload = '<img src=x onerror="window.__diamond_attack=1">'
        act()
        page.goto(public_origin + "/", wait_until="domcontentloaded")
        with page.expect_navigation(wait_until="domcontentloaded") as navigation:
            page.evaluate("""values => {
                const form = document.createElement('form'); form.method = 'POST'; form.action = '/echo';
                const input = document.createElement('input'); input.name = 'message'; input.value = values.payload;
                const csrf = document.createElement('input'); csrf.name = '_diamond_csrf'; csrf.value = values.csrf;
                form.appendChild(input); form.appendChild(csrf); document.body.appendChild(form); form.submit();
            }""", {"payload": payload, "csrf": csrf})
        echo = navigation.value
        page.wait_for_timeout(100)
        echo_text = page.locator("body").inner_text()
        signaled = page.evaluate("Boolean(window.__diamond_attack)")
        escaped = echo.status == 200 and not signaled and "<img" in echo_text and "onerror=" in echo_text
        observed_request = traffic[-1] if traffic else {"method": "none", "path": "none"}
        case("diamond-browser-echo-escaping", "reflected_markup", f"{observed_request['method']} {observed_request['path']} returned {echo.status}; reflected markup remained text; script signal {signaled}", ["/echo"], escaped)
        screenshot(page, "diamond-browser-echo-escaping")

        act()
        blocked_before = blocked
        off_scope_page = context.new_page()
        try:
            off_scope_page.goto("https://example.invalid/red-team", wait_until="domcontentloaded", timeout=3000)
        except Exception:
            pass
        off_scope_page.close()
        off_scope = blocked > blocked_before
        case("diamond-browser-off-scope", "network_scope", "off-scope browser request was blocked", [], off_scope)
        trace = args.output / "diamond-browser-trace.zip"
        context.tracing.stop(path=str(trace))
        trace_content = trace.read_bytes()
        artifacts.append({"kind": "trace", "digest": digest(trace_content), "bytes": len(trace_content), "case_id": None})
        context.close()

        fresh = browser.new_context(service_workers="block")
        isolated = not fresh.cookies() and not fresh.storage_state()["origins"]
        fresh.route("**/*", route_request)
        page = fresh.new_page()
        act()
        response = page.goto(public_origin + "/", wait_until="domcontentloaded")
        replayed = isolated and response is not None and response.status == 200
        case("diamond-browser-fresh-context", "browser_recovery", "root replayed from an empty browser context", ["/"], replayed, True)
        fresh.close()
        browser.close()

    traffic_bytes = (json.dumps(traffic, sort_keys=True, separators=(",", ":")) + "\n").encode()
    traffic_path = args.output / "diamond-browser-traffic.json"
    traffic_path.write_bytes(traffic_bytes)
    artifacts.append({"kind": "traffic", "digest": digest(traffic_bytes), "bytes": len(traffic_bytes), "case_id": None})
    result = {
        "schema": 1,
        "browser_identity": browser_identity,
        "cases": cases,
        "artifacts": artifacts,
        "traffic_digest": digest(traffic_bytes),
        "requests_observed": len(traffic),
        "actions_executed": actions,
        "context_isolation_observed": isolated,
        "off_scope_requests_blocked": blocked,
    }
    args.result.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
