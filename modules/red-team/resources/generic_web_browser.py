#!/usr/bin/env python3
"""Contained loopback browser campaign for source-bound web applications."""

import argparse
import hashlib
import json
import pathlib
import time
from urllib.parse import quote, urlparse

from playwright.sync_api import sync_playwright


def digest(value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def case(case_id, family, operation, disposition, status, oracle, request, response):
    replay = json.dumps({"operation": operation, "request": request}, sort_keys=True)
    return {
        "id": case_id,
        "class": family,
        "operation": operation,
        "disposition": disposition,
        "response_status": status,
        "request_digest": digest(request),
        "response_digest": digest(response),
        "oracle": oracle,
        "replay_digest": digest(replay),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--result", required=True)
    parser.add_argument("--browser-executable", required=True)
    args = parser.parse_args()
    output = pathlib.Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    target = args.target.rstrip("/")
    target_origin = urlparse(target).netloc
    cases = []
    blocked = 0
    console = []

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            executable_path=args.browser_executable,
            headless=True,
            chromium_sandbox=False,
            args=["--disable-dev-shm-usage"],
        )
        context = browser.new_context()

        def route_handler(route):
            nonlocal blocked
            if urlparse(route.request.url).netloc != target_origin:
                blocked += 1
                route.abort()
            else:
                route.continue_()

        context.route("**/*", route_handler)
        page = context.new_page()
        page.on("console", lambda message: console.append(message.text[:1000]))
        path = "/api/signup" if args.profile == "comms-bun.v1" else "/"
        response = page.goto(target + path, wait_until="domcontentloaded", timeout=15000)
        status = response.status if response else None
        headers = response.headers if response else {}
        body = page.content()
        has_form = page.locator("form").count() > 0
        csp = headers.get("content-security-policy", "")
        expected = status == 200 and (has_form and "default-src 'none'" in csp if args.profile == "comms-bun.v1" else True)
        cases.append(case(
            "browser-page-and-form", "browser_and_client_trust", "navigate-and-inspect",
            "held" if expected else "violation", status,
            "The page must render; Comms must expose its signup form with a deny-by-default CSP.",
            target + path, body,
        ))

        if args.profile != "comms-bun.v1":
            payload = '<script>window.__peritus_generic_xss=1</script>'
            probe_url = target + "/?peritus_probe=" + quote(payload, safe="")
            probe_response = page.goto(
                probe_url, wait_until="domcontentloaded", timeout=15000
            )
            probe_status = probe_response.status if probe_response else None
            executed = page.evaluate("() => window.__peritus_generic_xss === 1")
            probe_body = page.content()
            cases.append(case(
                "browser-generic-query-script-injection",
                "input_interpretation_and_injection",
                "query-reflection-script-execution",
                "violation" if executed else "held",
                probe_status,
                "A script payload in an ordinary query value must not execute in the browser.",
                probe_url,
                probe_body,
            ))

        if args.profile == "comms-bun.v1" and has_form:
            email = f"peritus-{int(time.time() * 1000)}@example.invalid"
            page.locator('input[name="email"]').fill(email)
            page.locator('button[type="submit"]').click()
            page.wait_for_load_state("domcontentloaded")
            result_body = page.content()
            accepted = page.get_by_role("heading", name="Signup received").count() == 1
            cases.append(case(
                "browser-benign-signup", "business_logic_and_workflow", "form-submit",
                "held" if accepted else "violation", None,
                "A benign same-origin signup must complete through the rendered form.",
                email, result_body,
            ))

            fresh = context.new_page()
            fresh.goto(target + "/api/signup", wait_until="domcontentloaded", timeout=15000)
            payload = '\"><script>window.__peritus_attack=1</script>@example.invalid'
            fresh.locator('input[name="email"]').fill(payload)
            fresh.locator('button[type="submit"]').click()
            fresh.wait_for_load_state("domcontentloaded")
            xss = fresh.evaluate("() => window.__peritus_attack === 1")
            reflected = fresh.content()
            cases.append(case(
                "browser-signup-script-injection", "input_interpretation_and_injection", "form-script-injection",
                "violation" if xss else "held", None,
                "Untrusted form input must not execute script in a fresh browser context.",
                payload, reflected,
            ))

        browser.close()

    artifact = output / "console.json"
    artifact.write_text(json.dumps(console, indent=2), encoding="utf-8")
    result = {
        "cases": cases,
        "off_scope_requests_blocked": blocked,
        "artifacts_digest": digest(artifact.read_bytes()),
    }
    pathlib.Path(args.result).write_text(json.dumps(result, sort_keys=True), encoding="utf-8")


if __name__ == "__main__":
    main()
