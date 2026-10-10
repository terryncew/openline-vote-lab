#!/usr/bin/env python3
"""Optional browser QA for a disposable local Vote Lab server.

Requires an existing Python installation with Playwright and system Chromium;
neither is a project runtime dependency. Does not install tools or contact remote
services. Start the demo first, then run:

    python scripts/browser_smoke.py --url http://127.0.0.1:8000

WARNING: This script resets the server's current synthetic experiment, fills its
100 fake voters, and finally resets it to receiver mode. Use a disposable server.
"""

import argparse
from pathlib import Path
import shutil
from urllib.parse import urlsplit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--chromium", help="Path to an already installed Chromium executable")
    parser.add_argument("--screenshots", type=Path, help="Optional directory for desktop/mobile screenshots")
    args = parser.parse_args()
    target = urlsplit(args.url)
    if target.scheme != "http" or target.hostname not in ("127.0.0.1", "localhost") or target.username or target.password:
        parser.error("Browser smoke tests require an HTTP loopback server with synthetic data")
    if target.path not in ("", "/") or target.query or target.fragment:
        parser.error("Use the loopback server's origin, without a path or query")
    executable = args.chromium or shutil.which("chromium") or shutil.which("google-chrome")
    if not executable:
        parser.error("No existing Chromium installation found; supply --chromium")
    try:
        from playwright.sync_api import expect, sync_playwright
    except ImportError:
        parser.error("Optional browser QA requires an existing Python installation with Playwright")

    origin = f"{target.scheme}://{target.netloc}"
    if args.screenshots:
        args.screenshots.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path=executable, headless=True, args=["--no-sandbox"])
        page = browser.new_page(viewport={"width": 1440, "height": 1100})
        javascript_errors, external_requests = [], []
        page.on("pageerror", lambda error: javascript_errors.append(str(error)))

        def local_requests_only(route):
            requested = urlsplit(route.request.url)
            if f"{requested.scheme}://{requested.netloc}" != origin:
                external_requests.append(route.request.url)
                route.abort()
            else:
                route.continue_()

        page.route("**/*", local_requests_only)

        def settled():
            expect(page.locator("#activity")).to_have_class("activity success", timeout=180_000)
            expect(page.locator("#connection-error")).to_be_hidden()

        def no_overflow():
            assert page.evaluate("() => document.documentElement.scrollWidth <= window.innerWidth"), "Horizontal overflow"

        def new_experiment(mode):
            page.locator("#mode").select_option(mode)
            page.get_by_role("button", name="New experiment").click()
            expect(page.locator("#reset-dialog")).to_be_visible()
            page.get_by_role("button", name="Start new experiment", exact=True).click()
            settled()
            expect(page.locator("#cast-count")).to_have_text("0")

        page.goto(origin)
        settled()
        page.keyboard.press("Tab")
        assert page.locator(".skip-link").evaluate("(node) => node === document.activeElement"), "Skip link is not keyboard accessible"
        page.keyboard.press("Enter")
        new_experiment("baseline")
        assert page.locator("#voter option").count() == 100
        assert page.locator("#cast-button").is_enabled()
        assert page.locator("#seal-button").is_disabled()
        no_overflow()
        if args.screenshots:
            page.screenshot(path=str(args.screenshots / "desktop-initial.png"), full_page=True)

        page.emulate_media(reduced_motion="reduce")
        assert page.evaluate("() => matchMedia('(prefers-reduced-motion: reduce)').matches")
        assert page.evaluate("() => getComputedStyle(document.documentElement).scrollBehavior") == "auto"
        page.locator("input[value=garden]").focus()
        page.keyboard.press("ArrowRight")
        assert page.locator("input[value=library]").is_checked(), "Native radio keyboard controls failed"
        page.get_by_role("button", name="Encrypt & cast ballot").click()
        settled()
        expect(page.locator("#cast-count")).to_have_text("1")
        assert len(page.locator("#receipt-hash").inner_text()) == 64
        assert page.locator("#voter").input_value() == "voter-002"
        page.get_by_role("button", name="Check this ballot’s inclusion").click()
        settled()
        assert "Ballot included" in page.locator("#inclusion-result").inner_text()
        print("PASS: Keyboard navigation, reduced motion, manual ballot, and inclusion receipt", flush=True)

        page.get_by_role("button", name="Complete 100-voter simulation").click()
        assert page.evaluate("() => getComputedStyle(document.querySelector('#activity'), '::before').animationName") == "none"
        settled()
        expect(page.locator("#cast-count")).to_have_text("100")
        assert page.locator("#cast-button").is_disabled()
        page.get_by_role("button", name="Close & tally election").click()
        settled()
        expect(page.locator("#tally-results")).to_be_visible()
        assert int(page.locator("#garden-total").inner_text()) + int(page.locator("#library-total").inner_text()) == 100
        page.get_by_role("button", name="Run independent verification").click()
        settled()
        assert "passed" in page.locator("#verification-heading").inner_text()
        print("PASS: 100 synthetic voters, tally, and independent verification", flush=True)

        for attack in ("duplicate", "unauthorized", "deleted", "modified", "invalid-proof", "operator-retally", "operator-forgery", "checkpoint-rewrite"):
            page.locator("#attack").select_option(attack)
            page.get_by_role("button", name="Run attack").click()
            settled()
            expect(page.locator("#attack-result")).to_be_visible()
            assert page.locator("#attack-result-title").inner_text() == "Tampering detected by the verifier", attack
        for artifact in ("record", "anchor", "checkpoint", "receipts"):
            with page.expect_download() as download:
                page.locator("#export-" + artifact).click()
            assert download.value.suggested_filename == artifact + ".json"
        print("PASS: All eight adversarial experiments and four artifact downloads", flush=True)

        no_overflow()
        if args.screenshots:
            page.screenshot(path=str(args.screenshots / "desktop-result.png"), full_page=True)
        for width in (375, 320):
            page.set_viewport_size({"width": width, "height": 812})
            no_overflow()
        if args.screenshots:
            page.set_viewport_size({"width": 375, "height": 812})
            page.screenshot(path=str(args.screenshots / "mobile-result.png"), full_page=True)

        page.locator("#mode").select_option("receiver")
        page.locator("#reset-button").focus()
        page.keyboard.press("Enter")
        expect(page.locator("#reset-dialog")).to_be_visible()
        assert page.locator("#reset-cancel").evaluate("(node) => node === document.activeElement"), "Dialog did not move focus"
        page.keyboard.press("Tab")
        assert page.locator("#reset-confirm").evaluate("(node) => node === document.activeElement"), "Dialog keyboard order failed"
        page.keyboard.press("Escape")
        expect(page.locator("#reset-dialog")).to_be_hidden()
        assert page.locator("#reset-button").evaluate("(node) => node === document.activeElement"), "Dialog did not restore focus"
        expect(page.locator("#cast-count")).to_have_text("100")
        new_experiment("receiver")
        assert "Receiver" in page.locator("#mode-chip").inner_text()
        for result in ("verification-result", "attack-result", "receipt-details"):
            expect(page.locator("#" + result)).to_be_hidden()
        assert not javascript_errors, javascript_errors
        assert not external_requests, external_requests
        print("PASS: Mobile 375/320 px, keyboard dialog focus, receiver reset, no JS errors or third-party requests", flush=True)
        browser.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
