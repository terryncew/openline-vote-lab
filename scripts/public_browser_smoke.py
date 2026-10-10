#!/usr/bin/env python3
"""Exercise the new OpenLine Vote experience against a disposable loopback server.

This optional QA script uses an already installed Playwright and Chromium. It
does not install dependencies or contact an external service. Every browser
context creates a fresh synthetic election; only public files are downloaded.
Start ``python -m vote_lab.demo_server --port 8002`` separately, then run this
script with an interpreter that already has Playwright. ElectionGuard checks
use the supplied project interpreter, not Playwright's Python environment.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
TIMEOUT = 180_000


def loopback_origin(value: str) -> str:
    target = urlsplit(value)
    if (target.scheme != "http" or target.hostname not in ("127.0.0.1", "localhost")
            or target.username or target.password or target.path not in ("", "/")
            or target.query or target.fragment):
        raise ValueError("Use only a disposable HTTP loopback server's origin")
    return f"{target.scheme}://{target.netloc}"


def installed_browser(value: str | None) -> str:
    found = value or shutil.which("chromium") or shutil.which("google-chrome")
    if not found:
        raise ValueError("Supply --chromium for an already installed browser")
    return found


def public_only(value):
    """Reject private export fields while permitting null serialized nonces."""
    if isinstance(value, dict):
        for name, item in value.items():
            assert name not in {"secret_key", "private_key", "plaintext", "choice", "vote", "seed"}, name
            if name == "nonce":
                assert item is None, "Public ballot includes an encryption nonce"
            public_only(item)
    elif isinstance(value, list):
        for item in value:
            public_only(item)


class DemoRun:
    """Small shared harness for browser QA and a genuine interaction recording."""

    def __init__(self, page, origin):
        self.page, self.origin = page, origin
        self.javascript_errors = []
        self.external_requests = []
        self.responses = []
        page.on("pageerror", lambda error: self.javascript_errors.append(str(error)))
        page.route("**/*", self._local_only)
        page.on("response", self._response)

    def _local_only(self, route):
        target = urlsplit(route.request.url)
        if f"{target.scheme}://{target.netloc}" != self.origin:
            self.external_requests.append(route.request.url)
            route.abort()
        else:
            route.continue_()

    def _response(self, response):
        path = urlsplit(response.url).path
        if path.startswith("/api/demo/") and response.request.method == "POST":
            self.responses.append({"path": path, "status": response.status})

    def wait_state(self, predicate, *, seconds=180):
        deadline = time.monotonic() + seconds
        last = None
        while time.monotonic() < deadline:
            response = self.page.request.get(self.origin + "/api/demo/state")
            assert response.status == 200, response.text()
            last = response.json()
            if predicate(last):
                return last
            self.page.wait_for_timeout(250)
        raise AssertionError(f"Timed out waiting for a real backend result: {last}")

    def complete(self, operation, *, attack=None):
        return self.wait_state(lambda state: (state.get("job") or {}).get("operation") == operation
                               and (state.get("job") or {}).get("status") in ("complete", "error")
                               and (attack is None or (state.get("audit") or {}).get("attack") == attack))

    def healthy(self):
        assert not self.javascript_errors, self.javascript_errors
        assert not self.external_requests, self.external_requests

    def no_overflow(self):
        assert self.page.evaluate("() => document.documentElement.scrollWidth <= innerWidth"), "Horizontal overflow"


def offline_check(files, python):
    """Verify actual downloaded files in a process with outbound sockets blocked."""
    helper = """
import json, runpy, socket, sys
def blocked(*args, **kwargs):
    raise AssertionError('Offline verification attempted a network connection')
socket.socket.connect = blocked
socket.socket.connect_ex = blocked
socket.create_connection = blocked
sys.argv = ['vote_lab', 'verify'] + sys.argv[1:]
try:
    runpy.run_module('vote_lab', run_name='__main__')
except SystemExit as exc:
    assert 'vote_lab.model' not in sys.modules
    assert 'vote_lab.server' not in sys.modules
    assert 'vote_lab.demo_server' not in sys.modules
    raise
"""
    arguments = []
    for name in ("record", "anchor", "checkpoint", "receipts"):
        arguments.extend(["--" + name, str(files[name])])
    process = subprocess.run([str(python), "-c", helper, *arguments], cwd=ROOT,
                             capture_output=True, text=True, timeout=90)
    assert process.returncode == 0, process.stdout + process.stderr
    result = json.loads(process.stdout)
    assert result["ok"] and result["completeness"]
    assert sum(result["totals"].values()) == 100
    return {"exit_code": process.returncode, "ok": result["ok"], "completeness": result["completeness"],
            "checks": result["checks"], "outbound_sockets_blocked": True,
            "server_and_private_model_not_imported": True}


def main():
    started = time.monotonic()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8002")
    parser.add_argument("--chromium")
    parser.add_argument("--project-python", type=Path, default=ROOT / ".venv/bin/python")
    parser.add_argument("--screenshots", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        origin, executable = loopback_origin(args.url), installed_browser(args.chromium)
        from playwright.sync_api import expect, sync_playwright
    except (ValueError, ImportError) as exc:
        parser.error(str(exc))
    if args.screenshots:
        args.screenshots.mkdir(parents=True, exist_ok=True)
    findings = {"scope": "Local browser QA; synthetic election; no independent administration established",
                "viewports": [], "external_requests": 0, "real_custody_status": "INCONCLUSIVE",
                "shared_account_isolation": "FAILED"}
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path=executable, headless=True, args=["--no-sandbox"])
        findings["browser"] = {"engine": "Chromium", "version": browser.version,
                               "environment": "Headless Linux, HTTP loopback, responsive viewport emulation",
                               "not_tested": ["Physical phones", "Mobile Safari", "Real external custody"]}
        context = browser.new_context(viewport={"width": 390, "height": 844}, reduced_motion="reduce")
        page = context.new_page()
        run = DemoRun(page, origin)
        page.goto(origin)
        expect(page.locator("#choice-fieldset")).to_be_enabled(timeout=TIMEOUT)
        assert page.locator("h1").count() == 1
        assert page.locator("html").get_attribute("lang") == "en"
        assert page.locator("#activity").get_attribute("role") == "status"
        assert page.locator("#connection-error").get_attribute("role") == "alert"
        assert page.locator("input[name=choice]").count() == 2
        for radio in page.locator("input[name=choice]").all():
            assert radio.evaluate("node => node.labels.length > 0"), "Radio has no native label"
        page.locator(".skip-link").focus()
        page.keyboard.press("Enter")
        assert page.evaluate("() => location.hash") == "#demo"
        page.locator("input[value=garden]").focus()
        page.keyboard.press("ArrowRight")
        assert page.locator("input[value=library]").is_checked(), "Native radio keyboard selection failed"
        assert page.evaluate("() => matchMedia('(prefers-reduced-motion: reduce)').matches")
        assert page.evaluate("() => getComputedStyle(document.documentElement).scrollBehavior") == "auto"
        for width, height in ((320, 812), (375, 812), (390, 844), (1440, 1000)):
            page.set_viewport_size({"width": width, "height": height})
            run.no_overflow()
            findings["viewports"].append({"width": width, "height": height, "initial_no_overflow": True})
            if args.screenshots:
                page.screenshot(path=str(args.screenshots / f"vote-{width}.png"), full_page=True)
        page.set_viewport_size({"width": 390, "height": 844})

        # An injected service failure must be shown honestly and permit retry.
        def fail_vote(route):
            route.fulfill(status=503, content_type="application/json", body=json.dumps({"error": "Injected local QA service failure"}))
        page.route("**/api/demo/vote", fail_vote)
        page.locator("#vote-button").click()
        expect(page.locator("#connection-error")).to_be_visible()
        expect(page.locator("#connection-error")).to_contain_text("Injected local QA service failure")
        expect(page.locator("#vote-button")).to_be_enabled()
        assert page.locator("input[value=library]").is_checked()
        page.unroute("**/api/demo/vote", fail_vote)
        findings["injected_service_failure"] = "Displayed; no success claim; same choice available for retry"
        print("PASS: Mobile layouts, native keyboard controls, reduced motion, and service-error recovery", flush=True)

        page.locator("#vote-button").click()
        expect(page.locator("#vote-button")).to_be_disabled()
        busy = page.request.post(origin + "/api/demo/vote", data={"choice": "garden"})
        assert busy.status == 409, busy.text()
        failures = []
        def transient_state_failure(route):
            if not failures:
                failures.append(True)
                route.fulfill(status=503, content_type="application/json", body=json.dumps({"error": "Injected transient polling failure"}))
            else:
                route.continue_()
        page.route("**/api/demo/state", transient_state_failure)
        voted = run.complete("vote")
        page.unroute("**/api/demo/state", transient_state_failure)
        assert failures, "No real browser polling request was exercised"
        assert voted["job"]["status"] == "complete", voted
        assert voted["inclusion"]["included"]
        expect(page.locator("#verify-button")).to_be_enabled(timeout=TIMEOUT)
        expect(page.locator("#connection-error")).to_be_hidden(timeout=TIMEOUT)
        receipt = voted["receipt"]
        public_only(receipt)
        assert set(receipt) == {"payload", "signature"}
        assert not any(name in json.dumps(receipt).lower() for name in ("garden", "library", "choice", "nonce"))
        expect(page.locator("#receipt-hash")).to_have_text(receipt["payload"]["ballot_hash"])
        repeat = page.request.post(origin + "/api/demo/vote", data={"choice": "garden"})
        assert repeat.status == 409
        findings["vote"] = {"real_api_status": 202, "synthetic_ballots": 100, "included": True,
                            "duplicate_request_rejected": True, "transient_polling_recovered": True,
                            "public_receipt_has_no_choice_or_nonce": True}
        print("PASS: Real 100-ballot ElectionGuard session, busy rejection, honest polling recovery, choice-free receipt", flush=True)

        page.locator("#verify-button").click()
        verified = run.complete("verify")
        assert verified["job"]["status"] == "complete", verified
        checks = verified["verification"]
        assert checks["ok"] and checks["crypto_valid"] and checks["included"] and checks["tally_verified"]
        expect(page.locator("#verification-result")).to_be_visible(timeout=TIMEOUT)
        expect(page.locator("#verification-title")).to_contain_text("checks")
        expect(page.locator("#published-tally")).to_be_visible()
        for choice in ("garden", "library"):
            expect(page.locator(f"#{choice}-count")).to_have_text(str(checks["totals"][choice]))
        assert sum(checks["totals"].values()) == 100
        for kind in ("encryption", "recording", "inclusion", "tally"):
            expect(page.locator(f"#proof-{kind} .trail-status")).not_to_have_text("Not checked")
        findings["verification"] = {name: checks[name] for name in ("ok", "crypto_valid", "included", "tally_verified", "record_hash")}
        print("PASS: Explicit live ballot, recording, inclusion, and tally verification", flush=True)

        with tempfile.TemporaryDirectory(prefix="openline-vote-browser-public-") as temporary:
            files = {}
            page.locator("#technical-evidence summary").click()
            for artifact in ("record", "anchor", "checkpoint", "receipt"):
                with page.expect_download() as download:
                    page.locator("#export-" + artifact).click()
                path = Path(temporary) / (artifact + ".json")
                download.value.save_as(path)
                data = json.loads(path.read_text())
                public_only(data)
                files[artifact] = path
            record = json.loads(files["record"].read_text())
            assert len(record["ballots"]) == 100
            downloaded_receipts = json.loads(files["receipt"].read_text())
            if isinstance(downloaded_receipts, list):
                assert downloaded_receipts == [receipt], "Receipt download should contain this session's single public receipt"
                files["receipts"] = files["receipt"]
            else:
                assert downloaded_receipts == receipt
                receipts = Path(temporary) / "receipts.json"
                receipts.write_text(json.dumps([downloaded_receipts]))
                files["receipts"] = receipts
            findings["offline_verification"] = offline_check(files, args.project_python)
            findings["public_download_hashes"] = {name: hashlib.sha256(path.read_bytes()).hexdigest()
                                                 for name, path in files.items()}
        print("PASS: Four actual public downloads verify offline with sockets blocked and no server/private-model imports", flush=True)

        page.locator("#to-audit").click()
        for button, attack, detection in (("#attack-delete", "witnessed-delete", "DETECTED"),
                                         ("#attack-suppress", "unobserved-suppression", "NOT DETECTED")):
            page.locator(button).click()
            expect(page.locator("#audit-result")).to_be_hidden()
            audited = run.complete("audit", attack=attack)
            assert audited["job"]["status"] == "complete", audited
            result = audited["audit"]
            assert result["attack"] == attack and result["detection"] == detection, result
            assert result["archive_only"]["ok"], "Attack subset should remain cryptographically consistent"
            assert result["real_custody_status"] == "INCONCLUSIVE"
            assert result["shared_account_isolation"] == "FAILED"
            expect(page.locator("#audit-label")).to_have_text(detection, timeout=TIMEOUT)
            assert "totals" not in json.dumps(result), "Audit should not expose adjacent subset totals"
            findings[attack] = {"detection": detection, "archive_only_valid": True,
                                "real_custody_status": "INCONCLUSIVE", "shared_account_isolation": "FAILED"}
            if args.screenshots:
                page.screenshot(path=str(args.screenshots / f"audit-{attack}.png"), full_page=True)
        print("PASS: Live witnessed deletion detected; pre-observation suppression not detected", flush=True)

        for viewport in findings["viewports"]:
            page.set_viewport_size({"width": viewport["width"], "height": viewport["height"]})
            run.no_overflow()
            viewport["audit_no_overflow"] = True
        page.set_viewport_size({"width": 390, "height": 844})
        for stage in ("verify", "vote"):
            page.locator(f"[data-stage={stage}]").click()
            run.no_overflow()
        body = page.locator("body").inner_text().lower()
        for caveat in ("independent custody: inconclusive", "isolation test failed", "compromised phones", "coercion", "not private internet voting"):
            assert caveat in body, caveat
        for path in ("/research/findings", "/research/limitations", "/research/verification", "/research/witness-002"):
            response = page.request.get(origin + path)
            assert response.status == 200, path
        run.healthy()
        assert any(item == {"path": "/api/demo/vote", "status": 202} for item in run.responses)
        assert any(item == {"path": "/api/demo/verify", "status": 202} for item in run.responses)
        findings["api_responses"] = run.responses
        findings["javascript_errors"] = []
        findings["accessibility_scope"] = "Native labels, keyboard selection/skip link, status/alert semantics, reduced motion; no independent accessibility audit"
        findings["result"] = "PASS"
        browser.close()
    findings["elapsed_seconds"] = round(time.monotonic() - started, 3)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(findings, indent=2) + "\n")
    print("PASS: All public-demo browser checks; zero third-party requests", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
