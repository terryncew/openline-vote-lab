"""Ephemeral OpenLine Vote browser research demo using the preserved verifier.

This is an educational wrapper, not election administration. The server learns
the submitted fictional choice and holds every simulated private key. Witnesses
here are simulated in this same process; actual custody remains INCONCLUSIVE.
No private keys, plaintext selections, or subset tallies are public artifacts.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import re
import secrets
import threading
import time
from urllib.parse import urlsplit

from flask import Flask, Response, jsonify, request

from .model import Simulation
from .records import checkpoint_payload, digest, sign
from .verification import verify_record


COOKIE = "openline_demo"
LIMITATIONS = {
    "experimental": True,
    "fictional_nonbinding": True,
    "real_custody_status": "INCONCLUSIVE",
    "shared_account_isolation": "FAILED",
    "witness_scope": "Witness records are simulated on the same server, under the same authority.",
    "privacy": "This server receives the fictional choice and holds all simulated keys. Public receipts contain no choice or encryption opening.",
    "unsolved": ["Compromised phones", "Coercion", "Vote buying", "Denial of service", "Suppression before trustworthy observation"],
}
_RESEARCH = {
    "research": "RESEARCH.md",
    "findings": "RESEARCH.md",
    "witness-001": "WITNESS-001.md",
    "witness-002": "WITNESS-002.md",
    "limitations": "THREAT_MODEL.md",
    "verification": "OPENLINE-VOTE-VERIFY.md",
    "external-test": "WITNESS-002-EXTERNAL-TEST.md",
}


@dataclass
class _Session:
    touched: float
    lock: threading.RLock = field(default_factory=threading.RLock)
    simulation: Simulation | None = None
    receipt: dict | None = None
    verification: dict | None = None
    audit: dict | None = None
    subset: dict | None = None
    job: dict | None = None

    def state(self):
        with self.lock:
            busy = bool(self.job and self.job["status"] in ("queued", "running"))
            phase = ("working" if busy else "verified" if self.verification else
                     "recorded" if self.simulation else "ready")
            inclusion = (self.simulation.inclusion(self.receipt["payload"]["ballot_id"],
                                                   self.receipt["payload"]["ballot_hash"])
                         if self.simulation and self.receipt else None)
            return {"phase": phase, "eligible_count": 100,
                    "cast_count": 100 if self.simulation else 0,
                    "election_id": self.simulation.election_id if self.simulation else None,
                    "receipt": deepcopy(self.receipt), "inclusion": inclusion,
                    "verification": deepcopy(self.verification), "audit": deepcopy(self.audit),
                    "job": deepcopy(self.job), "limitations": deepcopy(LIMITATIONS)}


def _without_totals(result):
    """Never send a 99-ballot plaintext tally alongside the public 100-ballot tally."""
    return {key: deepcopy(value) for key, value in result.items() if key != "totals"}


def _allowed_hosts(values):
    hosts = {"localhost", "127.0.0.1", "::1"}
    for value in values:
        value = value.strip().lower()
        if value == "::1" or re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", value):
            hosts.add(value)
        else:
            raise ValueError("Allowed hosts must be exact hostnames without a scheme, port, path or wildcard")
    return hosts


def create_app(*, allowed_hosts=None, cookie_secure=None, simulation_factory=None,
               session_ttl=1800, max_sessions=16, max_workers=1, max_pending=2,
               clock=None):
    """Create one bounded, in-memory process; replicas do not share visitor state.

    Public hostnames require an explicit allowlist. HTTPS reverse proxies should
    preserve Host and enable OPENLINE_COOKIE_SECURE=1. Forwarded headers are not
    implicitly trusted. No request-body, choice, or cookie logging is added.
    """
    app = Flask(__name__, static_folder="public_static", static_url_path="/static")
    app.config["MAX_CONTENT_LENGTH"] = 4 * 1024
    if allowed_hosts is None:
        allowed_hosts = filter(None, os.environ.get("OPENLINE_ALLOWED_HOSTS", "").split(","))
    hosts = _allowed_hosts(allowed_hosts)
    if cookie_secure is None:
        cookie_secure = os.environ.get("OPENLINE_COOKIE_SECURE", "0") == "1"
    if (type(max_sessions) is not int or not 1 <= max_sessions <= 100 or
            type(max_workers) is not int or not 1 <= max_workers <= 4 or
            type(max_pending) is not int or not max_workers <= max_pending <= 8 or
            not isinstance(session_ttl, (int, float)) or isinstance(session_ttl, bool) or
            not 1 <= session_ttl <= 3600):
        raise ValueError("Invalid bounded demo resource configuration")
    make_simulation = simulation_factory or Simulation
    now = clock or time.monotonic
    sessions = {}
    registry_lock = threading.RLock()
    executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="fictional-election")
    work_slots = threading.BoundedSemaphore(max_pending)
    app.extensions["openline_demo_executor"] = executor

    @app.before_request
    def boundaries():
        host = urlsplit("//" + request.host).hostname
        if host is None or host.lower() not in hosts:
            return jsonify(error="This host has not been enabled for the research demo."), 403
        if request.path.startswith("/api/") and request.headers.get("Sec-Fetch-Site") == "cross-site":
            return jsonify(error="Cross-site requests are not allowed."), 403
        if request.method == "POST":
            origin = request.headers.get("Origin")
            if origin:
                parsed = urlsplit(origin)
                if (parsed.scheme not in ("http", "https") or parsed.netloc != request.host or
                        parsed.path or parsed.query or parsed.fragment or parsed.username):
                    return jsonify(error="Cross-origin requests are not allowed."), 403
            if request.headers.get("Sec-Fetch-Site") == "cross-site":
                return jsonify(error="Cross-site requests are not allowed."), 403
            if request.mimetype != "application/json":
                return jsonify(error="Send a JSON object."), 415

    @app.after_request
    def headers(response):
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response

    @app.errorhandler(ValueError)
    def invalid_input(exc):
        return jsonify(error=str(exc)), 400

    def session(*, create=False):
        token = request.cookies.get(COOKIE, "")
        fresh = False
        with registry_lock:
            instant = now()
            for key, item in list(sessions.items()):
                with item.lock:
                    busy = bool(item.job and item.job["status"] in ("queued", "running"))
                    if instant - item.touched >= session_ttl and not busy:
                        del sessions[key]
            item = sessions.get(token) if re.fullmatch(r"[A-Za-z0-9_-]{43}", token) else None
            if item is None:
                if not create:
                    return None, None, False
                if len(sessions) >= max_sessions:
                    return None, None, False
                token = secrets.token_urlsafe(32)
                item = sessions[token] = _Session(instant)
                fresh = True
            item.touched = instant
            return item, token, fresh

    def state_response(item, token=None, fresh=False, status=200):
        response = jsonify(item.state())
        response.status_code = status
        if fresh:
            response.set_cookie(COOKIE, token, max_age=int(session_ttl), httponly=True,
                                secure=cookie_secure, samesite="Strict", path="/")
        return response

    def enqueue(item, operation, function):
        with item.lock:
            if item.job and item.job["status"] in ("queued", "running"):
                return jsonify(error="This fictional election is still working."), 409
            if operation == "vote" and item.simulation is not None:
                return jsonify(error="This session already cast its one fictional ballot."), 409
            if not work_slots.acquire(blocking=False):
                return jsonify(error="The demo is busy. Try again in a moment."), 503
            item.job = {"operation": operation, "status": "queued", "message": "Waiting for a local cryptographic check."}

        def run():
            try:
                with item.lock:
                    item.job.update(status="running", message="Running ElectionGuard and signed-record checks.")
                function()
                with item.lock:
                    item.job.update(status="complete", message="Local cryptographic checks finished.")
            except Exception as exc:
                # Never expose raw internal objects or the submitted choice.
                app.logger.error("Synthetic demo job failed (%s)", type(exc).__name__)
                with item.lock:
                    item.job.update(status="error", message="The synthetic experiment could not finish. Open a fresh session to retry.")
            finally:
                work_slots.release()
        try:
            executor.submit(run)
        except RuntimeError:
            work_slots.release()
            with item.lock:
                item.job.update(status="error", message="The local worker is unavailable.")
            return jsonify(error="The local worker is unavailable."), 503
        return state_response(item, status=202)

    @app.get("/")
    def index():
        return app.send_static_file("index.html")

    @app.get("/health")
    def health():
        return jsonify(status="ok", scope="synthetic research demo")

    @app.get("/research/<slug>")
    def research(slug):
        filename = _RESEARCH.get(slug)
        if filename is None:
            return jsonify(error="Unknown research document."), 404
        text = (Path(__file__).resolve().parent.parent / "docs" / filename).read_text(encoding="utf-8")
        return Response(text, mimetype="text/plain")

    @app.get("/api/demo/state")
    def state():
        item, token, fresh = session(create=True)
        if item is None:
            return jsonify(error="All local demo slots are in use. Try again later."), 503
        return state_response(item, token, fresh)

    def json_object(fields):
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or set(data) != fields:
            raise ValueError("Expected exactly " + (", ".join(sorted(fields)) or "an empty JSON object") + ".")
        return data

    @app.post("/api/demo/reset")
    def reset():
        """Forget only this visitor's completed experiment, never another session."""
        json_object(set())
        item, token, _ = session()
        if item is None:
            return jsonify(error="Open the demo first to start a session."), 409
        with registry_lock:
            with item.lock:
                if item.job and item.job["status"] in ("queued", "running"):
                    return jsonify(error="Wait for the current cryptographic job before restarting."), 409
                if sessions.get(token) is not item:
                    return jsonify(error="This local session expired. Reload the demo."), 409
                del sessions[token]
            new_item, new_token, fresh = session(create=True)
        return state_response(new_item, new_token, fresh)

    @app.post("/api/demo/vote")
    def vote():
        data = json_object({"choice"})
        choice = data["choice"]
        if not isinstance(choice, str) or choice not in ("garden", "library"):
            raise ValueError("Choose the fictional garden or library.")
        item, _, _ = session()
        if item is None:
            return jsonify(error="Open the demo first to start an anonymous local session."), 409
        def cast():
            sim = make_simulation()
            receipt = sim.cast("voter-001", choice)
            # A fixed 60/40 remainder would make the aggregate reveal this choice.
            # Every other fake voter therefore chooses independently at random.
            for voter in sim.voter_keys:
                if voter not in sim.voted:
                    sim.cast(voter, secrets.choice(("garden", "library")))
            sim.seal()
            if not sim.last_verification["ok"] or len(sim.record["ballots"]) != 100:
                raise ValueError("Synthetic complete election did not verify")
            with item.lock:
                item.simulation, item.receipt = sim, receipt
        return enqueue(item, "vote", cast)

    @app.post("/api/demo/verify")
    def verify():
        json_object(set())
        item, _, _ = session()
        if item is None or item.simulation is None:
            return jsonify(error="Finish the fictional ballot first."), 409

        def check():
            sim = item.simulation
            result = verify_record(sim.record, sim.anchor, sim.checkpoint, [item.receipt])
            inclusion = sim.inclusion(item.receipt["payload"]["ballot_id"], item.receipt["payload"]["ballot_hash"])
            result.update(crypto_valid=result["ok"], recorded=True, included=inclusion["included"],
                          tally_verified=result["ok"], record_hash=digest(sim.record),
                          ballot_encryption="ElectionGuard encrypted ballots and validity proofs checked",
                          real_custody_status="INCONCLUSIVE", shared_account_isolation="FAILED",
                          witness_scope=LIMITATIONS["witness_scope"])
            with item.lock:
                item.verification = result
        return enqueue(item, "verify", check)

    @app.post("/api/demo/audit")
    def audit():
        data = json_object({"attack"})
        attack = data["attack"]
        if not isinstance(attack, str) or attack not in ("witnessed-delete", "unobserved-suppression"):
            raise ValueError("Choose a supported fictional audit scenario.")
        item, _, _ = session()
        if item is None or item.simulation is None or item.verification is None:
            return jsonify(error="Verify the fictional election before auditing it."), 409

        def check():
            sim = item.simulation
            if item.subset is None:
                # Remove a different fake voter's ballot, not this visitor's.
                # This smaller plaintext tally remains private to this job.
                item.subset = sim._record(sim.accepted[:-1])
            record = item.subset
            archive_only = verify_record(record, sim.anchor, require_checkpoint=False)
            result = {"attack": attack, "archive_only": _without_totals(archive_only),
                      "crypto_valid": archive_only["ok"], "observed_ballot_count": 99,
                      "real_custody_status": "INCONCLUSIVE", "shared_account_isolation": "FAILED",
                      "witness_scope": LIMITATIONS["witness_scope"],
                      "subset_tally_public": False}
            if attack == "witnessed-delete":
                retained = verify_record(record, sim.anchor, sim.checkpoint)
                result.update(detection="DETECTED" if not retained["ok"] else "NOT DETECTED",
                              retained_evidence=_without_totals(retained),
                              evidence="The retained signed 100-ballot checkpoint commits to a different record hash.",
                              trustworthy_party="A witness must retain its authentic evidence and pinned key outside operator control; this browser only simulates that condition.",
                              without_retained_evidence="NOT DETECTED" if archive_only["ok"] else "DETECTED",
                              explanation="A valid smaller tally does not prove that an observed ballot was never deleted. Comparing it with the earlier signed checkpoint detects the contradiction.")
            else:
                first_checkpoint = sign(sim.witness_key, checkpoint_payload(sim.anchor, record))
                first = verify_record(record, sim.anchor, first_checkpoint)
                result.update(detection="NOT DETECTED" if first["ok"] else "DETECTED",
                              branch="counterfactual-before-first-observation",
                              first_observation=_without_totals(first),
                              evidence="No authentic acknowledgment or witness observation of the suppressed synthetic submission exists in this branch.",
                              trustworthy_party="No later verifier can reconstruct an event that no trustworthy party observed.",
                              without_retained_evidence="NOT DETECTED" if archive_only["ok"] else "DETECTED",
                              explanation="In a separate counterfactual branch, a different synthetic submission is withheld before any receipt reaches its voter or witness. This verifier receives only the first 99-ballot observation, without the earlier 100-ballot evidence used in the deletion branch. It has no evidence of the missing submission.")
            with item.lock:
                item.audit = result
        return enqueue(item, "audit", check)

    @app.get("/api/demo/export/<artifact>")
    def export(artifact):
        item, _, _ = session()
        if item is None or item.simulation is None:
            return jsonify(error="Finish the fictional ballot before exporting public evidence."), 409
        with item.lock:
            sim = item.simulation
            artifacts = {"record": sim.record, "anchor": sim.anchor, "checkpoint": sim.checkpoint,
                         "receipt": item.receipt, "receipts": [item.receipt],
                         "verification": item.verification}
            if artifact not in artifacts:
                return jsonify(error="Unknown public artifact. Attack subset tallies are never exported."), 404
            if artifacts[artifact] is None:
                return jsonify(error="Run verification before exporting its result."), 409
            value = deepcopy(artifacts[artifact])
        return Response(json.dumps(value, indent=2, allow_nan=False) + "\n", mimetype="application/json",
                        headers={"Content-Disposition": f'attachment; filename="openline-vote-{artifact}.json"'})

    return app


def main(argv=None):
    parser = argparse.ArgumentParser(description="OpenLine Vote: synthetic, nonbinding research only")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8001)
    parser.add_argument("--allow-host", action="append", default=None,
                        help="Explicit additional hostname; no wildcard or scheme")
    parser.add_argument("--secure-cookie", action="store_true", default=None,
                        help="Require HTTPS for the ephemeral session cookie")
    args = parser.parse_args(argv)
    app = create_app(allowed_hosts=args.allow_host, cookie_secure=args.secure_cookie)
    # Existing dependency; no monkey-patching or extra paid/network service.
    from gevent.pywsgi import WSGIServer
    print(f"OpenLine Vote research demo on {args.host}:{args.port}; fictional only, independent custody INCONCLUSIVE.", flush=True)
    try:
        WSGIServer((args.host, args.port), app, log=None).serve_forever()
    finally:
        app.extensions["openline_demo_executor"].shutdown(wait=True, cancel_futures=True)


if __name__ == "__main__":
    main()
