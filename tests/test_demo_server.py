"""Public wrapper tests: actual ElectionGuard flow and negative trust controls."""
from copy import deepcopy
import json
import threading
import time

import pytest

from vote_lab.demo_server import COOKIE, create_app
from vote_lab.model import Simulation
from vote_lab.records import checkpoint_payload, digest, receipt_payload, sign, vote_payload
from vote_lab.verification import verify_record


def finished(client, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = client.get("/api/demo/state").json
        if state["job"] and state["job"]["status"] == "complete":
            return state
        assert not state["job"] or state["job"]["status"] != "error", state
        time.sleep(0.03)
    pytest.fail("Bounded local cryptographic job did not finish")


@pytest.fixture(scope="module")
def real_flow():
    simulations = []

    def factory():
        sim = Simulation()
        simulations.append(sim)
        return sim

    app = create_app(simulation_factory=factory)
    app.config["TESTING"] = True
    client = app.test_client()
    assert client.get("/api/demo/state").json["phase"] == "ready"
    assert client.post("/api/demo/vote", json={"choice": "garden"}).status_code == 202
    state = finished(client)
    assert state["phase"] == "recorded"
    assert client.post("/api/demo/verify", json={}).status_code == 202
    finished(client)
    yield app, client, simulations[0]
    app.extensions["openline_demo_executor"].shutdown(wait=True)


@pytest.fixture()
def bare_app():
    app = create_app()
    app.config["TESTING"] = True
    yield app
    app.extensions["openline_demo_executor"].shutdown(wait=True)


def test_real_crypto_receipt_inclusion_and_tally(real_flow):
    _, client, sim = real_flow
    state = client.get("/api/demo/state").json
    verification = state["verification"]
    assert state["cast_count"] == state["eligible_count"] == 100
    assert state["receipt"]["payload"]["sequence"] == 1
    assert state["receipt"]["payload"]["ballot_hash"] == digest(sim.record["ballots"][0]["entry"]["ballot"])
    assert state["inclusion"]["included"]
    assert verification["ok"] and verification["crypto_valid"] and verification["tally_verified"]
    assert verification["included"] and verification["recorded"]
    assert sum(verification["totals"].values()) == 100
    assert any("ElectionGuard" in check for check in verification["checks"])
    assert verification["record_hash"] == digest(sim.record)
    assert verification["real_custody_status"] == "INCONCLUSIVE"
    assert verification["shared_account_isolation"] == "FAILED"


def test_public_exports_verify_offline_and_receipt_is_choice_free(real_flow):
    _, client, _ = real_flow
    artifacts = {name: client.get("/api/demo/export/" + name).json
                 for name in ("record", "anchor", "checkpoint", "receipt")}
    result = verify_record(artifacts["record"], artifacts["anchor"], artifacts["checkpoint"], [artifacts["receipt"]])
    assert result["ok"] and result["completeness"]
    receipts = client.get("/api/demo/export/receipts")
    assert receipts.json == [artifacts["receipt"]]
    assert "openline-vote-receipts.json" in receipts.headers["Content-Disposition"]
    assert verify_record(artifacts["record"], artifacts["anchor"], artifacts["checkpoint"], receipts.json)["ok"]
    receipt_json = json.dumps(artifacts["receipt"])
    assert all(word not in receipt_json for word in ("garden", "library", "choice", "nonce", "private", "secret"))
    assert len(artifacts["record"]["ballots"]) == 100

    def no_openings(value):
        if isinstance(value, dict):
            for key, child in value.items():
                assert key not in ("choice", "private_key", "secret_key", "signing_key", "opening", "plaintext_ballot")
                if key == "nonce":
                    assert child is None
                no_openings(child)
        elif isinstance(value, list):
            for child in value:
                no_openings(child)
    no_openings(artifacts)
    assert client.get("/api/demo/export/signing-key").status_code == 404
    assert client.get("/api/demo/export/subset").status_code == 404


def test_witnessed_deletion_detected_only_with_retained_evidence(real_flow):
    _, client, sim = real_flow
    before = digest(sim.record)
    assert client.post("/api/demo/audit", json={"attack": "witnessed-delete"}).status_code == 202
    audit = finished(client)["audit"]
    assert audit["detection"] == "DETECTED"
    assert audit["crypto_valid"]
    assert audit["archive_only"]["ok"]
    assert not audit["retained_evidence"]["ok"]
    assert audit["without_retained_evidence"] == "NOT DETECTED"
    assert audit["observed_ballot_count"] == 99
    assert "totals" not in json.dumps(audit)
    assert digest(sim.record) == before
    exported = client.get("/api/demo/export/record").json
    assert len(exported["ballots"]) == 100
    assert digest(exported) == before


def test_suppression_before_trustworthy_observation_not_detected(real_flow):
    _, client, _ = real_flow
    assert client.post("/api/demo/audit", json={"attack": "unobserved-suppression"}).status_code == 202
    audit = finished(client)["audit"]
    assert audit["detection"] == "NOT DETECTED"
    assert audit["first_observation"]["ok"] and audit["archive_only"]["ok"]
    assert audit["without_retained_evidence"] == "NOT DETECTED"
    assert audit["real_custody_status"] == "INCONCLUSIVE"
    assert audit["shared_account_isolation"] == "FAILED"
    assert "totals" not in json.dumps(audit)
    assert "No authentic acknowledgment" in audit["evidence"]


def test_same_session_cannot_cast_twice_and_other_visitors_are_isolated(real_flow):
    app, client, _ = real_flow
    assert client.post("/api/demo/vote", json={"choice": "library"}).status_code == 409
    other = app.test_client()
    state = other.get("/api/demo/state").json
    assert state["phase"] == "ready" and state["receipt"] is None
    assert other.get("/api/demo/export/record").status_code == 409
    assert other.post("/api/demo/verify", json={}).status_code == 409
    assert other.post("/api/demo/audit", json={"attack": "witnessed-delete"}).status_code == 409
    assert other.post("/api/demo/reset", json={}).status_code == 200
    assert client.get("/api/demo/state").json["cast_count"] == 100


def test_invalid_proof_with_valid_wrapper_signatures_is_not_green(real_flow):
    _, client, sim = real_flow
    original_record, original_checkpoint = sim.record, sim.checkpoint
    changed = deepcopy(sim.record)
    accepted = changed["ballots"][-1]
    entry = accepted["entry"]
    Simulation._damage_proof(entry["ballot"])
    entry["authorization"] = sign(sim.voter_keys[entry["voter_id"]],
                                  vote_payload(sim.anchor, entry["voter_id"], entry["ballot_id"], digest(entry["ballot"])))
    accepted["receipt"] = sign(sim.receiver_key, receipt_payload(sim.anchor, entry, 100))
    sim.record, sim.checkpoint = changed, sign(sim.witness_key, checkpoint_payload(sim.anchor, changed))
    try:
        assert client.post("/api/demo/verify", json={}).status_code == 202
        result = finished(client)["verification"]
        assert not result["ok"] and not result["crypto_valid"] and not result["tally_verified"]
        assert any("proof" in error.lower() or "encryption" in error.lower() for error in result["errors"])
    finally:
        sim.record, sim.checkpoint = original_record, original_checkpoint
        assert client.post("/api/demo/verify", json={}).status_code == 202
        assert finished(client)["verification"]["ok"]


@pytest.mark.parametrize("origin", ["https://foreign.example", "null", "http://localhost/route", "file://localhost", "http://localhost?x=1"])
def test_foreign_or_malformed_origins_rejected(bare_app, origin):
    client = bare_app.test_client()
    client.get("/api/demo/state")
    response = client.post("/api/demo/vote", json={"choice": "garden"}, headers={"Origin": origin})
    assert response.status_code == 403
    assert client.get("/api/demo/state").json["cast_count"] == 0


def test_host_opt_in_http_https_and_no_forwarded_header_trust(bare_app):
    client = bare_app.test_client()
    assert client.get("/api/demo/state", headers={"Host": "public.example"}).status_code == 403
    assert client.get("/health", headers={"X-Forwarded-Host": "public.example"}).status_code == 200
    public = create_app(allowed_hosts=["public.example"], cookie_secure=True)
    try:
        response = public.test_client().get("/api/demo/state", base_url="https://public.example")
        assert response.status_code == 200 and "Secure" in response.headers["Set-Cookie"]
        for origin in ("https://public.example", "http://public.example"):
            assert public.test_client().post("/api/demo/verify", json={}, base_url="https://public.example",
                                             headers={"Origin": origin}).status_code == 409
        assert public.test_client().get("/health", headers={"Host": "other.example"}).status_code == 403
    finally:
        public.extensions["openline_demo_executor"].shutdown(wait=True)


@pytest.mark.parametrize("host", ["*", "https://example.org", "example.org:8001", "example.org/path", ""])
def test_wildcard_or_ambiguous_host_configuration_rejected(host):
    with pytest.raises(ValueError):
        create_app(allowed_hosts=[host])


@pytest.mark.parametrize("data", [{}, {"choice": []}, {"choice": "real-candidate"}, {"choice": "garden", "name": "do not collect"}, []])
def test_only_neutral_choice_field_is_accepted(bare_app, data):
    client = bare_app.test_client()
    client.get("/api/demo/state")
    assert client.post("/api/demo/vote", json=data).status_code == 400


def test_strict_json_body_limit_and_cross_site_control(bare_app):
    client = bare_app.test_client()
    client.get("/api/demo/state")
    assert client.post("/api/demo/vote", data='{"choice":"garden"}').status_code == 415
    assert client.post("/api/demo/vote", json={"choice": "garden"}, headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert client.post("/api/demo/vote", data="x" * 5000, content_type="application/json").status_code == 413
    assert client.post("/api/demo/verify", json={"unexpected": True}).status_code == 400


def test_cookie_is_opaque_httponly_and_no_identity_information(bare_app):
    response = bare_app.test_client().get("/api/demo/state")
    cookie = response.headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie and "Max-Age=1800" in cookie
    assert set(response.json) == {"phase", "eligible_count", "cast_count", "election_id", "receipt", "inclusion", "verification", "audit", "job", "limitations"}
    assert "name" not in response.json and "voters" not in response.json


def test_client_chosen_session_token_is_not_adopted(bare_app):
    client = bare_app.test_client()
    forged = "a" * 43
    client.set_cookie(COOKIE, forged)
    response = client.get("/api/demo/state")
    assert response.status_code == 200
    assert forged not in response.headers["Set-Cookie"]


def test_capacity_and_expiry_bound_memory():
    current = [0.0]
    app = create_app(max_sessions=1, session_ttl=1, clock=lambda: current[0])
    try:
        first, second = app.test_client(), app.test_client()
        assert first.get("/api/demo/state").status_code == 200
        assert second.get("/api/demo/state").status_code == 503
        current[0] = 2.0
        assert second.get("/api/demo/state").status_code == 200
        assert first.get("/api/demo/state").status_code == 503
    finally:
        app.extensions["openline_demo_executor"].shutdown(wait=True)


def test_background_worker_capacity_busy_reset_and_no_early_tallies():
    started, release = threading.Event(), threading.Event()

    def failing_factory():
        started.set()
        release.wait(5)
        raise ValueError("private simulation detail must not be returned")

    app = create_app(simulation_factory=failing_factory, max_workers=1, max_pending=1)
    try:
        first, second = app.test_client(), app.test_client()
        first.get("/api/demo/state")
        second.get("/api/demo/state")
        assert first.post("/api/demo/vote", json={"choice": "garden"}).status_code == 202
        assert started.wait(2)
        pending = first.get("/api/demo/state").json
        assert pending["cast_count"] == 0 and pending["verification"] is None and pending["receipt"] is None
        assert first.post("/api/demo/vote", json={"choice": "library"}).status_code == 409
        assert first.post("/api/demo/reset", json={}).status_code == 409
        assert second.post("/api/demo/vote", json={"choice": "library"}).status_code == 503
        assert first.get("/api/demo/export/record").status_code == 409
        release.set()
        deadline = time.monotonic() + 5
        while first.get("/api/demo/state").json["job"]["status"] != "error" and time.monotonic() < deadline:
            time.sleep(0.03)
        state = first.get("/api/demo/state").json
        assert state["job"]["status"] == "error"
        assert "private simulation detail" not in json.dumps(state)
        assert first.post("/api/demo/reset", json={}).json["phase"] == "ready"
    finally:
        release.set()
        app.extensions["openline_demo_executor"].shutdown(wait=True)


def test_research_whitelist_health_no_cookie_and_security_headers(bare_app):
    client = bare_app.test_client()
    health = client.get("/health")
    assert health.status_code == 200 and "Set-Cookie" not in health.headers
    assert client.get("/research/witness-002").status_code == 200
    assert client.get("/research/private-key").status_code == 404
    assert "frame-ancestors 'none'" in health.headers["Content-Security-Policy"]
    assert health.headers["X-Content-Type-Options"] == "nosniff"
    assert health.headers["Referrer-Policy"] == "no-referrer"
    assert health.headers["Cache-Control"] == "no-store"
    assert "geolocation=()" in health.headers["Permissions-Policy"]
