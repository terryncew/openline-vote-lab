import pytest

from vote_lab.model import Simulation
from vote_lab.server import create_app


@pytest.fixture()
def client():
    app = create_app(Simulation())
    app.config.update(TESTING=True)
    return app.test_client()


def test_local_browser_flow_and_exports(client):
    assert client.get("/").status_code == 200
    state = client.get("/api/state").json
    assert state["eligible_count"] == 100 and state["cast_count"] == 0
    response = client.post("/api/cast", json={"voter_id": "voter-001", "choice": "garden"})
    assert response.status_code == 200
    receipt = response.json["receipt"]["payload"]
    assert client.post("/api/inclusion", json=receipt).json["included"]
    assert client.post("/api/cast", json={"voter_id": "voter-001", "choice": "library"}).status_code == 400
    assert client.post("/api/seal", json={}).json["totals"] == {"garden": 1, "library": 0}
    assert client.post("/api/verify", json={}).json["ok"]
    assert client.post("/api/attack", json={"attack": "modified"}).json["detected"]
    assert client.get("/api/export/record").json["schema"] == "openline-vote-lab/record/v1"
    assert client.get("/api/export/checkpoint").json["signature"]


def test_foreign_origin_and_host_cannot_mutate_simulation(client):
    assert client.post("/api/simulate", json={}, headers={"Origin": "https://foreign.example"}).status_code == 403
    assert client.post("/api/simulate", json={}, headers={"Host": "foreign.example"}).status_code == 403
    assert client.post("/api/simulate", data="{}").status_code == 415
    assert client.get("/api/state").json["cast_count"] == 0


@pytest.mark.parametrize("voter_id,choice", [([], "garden"), ({}, "garden"), ("voter-001", []), ("unknown", "garden")])
def test_malformed_cast_rejected(client, voter_id, choice):
    assert client.post("/api/cast", json={"voter_id": voter_id, "choice": choice}).status_code == 400


def test_security_headers_and_open_export_rules(client):
    response = client.get("/")
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert client.get("/api/export/anchor").status_code == 200
    assert client.get("/api/export/checkpoint").status_code == 400
    assert client.post("/api/reset", json={"mode": "not-a-mode"}).status_code == 400
