"""Independent regression for an observed anonymous-demo resource attack."""
from vote_lab.demo_server import create_app


def test_cross_site_state_requests_cannot_consume_the_only_demo_slot():
    app = create_app(max_sessions=1)
    try:
        for _ in range(3):
            response = app.test_client().get(
                "/api/demo/state", headers={"Sec-Fetch-Site": "cross-site"}
            )
            assert response.status_code == 403
            assert "Set-Cookie" not in response.headers

        visitor = app.test_client()
        response = visitor.get(
            "/api/demo/state", headers={"Sec-Fetch-Site": "same-origin"}
        )
        assert response.status_code == 200
        assert response.json["phase"] == "ready"
        assert "Set-Cookie" in response.headers
        assert app.test_client().get("/api/demo/state").status_code == 503
    finally:
        app.extensions["openline_demo_executor"].shutdown(wait=True)
