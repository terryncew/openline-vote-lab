"""Loopback-only synthetic browser demonstration; deliberately not a voting service."""
import json
import threading
from urllib.parse import urlsplit

from flask import Flask, Response, jsonify, request

from .model import Simulation


def create_app(simulation=None):
    app = Flask(__name__, static_folder="static", static_url_path="/static")
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
    app.config["SIMULATION"] = simulation or Simulation()
    lock = threading.RLock()

    @app.before_request
    def local_only():
        if request.host.split(":")[0] not in ("localhost", "127.0.0.1"):
            return jsonify(error="This experimental demo accepts loopback hosts only"), 403
        if request.method == "POST":
            origin = request.headers.get("Origin")
            if origin and (urlsplit(origin).scheme != "http" or urlsplit(origin).netloc != request.host):
                return jsonify(error="Cross-origin requests are not allowed"), 403
            if request.mimetype != "application/json":
                return jsonify(error="POST requests must use application/json"), 415

    @app.after_request
    def response_headers(response):
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(ValueError)
    def invalid_input(exc):
        return jsonify(error=str(exc)), 400

    @app.get("/")
    def index():
        return app.send_static_file("index.html")

    @app.get("/api/state")
    def state():
        with lock:
            return jsonify(app.config["SIMULATION"].state())

    @app.post("/api/<operation>")
    def operate(operation):
        data = request.get_json()
        if not isinstance(data, dict):
            raise ValueError("Expected a JSON object")
        with lock:
            sim = app.config["SIMULATION"]
            if operation == "cast":
                receipt = sim.cast(data.get("voter_id"), data.get("choice"))
                return jsonify(**sim.state(), receipt=receipt)
            if operation == "simulate":
                sim.simulate()
            elif operation == "seal":
                sim.seal()
            elif operation == "verify":
                sim.last_verification = sim.verify()
                return jsonify(sim.last_verification)
            elif operation == "attack":
                return jsonify(sim.attack(data.get("attack")))
            elif operation == "inclusion":
                return jsonify(sim.inclusion(data.get("ballot_id"), data.get("ballot_hash")))
            elif operation == "reset":
                app.config["SIMULATION"] = Simulation(data.get("mode", "baseline"))
                sim = app.config["SIMULATION"]
            else:
                return jsonify(error="Unknown demonstration operation"), 404
            return jsonify(sim.state())

    @app.get("/api/export/<artifact>")
    def export(artifact):
        with lock:
            sim = app.config["SIMULATION"]
            artifacts = {"record": sim.record, "anchor": sim.anchor, "checkpoint": sim.checkpoint, "receipts": sim.receipts()}
            if artifact not in artifacts:
                return jsonify(error="Unknown artifact"), 404
            if artifacts[artifact] is None:
                raise ValueError("Seal the election before exporting the archive or checkpoint")
            return Response(json.dumps(artifacts[artifact], indent=2), mimetype="application/json",
                            headers={"Content-Disposition": f'attachment; filename="{artifact}.json"'})

    return app
