"""Real proof checks through separately operable CLIs, not real independence."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys

import pytest

from vote_lab.custody_experiment import CustodyExperiment
from vote_lab.custody_operator import OperatorFixture
from vote_lab.model import Simulation
from vote_lab.records import digest, receipt_payload, sign


class SmallOperator:
    """Three real encrypted synthetic ballots keep process-boundary tests quick.

    The actual research demonstration uses the default 100-ballot fixture.
    This test reuses the production attack constructors and ElectionGuard.
    """
    record_for = OperatorFixture.record_for

    def __init__(self):
        self.sim = Simulation()
        for number, choice in ((1, "garden"), (2, "library"), (3, "garden")):
            self.sim.cast(f"voter-{number:03d}", choice)
        self.sim.seal()
        self.anchor, self.original = deepcopy(self.sim.anchor), deepcopy(self.sim.record)
        self.prefix = self.sim._record(self.sim.accepted[:-1])
        self.reordered = deepcopy(self.original)
        self.reordered["ballots"].reverse()
        for index, accepted in enumerate(self.reordered["ballots"], 1):
            accepted["receipt"] = sign(self.sim.receiver_key, receipt_payload(self.anchor, accepted["entry"], index))
        self._prepared = {}

    def export(self, path):
        path.mkdir()
        for name, value in (("anchor", self.anchor), ("initial-record", self.original),
                            ("selected-attack-record", self.reordered)):
            (path / (name + ".json")).write_text(json.dumps(value))


@pytest.fixture(scope="module")
def apparatus(tmp_path_factory):
    experiment = CustodyExperiment(tmp_path_factory.mktemp("custody-processes") / "run", fixture=SmallOperator())
    return experiment, experiment.run()


REQUIREMENTS = {
    "honest": "PASS", "delete-accepted": "FAIL", "alter-ballot": "FAIL", "replace-ballot": "FAIL",
    "rewrite-history": "FAIL", "conflicting-histories": "FAIL", "forge-checkpoint": "FAIL",
    "replay-checkpoint": "FAIL", "rollback-checkpoint": "FAIL", "suppression-before-observation": "PASS",
    "observer-lost": "FAIL", "observer-unavailable": "INCONCLUSIVE", "observer-compromised": "FAIL",
    "compromised-survivor-only": "INCONCLUSIVE", "idempotent-replay": "PASS", "isolated-equivocation": "PASS",
    "all-observers-lost": "INCONCLUSIVE", "missing-trust": "INCONCLUSIVE", "missing-identity-pin": "INCONCLUSIVE",
    "invalid-signature": "FAIL",
}


@pytest.mark.parametrize("scenario,expected", REQUIREMENTS.items())
def test_matched_process_apparatus_actual_outcomes(apparatus, scenario, expected):
    _, results = apparatus
    row = next(row for row in results["results"] if row["scenario"] == scenario)
    assert row["status"] == expected and row["test_result"] == "PASS"
    assert row["real_custody_status"] == "INCONCLUSIVE"
    assert row["without_trust"] == "INCONCLUSIVE", "Untrusted self-issued keys cannot earn a security PASS"
    assert "totals" not in row
    if expected == "FAIL":
        assert row["detection"] == "DETECTED" and row["evidence"]


def test_local_administrative_boundary_explicitly_fails(apparatus):
    _, results = apparatus
    assert results["same_uid_boundary_probe"]["operator_can_rewrite_witness_store"] is True
    assert results["same_uid_boundary_probe"]["separation_requirement"] == "FAIL"
    assert results["real_custody_status"] == "INCONCLUSIVE"
    assert results["environment"]["third_party_reproduction"] == "NOT PERFORMED"
    assert all(role["independent_administrative_owner"] == "NOT ESTABLISHED" for role in results["key_provenance"])


def test_witness_refuses_valid_rewrite_without_advancing(apparatus):
    _, results = apparatus
    assert results["witness_refusal"] == {"artifact_status": "FAIL", "retained_evidence_unchanged": True, "test_result": "PASS"}


def test_suppression_vs_witnessed_deletion_same_math_different_history(apparatus):
    _, results = apparatus
    rows = {row["scenario"]: row for row in results["results"]}
    assert rows["suppression-before-observation"]["record_hash"] == rows["delete-accepted"]["record_hash"]
    assert rows["suppression-before-observation"]["status"] == "PASS"
    assert rows["delete-accepted"]["status"] == "FAIL"
    assert rows["delete-accepted"]["crypto_valid"] is True


def test_old_authentic_checkpoint_cannot_establish_latest_state(apparatus):
    _, results = apparatus
    for scenario in ("replay-checkpoint", "rollback-checkpoint"):
        row = next(row for row in results["results"] if row["scenario"] == scenario)
        assert row["status"] == "FAIL" and row["crypto_valid"] is True
        assert row["older_reference_only"] == "PASS"
        assert row["without_retained_evidence"] == "INCONCLUSIVE"


def test_existing_crypto_rejections_survive_without_observer_evidence(apparatus):
    _, results = apparatus
    for scenario in ("alter-ballot", "replace-ballot"):
        row = next(row for row in results["results"] if row["scenario"] == scenario)
        assert row["crypto_valid"] is False
        assert row["without_retained_evidence"] == "FAIL"


@pytest.mark.parametrize("kind,expected", [("full", 1), ("no-pins", 3), ("no-evidence", 3),
                                           ("missing-file", 3), ("malformed-file", 3)])
def test_offline_cli_missing_inputs_never_pass(apparatus, tmp_path, kind, expected):
    experiment, _ = apparatus
    offline = experiment.root / "offline"
    command = [sys.executable, "-m", "vote_lab.custody_cli", "verify", "--publication", str(offline / "publication.json")]
    if kind != "no-pins":
        trust = offline / "pinned-trust.json"
        if kind == "missing-file":
            trust = tmp_path / "nonexistent.json"
        elif kind == "malformed-file":
            trust = tmp_path / "invalid.json"
            trust.write_text('{"schema":')
        command += ["--trust", str(trust)]
    if kind != "no-evidence":
        for number in (1, 2):
            command += ["--evidence", str(offline / f"witness-{number}-evidence.json")]
    run = subprocess.run(command, capture_output=True, text=True, timeout=45)
    assert run.returncode == expected, run.stderr + run.stdout
    verdict = json.loads(run.stdout)
    assert verdict["status"] == ("FAIL" if kind == "full" else "INCONCLUSIVE")
    assert verdict["real_custody_status"] == "INCONCLUSIVE"


def test_offline_cli_does_not_import_private_role_code_or_connect(apparatus):
    experiment, _ = apparatus
    offline = experiment.root / "offline"
    script = """
import socket,sys
def blocked(*args,**kwargs): raise AssertionError('Network used by offline verifier')
socket.socket.connect=blocked
socket.socket.connect_ex=blocked
socket.create_connection=blocked
from vote_lab.custody_cli import main
code=main(sys.argv[1:])
assert 'vote_lab.custody' not in sys.modules
assert 'vote_lab.model' not in sys.modules
assert 'vote_lab.server' not in sys.modules
raise SystemExit(code)
"""
    command = [sys.executable, "-c", script, "verify", "--publication", str(offline / "publication.json"),
               "--trust", str(offline / "pinned-trust.json")]
    for number in (1, 2):
        command += ["--evidence", str(offline / f"witness-{number}-evidence.json")]
    run = subprocess.run(command, capture_output=True, text=True, timeout=45)
    assert run.returncode == 1, run.stderr + run.stdout
    verdict = json.loads(run.stdout)
    assert verdict["status"] == "FAIL" and verdict["crypto_valid"] is True


def test_no_overwrite_and_public_matrix_does_not_export_keys_or_choices(apparatus):
    experiment, results = apparatus
    with pytest.raises(ValueError, match="fresh output"):
        CustodyExperiment(experiment.root, fixture=experiment.fixture)
    serialized = json.dumps(results)
    assert '"private_key"' not in serialized and '"totals"' not in serialized
    pub = json.loads((experiment.root / "offline/publication.json").read_text())
    assert digest(pub["record"]) == digest(experiment.fixture.reordered)
