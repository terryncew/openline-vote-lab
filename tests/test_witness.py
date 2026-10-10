"""Matched attacks and negative controls for the bounded custody experiment."""
from copy import deepcopy
import json
import subprocess
import sys

import pytest

from vote_lab.records import canonical, digest
from vote_lab.witness import ATTACKS, CONDITIONS, CONTROLS, WitnessExperiment
from vote_lab.witness_verify import verify_witness


@pytest.fixture(scope="module")
def experiment():
    return WitnessExperiment()


@pytest.fixture(scope="module")
def outcomes(experiment):
    return experiment.run()


EXPECTED = {
    "delete-accepted": ("NOT DETECTED", "NOT DETECTED", "DETECTED"),
    "alter-ballot": ("DETECTED", "DETECTED", "DETECTED"),
    "replace-ballot": ("DETECTED", "DETECTED", "DETECTED"),
    "rewrite-history": ("NOT DETECTED", "NOT DETECTED", "DETECTED"),
    "conflicting-histories": ("NOT DETECTED", "NOT DETECTED", "DETECTED"),
    "forge-checkpoint": ("NOT DETECTED", "NOT DETECTED", "DETECTED"),
    "replay-checkpoint": ("DETECTED", "DETECTED", "DETECTED"),
    "rollback-checkpoint": ("NOT DETECTED", "NOT DETECTED", "DETECTED"),
    "suppression-before-observation": ("NOT DETECTED", "NOT DETECTED", "NOT DETECTED"),
    "observer-lost": ("NOT DETECTED", "NOT DETECTED", "DETECTED"),
    "observer-compromised": ("NOT DETECTED", "NOT DETECTED", "DETECTED"),
    "honest": ("NOT DETECTED", "NOT DETECTED", "NOT DETECTED"),
    "idempotent-replay": ("NOT DETECTED", "NOT DETECTED", "NOT DETECTED"),
    "isolated-equivocation": ("NOT DETECTED", "NOT DETECTED", "NOT DETECTED"),
    "observer-lost-honest": ("NOT DETECTED", "NOT DETECTED", "INCONCLUSIVE"),
    "all-observers-lost": ("NOT DETECTED", "NOT DETECTED", "INCONCLUSIVE"),
    "invalid-signature": ("DETECTED", "DETECTED", "DETECTED"),
}


@pytest.mark.parametrize("scenario", list(EXPECTED))
def test_matched_attack_and_negative_control_matrix(outcomes, scenario):
    rows = [r for r in outcomes["results"] if r["scenario"] == scenario]
    assert [r["condition"] for r in rows] == list(CONDITIONS)
    assert tuple(r["status"] for r in rows) == EXPECTED[scenario]
    assert len({r["record_hash"] for r in rows}) == 1, "Treatment conditions must share exact attack record bytes"
    for row in rows:
        assert row["trustworthy_party"] and row["scope"]
        assert "without_independent_evidence" in row and "without_any_witness_statements" in row
        assert "totals" not in row
        if row["status"] == "DETECTED":
            assert row["evidence"]


@pytest.mark.parametrize("scenario", ["delete-accepted", "rewrite-history", "conflicting-histories", "forge-checkpoint",
                                       "rollback-checkpoint", "observer-lost", "observer-compromised"])
def test_removing_independent_evidence_changes_valid_rewrite_detection(outcomes, scenario):
    row = next(r for r in outcomes["results"] if r["scenario"] == scenario and r["condition"] == "C")
    assert row["status"] == "DETECTED" and row["crypto_valid"] is True
    assert row["without_independent_evidence"] == "NOT DETECTED"
    assert row["removing_evidence_changes_result"] is True


def test_suppression_is_not_manufactured_into_a_detectable_failure(experiment):
    publication, trust, retained = experiment.case("suppression-before-observation", "C")
    assert len(publication["record"]["ballots"]) == 99
    assert verify_witness(publication, trust, retained)["status"] == "NOT DETECTED"
    # Same valid subset, but acknowledged/observed100 in a different branch.
    deleted, trust, retained = experiment.case("delete-accepted", "C")
    assert canonical(deleted["record"]) == canonical(publication["record"])
    assert verify_witness(deleted, trust, retained)["status"] == "DETECTED"


def test_separate_operator_owned_storage_adds_no_observer_property(outcomes):
    for scenario in [*ATTACKS, *CONTROLS]:
        rows = [r for r in outcomes["results"] if r["scenario"] == scenario]
        assert rows[0]["status"] == rows[1]["status"]


def test_single_observer_cannot_detect_a_fork_it_never_sees(experiment):
    assert digest(experiment._fork_histories["observer-1"][-1]) != digest(experiment._fork_histories["observer-2"][-1])
    pub, trust, retained = experiment.case("isolated-equivocation", "C")
    assert trust["required_observers"] == ["observer-1"]
    assert verify_witness(pub, trust, retained)["status"] == "NOT DETECTED"
    compared = experiment.case("conflicting-histories", "C")
    assert verify_witness(*compared)["status"] == "DETECTED"


def test_public_witness_receipts_are_commitments_not_individual_choice_receipts(experiment):
    permitted = {"domain", "election_id", "anchor_hash", "observer_id", "sequence", "previous_checkpoint_hash",
                 "phase", "record_hash", "ballot_count"}
    for history in experiment._histories.values():
        for signed in history:
            assert set(signed) == {"payload", "signature"}
            assert set(signed["payload"]) == permitted
            assert not ({"voter_id", "choice", "ballot_id", "nonce", "plaintext", "totals"} & set(signed["payload"]))


def test_export_uses_one_tally_and_preserves_existing_paths(experiment, outcomes, tmp_path):
    root = tmp_path / "run"
    experiment.export(root, results=outcomes)
    publications = list(root.rglob("publication.json"))
    assert len(publications) == 3
    records = [json.loads(p.read_text())["record"] for p in publications]
    assert len({digest(r) for r in records}) == 1
    assert all(len(r["ballots"]) == 100 for r in records)
    assert not any("private_key" in p.read_text() or "secret_key" in p.read_text() for p in root.rglob("*.json"))
    assert json.loads((root / "export-policy.json").read_text())["selected_scenario"] == "rewrite-history"
    with pytest.raises(ValueError, match="never overwritten"):
        experiment.export(root)


@pytest.mark.parametrize("condition,expected_code", [("A", 0), ("B", 0), ("C", 1)])
def test_offline_cli_returns_actual_detection_from_exported_public_evidence(experiment, tmp_path, condition, expected_code):
    root = tmp_path / "run"
    experiment.export(root)
    command = [sys.executable, "-m", "vote_lab", "witness-verify", "--publication", str(root / "operator" / condition / "publication.json")]
    if condition == "C":
        command += ["--trust", str(root / "observer-custody/pinned-trust.json"),
                    "--retained", str(root / "observer-custody/retained-evidence.json")]
    run = subprocess.run(command, capture_output=True, text=True, timeout=45)
    assert run.returncode == expected_code, run.stderr + run.stdout
    result = json.loads(run.stdout)
    assert result["status"] == ("DETECTED" if condition == "C" else "NOT DETECTED")
    assert "totals" not in result


def test_missing_observer_state_is_inconclusive_not_fabricated_detection(experiment, tmp_path):
    pub, trust, retained = experiment.case("observer-lost-honest", "C")
    assert verify_witness(pub, trust, retained)["status"] == "INCONCLUSIVE"
    for name, value in [("publication", pub), ("trust", trust), ("retained", retained)]:
        (tmp_path / f"{name}.json").write_text(json.dumps(value))
    command = [sys.executable, "-m", "vote_lab", "witness-verify"]
    for name in ["publication", "trust", "retained"]:
        command += ["--" + name, str(tmp_path / f"{name}.json")]
    run = subprocess.run(command, capture_output=True, text=True, timeout=45)
    assert run.returncode == 3 and json.loads(run.stdout)["status"] == "INCONCLUSIVE"


def test_existing_election_verification_does_not_depend_on_witnesses(outcomes):
    for scenario in ["alter-ballot", "replace-ballot"]:
        for row in [r for r in outcomes["results"] if r["scenario"] == scenario]:
            assert row["status"] == "DETECTED" and row["crypto_valid"] is False
            assert row["without_any_witness_statements"] == "DETECTED"


@pytest.mark.parametrize("scenario", ["delete-accepted", "rewrite-history", "observer-lost", "all-observers-lost", "conflicting-histories", "replay-checkpoint"])
def test_operator_c_attack_adapter_cannot_use_honest_observer_signing_keys(experiment, monkeypatch, scenario):
    def forbidden(*args, **kwargs):
        raise AssertionError("An operator-only attack must not mint an honest observer statement")
    monkeypatch.setattr(experiment, "_sign", forbidden)
    # Statement fixtures were genuinely issued before the attack adapter runs.
    experiment.case(scenario, "C")


def test_one_compromised_observer_does_not_grant_the_other_key(experiment, monkeypatch):
    original = experiment._sign
    used = []
    def only_compromised(observer, *args, **kwargs):
        assert observer == "observer-1", "The uncorrupted observer's key must remain unavailable to the operator"
        used.append(observer)
        return original(observer, *args, **kwargs)
    monkeypatch.setattr(experiment, "_sign", only_compromised)
    experiment.case("observer-compromised", "C")
    assert used == ["observer-1"]
