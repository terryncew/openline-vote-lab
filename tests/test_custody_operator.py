"""Synthetic operator archives remain valid without any custody-observer secret."""
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import pytest

from vote_lab import model
from vote_lab.custody_operator import (
    OperatorFixture, SCENARIOS, main, make_publication, read_public_identity,
)
from vote_lab.records import canonical, digest, new_key, public_key
from vote_lab.verification import verify_record


@pytest.fixture(scope="module")
def fixture():
    original_keygen = model.new_key
    generated = []
    def baseline_key():
        key = original_keygen()
        generated.append(key)
        return key
    with patch.object(model, "new_key", baseline_key):
        operator = OperatorFixture()
    # 100 synthetic voters + one receipt key + the inherited, unused legacy
    # witness key. There is no additional custody-observer key generation.
    assert len(generated) == 102
    return operator


@pytest.fixture
def identities(tmp_path):
    paths, keys = [], {}
    for observer in ("observer-1", "observer-2"):
        descriptor = {"schema": "witness-002/identity/v1", "observer_id": observer,
                      "public_key": public_key(new_key())}
        path = tmp_path / (observer + ".json")
        path.write_text(json.dumps({"identity": descriptor, "fingerprint": digest(descriptor)}))
        paths.append(path)
        keys[observer] = descriptor["public_key"]
    return paths, keys


def test_operator_has_only_baseline_role_keys_and_100_synthetic_voters(fixture):
    assert fixture.sim.last_verification["ok"] is True
    assert len(fixture.original["ballots"]) == 100
    assert len(fixture.anchor["eligible_voters"]) == 100
    assert fixture.anchor["mode"] == "baseline"
    assert not hasattr(fixture, "observer_keys")
    assert not hasattr(fixture, "observer_private_keys")
    source = Path(sys.modules[OperatorFixture.__module__].__file__).read_text()
    assert "WitnessExperiment" not in source
    assert "Ed25519PrivateKey" not in source


@pytest.mark.parametrize("scenario,expected_count", [("rewrite-history", 100), ("delete-accepted", 99)])
def test_stronger_operator_attacks_keep_valid_electionguard_archives(fixture, scenario, expected_count):
    record = fixture.record_for(scenario)
    result = verify_record(record, fixture.anchor, require_checkpoint=False)
    assert result["ok"] is True, result["errors"]
    assert result["completeness"] is False
    assert len(record["ballots"]) == expected_count
    assert digest(record) != digest(fixture.original)


def test_history_rewrite_preserves_every_encrypted_vote_and_the_exact_tally(fixture):
    assert canonical(fixture.original["tally"]) == canonical(fixture.reordered["tally"])
    assert sorted(digest(item["entry"]) for item in fixture.original["ballots"]) == \
           sorted(digest(item["entry"]) for item in fixture.reordered["ballots"])
    assert fixture.original["ballots"][0]["entry"] == fixture.reordered["ballots"][1]["entry"]


def test_rollback_changes_only_published_checkpoint_not_the_sealed_archive(fixture):
    assert canonical(fixture.record_for("rollback-checkpoint")) == canonical(fixture.original)


@pytest.mark.parametrize("scenario", ["alter-ballot", "replace-ballot"])
def test_operator_cannot_hide_invalid_voter_authorization(fixture, scenario):
    result = verify_record(fixture.record_for(scenario), fixture.anchor, require_checkpoint=False)
    assert result["ok"] is False
    assert any("signature" in error.lower() or "scope" in error.lower() for error in result["errors"])


def test_record_for_is_stable_and_does_not_return_mutable_internal_state(fixture):
    selected = fixture.record_for("replace-ballot")
    before = digest(selected)
    selected["ballots"].clear()
    assert digest(fixture.record_for("replace-ballot")) == before
    assert len(fixture.original["ballots"]) == 100
    with pytest.raises(ValueError, match="Unknown"):
        fixture.record_for("not-a-scenario")
    assert "suppression-before-observation" in SCENARIOS


def _inspect_public(value):
    if isinstance(value, dict):
        for key, child in value.items():
            assert key not in {"secret_key", "private_key", "plaintext", "answer", "vote", "choice"}
            if key == "nonce":
                assert child is None
            _inspect_public(child)
    elif isinstance(value, list):
        for child in value:
            _inspect_public(child)


def test_default_export_contains_no_observer_identity_or_secrets_or_subset_tally(fixture, tmp_path):
    destination = tmp_path / "operator"
    fixture.export(destination)
    assert sorted(p.name for p in destination.iterdir()) == [
        "anchor.json", "initial-record.json", "scenario.json", "selected-attack-record.json"]
    values = {p.name: json.loads(p.read_text()) for p in destination.iterdir()}
    _inspect_public(values)
    initial, selected = values["initial-record.json"], values["selected-attack-record.json"]
    assert len(initial["ballots"]) == len(selected["ballots"]) == 100
    assert canonical(initial["tally"]) == canonical(selected["tally"])
    assert "totals" not in values["scenario.json"]
    assert "observer_keys" not in values["scenario.json"]
    before = {p.name: p.read_bytes() for p in destination.iterdir()}
    with pytest.raises(ValueError, match="never overwritten"):
        fixture.export(destination)
    assert before == {p.name: p.read_bytes() for p in destination.iterdir()}


def test_subset_export_makes_adjacent_tally_privacy_leak_explicit(fixture, tmp_path, capsys):
    destination = tmp_path / "private-deletion-fixture"
    fixture.export(destination, scenario="delete-accepted")
    description = json.loads((destination / "scenario.json").read_text())
    assert "difference reveals" in description["privacy"]
    assert "Do not publish" in description["privacy"]
    assert "SYNTHETIC PRIVATE ATTACK FIXTURE ONLY" in capsys.readouterr().err


def test_publication_uses_exact_archives_and_exported_public_keys(fixture, identities):
    paths, keys = identities
    for path in paths:
        identity = read_public_identity(path)
        assert identity["public_key"] == keys[identity["observer_id"]]
    publication = make_publication(fixture.anchor, fixture.reordered, keys)
    assert set(publication) == {"schema", "condition", "anchor", "record", "observer_keys", "checkpoints"}
    assert publication["condition"] == "C"
    assert canonical(publication["record"]) == canonical(fixture.reordered)
    assert publication["observer_keys"] == keys
    publication["record"]["ballots"].clear()
    assert len(fixture.reordered["ballots"]) == 100


@pytest.mark.parametrize("attack", ["fingerprint", "secret-field", "identity-field", "bad-public-key"])
def test_public_identity_reader_rejects_tampering_and_private_key_fields(identities, attack):
    paths, _ = identities
    value = json.loads(paths[0].read_text())
    if attack == "fingerprint":
        value["fingerprint"] = "0" * 64
    elif attack == "secret-field":
        value["private_key"] = "must-not-be-read"
    elif attack == "identity-field":
        value["identity"]["private_key"] = "must-not-be-read"
        value["fingerprint"] = digest(value["identity"])
    else:
        value["identity"]["public_key"] = "AAAA"
        value["fingerprint"] = digest(value["identity"])
    paths[0].write_text(json.dumps(value))
    with pytest.raises(ValueError):
        read_public_identity(paths[0])


def test_publication_rejects_absent_or_duplicate_observer_identity(fixture, identities):
    _, keys = identities
    with pytest.raises(ValueError, match="both"):
        make_publication(fixture.anchor, fixture.original, {"observer-1": keys["observer-1"]})
    with pytest.raises(ValueError, match="distinct"):
        make_publication(fixture.anchor, fixture.original,
                         {"observer-1": keys["observer-1"], "observer-2": keys["observer-1"]})


def test_publication_cli_reads_only_public_role_identities(fixture, identities, tmp_path):
    paths, keys = identities
    for name, value in (("anchor", fixture.anchor), ("record", fixture.reordered)):
        (tmp_path / (name + ".json")).write_text(json.dumps(value))
    out = tmp_path / "publication.json"
    command = [sys.executable, "-m", "vote_lab.custody_operator", "publish", "--anchor",
               str(tmp_path / "anchor.json"), "--record", str(tmp_path / "record.json"),
               "--identity-a", str(paths[0]), "--identity-b", str(paths[1]), "--out", str(out)]
    run = subprocess.run(command, capture_output=True, text=True, timeout=15)
    assert run.returncode == 0, run.stdout + run.stderr
    publication = json.loads(out.read_text())
    assert publication["observer_keys"] == keys
    assert digest(publication["record"]) == digest(fixture.reordered)
    old = out.read_bytes()
    repeated = subprocess.run(command, capture_output=True, text=True, timeout=15)
    assert repeated.returncode == 1 and "never overwritten" in repeated.stderr
    assert out.read_bytes() == old


def test_existing_output_stops_before_expensive_fixture_creation(tmp_path):
    destination = tmp_path / "existing"
    destination.mkdir()
    with patch("vote_lab.custody_operator.OperatorFixture") as constructor:
        assert main(["--out", str(destination)]) == 1
    constructor.assert_not_called()
