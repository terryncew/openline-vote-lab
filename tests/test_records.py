import copy
import json
import subprocess
import sys

import pytest

from vote_lab.__main__ import read_json
from vote_lab.model import ATTACKS, Simulation
from vote_lab.records import checkpoint_payload, digest, new_key, receipt_payload, sign, vote_payload
from vote_lab.verification import verify_record


@pytest.fixture(scope="module")
def election():
    sim = Simulation()
    sim.simulate()
    sim.seal()
    return sim


@pytest.fixture(scope="module")
def receiver():
    sim = Simulation("receiver")
    for i, choice in [(1, "garden"), (2, "library"), (3, "garden")]:
        sim.cast(f"voter-{i:03d}", choice)
    sim.seal()
    return sim


def test_full_hundred_voter_election(election):
    result = election.verify()
    assert result["ok"] and result["completeness"]
    assert result["totals"] == {"garden": 60, "library": 40}
    assert len(election.record["ballots"]) == 100


@pytest.mark.parametrize("attack", list(ATTACKS))
@pytest.mark.parametrize("fixture", ["election", "receiver"])
def test_adversarial_record_copies(attack, fixture, request):
    sim = request.getfixturevalue(fixture)
    original = digest(sim.record)
    result = sim.attack(attack)
    assert result["detected"] and not result["ok"], result
    assert result["errors"]
    assert digest(sim.record) == original


def test_admission_rejects_duplicate_and_ineligible_voters():
    sim = Simulation()
    with pytest.raises(ValueError, match="eligible"):
        sim.cast("outsider-999", "garden")
    with pytest.raises(ValueError, match="fictional options"):
        sim.cast("voter-001", "real-candidate")
    sim.cast("voter-001", "garden")
    with pytest.raises(ValueError, match="already"):
        sim.cast("voter-001", "library")
    assert len(sim.accepted) == 1


def test_retallied_subset_is_valid_but_not_complete(election):
    # Honest ballot/proof/signature subset; the operator can decrypt and publish it.
    subset = election._record(election.accepted[:-1])
    without_external_evidence = verify_record(subset, election.anchor, require_checkpoint=False)
    assert without_external_evidence["ok"]
    assert not without_external_evidence["completeness"]
    assert sum(without_external_evidence["totals"].values()) == 99
    assert not verify_record(subset, election.anchor, election.checkpoint)["ok"]
    assert not verify_record(subset, election.anchor, receipts=election.receipts(), require_checkpoint=False)["ok"]


def test_valid_replacement_ciphertext_cannot_be_signed_by_operator(receiver):
    record = copy.deepcopy(receiver.record)
    entry = record["ballots"][0]["entry"]
    entry["ballot"] = receiver.crypto.encrypt(entry["ballot_id"], "library")
    entry["authorization"] = sign(receiver.receiver_key, vote_payload(receiver.anchor, entry["voter_id"], entry["ballot_id"], digest(entry["ballot"])))
    record["ballots"][0]["receipt"] = sign(receiver.receiver_key, receipt_payload(receiver.anchor, entry, 1))
    result = verify_record(record, receiver.anchor, require_checkpoint=False)
    assert not result["ok"] and "signature" in result["errors"][0]


def test_receiver_capability_has_no_replacement_for_voter_signature(receiver):
    record = copy.deepcopy(receiver.record)
    record["ballots"][0]["entry"]["authorization"]["signature"] = record["ballots"][0]["entry"]["capability"]["signature"]
    assert not verify_record(record, receiver.anchor, require_checkpoint=False)["ok"]


@pytest.mark.parametrize("mutation", ["missing", "invalid", "other-election"])
def test_optional_capability_checked(receiver, mutation):
    record = copy.deepcopy(receiver.record)
    entry = record["ballots"][0]["entry"]
    if mutation == "missing":
        del entry["capability"]
    elif mutation == "invalid":
        entry["capability"] = sign(new_key(), entry["capability"]["payload"])
    else:
        entry["capability"]["payload"]["election_id"] = "another-fictional-election"
    assert not verify_record(record, receiver.anchor, require_checkpoint=False)["ok"]


def test_independent_anchor_rejects_whole_election_replacement(election, receiver):
    assert not verify_record(receiver.record, election.anchor, receiver.checkpoint)["ok"]


def test_no_closure_checkpoint_means_no_completeness_claim(receiver):
    assert not verify_record(receiver.record, receiver.anchor)["ok"]
    result = verify_record(receiver.record, receiver.anchor, require_checkpoint=False)
    assert result["ok"] and not result["completeness"]


def test_receipt_inclusion_checks_exact_ciphertext(receiver):
    payload = receiver.receipts()[0]["payload"]
    assert receiver.inclusion(payload["ballot_id"], payload["ballot_hash"])["included"]
    assert not receiver.inclusion(payload["ballot_id"], "00" * 32)["included"]


def test_signed_checkpoint_is_not_self_authenticating(receiver):
    forged = sign(receiver.receiver_key, checkpoint_payload(receiver.anchor, receiver.record))
    assert not verify_record(receiver.record, receiver.anchor, forged)["ok"]


def test_public_artifacts_do_not_export_plaintext_or_keys(election):
    def walk(value):
        if isinstance(value, dict):
            for name, item in value.items():
                assert name not in {"secret_key", "private_key", "plaintext", "choice", "vote", "seed"}
                if name == "nonce":
                    assert item is None
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
    walk([election.record, election.anchor, election.checkpoint, election.receipts()])


def test_offline_cli_verifies_without_the_server_or_private_keys(receiver, tmp_path):
    for name, value in [("record", receiver.record), ("anchor", receiver.anchor), ("checkpoint", receiver.checkpoint), ("receipts", receiver.receipts())]:
        (tmp_path / f"{name}.json").write_text(json.dumps(value))
    command = [sys.executable, "-m", "vote_lab", "verify"]
    for name in ["record", "anchor", "checkpoint", "receipts"]:
        command += [f"--{name}", str(tmp_path / f"{name}.json")]
    process = subprocess.run(command, capture_output=True, text=True, timeout=30)
    assert process.returncode == 0, process.stderr + process.stdout
    assert json.loads(process.stdout)["totals"] == {"garden": 2, "library": 1}
    corrupt = copy.deepcopy(receiver.record)
    corrupt["tally"]["totals"]["garden"] += 1
    (tmp_path / "record.json").write_text(json.dumps(corrupt))
    process = subprocess.run(command, capture_output=True, text=True, timeout=30)
    assert process.returncode == 1
    assert not json.loads(process.stdout)["ok"]


@pytest.mark.parametrize("content", ['{"x":1,"x":2}', '{"x":NaN}'])
def test_cli_rejects_ambiguous_json(tmp_path, content):
    path = tmp_path / "invalid.json"
    path.write_text(content)
    with pytest.raises(ValueError):
        read_json(path)


def test_anchor_outer_scope_must_match_cryptographic_scope(receiver):
    anchor = copy.deepcopy(receiver.anchor)
    anchor["election_id"] = "fictional-replacement-scope"
    result = verify_record(receiver.record, anchor, receiver.checkpoint)
    assert not result["ok"] and "cryptographic election scope" in result["errors"][0]


def test_demo_preserves_existing_exports_without_partial_write(tmp_path):
    existing = tmp_path / "record.json"
    existing.write_text("existing synthetic evidence")
    process = subprocess.run([sys.executable, "-m", "vote_lab", "demo", "--out", str(tmp_path)],
                             capture_output=True, text=True, timeout=10)
    assert process.returncode == 1 and "Refusing to overwrite" in process.stderr
    assert existing.read_text() == "existing synthetic evidence"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["record.json"]
