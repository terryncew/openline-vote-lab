"""Independent adversarial review: historical trust must come from outside.

This small fixture complements the matched 100-voter experiment, rather than
replacing it. No witness key isolation is claimed from running these roles here.
"""
from copy import deepcopy
import socket
import subprocess
import sys

import pytest

from vote_lab.model import Simulation
from vote_lab.records import digest, new_key, public_key, receipt_payload, sign
from vote_lab.witness_verify import verify_witness
import vote_lab.witness_verify as witness_verifier


@pytest.fixture(scope="module")
def witnessed_election():
    sim = Simulation()
    for number, choice in ((1, "garden"), (2, "library"), (3, "garden")):
        sim.cast(f"voter-{number:03d}", choice)
    sim.seal()
    keys = {observer: new_key() for observer in ("observer-1", "observer-2")}
    prefix = sim._record(sim.accepted[:-1])
    return sim, keys, prefix


def checkpoint(key, observer, anchor, record, sequence=1, previous=None):
    return sign(key, {
        "domain": "witness-001/checkpoint/v1",
        "election_id": anchor["election_id"], "anchor_hash": digest(anchor),
        "observer_id": observer, "sequence": sequence,
        "previous_checkpoint_hash": digest(previous) if previous else None,
        "phase": "closed", "record_hash": digest(record),
        "ballot_count": len(record["ballots"]),
    })


def evidence(fixture, record=None):
    sim, keys, prefix = fixture
    record = record if record is not None else sim.record
    histories = {}
    for observer, key in keys.items():
        first = checkpoint(key, observer, sim.anchor, prefix)
        histories[observer] = [first, checkpoint(key, observer, sim.anchor, record, 2, first)]
    publication = {
        "schema": "witness-001/publication/v1", "condition": "C",
        "anchor": deepcopy(sim.anchor), "record": deepcopy(record),
        "observer_keys": {observer: public_key(key) for observer, key in keys.items()},
        "checkpoints": deepcopy(histories),
    }
    trust = {"schema": "witness-001/trust/v1", "election_anchor": deepcopy(sim.anchor),
             "observer_keys": deepcopy(publication["observer_keys"]),
             "required_observers": list(keys)}
    retained = {"schema": "witness-001/retained/v1", "histories": deepcopy(histories),
                "heads": {observer: {"sequence": 2, "checkpoint_hash": digest(chain[-1])}
                          for observer, chain in histories.items()}}
    return publication, trust, retained


def reordered(fixture):
    sim, _, _ = fixture
    record = deepcopy(sim.record)
    record["ballots"].reverse()
    for index, accepted in enumerate(record["ballots"], 1):
        accepted["receipt"] = sign(sim.receiver_key, receipt_payload(sim.anchor, accepted["entry"], index))
    # Homomorphic addition is commutative: the same tally/proofs remain valid.
    return record


def test_honest_evidence_checks_without_disclosing_totals(witnessed_election):
    result = verify_witness(*evidence(witnessed_election))
    assert result["status"] == "NOT DETECTED" and result["crypto_valid"] is True
    assert "totals" not in result
    assert "not prevention" in result["scope"]


@pytest.mark.parametrize("condition", ["A", "B", "C"])
def test_condition_label_does_not_supply_historical_trust(witnessed_election, condition):
    publication, _, _ = evidence(witnessed_election, reordered(witnessed_election))
    publication["condition"] = condition
    result = verify_witness(publication)
    assert result["status"] == "NOT DETECTED" and result["crypto_valid"]
    assert "No independently retained evidence" in result["scope"]


def test_valid_rewrite_needs_original_outside_reference(witnessed_election):
    _, trust, retained = evidence(witnessed_election)
    changed, _, _ = evidence(witnessed_election, reordered(witnessed_election))
    result = verify_witness(changed, trust, retained)
    assert result["status"] == "DETECTED" and result["crypto_valid"]
    assert any("retained" in finding for finding in result["evidence"])


def test_separate_key_pin_cannot_be_replaced_with_operator_bundle_key(witnessed_election):
    publication, trust, retained = evidence(witnessed_election)
    publication["observer_keys"]["observer-1"] = public_key(new_key())
    result = verify_witness(publication, trust, retained)
    assert result["status"] == "DETECTED"
    assert any("pinned verification keys" in finding for finding in result["evidence"])


def test_authentic_older_archive_is_valid_without_retained_later_head(witnessed_election):
    sim, _, prefix = witnessed_election
    publication, trust, retained = evidence(witnessed_election)
    publication["record"] = deepcopy(prefix)
    publication["checkpoints"] = {observer: chain[:1] for observer, chain in publication["checkpoints"].items()}
    assert verify_witness(publication)["status"] == "NOT DETECTED"
    protected = verify_witness(publication, trust, retained)
    assert protected["status"] == "DETECTED" and protected["crypto_valid"]
    assert any("rollback" in finding for finding in protected["evidence"])
    assert len(sim.record["ballots"]) == 3  # Attacks must preserve the reference.


def test_identical_checkpoint_replay_is_idempotent(witnessed_election):
    args = evidence(witnessed_election)
    first = verify_witness(*args)
    second = verify_witness(*deepcopy(args))
    assert first == second and first["status"] == "NOT DETECTED"


def test_lost_observer_reduces_coverage_without_fabricating_attack(witnessed_election):
    publication, trust, retained = evidence(witnessed_election)
    del publication["checkpoints"]["observer-1"]
    del retained["histories"]["observer-1"]
    del retained["heads"]["observer-1"]
    result = verify_witness(publication, trust, retained)
    assert result["status"] == "INCONCLUSIVE" and result["crypto_valid"]
    assert not result["evidence"]
    assert "observer-1" in " ".join(result["errors"])


def test_surviving_honest_observer_exposes_rewrite_despite_coverage_gap(witnessed_election):
    _, trust, retained = evidence(witnessed_election)
    publication, _, _ = evidence(witnessed_election, reordered(witnessed_election))
    del publication["checkpoints"]["observer-1"]
    del retained["histories"]["observer-1"]
    del retained["heads"]["observer-1"]
    result = verify_witness(publication, trust, retained)
    assert result["status"] == "DETECTED" and result["crypto_valid"]
    assert any("observer-2" in finding for finding in result["evidence"])


def test_one_compromised_observer_cannot_erase_other_retained_view(witnessed_election):
    _, trust, original = evidence(witnessed_election)
    publication, _, compromised = evidence(witnessed_election, reordered(witnessed_election))
    # Observer-1 can genuinely sign lies; observer-2 keeps its original history.
    compromised["histories"]["observer-2"] = original["histories"]["observer-2"]
    compromised["heads"]["observer-2"] = original["heads"]["observer-2"]
    result = verify_witness(publication, trust, compromised)
    assert result["status"] == "DETECTED" and result["crypto_valid"]
    assert any("do not identify which observer is honest" in finding for finding in result["evidence"])


def test_unknown_suppressed_submission_cannot_be_inferred(witnessed_election):
    _, _, prefix = witnessed_election
    publication, trust, retained = evidence(witnessed_election, prefix)
    result = verify_witness(publication, trust, retained)
    assert result["status"] == "NOT DETECTED" and result["crypto_valid"]
    assert "unobserved submissions" in result["scope"]


def test_pinned_keys_without_retained_history_do_not_prove_freshness(witnessed_election):
    publication, trust, _ = evidence(witnessed_election)
    result = verify_witness(publication, trust)
    assert result["status"] == "INCONCLUSIVE" and result["crypto_valid"]


def test_explicit_single_observer_policy_cannot_detect_hidden_equivocation(witnessed_election):
    publication, trust, retained = evidence(witnessed_election)
    changed, _, fork = evidence(witnessed_election, reordered(witnessed_election))
    # Observer-1 is shown only the original view. Observer-2's conflicting
    # authenticated view is unavailable to this explicitly narrower check.
    publication["checkpoints"].pop("observer-2")
    retained["histories"]["observer-2"] = fork["histories"]["observer-2"]
    retained["heads"]["observer-2"] = fork["heads"]["observer-2"]
    trust["required_observers"] = ["observer-1"]
    result = verify_witness(publication, trust, retained)
    assert result["status"] == "NOT DETECTED" and result["crypto_valid"]
    assert "single-observer policy" in result["scope"]
    trust["required_observers"] = ["observer-1", "observer-2"]
    assert verify_witness(publication, trust, retained)["status"] == "DETECTED"


@pytest.mark.parametrize("condition", ["A", "B"])
def test_operator_named_missing_observer_has_no_authenticated_coverage_policy(witnessed_election, condition):
    publication, _, _ = evidence(witnessed_election)
    publication["condition"] = condition
    publication["checkpoints"].pop("observer-1")
    result = verify_witness(publication)
    assert result["status"] == "NOT DETECTED" and result["crypto_valid"]


def test_offline_check_makes_no_network_connection(witnessed_election, monkeypatch):
    def blocked_connection(*args, **kwargs):
        raise AssertionError("Offline verification attempted a network connection")
    monkeypatch.setattr(socket.socket, "connect", blocked_connection)
    result = verify_witness(*evidence(witnessed_election))
    assert result["status"] == "NOT DETECTED" and result["crypto_valid"]


def test_verifier_imports_no_private_role_simulation_or_server():
    process = subprocess.run([sys.executable, "-c",
        "import sys; import vote_lab.witness_verify; "
        "assert 'vote_lab.model' not in sys.modules; "
        "assert 'vote_lab.server' not in sys.modules"], capture_output=True, text=True, timeout=30)
    assert process.returncode == 0, process.stdout + process.stderr


@pytest.mark.parametrize("field, value", [("sequence", True), ("ballot_count", True)])
def test_signed_boolean_cannot_replace_integer_checkpoint_fields(witnessed_election, field, value):
    publication, trust, retained = evidence(witnessed_election)
    _, keys, _ = witnessed_election
    payload = publication["checkpoints"]["observer-1"][0]["payload"]
    payload[field] = value
    publication["checkpoints"]["observer-1"][0] = sign(keys["observer-1"], payload)
    result = verify_witness(publication, trust, retained)
    assert result["status"] == "DETECTED" and result["crypto_valid"]


def test_witness_receipts_contain_commitments_not_voter_choices(witnessed_election):
    publication, _, retained = evidence(witnessed_election)
    allowed = {"domain", "election_id", "anchor_hash", "observer_id", "sequence",
               "previous_checkpoint_hash", "phase", "record_hash", "ballot_count"}
    for histories in (publication["checkpoints"], retained["histories"]):
        for chain in histories.values():
            for signed in chain:
                assert set(signed["payload"]) == allowed
                assert not ({"choice", "voter_id", "ballot_id", "nonce", "plaintext", "private_key"}
                            & set(signed["payload"]))


def test_unparsed_schema_does_not_claim_crypto_was_checked():
    result = verify_witness({"schema": "wrong"})
    assert result["status"] == "DETECTED" and result["crypto_valid"] is None


def test_retained_files_without_separate_key_pins_are_inconclusive(witnessed_election):
    publication, _, retained = evidence(witnessed_election)
    result = verify_witness(publication, retained=retained)
    assert result["status"] == "INCONCLUSIVE" and result["crypto_valid"]


def test_crypto_cache_rechecks_changed_record_and_anchor_bytes(witnessed_election, monkeypatch):
    publication, trust, retained = evidence(witnessed_election)
    original_verifier = witness_verifier.verify_record
    calls = []
    def counted_verifier(record, anchor, **kwargs):
        calls.append((digest(record), digest(anchor)))
        return original_verifier(record, anchor, **kwargs)
    witness_verifier._cached_archive.cache_clear()
    monkeypatch.setattr(witness_verifier, "verify_record", counted_verifier)
    assert verify_witness(publication, trust, retained)["crypto_valid"] is True
    assert verify_witness(*deepcopy((publication, trust, retained)))["crypto_valid"] is True
    assert len(calls) == 1

    changed_record = deepcopy(publication)
    changed_record["record"]["tally"]["totals"]["garden"] += 1
    invalid = verify_witness(changed_record, trust, retained)
    assert invalid["status"] == "DETECTED" and invalid["crypto_valid"] is False
    assert len(calls) == 2

    changed_anchor = deepcopy(trust)
    changed_anchor["election_anchor"]["eligible_voters"]["voter-001"] = public_key(new_key())
    invalid = verify_witness(publication, changed_anchor, retained)
    assert invalid["status"] == "DETECTED" and invalid["crypto_valid"] is False
    assert len(calls) == 3
    assert len(set(calls)) == 3
    # Witness evidence is always checked afresh even for a cached valid record.
    changed_head = deepcopy(retained)
    changed_head["heads"]["observer-1"]["checkpoint_hash"] = "0" * 64
    assert verify_witness(publication, trust, changed_head)["status"] == "DETECTED"
    assert len(calls) == 3
    witness_verifier._cached_archive.cache_clear()
