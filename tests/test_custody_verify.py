"""Adapter controls; real ElectionGuard and process roles have separate tests.

These lean fixtures intentionally mock only the existing archive verifier, so
they test pin/evidence policy and real Ed25519 statements without presenting a
tiny synthetic dictionary as an ElectionGuard election.
"""
from copy import deepcopy
import socket
import subprocess
import sys

import pytest

from vote_lab.custody_verify import validate_trust, verify_custody
from vote_lab.records import digest, new_key, public_key, sign
import vote_lab.witness_verify as existing


def checkpoint(key, observer, anchor, record, sequence=1, previous=None, phase="closed"):
    return sign(key, {"domain": "witness-001/checkpoint/v1", "election_id": anchor["election_id"],
                     "anchor_hash": digest(anchor), "observer_id": observer, "sequence": sequence,
                     "previous_checkpoint_hash": digest(previous) if previous else None,
                     "phase": phase, "record_hash": digest(record), "ballot_count": len(record["ballots"])})


@pytest.fixture
def supplied(monkeypatch):
    def archive_check(record, anchor, require_checkpoint):
        assert require_checkpoint is False
        return {"ok": not record.get("invalid", False),
                "errors": ["Unit fixture models a rejected existing proof"] if record.get("invalid") else []}
    monkeypatch.setattr(existing, "verify_record", archive_check)
    existing._cached_archive.cache_clear()
    anchor = {"schema": "adapter-unit-fixture", "election_id": "fictional-custody-unit"}
    record = {"ballots": [{"encrypted-unit-placeholder": 1}, {"encrypted-unit-placeholder": 2}]}
    keys = {observer: new_key() for observer in ("observer-1", "observer-2")}
    identities = {observer: {"schema": "witness-002/identity/v1", "observer_id": observer,
                             "public_key": public_key(key)} for observer, key in keys.items()}
    histories = {observer: [checkpoint(key, observer, anchor, record)] for observer, key in keys.items()}
    publication = {"schema": "witness-001/publication/v1", "condition": "C", "anchor": anchor,
                   "record": record, "observer_keys": {observer: public_key(key) for observer, key in keys.items()},
                   "checkpoints": deepcopy(histories)}
    trust = {"schema": "witness-002/trust/v1", "election_anchor": deepcopy(anchor),
             "observer_identities": identities, "required_observers": list(keys),
             "pins": {"anchor_hash": digest(anchor),
                      "identity_hashes": {observer: digest(identity) for observer, identity in identities.items()}}}
    evidence = {"schema": "witness-001/retained/v1", "histories": deepcopy(histories),
                "heads": {observer: {"sequence": 1, "checkpoint_hash": digest(chain[-1])}
                          for observer, chain in histories.items()}}
    yield publication, trust, evidence, keys
    existing._cached_archive.cache_clear()


def observer_export(evidence, observer):
    return {"schema": evidence["schema"], "histories": {observer: deepcopy(evidence["histories"][observer])},
            "heads": {observer: deepcopy(evidence["heads"][observer])}}


def test_complete_two_observer_evidence_passes_only_internal_consistency(supplied):
    publication, trust, evidence, _ = supplied
    result = verify_custody(publication, trust, evidence)
    assert result["status"] == "PASS" and result["detection"] == "NOT DETECTED"
    assert result["crypto_valid"] is True
    assert result["real_custody_status"] == "INCONCLUSIVE"
    assert "not prevention" in result["scope"] and "receipt-freeness" in result["scope"]
    assert "totals" not in result


def test_separate_exports_and_identical_duplicate_are_idempotent(supplied):
    publication, trust, evidence, _ = supplied
    artifacts = [observer_export(evidence, observer) for observer in trust["required_observers"]]
    assert verify_custody(publication, trust, artifacts)["status"] == "PASS"
    assert verify_custody(publication, trust, artifacts + deepcopy(artifacts))["status"] == "PASS"


def test_disjoint_history_and_head_fragments_can_be_authenticated_together(supplied):
    publication, trust, evidence, _ = supplied
    histories_only = {"schema": evidence["schema"], "histories": evidence["histories"], "heads": {}}
    heads_only = {"schema": evidence["schema"], "histories": {}, "heads": evidence["heads"]}
    result = verify_custody(publication, trust, [histories_only, heads_only])
    assert result["status"] == "PASS" and result["errors"] == []


@pytest.mark.parametrize("condition", ["A", "B", "C"])
def test_operator_labels_never_authenticate_pins(supplied, condition):
    publication, _, evidence, _ = supplied
    publication["condition"] = condition
    result = verify_custody(publication, evidence=evidence)
    assert result["status"] == "INCONCLUSIVE" and result["crypto_valid"]
    assert result["real_custody_status"] == "INCONCLUSIVE"


@pytest.mark.parametrize("fault", ["absent", "anchor-absent", "identity-absent", "hash-malformed",
                                   "anchor-mismatch", "identity-mismatch", "schema", "key", "same-key",
                                   "boolean-policy", "custody-claim"])
def test_incomplete_or_unusable_pinsets_never_pass_or_claim_detected(supplied, fault):
    publication, trust, evidence, _ = supplied
    if fault == "absent":
        del trust["pins"]
    elif fault == "anchor-absent":
        del trust["pins"]["anchor_hash"]
    elif fault == "identity-absent":
        del trust["pins"]["identity_hashes"]["observer-2"]
    elif fault == "hash-malformed":
        trust["pins"]["anchor_hash"] = "not-a-hash"
    elif fault == "anchor-mismatch":
        trust["election_anchor"]["election_id"] = "substituted"
    elif fault == "identity-mismatch":
        trust["observer_identities"]["observer-1"]["public_key"] = public_key(new_key())
    elif fault == "schema":
        trust["schema"] = "operator-declared-trust/v1"
    elif fault == "key":
        trust["observer_identities"]["observer-1"]["public_key"] = "AA=="
        trust["pins"]["identity_hashes"]["observer-1"] = digest(trust["observer_identities"]["observer-1"])
    elif fault == "same-key":
        trust["observer_identities"]["observer-2"]["public_key"] = trust["observer_identities"]["observer-1"]["public_key"]
        trust["pins"]["identity_hashes"]["observer-2"] = digest(trust["observer_identities"]["observer-2"])
    elif fault == "boolean-policy":
        trust["required_observers"] = [True]
    elif fault == "custody-claim":
        trust["independent_custody"] = True
    result = verify_custody(publication, trust, evidence)
    assert result["status"] == result["detection"] == "INCONCLUSIVE"
    assert result["real_custody_status"] == "INCONCLUSIVE"


@pytest.mark.parametrize("evidence", [None, [], {"schema": "wrong", "histories": {}, "heads": {}},
                                      {"schema": "witness-001/retained/v1", "histories": {}, "heads": {}}])
def test_absent_or_unusable_required_evidence_is_inconclusive(supplied, evidence):
    publication, trust, _, _ = supplied
    result = verify_custody(publication, trust, evidence)
    assert result["status"] == "INCONCLUSIVE" and result["crypto_valid"] is True


@pytest.mark.parametrize("missing", ["histories", "heads", "both"])
def test_losing_one_required_observer_does_not_certify_completeness(supplied, missing):
    publication, trust, evidence, _ = supplied
    for field in ("histories", "heads") if missing == "both" else (missing,):
        del evidence[field]["observer-1"]
    assert verify_custody(publication, trust, evidence)["status"] == "INCONCLUSIVE"


def test_published_key_substitution_fails_against_complete_pins(supplied):
    publication, trust, evidence, _ = supplied
    publication["observer_keys"]["observer-1"] = public_key(new_key())
    result = verify_custody(publication, trust, evidence)
    assert result["status"] == "FAIL" and result["detection"] == "DETECTED"
    assert any("pinned verification keys" in item for item in result["evidence"])


def test_surviving_observer_detects_valid_archive_rewrite_with_missing_other_observer(supplied):
    publication, trust, evidence, _ = supplied
    publication["record"]["ballots"].reverse()
    publication["checkpoints"] = {}
    for field in ("histories", "heads"):
        evidence[field].pop("observer-1")
    result = verify_custody(publication, trust, evidence)
    assert result["status"] == "FAIL" and result["crypto_valid"] is True
    assert any("observer-2" in item for item in result["evidence"])


def test_invalid_signed_retained_statement_fails(supplied):
    publication, trust, evidence, _ = supplied
    evidence["histories"]["observer-1"][0]["payload"]["ballot_count"] = 1
    evidence["heads"]["observer-1"]["checkpoint_hash"] = digest(evidence["histories"]["observer-1"][0])
    result = verify_custody(publication, trust, evidence)
    assert result["status"] == "FAIL"
    assert any("signature" in item.lower() for item in result["errors"])


def test_existing_crypto_failure_is_preserved(supplied):
    publication, trust, evidence, _ = supplied
    publication["record"]["invalid"] = True
    result = verify_custody(publication, trust, evidence)
    assert result["status"] == "FAIL" and result["crypto_valid"] is False
    assert any("Existing election verification" in item for item in result["evidence"])


@pytest.mark.parametrize("where", ["published", "retained", "both"])
def test_authentic_closed_history_cannot_change_frozen_commitment(supplied, where):
    publication, trust, evidence, keys = supplied
    prior = deepcopy(publication["record"])
    prior["ballots"].reverse()
    for observer, key in keys.items():
        first = checkpoint(key, observer, publication["anchor"], prior)
        chain = [first, checkpoint(key, observer, publication["anchor"], publication["record"], 2, first)]
        if where in ("published", "both"):
            publication["checkpoints"][observer] = deepcopy(chain)
        else:
            publication["checkpoints"] = {}
        if where in ("retained", "both"):
            evidence["histories"][observer] = deepcopy(chain)
            evidence["heads"][observer] = {"sequence": 2, "checkpoint_hash": digest(chain[-1])}
        elif where == "published":
            # Current retained head agrees with the published refreshed head;
            # only the earlier authentic closed commitment exposes the fault.
            evidence["histories"][observer] = deepcopy(chain)
            evidence["heads"][observer] = {"sequence": 2, "checkpoint_hash": digest(chain[-1])}
    result = verify_custody(publication, trust, evidence)
    assert result["status"] == "FAIL"
    assert any("frozen sealed" in item for item in result["evidence"])


def test_current_head_variants_are_not_silently_overwritten(supplied):
    publication, trust, evidence, keys = supplied
    original = observer_export(evidence, "observer-1")
    refreshed = deepcopy(evidence)
    for observer, key in keys.items():
        chain = refreshed["histories"][observer]
        chain.append(checkpoint(key, observer, publication["anchor"], publication["record"], 2, chain[-1]))
        refreshed["heads"][observer] = {"sequence": 2, "checkpoint_hash": digest(chain[-1])}
    publication["checkpoints"] = deepcopy(refreshed["histories"])
    for order in ([original, refreshed], [refreshed, original]):
        result = verify_custody(publication, trust, order)
        assert result["status"] == "FAIL"
        assert any("not by itself proof of operator equivocation" in item for item in result["evidence"])


def test_absence_of_any_trustworthy_acknowledgment_cannot_reveal_suppression(supplied):
    publication, trust, evidence, _ = supplied
    # The fixture's entire observed election is internally consistent. A ballot
    # never observed by any actor has no representation in verifier inputs.
    result = verify_custody(publication, trust, evidence)
    assert result["status"] == "PASS" and "unobserved submissions" in result["scope"]


def test_unavailable_second_view_remains_inconclusive_under_two_observer_policy(supplied):
    publication, trust, evidence, _ = supplied
    only_first = observer_export(evidence, "observer-1")
    publication["checkpoints"].pop("observer-2")
    assert verify_custody(publication, trust, only_first)["status"] == "INCONCLUSIVE"
    trust["required_observers"] = ["observer-1"]
    weak = verify_custody(publication, trust, only_first)
    assert weak["status"] == "PASS" and "single-observer" in weak["scope"]


def test_offline_adapter_makes_no_network_calls(supplied, monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError("Offline adapter attempted a network connection")
    monkeypatch.setattr(socket.socket, "connect", no_network)
    publication, trust, evidence, _ = supplied
    assert verify_custody(publication, trust, evidence)["status"] == "PASS"


def test_offline_import_does_not_load_private_roles_or_server():
    process = subprocess.run([sys.executable, "-c",
        "import sys; import vote_lab.custody_verify; "
        "assert 'vote_lab.custody' not in sys.modules; "
        "assert 'vote_lab.model' not in sys.modules; "
        "assert 'vote_lab.server' not in sys.modules"], capture_output=True, text=True, timeout=30)
    assert process.returncode == 0, process.stdout + process.stderr


def test_validation_returns_only_existing_verifier_inputs(supplied):
    _, trust, _, _ = supplied
    normalized = validate_trust(trust)
    assert normalized["schema"] == "witness-001/trust/v1"
    assert set(normalized) == {"schema", "election_anchor", "observer_keys", "required_observers"}
    normalized["election_anchor"]["election_id"] = "caller-change"
    assert trust["election_anchor"]["election_id"] == "fictional-custody-unit"


def test_unsupported_direct_api_evidence_values_do_not_raise(supplied):
    publication, trust, evidence, _ = supplied
    corrupt = deepcopy(evidence)
    corrupt["heads"]["observer-1"] = {"recursive": None}
    corrupt["heads"]["observer-1"]["recursive"] = corrupt["heads"]["observer-1"]
    result = verify_custody(publication, trust, [corrupt, deepcopy(evidence)])
    assert result["status"] == "INCONCLUSIVE" and result["crypto_valid"] is True
    assert result["real_custody_status"] == "INCONCLUSIVE"
