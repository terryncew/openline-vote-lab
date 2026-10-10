"""Independent review of WITNESS-002 apparatus, not external custody proof.

The fixture's roles share a UID and test process deliberately. Its assertions
exercise authentic evidence comparison and expose that local filesystem modes
cannot establish the separately administered custody required by the report.
"""
from copy import deepcopy
import json
from pathlib import Path
import socket
import subprocess
import sys

import pytest

from vote_lab.custody import (
    export_evidence,
    export_trust,
    init_witness,
    observe,
    pin_trust,
    public_identity,
)
from vote_lab.custody_verify import verify_custody
from vote_lab.model import Simulation
from vote_lab.records import canonical, digest, new_key, public_key, receipt_payload, sign


@pytest.fixture(scope="module")
def custody_fixture(tmp_path_factory):
    sim = Simulation()
    for number, choice in ((1, "garden"), (2, "library"), (3, "garden")):
        sim.cast(f"voter-{number:03d}", choice)
    sim.seal()
    stores = {observer: tmp_path_factory.mktemp(observer) / "custody"
              for observer in ("observer-1", "observer-2")}
    descriptors = {observer: init_witness(store, observer)["identity"]
                   for observer, store in stores.items()}
    pins = {observer: digest(identity) for observer, identity in descriptors.items()}
    for store in stores.values():
        pin_trust(store, sim.anchor, descriptors, digest(sim.anchor), pins)
        assert observe(store, sim.record)["status"] == "PASS"
        assert observe(store, sim.record, refresh=True)["status"] == "PASS"
    publication = {
        "schema": "witness-001/publication/v1", "condition": "C",
        "anchor": deepcopy(sim.anchor), "record": deepcopy(sim.record),
        "observer_keys": {observer: identity["public_key"]
                          for observer, identity in descriptors.items()},
        "checkpoints": {},
    }
    evidence = [export_evidence(store) for store in stores.values()]
    trust = export_trust(stores["observer-1"])
    return sim, stores, publication, trust, evidence


def unchanged(fixture):
    _, _, publication, trust, evidence = fixture
    return deepcopy(publication), deepcopy(trust), deepcopy(evidence)


def reordering(fixture):
    sim, _, publication, _, _ = fixture
    altered = deepcopy(publication)
    altered["record"]["ballots"].reverse()
    for sequence, accepted in enumerate(altered["record"]["ballots"], 1):
        accepted["receipt"] = sign(sim.receiver_key, receipt_payload(sim.anchor, accepted["entry"], sequence))
    return altered


def test_honest_cryptographic_comparison_never_attests_real_custody(custody_fixture):
    result = verify_custody(*unchanged(custody_fixture))
    assert result["status"] == "PASS" and result["crypto_valid"] is True
    assert result["detection"] == "NOT DETECTED"
    assert result["real_custody_status"] == "INCONCLUSIVE"
    assert "totals" not in result


def test_self_supplied_matching_pins_cannot_prove_out_of_band_authenticity(custody_fixture):
    publication, trust, evidence = unchanged(custody_fixture)
    keys = {observer: new_key() for observer in ("observer-1", "observer-2")}
    for observer, key in keys.items():
        identity = trust["observer_identities"][observer]
        identity["public_key"] = public_key(key)
        trust["pins"]["identity_hashes"][observer] = digest(identity)
        publication["observer_keys"][observer] = public_key(key)
    # An operator can issue an internally consistent *alternative* keyset.
    # The verifier cannot distinguish it from genuine pins supplied through an
    # authentic channel. External fingerprint comparison is therefore essential.
    for artifact in evidence:
        for observer, history in artifact["histories"].items():
            replaced = []
            for checkpoint in history:
                payload = deepcopy(checkpoint["payload"])
                payload["previous_checkpoint_hash"] = digest(replaced[-1]) if replaced else None
                replaced.append(sign(keys[observer], payload))
            artifact["histories"][observer] = replaced
            artifact["heads"][observer] = {
                "sequence": replaced[-1]["payload"]["sequence"],
                "checkpoint_hash": digest(replaced[-1]),
            }
    result = verify_custody(publication, trust, evidence)
    assert result["status"] == "PASS" and result["crypto_valid"] is True
    assert result["real_custody_status"] == "INCONCLUSIVE"


@pytest.mark.parametrize("condition", ["A", "B", "C"])
def test_operator_condition_label_cannot_replace_separate_trust(custody_fixture, condition):
    publication, _, evidence = unchanged(custody_fixture)
    publication["condition"] = condition
    result = verify_custody(publication, evidence=evidence)
    assert result["status"] == "INCONCLUSIVE"
    assert result["real_custody_status"] == "INCONCLUSIVE"


@pytest.mark.parametrize("mutation", ["anchor", "identity", "empty", "missing", "boolean-policy"])
def test_insufficient_or_inconsistent_key_pins_are_inconclusive(custody_fixture, mutation):
    publication, trust, evidence = unchanged(custody_fixture)
    if mutation == "anchor":
        trust["pins"]["anchor_hash"] = "0" * 64
    elif mutation == "identity":
        trust["observer_identities"]["observer-1"]["public_key"] = public_key(new_key())
    elif mutation == "empty":
        trust["pins"]["identity_hashes"] = {}
    elif mutation == "missing":
        trust.pop("pins")
    else:
        trust["required_observers"] = [True]
    result = verify_custody(publication, trust, evidence)
    assert result["status"] == "INCONCLUSIVE"
    assert result["real_custody_status"] == "INCONCLUSIVE"


def test_key_pins_alone_cannot_prove_a_current_history(custody_fixture):
    publication, trust, _ = unchanged(custody_fixture)
    result = verify_custody(publication, trust)
    assert result["status"] == "INCONCLUSIVE" and result["crypto_valid"] is True


def test_valid_reordered_archive_conflicts_with_retained_observations(custody_fixture):
    _, trust, evidence = unchanged(custody_fixture)
    result = verify_custody(reordering(custody_fixture), trust, evidence)
    assert result["status"] == "FAIL" and result["crypto_valid"] is True
    assert result["detection"] == "DETECTED"
    assert any("retained" in finding for finding in result["evidence"])


def test_valid_subset_is_detected_only_after_trustworthy_observation(custody_fixture):
    sim, _, _, _, _ = custody_fixture
    publication, trust, evidence = unchanged(custody_fixture)
    publication["record"] = sim._record(sim.accepted[:-1])
    result = verify_custody(publication, trust, evidence)
    assert result["status"] == "FAIL" and result["crypto_valid"] is True
    # WITNESS-002 refuses to turn omission of evidence into a completeness PASS.
    assert verify_custody(publication, trust)["status"] == "INCONCLUSIVE"


def test_one_missing_observer_cannot_certify_two_observer_coverage(custody_fixture):
    publication, trust, evidence = unchanged(custody_fixture)
    result = verify_custody(publication, trust, evidence[:1])
    assert result["status"] == "INCONCLUSIVE" and result["crypto_valid"] is True
    assert not result["evidence"]


def test_one_honest_retained_view_still_exposes_changed_history(custody_fixture):
    _, trust, evidence = unchanged(custody_fixture)
    result = verify_custody(reordering(custody_fixture), trust, evidence[:1])
    assert result["status"] == "FAIL" and result["crypto_valid"] is True


def test_checkpoint_rollback_needs_an_authentic_retained_later_head(custody_fixture):
    publication, trust, evidence = unchanged(custody_fixture)
    publication["checkpoints"] = {}
    older = deepcopy(evidence)
    for artifact in older:
        for observer, chain in artifact["histories"].items():
            artifact["histories"][observer] = chain[:1]
            artifact["heads"][observer] = {"sequence": 1, "checkpoint_hash": digest(chain[0])}
            publication["checkpoints"][observer] = chain[:1]
    assert verify_custody(publication, trust, older)["status"] == "PASS"
    result = verify_custody(publication, trust, evidence)
    assert result["status"] == "FAIL" and result["crypto_valid"] is True
    assert any("rollback" in finding for finding in result["evidence"])


def test_genuine_cross_election_checkpoint_replay_preserves_crypto_validity(custody_fixture):
    _, stores, _, _, _ = custody_fixture
    original_store_states = {observer: (store / "state.json").read_bytes()
                             for observer, store in stores.items()}
    publication, trust, evidence = unchanged(custody_fixture)
    second = Simulation()
    second.cast("voter-001", "garden")
    second.cast("voter-002", "library")
    second.seal()
    assert digest(second.anchor) != trust["pins"]["anchor_hash"]

    # The second election is a real, independently verified ElectionGuard
    # archive. Replayed statements below are the first election's genuine
    # witness signatures, not forged signatures on a manufactured wrong scope.
    publication["anchor"] = deepcopy(second.anchor)
    publication["record"] = deepcopy(second.record)
    publication["checkpoints"] = {
        observer: deepcopy(chain)
        for artifact in evidence for observer, chain in artifact["histories"].items()
    }
    trust["election_anchor"] = deepcopy(second.anchor)
    trust["pins"]["anchor_hash"] = digest(second.anchor)
    # This public, separately specified test scope leaves both witness stores,
    # their original pins, and their private keys unchanged.
    protected = verify_custody(publication, trust, evidence)
    assert protected["status"] == "FAIL" and protected["detection"] == "DETECTED"
    assert protected["crypto_valid"] is True
    assert protected["real_custody_status"] == "INCONCLUSIVE"
    assert any("scope" in finding.lower() for finding in protected["evidence"])

    without_retained = verify_custody(publication, trust)
    assert without_retained["status"] == "FAIL"
    assert without_retained["crypto_valid"] is True
    assert without_retained["real_custody_status"] == "INCONCLUSIVE"

    publication["checkpoints"] = {}
    without_any_statements = verify_custody(publication, trust)
    assert without_any_statements["status"] == "INCONCLUSIVE"
    assert without_any_statements["crypto_valid"] is True
    assert without_any_statements["real_custody_status"] == "INCONCLUSIVE"
    assert original_store_states == {observer: (store / "state.json").read_bytes()
                                     for observer, store in stores.items()}


def test_frozen_witness_cannot_sign_changed_valid_history(custody_fixture):
    _, stores, _, _, _ = custody_fixture
    store = stores["observer-1"]
    before = export_evidence(store)
    changed = reordering(custody_fixture)["record"]
    result = observe(store, changed, refresh=True)
    assert result["status"] == "FAIL" and result["checkpoint"] is None
    assert export_evidence(store) == before


def test_published_key_replacement_is_not_a_valid_identity_pin(custody_fixture):
    publication, trust, evidence = unchanged(custody_fixture)
    publication["observer_keys"]["observer-1"] = public_key(new_key())
    result = verify_custody(publication, trust, evidence)
    assert result["status"] == "FAIL" and result["crypto_valid"] is True
    assert any("pinned" in finding for finding in result["evidence"])


def test_exports_reveal_only_public_material_not_private_key(custody_fixture):
    _, stores, _, _, _ = custody_fixture
    for observer, store in stores.items():
        identity = public_identity(store)
        assert set(identity) == {"identity", "fingerprint"}
        assert identity["fingerprint"] == digest(identity["identity"])
        exported = json.dumps({"trust": export_trust(store), "evidence": export_evidence(store)})
        assert "private_key" not in exported and "signing-key" not in exported
        assert identity["identity"]["observer_id"] == observer
        allowed = {"domain", "election_id", "anchor_hash", "observer_id", "sequence",
                   "previous_checkpoint_hash", "phase", "record_hash", "ballot_count"}
        for chain in export_evidence(store)["histories"].values():
            for checkpoint in chain:
                assert set(checkpoint["payload"]) == allowed


def test_new_identity_generation_refuses_overwrite_and_symlink(tmp_path):
    store = tmp_path / "store"
    init_witness(store, "observer-1")
    existing = (store / "signing-key.bin").read_bytes()
    with pytest.raises((ValueError, FileExistsError, OSError)):
        init_witness(store, "observer-1")
    assert (store / "signing-key.bin").read_bytes() == existing
    alias = tmp_path / "alias"
    alias.symlink_to(store, target_is_directory=True)
    with pytest.raises((ValueError, FileExistsError, OSError)):
        init_witness(alias, "observer-1")


def test_local_same_uid_can_modify_a_0600_store_so_independence_is_unproved(tmp_path):
    store = tmp_path / "local-only"
    init_witness(store, "observer-1")
    state = store / "state.json"
    assert state.stat().st_mode & 0o777 == 0o600
    original = state.read_bytes()
    state.write_bytes(b"operator under same UID can rewrite this fixture\n")
    assert state.read_bytes() != original
    state.write_bytes(original)


def test_boolean_retained_head_is_not_accepted_as_integer_sequence(custody_fixture, tmp_path):
    sim, _, _, trust, _ = custody_fixture
    store = tmp_path / "corrupted-retained-head"
    own_identity = init_witness(store, "observer-1")["identity"]
    identities = deepcopy(trust["observer_identities"])
    identities["observer-1"] = own_identity
    pin_trust(store, sim.anchor, identities, digest(sim.anchor),
              {observer: digest(identity) for observer, identity in identities.items()})
    assert observe(store, sim.record)["status"] == "PASS"
    state_path = store / "state.json"
    state = json.loads(state_path.read_bytes())
    assert state["head"]["sequence"] == 1
    state["head"]["sequence"] = True
    state_path.write_bytes(canonical(state))
    with pytest.raises(ValueError):
        export_evidence(store)


def test_offline_verifier_makes_no_network_connection(custody_fixture, monkeypatch):
    def blocked_connection(*args, **kwargs):
        raise AssertionError("Offline verification attempted a network connection")
    monkeypatch.setattr(socket.socket, "connect", blocked_connection)
    assert verify_custody(*unchanged(custody_fixture))["status"] == "PASS"


def test_offline_verifier_imports_no_key_store_or_simulator():
    command = (
        "import sys; import vote_lab.custody_verify; "
        "assert 'vote_lab.custody' not in sys.modules; "
        "assert 'vote_lab.model' not in sys.modules; "
        "assert 'vote_lab.server' not in sys.modules"
    )
    process = subprocess.run([sys.executable, "-c", command], capture_output=True,
                             text=True, timeout=30)
    assert process.returncode == 0, process.stdout + process.stderr
