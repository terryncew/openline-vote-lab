"""Witness process state, pins, key provenance and public-export boundaries.

These small tests isolate store behavior; the integration experiment separately
uses the real ElectionGuard verifier and 100 synthetic ballots.
"""
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
import json
import os
import stat

import pytest

import vote_lab.custody as custody
from vote_lab.records import canonical, digest


@pytest.fixture
def stores(tmp_path, monkeypatch):
    def check(record, anchor, **kwargs):
        good = record.get("verified") is True and record.get("anchor_hash") == digest(anchor)
        return {"ok": good, "errors": [] if good else ["Fixture invalid archive"]}

    monkeypatch.setattr(custody, "verify_record", check)
    anchor = {"schema": "openline-vote-lab/anchor/v1", "election_id": "fictional-core-test"}
    paths = {observer: tmp_path / observer for observer in ("observer-1", "observer-2")}
    public = {observer: custody.init_witness(path, observer) for observer, path in paths.items()}
    identities = {observer: item["identity"] for observer, item in public.items()}
    hashes = {observer: item["fingerprint"] for observer, item in public.items()}
    for path in paths.values():
        custody.pin_trust(path, anchor, identities, digest(anchor), hashes)
    record = {"verified": True, "anchor_hash": digest(anchor), "ballots": ["encrypted-fixture"],
              "tally": {"aggregate": "fixture-only"}}
    return paths, public, anchor, identities, hashes, record


def test_keys_generated_independently_in_private_stores(stores):
    paths, public, *_ = stores
    assert public["observer-1"]["identity"]["public_key"] != public["observer-2"]["identity"]["public_key"]
    assert paths["observer-1"].joinpath("signing-key.bin").read_bytes() != paths["observer-2"].joinpath("signing-key.bin").read_bytes()
    for observer, path in paths.items():
        assert stat.S_IMODE(path.stat().st_mode) == 0o700
        assert path.stat().st_uid == os.getuid()
        assert all(stat.S_IMODE(child.stat().st_mode) == 0o600 for child in path.iterdir())
        assert custody.public_identity(path) == public[observer]
        assert public[observer]["fingerprint"] == digest(public[observer]["identity"])


def test_initialize_never_overwrites_even_empty_directory(tmp_path):
    path = tmp_path / "existing"
    path.mkdir()
    with pytest.raises(FileExistsError):
        custody.init_witness(path, "observer-1")
    assert not list(path.iterdir())


def test_initialize_never_follows_store_symlink(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "alias"
    link.symlink_to(target)
    with pytest.raises(FileExistsError):
        custody.init_witness(link, "observer-1")
    assert not list(target.iterdir())


@pytest.mark.parametrize("target", ["directory", "signing-key.bin", "identity.json", "state.json", ".lock"])
def test_insecure_permissions_fail_closed(stores, target):
    path = stores[0]["observer-1"]
    os.chmod(path if target == "directory" else path / target, 0o755 if target == "directory" else 0o644)
    with pytest.raises(ValueError, match="mode 0[67]00"):
        custody.public_identity(path)


def test_private_key_symlink_is_rejected(stores):
    path = stores[0]["observer-1"]
    target = path.parent / "outside-seed"
    (path / "signing-key.bin").rename(target)
    (path / "signing-key.bin").symlink_to(target)
    with pytest.raises(OSError):
        custody.public_identity(path)


def test_hardlinked_private_key_is_rejected(stores):
    path = stores[0]["observer-1"]
    os.link(path / "signing-key.bin", path.parent / "copied-link")
    with pytest.raises(ValueError, match="one link"):
        custody.public_identity(path)


def test_wrong_fingerprint_never_replaces_pinned_state(stores):
    paths, _, anchor, identities, hashes, _ = stores
    path = paths["observer-1"]
    previous = (path / "state.json").read_bytes()
    with pytest.raises(ValueError):
        custody.pin_trust(path, anchor, identities, "0" * 64, hashes)
    assert (path / "state.json").read_bytes() == previous


def test_missing_fingerprint_does_not_allow_implicit_tofu(stores):
    paths, _, anchor, identities, hashes, _ = stores
    with pytest.raises(ValueError):
        custody.pin_trust(paths["observer-1"], anchor, identities, digest(anchor), {"observer-1": hashes["observer-1"]})


def test_election_and_observer_pins_cannot_be_replaced(stores):
    paths, _, anchor, identities, hashes, _ = stores
    changed = deepcopy(anchor)
    changed["election_id"] = "another-fictional-election"
    with pytest.raises(ValueError, match="cannot replace"):
        custody.pin_trust(paths["observer-1"], changed, identities, digest(changed), hashes)


def test_witness_own_identity_cannot_be_substituted(stores):
    paths, _, anchor, identities, hashes, _ = stores
    identities = deepcopy(identities)
    identities["observer-1"]["public_key"] = identities["observer-2"]["public_key"]
    hashes = {observer: digest(identity) for observer, identity in identities.items()}
    with pytest.raises(ValueError):
        custody.pin_trust(paths["observer-1"], anchor, identities, digest(anchor), hashes)


def test_pin_before_any_observation_required(tmp_path):
    path = tmp_path / "uninitialized-trust"
    custody.init_witness(path, "observer-1")
    with pytest.raises(ValueError, match="pin trust"):
        custody.observe(path, {"ballots": []})
    with pytest.raises(ValueError, match="pinned trust"):
        custody.export_evidence(path)


def test_exact_record_replay_does_not_advance_head(stores):
    paths, *_, record = stores
    path = paths["observer-1"]
    first = custody.observe(path, record)
    before = (path / "state.json").read_bytes()
    second = custody.observe(path, deepcopy(record))
    assert first["status"] == second["status"] == "PASS"
    assert first["checkpoint"] == second["checkpoint"]
    assert first["idempotent"] is False and second["idempotent"] is True
    assert (path / "state.json").read_bytes() == before


def test_concurrent_delivery_is_one_observation_not_duplicate_checkpoints(stores):
    paths, *_, record = stores
    path = paths["observer-1"]
    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda _: custody.observe(path, deepcopy(record)), range(16)))
    assert all(outcome["status"] == "PASS" for outcome in outcomes)
    assert sum(not outcome["idempotent"] for outcome in outcomes) == 1
    assert len(custody.export_evidence(path)["histories"]["observer-1"]) == 1


def test_explicit_refresh_advances_only_same_sealed_commitment(stores):
    paths, *_, record = stores
    path = paths["observer-1"]
    first = custody.observe(path, record)["checkpoint"]
    second = custody.observe(path, record, refresh=True)["checkpoint"]
    assert first["payload"]["sequence"] == 1 and second["payload"]["sequence"] == 2
    assert second["payload"]["previous_checkpoint_hash"] == digest(first)
    assert second["payload"]["record_hash"] == first["payload"]["record_hash"]
    assert custody.export_evidence(path)["heads"]["observer-1"]["checkpoint_hash"] == digest(second)


@pytest.mark.parametrize("refresh", [False, True])
def test_changed_valid_archive_is_never_signed_or_committed(stores, refresh):
    paths, *_, record = stores
    path = paths["observer-1"]
    custody.observe(path, record)
    previous = (path / "state.json").read_bytes()
    changed = deepcopy(record)
    changed["ballots"] = ["different-valid-fixture"]
    result = custody.observe(path, changed, refresh=refresh)
    assert result["status"] == "FAIL" and result["detection"] == "DETECTED"
    assert result["checkpoint"] is None
    assert (path / "state.json").read_bytes() == previous


def test_invalid_archive_is_never_signed(stores):
    paths, *_, record = stores
    record["verified"] = False
    result = custody.observe(paths["observer-1"], record)
    assert result["status"] == "FAIL" and result["checkpoint"] is None
    assert custody.export_evidence(paths["observer-1"])["heads"] == {}


def test_public_exports_never_contain_private_key_ballots_or_tallies(stores):
    paths, *_, record = stores
    path = paths["observer-1"]
    custody.observe(path, record)
    evidence = custody.export_evidence(path)
    encoded = canonical(evidence)
    assert set(evidence) == {"schema", "histories", "heads"}
    assert b'"ballots"' not in encoded and b'"tally"' not in encoded and b'"private_key"' not in encoded
    assert b"encrypted-fixture" not in encoded
    assert (path / "signing-key.bin").read_bytes() not in encoded
    assert set(custody.export_trust(path)) == {"schema", "election_anchor", "observer_identities", "pins", "required_observers"}


def test_retained_head_corruption_is_not_silently_repaired(stores):
    paths, *_, record = stores
    path = paths["observer-1"]
    custody.observe(path, record)
    state = json.loads((path / "state.json").read_bytes())
    state["head"]["checkpoint_hash"] = "0" * 64
    (path / "state.json").write_bytes(canonical(state))
    with pytest.raises(ValueError, match="head disagree"):
        custody.export_evidence(path)


def test_signed_history_corruption_is_not_silently_repaired(stores):
    paths, *_, record = stores
    path = paths["observer-1"]
    custody.observe(path, record)
    state = json.loads((path / "state.json").read_bytes())
    state["history"][0]["payload"]["record_hash"] = "0" * 64
    (path / "state.json").write_bytes(canonical(state))
    with pytest.raises(ValueError, match="signature"):
        custody.export_evidence(path)


def test_atomic_write_failure_preserves_existing_evidence(stores, monkeypatch):
    paths, *_, record = stores
    path = paths["observer-1"]
    custody.observe(path, record)
    before = (path / "state.json").read_bytes()
    original = os.replace
    def fail_state(source, destination, **kwargs):
        if destination == "state.json":
            raise OSError("Simulated replacement failure")
        return original(source, destination, **kwargs)
    monkeypatch.setattr(custody.os, "replace", fail_state)
    with pytest.raises(OSError, match="replacement failure"):
        custody.observe(path, record, refresh=True)
    assert (path / "state.json").read_bytes() == before
    assert set(p.name for p in path.iterdir()) == custody._FILES


def test_duplicate_store_json_fields_fail_closed(stores):
    path = stores[0]["observer-1"]
    (path / "state.json").write_bytes(b'{"schema":"witness-002/store/v1","schema":"other"}')
    with pytest.raises(ValueError, match="Duplicate"):
        custody.public_identity(path)
