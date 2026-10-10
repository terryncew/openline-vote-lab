"""A small process-local witness store for WITNESS-002.

Each witness generates its own signing key inside its store. Filesystem checks
protect ordinary accidental exposure, not a malicious administrator, a shared
UID, or a compromised operating system. Running this on one machine does not
establish independent custody. No operator or coordinator key-generation API
is provided here.
"""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
import fcntl
import json
import os
from pathlib import Path
import secrets
import stat

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from .records import canonical, digest, public_key, sign
from .verification import verify_record
from .witness_verify import OBSERVERS, _chain

IDENTITY_SCHEMA = "witness-002/identity/v1"
TRUST_SCHEMA = "witness-002/trust/v1"
STATE_SCHEMA = "witness-002/store/v1"
_LIMIT = 16 * 1024 * 1024
_FILES = frozenset(("signing-key.bin", "identity.json", "state.json", ".lock"))


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _parse(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            _require(key not in result, "Duplicate fields in witness store")
            result[key] = value
        return result

    def nonfinite(value):
        raise ValueError("Non-finite JSON values are not permitted")

    return json.loads(data, object_pairs_hook=unique, parse_constant=nonfinite)


def _file_stat(fd, name):
    info = os.fstat(fd)
    _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
             f"Witness {name} must be a regular file with one link")
    _require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600,
             f"Witness {name} must be owned by this process user with mode 0600")
    return info


def _read(fd, name):
    child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
    try:
        info = _file_stat(child, name)
        _require(info.st_size <= _LIMIT, "Witness store file exceeds the size limit")
        pieces, total = [], 0
        while True:
            chunk = os.read(child, min(65536, _LIMIT + 1 - total))
            if not chunk:
                break
            pieces.append(chunk)
            total += len(chunk)
            _require(total <= _LIMIT, "Witness store file exceeds the size limit")
        return b"".join(pieces)
    finally:
        os.close(child)


def _write(fd, name, data):
    """Replace one state file atomically, keeping the directory open throughout."""
    temporary = ".pending-" + secrets.token_hex(16)
    child = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600, dir_fd=fd)
    try:
        os.fchmod(child, 0o600)
        with os.fdopen(child, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(child)
        os.replace(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        os.close(child)
        try:
            os.unlink(temporary, dir_fd=fd)
        except FileNotFoundError:
            pass


@contextmanager
def _store(store):
    fd = os.open(os.fspath(store), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    lock = None
    try:
        info = os.fstat(fd)
        _require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
                 "Witness store must be owned by this process user with mode 0700")
        lock = os.open(".lock", os.O_RDWR | os.O_NOFOLLOW, dir_fd=fd)
        _file_stat(lock, ".lock")
        fcntl.flock(lock, fcntl.LOCK_EX)
        _require(set(os.listdir(fd)) == _FILES,
                 "Witness store is incomplete or contains unexpected files")
        yield fd
    finally:
        if lock is not None:
            fcntl.flock(lock, fcntl.LOCK_UN)
            os.close(lock)
        os.close(fd)


def _load(fd):
    key_bytes = _read(fd, "signing-key.bin")
    _require(len(key_bytes) == 32, "Witness private key has an invalid length")
    key = Ed25519PrivateKey.from_private_bytes(key_bytes)
    identity = _parse(_read(fd, "identity.json"))
    _require(isinstance(identity, dict)
             and set(identity) == {"schema", "observer_id", "public_key"}
             and identity["schema"] == IDENTITY_SCHEMA
             and identity["observer_id"] in OBSERVERS,
             "Witness identity is malformed")
    _require(identity["public_key"] == public_key(key),
             "Witness identity does not match its locally generated private key")
    state = _parse(_read(fd, "state.json"))
    _require(isinstance(state, dict)
             and set(state) == {"schema", "observer_id", "identity_hash", "trust", "history", "head"}
             and state["schema"] == STATE_SCHEMA
             and state["observer_id"] == identity["observer_id"]
             and state["identity_hash"] == digest(identity),
             "Witness state does not match its identity")
    history, head = state["history"], state["head"]
    _require(isinstance(history, list) and len(history) <= 100,
             "Witness history is malformed or exceeds 100 checkpoints")
    if state["trust"] is None:
        _require(not history and head is None, "Unpinned witness cannot contain observations")
    else:
        from .custody_verify import validate_trust
        normalized = validate_trust(state["trust"])
        _require(normalized["observer_keys"][identity["observer_id"]] == identity["public_key"],
                 "Pinned observer identity differs from this witness's own generated key")
        if history:
            latest = _chain(history, identity["observer_id"], identity["public_key"],
                            normalized["election_anchor"])
            _require(isinstance(head, dict) and set(head) == {"sequence", "checkpoint_hash"}
                     and type(head["sequence"]) is int
                     and head == {"sequence": latest["payload"]["sequence"],
                                  "checkpoint_hash": digest(latest)},
                     "Witness history and locally retained head disagree")
            first = history[0]["payload"]
            _require(all(item["payload"]["phase"] == "closed"
                         and item["payload"]["record_hash"] == first["record_hash"]
                         and item["payload"]["ballot_count"] == first["ballot_count"]
                         for item in history),
                     "Witness signed history changes its frozen closed archive")
        else:
            _require(head is None, "Empty witness history cannot contain a head")
    return key, identity, state


def init_witness(store, observer_id):
    """Generate a witness-owned key in a fresh store; return public data only."""
    _require(observer_id in OBSERVERS, "Expected observer-1 or observer-2")
    path = Path(store)
    # mkdir is exclusive: even an existing empty directory is never reused.
    os.mkdir(path, 0o700)
    os.chmod(path, 0o700)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        key = Ed25519PrivateKey.generate()
        identity = {"schema": IDENTITY_SCHEMA, "observer_id": observer_id,
                    "public_key": public_key(key)}
        state = {"schema": STATE_SCHEMA, "observer_id": observer_id,
                 "identity_hash": digest(identity), "trust": None, "history": [], "head": None}
        _write(fd, "signing-key.bin", key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
        _write(fd, "identity.json", canonical(identity))
        _write(fd, "state.json", canonical(state))
        _write(fd, ".lock", b"")
    finally:
        os.close(fd)
    return {"identity": identity, "fingerprint": digest(identity)}


def public_identity(store):
    """Export a descriptor and its fingerprint, never the signing seed."""
    with _store(store) as fd:
        _, identity, _ = _load(fd)
        return {"identity": identity, "fingerprint": digest(identity)}


def pin_trust(store, anchor, identities, expected_anchor_hash, expected_identity_hashes,
              required_observers=None):
    """Pin explicitly compared fingerprints; no implicit trust-on-first-use.

    The supplied hashes must have been obtained over an authentic channel. This
    function verifies comparisons but cannot establish that channel's custody.
    """
    from .custody_verify import validate_trust
    trust = {"schema": TRUST_SCHEMA, "election_anchor": deepcopy(anchor),
             "observer_identities": deepcopy(identities),
             "pins": {"anchor_hash": expected_anchor_hash,
                      "identity_hashes": deepcopy(expected_identity_hashes)},
             "required_observers": sorted(OBSERVERS) if required_observers is None
             else deepcopy(required_observers)}
    normalized = validate_trust(trust)
    with _store(store) as fd:
        _, identity, state = _load(fd)
        _require(normalized["observer_keys"][identity["observer_id"]] == identity["public_key"],
                 "Pinned identity does not match this witness's own generated key")
        if state["trust"] is not None:
            _require(canonical(state["trust"]) == canonical(trust),
                     "An initialized witness cannot replace its pinned election or identities")
        else:
            state["trust"] = trust
            _write(fd, "state.json", canonical(state))
    return trust


def export_trust(store):
    """Export public pins and election parameters for offline comparison."""
    with _store(store) as fd:
        _, _, state = _load(fd)
        _require(state["trust"] is not None, "Witness has not pinned election and observer identities")
        return state["trust"]


def observe(store, record, *, refresh=False):
    """Verify and freeze a sealed archive; a rewrite is detected, never signed.

    An exact replay is idempotent. Explicit refresh signs a next checkpoint for
    the same frozen archive, allowing the experiment to test old-head rollback
    without exporting adjacent plaintext tally snapshots.
    """
    _require(type(refresh) is bool, "refresh must be a Boolean")
    with _store(store) as fd:
        key, identity, state = _load(fd)
        _require(state["trust"] is not None, "Witness must pin trust before observation")
        checked = verify_record(record, state["trust"]["election_anchor"], require_checkpoint=False)
        if not checked["ok"]:
            return {"status": "FAIL", "detection": "DETECTED", "checkpoint": None,
                    "idempotent": False, "errors": checked["errors"]}
        record_hash, count = digest(record), len(record["ballots"])
        if state["history"]:
            first = state["history"][0]["payload"]
            if first["record_hash"] != record_hash or first["ballot_count"] != count:
                return {"status": "FAIL", "detection": "DETECTED", "checkpoint": None,
                        "idempotent": False,
                        "errors": ["Verified archive differs from this witness's frozen closed commitment"]}
            if not refresh:
                return {"status": "PASS", "detection": "NOT DETECTED",
                        "checkpoint": deepcopy(state["history"][-1]), "idempotent": True, "errors": []}
        _require(len(state["history"]) < 100, "Witness checkpoint limit reached")
        anchor = state["trust"]["election_anchor"]
        payload = {"domain": "witness-001/checkpoint/v1", "election_id": anchor["election_id"],
                   "anchor_hash": digest(anchor), "observer_id": identity["observer_id"],
                   "sequence": len(state["history"]) + 1,
                   "previous_checkpoint_hash": state["head"]["checkpoint_hash"] if state["head"] else None,
                   "phase": "closed", "record_hash": record_hash, "ballot_count": count}
        checkpoint = sign(key, payload)
        state["history"].append(checkpoint)
        state["head"] = {"sequence": payload["sequence"], "checkpoint_hash": digest(checkpoint)}
        _write(fd, "state.json", canonical(state))
        return {"status": "PASS", "detection": "NOT DETECTED", "checkpoint": checkpoint,
                "idempotent": False, "errors": []}


def export_evidence(store):
    """Export only commitments/signatures/head references, never records or keys."""
    with _store(store) as fd:
        _, identity, state = _load(fd)
        _require(state["trust"] is not None, "Witness has not pinned trust")
        observer = identity["observer_id"]
        return {"schema": "witness-001/retained/v1",
                "histories": {observer: state["history"]} if state["history"] else {},
                "heads": {observer: state["head"]} if state["head"] else {}}
