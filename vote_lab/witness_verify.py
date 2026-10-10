"""WITNESS-001 offline evidence comparison; no simulator, secrets, or network.

Signatures authenticate statements under the supplied keys. Outside custody and
key authenticity are assumptions, not properties established by local files.
"""
from __future__ import annotations

import base64
from copy import deepcopy
from functools import lru_cache
import json
import re

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .records import canonical, check_signature, digest
from .verification import verify_record

OBSERVERS = frozenset(("observer-1", "observer-2"))
_CHECKPOINT_FIELDS = frozenset((
    "domain", "election_id", "anchor_hash", "observer_id", "sequence",
    "previous_checkpoint_hash", "phase", "record_hash", "ballot_count",
))
_SCOPE = ("Consistency of the supplied encrypted archive and observed history only. "
          "Detection is not prevention or recovery; unobserved submissions, hidden "
          "views, voter intent, and real-world independent custody are not established.")


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _fields(value, expected, name):
    _require(isinstance(value, dict) and set(value) == set(expected),
             f"Unexpected {name} fields")


def _hash(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _keys(value):
    _fields(value, OBSERVERS, "observer verification key")
    for key in value.values():
        _require(isinstance(key, str), "Observer verification keys must be Base64 strings")
        Ed25519PublicKey.from_public_bytes(base64.b64decode(key, validate=True))
    return value


def _histories(value, name):
    _require(isinstance(value, dict) and set(value) <= OBSERVERS,
             f"Unexpected {name} observer identifiers")
    return value


@lru_cache(maxsize=16)
def _cached_archive(record_bytes, anchor_bytes):
    """Recheck each exact byte pair once per process; never cache witness checks.

    Both inputs are complete canonical JSON bytes, including JSON types and
    every proof. No external verification assertion enters this cache. A fresh
    standalone process recomputes ElectionGuard verification with an empty
    cache. The bounded cache contains only public records/results, no keys.
    """
    return verify_record(json.loads(record_bytes), json.loads(anchor_bytes), require_checkpoint=False)


def _chain(history, observer, key, anchor):
    _require(isinstance(history, list) and 1 <= len(history) <= 100,
             "Observer history must contain between 1 and 100 checkpoints")
    previous = None
    for index, signed in enumerate(history, 1):
        _fields(signed, ("payload", "signature"), "signed checkpoint")
        payload = signed["payload"]
        _fields(payload, _CHECKPOINT_FIELDS, "checkpoint payload")
        _require(payload["domain"] == "witness-001/checkpoint/v1",
                 "Unsupported witness checkpoint domain")
        _require(canonical(payload["election_id"]) == canonical(anchor["election_id"])
                 and payload["anchor_hash"] == digest(anchor),
                 "Checkpoint election scope does not match the election anchor")
        _require(payload["observer_id"] == observer,
                 "Checkpoint observer identity does not match its pinned key")
        _require(type(payload["sequence"]) is int and payload["sequence"] == index,
                 "Checkpoint sequence is invalid, missing, duplicated, or reordered")
        _require(payload["previous_checkpoint_hash"] == previous,
                 "Checkpoint predecessor does not match the supplied signed history")
        _require(payload["phase"] in ("provisional", "closed"), "Unsupported checkpoint phase")
        _require(_hash(payload["record_hash"]), "Checkpoint record commitment is malformed")
        _require(type(payload["ballot_count"]) is int and 1 <= payload["ballot_count"] <= 100,
                 "Checkpoint ballot count must be an integer between 1 and 100")
        check_signature(key, signed, payload)
        previous = digest(signed)
    return history[-1]


def verify_witness(publication, trust=None, retained=None):
    """Check exported evidence without consulting an operator database or API.

    ``trust`` and ``retained`` must themselves come from authentic outside
    custody. The ``condition`` label never establishes that custody. Omitting
    both explicitly requests the weaker, operator-provided consistency check.
    """
    result = {"status": "INCONCLUSIVE", "crypto_valid": None, "checks": [],
              "evidence": [], "errors": [], "trustworthy_party": [], "scope": _SCOPE}
    checks, evidence, errors = result["checks"], result["evidence"], result["errors"]
    contradictions, missing = [], []
    try:
        _fields(publication, ("schema", "condition", "anchor", "record", "observer_keys", "checkpoints"),
                "publication")
        _require(publication["schema"] == "witness-001/publication/v1"
                 and publication["condition"] in ("A", "B", "C"), "Unsupported witness publication")
        published_keys = _keys(publication["observer_keys"])
        published_histories = _histories(publication["checkpoints"], "published history")
        supplied_anchor = publication["anchor"]
        independent = trust is not None
        if independent:
            _fields(trust, ("schema", "election_anchor", "observer_keys", "required_observers"), "trust anchor")
            _require(trust["schema"] == "witness-001/trust/v1", "Unsupported separate trust anchor")
            anchor = trust["election_anchor"]
            keys = _keys(trust["observer_keys"])
            required = trust["required_observers"]
            _require(isinstance(required, list) and 1 <= len(required) <= 2
                     and all(isinstance(item, str) for item in required)
                     and len(set(required)) == len(required) and set(required) <= OBSERVERS,
                     "Required observer policy must name distinct pinned observers")
            if canonical(supplied_anchor) != canonical(anchor):
                contradictions.append("Published election anchor differs from the separately retained anchor")
            if canonical(published_keys) != canonical(keys):
                contradictions.append("Published observer keys differ from separately pinned verification keys")
            checks.append("Separate election anchor and observer verification keys supplied")
            result["trustworthy_party"] = ["Authentic separately retained election anchor and verification keys",
                                             "At least one honest observer retaining the relevant observed history",
                                             "Correct verifier and reused ElectionGuard/cryptography implementations"]
        else:
            if retained is not None:
                missing.append("Separately pinned verification keys are missing; retained evidence cannot be authenticated")
            anchor, keys, required = supplied_anchor, published_keys, sorted(OBSERVERS)
            checks.append("Operator-provided keys and history: no outside authenticity or freshness established")
            result["trustworthy_party"] = ["Authentic election parameters for the interpreted election",
                                             "Correct verifier and reused ElectionGuard/cryptography implementations"]

        crypto = deepcopy(_cached_archive(canonical(publication["record"]), canonical(anchor)))
        result["crypto_valid"] = bool(crypto["ok"])
        if not crypto["ok"]:
            contradictions.extend("Existing election verification: " + error for error in crypto["errors"])
        else:
            checks.append("Existing verifier checked eligibility, signatures, ElectionGuard proofs and recomputed tally")
        record_hash = digest(publication["record"])
        ballot_count = len(publication["record"]["ballots"])
        published_heads = {}
        for observer, history in published_histories.items():
            head = _chain(history, observer, keys[observer], anchor)
            published_heads[observer] = head
            payload = head["payload"]
            if payload["phase"] != "closed":
                contradictions.append(f"Published head for {observer} does not attest to a closed archive")
            if payload["record_hash"] != record_hash or payload["ballot_count"] != ballot_count:
                contradictions.append(f"Signed published head for {observer} conflicts with the supplied archive")
        if published_heads:
            checks.append("Published checkpoint scopes, signatures, sequences and predecessor commitments checked")

        retained_heads = {}
        if independent and retained is None:
            missing.append("Independently retained observer histories and heads are missing")
        elif independent:
            _fields(retained, ("schema", "heads", "histories"), "retained evidence")
            _require(retained["schema"] == "witness-001/retained/v1", "Unsupported retained witness evidence")
            histories = _histories(retained["histories"], "retained history")
            heads = _histories(retained["heads"], "retained head")
            for observer in required:
                if observer not in histories or observer not in heads:
                    missing.append(f"Independently retained history/head for {observer} is missing")
                    continue
                declared_head = heads[observer]
                _fields(declared_head, ("sequence", "checkpoint_hash"), "retained head")
                _require(type(declared_head["sequence"]) is int and declared_head["sequence"] >= 1
                         and _hash(declared_head["checkpoint_hash"]), "Malformed retained head reference")
                head = _chain(histories[observer], observer, keys[observer], anchor)
                _require(head["payload"]["sequence"] == declared_head["sequence"]
                         and digest(head) == declared_head["checkpoint_hash"],
                         "Retained history disagrees with its separately retained head reference")
                retained_heads[observer] = head
                payload = head["payload"]
                if payload["phase"] != "closed":
                    missing.append(f"Retained head for {observer} does not cover a closed archive")
                elif payload["record_hash"] != record_hash or payload["ballot_count"] != ballot_count:
                    contradictions.append(f"Independently retained signed closed head for {observer} conflicts with the published archive")
                published_head = published_heads.get(observer)
                if published_head is not None and digest(published_head) != digest(head):
                    contradictions.append(f"Published checkpoint head for {observer} is not its independently retained head: rollback or conflicting history")
            if retained_heads:
                checks.append("Independently retained signed histories matched separately retained head references")
            closed_views = {(head["payload"]["record_hash"], head["payload"]["ballot_count"])
                            for head in retained_heads.values() if head["payload"]["phase"] == "closed"}
            if len(closed_views) > 1:
                contradictions.append("Authentic retained observer views conflict; signatures do not identify which observer is honest")

        evidence.extend(contradictions)
        errors.extend(contradictions)
        errors.extend(missing)
        if contradictions:
            result["status"] = "DETECTED"
        elif missing:
            result["status"] = "INCONCLUSIVE"
        else:
            result["status"] = "NOT DETECTED"
            checks.append("No contradiction in supplied evidence; this does not establish absence of an attack")
        if not independent:
            result["scope"] += " No independently retained evidence was used; archive completeness is unproved."
        elif result["status"] == "INCONCLUSIVE":
            result["scope"] += f" Required {len(required)}-observer evidence coverage is incomplete."
        else:
            result["scope"] += " Outside authenticity, honest observation and custody are assumed, not tested on this machine."
            if len(required) == 1:
                result["scope"] += " Explicit single-observer policy cannot expose an unavailable conflicting view."
    except (ValueError, KeyError, TypeError, IndexError, AttributeError, OverflowError, RecursionError) as exc:
        message = str(exc) or type(exc).__name__
        evidence.extend(item for item in contradictions if item not in evidence)
        errors.extend(item for item in contradictions if item not in errors)
        errors.append(message)
        evidence.append("Supplied artifact fails bounded schema, scope, chain or signature verification: " + message)
        result["status"] = "DETECTED"
    return result
