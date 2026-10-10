"""WITNESS-002 offline adapter; authentic pins and physical custody are inputs.

The existing ElectionGuard and WITNESS-001 verifiers remain unchanged.  A PASS
means supplied artifacts are internally consistent under a complete pinset; it
does not establish that any file or signing key was independently controlled.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import re

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .records import canonical, digest
from .witness_verify import verify_witness


OBSERVERS = frozenset(("observer-1", "observer-2"))
IDENTITY_SCHEMA = "witness-002/identity/v1"
TRUST_SCHEMA = "witness-002/trust/v1"
_SCOPE = (
    "PASS establishes consistency of supplied encrypted election evidence under "
    "the supplied pins only. Authentic external pins, independent observation, "
    "and independent custody are assumptions that this offline verifier cannot "
    "establish. Detection is not prevention or recovery; unobserved submissions, "
    "unavailable conflicting views, voter intent, and receipt-freeness remain unproved."
)


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _fields(value, expected, name):
    _require(isinstance(value, dict) and set(value) == set(expected),
             f"Unexpected {name} fields")


def _hash(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def validate_trust(trust):
    """Return the pinned WITNESS-001 adapter input, or reject an unusable pinset.

    These hashes detect substitutions only if the pinset itself was obtained
    authentically outside operator control. They do not authenticate themselves.
    Caller-supplied custody flags are deliberately not accepted.
    """
    _fields(trust, ("schema", "election_anchor", "observer_identities", "pins", "required_observers"),
            "WITNESS-002 trust")
    _require(trust["schema"] == TRUST_SCHEMA, "Unsupported WITNESS-002 trust schema")
    anchor = trust["election_anchor"]
    _require(isinstance(anchor, dict), "Pinned election anchor must be an object")
    identities, pins = trust["observer_identities"], trust["pins"]
    _fields(identities, OBSERVERS, "observer identity set")
    _fields(pins, ("anchor_hash", "identity_hashes"), "pinset")
    _fields(pins["identity_hashes"], OBSERVERS, "observer identity pins")
    _require(_hash(pins["anchor_hash"]), "Missing or malformed election anchor pin")
    _require(digest(anchor) == pins["anchor_hash"], "Election anchor does not match its supplied pin")
    keys = {}
    for observer in sorted(OBSERVERS):
        identity = identities[observer]
        _fields(identity, ("schema", "observer_id", "public_key"), "observer identity")
        _require(identity["schema"] == IDENTITY_SCHEMA and identity["observer_id"] == observer,
                 "Observer identity schema or identifier is invalid")
        pin = pins["identity_hashes"][observer]
        _require(_hash(pin), f"Missing or malformed identity pin for {observer}")
        _require(digest(identity) == pin, f"Observer identity for {observer} does not match its supplied pin")
        encoded = identity["public_key"]
        _require(isinstance(encoded, str), "Observer verification key must be a Base64 string")
        try:
            decoded = base64.b64decode(encoded, validate=True)
            Ed25519PublicKey.from_public_bytes(decoded)
        except (ValueError, TypeError) as exc:
            raise ValueError("Observer verification key is invalid") from exc
        _require(base64.b64encode(decoded).decode("ascii") == encoded,
                 "Observer verification key must use canonical Base64 encoding")
        keys[observer] = encoded
    _require(len(set(keys.values())) == 2, "The two pinned observers must use distinct verification keys")
    required = trust["required_observers"]
    _require(isinstance(required, list) and 1 <= len(required) <= 2
             and all(isinstance(observer, str) for observer in required)
             and len(set(required)) == len(required) and set(required) <= OBSERVERS,
             "Required observer policy must name distinct pinned observers")
    return {"schema": "witness-001/trust/v1", "election_anchor": deepcopy(anchor),
            "observer_keys": keys, "required_observers": list(required)}


def _result():
    return {"status": "INCONCLUSIVE", "detection": "INCONCLUSIVE", "crypto_valid": None,
            "real_custody_status": "INCONCLUSIVE", "checks": [], "evidence": [],
            "errors": [], "trustworthy_party": [], "scope": _SCOPE}


def _extend_unique(target, values):
    for value in values:
        if value not in target:
            target.append(value)


def _absorb(result, checked):
    for field in ("checks", "evidence", "errors", "trustworthy_party"):
        _extend_unique(result[field], checked[field])
    if checked["crypto_valid"] is not None:
        result["crypto_valid"] = checked["crypto_valid"]


def _retained_artifacts(evidence):
    if evidence is None:
        return []
    artifacts = evidence if isinstance(evidence, list) else [evidence]
    _require(len(artifacts) <= 16, "At most 16 retained evidence artifacts may be supplied")
    for artifact in artifacts:
        _fields(artifact, ("schema", "histories", "heads"), "retained evidence")
        _require(artifact["schema"] == "witness-001/retained/v1", "Unsupported retained evidence schema")
        for name in ("histories", "heads"):
            value = artifact[name]
            _require(isinstance(value, dict) and set(value) <= OBSERVERS,
                     f"Unexpected retained {name} observer identifiers")
    return artifacts


def _sealed_changes(artifact):
    """After existing signature/chain validation, freeze the first closed view."""
    changes = []
    for observer, history in artifact["histories"].items():
        closed = [(entry["payload"]["record_hash"], entry["payload"]["ballot_count"])
                  for entry in history if entry["payload"]["phase"] == "closed"]
        if len(set(closed)) > 1:
            changes.append(f"Authentic closed checkpoints for {observer} change the frozen sealed archive commitment")
    return changes


def _verify_custody(publication, trust=None, evidence=None):
    """Verify public export files offline, without consulting operator state.

    ``evidence`` accepts one CURRENT retained-state export or a list from
    separate observers, rather than an arbitrary bag of historical receipts.
    Identical duplicates are idempotent. Different declared current states are
    checked individually and cannot disappear through a last-write-wins merge.
    Mixing an old export with its ordinary refreshed successor is an input
    inconsistency; that failure alone is not proof of operator equivocation.
    A complete externally authenticated pinset is a necessary input to PASS.
    """
    result = _result()
    try:
        pinned = validate_trust(trust)
    except (ValueError, KeyError, TypeError, AttributeError, OverflowError, RecursionError) as exc:
        result["errors"].append("Authentic complete pins are unavailable: " + (str(exc) or type(exc).__name__))
        # Compute the weaker archive check when possible, but never promote an
        # operator-supplied key bundle into authenticated outside evidence.
        weak = verify_witness(publication)
        result["crypto_valid"] = weak["crypto_valid"]
        result["checks"].append("Operator-provided archive consistency was evaluated without an authenticated pinset")
        if weak["status"] == "DETECTED":
            result["errors"].extend("Untrusted-input check: " + error for error in weak["errors"])
        return result

    result["checks"].append("Supplied election anchor and both observer identities match their complete supplied pinset")
    try:
        artifacts = _retained_artifacts(evidence)
    except (ValueError, KeyError, TypeError, AttributeError, OverflowError, RecursionError) as exc:
        # Unreadable artifacts provide no authentic retained coverage. Preserve
        # any independently established publication failure under valid pins.
        checked = verify_witness(publication, pinned, None)
        _absorb(result, checked)
        result["errors"].append("Retained evidence is unavailable or malformed: " + (str(exc) or type(exc).__name__))
        if checked["status"] == "DETECTED":
            result.update(status="FAIL", detection="DETECTED")
        return result

    combined = {"schema": "witness-001/retained/v1", "histories": {}, "heads": {}}
    divergent = set()
    for artifact in artifacts:
        for name in ("histories", "heads"):
            for observer, value in artifact[name].items():
                if observer in combined[name] and canonical(combined[name][observer]) != canonical(value):
                    divergent.add(observer)
                elif observer not in combined[name]:
                    combined[name][observer] = deepcopy(value)

    checked = verify_witness(publication, pinned, combined if artifacts else None)
    _absorb(result, checked)
    failed = checked["status"] == "DETECTED"
    incomplete = checked["status"] == "INCONCLUSIVE"
    if not failed:
        changes = _sealed_changes({"histories": publication["checkpoints"]})
        if checked["status"] == "NOT DETECTED":
            changes += _sealed_changes(combined)
        _extend_unique(result["evidence"], changes)
        _extend_unique(result["errors"], changes)
        failed |= bool(changes)

    # Validate every supplied variant, so alternate signed states cannot be
    # overwritten by a later file with the same observer identifier.
    for artifact in artifacts:
        represented = set(artifact["histories"]) | set(artifact["heads"])
        if not represented:
            continue
        narrowed = deepcopy(pinned)
        narrowed["required_observers"] = sorted(represented)
        individual = verify_witness(publication, narrowed, artifact)
        # A head-only and history-only export can complete each other. Missing
        # fields in an individual fragment do not undo authenticated aggregate
        # coverage, which the combined check above already reports.
        if individual["status"] == "INCONCLUSIVE":
            _extend_unique(result["checks"], individual["checks"])
        else:
            _absorb(result, individual)
        failed |= individual["status"] == "DETECTED"
        if individual["status"] == "NOT DETECTED":
            changes = _sealed_changes(artifact)
            _extend_unique(result["evidence"], changes)
            _extend_unique(result["errors"], changes)
            failed |= bool(changes)

    if divergent:
        message = ("Supplied CURRENT retained-state exports declare different histories or heads for: "
                   + ", ".join(sorted(divergent))
                   + "; mixing historical and current exports is not by itself proof of operator equivocation")
        result["evidence"].append(message)
        result["errors"].append(message)
        failed = True
    if failed:
        result.update(status="FAIL", detection="DETECTED")
    elif incomplete:
        result.update(status="INCONCLUSIVE", detection="INCONCLUSIVE")
    else:
        result.update(status="PASS", detection="NOT DETECTED")
        result["checks"].append("No contradiction in supplied evidence; no conclusion about unavailable observations or independent custody")
    if len(pinned["required_observers"]) == 1:
        result["scope"] += " The explicit single-observer policy cannot expose an unavailable conflicting view."
    return result


def verify_custody(publication, trust=None, evidence=None):
    """Bounded offline adapter; see ``_verify_custody`` for evidence semantics.

    Unsupported Python values cannot enter through the bounded JSON CLI, but
    callers of this API still receive a result instead of an uncaught exception.
    Unreadable retained evidence is missing coverage. A separately established
    publication failure under valid pins remains FAIL.
    """
    try:
        return _verify_custody(publication, trust, evidence)
    except (ValueError, KeyError, TypeError, IndexError, AttributeError, OverflowError, RecursionError) as exc:
        result = _result()
        result["errors"].append("Retained evidence cannot be interpreted: " + (str(exc) or type(exc).__name__))
        try:
            pinned = validate_trust(trust)
        except (ValueError, KeyError, TypeError, AttributeError, OverflowError, RecursionError):
            result["errors"].append("Authentic complete pins are unavailable")
            return result
        checked = verify_witness(publication, pinned, None)
        _absorb(result, checked)
        if checked["status"] == "DETECTED":
            result.update(status="FAIL", detection="DETECTED")
        return result
