"""WITNESS-002 synthetic operator role; no custody-observer private keys.

The existing Simulation owns synthetic voters, election guardians and the
operator receipt key. Its inherited legacy witness key is unused here. New
custody observers generate and retain their own keys in a separate role; this
module consumes only their exported public identities.

Process and path separation on one administrator-controlled host does not
establish real-world independent custody. No real or binding election is safe
to run with this research fixture.
"""
from __future__ import annotations

import argparse
import base64
from copy import deepcopy
import json
from pathlib import Path
import secrets
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .model import Simulation
from .records import digest, receipt_payload, sign, vote_payload


OBSERVERS = frozenset(("observer-1", "observer-2"))
SCENARIOS = {
    "honest": "Publish the original 100-ballot encrypted archive",
    "delete-accepted": "Delete an accepted ballot and recompute a valid 99-ballot tally",
    "alter-ballot": "Alter ciphertext-linked metadata without a valid voter signature",
    "replace-ballot": "Substitute valid ciphertext with an operator-forged voter signature",
    "rewrite-history": "Reorder authentic accepted ballots and re-sign operator receipts",
    "conflicting-histories": "Present different valid 100-ballot histories to observers",
    "forge-checkpoint": "Attempt to replace declared custody-observer verification keys",
    "replay-checkpoint": "Replay an authentic checkpoint in the wrong election scope",
    "rollback-checkpoint": "Publish an authentic older checkpoint for the same 100-ballot sealed archive",
    "suppression-before-observation": "Suppress a submission before trustworthy observation",
    "observer-lost": "Delete an accepted ballot after losing one observer",
    "observer-compromised": "Delete an accepted ballot after compromising one observer",
    "idempotent-replay": "Re-present an identical genuine checkpoint",
    "isolated-equivocation": "Keep one authentic conflicting view unseen",
    "observer-lost-honest": "Lose one observer without changing the archive",
    "all-observers-lost": "Lose all external evidence after deleting a ballot",
    "invalid-signature": "Present an invalid custody checkpoint signature",
}
_PREFIX_CASES = frozenset((
    "delete-accepted", "forge-checkpoint",
    "suppression-before-observation", "observer-lost", "observer-compromised",
    "all-observers-lost",
))
_PRIVACY_WARNING = (
    "SYNTHETIC PRIVATE ATTACK FIXTURE ONLY: this export includes both the "
    "100-ballot initial tally and a 99-ballot subset tally. Their difference "
    "reveals the removed fictional ballot's choice. Do not publish this pair "
    "as a receipt or feed; never use real data. Receipt-freeness is not established."
)


def _write_json(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def _read_json(path):
    # Reuse the existing bounded reader, including duplicate-field rejection.
    from .__main__ import read_json
    return read_json(path)


def _public_key(value):
    if not isinstance(value, str):
        raise ValueError("Custody identity must contain a public Ed25519 Base64 key")
    try:
        raw = base64.b64decode(value, validate=True)
        Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, TypeError) as exc:
        raise ValueError("Invalid public custody-observer verification key") from exc
    if base64.b64encode(raw).decode("ascii") != value:
        raise ValueError("Public custody-observer key encoding is not canonical")
    return value


def read_public_identity(path):
    """Read the public wrapper only; extra fields, including secrets, fail closed."""
    wrapper = _read_json(path)
    if not isinstance(wrapper, dict) or set(wrapper) != {"identity", "fingerprint"}:
        raise ValueError("Unexpected public identity wrapper fields")
    identity = wrapper["identity"]
    if not isinstance(identity, dict) or set(identity) != {"schema", "observer_id", "public_key"}:
        raise ValueError("Unexpected public identity descriptor fields")
    if identity["schema"] != "witness-002/identity/v1" or identity["observer_id"] not in OBSERVERS:
        raise ValueError("Unsupported public custody-observer identity")
    _public_key(identity["public_key"])
    if wrapper["fingerprint"] != digest(identity):
        raise ValueError("Public identity descriptor fingerprint mismatch")
    return deepcopy(identity)


def make_publication(anchor, record, observer_keys, checkpoints=None):
    """Assemble existing verifier input from exact archives and PUBLIC role keys.

    Self-consistency and a fingerprint do not authenticate a key's ownership.
    The verifier must use separately pinned identities and retained evidence.
    """
    if not isinstance(observer_keys, dict) or set(observer_keys) != OBSERVERS:
        raise ValueError("Publication requires both exported observer public identities")
    for key in observer_keys.values():
        _public_key(key)
    if len(set(observer_keys.values())) != 2:
        raise ValueError("Custody observers must have distinct public keys")
    if not isinstance(anchor, dict) or not isinstance(record, dict):
        raise ValueError("Election anchor and encrypted record must be JSON objects")
    histories = {} if checkpoints is None else checkpoints
    if not isinstance(histories, dict) or not set(histories) <= OBSERVERS:
        raise ValueError("Unexpected published checkpoint observer identifiers")
    return {"schema": "witness-001/publication/v1", "condition": "C",
            "anchor": deepcopy(anchor), "record": deepcopy(record),
            "observer_keys": deepcopy(observer_keys), "checkpoints": deepcopy(histories)}


class OperatorFixture:
    """One synthetic election; no new custody-observer key material is held here."""

    def __init__(self):
        self.sim = Simulation("baseline")
        for voter in self.sim.voter_keys:
            self.sim.cast(voter, secrets.choice(("garden", "library")))
        self.sim.seal()
        self.anchor = deepcopy(self.sim.anchor)
        self.original = deepcopy(self.sim.record)
        self.prefix = self.sim._record(self.sim.accepted[:-1])
        self.reordered = deepcopy(self.original)
        self.reordered["ballots"][0], self.reordered["ballots"][1] = (
            self.reordered["ballots"][1], self.reordered["ballots"][0])
        for index, accepted in enumerate(self.reordered["ballots"], 1):
            accepted["receipt"] = sign(
                self.sim.receiver_key, receipt_payload(self.anchor, accepted["entry"], index))
        # Commutative ElectionGuard aggregation is unchanged. This valid attack
        # does not expose an additional plaintext subset tally.
        self._prepared = {}

    def record_for(self, scenario):
        if scenario not in SCENARIOS:
            raise ValueError("Unknown WITNESS-002 operator scenario")
        if scenario in self._prepared:
            return deepcopy(self._prepared[scenario])
        record = deepcopy(self.original)
        if scenario in _PREFIX_CASES:
            record = deepcopy(self.prefix)
        elif scenario == "rewrite-history":
            record = deepcopy(self.reordered)
        elif scenario == "alter-ballot":
            record["ballots"][0]["entry"]["ballot"]["code"] = "00"
        elif scenario == "replace-ballot":
            entry = record["ballots"][0]["entry"]
            entry["ballot"] = self.sim.crypto.encrypt(entry["ballot_id"], "garden")
            entry["authorization"] = sign(
                self.sim.receiver_key,
                vote_payload(self.anchor, entry["voter_id"], entry["ballot_id"], digest(entry["ballot"])))
            record["ballots"][0]["receipt"] = sign(
                self.sim.receiver_key, receipt_payload(self.anchor, entry, 1))
        self._prepared[scenario] = deepcopy(record)
        return record

    def export(self, directory, *, scenario="rewrite-history"):
        target = Path(directory)
        if target.exists():
            raise ValueError("Use a new output directory; existing evidence is never overwritten")
        record = self.record_for(scenario)
        privacy = (_PRIVACY_WARNING if scenario in _PREFIX_CASES else
                   "Initial and selected records contain the same 100-ballot tally; "
                   "no adjacent subset plaintext tally pair is exported. Receipt-freeness is not established.")
        if scenario in _PREFIX_CASES:
            print(_PRIVACY_WARNING, file=sys.stderr)
        target.mkdir(parents=True)
        for name, value in (("anchor", self.anchor), ("initial-record", self.original),
                            ("selected-attack-record", record)):
            _write_json(target / (name + ".json"), value)
        _write_json(target / "scenario.json", {
            "schema": "witness-002/operator-fixture/v1", "experiment": "WITNESS-002",
            "synthetic_voters": 100, "selected_scenario": scenario,
            "description": SCENARIOS[scenario], "initial_record_hash": digest(self.original),
            "selected_record_hash": digest(record), "privacy": privacy,
            "custody": "Operator role has no new observer private keys; same-host roles do not establish independent custody",
            "external_api_spending_usd": 0,
        })


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(description="WITNESS-002 synthetic operator; local, fictional, nonbinding only")
    if arguments and arguments[0] == "publish":
        parser.add_argument("command", choices=["publish"])
        parser.add_argument("--anchor", required=True, type=Path)
        parser.add_argument("--record", required=True, type=Path)
        parser.add_argument("--identity-a", required=True, type=Path)
        parser.add_argument("--identity-b", required=True, type=Path)
        parser.add_argument("--checkpoints", type=Path)
        parser.add_argument("--out", required=True, type=Path)
        args = parser.parse_args(arguments)
        try:
            if args.out.exists():
                raise ValueError("Use a new output file; existing publication is never overwritten")
            identities = [read_public_identity(path) for path in (args.identity_a, args.identity_b)]
            keys = {identity["observer_id"]: identity["public_key"] for identity in identities}
            publication = make_publication(_read_json(args.anchor), _read_json(args.record), keys,
                                           _read_json(args.checkpoints) if args.checkpoints else None)
            args.out.parent.mkdir(parents=True, exist_ok=True)
            _write_json(args.out, publication)
            print(json.dumps({"publication": str(args.out), "record_hash": digest(publication["record"])}))
            return 0
        except (ValueError, OSError, TypeError) as exc:
            print(json.dumps({"ok": False, "errors": [str(exc)]}), file=sys.stderr)
            return 1
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--export-case", choices=SCENARIOS, default="rewrite-history")
    args = parser.parse_args(arguments)
    try:
        if args.out.exists():
            raise ValueError("Use a new output directory; existing evidence is never overwritten")
        print("WITNESS-002 operator fixture: 100 synthetic voters, no custody-observer keys, no paid services.", file=sys.stderr)
        OperatorFixture().export(args.out, scenario=args.export_case)
        print(json.dumps({"export": str(args.out), "selected_scenario": args.export_case}))
        return 0
    except (ValueError, OSError, TypeError) as exc:
        print(json.dumps({"ok": False, "errors": [str(exc)]}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
