"""Standard Ed25519 signatures and SHA-256 commitments; no election cryptography here."""
import base64
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def public_key(key):
    return base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode("ascii")


def sign(key, payload):
    return {"payload": payload, "signature": base64.b64encode(key.sign(canonical(payload))).decode("ascii")}


def check_signature(key, signed, expected):
    if not isinstance(signed, dict) or set(signed) != {"payload", "signature"} or canonical(signed["payload"]) != canonical(expected):
        raise ValueError("Signed record has incorrect fields or scope")
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(key, validate=True)).verify(
            base64.b64decode(signed["signature"], validate=True), canonical(signed["payload"])
        )
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise ValueError("Ed25519 signature is invalid") from exc


def new_key():
    return Ed25519PrivateKey.generate()


def vote_payload(anchor, voter_id, ballot_id, ballot_hash):
    return {"domain": "openline-vote-lab/voter-authorization/v1", "election_id": anchor["election_id"],
            "anchor_hash": digest(anchor), "voter_id": voter_id, "ballot_id": ballot_id, "ballot_hash": ballot_hash}


def capability_payload(anchor, voter_id):
    return {"domain": "openline-vote-lab/receiver-capability/v1", "election_id": anchor["election_id"],
            "receiver_public_key": anchor["receiver_public_key"], "voter_id": voter_id,
            "voter_public_key": anchor["eligible_voters"][voter_id], "max_counted_ballots": 1}


def receipt_payload(anchor, entry, sequence):
    return {"domain": "openline-vote-lab/receipt/v1", "election_id": anchor["election_id"],
            "anchor_hash": digest(anchor), "voter_id": entry["voter_id"], "ballot_id": entry["ballot_id"],
            "ballot_hash": digest(entry["ballot"]), "entry_hash": digest(entry), "sequence": sequence}


def checkpoint_payload(anchor, record):
    return {"domain": "openline-vote-lab/witness-checkpoint/v1", "election_id": anchor["election_id"],
            "anchor_hash": digest(anchor), "record_hash": digest(record), "ballot_count": len(record["ballots"])}
