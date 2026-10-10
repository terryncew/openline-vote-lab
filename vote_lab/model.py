"""Synthetic role simulation. All private keys share this process; never use real data."""
import copy
import secrets
import uuid

from .crypto import ElectionCrypto
from .records import (capability_payload, checkpoint_payload, digest, new_key, public_key,
                      receipt_payload, sign, vote_payload)
from .verification import verify_record

ATTACKS = {
    "duplicate": "Duplicate a previously counted encrypted ballot.",
    "unauthorized": "Insert a ballot under a fake identity outside the independently pinned roster.",
    "deleted": "Remove the last counted ballot from the published archive.",
    "modified": "Alter encrypted ballot data after the voter signs it.",
    "invalid-proof": "A stronger adversary replaces a proof and re-signs voter, operator and witness records; ElectionGuard proof verification still fails.",
    "operator-retally": "Remove a ballot, compute a valid smaller tally, and re-sign receipts; retained witness evidence exposes the omission.",
    "operator-forgery": "Substitute an otherwise valid encrypted ballot for an eligible voter; operator cannot sign as that voter.",
    "checkpoint-rewrite": "Operator signs a replacement witness checkpoint with the wrong key.",
}


class Simulation:
    def __init__(self, mode="baseline"):
        if mode not in ("baseline", "receiver"):
            raise ValueError("Unknown authorization mode")
        self.election_id = "fictional-commons-" + uuid.uuid4().hex
        self.crypto = ElectionCrypto(self.election_id)
        self.voter_keys = {f"voter-{i:03d}": new_key() for i in range(1, 101)}
        self.receiver_key, self.witness_key = new_key(), new_key()
        self.anchor = {"schema": "openline-vote-lab/anchor/v1", "election_id": self.election_id,
                       "mode": mode, "eligible_voters": {v: public_key(k) for v, k in self.voter_keys.items()},
                       "receiver_public_key": public_key(self.receiver_key), "witness_public_key": public_key(self.witness_key),
                       "crypto": self.crypto.public_config()}
        self.accepted = []
        self.voted = set()
        self.record = self.checkpoint = self.last_verification = None

    def cast(self, voter_id, choice):
        if not isinstance(voter_id, str) or not isinstance(choice, str):
            raise ValueError("Synthetic voter ID and choice must be strings")
        if self.record is not None:
            raise ValueError("Election is sealed; reset to start another fictional experiment")
        if voter_id not in self.voter_keys:
            raise ValueError("Only the 100 enrolled synthetic voters are eligible")
        if voter_id in self.voted:
            raise ValueError("This synthetic voter already has a counted ballot")
        if choice not in ("garden", "library"):
            raise ValueError("Choose one of the two fictional options")
        ballot_id = "ballot-" + uuid.uuid4().hex
        ballot = self.crypto.encrypt(ballot_id, choice)
        entry = {"voter_id": voter_id, "ballot_id": ballot_id, "ballot": ballot,
                 "authorization": sign(self.voter_keys[voter_id], vote_payload(self.anchor, voter_id, ballot_id, digest(ballot)))}
        if self.anchor["mode"] == "receiver":
            entry["capability"] = sign(self.receiver_key, capability_payload(self.anchor, voter_id))
        receipt = sign(self.receiver_key, receipt_payload(self.anchor, entry, len(self.accepted) + 1))
        self.accepted.append({"entry": entry, "receipt": receipt})
        self.voted.add(voter_id)
        return receipt

    def simulate(self):
        pending = [voter for voter in self.voter_keys if voter not in self.voted]
        garden_count = round(len(pending) * 0.6)
        choices = ["garden"] * garden_count + ["library"] * (len(pending) - garden_count)
        # Keep reproducible aggregate proportions, never a public identity-to-choice formula.
        secrets.SystemRandom().shuffle(choices)
        for voter, choice in zip(pending, choices):
            self.cast(voter, choice)

    def seal(self):
        if not self.accepted:
            raise ValueError("Cast at least one synthetic ballot before sealing")
        if self.record is not None:
            return
        self.record = self._record(self.accepted)
        self.checkpoint = sign(self.witness_key, checkpoint_payload(self.anchor, self.record))
        self.last_verification = self.verify()
        if not self.last_verification["ok"]:
            raise ValueError("Fresh election failed independent verification: " + "; ".join(self.last_verification["errors"]))

    def _record(self, accepted):
        return {"schema": "openline-vote-lab/record/v1", "election_id": self.election_id,
                "anchor_hash": digest(self.anchor), "ballots": copy.deepcopy(accepted),
                "tally": self.crypto.tally([a["entry"]["ballot"] for a in accepted])}

    def verify(self):
        if self.record is None:
            raise ValueError("Seal the fictional election first")
        return verify_record(self.record, self.anchor, self.checkpoint, self.receipts())

    def receipts(self):
        return [copy.deepcopy(a["receipt"]) for a in self.accepted]

    def inclusion(self, ballot_id, ballot_hash):
        entries = self.record["ballots"] if self.record else self.accepted
        included = any(a["entry"]["ballot_id"] == ballot_id and digest(a["entry"]["ballot"]) == ballot_hash for a in entries)
        return {"included": included, "explanation": "Exact encrypted ballot hash is present" if included else "No matching encrypted ballot is present"}

    def state(self):
        return {"election_id": self.election_id, "phase": "sealed" if self.record else "open",
                "mode": self.anchor["mode"], "cast_count": len(self.accepted), "eligible_count": 100,
                "voters": [{"id": v, "voted": v in self.voted} for v in self.voter_keys],
                "receipts": [{**a["receipt"]["payload"], "signed": a["receipt"]} for a in self.accepted],
                "totals": self.last_verification["totals"] if self.last_verification else None,
                "verification": self.last_verification}

    def attack(self, attack):
        if self.record is None:
            raise ValueError("Seal the fictional election before testing tampering")
        if not isinstance(attack, str) or attack not in ATTACKS:
            raise ValueError("Unknown tamper experiment")
        mutated, checkpoint = copy.deepcopy(self.record), copy.deepcopy(self.checkpoint)
        entries = mutated["ballots"]
        if attack == "duplicate":
            entries.append(copy.deepcopy(entries[0]))
        elif attack == "unauthorized":
            entries[0]["entry"]["voter_id"] = "outsider-999"
        elif attack == "deleted":
            entries.pop()
        elif attack == "modified":
            entries[0]["entry"]["ballot"]["code"] = "00"
        elif attack == "operator-retally":
            if len(entries) < 2:
                raise ValueError("Cast at least two ballots to demonstrate a valid subset tally")
            entries.pop()
            for index, accepted in enumerate(entries, 1):
                accepted["receipt"] = sign(self.receiver_key, receipt_payload(self.anchor, accepted["entry"], index))
            mutated = self._record(entries)
        elif attack == "operator-forgery":
            entry = entries[0]["entry"]
            entry["ballot"] = self.crypto.encrypt(entry["ballot_id"], "library")
            entry["authorization"] = sign(self.receiver_key, vote_payload(self.anchor, entry["voter_id"], entry["ballot_id"], digest(entry["ballot"])))
        elif attack == "invalid-proof":
            entry = entries[0]["entry"]
            self._damage_proof(entry["ballot"])
            # This explicit stronger adversary also gets a simulated voter and witness key;
            # valid wrapper signatures must not hide an invalid ElectionGuard proof.
            entry["authorization"] = sign(self.voter_keys[entry["voter_id"]], vote_payload(self.anchor, entry["voter_id"], entry["ballot_id"], digest(entry["ballot"])))
            entries[0]["receipt"] = sign(self.receiver_key, receipt_payload(self.anchor, entry, 1))
            checkpoint = sign(self.witness_key, checkpoint_payload(self.anchor, mutated))
        elif attack == "checkpoint-rewrite":
            checkpoint = sign(self.receiver_key, checkpoint_payload(self.anchor, mutated))
        result = verify_record(mutated, self.anchor, checkpoint)
        return {"attack": attack, **result, "detected": not result["ok"], "explanation": ATTACKS[attack]}

    @staticmethod
    def _damage_proof(ballot):
        for contest in ballot["contests"]:
            for selection in contest["ballot_selections"]:
                if selection.get("proof"):
                    selection["proof"]["proof_zero_response"] = "00"
                    return
        raise ValueError("Could not locate ElectionGuard proof")
