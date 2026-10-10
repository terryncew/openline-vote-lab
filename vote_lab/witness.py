"""WITNESS-001: matched, synthetic custody experiment, not a distributed service.

The coordinator can access every simulated private key. Condition C models
outside custody by restricting the attack adapter; directories on one machine
are NOT a real independent security boundary. ElectionGuard and the candidate's
voter/receipt verifier are reused unchanged. No new authorization scheme.
"""
from copy import deepcopy
import json
from pathlib import Path
import secrets

from .model import Simulation
from .records import canonical, digest, new_key, public_key, receipt_payload, sign, vote_payload
from .witness_verify import verify_witness

CONDITIONS = {
    "A": "All archive, key declarations and observer records are operator-controlled",
    "B": "Observer files are in a separate directory, still operator-controlled",
    "C": "Two observers model separately pinned keys and externally retained signed evidence",
}

ATTACKS = {
    "delete-accepted": "Delete an acknowledged ballot and compute a valid smaller tally",
    "alter-ballot": "Alter ciphertext-linked data without a valid voter signature",
    "replace-ballot": "Substitute a valid ciphertext with an operator-forged voter signature",
    "rewrite-history": "Reorder authentic accepted ballots and re-sign operator receipts",
    "conflicting-histories": "Present different valid 100-ballot histories to two observers",
    "forge-checkpoint": "Replace witness verification-key declarations and sign a rewritten checkpoint",
    "replay-checkpoint": "Replay a genuinely signed checkpoint from another election scope",
    "rollback-checkpoint": "Publish an authentic older signed revision and its valid 99-ballot tally",
    "suppression-before-observation": "Suppress the last submission before any acknowledgment or independent observation",
    "observer-lost": "Delete a ballot and lose one observer's retained history",
    "observer-compromised": "Delete a ballot and compromise one observer's key and retained history",
}

CONTROLS = {
    "honest": "Both retained histories agree with an unchanged archive",
    "idempotent-replay": "Re-present the same genuine checkpoint for the same state",
    "isolated-equivocation": "An observer sees only its own internally consistent fork",
    "observer-lost-honest": "Lose one observer's evidence with no archive alteration",
    "all-observers-lost": "No independently retained checkpoint remains available",
    "invalid-signature": "Ordinary malformed checkpoint signature, not a valid key replacement",
}


def checkpoint_payload(anchor, observer, record, sequence, previous=None, *, election_id=None):
    return {"domain": "witness-001/checkpoint/v1", "election_id": election_id or anchor["election_id"],
            "anchor_hash": digest(anchor), "observer_id": observer, "sequence": sequence,
            "previous_checkpoint_hash": digest(previous) if previous else None,
            "phase": "closed", "record_hash": digest(record), "ballot_count": len(record["ballots"])}


class WitnessExperiment:
    """Build one election/corpus; every condition receives the same attack record."""

    def __init__(self):
        self.sim = Simulation("baseline")
        # Unlike the baseline's fixed aggregate, do not make the hidden original
        # total inferable when exporting a selected deletion case.
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
            accepted["receipt"] = sign(self.sim.receiver_key, receipt_payload(self.anchor, accepted["entry"], index))
        # Commutative aggregation is identical. No alternate plaintext tally is
        # generated or disclosed for this stronger, valid history rewrite.
        self.observer_keys = {name: new_key() for name in ("observer-1", "observer-2")}
        self.operator_key = new_key()
        self.trust = {"schema": "witness-001/trust/v1", "election_anchor": self.anchor,
                      "observer_keys": {o: public_key(k) for o, k in self.observer_keys.items()},
                      "required_observers": list(self.observer_keys)}
        self._histories = {}
        for observer in self.observer_keys:
            first = self._sign(observer, self.prefix, 1)
            self._histories[observer] = [first, self._sign(observer, self.original, 2, first)]
        self._fork_histories = deepcopy(self._histories)
        self._fork_histories["observer-2"][-1] = self._sign(
            "observer-2", self.reordered, 2, self._fork_histories["observer-2"][0])
        # Genuine unrelated-election statements are issued as fixtures before
        # attack execution; replaying them needs no honest signing-key access.
        self._replay_histories = {
            observer: [self._sign(observer, self.original, 1,
                                  election_id="fictional-unrelated-election")]
            for observer in self.observer_keys
        }
        self._prepared = {}

    def _sign(self, observer, record, sequence, previous=None, *, key=None, election_id=None):
        return sign(key or self.observer_keys[observer],
                    checkpoint_payload(self.anchor, observer, record, sequence, previous, election_id=election_id))

    def _current_histories(self, record):
        histories = deepcopy(self._histories)
        for observer, history in histories.items():
            history[-1] = self._sign(observer, record, 2, history[0])
        return histories

    @staticmethod
    def _retained(histories):
        return {"schema": "witness-001/retained/v1", "histories": deepcopy(histories),
                "heads": {o: {"sequence": h[-1]["payload"]["sequence"], "checkpoint_hash": digest(h[-1])}
                          for o, h in histories.items()}}

    def _record_for(self, attack):
        # Construct once; exact ciphertexts/record bytes are shared across A/B/C.
        if attack in self._prepared:
            return deepcopy(self._prepared[attack])
        record = deepcopy(self.original)
        if attack in {"delete-accepted", "forge-checkpoint", "rollback-checkpoint", "suppression-before-observation",
                      "observer-lost", "observer-compromised", "all-observers-lost"}:
            record = deepcopy(self.prefix)
        elif attack == "rewrite-history":
            record = deepcopy(self.reordered)
        elif attack == "alter-ballot":
            record["ballots"][0]["entry"]["ballot"]["code"] = "00"
        elif attack == "replace-ballot":
            entry = record["ballots"][0]["entry"]
            entry["ballot"] = self.sim.crypto.encrypt(entry["ballot_id"], "garden")
            entry["authorization"] = sign(self.sim.receiver_key,
                vote_payload(self.anchor, entry["voter_id"], entry["ballot_id"], digest(entry["ballot"])))
            record["ballots"][0]["receipt"] = sign(self.sim.receiver_key, receipt_payload(self.anchor, entry, 1))
        self._prepared[attack] = deepcopy(record)
        return record

    def case(self, attack, condition):
        if attack not in ATTACKS and attack not in CONTROLS:
            raise ValueError("Unknown WITNESS-001 scenario")
        if condition not in CONDITIONS:
            raise ValueError("Unknown custody condition")
        record = self._record_for(attack)
        # The operator is allowed to mint witness statements only in A/B.
        # C starts from genuinely issued fixture statements; attack branches
        # may replay them, replace key declarations, or compromise ONE signer.
        advertised = self._current_histories(record) if condition != "C" else deepcopy(self._histories)
        independent = deepcopy(self._histories)
        trust = deepcopy(self.trust)
        keys = deepcopy(self.trust["observer_keys"])

        if condition == "C" and attack in {"delete-accepted", "rewrite-history", "observer-lost"}:
            # The operator can suppress old public statements, but cannot alter
            # an honest observer's externally retained copy or mint its key.
            advertised = {}

        if attack == "conflicting-histories":
            # Each observer has an authentic, individually consistent view.
            independent = deepcopy(self._fork_histories)
            if condition == "C":
                # Operator serves only a consistent first view; external second
                # evidence is essential. No second plaintext tally is exported.
                advertised = {"observer-1": deepcopy(independent["observer-1"])}
        elif attack == "forge-checkpoint":
            keys = {o: public_key(self.operator_key) for o in self.observer_keys}
            advertised = {}
            for observer in self.observer_keys:
                first = self._sign(observer, self.prefix, 1, key=self.operator_key)
                advertised[observer] = [first, self._sign(observer, record, 2, first, key=self.operator_key)]
        elif attack == "replay-checkpoint":
            advertised = deepcopy(self._replay_histories)
        elif attack == "rollback-checkpoint":
            advertised = {o: [deepcopy(h[0])] for o, h in self._histories.items()}
        elif attack == "suppression-before-observation":
            # Counterfactual branch: only99 were ever acknowledged/observed.
            # The coordinator's100-ballot fixture is not external evidence in
            # this branch and its last acceptance is never issued to an actor.
            advertised = self._current_histories(record)
            independent = deepcopy(advertised)
        elif attack in ("observer-lost", "observer-lost-honest"):
            advertised.pop("observer-1", None)
            independent.pop("observer-1")
        elif attack == "observer-compromised":
            # The compromised observer can replace its own private retained
            # state and sign a lie. It cannot change the other retained state.
            independent["observer-1"][-1] = self._sign("observer-1", record, 2, independent["observer-1"][0])
            if condition == "C":
                advertised = {"observer-1": deepcopy(independent["observer-1"])}
        elif attack == "isolated-equivocation":
            # Explicit weaker negativecontrol: only one observer's scope is
            # available, with no claim that an unseen second view agrees.
            independent = deepcopy(self._fork_histories)
            advertised = {"observer-1": deepcopy(independent["observer-1"])}
            independent = deepcopy(advertised)
            trust["required_observers"] = ["observer-1"]
            # Retain both setup keys so missing publication data is not confused
            # with accepting an operator-issued replacement verification key.
        elif attack == "all-observers-lost":
            independent = {}
            if condition == "C":
                advertised = {}
        elif attack == "invalid-signature":
            advertised["observer-1"][-1]["signature"] = "AAAA"
        publication = {"schema": "witness-001/publication/v1", "condition": condition,
                       "anchor": deepcopy(self.anchor), "record": record,
                       "observer_keys": keys, "checkpoints": advertised}
        if condition == "C":
            return publication, trust, self._retained(independent)
        return publication, None, None

    def run(self):
        results = []
        for scenario in [*ATTACKS, *CONTROLS]:
            for condition in CONDITIONS:
                publication, trust, retained = self.case(scenario, condition)
                result = verify_witness(publication, trust, retained)
                without = result if trust is None and retained is None else verify_witness(publication)
                archive_only = deepcopy(publication)
                archive_only["checkpoints"] = {}
                archive_result = verify_witness(archive_only)
                results.append({"scenario": scenario, "kind": "attack" if scenario in ATTACKS else "negative-control",
                                "condition": condition, "description": (ATTACKS | CONTROLS)[scenario],
                                "record_hash": digest(publication["record"]), **result,
                                "without_independent_evidence": without["status"],
                                "without_any_witness_statements": archive_result["status"],
                                "removing_evidence_changes_result": without["status"] != result["status"]})
        return {"experiment": "WITNESS-001", "schema": "witness-001/results/v1",
                "synthetic_voters": 100, "conditions": CONDITIONS, "results": results,
                "isolation": "Simulated custody on one machine; no genuine external operational independence",
                "privacy": "Commitment receipts contain no vote choices or openings; receipt-freeness is NOT established",
                "external_api_spending_usd": 0}

    def export(self, directory, *, scenario="rewrite-history", results=None):
        target = Path(directory)
        if target.exists():
            raise ValueError("Use a new output directory; existing evidence is never overwritten")
        if scenario not in ATTACKS and scenario not in CONTROLS:
            raise ValueError("Unknown export scenario")
        target.mkdir(parents=True)
        def write(path, value):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(value, indent=2) + "\n")
        # A/B folders explicitly remain inside the operator-controlled tree.
        # C folders model custody only. Exported files contain PUBLIC material,
        # never private role keys, individual plaintexts or encryption nonces.
        for condition in CONDITIONS:
            publication, trust, retained = self.case(scenario, condition)
            write(target / "operator" / condition / "publication.json", publication)
            if condition == "B":
                write(target / "operator" / "separate-observer-storage" / "observer-records.json",
                      {"keys": publication["observer_keys"], "histories": publication["checkpoints"]})
            if condition == "C":
                write(target / "observer-custody" / "pinned-trust.json", trust)
                write(target / "observer-custody" / "retained-evidence.json", retained)
                for observer, history in retained["histories"].items():
                    write(target / "observer-custody" / observer / "commitment-receipts.json", history)
        if results is not None:
            write(target / "results.json", results)
        write(target / "export-policy.json", {
            "experiment": "WITNESS-001", "selected_scenario": scenario,
            "same_attack_record_hash": digest(self._record_for(scenario)),
            "privacy": "One selected archive/tally only; no original/removed-prefix plaintext tally pair is exported",
            "custody": "All paths share one machine. C represents an assumption, not enforced independent custody",
            "scope": "Separate authentic copies and keys must be obtained outside the operator in a real review",
        })


def format_matrix(results):
    lines = ["WITNESS-001 — synthetic research, detection only", "scenario                         A             B             C"]
    for scenario in [*ATTACKS, *CONTROLS]:
        cells = [next(r["status"] for r in results["results"] if r["scenario"] == scenario and r["condition"] == c) for c in CONDITIONS]
        lines.append(f"{scenario:32} {cells[0]:13} {cells[1]:13} {cells[2]:13}")
    return "\n".join(lines)
