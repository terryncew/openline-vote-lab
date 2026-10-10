"""Public verifier: imports no simulation keys and makes no server or network requests."""
from .crypto import verify_crypto
from .records import (capability_payload, check_signature, checkpoint_payload, digest,
                      receipt_payload, vote_payload)


def verify_record(record, anchor, checkpoint=None, receipts=None, *, require_checkpoint=True):
    checks, errors = [], []
    totals = None
    try:
        if anchor.get("schema") != "openline-vote-lab/anchor/v1" or anchor.get("mode") not in ("baseline", "receiver"):
            raise ValueError("Unsupported trusted anchor")
        if anchor["crypto"]["election_id"] != anchor["election_id"]:
            raise ValueError("Anchor and cryptographic election scope differ")
        roster = anchor["eligible_voters"]
        if len(roster) != 100 or len(set(roster.values())) != 100:
            raise ValueError("Expected 100 distinct synthetic voter keys")
        if set(record) != {"schema", "election_id", "anchor_hash", "ballots", "tally"}:
            raise ValueError("Unexpected public record fields")
        if record["schema"] != "openline-vote-lab/record/v1" or record["election_id"] != anchor["election_id"] or record["anchor_hash"] != digest(anchor):
            raise ValueError("Record does not match independently retained election anchor")
        entries = record["ballots"]
        if not isinstance(entries, list) or not 1 <= len(entries) <= 100:
            raise ValueError("Invalid counted ballot quantity")
        checks.append("Election scope and independent roster anchor match")
        voters, ballot_ids = set(), set()
        by_id = {}
        for index, accepted in enumerate(entries, 1):
            if set(accepted) != {"entry", "receipt"}:
                raise ValueError("Unexpected accepted ballot fields")
            entry = accepted["entry"]
            expected_fields = {"voter_id", "ballot_id", "ballot", "authorization"}
            if anchor["mode"] == "receiver":
                expected_fields.add("capability")
            if set(entry) != expected_fields:
                raise ValueError("Unexpected ballot entry fields")
            voter, ballot_id = entry["voter_id"], entry["ballot_id"]
            if voter not in roster:
                raise ValueError("Unauthorized voter is outside the independent roster")
            if voter in voters or ballot_id in ballot_ids:
                raise ValueError("Duplicate voter or ballot: only one counted vote is allowed")
            if ballot_id != entry["ballot"]["object_id"]:
                raise ValueError("Ballot identifier does not match its encrypted contents")
            check_signature(roster[voter], entry["authorization"],
                            vote_payload(anchor, voter, ballot_id, digest(entry["ballot"])))
            if anchor["mode"] == "receiver":
                check_signature(anchor["receiver_public_key"], entry["capability"], capability_payload(anchor, voter))
            check_signature(anchor["receiver_public_key"], accepted["receipt"], receipt_payload(anchor, entry, index))
            voters.add(voter)
            ballot_ids.add(ballot_id)
            by_id[ballot_id] = accepted
        checks.append("All voters are eligible; voter signatures, receipts and uniqueness pass")
        if anchor["mode"] == "receiver":
            checks.append("Optional receiver capabilities are valid and scoped to this election")
        if checkpoint is not None:
            check_signature(anchor["witness_public_key"], checkpoint, checkpoint_payload(anchor, record))
            checks.append("Independently retained witness checkpoint matches the complete archive")
        elif require_checkpoint:
            raise ValueError("Independent witness checkpoint is required to claim archive completeness")
        else:
            checks.append("ARCHIVE ONLY: completeness and deletion detection are not established")
        for receipt in receipts or []:
            payload = receipt["payload"]
            ballot_id = payload["ballot_id"]
            if ballot_id not in by_id or digest(by_id[ballot_id]["receipt"]) != digest(receipt):
                raise ValueError("A separately retained voter receipt is missing or changed")
            accepted = by_id[ballot_id]
            check_signature(anchor["receiver_public_key"], receipt,
                            receipt_payload(anchor, accepted["entry"], payload["sequence"]))
        if receipts:
            checks.append(f"{len(receipts)} separately retained voter receipts are included unchanged")
        totals = verify_crypto(anchor["crypto"], [v["entry"]["ballot"] for v in entries], record["tally"])
        checks.append("ElectionGuard ballot proofs, recomputed aggregate and trustee decryption proofs pass")
    except (ValueError, KeyError, TypeError, IndexError, AttributeError, OverflowError) as exc:
        errors.append(str(exc) or type(exc).__name__)
    return {"ok": not errors, "checks": checks, "errors": errors, "totals": totals,
            "completeness": not errors and checkpoint is not None}
