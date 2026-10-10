"""Narrow ElectionGuard adapter for a fictional, local, two-choice experiment.

Encryption, ballot proofs, key proofs, homomorphic addition and decryption proofs
come from the pinned upstream ElectionGuard implementation. This module supplies
strict application-level bindings and a public verifier; it is not a new scheme.
Both simulated guardians live in one process: there is no operational separation
of trustees, and this does not protect plaintext from the local machine's owner.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from electionguard.ballot import (
    BallotBoxState,
    PlaintextBallot,
    PlaintextBallotContest,
    PlaintextBallotSelection,
    SubmittedBallot,
)
from electionguard.ballot_box import cast_ballot
from electionguard.ballot_code import get_ballot_code
from electionguard.constants import STANDARD_CONSTANTS, get_constants
from electionguard.decryption import compute_decryption_share
from electionguard.decryption_share import DecryptionShare
from electionguard.decrypt_with_shares import decrypt_tally
from electionguard.discrete_log import DiscreteLog
from electionguard.election import CiphertextElectionContext, make_ciphertext_election_context
from electionguard.encrypt import EncryptionDevice, EncryptionMediator
from electionguard.group import ONE_MOD_P
from electionguard.key_ceremony import (
    ElectionPublicKey,
    combine_election_public_keys,
    generate_election_key_pair,
)
from electionguard.manifest import (
    BallotStyle,
    Candidate,
    ContestDescription,
    ElectionType,
    GeopoliticalUnit,
    InternalManifest,
    Manifest,
    ReportingUnitType,
    SelectionDescription,
    SpecVersion,
    VoteVariationType,
)
from electionguard.serialize import from_raw, to_raw
from electionguard.tally import CiphertextTally, PublishedCiphertextTally


UPSTREAM_COMMIT = "a9753841f5082d1c35bdc1b053aade74778662b7"
CHOICES = ("garden", "library")
CONTEST = "fictional-community-project"
STYLE = "fictional-style"
GUARDIAN_IDS = ("simulated-guardian-1", "simulated-guardian-2")
MAX_BALLOTS = 100

# The reference library prints verbose cryptographic objects to stdout. Our
# adapter reports bounded errors itself so CLI JSON and local logs stay clean.
logging.getLogger("electionguard").disabled = True


class _SerialScheduler:
    """Use upstream's scheduler extension point without creating CPU-sized pools."""

    @staticmethod
    def schedule(task, arguments, with_shared_resources=False):
        return [task(*args) for args in arguments]


_SCHEDULER = _SerialScheduler()


def _json(value: Any) -> dict:
    return json.loads(to_raw(value))


def _encoded(value: Any) -> str:
    """Compare JSON types as well as values (Python treats True as equal to 1)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _read(cls, value: dict):
    _require(isinstance(value, dict), "Cryptographic object must be a JSON object")
    obj = from_raw(cls, json.dumps(value))
    # Dacite otherwise ignores unknown fields; public inputs must be exact.
    _require(_encoded(_json(obj)) == _encoded(value), "Unexpected or noncanonical cryptographic fields")
    return obj


def _manifest(election_id: str) -> Manifest:
    _require(isinstance(election_id, str) and 1 <= len(election_id) <= 100,
             "Invalid fictional election identifier")
    return Manifest(
        election_scope_id=election_id,
        spec_version=SpecVersion.EG0_95,
        type=ElectionType.other,
        start_date=datetime(2026, 1, 1, tzinfo=timezone.utc),
        end_date=datetime(2026, 1, 2, tzinfo=timezone.utc),
        geopolitical_units=[GeopoliticalUnit("fictional-district", "Fictional community", ReportingUnitType.other)],
        parties=[],
        candidates=[Candidate(choice) for choice in CHOICES],
        contests=[ContestDescription(
            object_id=CONTEST, sequence_order=1,
            electoral_district_id="fictional-district",
            vote_variation=VoteVariationType.one_of_m,
            number_elected=1, votes_allowed=1,
            name="Fictional community project",
            ballot_selections=[SelectionDescription(choice, i, choice) for i, choice in enumerate(CHOICES)],
        )],
        ballot_styles=[BallotStyle(STYLE, ["fictional-district"])],
    )


def _public_context(config: dict):
    _require(get_constants() == STANDARD_CONSTANTS, "ElectionGuard standard group required")
    _require(set(config) == {"schema", "implementation", "election_id", "constants", "manifest", "context", "guardians"},
             "Unexpected public configuration fields")
    _require(config["schema"] == "openline-eg-v1" and config["implementation"] == UPSTREAM_COMMIT,
             "Unsupported cryptographic configuration")
    _require(_encoded(config["constants"]) == _encoded(_json(STANDARD_CONSTANTS)), "Nonstandard cryptographic group")
    manifest = _read(Manifest, config["manifest"])
    _require(_encoded(_json(manifest)) == _encoded(_json(_manifest(config["election_id"]))) and manifest.is_valid(),
             "Manifest differs from the fixed fictional election")
    _require(isinstance(config["guardians"], list) and len(config["guardians"]) == 2,
             "Exactly two public guardians required")
    guardians = [_read(ElectionPublicKey, record) for record in config["guardians"]]
    for i, guardian in enumerate(guardians, 1):
        _require(guardian.owner_id == GUARDIAN_IDS[i - 1]
                 and type(guardian.sequence_order) is int and guardian.sequence_order == i,
                 "Unexpected or duplicate guardian identity")
        _require(len(guardian.coefficient_commitments) == 2 and len(guardian.coefficient_proofs) == 2,
                 "Invalid guardian polynomial commitments")
        _require(guardian.key != ONE_MOD_P and guardian.key.is_valid_residue()
                 and guardian.key == guardian.coefficient_commitments[0], "Invalid guardian public key")
        for commitment, proof in zip(guardian.coefficient_commitments, guardian.coefficient_proofs):
            _require(proof.public_key == commitment and proof.is_valid(), "Invalid guardian knowledge proof")
    joint = combine_election_public_keys(guardians)
    _require(joint.joint_public_key != ONE_MOD_P, "Invalid joint public key")
    context = _read(CiphertextElectionContext, config["context"])
    expected = make_ciphertext_election_context(2, 2, joint.joint_public_key, joint.commitment_hash, manifest.crypto_hash())
    _require(_encoded(_json(context)) == _encoded(_json(expected)),
             "Guardian keys, manifest and election context do not match")
    return manifest, InternalManifest(manifest), context, guardians


def _ballot(raw: dict, internal: InternalManifest, context: CiphertextElectionContext) -> SubmittedBallot:
    ballot = _read(SubmittedBallot, raw)
    _require(isinstance(ballot.object_id, str) and 1 <= len(ballot.object_id) <= 100,
             "Invalid ballot identifier")
    _require(ballot.state == BallotBoxState.CAST and ballot.style_id == STYLE and ballot.nonce is None,
             "Ballot must be cast, match the fixed style, and contain no nonce")
    _require(type(ballot.timestamp) is int and ballot.timestamp >= 0 and ballot.code_seed is not None,
             "Invalid ballot confirmation metadata")
    descriptions = internal.get_contests_for(STYLE)
    _require(len(ballot.contests) == len(descriptions), "Missing or extra ballot contests")
    for contest, description in zip(ballot.contests, descriptions):
        _require(contest.object_id == description.object_id
                 and type(contest.sequence_order) is int
                 and contest.sequence_order == description.sequence_order
                 and contest.description_hash == description.crypto_hash()
                 and contest.nonce is None and contest.extended_data is None,
                 "Ballot contest differs from manifest or carries unsupported metadata")
        expected_selections = description.ballot_selections + description.placeholder_selections
        _require(len(contest.ballot_selections) == len(expected_selections), "Missing or extra ballot selections")
        for selection, expected in zip(contest.ballot_selections, expected_selections):
            _require(selection.object_id == expected.object_id
                     and type(selection.sequence_order) is int
                     and selection.sequence_order == expected.sequence_order
                     and selection.description_hash == expected.crypto_hash()
                     and type(selection.is_placeholder_selection) is bool
                     and selection.is_placeholder_selection == (expected in description.placeholder_selections)
                     and selection.nonce is None, "Ballot selection differs from manifest")
        _require(contest.proof is not None and type(contest.proof.constant) is int
                 and contest.proof.constant == description.number_elected,
                 "Ballot contest proof uses the wrong vote limit")
    _require(ballot.is_valid_encryption(internal.manifest_hash, context.elgamal_public_key,
                                        context.crypto_extended_base_hash), "Invalid encrypted ballot or ballot proof")
    _require(ballot.code == get_ballot_code(ballot.code_seed, ballot.timestamp, ballot.crypto_hash),
             "Invalid ballot confirmation code")
    return ballot


def _aggregate(ballots: list[dict], internal: InternalManifest, context: CiphertextElectionContext) -> CiphertextTally:
    _require(isinstance(ballots, list) and len(ballots) <= MAX_BALLOTS, "At most 100 simulated ballots supported")
    tally = CiphertextTally("fictional-tally", internal, context)
    ids = set()
    for raw in ballots:
        ballot = _ballot(raw, internal, context)
        _require(ballot.object_id not in ids, "Duplicate encrypted ballot")
        ids.add(ballot.object_id)
        # Proofs were checked immediately above. No proof checks are bypassed.
        _require(tally.append(ballot, False, _SCHEDULER), "Ballot could not be accumulated")
    return tally


def _decrypt(tally: CiphertextTally, shares: list[dict], context: CiphertextElectionContext,
             guardians: list[ElectionPublicKey], manifest: Manifest) -> dict[str, int]:
    _require(isinstance(shares, list) and len(shares) == 2, "Exactly two guardian decryption shares required")
    keyed = {}
    for raw, guardian in zip(shares, guardians):
        share = _read(DecryptionShare, raw)
        _require(share.guardian_id == guardian.owner_id and share.public_key == guardian.key
                 and share.object_id == tally.object_id and set(share.contests) == {CONTEST},
                 "Decryption share does not match guardian or tally")
        contest = share.contests[CONTEST]
        _require(contest.object_id == CONTEST and contest.guardian_id == guardian.owner_id
                 and contest.description_hash == tally.contests[CONTEST].description_hash
                 and set(contest.selections) == set(CHOICES), "Invalid decryption contest structure")
        for selection_id, selection in contest.selections.items():
            _require(selection.object_id == selection_id and selection.guardian_id == guardian.owner_id
                     and selection.proof is not None and selection.recovered_parts is None,
                     "Invalid decryption selection structure")
        keyed[share.guardian_id] = share
    dlog = DiscreteLog()
    dlog.set_max_exponent(MAX_BALLOTS)
    dlog.precompute_cache(MAX_BALLOTS)
    dlog.set_lazy_evaluation(False)
    plaintext = decrypt_tally(tally, keyed, context.crypto_extended_base_hash, manifest)
    _require(plaintext is not None, "Invalid guardian decryption proof")
    totals = {choice: plaintext.contests[CONTEST].selections[choice].tally for choice in CHOICES}
    _require(all(type(value) is int and 0 <= value <= MAX_BALLOTS for value in totals.values()),
             "Invalid decrypted tally range")
    return totals


class ElectionCrypto:
    """Two simulated guardians. Private keys remain in this instance's memory."""

    def __init__(self, election_id: str):
        _require(get_constants() == STANDARD_CONSTANTS, "ElectionGuard standard group required")
        self._manifest = _manifest(election_id)
        _require(self._manifest.is_valid(), "Invalid fictional manifest")
        # 2-of-2 requires both original shares; no backup recovery is implemented.
        self._keys = [generate_election_key_pair(identity, i, 2) for i, identity in enumerate(GUARDIAN_IDS, 1)]
        self._guardians = [key.share() for key in self._keys]
        joint = combine_election_public_keys(self._guardians)
        self._internal = InternalManifest(self._manifest)
        self._context = make_ciphertext_election_context(2, 2, joint.joint_public_key,
                                                        joint.commitment_hash, self._manifest.crypto_hash())
        self._encrypter = EncryptionMediator(self._internal, self._context,
                                              EncryptionDevice(1, 1, 1, "Fictional local simulator"))
        self._config = {
            "schema": "openline-eg-v1", "implementation": UPSTREAM_COMMIT,
            "election_id": election_id, "constants": _json(STANDARD_CONSTANTS),
            "manifest": _json(self._manifest), "context": _json(self._context),
            "guardians": [_json(guardian) for guardian in self._guardians],
        }

    def public_config(self) -> dict:
        return json.loads(json.dumps(self._config))

    def encrypt(self, ballot_id: str, choice: str) -> dict:
        _require(choice in CHOICES, "Choose garden or library")
        _require(isinstance(ballot_id, str) and 1 <= len(ballot_id) <= 100, "Invalid ballot identifier")
        plaintext = PlaintextBallot(ballot_id, STYLE, [PlaintextBallotContest(
            CONTEST, [PlaintextBallotSelection(candidate, int(candidate == choice)) for candidate in CHOICES],
        )])
        encrypted = self._encrypter.encrypt(plaintext)
        _require(encrypted is not None, "ElectionGuard encryption failed")
        # The official CAST conversion removes ballot, contest and selection nonces.
        submitted = cast_ballot(encrypted)
        # No write-ins or encryption-error metadata in this fixed contest. That
        # optional field is not covered by public ballot validity proofs.
        for contest in submitted.contests:
            contest.extended_data = None
        return _json(submitted)

    def tally(self, ballots: list[dict]) -> dict:
        aggregate = _aggregate(ballots, self._internal, self._context)
        shares = []
        for key in self._keys:
            share = compute_decryption_share(key, aggregate, self._context, _SCHEDULER)
            _require(share is not None, "ElectionGuard decryption share failed")
            shares.append(_json(share))
        totals = _decrypt(aggregate, shares, self._context, self._guardians, self._manifest)
        _require(sum(totals.values()) == len(ballots), "Each counted ballot must select exactly one choice")
        return {"ciphertext_tally": _json(aggregate.publish()), "shares": shares,
                "totals": totals, "ballot_count": len(ballots)}


def verify_crypto(config: dict, ballots: list[dict], tally: dict) -> dict[str, int]:
    """Verify public artifacts alone; never accepts a secret key or operator service.

    Eligibility, signatures, roster anchoring and inclusion checkpoints are checked
    by the surrounding public record verifier, separately from this crypto layer.
    """
    try:
        manifest, internal, context, guardians = _public_context(config)
        _require(isinstance(tally, dict) and set(tally) == {"ciphertext_tally", "shares", "totals", "ballot_count"},
                 "Unexpected tally fields")
        _require(type(tally["ballot_count"]) is int and tally["ballot_count"] == len(ballots),
                 "Reported ballot count differs from public ballots")
        aggregate = _aggregate(ballots, internal, context)
        published = _read(PublishedCiphertextTally, tally["ciphertext_tally"])
        _require(_encoded(_json(published)) == _encoded(_json(aggregate.publish())),
                 "Published encrypted tally differs from ballot aggregation")
        totals = _decrypt(aggregate, tally["shares"], context, guardians, manifest)
        _require(isinstance(tally["totals"], dict) and set(tally["totals"]) == set(CHOICES)
                 and all(type(value) is int for value in tally["totals"].values())
                 and tally["totals"] == totals, "Reported plaintext tally differs from verified decryption")
        _require(sum(totals.values()) == len(ballots), "Each counted ballot must select exactly one choice")
        return totals
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("Malformed or invalid ElectionGuard artifact") from exc
