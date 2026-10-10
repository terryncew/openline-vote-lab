"""Adversarial checks against public ElectionGuard artifacts, without signing layers."""

from copy import deepcopy
import json

import pytest

from vote_lab.crypto import CHOICES, CONTEST, ElectionCrypto, verify_crypto


@pytest.fixture(scope="module")
def artifacts():
    crypto = ElectionCrypto("fictional-crypto-test")
    ballots = [crypto.encrypt(f"synthetic-ballot-{i}", CHOICES[i % 2]) for i in range(6)]
    return crypto.public_config(), ballots, crypto.tally(ballots)


def _increment(hex_value):
    return format(int(hex_value, 16) + 1, "02X")


def test_public_artifacts_verify_without_operator(artifacts):
    config, ballots, tally = artifacts
    # Only dictionaries are passed: neither ElectionCrypto nor keys are available.
    assert verify_crypto(config, ballots, tally) == {"garden": 3, "library": 3}


def test_export_does_not_reveal_choices_or_nonces(artifacts):
    config, ballots, tally = artifacts

    def inspect(value):
        if isinstance(value, dict):
            for key, child in value.items():
                assert key not in {"secret_key", "private_key", "plaintext", "answer", "vote"}
                if key == "nonce":
                    assert child is None
                inspect(child)
        elif isinstance(value, list):
            for child in value:
                inspect(child)

    inspect([config, ballots, tally])
    assert not any("choice" in ballot for ballot in ballots)
    # Same plaintext gets unrelated ciphertexts with fresh upstream randomness.
    assert ballots[0]["contests"][0]["ballot_selections"][0]["ciphertext"] != \
           ballots[2]["contests"][0]["ballot_selections"][0]["ciphertext"]
    json.dumps([config, ballots, tally])


@pytest.mark.parametrize("attack", ["selection-proof", "contest-proof", "constant", "ciphertext",
                                     "extra-contest", "unknown-style", "duplicate-selection", "placeholder",
                                     "nonce", "unsupported-metadata", "confirmation-code", "boolean-sequence",
                                     "boolean-limit", "boolean-timestamp", "integer-placeholder", "boolean-state"])
def test_malformed_or_altered_ballot_rejected(artifacts, attack):
    config, original, tally = artifacts
    ballots = deepcopy(original)
    ballot = ballots[0]
    contest = ballot["contests"][0]
    selection = contest["ballot_selections"][0]
    if attack == "selection-proof":
        selection["proof"]["proof_zero_response"] = _increment(selection["proof"]["proof_zero_response"])
    elif attack == "contest-proof":
        contest["proof"]["response"] = _increment(contest["proof"]["response"])
    elif attack == "constant":
        contest["proof"]["constant"] = 2
    elif attack == "ciphertext":
        selection["ciphertext"]["data"] = _increment(selection["ciphertext"]["data"])
    elif attack == "extra-contest":
        ballot["contests"].append(deepcopy(contest))
    elif attack == "unknown-style":
        ballot["style_id"] = "nonexistent-style"
    elif attack == "duplicate-selection":
        contest["ballot_selections"][1] = deepcopy(selection)
    elif attack == "placeholder":
        selection["is_placeholder_selection"] = True
    elif attack == "nonce":
        selection["nonce"] = "01"
    elif attack == "unsupported-metadata":
        contest["extended_data"] = {"pad": "01", "data": "plaintext injection", "mac": "00"}
    elif attack == "confirmation-code":
        ballot["code"] = _increment(ballot["code"])
    elif attack == "boolean-sequence":
        contest["sequence_order"] = True
    elif attack == "boolean-limit":
        contest["proof"]["constant"] = True
    elif attack == "boolean-timestamp":
        ballot["timestamp"] = True
    elif attack == "integer-placeholder":
        selection["is_placeholder_selection"] = 0
    elif attack == "boolean-state":
        ballot["state"] = True
    with pytest.raises(ValueError):
        verify_crypto(config, ballots, tally)


@pytest.mark.parametrize("attack", ["duplicate", "deleted", "inserted"])
def test_changed_ballot_collection_rejected(artifacts, attack):
    config, original, tally = artifacts
    ballots = deepcopy(original)
    if attack == "duplicate":
        ballots.append(deepcopy(ballots[0]))
    elif attack == "deleted":
        ballots.pop()
    else:
        new = ElectionCrypto("fictional-crypto-test")
        ballots.append(new.encrypt("not-in-original-election", "garden"))
    tampered = deepcopy(tally)
    tampered["ballot_count"] = len(ballots)
    with pytest.raises(ValueError):
        verify_crypto(config, ballots, tampered)


@pytest.mark.parametrize("attack", ["count", "decryption-proof", "missing-share", "duplicate-share",
                                     "share-key", "share-selection", "ciphertext-tally", "tally-boolean-sequence"])
def test_operator_cannot_publish_false_tally(artifacts, attack):
    config, ballots, original = artifacts
    tally = deepcopy(original)
    if attack == "count":
        tally["totals"]["garden"] += 1
        tally["totals"]["library"] -= 1
    elif attack == "decryption-proof":
        proof = tally["shares"][0]["contests"][CONTEST]["selections"]["garden"]["proof"]
        proof["response"] = _increment(proof["response"])
    elif attack == "missing-share":
        tally["shares"].pop()
    elif attack == "duplicate-share":
        tally["shares"][1] = deepcopy(tally["shares"][0])
    elif attack == "share-key":
        tally["shares"][0]["public_key"] = config["guardians"][1]["key"]
    elif attack == "share-selection":
        selection = tally["shares"][0]["contests"][CONTEST]["selections"]["garden"]
        selection["object_id"] = "library"
    elif attack == "ciphertext-tally":
        ciphertext = tally["ciphertext_tally"]["contests"][CONTEST]["selections"]["garden"]["ciphertext"]
        ciphertext["data"] = _increment(ciphertext["data"])
    elif attack == "tally-boolean-sequence":
        tally["ciphertext_tally"]["contests"][CONTEST]["sequence_order"] = True
    with pytest.raises(ValueError):
        verify_crypto(config, ballots, tally)


@pytest.mark.parametrize("attack", ["nonstandard-group", "manifest", "context-key", "guardian-key",
                                     "guardian-proof", "duplicate-guardian", "unknown-field"])
def test_election_configuration_is_bound_to_guardians_and_manifest(artifacts, attack):
    original, ballots, tally = artifacts
    config = deepcopy(original)
    if attack == "nonstandard-group":
        config["constants"]["generator"] = "02"
    elif attack == "manifest":
        config["manifest"]["contests"][0]["votes_allowed"] = 2
    elif attack == "context-key":
        config["context"]["elgamal_public_key"] = config["guardians"][0]["key"]
    elif attack == "guardian-key":
        config["guardians"][0]["key"] = "01"
    elif attack == "guardian-proof":
        proof = config["guardians"][0]["coefficient_proofs"][0]
        proof["response"] = _increment(proof["response"])
    elif attack == "duplicate-guardian":
        config["guardians"][1] = deepcopy(config["guardians"][0])
    else:
        config["context"]["ignored_attacker_field"] = "unexpected"
    with pytest.raises(ValueError):
        verify_crypto(config, ballots, tally)


def test_empty_tally_verifies():
    crypto = ElectionCrypto("fictional-empty-election")
    assert verify_crypto(crypto.public_config(), [], crypto.tally([])) == {"garden": 0, "library": 0}


def test_wrong_choice_is_rejected_before_encryption():
    crypto = ElectionCrypto("fictional-wrong-choice")
    with pytest.raises(ValueError):
        crypto.encrypt("synthetic-ballot", "real-world-candidate")
