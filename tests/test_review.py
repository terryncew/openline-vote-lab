"""Independent review regressions for exact signed-message byte handling."""

from copy import deepcopy

import pytest

from vote_lab.records import check_signature, new_key, public_key, sign


@pytest.mark.parametrize(
    "original, replacement",
    [
        ({"sequence": 1}, {"sequence": True}),
        ({"max_counted_ballots": 1}, {"max_counted_ballots": True}),
        ({"sequence": 0}, {"sequence": False}),
        ({"nested": [1, {"limit": 0}]}, {"nested": [True, {"limit": False}]}),
    ],
)
def test_signed_payload_type_substitution_is_rejected(original, replacement):
    """JSON booleans must never inherit signatures issued over JSON numbers."""
    key = new_key()
    signed = sign(key, original)
    check_signature(public_key(key), signed, original)

    changed = deepcopy(signed)
    changed["payload"] = replacement
    with pytest.raises(ValueError):
        check_signature(public_key(key), changed, original)


def test_signature_cannot_be_reused_for_a_different_scope():
    key = new_key()
    original = {"domain": "voter-authorization/v1", "election_id": "fictional-a"}
    changed_scope = {"domain": "voter-authorization/v1", "election_id": "fictional-b"}
    signed = sign(key, original)
    with pytest.raises(ValueError):
        check_signature(public_key(key), signed, changed_scope)
