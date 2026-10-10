# Check the OpenLine Vote evidence yourself

The browser's result is delivered by the demo server. You can instead run the
preserved verifier locally against downloaded public files, without its database,
API, private keys or a network connection at verification time.

This checks a fictional election record. It does not certify an election or prove
the administrators were independent.

## Download and verify

After the fictional 100-ballot election is ready, open **Take the evidence with
you** and download the record, anchor, witness checkpoint and receipts. Keep
their filenames together in a separate folder. From a complete source checkout,
install the pinned dependencies once using the README instructions, then run:

```sh
.venv/bin/python -m vote_lab verify \
  --record /path/to/openline-vote-record.json \
  --anchor /path/to/openline-vote-anchor.json \
  --checkpoint /path/to/openline-vote-checkpoint.json \
  --receipts /path/to/openline-vote-receipts.json
```

Replace `/path/to/` with the download folder. Exit `0` means the supplied evidence
passed the implemented checks. Exit `1` means verification found a failure.
Argument errors exit `2`. An exit code is a result about those inputs, not about
the fairness or safety of a real election.

The narrow ElectionGuard adapter checks ballot validity proofs, ciphertext
aggregation and tally decryption evidence. The surrounding verifier also checks
the synthetic roster, signed ballot entries, one counted ballot per fake voter,
signed acceptance records, exact encrypted-ballot inclusion, and consistency
with the retained closed-record checkpoint.

Your receipt contains a fingerprint of an encrypted ballot and a signed
acknowledgment. It contains no fictional choice, decryption key or encryption
opening. Receipt-freeness and protection from vote buying remain unproved.

## The reference must survive outside the operator

Download and retain evidence before comparing it with a later publication. In a
genuine external test, authenticate the election anchor and witness key through
a channel the operator cannot substitute. A signature under a key supplied by
that same operator cannot establish independent historical custody.

The browser's witness runs under the same server authority. This is a modeled
comparison, not genuinely independent custody. WITNESS-002's actual custody
verdict remains INCONCLUSIVE, and shared-account isolation FAILED.

An original checkpoint can contradict a correctly recomputed smaller record.
Without a surviving historical reference, a valid subset may pass the explicitly
weaker check:

```sh
.venv/bin/python -m vote_lab verify \
  --record /path/to/openline-vote-record.json \
  --anchor /path/to/openline-vote-anchor.json --archive-only
```

Archive-only success reports `completeness: false`. It cannot distinguish an
unobserved suppressed ballot from an abstention. This is a negative control,
not a substitute for complete verification.

The browser does not export attack-subset records or totals. Comparing an
original plaintext total with a deleted-subset total can reveal the removed
choice. Use only synthetic data for adversarial experiments.

## What this cannot establish

The demo server sees the fake choice before encryption and holds every simulated
private key. The verifier cannot prove what the phone intended, detect every
submission suppressed before a trustworthy observation, remove coercion or vote
buying, force availability, or certify honest registration and independent
administrators. See `THREAT_MODEL.md`, `WITNESS-001.md` and `WITNESS-002.md`.

The prepared independently administered test is in
`WITNESS-002-EXTERNAL-TEST.md`. It has not been performed.
