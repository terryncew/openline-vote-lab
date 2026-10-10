# OpenLine Vote Lab

**Experimental research · fictional elections · 100 synthetic voters · local only**

Can someone check an election result without reading individual ballots or taking the operator's word for the count? This small lab shows how established election cryptography and independently retained evidence can help—and where those guarantees stop.

This is a release candidate for open-source review, **not software for real elections**. It collects no real identities or ballots, connects to no government systems, uses no paid APIs, and has not been deployed publicly. All role keys and fake selections share one local simulator; confidentiality from that simulator is **not** demonstrated.

## WITNESS-002: independently runnable roles, external test pending

The current candidate is **0.1.2rc1**. **Actual independent custody: INCONCLUSIVE.** This session provides one shared user account and workspace, not separately administered observer machines. Local processes and protected directories do not change that boundary. No independent third party reproduced the experiment.

Each witness can now generate and retain its own signing key, explicitly pin authentic election and observer fingerprints, verify a sealed encrypted archive, retain signed commitments, and export public evidence for offline comparison. The operator role consumes public identities and never generates the new observer keys. Witnesses refuse to endorse a rewrite after their first sealed observation. Existing ElectionGuard verification is unchanged.

```sh
.venv/bin/python -m vote_lab.custody_experiment --out artifacts/witness-002-local
.venv/bin/python -m vote_lab.custody_cli verify \
  --publication artifacts/witness-002-local/offline/publication.json \
  --trust artifacts/witness-002-local/offline/pinned-trust.json \
  --evidence artifacts/witness-002-local/offline/witness-1-evidence.json \
  --evidence artifacts/witness-002-local/offline/witness-2-evidence.json
```

The local run uses 100 synthetic ballots and tests 20 cases. The default offline example detects a valid rewrite: artifact **FAIL**, detection **DETECTED**, exit `1`. Artifact `PASS` means supplied evidence is consistent under the supplied pins, never that administration is independent or an election is safe. Missing evidence or usable trust returns `INCONCLUSIVE`, exit `3`. All real-custody verdicts remain `INCONCLUSIVE`.

The complete regression suite passed **288 tests**, including the preserved 149-test candidate and 139 new checks. These are internal tests, not independent third-party reproduction.

The same-account negative control successfully rewrote witness state despite 0700/0600 permissions, so the local separation requirement **failed**. Deletion and compared forks were detectable with retained references, while suppression before observation and an unseen fork were not. Authentic fingerprints must be compared through a channel the operator cannot substitute; matching self-supplied hashes do not establish that channel.

Use the [human-operated cross-machine instructions](docs/WITNESS-002-EXTERNAL-TEST.md) for independently administered machines or accounts. Never transfer witness stores or private keys to the operator. The [WITNESS-002 report](docs/WITNESS-002.md) records actual results, owners and unknowns, failure cases, and pending external evidence. [Candidate validation](docs/WITNESS-002-RELEASE.md) describes tests and the local archive. No external deployment or publication is part of this candidate.

Witness exports contain commitments, not vote choices or openings. Privacy, coercion resistance, receipt-freeness, compromised devices, suppression and denial of service remain outside demonstrated guarantees. Comparing original and deleted-subset plaintext totals in a private synthetic attack can reveal the removed fake choice; never publish that pair or use real data.

## WITNESS-001: preserved custody experiment

The preserved candidate, **0.1.1rc1**, introduced WITNESS-001. The [0.1.0rc1 research findings](docs/RESEARCH.md) and [historical 84-test validation](docs/RELEASE_CANDIDATE.md) remain unchanged: receiver grants demonstrated no additional election-security guarantee, and deletion detection requires authentic evidence outside operator control. Neither witness experiment adds OpenLine authorization machinery.

WITNESS-001 result: A and B were indistinguishable. C exposed seven valid archive/history attacks that A/B missed; removing independent evidence removed those detections. Suppression before any trustworthy acknowledgment or observation remained undetected. Its preserved regression suite passed all **149 tests**.

Run one synthetic election against matched attacks with (A) all records operator-owned, (B) separate observer directories still operator-owned, and (C) modeled outside custody with separately pinned observer keys and retained signed histories:

```sh
.venv/bin/python -m vote_lab witness-demo --out artifacts/witness-001
.venv/bin/python -m vote_lab witness-verify \
  --publication artifacts/witness-001/operator/C/publication.json \
  --trust artifacts/witness-001/observer-custody/pinned-trust.json \
  --retained artifacts/witness-001/observer-custody/retained-evidence.json
```

The default export contains a valid rewritten 100-ballot history. Its C verification is expected to return `DETECTED` (exit `1`), while A/B checks without external evidence return `NOT DETECTED` (exit `0`). Missing required evidence can return `INCONCLUSIVE` (exit `3`). None of these labels means prevention; `NOT DETECTED` does not establish that no attack occurred. `results.json` records every attack's evidence, trusted parties, and evidence-removal controls.

Only one selected archive/tally is exported, with commitment-only witness receipts. No original/prefix plaintext tally pair is exported, and the WITNESS election uses unpredictable synthetic totals. Keep separate exports of one election out of a public feed: comparing before/after plaintext totals can reveal a removed choice. Receipts contain no choices, individual voter identifiers, or encryption openings; **receipt-freeness and protection from vote buying remain unproven**.

All roles still share one machine. The C folders represent assumed outside custody, not genuine isolation. The offline verifier imports no server/simulator, needs no database or API, and reuses the existing election verification. It memoizes results only for identical canonical record and election-anchor bytes within a process; every new input and every checkpoint/signature/reference comparison is checked.

See the [WITNESS-001 report](docs/WITNESS-001.md) and [current candidate validation](docs/WITNESS-001-RELEASE.md) for the actual outcomes and reproducible archive instructions. This remains **experimental infrastructure, not certified election software**.

## Try the local demonstration

Requirements: Python **3.12**, Git, and network access for the initial free dependency download. Runtime and verification work offline. Linux x86-64 was tested; other platforms have not been validated.

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python -m vote_lab serve
```

Open the loopback address printed by the command in a browser **on the same local machine**. The server binds to `127.0.0.1:8000`, with no public listener, authentication service, analytics, CDN, external fonts, or paid service. It is an in-memory experiment; stopping or resetting discards the synthetic election. Save exports you want to retain first.

[Desktop demonstration](docs/screenshots/desktop.png) · [Mobile demonstration](docs/screenshots/mobile.png)

1. Cast a ballot as one of the 100 fake identities. A second accepted ballot from that identity is rejected.
2. Save and check the receipt: its hash identifies the encrypted ballot without containing a choice.
3. Complete the 100-voter simulation and close the election. Two simulated guardians disclose only the aggregate through the normal workflow.
4. Run verification, then try duplicate, unauthorized, deleted, modified, invalid-proof, and dishonest-operator records. Attacks mutate copies; the reference record stays intact.
5. Export the public record, trust anchor, witness checkpoint, and receipts. Verify outside the browser.

Each fresh automated 100-voter run assigns 60 garden and 40 library choices randomly across the fake identities. Manual choices can change that total. Ciphertexts, keys, and hashes vary across runs; tests check invariants rather than require identical cryptographic output.

## Generate and verify public evidence

```sh
.venv/bin/python -m vote_lab demo --out artifacts/baseline --adversarial
.venv/bin/python -m vote_lab verify \
  --record artifacts/baseline/record.json \
  --anchor artifacts/baseline/anchor.json \
  --checkpoint artifacts/baseline/checkpoint.json \
  --receipts artifacts/baseline/receipts.json

# Compare the optional receiver-authorization model with the same attacks.
.venv/bin/python -m vote_lab demo --mode receiver --out artifacts/receiver --adversarial
```

The standalone verifier does not need the server, private keys, a database, or network access. It returns JSON and exits `0` for accepted evidence or `1` for verification failure. Invalid command arguments exit `2`. Existing output files are preserved; use a fresh `--out` directory for another run.

**Obtain the anchor authentically before trusting the archive, and retain the checkpoint or receipts independently.** Downloading all files from a dishonest operator after an attack does not establish an honest history. In this simulator, distinct artifacts model independent evidence; all keys are colocated, so actual authority separation is absent.

The explicit `--archive-only` option allows tally verification without a checkpoint. Its result has `completeness: false`. A correctly retallied subset can pass this weaker check: encryption cannot tell an omitted accepted ballot from an abstention without external evidence. Receipts can independently expose acknowledged ballots that disappear.

| Artifact | What it supplies | What it does not supply |
| --- | --- | --- |
| `anchor.json` | Frozen fictional manifest, public guardian/roster/receiver/witness keys and mode | Self-authenticating eligibility or honest registration |
| `record.json` | Signed encrypted ballots, proofs, encrypted aggregate, guardian shares and claimed totals | Proof of voter intent or completeness on its own |
| `checkpoint.json` | Witness signature committing to the exact closed archive and count | Real independent witness operation in this simulator |
| `receipts.json` | Separately retained signed acceptance references | Receipt-freeness, coercion resistance, or forced publication |
| `attacks.json` | Results of the eight CLI tamper experiments | A universal security proof |

## What the verifier checks

ElectionGuard supplies encryption, ballot validity proofs, public guardian-key proofs, homomorphic aggregation, and tally decryption proofs. The wrapper uses its standard group and checks the exact fixed manifest, selection structure, unique ballot IDs, absence of nonces/unproved metadata, and both guardian shares. It recomputes the encrypted aggregate, verifies decryption evidence, and compares the result with reported totals; it does not accept the operator's numbers as truth.

The surrounding verifier checks the frozen roster, voter Ed25519 signatures scoped to the election and ciphertext, one counted ballot per identity, operator receipts, and retained witness evidence. It rejects unsupported fields, ambiguous JSON input, and several malformed proof/record cases. It is deliberately limited to this fixed two-choice, at-most-100-ballot format, not a general ElectionGuard conformance verifier.

The maintained ElectionGuard Python source is pinned to commit `a9753841f5082d1c35bdc1b053aade74778662b7` rather than the older PyPI release with the same version number. This reference implementation targets ElectionGuard specification 0.95.0. Standard signatures use the maintained `cryptography` library. We did not invent an encryption or proof scheme. The application-level composition and dependencies still need independent security review.

## Research result: no new election-security guarantee

ElectionGuard and Helios already provide the central cryptographic mechanisms. Belenios already provides public credentials and signed ballots, an especially relevant precedent for authorization claims.

The optional receiver mode models an election-scoped grant for each enrolled voter, checked in addition to baseline voter signatures. No formal OpenLine protocol or integration was provided, so this is **an idea modeled for comparison, not an OpenLine implementation**. Both modes already bind voter, receiver/election context, and accepted ciphertext to authenticated keys. The extra grant exposes a permission decision but demonstrates no additional tally, confidentiality, coercion, or completeness guarantee. A dishonest operator's signature cannot make its tally true.

The contribution is an inspectable teaching and testing experiment. There is no demonstrated cryptographic novelty to justify a larger voting platform. [Read the plain-English research report](docs/RESEARCH.md) for sources and the comparison.

## What remains unsafe

The local server receives each fake choice before encryption and holds every simulated private key. It can decrypt individual ciphertexts if it abuses those keys. Public exports omit individual plaintexts and nonces, but ciphertext privacy is conditional on honest key custody and secure devices; it is not anonymity, and small or unanimous totals can reveal choices.

Compromised voter devices, coercion, vote buying, denied or suppressed submissions, malicious registration, stolen keys, colluding guardians/witnesses, and denial of service are **not solved**. There is no cast-as-intended challenge workflow, independent guardian ceremony, secure key erasure, persistence/recovery service, or production election procedure. See the [threat model](docs/THREAT_MODEL.md).

## Tests and review

```sh
.venv/bin/python -m pytest -q
.venv/bin/python -m pip check
```

The adversarial suite includes cryptographic-proof failures, fabricated totals, wrong/missing/duplicated guardian shares, unknown ballot styles, duplicated/unauthorized voters, election replay, omission with a valid recomputed tally, forged receipts/checkpoints, exact signed JSON type handling, and loopback browser API restrictions. It also demonstrates the archive-only limitation rather than hiding it behind a passing completeness check.

See [current WITNESS-002 validation](docs/WITNESS-002-RELEASE.md), [preserved WITNESS-001 validation](docs/WITNESS-001-RELEASE.md), and [historical baseline validation](docs/RELEASE_CANDIDATE.md) for actual execution results. Internal checks are not an independent cryptographic audit. No release tag, public deployment, or published security claim is authorized or performed.

## Accessibility and project layout

The browser uses semantic forms, labeled controls, keyboard focus, textual verification results, live status messages, responsive layouts, and reduced-motion support. Keyboard/mobile checks are recorded with release validation. Screen-reader usability and contrast need independent review; this is not an accessibility certification.

An optional `scripts/browser_smoke.py` uses existing Python Playwright and system Chromium to check a disposable loopback demo, including keyboard focus, downloads, reduced motion and 320 px layout. It resets its target; read its instructions before running it. The core Python tests need neither a browser nor Playwright.

- `vote_lab/crypto.py`: narrow adapter to upstream election cryptography.
- `vote_lab/records.py` and `verification.py`: signed messages and public record verification.
- `vote_lab/model.py`: fake identities, keys, and attack copies.
- `vote_lab/witness.py` and `witness_verify.py`: matched custody experiment and offline evidence checks.
- `vote_lab/custody*.py`: independently operable witness/operator CLIs, offline verifier, and explicitly local apparatus tests.
- `vote_lab/server.py` and `static/`: loopback browser control panel.
- `tests/`: automated adversarial and functional tests.
- `docs/`: research, threat model, release results, and artifact formats.
- `requirements.lock`: tested exact dependency versions and upstream revision. Upstream GUI/database packages arrive transitively; the lab runs neither their GUI nor a database.

Apache-2.0 licensed, as specified by this repository's [LICENSE](LICENSE). Upstream dependencies retain their own licenses; ElectionGuard Python is MIT, Helios was studied under Apache-2.0, and Belenios was studied as a comparator rather than bundled. External API spending: **$0**.
