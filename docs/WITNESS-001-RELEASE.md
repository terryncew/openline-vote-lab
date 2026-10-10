# WITNESS-001 release candidate: 0.1.1rc1

Prepared locally on October 10, 2026 for review. **Experimental infrastructure, not certified election software.** Synthetic identities and fictional, nonbinding elections only. No public deployment, GitHub push, release publication, real election credentials, or paid external API was used. External API spending: **$0**.

The historical 0.1.0rc1 reports and archive remain preserved. This candidate adds only the bounded witness experiment, its offline verifier, tests, and documentation. It does not add OpenLine authorization or alter the baseline finding that receiver grants demonstrated no additional election-security guarantee.

## Executed source validation

Host: Linux x86-64, Python 3.12.14, pytest 8.4.2, cryptography 50.0.2. Existing dependencies remain pinned in `requirements.lock`, including ElectionGuard revision `a9753841f5082d1c35bdc1b053aade74778662b7`. No new dependency is required. Runtime and verification use no network service.

| Check | Executed result |
| --- | --- |
| Final full regression suite | 149 passed, 0 failed, 0 skipped in 161.34 seconds |
| Matched experiment | 51 rows: 11 attacks and six controls in each of A/B/C; identical attack record hashes across conditions |
| Outside-evidence removal | All seven C-only detections of valid rewrites became NOT DETECTED without independent references; the second control also removed operator-supplied witness statements |
| Standalone verifier on the actual default C export | DETECTED, exit 1, with valid election cryptography; independently retained heads exposed the rewritten archive |
| Dependency integrity | `python -m pip check`: no broken requirements |
| Review | Internal adversarial and report review found no unresolved blocker; this is not an independent security audit |

The final suite includes the historical 84 tests and 65 new matched-election, evidence-removal, custody-capability, offline-process, parsing/signature, and negative-control checks. The replay fixture issues unrelated-election statements before attack execution; the C replay adapter cannot use honest observer signing keys. This is a test-harness refinement, not a new security guarantee.

The actual matched run is in `artifacts/witness-001-rc/results.json`. It omits plaintext totals. Generated election records are not bundled into the source archive. Random keys, encrypted ballots, IDs, and synthetic choices change between runs; the tested invariants and outcome matrix are reproducible, not the generated election bytes.

The existing browser was not changed by WITNESS-001. Its earlier validation remains historical; this candidate's new experiment is a local command-line demonstration. Current metadata also corrects the README and package license declaration to match the repository's existing Apache-2.0 `LICENSE`; the license file itself is unchanged.

## Local archive and checksum

The version-aware builder preserves the old release directory and writes:

```text
artifacts/release-0.1.1rc1/openline-vote-lab-0.1.1rc1.tar.gz
artifacts/release-0.1.1rc1/SHA256SUMS
```

It bundles source, tests, documentation, the existing license, and the dependency lock. It excludes virtual environments, generated elections, private keys, Git metadata, and caches; refuses symlinks; and normalizes archive metadata. Building twice from unchanged inputs must produce the same SHA-256. The checksum detects byte changes; it is not a signed release attestation.

```sh
.venv/bin/python scripts/build_release.py
cd artifacts/release-0.1.1rc1
sha256sum -c SHA256SUMS
```

The prepared workspace also retains `VALIDATION.json` beside the archive. It records the tested archive hash, extracted-source test result, standalone offline results, and preservation of the old archive. It is generated after testing the archive and is deliberately outside it, avoiding a self-referential checksum.

## Reproduce from the archive

Extract the source archive into a fresh directory and enter `openline-vote-lab-0.1.1rc1`. Install the same free pinned dependencies, then run:

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python -m pytest -q
.venv/bin/python -m pip check
.venv/bin/python -m vote_lab witness-demo --out artifacts/review-run
```

The initial dependency download needs network access, Git, and Python 3.12. Existing installed dependencies can be reused for offline review. There are no paid services. The demo refuses to overwrite an output directory.

Run the standalone verifier in a fresh process:

```sh
.venv/bin/python -m vote_lab witness-verify \
  --publication artifacts/review-run/operator/C/publication.json \
  --trust artifacts/review-run/observer-custody/pinned-trust.json \
  --retained artifacts/review-run/observer-custody/retained-evidence.json
```

Expected: **DETECTED, exit 1**, because the default export deliberately contains a valid rewritten history. Recheck that same publication without `--trust` or `--retained`: expected **NOT DETECTED, exit 0**. A/B publications likewise pass their weaker operator-provided checks. A parsed bundle with missing required observer observations yields **INCONCLUSIVE, exit 3**; file read/parse errors are input failures rather than structured attack verdicts. A zero exit does not prove there was no attack.

To export an unchanged-election control, use a fresh output path and `--export-case honest`. Only one selected archive/tally is exported per run; the complete outcome matrix includes every scenario. Do not publish adjacent 99/100-ballot plaintext tally pairs as privacy-preserving evidence.

For focused packaged-source checks:

```sh
.venv/bin/python -m pytest tests/test_witness.py tests/test_witness_review.py -q
```

Those tests also check that verification imports no simulator or server, attempts no network connection, checks altered records and anchors afresh, and never treats an operator-provided condition label as independent custody.

## What this candidate establishes and leaves unsafe

The [research report](WITNESS-001.md) gives every attack's evidence, required trustworthy party, and evidence-removal outcome. A and B are indistinguishable. C exposes specified contradictions when authentic independently retained observations and separately pinned keys survive. It demonstrates detection, not prevention, recovery, or a new voting protocol.

Suppression before trustworthy acknowledgment or observation remains NOT DETECTED. A single consistent view cannot expose a hidden fork. Missing required evidence can be INCONCLUSIVE. A surviving honest observer can expose a covered mismatch after one observer is lost or compromised, but signatures do not identify which observer lied. Collusion, loss of all references, corrupted key pins, and compromise of this one-machine simulator invalidate the assumed boundary.

New witness receipts contain aggregate commitments, not choices or encryption openings. Receipt-freeness and vote-buying resistance remain unproven. Compromised voter devices, coercion, denial of service, malicious enrollment, guardian collusion, aggregate inference, and implementation/supply-chain flaws remain unsafe. Independent security review must assess the composition, supported ElectionGuard proof coverage, authentic key acquisition, privacy, and actual custody arrangements before any further security claim.

This experiment stops at a tested local candidate and its findings. It supplies no basis for public deployment, real election use, or a larger voting platform.
