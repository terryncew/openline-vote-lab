# WITNESS-002 release candidate: 0.1.2rc1

Prepared locally for review on October 10, 2026 (Pacific time). **Experimental infrastructure, synthetic-only and nonbinding; not certified election software. Actual independent custody: INCONCLUSIVE.** No separately administered external witness test or independent third-party reproduction was performed.

This candidate provides independently operable file-based operator and witness roles, an offline verifier, local matched attacks, and a [human-operated external runbook](WITNESS-002-EXTERNAL-TEST.md). It does not provision environments or certify independence. No public deployment, GitHub push, release publication, paid infrastructure, real electorate, real election credentials, or binding election was used. External API spending: **$0**.

## Executed validation

Host: shared `/workspace`, UID/GID 1000 (`agent`), Linux x86-64, Python 3.12.14. Witness stores and operator files remain writable by the same account. No actual independent human administrator is established. Existing dependencies and ElectionGuard revision `a9753841f5082d1c35bdc1b053aade74778662b7` remain pinned; no dependency was added or replaced.

| Executed check | Result |
| --- | --- |
| Final complete regression suite | 288 passed, 0 failed, 0 skipped in 242.81 seconds: the preserved 149 tests plus 139 new checks |
| New witness store and offline adapter checks | Core 26 and adapter 38 checks passed in focused validation |
| Independent internal review checks | 25 passed, including genuine cross-election replay and the shared-UID/unauthenticated-pin negative controls; this is internal review, not a third-party audit |
| Synthetic operator checks | 18 passed, including a genuine 100-ballot election, valid subset tally, valid reorder, public-identity handling, no new observer keys, and privacy warnings |
| Separately operable CLI integration | 32 passed using a small real ElectionGuard election; checks all 20 local cases, input failures, no network/private-role imports, and failure to establish a local administrative boundary |
| Actual local demonstration | 100 accepted synthetic ballots; 20 cases; every stated expected local result reproduced |
| Artifact outcomes in that demonstration | 11 FAIL/DETECTED, four PASS/NOT DETECTED, five INCONCLUSIVE; all real-custody verdicts INCONCLUSIVE |
| Witness signing-service refusal | A valid closed-history rewrite was refused; no checkpoint issued; exported retained commitment unchanged |
| Local custody boundary negative control | Another same-UID process could rewrite protected witness state: local separation requirement FAIL |
| Fresh standalone verifier, connections blocked | Actual default rewritten 100-ballot export: FAIL/DETECTED, exit 1, `crypto_valid: true`; no simulator, server, or witness private-store code imported |
| Dependency check and whitespace check | `pip check`: no broken requirements; `git diff --check`: clean |

Artifact FAIL means supplied evidence exposes a contradiction or integrity failure. A local expected-outcome test can PASS by reproducing an undetected attack. Missing trust or required evidence is INCONCLUSIVE. Artifact PASS establishes consistency under supplied pins only; it never establishes independently administered custody. Review the [research report](WITNESS-002.md) for every case, evidence, trust prerequisite, removal control, and privacy limitation.

## Preservation and scope

The historical reports, WITNESS-001 source/verifier/tests, baseline ElectionGuard adapter, original election verification and signature code, and 0.1.0rc1/0.1.1rc1 archives were preserved. Before release, preserved source bytes were compared directly with the 0.1.1rc1 archive and their digests were recorded. Neither historical finding was rewritten: operator-owned storage adds no outside custody, and OpenLine receiver grants demonstrated no additional election-security guarantee.

WITNESS-002 uses the prior checkpoint format but freezes its first closed archive. Its explicit refresh advances a checkpoint sequence for that same archive. This is a deliberately narrower experiment, not a new election lifecycle or voting protocol. Old WITNESS-001 snapshot semantics remain unchanged in their original implementation.

Only independently administered external environments could test the missing custody premise. Separate local role processes, fresh key generation, file modes and successful cryptographic checks cannot supply that premise. The runbook leaves each external administrative owner and attack result pending. No substitute administrators, shared witness keys, or operator-generated WITNESS-002 identities fill those cells.

## Reproducible candidate archive

From the source root:

```sh
.venv/bin/python scripts/build_release.py
cd artifacts/release-0.1.2rc1
sha256sum -c SHA256SUMS
```

The version-aware builder writes `openline-vote-lab-0.1.2rc1.tar.gz` and `SHA256SUMS`. It packages source, tests, documentation, license and dependency lock; excludes generated role stores, private keys, election exports, environments, caches and Git data; and normalizes metadata. Two builds from unchanged source must match. The checksum detects changes but does not authenticate a release publisher.

`VALIDATION.json` beside the prepared archive records its actual hash, deterministic rebuild check, extracted-source checks and offline verdicts, and preserved historical hashes. Raw test logs and the public local result matrix are retained there. These generated validation artifacts remain outside the source archive so its hash is not self-referential. **Never publish or transfer the local `local-role-stores/` directories: they contain synthetic witness private keys.**

## Reproduce validation from extracted source

Use a fresh complete candidate extraction. Enter its source root, create its virtual environment, and install the free pinned dependencies:

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python -m pip check
.venv/bin/python -m pytest -q
.venv/bin/python -m vote_lab.custody_experiment --out artifacts/review-local
```

Initial dependency download requires Git, Python 3.12 and network access. Installed dependencies can be reused for offline review. Runtime uses no remote service. The generator refuses existing output paths and uses fresh random keys and encryption; outcome invariants are reproducible, not byte-identical generated elections.

Verify the selected default attack independently in a fresh process:

```sh
.venv/bin/python -m vote_lab.custody_cli verify \
  --publication artifacts/review-local/offline/publication.json \
  --trust artifacts/review-local/offline/pinned-trust.json \
  --evidence artifacts/review-local/offline/witness-1-evidence.json \
  --evidence artifacts/review-local/offline/witness-2-evidence.json
```

Expected artifact FAIL/DETECTED, exit `1`, with valid election cryptography and real custody INCONCLUSIVE. Omitting trust or witness evidence yields INCONCLUSIVE, exit `3`. A missing/unreadable file likewise yields a structured INCONCLUSIVE input result. Wrong arguments can exit `2`. A consistent fully supplied control yields artifact PASS, exit `0`, and still real custody INCONCLUSIVE.

Focused packaged-source validation:

```sh
.venv/bin/python -m pytest \
  tests/test_custody_core.py tests/test_custody_verify.py \
  tests/test_custody_operator.py tests/test_custody_review.py \
  tests/test_custody_experiment.py -q
```

## Unsafe and pending properties

Authentic external fingerprints, genuine independent administration, immutable external custody, and independent reproduction remain operational requirements, not verified results. Missing observations, hidden forks, compromise of every relevant witness, and shared administrative authority defeat the intended protection. Detection does not prevent operator deletion, suppression or denial of service.

Privacy, coercion resistance, receipt-freeness, voter-device integrity and real enrollment are outside demonstrated guarantees. Comparing original and subset plaintext tallies can reveal a removed choice; the synthetic deletion fixture explicitly warns about that failure. Witness commitment exports contain no choices or openings, but they do not solve vote buying. All voter, guardian and baseline operator secrets are simulated and colocated. Source tests and internal review do not replace independent security review.

The experiment stops at this local candidate and the pending external test instructions. It makes no claim of REAL CUSTODY VERIFIED.
