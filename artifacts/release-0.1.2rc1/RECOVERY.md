# Recovery and preservation record

This is a local-only, synthetic research candidate. The source and research
findings have not been rewritten. Actual independent custody is INCONCLUSIVE;
the shared-account isolation requirement FAILED. External testing is PENDING
and independent third-party reproduction was NOT PERFORMED.

The existing 0.1.2rc1 source archive and SHA256SUMS were preserved without
replacement or rebuild. SOURCE_HASHES.json records each of its 46 source files
and the local source-preservation commit. Historical source archives and their
existing validation records are also preserved locally in Git.

The saved 288-test and 139-test logs, 20-case result matrix and four-case offline
summary were copied byte-for-byte from surviving files. They are local historical
evidence, not signed attestations or a security audit. Pytest logs retain aggregate
summaries, not individual structured test records or process exit metadata.

No separate second-build log or second source archive survives to substantiate
the earlier reported deterministic-rebuild check. Recovery did not rebuild it;
VALIDATION.json records that check as INCONCLUSIVE rather than inventing evidence.

Only the selected public encrypted archive, public pinset and two commitment-only
witness exports are included in offline/. These simulated pins do not establish
external identity authenticity. No subset tally pair, private witness store,
private key, election-operator state, environment or cache is included.

The helper below blocks outbound connections and checks that the verifier imports
neither the private witness-store module nor simulator/server modules. It is the
surviving validation helper, copied unchanged. From the complete source root,
with the existing dependencies installed:

```sh
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -B \
  artifacts/release-0.1.2rc1/recovery-offline-check.py verify \
  --publication artifacts/release-0.1.2rc1/offline/publication.json \
  --trust artifacts/release-0.1.2rc1/offline/pinned-trust.json \
  --evidence artifacts/release-0.1.2rc1/offline/witness-1-evidence.json \
  --evidence artifacts/release-0.1.2rc1/offline/witness-2-evidence.json
```

Expected artifact FAIL, detection DETECTED, exit 1, crypto_valid true and
real_custody_status INCONCLUSIVE. This detects a valid rewritten history;
it does not demonstrate prevention or actual administrative independence.

The current source README and docs/WITNESS-002-EXTERNAL-TEST.md contain the
pending human-operated external instructions. Separate authorized administrators,
authenticated pin exchange and independent retained evidence must be established
before that test. No public deployment, push, publication or external testing was
performed during recovery. External API spending is $0.
