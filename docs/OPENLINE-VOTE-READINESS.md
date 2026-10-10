# OpenLine Vote: publication readiness

Local review candidate **0.2.0rc1**, validated on 2026-10-10. The existing
repository now has a working, mobile-first **Vote → Verify → Audit** experience.
It is experimental infrastructure for fictional, nonbinding elections, not
certified election software. Nothing has been pushed, publicly deployed, or
published. External API spending is **$0**.

## What works

The new browser adapter uses the preserved ElectionGuard implementation. A
visitor selects one synthetic ballot in a fresh 100-voter election; 99 other
synthetic choices are independently randomized. Real encrypted ballots,
signatures, inclusion checks, validity proofs, aggregation and decryption
evidence are checked by the existing verifier. The UI renders the returned
results, not a predetermined success animation. Only the full 100-ballot
aggregate is displayed, after verification.

The demo encrypts on its server. That server sees the fictional choice and
holds every simulated guardian and voter key. This is an educational browser
adapter, not private voting against its administrator. No names, contact
details, registration, analytics, remote fonts or paid APIs are required.

| Audit condition | Actual result | Evidence and trust requirement |
| --- | --- | --- |
| Remove a previously witnessed ballot and recompute a valid smaller tally | **DETECTED** with retained evidence; the smaller archive alone passes cryptographic checks | The authentic original checkpoint disagrees with the later archive. Someone must retain that checkpoint and authenticate its key outside the operator's authority. |
| Suppress a different synthetic submission before any trustworthy acknowledgment or observation | **NOT DETECTED** | The verifier in this separate counterfactual branch receives only the first valid 99-ballot observation. It has no authentic earlier evidence of the omitted event. |

The first attack demonstrates detection, not prevention. Removing the original
history reference removes that completeness assurance. The second branch
explicitly withholds the deletion branch's original 100-ballot reference; it
does not assert that an already witnessed event became unobserved. Neither
attack publishes a 99-ballot plaintext tally or subset archive: comparing full
and one-ballot-smaller totals could reveal that synthetic ballot's choice.

The public downloads contain the original sealed record, anchor, checkpoint
and a choice-free receipt list. The existing verifier runs offline without the
demo database or API. Authenticating the anchor/key and retaining the historical
evidence independently are separate tasks. Downloading everything from one
operator after manipulation does not establish independent custody.

## Completed validation

| Check | Recorded result |
| --- | --- |
| Full local regression suite, including all preserved historical tests | **317 passed**, 328.23 seconds |
| Clean dependency installation in Python 3.12/Linux container | Locked ElectionGuard revision installed; `pip check` passed |
| Focused tests in clean, non-root container with runtime networking disabled | **67 passed**, 117.56 seconds; new adapter, public review and cryptographic tests |
| Chromium browser QA | **PASS**, 85.678 seconds; actual 100-ballot election, explicit verification, duplicate rejection, service/polling failure recovery and both audit outcomes |
| Public downloads independently rechecked | Offline exit **0**, `ok: true`, `completeness: true`; outbound sockets blocked; server/private model not imported |
| Responsive layouts | No horizontal overflow at 320, 375, 390 and 1440 pixels; final verification layout and displayed tally checked in a fresh recording session |
| Accessibility checks | Keyboard skip link and native choice controls, labels, visible focus, status/alert semantics, reduced motion and textual verdicts checked |
| External requests during browser QA and recording | **0** |
| Walkthrough | Genuine local run; H.264, 390×844, 30 fps, exactly **30.000 seconds** |

Evidence is retained in [validation/](openline-vote/validation/):
[full test log](openline-vote/validation/full-tests.txt),
[clean-container test log](openline-vote/validation/clean-container-tests.txt),
[browser results](openline-vote/validation/browser.json), and
[walkthrough provenance](openline-vote/validation/walkthrough.json).
These are our local checks, not independent security review or certification.

The adapter has bounded work and temporary per-browser sessions, strict host
and origin checks, opaque HttpOnly/SameSite cookies, security response headers,
and an existing gevent WSGI runner. Tests cover unauthorized hosts/origins,
cross-site session allocation, concurrent duplicate requests, session isolation,
expiry/capacity, invalid input, export privacy and actual cryptographic outcomes.
These controls do not guarantee availability or production security.

## Walkthrough and appearance

[Watch the 30-second phone walkthrough](openline-vote/walkthrough.mp4).
[Phone preview](openline-vote/phone.png) ·
[Desktop preview](openline-vote/desktop.png) ·
[Verified evidence](openline-vote/verification.png) ·
[Detected deletion](openline-vote/detected.png) ·
[Undetected suppression](openline-vote/undetected.png).

The continuous source capture lasted **83.52 seconds**. The edited video keeps
actual result frames and shortens processing waits, with the visible caption
“Genuine local run | processing shortened.” No success frames were substituted.
Exact source intervals are recorded in the provenance JSON. The raw recording
remains in ignored local review artifacts; its SHA-256 is
`698080b9c421fcaee1f0eec51bcd28cfda782b9d3eb6cc4933bf90bad6bbbcc7`.
The prepared MP4 SHA-256 is
`b0e3ca354eb0adeb94abce42676064c08af35dd17ea522a7746fcd6bfaedc904`.

The 30-second video is an edited explanation, not a claim that cryptographic
work always completes in 30 seconds. Concurrency, memory and public-traffic
capacity have not been benchmarked. Physical phones, mobile Safari, other
browser engines and an independent accessibility audit remain untested.

## Preserved science and unsafe boundaries

The original ElectionGuard adapter, verification, simulation, witness/custody
source, historical tests, research reports and all three historical release
archives remain unchanged. README and packaging version/description were
updated; the new UI, server adapter, tests, developer documentation and media
were added separately. Dependencies and the existing Apache-2.0 license are
unchanged. The former local browser remains available on port 8000.

**Actual independent custody remains INCONCLUSIVE. Shared-account isolation
FAILED.** The browser's observer and operator roles share one administrator.
It models evidence comparison; it does not prove externally administered
custody. No additional OpenLine authorization guarantee is claimed or added.
WITNESS-001 and WITNESS-002's negative findings and missing historical
second-build evidence remain as previously reported.

Compromised phones, coercion, vote buying, malicious enrollment, colluding
guardians, suppression before observation and denial of service remain unsafe.
Receipt contents do not reveal a choice or encryption opening, but the system
has not established receipt-freeness. Small or unanimous aggregate results can
reveal choices. There is no improved-turnout claim, binding-election readiness,
or independent security review.

## Reproduce locally

From a checkout with Python 3.12:

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python -m pip check
.venv/bin/python -m pytest -q
.venv/bin/python -m vote_lab.demo_server --port 8001
```

Open `http://127.0.0.1:8001`. See the
[offline instructions](OPENLINE-VOTE-VERIFY.md) for the evidence verification
command, and the [hosting runbook](OPENLINE-VOTE-PUBLISH.md) for the clean
container validation command.

Optional browser checks require an interpreter with Playwright already
installed, a local Chromium, and (for recording) local ffmpeg/ffprobe plus a
supported font. In this environment those tools exist in the system interpreter,
separate from the project's virtual environment. Start a disposable loopback
server on port 8002, then use new output paths:

```sh
.venv/bin/python -m vote_lab.demo_server --port 8002
# In another terminal, using the interpreter that has Playwright:
python scripts/public_browser_smoke.py --url http://127.0.0.1:8002 \
  --chromium /usr/bin/chromium --project-python .venv/bin/python \
  --screenshots artifacts/browser-new --report artifacts/browser-new.json
python scripts/record_walkthrough.py --url http://127.0.0.1:8002 \
  --chromium /usr/bin/chromium --out artifacts/walkthrough-new
```

The demo itself does not require these optional tools. Regenerated elections
use fresh randomness; ciphertexts, signatures and media hashes will differ.
Compare verified behavior, not ciphertext byte identity.

## Exact publication gap

The repository, license, reviewed synthetic media, developer setup, source
links and [approval-gated publication steps](OPENLINE-VOTE-PUBLISH.md) are
prepared. No public URL exists yet. GitHub Pages cannot run the live Python
cryptography. The remaining hosting requirement is an already authorized,
reachable **Python 3.12/Linux host plus an approved HTTPS hostname or tunnel**,
using one application process and bounded resources. No free-provider account,
domain or suitable public host has been provisioned or verified.

After approval, publish the reviewed source commit, review it against `main`,
and separately approve the HTTPS deployment. Confirm the live source link points
to that implementation. Test an actual phone and HTTPS cookies on the approved
host before sharing it widely. Do not promise unlimited availability on a free
plan. The separately administered WITNESS-002 custody test also requires its
own approval and trustworthy administrators; it has not been run.
