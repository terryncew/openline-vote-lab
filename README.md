# OpenLine Vote

**A fictional vote. Evidence you can check.**

OpenLine Vote is an open-source research demonstration of encrypted ballots and checkable election records. Choose a community garden or a neighborhood library, inspect the evidence, and try changing the count. Then discover what the evidence cannot tell you.

**Experimental infrastructure. No real elections, voters, or candidates. Not certified election software.** The demo collects no names, email addresses, or account details. It uses no paid APIs, analytics, advertising, or external fonts.

[Watch the real 30-second walkthrough](docs/openline-vote/walkthrough.mp4) · [Phone preview](docs/openline-vote/phone.png) · [Desktop preview](docs/openline-vote/desktop.png)

## Try it locally

Python **3.12**, Git, and an initial free dependency download are required. Linux x86-64 is the tested platform.

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python -m vote_lab.demo_server --port 8001
```

Open `http://127.0.0.1:8001` on that machine. The default listener is local. A phone-accessible public link requires an approved HTTPS host; no public deployment or GitHub push has been performed. See the [exact publication and hosting instructions](docs/OPENLINE-VOTE-PUBLISH.md).

No sign-up. Each browser gets a separate temporary fictional election with 100 synthetic voters. The visitor chooses one fake ballot; the other 99 choices are randomized. Starting another election does not reset someone else's demonstration.

## Vote → Verify → Audit

1. **Vote.** Pick a fictional project. The existing ElectionGuard implementation encrypts a synthetic ballot on the server and produces a choice-free signed receipt.
2. **Verify.** Check recording and exact encrypted-ballot inclusion, then check the ballot and tally proofs. Download the public evidence to run the existing verifier yourself.
3. **Audit.** Delete a previously witnessed ballot and recompute a mathematically valid smaller tally. Retained evidence exposes the changed history. Also try suppression before observation: without a trustworthy acknowledgment or historical reference, a valid smaller record can escape detection.

The browser shows actual results from the existing verifier. Loading indicators describe work in progress; they are not proof of success. A displayed server result is still delivered by the demo operator. Downloaded evidence and an independently run verifier provide a separate checking path.

Receipts contain commitments, not choices or encryption openings. **Encryption, recording, inclusion and a verified tally are different claims.** None proves that a phone encrypted the intended choice, every attempted submission was accepted, or the administrators were independent.

## Why can't we use this for real elections?

The server sees the fake selection and holds all simulated voter and guardian keys. It is capable of decrypting individual ballots. Separate visitor sessions do not establish separate election authorities.

Compromised phones, coercion, vote buying, malicious enrollment, suppression before observation, colluding trustees and denial of service remain unsolved. Small or unanimous totals can reveal choices. A receipt without a choice does not establish receipt-freeness. No improved-turnout claim is supported.

**Actual independent custody remains INCONCLUSIVE. Shared-account isolation FAILED.** The witness comparison demonstrates conditional detection, not prevention, secure internet voting, or independent administration.

[Limitations and threat model](docs/THREAT_MODEL.md) · [Plain-English research](docs/RESEARCH.md) · [Publication readiness](docs/OPENLINE-VOTE-READINESS.md)

## Verify outside the browser

Download the sealed record, anchor, checkpoint and receipts from the demo. With dependencies installed, verification runs offline:

```sh
.venv/bin/python -m vote_lab verify \
  --record openline-vote-record.json --anchor openline-vote-anchor.json \
  --checkpoint openline-vote-checkpoint.json --receipts openline-vote-receipts.json
```

Exit `0` means those supplied artifacts passed the implemented checks; exit `1` means a failure was found. It is not a certification. Authenticate and retain the anchor and checkpoint independently before trusting later operator publications. Obtaining every reference from the same operator after an attack does not establish an honest past.

`--archive-only` intentionally omits the historical checkpoint requirement. A valid subset tally can pass with `completeness: false`. That negative control is central to the research result.

## Preserved research

The original ElectionGuard adapter, verifiers, simulator, witness experiments, historical tests, reports and release archives remain intact. OpenLine Vote adds a separate browser adapter and presentation; it does not invent voting cryptography or add OpenLine authorization machinery.

| Preserved candidate | What it established |
| --- | --- |
| [0.1.0rc1](docs/RELEASE_CANDIDATE.md) | 84 historical tests; receiver grants demonstrated no additional election-security guarantee |
| [WITNESS-001](docs/WITNESS-001.md) | 149 tests and 51 matched outcomes; A/B were equivalent, C detected seven additional history attacks under assumed outside evidence custody |
| [WITNESS-002](docs/WITNESS-002.md) | 288 local tests, 139 extracted-archive checks, 20 outcomes; real custody INCONCLUSIVE, shared-account isolation FAIL |

The [0.1.2rc1 recovery evidence](artifacts/release-0.1.2rc1/RECOVERY.md) includes saved results, source hashes and unchanged archives. Historical second-build evidence is missing and explicitly marked inconclusive. An [independently administered external custody test](docs/WITNESS-002-EXTERNAL-TEST.md) is prepared but has not been performed.

ElectionGuard supplies the ballot encryption, validity proofs, aggregation and decryption evidence. The Python dependency is pinned to upstream commit `a9753841f5082d1c35bdc1b053aade74778662b7` and specification 0.95.0. Ed25519 signatures use `cryptography`. Helios and Belenios were studied as established precedents. The narrow adapter and application composition still need independent security review; no cryptographic novelty is claimed.

## Develop and review

```sh
.venv/bin/python -m pytest -q
.venv/bin/python -m pip check
```

The original browser remains available through `.venv/bin/python -m vote_lab serve` on loopback port 8000. The independently operable witness and offline-verifier commands in the historical reports remain available.

- `vote_lab/public_static/`: the mobile-first OpenLine Vote experience.
- `vote_lab/demo_server.py`: temporary synthetic sessions and the existing-crypto browser adapter.
- `vote_lab/crypto.py`, `verification.py`, `records.py`: preserved cryptography and verification.
- `vote_lab/witness*.py`, `custody*.py`: preserved witness experiments and offline tools.
- `tests/`: historical and new adversarial checks.
- `Dockerfile.demo`: an optional local container using the same pinned dependencies.

The new experience uses semantic controls, visible keyboard focus, responsive layouts, text verdicts and reduced-motion support. Mobile, keyboard and browser checks are recorded in the readiness report; they are not an accessibility certification.

## Share the experiment

[30-second walkthrough](docs/openline-vote/walkthrough.mp4) · [Publication instructions](docs/OPENLINE-VOTE-PUBLISH.md) · [Source repository](https://github.com/terryncew/openline-vote-lab)

Apache-2.0 licensed under the existing [LICENSE](LICENSE). Upstream dependencies retain their licenses. External API spending: **$0**. Publication, public deployment and external custody testing require approval.
