# OpenLine Vote 0.2.0rc1: publication audit

This is an experimental, synthetic-only research release. Publication of source
and review materials is authorized; deployment of a public voting server is not.
This audit is an addendum to the dated [local readiness report](OPENLINE-VOTE-READINESS.md),
which records the original unpublished candidate at commit
`6843d2269b7dc98bdc62b3fc6b3f02972fab8740`.

## Safety audit

The baseline audit covered all **98 tracked files**, **102 reachable Git-history
blobs across four commits**, and **106 members of the three historical release
archives**. Archives contained regular files with safe paths, with no symbolic
links, credentials, environments or sensitive witness stores. Credential and
private-key scans found no matches. Comparisons against the raw, hexadecimal
and Base64 representations of all six ignored synthetic witness signing seeds
found no matches in tracked history or archives. The six seeds remain excluded.

Seventeen JSON artifacts were inspected; 500 fields named `nonce` were all
`null`, with no published encryption openings. Git history retains ordinary
authorship contact metadata. No history was rewritten. The audit checks do not
constitute an independent security review or a guarantee that no defect exists.

All seven tracked screenshots and the complete 30-second walkthrough were
reviewed for accidental disclosure. The walkthrough contains one H.264 video
stream with no audio, credential, terminal, cookie, signing-key, identity or
location disclosure. Half-second samples, scene-change frames, OCR checks and
raw-capture samples show only the intended fictional demonstration. Processing
edits remain visibly disclosed. Its SHA-256 remains
`b0e3ca354eb0adeb94abce42676064c08af35dd17ea522a7746fcd6bfaedc904`.

All original release archives match their recorded checksums:

| Candidate | SHA-256 |
| --- | --- |
| 0.1.0rc1 | `f0d234d9001660e461c356b092c14e1ee6e15a9d67f3bc1cee0cb5bf72ff1d41` |
| 0.1.1rc1 | `d1456a79d3903ae19ff0f11a084f1c1f7df2443de332b7c14037fc177b41a8d4` |
| 0.1.2rc1 | `7cef59d2c2fcc04083789c966145bc37bb3868f6f0a702ceeda27bc6ba76a178` |

## What changed for publication

The README now explains the project's origin in AI-agent verification research,
the demonstration, findings, reproduction and invitation to contributors.
The Docker default command was narrowed from container-internal `0.0.0.0` to
`127.0.0.1`; documented port-mapped runs require an explicit internal-listener
override while retaining a loopback-only host mapping. Both Python CLI defaults
already use loopback.

The container correction was checked using a configuration-only image derived
from the tested runtime, with no dependency or application rebuild. Default
startup returned health HTTP 200, rejected an unauthorized host with HTTP 403,
and exposed exactly a loopback listener. The check ran non-root, read-only,
with networking disabled and no published ports. Application bytes matched the
tested candidate. See the [startup evidence](openline-vote/validation/publication-startup.json).

Cryptography, Python application code, tests, dependency pins, WITNESS-001 and
WITNESS-002 reports, negative findings and historical archives were not changed.
The original validation manifests describe the original candidate; the
[publication source manifest](openline-vote/validation/PUBLICATION_SOURCE_HASHES.json)
records the documentation and startup amendments separately.

## Tests and reproduction

The candidate passed **317 local tests** and **67 focused clean-container
tests**, with pinned dependencies and successful `pip check`. Browser checks
covered real encryption, proof and tally verification, offline checking of
downloads, duplicate rejection, failure recovery, both audit results, keyboard
controls and widths 320–1440 pixels. These results are preserved, not recreated
as stronger security claims. Physical phones and Safari remain untested.

The source release archive is produced from the reviewed Git commit, using
only tracked files and normalized gzip metadata. It includes documentation,
tests, safe research evidence and the unchanged historical archives. Generated
key stores, raw session state, environments and Git credentials are excluded.
New archive extraction and focused test results are recorded in the separate
release asset `PUBLICATION-VALIDATION.json`; it identifies the exact source
commit and archive hashes without creating a self-referential source manifest.

After downloading and extracting the source archive, run the README's pinned
Python 3.12 installation and tests. The offline verifier operates on exported
public evidence without trusting a database or API. Ciphertexts and signatures
use fresh randomness; successful reproduction means the same checked behavior,
not identical regenerated election bytes. Original missing second-build
evidence for 0.1.2rc1 remains marked inconclusive.

The project retains Apache-2.0. ElectionGuard, cryptography, gmpy2 and other
dependencies retain their own licenses. This publication distributes source,
not a preinstalled dependency image or binary bundle. External API spending is
**$0**; GitHub publication does not deploy the demo.

## Claims and boundaries

The UI distinguishes encryption, signed recording, ballot inclusion and tally
verification. It uses actual verifier-returned results. Authentic earlier
evidence can expose a later incompatible record; removing that evidence removes
the corresponding assurance. This demonstrates conditional detection, not
prevention or secure voting from personal phones.

**Actual independent custody remains INCONCLUSIVE. Shared-account isolation
FAILED.** Suppression before trustworthy observation can escape detection.
The simulator sees synthetic choices and holds every simulated private key.
Compromised phones, coercion, vote buying, malicious enrollment, colluding
guardians and denial of service remain unsolved. No turnout benefit, certified
election status or production readiness is claimed.

The public adapter accepts only a fictional `garden` or `library` choice and
creates its own 100 fake voters. It has no real-election import, enrollment,
identity or credential submission endpoint. These restrictions do not make
misuse or arbitrary future modifications impossible. Use only fictional,
nonbinding experiments. A public server and an independently administered
custody test each require separate authorization and review.
