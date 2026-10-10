# WITNESS-002: real custody separation

**Experimental infrastructure; synthetic ballots; fictional, nonbinding election. Not certified election software.**

## Verdict and the boundary actually tested

**Actual independent custody: INCONCLUSIVE.** Only one shared execution environment was available for this work. Separate independently administered witness machines, administrators, and signing keys were not available or established. No genuinely independent third party has reproduced the verification. A local process, container, or directory cannot supply that missing evidence.

WITNESS-002 builds the apparatus for an external test: independently runnable operator and witness roles, witness-side key generation, authenticated public-key pinning instructions, retained signed observations, and offline verification. The human-operated test in [WITNESS-002-EXTERNAL-TEST.md](WITNESS-002-EXTERNAL-TEST.md) remains pending. Its custody verdict must not be changed to PASS until actual administrators control the separate environments and private keys and complete the adversarial comparison.

The preceding experiment is unchanged. [WITNESS-001](WITNESS-001.md) reported 149 passing tests and 51 matched outcomes. Its C condition detected seven attacks that operator-controlled records did not; removing independent evidence removed those detections. It also explicitly reported that every role was on one machine. The earlier receiver-grant finding remains unchanged: no additional election-security guarantee was demonstrated. WITNESS-002 adds no OpenLine authorization machinery and invents no voting cryptography.

## Decision question

Can an operator erase, rewrite, or conceal previously witnessed ballot records when observers actually control their keys, retained evidence, and verification environments?

The conditional technical answer is that an authentic, retained signed observation supplies a historical reference that the operator's current publication cannot supply alone. A verifier can compare that reference with a cryptographically valid replacement archive. A contradiction exposes a rewrite, rollback, or compared conflicting view even when the operator correctly recomputes the published tally. The operator can still delete its own files, withhold information, and prevent service; detection does not prevent those actions or reconstruct missing ballots.

This candidate tests the comparison mechanism locally. It does not establish the antecedent that independent administrators actually held the reference beyond the operator's authority. That is the purpose of the pending external test, not a result inferred from local test success.

## Available environments and ownership evidence

The observed execution environment was `/workspace` on Linux `6.18.44`, x86-64, running as UID/GID `1000` (`agent`), with no supplementary groups. The repository, its artifacts, and its Python environment were owned by `agent:agent`. Every coding agent shared that environment and filesystem. Process capability masks were zero, `NoNewPrivs` was `1`, and seccomp mode was `2`; these process restrictions do not establish separate witness administrators. The actual provider/hypervisor administrative owners were unknown and not audited. An account name is process provenance, not proof of the human or organization administering a machine.

The available tools did not provide an explicitly authorized second independently administered execution environment. Configuration-draft tools are not evidence that such a machine exists or is under another administrator's control. No substitute credentials, external accounts, remote deployment, or external messages were created to fill the gap.

| Role or boundary | Environment observed in this run | Administrative owner established? | Who can modify its local evidence? | Custody conclusion |
| --- | --- | --- | --- | --- |
| Operator apparatus | Shared `/workspace`, UID 1000 | No independent human administrator established | Shared workspace account and its administrators | Local development only |
| Witness A apparatus | Same shared environment; separate role files/processes | No independent witness administrator established | Shared workspace account and its administrators | Local development only |
| Witness B apparatus | Same shared environment; separate role files/processes | No independent witness administrator established | Shared workspace account and its administrators | Local development only |
| External Witness A | Not available/executed | Pending | Pending external administrator declaration and test | INCONCLUSIVE |
| External Witness B | Not available/executed | Pending | Pending external administrator declaration and test | INCONCLUSIVE |
| Independent reproduction | Not performed | Pending | Pending | INCONCLUSIVE |

The external run must record actual machines or accounts, their separate administrative owners, who generated each private key, where each key was retained, and every party able to modify each evidence store. A signed statement proves possession of a key; it does not prove who administers the machine holding that key. Operator access to witness storage, recovery keys, cloud authority, or a common administrative account defeats the claimed custody boundary even if the files reside in different directories.

## Evidence and cryptographic scope

ElectionGuard verification remains the existing narrow verifier for this fictional election. It checks ballot validity, signatures and authorization bindings, exact aggregation, and tally decryption evidence. The witness layer uses established SHA-256 commitments and Ed25519 signatures through `cryptography`. It provides no replacement encryption scheme or proof system.

Each witness must generate and retain its private key on its own environment. Only public descriptors, authentic election-anchor information, signed observations, and selected public election records cross role boundaries. The operator must not create witness keys or receive private-key backups. Public descriptors and election-anchor fingerprints must be authenticated through a channel whose authority is independent of the operator's publication. Merely copying the public key advertised next to an archive gives the operator control of both the assertion and its supposed verifier.

A witness verifies and freezes its first accepted closed archive, signs the exact record commitment, and keeps its own predecessor-linked history. A later changed archive is rejected without signing it or advancing retained state, even if its election cryptography is valid. An ordinary repeat observation is idempotent. An explicit refresh signs a later sequence for the same immutable closed record; it does not authorize a different record or reopen voting. This differs from WITNESS-001's modeled snapshot revisions without rewriting that earlier experiment.

A signature is an attributable statement under a pinned key, not proof that the signer is honest or independent. A later retained checkpoint supplies a reference for detecting rollback; an old valid signature alone does not prove freshness. The offline verifier uses exported files without consulting an operator database or API. Its trust inputs must come from the witness-controlled copies, rather than being reconstructed from the operator's altered bundle. Local file modes are key-storage hygiene; `0700` directories and `0600` keys under one UID do not deny another process of that UID access.

The default coverage policy requires observations from both named witnesses. A missing required observation or insufficient authentic trust information is INCONCLUSIVE if there is no conclusive contradiction. A surviving honest witness can expose a contradiction even when another required witness is missing. Compared authentic contradictory statements expose inconsistent views but do not, by themselves, identify the dishonest party.

## Result vocabulary

Separate result fields are necessary:

| Field | Values | Meaning |
| --- | --- | --- |
| Verifier `status` | PASS, FAIL, INCONCLUSIVE | Supplied evidence is consistent; an integrity contradiction was found; or required trustworthy evidence is unavailable |
| Verifier `detection` | DETECTED, NOT DETECTED, INCONCLUSIVE | Whether the supplied view exposes an attack/integrity failure or cannot support the required comparison |
| Matched-run `test_result` | PASS, FAIL, INCONCLUSIVE | Whether the executed test produced its stated expected result with enough supporting evidence |
| Verifier and matched-run `real_custody_status` | INCONCLUSIVE in the software/local run | No software signature can establish independently administered custody; the external human-operated verdict must be supported separately |

A negative-control test can PASS by producing NOT DETECTED for an attack that cannot be observed. That is successful reproduction of a failure limit, not a security PASS. A verifier PASS means consistency of the supplied evidence, not completeness of an unobserved history or real custody. A local test PASS cannot produce an external custody PASS. Missing evidence is not a clean bill of health. A detected damaged artifact does not prove who damaged it. CLI exit codes are `0` for verifier PASS, `1` for FAIL, and `3` for INCONCLUSIVE. Malformed or missing trust/evidence must remain inconclusive rather than becoming a clean pass; record other argument/input errors with their exact messages and return codes.

## Executed local results

The executed local matrix is `artifacts/witness-002-local/results.json`: **20 cases, all 20 local `test_result` values PASS**. Artifact verdicts were **11 FAIL/DETECTED, four PASS/NOT DETECTED, and five INCONCLUSIVE**. Every case and the overall result still reported `real_custody_status: INCONCLUSIVE`; the external test was PENDING. Those distinct labels prevent an expected hidden attack from being advertised as a security success.

The main experiment used one synthetic 100-voter election and matched copies of its records. Eighteen of the 20 supplied archives had `crypto_valid: true`; the two deliberately damaged/impersonated-ballot cases had `false`. Witnesses were individually initialized through their runnable CLI processes. Their public identities were pinned, each first archive was verified by its own local role process, and their signatures and retained histories were compared offline. All processes nevertheless belonged to the same local UID.

In the table, “without retained history” retains the complete supplied key/election pins and whatever checkpoints the operator advertised, but removes the witness-owned history files. “Without trust” removes the pinset; **all 20 cases became INCONCLUSIVE** at the custody-verifier level. These controls do not silently change the verifier into an operator-only completeness checker. Election proof/authentication validity is reported separately by `crypto_valid`. Every historical detection assumes authentic pins, an honest relevant observation that survives, and correct verification code; row-specific trust is stated below.

| Executed case | Artifact status / detection | Evidence exposing the problem or limiting the conclusion; required trustworthy party | Without retained history |
| --- | --- | --- | --- |
| `honest` | PASS / NOT DETECTED | Both authentic latest heads agree with the original record; both required observations and authentic pins must be available. | INCONCLUSIVE |
| `delete-accepted` | FAIL / DETECTED | Retained signed 100-ballot heads contradict a valid 99-ballot record and recomputed tally; one honest observer must retain the original history. | INCONCLUSIVE |
| `alter-ballot` | FAIL / DETECTED | Existing voter-signed payload no longer binds the altered ciphertext-linked data. Existing authenticated voter keys and election verification already expose it; witnesses also see changed commitments. | FAIL |
| `replace-ballot` | FAIL / DETECTED | A valid replacement ciphertext carries an operator-made counterfeit voter signature; authentic original voter keys and authorization bindings expose it without witness history. | FAIL |
| `rewrite-history` | FAIL / DETECTED | Honest retained exact-record commitments disagree with reordered valid ballots and freshly signed operator receipts, despite unchanged aggregate. | INCONCLUSIVE |
| `conflicting-histories` | FAIL / DETECTED | Authentic first-view commitments from A and B disagree when compared; the relevant views must reach the verifier. Signatures alone do not attribute which view is correct. | INCONCLUSIVE |
| `forge-checkpoint` | FAIL / DETECTED | Operator substitutes its own key declaration and a matching signature; the original separately pinned witness identity differs, and the signature fails under that pin. Authentic pins suffice to expose substitution. | FAIL |
| `replay-checkpoint` | FAIL / DETECTED | One authentic sequence-1 head is advertised while that observer retains sequence 2 for the same immutable record; its later retained head must survive. | INCONCLUSIVE |
| `rollback-checkpoint` | FAIL / DETECTED | Both sequence-1 heads are advertised against retained sequence-2 heads for the same record; at least one honest later reference must survive. | INCONCLUSIVE |
| `suppression-before-observation` | PASS / NOT DETECTED | Both witnesses truthfully first saw only the valid 99-ballot subset. The hidden attempted submission is not verifier evidence; no trustworthy observation or acknowledgment exists to expose it. | INCONCLUSIVE |
| `observer-lost` | FAIL / DETECTED | B's surviving honest 100-ballot head contradicts the valid deleted-ballot record. A's missing evidence is reported; B must retain the relevant observation. | INCONCLUSIVE |
| `observer-unavailable` | INCONCLUSIVE | B agrees with the unchanged record, but required A evidence is missing; one matching view cannot establish the default two-witness coverage. | INCONCLUSIVE |
| `observer-compromised` | FAIL / DETECTED | Compromised A signs a consistent false 99-ballot history; honest B's retained original head contradicts it and the publication. B must remain honest; signatures do not identify that honesty. | INCONCLUSIVE |
| `compromised-survivor-only` | INCONCLUSIVE | Only compromised A's matching false history reaches the verifier; required B is absent. There is no authentic contradiction in that available view. | INCONCLUSIVE |
| `idempotent-replay` | PASS / NOT DETECTED | Advertised current authentic heads match retained current heads; harmless repeated delivery is accepted. | INCONCLUSIVE |
| `isolated-equivocation` | PASS / NOT DETECTED | Explicit single-observer policy sees A's consistent view while B's differing view is withheld. No verifier can infer the unavailable fork. | INCONCLUSIVE |
| `all-observers-lost` | INCONCLUSIVE | A valid smaller archive lacks all required retained historical references; the verifier cannot determine its continuity. | INCONCLUSIVE |
| `missing-trust` | INCONCLUSIVE | No complete authentic pinset is supplied; operator-provided identities are not promoted into trusted witnesses. | INCONCLUSIVE |
| `missing-identity-pin` | INCONCLUSIVE | One required identity fingerprint is absent; the key set cannot be authenticated. | INCONCLUSIVE |
| `invalid-signature` | FAIL / DETECTED | A literal damaged advertised checkpoint signature fails under its authentic pinned key; a trusted pin and correct signature checking expose the integrity failure. | FAIL |

For both stale-checkpoint controls, advertising only the authentic earlier heads and supplying only matching earlier reference states gave **PASS**. The control changes the advertisement as well as the available reference; it does not mix an earlier retained state with an advertised newer head. The signatures were not intrinsically false. A signature cannot establish that no later checkpoint exists when the later evidence has disappeared.

The witness signing service was tested separately: it refused a changed cryptographically valid closed archive, issued no new checkpoint, and left its exported retained evidence unchanged by canonical hash (`retained_evidence_unchanged: true`). That local apparatus test passed. It prevents the normal witness service from endorsing that rewrite; it does not prevent an operator from rewriting its own publication or a compromised administrator from bypassing the witness service.

The local custody negative control was decisive: another process of the same UID successfully rewrote the witness state file's bytes while preserving its contents. `same_uid_boundary_probe.operator_can_rewrite_witness_store` was `true`, and the local `separation_requirement` was **FAIL**. Private file modes did not create an independent administrative boundary. No honest witness secret needed to be printed or transferred to demonstrate that failure.

### Key and execution provenance from the actual local run

The recorded platform was `Linux-6.18.44-x86_64-with-glibc2.41`, Python `3.12.14`, host label `3e40753ac5d7`, UID/GID 1000, cwd `/workspace/openline-vote-lab`. The host label is an execution identifier, not an attestation of administration. The run declared `separate_administrators_available: false` and `third_party_reproduction: NOT PERFORMED`.

| New role | Key generated by | Key/evidence retained by | Recorded public descriptor fingerprint | Independent administrator |
| --- | --- | --- | --- | --- |
| Witness A / `observer-1` | Its own `init` CLI process | Its own local store under shared UID | `8f488fc600d6c0446c5cbc615760b57c7ba597140db3e11f256b711d3ce0bd19` | NOT ESTABLISHED |
| Witness B / `observer-2` | Its own `init` CLI process | Its own local store under shared UID | `41b88b0227462df8bce2df3e869d3335d593174008ccb365cd1ca864a075d3fd` | NOT ESTABLISHED |

Those are the normal pair's observed public descriptors; fresh runs generate different keys and hashes. Additional local fork and suppression branches generated their own role keys through the same CLI. The deliberate A-compromise branch invoked a signing bypass within that specifically compromised role; it did not transfer B's key. The operator retains simulated voter, guardian, and receipt keys, and an inherited unused baseline witness key. That inherited key supplies no WITNESS-002 observer evidence.

### Additional automated boundary checks

The internal review suite exercised a genuine second fictional ElectionGuard election with valid crypto and authentic first-election checkpoints advertised in its publication. Wrong-scope replay returned FAIL even with no retained evidence, because the advertised signed statements themselves contradicted the new election scope. Removing all advertised checkpoints and retained evidence returned INCONCLUSIVE. This is scope checking, not a new outside-custody guarantee; it is separate from the 20-row stale-head matrix.

The review also demonstrated that replacement identities, signatures, and matching **self-supplied** fingerprints can still produce artifact PASS. Its `real_custody_status` remained INCONCLUSIVE. A format check or hash comparison cannot prove an authenticated external key exchange. The candidate's requirement for a separately authenticated human comparison is an operational prerequisite, not something the program can certify.

The full source/packaged test totals and reproducible archive validation are recorded in [WITNESS-002-RELEASE.md](WITNESS-002-RELEASE.md). Internal review tests are not independent third-party verification or a security audit.

### Reproduce the local apparatus

Install pinned dependencies as described in [README.md](../README.md), then use a fresh output directory:

```sh
.venv/bin/python -m vote_lab.custody_experiment --out artifacts/witness-002-local
.venv/bin/python -m vote_lab.custody_cli verify \
  --publication artifacts/witness-002-local/offline/publication.json \
  --trust artifacts/witness-002-local/offline/pinned-trust.json \
  --evidence artifacts/witness-002-local/offline/witness-1-evidence.json \
  --evidence artifacts/witness-002-local/offline/witness-2-evidence.json
```

The selected offline archive is the valid 100-ballot history rewrite. Verification is expected FAIL/DETECTED with exit `1` and `crypto_valid: true`. The experiment generator exits `0` when its expected local results match, including negative controls. It does not overwrite existing evidence. Local role stores contain synthetic private signing keys and must stay private; the release source archive excludes generated artifacts and keys. Public result JSON omits plaintext tally totals. Follow the separate external runbook to test actual custody rather than relabeling these local files as independent.

## What this adds to the earlier experiment

ElectionGuard already supplies the election proof checks; Helios and audited bulletin-board designs already illustrate encrypted-ballot tracking and public verification. Standard signed records, authentic key pins, retained history, and compared observer views are established techniques. Sources and the baseline comparison remain in [RESEARCH.md](RESEARCH.md). This candidate makes witness roles separately runnable and gives each role responsibility for its own new signing key and frozen history. It introduces no new encryption primitive, no OpenLine authorization layer, and no novel election-security guarantee.

The observed advance is a reproducible custody-test apparatus with honest failure reporting. WITNESS-001's outside-custody premise remains a premise; WITNESS-002 did not turn it into a measured independent-administration result. The available shared environment actually failed the local separation probe. The external procedure is concrete enough to run under separate administrators, but its execution and any stronger conclusion are pending. These findings do not justify expanding the candidate into an Internet voting platform.

## What remains unproven or unsafe

- **Suppression before observation:** no witness can expose a submission it never observed and for which no trustworthy acknowledgment exists. A 99-ballot archive can be valid without proving whether a hundredth submission was suppressed.
- **Hidden conflicting views:** witnesses that never compare observations cannot infer another consistent view shown elsewhere. Partitions and withheld exports can keep a contradiction unavailable.
- **Observer failure:** losing the last honest relevant observation or compromising every trusted witness restores the operator's ability to present a consistent replacement history. One surviving statement cannot establish a missing second view under a two-witness coverage policy.
- **Trust and administration:** pins need authentic distribution; administrator independence needs operational evidence; retained keys and records need protection against the actual operator authority. Local tests do not establish these facts.
- **Election correctness and voter intent:** the synthetic roster and colocated simulated guardian/voter keys are not independent election ceremonies. Malware can change a selection before encryption or observation. A consistent witnessed archive may contain wrongly cast or wrongly enrolled ballots.
- **Privacy, coercion, and receipt-freeness:** aggregate commitment receipts omit choices, encryption openings, and individual voter identifiers. This does not establish receipt-freeness, coercion resistance, vote-buying resistance, anonymity, or confidentiality from a compromised device or simulator. Publishing adjacent decrypted subset tallies can expose an individual choice by subtraction; the external run must not create a public feed of those tallies.
- **Availability:** signatures cannot force an operator or witness to stay online, deliver a record, or preserve access to a device. Denial of service and withheld ballots are not solved.
- **Implementation assurance:** the local producer, verifier, and test suite share code and dependencies. Tests do not replace independent security review. No certified election, production custody procedure, or public deployment is demonstrated.

## Answers to the final three questions

1. **What can an independently administered witness prove that the operator cannot prove alone?** Conditional on authentic pins, honest observation, intact witness custody, and correct verification, the witness can supply an externally retained commitment to a previously observed exact record. Comparison can prove that a later operator publication contradicts that record. The operator's current self-consistent publication cannot establish that historical fact by itself.
2. **When does that protection fail?** It fails before any honest observation, when relevant evidence or authentic pins are unavailable, when every relevant witness is compromised or shares the operator's authority, and when conflicting views never reach a comparison. It does not prove voter intent, prevent deletion, prevent denial of service, or establish receipt-freeness.
3. **Has actual independent custody been demonstrated?** No. The available environment supports building and testing the apparatus. The genuinely separate, human-operated test remains INCONCLUSIVE and pending.

The candidate stops here for review. External API spending is **$0**. No real voters, election credentials, binding election, paid infrastructure, public deployment, release publication, or GitHub push is part of the experiment.
