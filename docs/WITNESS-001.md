# WITNESS-001: what independently held evidence changes

**Experimental infrastructure. Fictional, nonbinding election; 100 synthetic voters; local only. Not certified election software.**

This is one bounded experiment following OpenLine Vote Lab 0.1.0rc1. It asks whether an observer can detect an operator rewriting its database and published tally. It does not reopen the earlier conclusion: optional receiver grants demonstrated no additional election-security guarantee. The historical 84-test result and the baseline research remain in [RESEARCH.md](RESEARCH.md) and [RELEASE_CANDIDATE.md](RELEASE_CANDIDATE.md).

## Result and scope

**Yes: independently retained evidence changed what this modeled malicious operator could conceal.** Seven attacks that passed A and B were detected in C: deletion with a valid recomputed tally, a valid history rewrite, conflicting histories, observer-key substitution with forged checkpoints, rollback, and deletion after either losing or compromising one observer. Removing the outside evidence made those same C attack records pass the weaker checks. These are actual results from `artifacts/witness-001-rc/results.json`, not predictions from the design.

The protection failed for suppression before any trustworthy acknowledgment or observation. It also failed to expose a hidden fork when only one consistent observer view was available. Missing observer evidence without a contradiction produced `INCONCLUSIVE`, rather than a false completeness claim. Literal ballot damage and operator impersonation of a voter were already rejected by the existing election verifier in all three conditions; those outcomes are not added witness guarantees.

A valid encrypted tally can still count a valid subset of the accepted ballots. ElectionGuard can check the encryption, ballot validity proofs, aggregation, and tally decryption evidence; it cannot infer an unobserved acceptance event. An external witness adds a reference for comparison, not a new election encryption scheme. A directory under an operator's control is not independent custody merely because it is named `observer`.

All roles in this experiment run on one machine. The tests model an attacker being denied access to selected witness keys and retained evidence. That is **simulated role isolation**, not proof that actual observers are independent. A complete compromise of the local simulator can obtain all its role secrets. Real independent custody would require separately administered observers, separate key storage and authentic key distribution, records that the operator cannot rewrite, and an opportunity for observers to compare their views.

## Three matched conditions

All conditions use the same fictional election, encrypted ballot set, election parameters, proof verifier, and attack construction. The WITNESS-001 run uses baseline authorization and independently randomized synthetic choices rather than assigning a publicly known 60/40 aggregate. No condition adds OpenLine authorization machinery. Conditions differ in who can replace the historical reference evidence.

| Condition | Historical evidence and keys | What the experiment permits the operator to do |
| --- | --- | --- |
| A. Operator controls all records | Only operator-provided history and acknowledgments remain available | Rewrite the archive and every history reference presented with it |
| B. Separate directory, same control | Observer-named files exist separately but their records and keys remain operator-controlled | Rewrite both the archive and those observer files, including replacement signatures |
| C. Independently retained evidence, separately pinned keys | The model preserves previously observed signed commitments outside the operator's attack scope and uses verification keys pinned separately from its bundle | Rewrite its archive and publisher output, but not uncompromised observers' retained evidence or pinned keys |

The matched attacks keep the original election anchor, roster, manifest, and guardian/voter verification material unchanged to compare like with like. C uses the separately retained election anchor. A and B read those parameters from the operator's publication; their consistency checks do not independently authenticate them. Their detection of a damaged ciphertext or a counterfeit voter signature therefore describes these attacks under the original parameters, not protection against also replacing the entire anchor or roster. Authentic election parameters are a prerequisite, not a historical completeness guarantee. If a real observer accepts a replacement anchor from the same malicious operator, the experiment's assurance does not apply.

## What a witness signs, and what an offline verifier checks

The witness layer uses conventional SHA-256 commitments and Ed25519 signatures through the existing maintained `cryptography` library. Election encryption and proofs remain the pinned ElectionGuard implementation; no replacement cryptographic construction is introduced.

The evidence must commit to the election scope and encrypted history, and bind each checkpoint to its predecessor and sequence. A signature answers who made a statement under a pinned key. The separately retained history answers whether that statement agrees with what an observer previously saw. A signature alone does not establish that its signer observed honestly, that the signer is independent, or that an old checkpoint is current.

The standalone verifier consumes exported public artifacts and retained evidence as files. It does not ask the election operator's database or API whether they are correct. It checks ElectionGuard ballot and decryption proofs and recomputes the tally. It also compares signed history statements with the evidence supplied by observers. Missing independent evidence must be reported as a weaker result, never silently promoted to proof of completeness.

Conflicting histories can be exposed only when authentic statements from the relevant views are brought together or compared with a retained reference. An isolated observer shown one internally consistent view cannot infer another hidden view. Conflicting authentic signatures establish inconsistency; they do not, by themselves, identify which observer lied or which history is correct. Under the one-observer compromise model, the interpretation still relies on another observer having honestly observed and retained the relevant history. Likewise, an authentic old checkpoint proves an earlier state, not the freshness of the current state, unless later evidence has been retained.

## Attack outcomes

`DETECTED` means the supplied artifacts let the implemented checks establish a contradiction or an integrity failure. It is detection, not prevention, recovery, or identification of a human attacker. `NOT DETECTED` means the attack leaves a view accepted by the applicable checks, including a deliberately demonstrated negative control. `INCONCLUSIVE` means the parsed evidence bundle lacks required trustworthy observations, so the verifier cannot establish the claimed continuity. A file that cannot be opened or parsed instead produces a CLI input error, not a structured attack verdict. A corrupt signature can establish an artifact integrity failure without proving who caused it; generic rejection is not automatically proof of an operator attack.

The executed matrix contains 51 rows: 11 attacks and six controls, each in A, B, and C. For each scenario the attack record hash is identical across the three conditions. The table below reports the actual outcomes. Every row assumes correct verification software and reused cryptographic implementations. Historical detections additionally require authentic observer key pins and honestly retained relevant observations.

Two evidence-removal checks are recorded for every case. `without_independent_evidence` removes C's pinned trust and retained history while keeping whatever checkpoint statements the operator supplied. `without_any_witness_statements` additionally removes those supplied statements, leaving the existing archive/tally checks under the original election parameters. In the final column, “both” means both checks returned the stated outcome.

| Attack | A | B | C | Evidence exposing the problem; party that must remain trustworthy | C after evidence removal |
| --- | --- | --- | --- | --- | --- |
| `delete-accepted`: remove an acknowledged ballot and compute a valid 99-ballot tally | NOT DETECTED | NOT DETECTED | DETECTED | Retained signed 100-ballot heads disagree with the valid 99-ballot archive; at least one honest observer must retain the original observation. | Both NOT DETECTED |
| `alter-ballot`: damage recorded ciphertext-linked data after signing | DETECTED | DETECTED | DETECTED | Existing voter-signed payload no longer matches the encrypted ballot; the original voter verification key and authorization binding must be authentic. C also sees a commitment mismatch. | Both DETECTED |
| `replace-ballot`: substitute a valid ciphertext but sign as the voter with the operator key | DETECTED | DETECTED | DETECTED | Existing verifier rejects the counterfeit voter signature; voter key custody and the original roster must be trustworthy. Witnesses add no necessary protection for this attack. | Both DETECTED |
| `rewrite-history`: reorder valid entries and re-sign operator acknowledgments; preserve the same 100-ballot aggregate | NOT DETECTED | NOT DETECTED | DETECTED | Retained signed record commitments disagree with the rewritten exact archive, despite valid election proofs; an honest observer must retain the prior ordering. | Both NOT DETECTED |
| `conflicting-histories`: show observers different valid orderings of the same ballot set | NOT DETECTED | NOT DETECTED | DETECTED | Compared authentic observer heads contain different record commitments; the relevant independently retained views must reach the verifier. Signatures alone do not identify which view is correct. | Both NOT DETECTED |
| `forge-checkpoint`: substitute observer key declarations and sign replacement checkpoints with an operator-held key | NOT DETECTED | NOT DETECTED | DETECTED | Published keys differ from separately pinned keys, and signature verification under those pins fails; authentic out-of-band pins must remain trustworthy. | Both NOT DETECTED |
| `replay-checkpoint`: present a genuinely signed checkpoint for another election | DETECTED | DETECTED | DETECTED | The checkpoint's election scope disagrees with the archive's anchor; authentic election scope and correct scope checking are required. Outside custody is not necessary to reject this malformed use. | DETECTED with supplied statements; NOT DETECTED with no witness statements |
| `rollback-checkpoint`: present an authentic 99-ballot predecessor in place of the later 100-ballot state | NOT DETECTED | NOT DETECTED | DETECTED | The older valid checkpoint and matching archive disagree with retained sequence-2 heads; an honest observer must preserve the later head. | Both NOT DETECTED |
| `suppression-before-observation`: suppress a submission before acknowledgment or observation | NOT DETECTED | NOT DETECTED | NOT DETECTED | No acknowledgment or independent observation exists to expose the attempted submission. Honest observers can only attest to the 99 ballots they actually saw. | Both NOT DETECTED |
| `observer-lost`: delete an accepted ballot after losing one observer's evidence | NOT DETECTED | NOT DETECTED | DETECTED | Observer 2's surviving authentic 100-ballot head contradicts the valid 99-ballot archive; that remaining observer must be honest. Observer 1's missing evidence is also reported. | Both NOT DETECTED |
| `observer-compromised`: delete a ballot and obtain one observer's false endorsement | NOT DETECTED | NOT DETECTED | DETECTED | Observer 2's retained head disagrees with the archive and observer 1's validly signed lie; at least one observer must remain honest and retain its evidence. The signatures do not attribute which observer lied. | Both NOT DETECTED |

The C-only detections did not depend on invalid election cryptography: their `crypto_valid` result was `true`. The subset tally, reordered archive, forged-key publication, rollback archive, and single-observer failure cases were all mathematically consistent election archives. C exposed a contradiction with the separately held record, rather than assuming the operator's claimed totals were true. A and B were indistinguishable in their outcomes because moving rewriteable records into another directory did not change the attacker capability.

The checkpoint-forgery case intentionally gives A and B control of the advertised observer keys. It is stronger than corrupting a signature byte: a fully replaced key declaration and matching fresh signature are internally valid there. C rejects the substitution against the pin. The ordinary invalid-signature control below confirms that all conditions still reject a literally bad signature under the key they are checking.

| Executed control | A | B | C | What it establishes |
| --- | --- | --- | --- | --- |
| `honest` | NOT DETECTED | NOT DETECTED | NOT DETECTED | Unchanged valid history produces no contradiction. |
| `idempotent-replay` | NOT DETECTED | NOT DETECTED | NOT DETECTED | Re-presenting the same authentic checkpoint for the same state is harmless; not every replay is an attack. |
| `isolated-equivocation` | NOT DETECTED | NOT DETECTED | NOT DETECTED | The explicit single-observer policy sees one internally consistent fork and cannot infer an unseen second view. |
| `observer-lost-honest` | NOT DETECTED | NOT DETECTED | INCONCLUSIVE | One surviving head matches the unchanged archive, but the default two-observer evidence coverage is incomplete. Removing independent inputs yields NOT DETECTED in both checks. |
| `all-observers-lost` | NOT DETECTED | NOT DETECTED | INCONCLUSIVE | The valid smaller archive supplies no historical contradiction when all outside observations are missing. Removing independent inputs yields NOT DETECTED in both checks. |
| `invalid-signature` | DETECTED | DETECTED | DETECTED | The supplied checkpoint's malformed signature fails verification. Keeping that statement still detects it without independent custody; discarding all witness statements leaves a valid archive and NOT DETECTED. |

One surviving honest head is sufficient to detect a mismatch it actually covers. It is not sufficient to certify that two observers agree: the default C policy requires both observers' retained evidence, and an unchanged archive with one missing observer is therefore inconclusive. The tests separate those claims rather than treating missing coverage as proof of a malicious operator.

The suppression control is essential: if the operator drops a submission before any trustworthy acknowledgment or independent observation, an abstention and an unacknowledged suppression produce the same public evidence. Knowing that the synthetic script attempted 100 submissions is test-harness knowledge, not a publicly verifiable acknowledgment. The experiment must not smuggle that knowledge into the verifier as an implicit expected count.

The unchanged-history controls passed all conditions, and the valid-subset and authentic-old-history cases became NOT DETECTED when retained later evidence was removed. Literal ciphertext damage and operator impersonation of a voter remained detected by existing authorization checks in every condition. The reordering and conflicting-history cases preserved the ballot set and plaintext aggregate so they tested history continuity without revealing a ballot through subtraction of adjacent totals.

## Privacy and receipt boundary

Witness public receipts are aggregate commitments to encrypted records, not individual choice receipts. They must export no individual plaintext selection, decryption key, encryption nonce or opening, or digest of an unencrypted choice. Hashing a choice from a two-option contest would not hide it. The witness layer does not need a new per-voter identity-to-choice artifact.

An aggregate record commitment alone does not certify a particular voter's selection or provide an opening with which to prove that choice. This is a narrow property of the exported witness artifact, **not a claim of cryptographic receipt-freeness**. The base public archive has synthetic participation links and encrypted ballot references; the local simulator sees all fake choices and holds all private role keys. A compromised device can retain randomness, reveal credentials, or show its choice to a coercer. Guardians with enough secret material can decrypt individual ballots. Small, unanimous, or otherwise inferable aggregate totals can disclose choices. Publishing both a 99-ballot and a 100-ballot plaintext tally, together with the identity of the extra ciphertext, can reveal that ballot's selection by subtraction. The experiment must avoid presenting adjacent subset tallies as a privacy-preserving public product. Those paths are not solved by a witness receipt.

Coercion and vote buying remain explicitly unsolved. The lab cannot honestly guarantee that no information available to a malicious device, colluding party, or observer could ever be used by a buyer. It instead keeps the new public witness artifacts free of choices and openings and stops at this bounded continuity experiment. Do not use the demo with real voters.

## Unsolved risks and trust requirements

- **Pre-observation suppression and denial of service:** witnesses cannot prove an event none of them observed. They cannot force acceptance, publication, recovery, or availability.
- **Compromised voter devices:** valid ciphertexts and signatures do not prove the vote matches a voter's intended selection. Malware can change a choice before it reaches the observed record.
- **Coercion and vote buying:** witnesses do not secure a voter device, stop credential transfer, prevent observation by a coercer, or make Internet voting safe.
- **Observer loss, compromise, and collusion:** continued detection requires at least the honest retained evidence specified by the tested policy. If all trustworthy reference evidence is lost or replaceable, the operator can again present a consistent rewrite. A dishonest observer can lie about its own observation.
- **Key authenticity and freshness:** a key supplied only inside the operator's bundle is not a separately pinned key. An authentic older signature is not proof that no newer accepted history existed.
- **Equivocation visibility:** an observer must receive or compare the conflicting signed views. Hidden views, withheld evidence, and network partitions can keep a contradiction from the verifier.
- **Enrollment, guardian custody, and implementation flaws:** the roster is synthetic; guardians are colocated; the producer and verifier share dependencies. Authentic election parameters, correct cryptography, safe parsing, and uncompromised verification software remain prerequisites.
- **Real custody and operations:** no independent organizations, hardware, ceremonies, recovery procedures, legal process, or election certification are demonstrated by separate local directories.

See [THREAT_MODEL.md](THREAT_MODEL.md) for the unchanged baseline threat analysis. Internal tests are not an independent security audit.

## Reproduce and review

Install the pinned dependencies as described in [README.md](../README.md), then run the experiment in a fresh directory:

```sh
.venv/bin/python -m vote_lab witness-demo --out artifacts/witness-001-rc
.venv/bin/python -m vote_lab witness-verify \
  --publication artifacts/witness-001-rc/operator/C/publication.json \
  --trust artifacts/witness-001-rc/observer-custody/pinned-trust.json \
  --retained artifacts/witness-001-rc/observer-custody/retained-evidence.json
```

The default export is the `rewrite-history` attack: one 100-ballot archive and tally. The C verification command is therefore expected to report `DETECTED` and exit `1`; it is a demonstration of attack detection, not a failed installation. The demo does not overwrite an existing output directory. To export an unchanged-history control from a new fictional election, use `--export-case honest` and a different `--out` path. The full generated matrix is in `results.json` and does not publish per-case plaintext totals.

The offline verifier emits `NOT DETECTED` with exit `0`, `DETECTED` with exit `1`, or `INCONCLUSIVE` with exit `3`. A zero exit means no contradiction was found in the supplied evidence; it does not prove that no attack happened. Argument errors exit `2`. Leave off `--trust` and `--retained` only when intentionally checking the weaker operator-provided view.

The public witness receipts sign the domain, election/anchor hash, observer identity, sequence, previous checkpoint hash, phase, record commitment, and ballot count. The `closed` phase refers to a sealed exported snapshot: sequence 1 is the earlier 99-ballot snapshot and sequence 2 is the later 100-ballot snapshot. It is not a real election-close procedure or permission to reopen a binding election. Freshness comes from an observer's retained latest head, not the operator's clock.

The default export includes `operator/A/publication.json`, `operator/B/publication.json`, and `operator/C/publication.json`. B's extra observer directory remains under `operator/`. C's `observer-custody/` directory holds public pinned-trust and retained-history inputs, plus each observer's aggregate commitment receipts. These paths illustrate custody assumptions; putting them beside each other does not enforce independence. Only a single selected archive/tally is exported. Do not combine exports of adjacent plaintext subset tallies into a privacy claim.

The actual research run exported its 51-row result matrix to `artifacts/witness-001-rc/results.json`. The source tests reproduce the attack constructions, custody comparison, evidence removal, parsing/signature boundaries, and negative controls. Run the current full suite and dependency check:

```sh
.venv/bin/python -m pytest -q
.venv/bin/python -m pip check
```

See [WITNESS-001-RELEASE.md](WITNESS-001-RELEASE.md) for executed test totals, extracted-archive validation, the new 0.1.1rc1 archive, and checksum instructions. Those new results are separate from the historical 0.1.0rc1 validation; the baseline report and archive remain preserved.

The deliverable is a local release candidate for review. No public deployment, release publication, GitHub push, real electorate, real election credentials, binding election, external ballot submission, blockchain, phone voting, or production platform is part of WITNESS-001. External API spending remains **$0**.

## Existing-system comparison and stopping rule

ElectionGuard already supplies ballot and tally verification primitives, and Helios already uses ballot trackers and publicly verifiable encrypted elections. Belenios already describes retaining and checking audited bulletin-board history. The baseline [research report](RESEARCH.md#what-was-studied) links the pinned upstream sources and documents those precedents. Standard signed records, monitored boards, pinned keys, and outside custody are established techniques.

WITNESS-001 established that this composition detects the specified observed-history attacks when authentic outside references remain available; A/B storage labels alone did not. It also established the negative cases: unobserved suppression and an unseen conflicting view remain undetectable, and lost required evidence can make the result inconclusive. This is a meaningful demonstrated trust-boundary difference, not a new cryptographic election guarantee or a reason to add OpenLine receiver grants. The experiment stops at its tested candidate and this answer. It provides no basis for claiming a novel voting protocol or expanding into a voting platform.
