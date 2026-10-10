# Threat model

**Research only.** All voters, credentials, ballots, and elections are synthetic. A successful verification means the supplied evidence passed particular checks. It does not mean an election was fair, that people were eligible, or that remote voting is safe.

## Assets and assumptions

The lab tries to preserve three things: the public record's confidentiality of individual selections; consistency between accepted encrypted ballots and the disclosed aggregate; and evidence of unauthorized, duplicated, changed, or omitted accepted ballots.

The reference setup assumes an authentic frozen roster and manifest, authentic verification keys, secure randomness, correct reused cryptographic libraries, and independently retained anchors or checkpoints. An observer must keep the reference evidence separately from an archive they want to verify. Choosing a fresh anchor delivered by the same potentially dishonest operator does not establish authenticity.

Each of 100 synthetic voters has one eligibility slot and one signing key. These are fake identities. The lab does not decide who is a real person or how a real electorate should be registered. Two synthetic guardians model a 2-of-2 tally-decryption policy, and a synthetic witness signs the closed record. These roles all run locally in the same process or machine; their independence is modeled, not operationally enforced.

## Attacker capabilities

Tests may give an attacker control over the exported archive or let an election operator bypass ordinary admission checks, recompute an aggregate, change totals, or publish another history. The verifier should still reject a mismatch with authentic voter signatures, proof evidence, roster policy, or retained checkpoints.

That attacker is not assumed to hold every independently pinned signing key. If it also compromises the synthetic voters, registrar, guardians, and witness, those parties cannot provide independent protection. In the actual local simulator, the server holds these secrets; a complete server compromise exceeds the role separation modeled in the tests.

## Detected or rejected under these assumptions

| Attack | Protection | Detection is conditional on |
| --- | --- | --- |
| A key outside the roster submits a ballot | Admission check and public signature/roster verification | An authentic roster retained before the attack |
| A second ballot uses an already spent eligibility slot | First-accepted-vote policy and duplicate checks | A complete accepted record being checked |
| A ciphertext is changed after signing | Hash/signature checks and election proofs | Authentic voter keys and correct byte/record handling |
| A ballot is moved to another election | Election-scoped authorization and signed messages | Authentic election configuration and context checks |
| A proof is invalid or a tally is inconsistent | Proof verification and independent accumulation | Complete verifier coverage and correct cryptographic dependencies |
| A previously accepted ballot disappears | Receipt comparison and/or witness closure checkpoint | Previously retained evidence outside the operator's replacement archive |
| The operator rewrites election configuration or a closed record | Anchor/checkpoint comparison | Authentic external reference evidence |

Rejection of an invalid artifact is **detection**, not recovery. It does not restore a missing ballot, stop a service from suppressing submissions, identify the human attacker, or force anyone to honor a correct result. A signed receipt may support accountability for acknowledged acceptance; it cannot force publication.

An operator can create a mathematically correct tally of a subset of ballots. Without an independently retained receipt or checkpoint, the public record may look valid. This is why record-only verification cannot prove that every attempted or previously accepted vote was included. Likewise, a correct final archive cannot prove that every observer saw the same history throughout voting.

## Threats the prototype does not solve

**Compromised voter devices.** Malware or a malicious browser can replace a selection before encryption, steal a signing key, retain encryption randomness, disclose the choice, or show a false receipt. A well-formed encrypted ballot and valid signature do not prove that the selection matches voter intent. This lab has no independently protected client or full cast-as-intended challenge workflow. Its server intentionally sees simulated selections before encryption.

**Coercion and vote buying.** A coercer can observe the device, require a particular selection, demand credentials, or obtain screenshots and encryption randomness. A buyer can use the same evidence or credential transfer. Ballot encryption and inclusion trackers do not eliminate these risks. First-accepted-vote policy does not make this experiment coercion resistant; it can remove a chance to recast after coercion. The lab makes no receipt-freeness claim.

**Denial of service and selective suppression.** An operator or network attacker can prevent submission, refuse a voter, withhold receipts, close the service, or make verification artifacts unavailable. A verifier can report missing evidence when it has a retained reference. It cannot guarantee delivery or availability, and it cannot prove a vote was accepted before any authentic evidence exists. Rate limits and robustness are operational controls, not a cryptographic solution.

**Malicious registration and stolen credentials.** A dishonest credential authority can enroll fake voters, issue several credentials to one person, or distribute a credential to someone else. A stolen voter key can authorize a valid ballot in that eligibility slot. The frozen synthetic roster lets the lab detect changes to a known roster; it does not validate real-world eligibility. Replacing a receiver-owned grant with another compromised authority merely moves this trust.

**Guardian collusion and key exposure.** Guardians with enough key material can decrypt individual ciphertexts, even if normal code decrypts only the aggregate. A 2-of-2 configuration assumes the relevant secret material does not become available to one adversary. Both guardians are on the same local server in this demonstration, so that isolation is absent. No secure hardware custody, independent ceremony, verified key erasure, or post-compromise confidentiality is demonstrated. Logs, memory snapshots, crash dumps, or backups can retain secrets and plaintexts.

**Witness collusion and equivocation.** A dishonest witness can attest to a manipulated closure, and an operator controlling all reference evidence can replace it together. Authentic retained checkpoints constrain later rewrites; they do not establish an honest initial roster or accepted history. This lab does not deploy distributed witnesses, a consensus service, or an independently operated transparency network.

**Metadata and small-election leakage.** Public pseudonyms, verification keys, signed ciphertexts, and receipts can reveal participation and link a pseudonym across records. They do not provide anonymity. Totals can disclose individual choices when an election is unanimous, groups are tiny, or an attacker knows other voters' choices. Successive tallies or carefully chosen queries can amplify that risk. Encryption does not conceal the aggregate result or information logically implied by it.

**Implementation and supply-chain flaws.** Dependency compromise, insecure randomness, parsing ambiguity, insufficient proof checks, bugs shared by producer and verifier, or malicious verifier delivery can defeat intended guarantees. Reusing upstream algorithms reduces invention risk; it does not validate the application protocol. The lab is not a complete conformance verifier for every ElectionGuard version or record type.

**Social, legal, and operational election integrity.** Cryptography cannot decide who is entitled to vote, stop intimidation away from the device, ensure equal access, resolve disputes, or establish a legally legitimate election. There are no jurisdictional, certification, audit, recovery, or election-administration procedures here.

## Accessibility and usability

The browser demonstration should expose semantic controls, keyboard operation, visible focus, readable contrast, clear error messages, and text labels for verification outcomes. Mobile layout should preserve the same actions and explanations. These are design requirements and should be reviewed with keyboard and screen-reader use; they are not an accessibility certification.

Displaying a cryptographic hash is insufficient usability by itself. Voters and observers need to understand what reference to save, where the reference must be retained, and what a failed check means. A green verification result should describe its scope, including the authentic anchor assumption, without implying freedom from coercion or endpoint compromise.

## Independent review before further work

- Confirm upstream dependency versions, integrity, licensing, and compatibility with the pinned ElectionGuard specification.
- Review signed message formats, election and receiver scope, serialization, duplicate rules, and replay handling.
- Check that every supported ballot and tally proof is verified, all required artifacts are checked, and malformed inputs fail safely.
- Test operator attacks using authentic external references, including a valid recomputed subset and a fully replaced archive.
- Review what secrets and plaintexts remain in memory, files, logs, backups, and exported artifacts.
- Examine guardian, registrar, witness, and voter role separation with adversaries stronger than archive editing.
- Validate keyboard, screen-reader, mobile, error-state, and receipt-retention usability with independent users of synthetic data.
- Prefer an independently implemented verifier for implementation diversity; evaluate any new protocol claim against Helios, ElectionGuard, and credential-signature systems such as Belenios.

No deployment or public security claim is authorized by these documents. The outcome is a local review candidate and a bounded research result.
