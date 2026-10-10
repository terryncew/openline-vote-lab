# OpenLine Vote Lab: research findings

**Experimental, fictional, and nonbinding.** This is a local research demonstration for 100 synthetic voters. It is not election administration software or evidence that Internet voting is safe. There are no real identities, government connections, external ballot submissions, paid APIs, or public deployment.

## Research question and conclusion

Can existing election cryptography let an observer check a published tally while keeping individual choices out of the public record? Yes, subject to important assumptions: the observer needs authentic election parameters, correct cryptographic implementations, and an independently retained record of which ballots were accepted. ElectionGuard and Helios already address these requirements in their respective workflows.

Does receiver-owned authorization or signed records establish a new voting guarantee? This experiment does not identify one. Scoped grants, public credentials, ballot signatures, receipts, and witnessed records can improve authorization checks and accountability around an election implementation. These are established techniques. Belenios, a derivative of Helios-C, already combines public credentials, signed ballots, separate roles, and a monitored public board.

The useful contribution here is a small, inspectable demonstration of those boundaries, including failures that remain detectable after an operator bypasses its normal admission checks. Any assertion that OpenLine introduces a new election security property would need a concrete protocol specification, a stronger comparison, and independent analysis. None is established here. Stop at this experiment and its review candidate; there is no evidence to justify a larger platform on a cryptographic novelty claim.

## What was studied

Research uses public upstream source and documentation. Source downloads were free; no paid external API was used. Dates below describe observed source revisions, not a certification or a promise of ongoing maintenance.

| Project | Upstream evidence | Relevant result |
| --- | --- | --- |
| ElectionGuard Python | [Pinned README](https://github.com/Election-Tech-Initiative/electionguard-python/blob/a9753841f5082d1c35bdc1b053aade74778662b7/README.md), revision `a9753841f5082d1c35bdc1b053aade74778662b7`, dated July 9, 2026 | A reference implementation with encrypted ballots, proofs, guardian decryption, public election artifacts, and verifier building blocks. This revision advertises specification **0.95.0**; do not describe this lab as conforming to the newest ElectionGuard specification. |
| Helios | [Pinned source](https://github.com/benadida/helios-server/tree/88621e3196961ec03fe54bbd3a1c2196e715e9a2), revision `88621e3196961ec03fe54bbd3a1c2196e715e9a2`, dated August 15, 2026 | Browser ballot encryption, ballot trackers, validity proofs, homomorphic tallying, trustee decryption proofs, and public verification. |
| Belenios | [README](https://github.com/glondu/belenios/blob/bda080d3866366c4815232f02eee4c262c83e428/README.md) and [protocol specification](https://github.com/glondu/belenios/blob/bda080d3866366c4815232f02eee4c262c83e428/doc/specification.tex), revision `bda080d3866366c4815232f02eee4c262c83e428` | A direct precedent for separating an administrator from a credential authority, validating signed ballots against public credentials, retaining one final ballot per credential, and monitoring a public board. |

ElectionGuard is reused for election encryption and proofs; this lab does not implement replacement cryptographic equations. Ed25519 signatures use an established cryptographic library. Application code specifies what data is signed and how records are checked; that protocol composition still requires review.

Helios was studied rather than embedded as a second application. Its [homomorphic workflow](https://github.com/benadida/helios-server/blob/88621e3196961ec03fe54bbd3a1c2196e715e9a2/helios/workflows/homomorphic.py) exposes ballot verification, accumulation, decryption factors, and proof verification. Its full [server installation](https://github.com/benadida/helios-server/blob/88621e3196961ec03fe54bbd3a1c2196e715e9a2/INSTALL.md) needs a Django application, PostgreSQL, and RabbitMQ; it is larger than this local experiment needs. The source retains older compatibility choices, including SHA-1 proof challenge functions in [the cryptographic implementation](https://github.com/benadida/helios-server/blob/88621e3196961ec03fe54bbd3a1c2196e715e9a2/helios/crypto/algs.py). Activity in an upstream repository is useful evidence of maintenance, not assurance that every historical construction meets a current deployment requirement.

## What existing systems already accomplish

Encryption lets the public inspect ciphertexts without reading individual selections. Proofs let observers check that an encrypted ballot follows election rules and that disclosed decryption results are consistent with the encrypted tally. A ballot tracker binds a voter's retained reference to an encrypted ballot. These mechanisms are already present in ElectionGuard and Helios.

ElectionGuard's [cast/spoil workflow](https://github.com/Election-Tech-Initiative/electionguard-python/blob/a9753841f5082d1c35bdc1b053aade74778662b7/docs/3_Cast_and_Spoil.md) separates counted ballots from challenged ballots, and its [publication documentation](https://github.com/Election-Tech-Initiative/electionguard-python/blob/a9753841f5082d1c35bdc1b053aade74778662b7/docs/5_Publish_and_Verify.md) lists the manifest, election context, guardian records, encrypted ballots, and tally artifacts used for verification. A cryptographically valid ballot alone does not prove that its submitter was eligible; eligibility and accepted-ballot policy belong to the surrounding system.

Helios's [models](https://github.com/benadida/helios-server/blob/88621e3196961ec03fe54bbd3a1c2196e715e9a2/helios/models.py) retain the latest valid vote for each voter, so recasting is permitted while only one final vote is counted. This lab uses a simpler policy: the first accepted ballot spends a synthetic voter's eligibility, and a second submission is rejected. That policy is an experimental choice, not an improvement over recasting policies.

Belenios's audit specification explicitly checks ballot proofs and signatures against public credentials, then retains only the last ballot for each credential. It also tells auditors to retain previously audited boards and check their continuity. Signed authorization and retained records therefore have a clear existing precedent.

The [Helios FAQ](https://github.com/benadida/helios-server/blob/88621e3196961ec03fe54bbd3a1c2196e715e9a2/server_ui/templates/faq.html) explicitly recommends against high-stakes public-office Internet elections because home computers and coercion remain serious risks. This lab adopts that boundary.

## The experiment's trust boundaries

The election contains 100 fake voter pseudonyms and a small fictional contest. Each synthetic voter has an Ed25519 key. A frozen, separately retained configuration anchors the roster, election manifest, verification keys, and election scope. A ballot signature binds the voter's key to that election and the encrypted ballot's hash. The admission policy and public verifier both enforce eligibility and one counted ballot per voter.

ElectionGuard encrypts the selections and creates the proofs. Two simulated guardians provide a 2-of-2 decryption workflow. Only the aggregate is intentionally decrypted. Public artifacts contain encrypted ballots and verification material, without voter signing keys, guardian private keys, or a table associating fake identities with choices.

The browser is a control panel for a **local simulator**. The server holds all synthetic secrets and sees the simulated selections before encryption. Both guardians, the witness, the registrar, the operator, and the voters share the same local machine. The demonstration therefore does not establish browser-to-operator secrecy, independent guardian custody, or actual separation of organizational authority. Public-record privacy is a narrower claim than secrecy from this server.

An observer verifies an exported record against a separately retained anchor and signed closure checkpoint, optionally checking retained voter receipts. The verifier recomputes and checks the evidence without calling the election server. This is independent of the operator's tally calculation, but it still depends on authentic inputs, the verifier, and the reused cryptographic implementation. An independently developed verifier would provide stronger implementation diversity.

## What tampering means here

| Attempt | Evidence the verifier needs | Limit of the claim |
| --- | --- | --- |
| Insert an unauthorized ballot | Frozen roster and valid voter signature | A registrar that changes the roster before it is independently accepted can authorize fake voters. |
| Count a voter twice or duplicate a ballot | Roster policy and uniqueness checks over all counted ballots | A credential is a synthetic eligibility slot, not proof of a unique real person. |
| Alter ciphertext or its election scope | Ballot hash/signature and ballot proof checks | A compromised device can sign a different valid selection before acceptance. |
| Publish invalid ballot or decryption proofs | Cryptographic verification of the public artifacts | A verifier bug or shared dependency flaw can undermine detection. |
| Change reported totals | Recomputed encrypted tally and checked decryption evidence | Verification establishes consistency with included valid ballots, not free voter intent. |
| Remove a ballot and recompute an otherwise valid tally | A retained receipt or independently retained closure checkpoint | An archive alone cannot distinguish an omitted vote from abstention. |
| Replace the whole election or show different histories | Authentic anchor and independently retained/checkable checkpoints | No single operator-provided archive authenticates its own history. |

Automated tests are bounded demonstrations of selected attacks, not proofs of universal security. Consult the release validation results for which cases were actually executed. No test claim should be inferred solely from the design above.

## Optional OpenLine-inspired comparison

No formal OpenLine receiver-owned authorization specification or maintained integration was supplied with this repository. The optional mode is an explicitly labeled **model** of the idea: a receiver grants an election-scoped capability to an eligible synthetic voter, and the operator signs its ballot acceptance record. It is not interoperability with a deployed OpenLine system.

An honest comparison checks both modes against the same attacks and the same authentic configuration. Baseline voter signatures already bind the ballot to the voter and election. An optional receiver/election/voter grant makes the authorization decision explicit; an operator signature makes acceptance attributable when a receipt is retained. Both protections depend on keys held outside the compromised party being modeled. A signature made by a dishonest operator does not make its tally true.

These additions may be useful integration or audit features. They do not improve election encryption, prove eligibility beyond the trusted roster, restore an omitted ballot, prevent coercion, secure a voter device, or ensure service availability. Publicly signed pseudonymous ballots also create participation links that deserve privacy review. Belenios's credential-signature model and established signed audit logs already provide comparable ideas.

## What the candidate can and cannot establish

The candidate can provide reproducible evidence that the implemented verifier rejects specified invalid records, that a public encrypted record can support tally verification, and that retained external evidence changes which operator manipulations become detectable. A valid test run is an implementation result under stated assumptions.

It cannot establish safe Internet voting, coercion resistance, trustworthy voter intent, real-world eligibility, secure key custody, honest guardians, or a novel cryptographic protocol. It has not had independent cryptographic or security review. Before any expansion, reviewers should examine the signed message formats, parsing boundaries, frozen configuration, proof coverage, key lifecycle, witness assumptions, and the distinction between application checks and cryptographic checks. [The threat model](THREAT_MODEL.md) explains the remaining risks.
