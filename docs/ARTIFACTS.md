# Public artifact and verification boundaries

This format is specific to the fixed fictional contest and is not an ElectionGuard standard export format. ElectionGuard objects are serialized by the pinned upstream implementation. The surrounding signatures and commitments use conventional Ed25519 and SHA-256 from established implementations.

All signed payloads have a distinct `domain` string. Canonical bytes are ASCII JSON with sorted keys, compact separators, escaped non-ASCII characters, and no nonfinite numbers. Signatures are Base64 Ed25519 signatures of those exact bytes. SHA-256 hashes use the same canonical bytes. JSON booleans and numbers are distinct; the parser rejects duplicate JSON fields. This serialization is a local format, not an assertion of compatibility with RFC 8785 or an OpenLine protocol.

The trusted anchor contains the election ID, mode, exactly 100 distinct synthetic voter public keys, receiver and witness public keys, and the crypto configuration. The crypto configuration contains the fixed manifest, standard group constants, public guardian commitments/proofs, and derived election context. Verification binds all of those values. The anchor has no self-authentication magic: an observer must establish its authenticity outside the supplied archive.

A public accepted ballot consists of an `entry` and a signed `receipt`. The entry has voter and opaque ballot identifiers, an ElectionGuard CAST ballot, and voter authorization. Receiver mode adds a signed capability for that receiver/election/voter public key and a maximum of one counted ballot. Voter authorization includes election ID, anchor hash, voter ID, ballot ID, and encrypted ballot hash. The receipt binds those identifiers, the hash of the complete entry, and its consecutive acceptance sequence. It is an operator acknowledgement, not proof of honest operator conduct.

The public record contains its schema, election ID, anchor hash, accepted ballots, and tally. The tally includes the recomputable encrypted aggregate, two guardian decryption shares with proofs, reported totals, and ballot count. The verifier recomputes the aggregate and decrypts the aggregate from publicly verifiable shares; it does not decrypt individual ballots. It checks reported totals only after that computation.

The separately retained witness checkpoint signs election ID, anchor hash, complete record hash, and counted-ballot quantity. It commits the entire closed archive, including tally artifacts. This models evidence retained by an honest witness, but the simulated witness shares the same process as the operator. A real independent witness would need authentic observation, separate key custody, and retained history, none of which this prototype establishes.

Voter receipts may be retained separately and compared with the archive. Public records already include receipts, but a receipt inside a rewritten record alone cannot demonstrate the old history. Retaining one missing receipt can expose that acknowledged omission; retaining only some receipts does not establish completeness for every voter.

The supported format omits secrets, nonces, write-ins, and optional unproved contest metadata. It exposes voter pseudonyms and participation links to ciphertexts; it is not an anonymous participation format. Aggregate disclosure and colocation of all private roles remain material privacy limits.

The standalone verifier requires a checkpoint by default. Explicit archive-only verification checks a consistent authorized ballot set and tally and reports `completeness: false`. Valid signatures and proofs cannot distinguish a retallied valid subset from an election in which omitted voters abstained. Deletion detection depends on authentic evidence outside that subset.
