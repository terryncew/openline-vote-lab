# Contributing to OpenLine Vote

This repository is a small, synthetic-only research demonstration. Contributions should make its evidence easier to inspect, reproduce and understand. It is not a real ballot collection service.

Use Python 3.12 and the exact dependencies in `requirements.lock`. Follow the README setup, run the relevant tests, and include the observed results with your proposed change. Keep experimental records and labels explicit.

Preserve the historical ElectionGuard adapter, witness reports, negative controls and release archives. A new result belongs in a new documented experiment; it must not rewrite WITNESS-001 or WITNESS-002. Do not replace live proof checks with simulated success messages.

Do not commit credentials, signing keys, witness stores, real voter information, real election records or adjacent original/subset plaintext tally pairs. Use synthetic data only. Document what an attack detects, its evidence and trust assumptions, and cases it does not detect.

Changes to cryptographic composition require independent security review before stronger claims. Improvements to presentation must distinguish recording, inclusion, cryptographic tally verification and genuine external custody. No test can certify separate administrators merely because files live in separate directories.

Public hosting, release publication, external custody tests and spending require the project owner's approval. Proposed hosting instructions must explain actual resources and costs; do not assume a free tier or provision accounts on someone else's behalf.

Contributions are provided under the repository's Apache-2.0 license. The current source URL is https://github.com/terryncew/openline-vote-lab. No pull request or issue is required to run the local research demonstration.
