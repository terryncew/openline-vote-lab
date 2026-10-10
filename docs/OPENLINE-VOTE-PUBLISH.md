# OpenLine Vote: publication and hosting runbook

OpenLine Vote is a fictional, nonbinding research demonstration. This runbook
prepares publication; it does not authorize a GitHub push, a public listener, a
deployment, or external custody testing. Obtain the project owner's explicit
approval before any of those actions. No paid API or hosting account is needed
to build or run it locally.

The public experience uses the existing ElectionGuard implementation. It does
not change the preserved WITNESS-001 or WITNESS-002 findings. Actual independent
custody is **INCONCLUSIVE**. The same-account isolation control **FAILED**.

## What can be free, and what a public link requires

GitHub can host the approved open-source repository and static documentation.
GitHub Pages cannot execute this Python application or its live ElectionGuard
checks. Publishing screenshots or a static frontend on Pages would not make a
working voting demonstration.

The live demo needs these resources:

| Requirement | Why it is needed |
| --- | --- |
| A publicly reachable, already authorized Linux machine or a genuinely free Python/container host | Python performs real ballot encryption, tally/proof checks, and the attack experiments. No public host is supplied by this repository. |
| Python 3.12 and the exact `requirements.lock` dependencies | ElectionGuard and `gmpy2` require the tested native runtime. Linux x86-64 is the supported validation target; other architectures are unverified. |
| One application process | Browser elections are held in process memory. Multiple workers or replicas need persistence and session routing that this prototype does not implement. |
| An HTTPS address, with its hostname explicitly allowed by the app | Phones need a reachable link; HTTPS protects the connection to the demonstration. A TLS reverse proxy must preserve the original `Host` header. |
| Bounded CPU and RAM, with no promise of continuous availability | Cryptographic work is computationally expensive. The app limits concurrent work and sessions; overload is a documented limitation. |
| Network access for the initial free dependency downloads | Runtime verification does not call a paid service or external API. |

A pilot machine with two CPU cores and 2 GiB of RAM is a conservative starting
configuration, not a demonstrated capacity guarantee. Use the measured timings
and resource observations in the [publication-readiness report](OPENLINE-VOTE-READINESS.md) to set traffic
expectations. The default app allows at most 16 ephemeral browser sessions,
sets a 30-minute cookie, expires inactive state after 30 minutes during request
cleanup, uses one cryptographic worker, and bounds pending work. This is not
secure key erasure. Restarting the process discards its in-memory fictional
elections; separately saved public exports survive.

An existing machine, an existing hostname, and a free TLS certificate can satisfy
the hosting requirements without new spending. A hostname or provider account
has not been provisioned or verified for this project. Do not promise that a
named provider's current free plan has the required memory, native wheels,
background CPU time, or terms. If no suitable free authorized machine is
available, the exact remaining requirement is **one reachable Python 3.12/Linux
host plus an approved HTTPS hostname or HTTPS tunnel**. A tunnel's owner and
provider become part of the privacy and availability boundary.

## Local developer setup

Run from the repository root:

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python -m pip check
.venv/bin/python -m vote_lab.demo_server
```

The new experience defaults to `http://127.0.0.1:8001`. Its WSGI runner uses
the already locked `gevent.pywsgi`; it does not enable Flask's debug server or
monkey-patch Python's threading. The original loopback research control panel
remains available through `.venv/bin/python -m vote_lab serve` on port 8000.

The browser needs no signup, account, real identity, or API key. It receives a
temporary opaque cookie for its own fictional election. The server receives the
selected **fake** choice before encryption and holds all simulated guardian and
voter keys. The visitor's phone does not perform independent voting encryption.
Public receipt/export payloads omit choices, private keys, and ballot openings;
that does not establish receipt-freeness or protection against vote buying.

## Local container build and review

The dedicated ignore file permits only the source, tests, documentation, exact
dependency list, README, license, and packaging metadata into the build context.
It excludes `.git`, `.venv`, `artifacts`, local witness stores, and private keys.
Derived validation summaries under `docs/openline-vote/validation` stay outside
the image because they describe the built image rather than its runtime inputs.
The image runs as UID/GID 10001. It does not include the retained research keys
or original release evidence bundles.

```sh
docker build -f Dockerfile.demo -t openline-vote:local .
docker run --rm --init --name openline-vote-local \
  --read-only --tmpfs /tmp:rw,nosuid,noexec,size=64m \
  --cap-drop ALL --security-opt no-new-privileges \
  --memory=2g --cpus=2 \
  -p 127.0.0.1:8001:8001 openline-vote:local \
  python -m vote_lab.demo_server --host 0.0.0.0 --port 8001
```

The image's default command binds to `127.0.0.1` inside the container. The
explicit command above opts into `0.0.0.0` inside the container so Docker's
port mapping can reach it; the published host port remains `127.0.0.1` only.
This does not make the demo public. Use a second terminal to check the response and then complete the
three-stage browser flow:

```sh
curl --fail http://127.0.0.1:8001/
```

Save the record, anchor, checkpoint, and receipts from the demo's evidence
downloads. From the root of an independently installed checkout, run the
existing verifier, replacing `/path/to/public-evidence` with the saved files'
directory:

```sh
.venv/bin/python -m vote_lab verify \
  --record /path/to/public-evidence/openline-vote-record.json \
  --anchor /path/to/public-evidence/openline-vote-anchor.json \
  --checkpoint /path/to/public-evidence/openline-vote-checkpoint.json \
  --receipts /path/to/public-evidence/openline-vote-receipts.json
```

This recomputes the cryptographic checks without a database or API. Obtain the
anchor and witness key authentically, and retain the checkpoint outside the
operator's authority, before relying on completeness. Downloading all inputs
from one operator after an attack supplies consistency checks under those
inputs; it does not establish an independently trusted history. The browser
demonstration does not establish that external custody.

The Python base image tag and OS package mirrors can change. The application
dependencies and ElectionGuard revision are pinned, but this Dockerfile is not
a byte-reproducible supply-chain lock. Record the built image ID and base-image
digest when reviewing an approved deployment; do not describe them as the
historical 0.1.2rc1 source archive. Do not rebuild or overwrite that archive.

If an environment requires an existing outbound proxy, Docker does not always
inherit it. Pass the standard variable names with `--build-arg HTTP_PROXY
--build-arg HTTPS_PROXY --build-arg http_proxy --build-arg https_proxy`; do not
write proxy values or credentials into this Dockerfile. Build-time networking
does not require exposing an application port.

For a TLS-inspecting environment that already trusts an administrator-provided
public CA bundle, the Dockerfile accepts the optional BuildKit mount
`--secret id=build_ca,src=/etc/ssl/certs/ca-certificates.crt`. The mounted bundle
is used only by the dependency-install steps and is absent from the runtime
image. This is a bundle of public trusted certificates, not a private key. The
default build on ordinary public TLS needs no override. Never disable
certificate verification or copy proxy credentials into the image. This cloud
environment additionally needed host networking and a build-time hostname
mapping for its existing outbound proxy; those are environment-specific build
settings, not public listener settings.

The separate validation image includes tests; the default demo image does not.
After the free build-time downloads, the validation run can have networking
disabled:

```sh
docker build -f Dockerfile.demo --target validation -t openline-vote:validation .
docker run --rm --network none --read-only \
  --tmpfs /tmp:rw,nosuid,noexec,size=512m \
  --cap-drop ALL --security-opt no-new-privileges \
  openline-vote:validation
```

## Public host preparation, after explicit deployment approval

This example assumes an existing authorized machine, Docker, a TLS reverse
proxy, and an approved hostname `demo.example.org`. Replace the example with
the real approved hostname. Do not execute it merely because this runbook exists.

```sh
docker run --detach --init --name openline-vote-demo \
  --restart unless-stopped \
  --read-only --tmpfs /tmp:rw,nosuid,noexec,size=64m \
  --cap-drop ALL --security-opt no-new-privileges \
  --memory=2g --cpus=2 \
  -p 127.0.0.1:8001:8001 \
  -e OPENLINE_ALLOWED_HOSTS=demo.example.org \
  -e OPENLINE_COOKIE_SECURE=1 \
  openline-vote:local \
  python -m vote_lab.demo_server --host 0.0.0.0 --port 8001
```

This explicitly opts into a container-internal listener while preserving the
loopback-only host port mapping. The image's default listener remains loopback.
Keep the application port private. Terminate TLS with an existing trusted
reverse proxy and preserve `Host: demo.example.org`. For example, an approved
Caddy installation on that same machine can use:

```caddyfile
demo.example.org {
    reverse_proxy 127.0.0.1:8001
}
```

Point the approved domain at the host, permit HTTPS and the certificate
challenge required by the selected proxy, and keep HTTP redirection at the
proxy. The app's secure cookie must be enabled for HTTPS. The application
accepts only explicitly allowed hostnames and same-origin POSTs. Do not add a
wildcard host, `ProxyFix`, public Flask debug mode, or unbounded worker replicas.

TLS is connection protection, not secure internet voting. The operator, reverse
proxy, hosting administrator, and any tunnel provider can observe traffic.
The app does not ask for personal information or add analytics, external fonts,
advertising, or paid API calls. Hosting access logs may record IP addresses and
user agents; review or disable unnecessary access logs under the host owner's
policy. Never log request bodies or the synthetic selections. No real election
credentials or submissions are permitted.

Check the approved HTTPS page on a phone. Verify cookie `Secure`/`HttpOnly`,
the host/origin rejection checks, exports, keyboard navigation, and the honest
and tampered results. Check the capacity-exceeded response. A browser result
does not establish that the server honestly ran its code; export the public
evidence and run the verifier independently.

## Release checks before approval

Use a fresh directory or a clean checkout. The core tests need neither paid
services nor a browser:

```sh
.venv/bin/python -m pytest -q
.venv/bin/python -m pip check
git diff --check
git status --short
```

Use the [publication-readiness report](OPENLINE-VOTE-READINESS.md) for the exact browser command, installed
browser requirements, screen recording, and completed test counts. These are
internal validation results, not independent security or accessibility review.

The real 30-second walkthrough can be reproduced from a running local demo:

```sh
python scripts/record_walkthrough.py \
  --url http://127.0.0.1:8001 --out artifacts/walkthrough-new
```

Use the Python interpreter that has Playwright installed. This optional script
requires local Playwright/Chromium, `ffmpeg`, `ffprobe`,
and a usable local font; they are not required by the demo server. Its caption
discloses shortened processing waits. It records genuine cryptographic results
and retains the raw recording and clip intervals. Review the generated media
before separately approving public upload. No synthetic result is prewritten
for the recording.

Keep the original release archives and their checksums unchanged. Verify each
from its own directory:

```sh
(cd artifacts/release && sha256sum -c SHA256SUMS)
(cd artifacts/release-0.1.1rc1 && sha256sum -c SHA256SUMS)
(cd artifacts/release-0.1.2rc1 && sha256sum -c SHA256SUMS)
```

Review the files to be published. Public retained evidence must contain no
private keys or guardian shares beyond the intended public proof statements,
no encryption nonces, no raw witness stores, no real identities, and no
before/after deleted-subset plaintext tally pair that would expose one fake
choice by subtraction. Review every staged path; do not use a blind `git add .`.

Apache-2.0 remains the repository license. Upstream dependencies retain their
own licenses. The source repository remains
`https://github.com/terryncew/openline-vote-lab`; the product name does not imply
that a repository rename, DNS name, published release, or live endpoint exists.

## GitHub publication, after explicit push approval

No push, PR, release tag, or hosted workflow execution is performed by this
runbook. After the owner approves the reviewed local commit, check its exact
identity and remote before using these commands:

```sh
git log -1 --oneline
git status --short
git remote -v
git push origin HEAD:refs/heads/openline-vote-demo
```

Then open a review against `main` at:

`https://github.com/terryncew/openline-vote-lab/compare/main...openline-vote-demo`

The review description should identify the fictional demo, unchanged
ElectionGuard adapter and historical archives, verified test results,
**INCONCLUSIVE** real custody, **FAILED** shared-account isolation, and the
remaining privacy/coercion/device/suppression risks. Do not turn expected attack
detection into a claim of prevention. Do not claim turnout benefits or
certification. Approval to push source does not by itself authorize a live demo
deployment, a release publication, or an external custody experiment.

Before an approved live deployment, make sure the demo's source link resolves
to the reviewed implementation. Merge the approved source review, or link the
demo to its exact published commit if serving an approved review branch. Record
that commit and the local image ID. Do not present the original repository's
placeholder `main` branch as the source of a newer live demonstration.

## What the public demonstration can establish

Visitors can see real checks of synthetic encryption, recorded-ballot
references, inclusion, and tally/proof evidence. In the attack scene, authentic
previously retained commitments can expose a contradictory later archive.
That is detection under supplied evidence and trusted keys. All simulated
roles still share the application administrator's authority.

Suppression before any trustworthy acknowledgment or witness observation can
remain undetected. Hidden conflicting views need comparison. Lost evidence,
untrusted key pins, compromised observers, and a dishonest application can
remove the demonstration's assurance. Compromised phones, coercion, vote
buying, denial of service, and binding election administration remain unsolved.

The separately administered experiment is still pending. Follow
[WITNESS-002's external-test runbook](WITNESS-002-EXTERNAL-TEST.md) only after
its administrators, authentic pin exchange, and authorization have actually
been established. Publishing this demo is not that experiment.
