# Security Review — gRPC VPC Lattice Reference Architecture

**Last reviewed:** 2026-11-05
**Scope:** this repository — backend, proxy-sdk (Option 1), proxy-envoy (Option 2)

## What this is

A record of the hardening applied to this reference architecture, the bugs it
fixed, and the limitations that remain. It is written for a reviewer who wants
to know what was checked, what was proven by running it, and what was
deliberately left as-is.

Changes were made as a **diff on working code**, not a rewrite: the
architecture, proto contracts, signing approach, and request flow are unchanged
from the version that was validated end to end. The hardening is limited to
correctness fixes, input validation, error handling, container hardening, and
dependency pinning.

Two design decisions worth stating up front, because they explain what is
*absent*:

- **There is no SigV4 sidecar option.** An earlier iteration included a third
  proxy based on `aws-sigv4-proxy`. It was removed because running gRPC over
  HTTP/1.1 is not recommended, and signing sidecars for gRPC generally use
  Envoy.
- **The backend tier is two services, not three** (User Service and Order
  Service). Each of the two signing options is authorized for exactly one of
  them, which is what makes per-service authorization demonstrable.

---

## Verification performed

| Check | Result |
|---|---|
| Python syntax (`py_compile`) — backend, proxy-sdk | Pass |
| Envoy config YAML parse | Pass |
| `envsubst` templating renders valid YAML, no unsubstituted vars | Pass (endpoint injected in all 4 required places) |
| Shell syntax (`sh -n`, `bash -n`) — entrypoint, build script | Pass |
| gRPC frame prefix size (`struct.calcsize('>BI')` == 5) | Pass |
| Header sanitization checked against CRLF / NUL / control characters | Pass |

### Verified by deployment and end-to-end testing

The template was deployed and the full request path exercised with real gRPC
clients. These are observed results, not inferences from configuration.

| Check | Result |
|---|---|
| Container images build for `linux/amd64` (all three) | Pass |
| Stack deploys clean (85 resources), all ECS services steady, all targets healthy | Pass |
| Token issuance via `client_credentials`, RS256, `token_use=access` | Pass |
| TLS ALPN negotiates `h2` at the ALB — gRPC over HTTP/2, no downgrade | Pass |
| Absent token, malformed token, and **tampered signature** each rejected 401 at the ALB | Pass |
| Authenticated request to an unrouted gRPC package returns 404 at the listener default | Pass |
| SDK path reaches the User Service; JWT `client_id` echoed back by the backend | Pass |
| Envoy path reaches the Order Service; Lua decoder forwards **real** claims | Pass |
| A second client identity propagates distinctly end to end | Pass |
| Unsigned request with forged identity headers is denied by the service network policy | Pass |
| Valid signature from the wrong task role is denied by VPC Lattice: neither `SdkTaskRole`'s IAM policy nor the Order Service auth policy allows it | Pass |
| ALB target groups `Protocol: HTTPS`, `ProtocolVersion: HTTP2`: all proxy targets healthy over HTTPS, SDK proxy logs `tls=enabled`, full matrix including cross-role passes (7/7), and replacement tasks start with no NAT gateway | Pass |
| TLS certificate and key handling, verified against the deployed stack: the running proxy image layers contain no certificate or private key created by this sample (only OS and library CA bundles and the stock GnuTLS self-test vectors). Each of the 4 proxy tasks had a unique ECDSA P-256 certificate issued at container start. The SDK proxy has no private key on disk, writes only the public certificate to `/tmp/tls-cert.pem` (0644), and runs as `appuser`. Envoy's `/tmp/tls` is 0700, its `key.pem` and `cert.pem` are 0600 `envoy:envoy`, and the process runs as `envoy`. The key never appears in the task definitions or in CloudWatch Logs | Pass |
| Proxy logs contain no token material | Pass |

Two behaviours found during that testing are worth recording, because both
contradict a reasonable assumption:

- **For gRPC traffic, a VPC Lattice authorization denial arrives as HTTP 200
  with `grpc-status: 7`** (`PERMISSION_DENIED`, carrying `AccessDeniedException`)
  — *not* as HTTP 403. The same unsigned request sent with a non-gRPC
  content type returns HTTP 403. Any check that inspects only the HTTP status
  code will read a gRPC denial as a success.
- **gRPC server reflection is enabled on the services but is not reachable
  through the ALB.** Its path matches no listener rule, so it falls through to
  the default action. See known limitation 2.

### Not verified

- **gRPC streaming end to end on the Envoy path.** The filter configuration
  supports it, but every test exercised unary calls only.
- **Behaviour against a non-conforming identity provider** (non-RS256, or a
  private JWKS endpoint). The RS256 and public-JWKS constraints are stated by
  ALB and were satisfied here, not probed with a failing provider.
- **JWKS size and key-count limits.** Documented by ALB; never approached in
  testing.
- **Expired-token handling as a scripted case.** Short token lifetimes were in
  effect and expiry was observed incidentally, but it is not an asserted test.

---

## Bugs found and fixed

### In the original baseline code

| # | Sev | Component | Issue | Fix |
|---|-----|-----------|-------|-----|
| 1 | High | proxy-sdk | Internal error detail leaked to gRPC clients (`context.abort(..., f"Lattice call failed: {e}")`) — exposes upstream topology and exception internals across the trust boundary | Generic client-facing messages; detail stays in server logs |
| 2 | High | proxy-sdk | JWT decode exception logged with full message (`log.warning("...: %s", e)`) — could write token fragments to CloudWatch | Log `type(exc).__name__` only |
| 3 | High | proxy-sdk | No size limit on the `Bearer` header before base64/JSON decode — memory-exhaustion vector | `MAX_JWT_LENGTH` (16 KB) guard pre-decode, and again post-decode |
| 4 | High | proxy-sdk | `grpc_unframe` returned `data[5:]` without validating the declared length — a frame header claiming more bytes than received causes a bad read | Validate `len(data) >= 5 + length` before slicing |
| 5 | High | proxy-envoy | Lua JWT decoding fell back to a **hardcoded** `"envoy-extracted"` client id and a hardcoded scope instead of the real claims — meaning VPC Lattice auth policies would have evaluated fabricated identity | Replaced with a pure-Lua base64 decoder that extracts the real `client_id`/`scope`/`sub`. Regression-tested end to end: the backend echoes the actual Cognito client id |
| 6 | High | proxy-envoy (both) | Admin interface bound to `0.0.0.0:9901` — exposes config dump, stats, and `/quitquitquit` shutdown to the whole subnet | Bound to `127.0.0.1` |
| 7 | Med | proxy-envoy (both) | No upstream TLS certificate validation, so the connection to VPC Lattice was open to a man-in-the-middle (MITM) attack | `trusted_ca` set to the system CA bundle; `ca-certificates` installed |
| 8 | Med | proxy-sdk | No startup validation — empty `LATTICE_USER_SVC` produced malformed URLs and cryptic runtime failures | `_validate_config()` fails fast with a clear message |
| 9 | Med | proxy-sdk | HTTP status not checked before gRPC unframing — attempted to parse HTML/JSON error bodies as protobuf | Check `status_code != 200`; map HTTP→gRPC status codes |
| 10 | Med | all | No graceful shutdown — in-flight RPCs dropped on ECS task stop (SIGTERM) | SIGTERM/SIGINT handlers with configurable grace period; backend also flips health to NOT_SERVING first so it drains |
| 11 | Med | all | Containers ran as root | Non-root users (`appuser`, `grpc`, `envoy`) |
| 12 | Med | proxy-sdk | New botocore session per request | Cached session (credentials still auto-refresh via the task role provider) |
| 13 | Med | proxy-sdk | Unbounded httpx connections | `httpx.Limits` (100 max, 20 keepalive) |
| 14 | Low | proxy-envoy | Region hardcoded to `us-east-1` | `${AWS_REGION}`, validated at startup |
| 15 | Low | all | Ports/timeouts/workers hardcoded | Environment-configurable with sane defaults |
| 16 | Low | proxy-sdk | Transitive deps unpinned (`h2`, `httpcore`) | Pinned |
| 16b | Low | proxy-envoy | Base image used the **floating** tag `envoyproxy/envoy:v1.31-latest`, so two builds of the same source could ship different Envoy binaries | Pinned by immutable manifest digest to an exact patch release (originally `v1.31.10`; now `v1.39.1`, see *Base image currency*). Python images were already pinned to `3.12.8-slim` |
| 17 | Low | all | Single-stage Dockerfiles kept `grpcio-tools` in the runtime image | Multi-stage; build tooling excluded from runtime |
| 18 | Low | proxy-envoy | `match_excluded_headers` missing `x-envoy` prefix | Added |
| 19 | Low | proxy-envoy | No access logging | JSON structured stdout access log incl. `grpc_status`, `x-client-id`, duration |
| 20 | Low | proxy-envoy | No connection/stream limits | Circuit breakers, `max_concurrent_streams`, header count/size caps, slow-loris timeout |

### Found during re-review of the hardened version

Worth recording — these were introduced during hardening and caught on
re-review, not present in the baseline:

| # | Sev | Component | Issue | Fix |
|---|-----|-----------|-------|-----|
| 21 | **High** | backend | Container `HEALTHCHECK` used `grpc.ssl_channel_credentials()` with the **default system trust store** against a **self-signed** certificate — TLS verification can never succeed, so the image health check could never pass. The container would report unhealthy under `docker run`, and under ECS too if a reader copied the check into a task-definition `healthCheck`. ECS ignores an image `HEALTHCHECK` that the task definition does not declare, and none of this template's task definitions declares one ([container health checks](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/healthcheck.html)) | Backend now exports its public certificate to `CERT_EXPORT_PATH` (`/tmp/tls-cert.pem`, public cert only — never the private key); health check uses it as the trust anchor with `ssl_target_name_override=localhost` matching the certificate subject alternative name (SAN) |
| 22 | **High** | proxy-envoy | `HEALTHCHECK` used `wget`, which is **not present** in the `envoyproxy/envoy` base image, so the image health check could never pass. The container would report unhealthy under `docker run`, and under ECS too if a reader copied the check into a task-definition `healthCheck`. ECS itself ignores the image `HEALTHCHECK`, because the task definition declares none | Install `curl` explicitly; health check uses `curl -fsS` |
| 23 | Low | proxy-sdk, backend | Health checks hardcoded ports while the listener port is env-configurable — a changed `LISTEN_PORT`/`GRPC_PORT` would silently break the check | Health checks read the same env vars as the server |
| 24 | Low | proxy-sdk | Health check had no per-call timeout — could hang rather than fail | `timeout=3` on the health RPC |

### New hardening added beyond the original review

| # | Sev | Component | Issue | Fix |
|---|-----|-----------|-------|-----|
| 25 | **Med** | proxy-sdk | JWT claim values were used directly as outbound header values with only length truncation. These become `x-client-id`/`x-client-scope`/`x-client-sub`, which are **covered by the SigV4 signature and evaluated by VPC Lattice auth policies**. A claim containing CR/LF is a header-injection vector; control characters could cause a signature/parse mismatch | `_sanitize_header_value()` strips everything outside printable US-ASCII (0x20–0x7E) and length-bounds. Unit-tested against CRLF, NUL, tab, and legitimate scope URLs |
| 26 | Low | proxy-sdk | `_grpc_unframe` ignored the compressed-flag byte — compressed payload bytes would be handed to the protobuf parser | Reject frames with a non-zero compression flag (this proxy never negotiates `grpc-encoding`) |
| 27 | **Med** | proxy-envoy | The Lua filter had neither of the guards finding 25 added to `proxy-sdk`: claims went straight from the JWT into `x-client-id`/`x-client-scope`/`x-client-sub` with no CR/LF or control-character filtering, and there was no size limit before base64-decoding — and the pure-Lua decoder concatenates in a loop, so an oversized token costs real CPU per request. It also stripped seven characters off `authorization` without checking the `Bearer` prefix, so `Basic …` was accepted as a bearer token | Added `sanitize_header_value()`, which strips everything outside printable US-ASCII (0x20–0x7E) and length-bounds to the same limits as `proxy-sdk` (256 / 1024 / 256), a `MAX_JWT_LENGTH` check before and after decoding, and a literal `Bearer ` prefix test. Both proxies now enforce identical bounds |
| 28 | **Med** | proxy-envoy | Claims were extracted with `string.match` against the raw decoded JSON, which matches the **first** occurrence anywhere in the payload. A same-named key nested inside another object — `{"meta":{"client_id":"evil"},"client_id":"legit"}` — resolved to the nested value. Not reachable with Cognito `client_credentials` claims, all of which are issuer-generated, but unsafe as published guidance for any IdP where a claim is user-influenced. Note that anchoring the pattern to a `{` or `,` delimiter does **not** fix this: a nested key is itself preceded by `{` | Replaced the pattern match with `json_top_level_string()`, a single-pass scan that tracks nesting depth and string state and only accepts a key at depth 1. JSON escapes are decoded, so an escaped `\n` becomes a real newline and is then stripped — matching `json.loads` plus `_sanitize_header_value()` on the SDK side. Verified against nested-object, nested-array, deep-nesting, truncated-payload and non-JSON inputs |

---

## Known limitations (documented, not fixed)

These are inherent to the design and are called out in code comments so a
reviewer isn't surprised by them.

### 1. gRPC status may be trailer-only on the SDK path

`httpx` does not expose HTTP/2 trailers via `response.headers`. When VPC
Lattice or the backend returns `grpc-status` in trailers rather than
headers, the SDK proxy's status check sees its `"0"` (OK) default.

**Why this is still safe:** an error response carries no valid gRPC
message body, so the unframe + protobuf-parse validation rejects it and
returns an error to the caller. The body validation — not the status
check — is the authoritative error path. The status check still fires when
`grpc-status` arrives in headers. VPC Lattice sends its policy denials that
way, as HTTP 200 with `grpc-status: 7` (`PERMISSION_DENIED`).

**If strict trailer inspection is required:** use a real gRPC client for
the outbound call instead of a raw HTTP/2 client. The Envoy option
(Option 2) does not have this limitation.

This is also *why* the blog states the SDK approach is unary-only.

### 2. gRPC server reflection is enabled on the services

The backend and the SDK proxy enable reflection so `grpcurl` works without a
local `.proto` file, which is useful when first exploring the deployment from inside
the VPC.

**It is not externally reachable in this topology.** Reflection is served at
`/grpc.reflection.v1alpha.ServerReflection/...`, which matches neither the
`/sdk.*` nor the `/envoy.*` listener rule, so it falls through to the ALB
listener default action. Verified: unauthenticated reflection is rejected 401,
and with a valid token it is still not routed — so external service enumeration
is not possible.

Reflection remains enabled deliberately. **Disable it for production**, where
callers reach services directly rather than through a path-routed ingress and
the default-action safety net does not apply.

### 3. Proxy inbound TLS uses a self-signed certificate

The ALB re-encrypts to the proxies: both ALB target groups use
`Protocol: HTTPS` with `ProtocolVersion: HTTP2`, so the JWT in the
`authorization` header is encrypted on the ALB-to-proxy hop as well as from
the client to the ALB. Each proxy generates an ephemeral ECDSA P-256
self-signed certificate at startup and offers ALPN `h2` only. The SDK proxy
does this in code and keeps the private key in memory. The Envoy entrypoint
uses `openssl` from the base image and writes the key under `/tmp/tls` with
mode `0600`, owned by the non-root `envoy` user. Self-signed is sufficient
because the ALB does not validate target certificates
([target groups](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-target-groups.html)), so there is no certificate authority, stored secret,
or rotation. The proxy still runs in a private subnet whose security group
only admits the ALB's security group.

### 4. Backend TLS uses a self-signed certificate

Required and sufficient: VPC Lattice target groups with
`ProtocolVersion: GRPC` require `Protocol: HTTPS` on the target, and
**VPC Lattice does not validate target certificates**. A self-signed cert
satisfies the protocol requirement without introducing certificate
management. Confirmed by deployment: both Lattice target groups run
`Protocol: HTTPS` with `ProtocolVersion: GRPC` and all targets report healthy.

The **ALB** target groups follow the same model with `Protocol: HTTPS` and
`ProtocolVersion: HTTP2` (see limitation 3).

### 5. JWT signature is not re-verified at the proxy

Deliberate. The ALB `jwt-validation` action has already validated
signature, `exp`, and `iss` — invalid tokens never reach the proxy. The
proxy decodes claims only. Re-verifying would require JWKS fetching and
caching in the proxy, adding latency and failure modes for no security
gain.

### 6. ECS Exec is enabled on all services

`EnableExecuteCommand` is set on all four ECS services so the deployment can be
inspected from inside the VPC — this is how the unsigned/forged-header check is
run, since VPC Lattice DNS resolves to link-local addresses that are not
reachable from outside.

It is an interactive access path into running tasks, gated by IAM. **Disable it
for production**, or restrict `ecs:ExecuteCommand` to a break-glass role. The
template notes this inline at the task role definitions.

### 7. There is no automated unit test suite

Verification was done by static checks plus end-to-end testing against a real
deployment (`test-auth-matrix.sh`). The header-sanitization behaviour described
in finding 25 was exercised ad hoc during development rather than committed as
a repeatable test, so there is no artifact in this repository that re-runs it.

For a reference architecture this is a reasonable trade — the end-to-end script
covers the security properties that matter and is runnable by anyone who
deploys. Stated explicitly so a reviewer is not left looking for a test
directory that does not exist. Adding unit tests for `_sanitize_header_value`
and `_grpc_unframe` would be the highest-value additions.

### 8. The proxy containers do not use a read-only root filesystem

Setting `readonlyRootFilesystem` would further harden both proxy containers,
but this sample does not enable it because
[ECS Exec](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-exec.html)
does not support a read-only root filesystem, and the verification steps use
ECS Exec. Production deployments that do not need ECS Exec can enable it on the
proxy containers and mount a writable `/tmp`. Fargate
[bind mounts](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/bind-mounts.html)
default to mode 0755 owned by root, so the image's `/tmp` ownership must allow
the non-root user (`appuser` or `envoy`) to write.

---

## Reviewer notes

Items a reviewer may reasonably raise, recorded here rather than left implicit.

**`Resource: '*'` in the VPC Lattice auth policies.** Three auth policies
(`NetworkAuthPolicy`, `UserSvcAuthPolicy`, `OrderSvcAuthPolicy`) use
`Resource: '*'`. A scanner looking for over-permissive IAM will flag these, so
the reasoning is recorded here.

These are **resource-based** policies, attached via `ResourceIdentifier` to one
specific service network or Lattice service. In that position `Resource: '*'`
means "the resource this policy is attached to" and cannot widen scope beyond
the attachment point. Authorization is carried by the `Principal`, which is
pinned to a single task role ARN in each per-service policy:

| Policy | Attached to | Principal |
|---|---|---|
| `NetworkAuthPolicy` | service network | both task roles, plus a source-VPC condition |
| `UserSvcAuthPolicy` | User Service | `SdkTaskRole` only |
| `OrderSvcAuthPolicy` | Order Service | `EnvoyTaskRole` only |

The result is the 1:1 mapping this sample exists to demonstrate. A request
signed by the wrong role reaches the service and authenticates successfully as
a valid IAM principal. Two independent layers then deny it: the role's own IAM
policy allows `vpc-lattice-svcs:Invoke` only on its mapped service, and the
per-service auth policy admits only the other role. VPC Lattice requires an
explicit allow from both
([how authorization works](https://docs.aws.amazon.com/vpc-lattice/latest/ug/auth-policies.html)).
That deny path is exercised by `test-auth-matrix.sh`, which shows that the
request is denied but not which layer denied it.

The identity-based `Resource: '*'` entries elsewhere in the template are for API
actions that do not support resource-level permissions, and each carries an
inline comment saying so.

**Container registry posture.** **Every base image reference resolves to Amazon
ECR**, and all five are pinned by immutable manifest digest.

| Image | Source | Credentials needed |
|---|---|---|
| Python ×4 (builder + runtime across two Dockerfiles) | `public.ecr.aws/docker/library/python:3.12.8-slim` | None — ECR Public allows anonymous pulls |
| Envoy ×1 | `<account>.dkr.ecr.<region>.amazonaws.com/docker-hub/envoyproxy/envoy:v1.39.1` via **Amazon ECR pull through cache** | Docker Hub read-only token, in Secrets Manager |

The Python image is byte-identical to the Docker Hub official image (both
`sha256:2199a62885a12290dc9c5be3ca0681d367576ab7bf037da120e564723292a2f0`), so
sourcing it from ECR Public changed the source of truth without changing the
artifact.

**Envoy is not published to any registry that allows an anonymous pull.**
Verified against the live registries rather than assumed: `envoyproxy/envoy`,
`docker/library/envoy` and `envoy/envoy` all return `NAME_UNKNOWN` on
`public.ecr.aws`; Envoy is absent from Quay (401 where a control repository
returns 200) and from `registry.k8s.io` (paths resolve but return `"tags":[]`).
Envoy is a vendor image rather than a Docker *official* image, so the
`/docker/library/` mirror does not cover it. The one AWS-published Envoy image,
`public.ecr.aws/appmesh/aws-appmesh-envoy`, was considered and rejected: AWS App
Mesh reaches [end of support on September 30,
2026](https://docs.aws.amazon.com/app-mesh/latest/userguide/doc-history.html),
and its current tags are on Envoy **1.34**, a minor line that itself reached end
of life on 2026-04-15 — five minor versions behind the pin used here — so
adopting it would mean moving onto unsupported Envoy deliberately.

`proxy-envoy/Dockerfile` therefore references Envoy through an **Amazon ECR pull
through cache in the deploying account**. `build-and-push.sh` creates the cache
rule and its credential secret if absent, verifies the pinned digest resolves
through the cache, and rewrites the placeholder registry in the Dockerfile to the
caller's own account and Region at build time. The committed Dockerfile therefore
references Amazon ECR, never Docker Hub, and the reader never hand-edits it.

**What the cache does and does not achieve.** It means the image is served from a
registry the deploying account controls, is scanned by that account's tooling,
falls under its lifecycle policies, and is insulated from Docker Hub rate limits
and outages after the first pull. It does **not** change the bytes — the same
content still originates at Docker Hub on the first pull — and it adds **no**
integrity guarantee beyond what the digest pin already provides. The digest is
verified by the container engine regardless of which registry served the image,
so a digest-pinned pull from Docker Hub and one through the cache are
equivalent on integrity. This was confirmed empirically: an image built through
the cache is **bit-identical** to one built directly from Docker Hub, producing
the same manifest digest.

Docker Hub is contacted **once**, at build time, on the machine running
`build-and-push.sh`. It is not in the deploy path and not in the runtime path —
Amazon ECS pulls only from the account's own private registry.

**Credential handling.** The Docker Hub token is stored in an AWS Secrets Manager
secret named `ecr-pullthroughcache/docker-hub`, encrypted with the default
`aws/secretsmanager` key (Amazon ECR requires that key for these secrets and does
not support a customer managed key). `build-and-push.sh` offers four modes, two of
which mean the script never handles a token at all (`--skip-ptc` and
`--credential-arn`). When it does prompt, the token is not echoed, is written
only to a `0600` temporary file, and never reaches the process list, the
environment or shell history. The README documents rotating the secret **value in
place** rather than deleting and recreating it, because the cache rule stores the
secret's ARN.

**Recommended token posture:** a **read-only** token (pulling a public image
needs `Read` only, not `Write` or `Delete`), with an expiry set, and an
**Organization Access Token** rather than a personal one where a Docker
organization exists — [Docker recommends OATs for proxy and CI/CD use](https://docs.docker.com/enterprise/security/access-tokens/)
so shared infrastructure does not depend on an individual's credentials.

**Residual considerations.** The pull through cache adds a long-lived third-party
credential to the deploying account, and Secrets Manager has no managed rotation
for Docker Hub credentials — so a short expiry and a manual refresh are the
realistic controls. Readers in accounts with Service Control Policies denying
`ecr:CreateRepository` or `ecr:BatchImportUpstreamImage` will find that cache
pulls fail even after the rule is created; the build script names this explicitly
in its failure output.

The three images this project *builds* are unaffected — `build-and-push.sh`
pushes them into the deploying account's own ECR with image scanning enabled, and
the template takes their URIs as parameters.

**Base image currency.** The Envoy base image is pinned to `v1.39.1`, the newest
release on a supported minor line as of 2026-08-29. Envoy maintains roughly the
last 12 months of minor releases
([support window](https://endoflife.date/envoy)), so **any pin will eventually
fall out of support if left unattended** — this one previously sat on `v1.31.10`,
which had been end-of-life since 2025-07-19.

Digest pinning is deliberate: it makes the bytes tamper-evident and the build
fail closed if upstream content changes. The trade-off is that security patches
are **not** picked up automatically. Two consequences for anyone using this
sample:

- **Before deploying,** check [Envoy releases](https://github.com/envoyproxy/envoy/releases)
  and move to the newest supported patch, then re-run `test-auth-matrix.sh`.
- **For anything long-lived,** automate the bump rather than relying on a manual
  review. Dependabot updates both the tag and the digest for the
  `image:tag@sha256:...` form used here.

**Direct dependencies and the security-relevant transitives are pinned exactly;
a few remaining transitives are not.** `certifi` was previously a floating
minimum (`>=2024.8.30`) so that the CA trust bundle used to validate the TLS
connection to VPC Lattice stayed current. It is now pinned exactly, along with
`h11`, `h2`, `hpack`, `hyperframe`, `httpcore`, `urllib3` and `idna`, so that a
rebuild resolves the same versions a scan was run against.

Be precise about what that does and does not achieve. Pip still resolves
`anyio`, `jmespath`, `python-dateutil`, `six`, `sniffio` and `typing_extensions`
freely, so this is **not** a fully locked dependency graph — a lock file
(`pip-compile`, or committed `pip freeze` output) is what would make that claim
true. And pinning `certifi` means the trust bundle only advances when the pin is
bumped, which makes automated dependency updates the compensating control rather
than an optional nicety.

**Container images are not published.** The template requires image URIs as
parameters with no defaults, and `build-and-push.sh` builds into the deploying
account's own ECR with `scanOnPush` enabled. There is no dependency on a
third-party registry at deploy time beyond the base images.

---

## Trust boundary summary

```
External client  ──TLS──▶  ALB              (validates JWT: sig, exp, iss)
                              │
                              │ HTTP/2 + TLS (self-signed), private subnet, security-group-restricted
                              ▼
                           ECS proxy         ◀── TRUST BOUNDARY
                                                 external identity (JWT)
                                                 → internal identity (SigV4)
                              │
                              │ HTTP/2 + TLS + SigV4 (verified certs)
                              ▼
                        VPC Lattice          (validates SigV4 → IAM principal,
                              │               evaluates auth policies)
                              │ HTTP/2 + TLS
                              ▼
                        Backend gRPC         (trusts x-client-* because they
                                              arrived via a verified path and
                                              were inside SignedHeaders)
```

Controls at each layer:

- **ALB** — JWT signature/claims validation; rejects with 401 before any
  compute is consumed
- **Proxy** — no static credentials (ECS task role only); claims
  sanitized before becoming signed headers; least-privilege task role
  scoped to one VPC Lattice service
- **VPC Lattice** — SigV4 signature validation; service network auth
  policy (2 allowed roles + `x-client-id` presence) plus per-service auth
  policy (exactly 1 role each)
- **Backend** — TLS; input validation; sanitized logging

The identity headers are inside `SignedHeaders`, so they cannot be
modified in transit without invalidating the signature. This is what
makes them safe for the backend to trust and for auth policies to
evaluate.

---

## Pre-deployment checklist

- [ ] SDK proxy task role has `vpc-lattice-svcs:Invoke` scoped to the **User Service ARN only**
- [ ] Envoy proxy task role has `vpc-lattice-svcs:Invoke` scoped to the **Order Service ARN only**
- [ ] `LATTICE_USER_SVC` set on the SDK proxy task definition (service will exit 1 if unset)
- [ ] `VPC_LATTICE_ENDPOINT` and `AWS_REGION` set on the Envoy task definition (entrypoint will exit if unset)
- [ ] `SERVICE_NAME` differentiates the two backend deployments (`user-service`, `order-service`)
- [ ] `GRPC_PORT=50051` on backend task definitions to match the existing Lattice target groups
- [ ] Proxy security group (SG) admits only the ALB SG on the proxy port
- [ ] Backend SG admits the VPC Lattice managed prefix list on 50051
- [ ] VPC association SG admits TCP 443 from the VPC CIDR — omitting this causes proxy-to-Lattice connections to time out with no clear error
- [ ] ECR image scanning enabled (`build-and-push.sh` sets `scanOnPush=true`)
- [ ] CloudWatch log retention set (≤ 30 days for a demo)
- [ ] No secrets in task definition environment variables (credentials come from the task role)
- [ ] Consider disabling gRPC reflection before any production use

---

## Files

```
.
├── .gitignore
├── LICENSE                     # MIT-0
├── README.md                   # deploy and test instructions
├── SECURITY-REVIEW.md          # this document
├── build-and-push.sh           # 3 images; ECR scanOnPush; finch/docker
├── test-auth-matrix.sh         # end-to-end verification, incl. cross-role deny
├── cfn/
│   └── grpc-lattice-sigv4-demo.yaml   # complete environment, 85 resources
├── proto/
│   ├── demo.proto              # backend contract (package demo)
│   ├── sdk_service.proto       # SDK proxy inbound (package sdk)
│   └── envoy_service.proto     # Envoy proxy inbound (package envoy)
├── backend/                    # deployed 2x: User Service, Order Service
│   ├── .dockerignore
│   ├── Dockerfile              # multi-stage, non-root, TLS-aware healthcheck
│   ├── requirements.txt
│   └── server.py
├── proxy-sdk/                  # Option 1: Native AWS SDK signing
│   ├── .dockerignore
│   ├── Dockerfile              # multi-stage, non-root, env-aware healthcheck
│   ├── requirements.txt        # runtime + pinned transitive deps
│   └── server.py
└── proxy-envoy/                # Option 2: Envoy signing filter
    ├── .dockerignore
    ├── Dockerfile              # non-root envoy user, curl healthcheck
    ├── docker-entrypoint.sh    # validates env vars, generates the self-signed TLS certificate, envsubst templating
    └── envoy.yaml              # Lua JWT decode → SigV4 → router
```
