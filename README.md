# Authenticate and authorize external gRPC clients with ALB JWT verification and Amazon VPC Lattice

[![License: MIT-0](https://img.shields.io/badge/License-MIT--0-yellow.svg)](https://opensource.org/licenses/MIT-0)

Reference implementation for the AWS blog post *Authenticate and authorize
external gRPC clients with Application Load Balancer JWT verification and
Amazon VPC Lattice*.

External machine-to-machine clients authenticate with JSON Web Tokens (JWTs)
from an identity provider. Amazon VPC Lattice authenticates callers with AWS
Signature Version 4 and authorizes them with IAM auth policies. This sample
builds the ingress layer that bridges the two, without giving external
clients AWS credentials and without breaking gRPC over HTTP/2.

You deploy everything into **your own AWS account**. Nothing is hosted for
you: you build the container images into your own Amazon Elastic Container
Registry (Amazon ECR) repositories and
deploy the CloudFormation template yourself.

> **This is sample code, for non-production usage.** You should work with your
> security and legal teams to meet your organizational security, regulatory and
> compliance requirements before deployment. It ships demo-grade defaults that
> are called out in [Before using this in production](#before-using-this-in-production)
> and recorded in full in [SECURITY-REVIEW.md](SECURITY-REVIEW.md). Do not deploy
> it to a production environment without additional security testing.

## Architecture

```
                                  ┌─────────────────── Ingress VPC ───────────────────┐
 External gRPC client             │                                                   │
 (grpcurl + Bearer JWT)  ──TLS──▶ │  ALB  ──TLS──▶  ECS proxy tier (Fargate)          │
                                  │  (Verify JWT)   ├─ SDK proxy    (SdkTaskRole)     │
        ▲                         │  path routing   └─ Envoy proxy  (EnvoyTaskRole)   │
        │                         └───────────────────────────┬───────────────────────┘
   Amazon Cognito                                             │ HTTP/2 + TLS + SigV4
   (client_credentials)                                       ▼
                                             ┌──── Amazon VPC Lattice service network ────┐
                                             │  validates SigV4 → resolves IAM principal  │
                                             │  evaluates auth policies                   │
                                             │    User Service   ← SdkTaskRole only       │
                                             │    Order Service  ← EnvoyTaskRole only     │
                                             └────────────────────┬───────────────────────┘
                                                                  │ HTTP/2 + TLS
                                  ┌─────────────────── Backend VPC ─┴─────────────────┐
                                  │  gRPC services (Fargate): user-service,           │
                                  │  order-service — echo the identity headers        │
                                  └───────────────────────────────────────────────────┘
```

### Request flow

1. The client obtains a JWT from Amazon Cognito using the OAuth 2.0
   `client_credentials` grant.
2. The ALB validates the token with its `jwt-validation` listener action
   (signature, `iss`, `exp`, and `nbf`/`iat` when present) and routes by gRPC
   package name. Invalid requests
   get HTTP 401 and never reach your compute. Valid requests go to the proxy
   tier over a new TLS connection, as described in
   [TLS between the ALB and the proxies](#tls-between-the-alb-and-the-proxies).
3. The proxy decodes the already-validated JWT, translates claims into
   `x-client-id` / `x-client-scope` / `x-client-sub`, and signs the outbound
   request with SigV4 using its Amazon Elastic Container Service (Amazon ECS)
   task role. The identity headers are inside
   `SignedHeaders`, so they cannot be tampered with in transit.
4. VPC Lattice validates the signature, resolves the caller to an IAM
   principal, and evaluates the service network policy followed by the
   per-service policy.
5. The backend receives the request with trusted identity context and echoes
   it back, which is what lets the tests prove the whole chain worked.

## Two SigV4 signing approaches

Each approach runs as its own ECS service with its own IAM task role, which is
what allows VPC Lattice to tell them apart by workload identity.

### Option 1 — Native AWS SDK signing (`proxy-sdk/`)

Application code signs the request: `botocore` builds the SigV4 signature and
`httpx` sends it over HTTP/2. You get full visibility and can inspect the
request before and after signing. In exchange your code owns credential
retrieval, canonical request construction, and gRPC message framing.

**Unary RPCs only.** The outbound call uses a raw HTTP/2 client rather than a
gRPC client library, so streaming is not supported on this path.

### Option 2 — Envoy signing filter (`proxy-envoy/`)

Envoy's `aws_request_signing` filter signs in the proxy pipeline. A Lua filter
decodes the JWT and rewrites `:authority` and `:path` **before** the signing
filter runs — ordering matters, because a host rewrite after signing produces
`InvalidSignatureException`.

**Supports all gRPC streaming modes**, since HTTP/2 is preserved end to end.
Choose this when you need streaming, already run Envoy, or want L7 features
such as retries and circuit breaking alongside signing.

### Why not `aws-sigv4-proxy`?

The open-source [`aws-sigv4-proxy`](https://github.com/awslabs/aws-sigv4-proxy)
serves plain HTTP on its listening port and is built around HTTP/1.1 request
forwarding. gRPC is defined over HTTP/2: it depends on HTTP/2 framing for
streaming and on trailers for its status. Putting an HTTP/1.1 hop in the path
gives up the properties that make gRPC worth using, so this sample does not
include that pattern. If you want a signing sidecar for gRPC, run Envoy as the
sidecar.

## TLS between the ALB and the proxies

The ALB connects to both proxies over TLS by default. The two ALB target
groups in `cfn/grpc-lattice-sigv4-demo.yaml`, `SdkTg` and `EnvoyTg`, use
`Protocol: HTTPS` with `ProtocolVersion: HTTP2`. The ALB terminates the
client's TLS session, validates the JWT, and opens a new TLS connection to the
proxy task. Both proxies offer Application-Layer Protocol Negotiation (ALPN)
`h2` only, so gRPC stays on HTTP/2, and the
JWT in the `authorization` header is encrypted from the client all the way to
the proxy tier. Health checks also run over TLS (`HealthCheckProtocol: HTTPS`).
The SDK target group sends its HTTP/2 GET probe to
`/grpc.health.v1.Health/Check`. Because the probe is not a gRPC call, the
`200-499` matcher treats any HTTP answer as healthy. The check proves that the
listener is up and completes TLS and HTTP/2, not that the gRPC health service
reports SERVING
([health checks for ALB target groups](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/target-group-health-checks.html)).
The Envoy target
group probes `/` and accepts the 404 that Envoy returns, through the
`200-499` matcher.

### How each proxy creates its certificate

Each proxy creates its own self-signed certificate. Neither proxy uses a
certificate authority (CA), a stored secret, or a certificate from AWS
Certificate Manager (ACM).

| | SDK proxy | Envoy proxy |
|---|---|---|
| Code | `_generate_self_signed_cert()` in `proxy-sdk/server.py` | `docker-entrypoint.sh` in `proxy-envoy/` |
| Tool | Python [`cryptography`](https://cryptography.io/) library, pinned as `cryptography==50.0.1` in `proxy-sdk/requirements.txt` | `openssl req -x509`, which ships in the Envoy base image |
| Key | ECDSA P-256 (`ec.SECP256R1()`), certificate signed with SHA-256 | ECDSA P-256 (`-newkey ec -pkeyopt ec_paramgen_curve:P-256`) |
| Subject | `CN=sdk-proxy.local, O=gRPC VPC Lattice Demo` | `CN=envoy-proxy.local, O=gRPC VPC Lattice Demo` |
| Subject alternative name | `DNS:localhost` | `DNS:localhost` |
| Validity | 365 days from container start | 365 days from container start (`-days 365`) |
| Private key location | Process memory only. `serve()` passes it to `grpc.ssl_server_credentials()` and never writes it to disk. | `/tmp/tls/key.pem`, inside the container's own filesystem. `umask 077` makes the directory mode `0700` and the files mode `0600`. |
| Files on disk | Public certificate only, at `CERT_EXPORT_PATH` (default `/tmp/tls-cert.pem`, mode `0644`). The image `HEALTHCHECK` uses it as its trust anchor. Only local container runs use that check: ECS ignores it because the task definition declares no `healthCheck` ([container health checks](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/healthcheck.html)). The ALB target group health check is what ECS acts on. | `/tmp/tls/cert.pem` and `/tmp/tls/key.pem` |
| Process user | Non-root `appuser` (`USER appuser` in `proxy-sdk/Dockerfile`) | Non-root `envoy` (`USER envoy` in `proxy-envoy/Dockerfile`), which owns `/tmp/tls` |

The Envoy listener in `proxy-envoy/envoy.yaml` reads both files from
`/tmp/tls`, sets `alpn_protocols: ["h2"]`, and requires TLS 1.2 or later
(`tls_minimum_protocol_version: TLSv1_2`).

### When the certificate is created

Each proxy creates its certificate when the container starts, never when the
image is built. The SDK proxy calls `_generate_self_signed_cert()` in
`serve()`, just before it opens its secure port. The Envoy entrypoint runs
`openssl` before it renders the config and starts Envoy with
`exec /usr/local/bin/envoy`. Neither Dockerfile contains a certificate step, so
no image layer holds a key. Every task gets a fresh key pair. Two tasks in the
same service have different certificates, and a replacement task never reuses
the key of the task it replaces.

### How the private key stays out of storage

The private key exists only inside the running task. This sample never writes
it to the following places:

- **The repository.** `.gitignore` excludes `*.pem`, `*.key`, and `*.crt`, and
  `git ls-files | grep -E '\.(pem|key|crt)$'` returns nothing.
- **The container image or Amazon ECR.** The key is created at run time. Both
  Dockerfiles `COPY` named files only, and `proxy-sdk/.dockerignore` and
  `proxy-envoy/.dockerignore` also exclude `*.pem` and `*.key` from the build
  context.
- **AWS Secrets Manager or the task definitions.** The proxy task definitions
  pass only the VPC Lattice endpoint, the Region, the listen port, and the log
  level. The only secret this sample uses is the Docker Hub token for the ECR
  pull through cache.
- **Logs.** Neither proxy logs certificate or key material. The SDK proxy logs
  `tls=enabled` at startup. If it cannot export the public certificate, it logs
  only the exception type name. The Envoy entrypoint runs with `set -eu` and
  prints nothing about the key.

The key disappears when the task stops. The Envoy key file lives in the task's
Fargate ephemeral storage, which is not kept after the task ends. On platform
version 1.4.0 or later, Fargate encrypts that storage at rest with AES-256
([Fargate task ephemeral storage](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/fargate-task-storage.html)).

### Why a self-signed certificate is acceptable here

The ALB does not validate the certificates on its targets, so it accepts
self-signed and expired certificates. AWS also states that traffic between
the load balancer and its targets in a VPC is authenticated at the packet
level, which protects it from man-in-the-middle attacks and spoofing even when
the target certificate is not valid
([target groups](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-target-groups.html)).
This means the sample needs no CA and no rotation. A task that runs longer
than the 365-day validity keeps working, because the ALB also accepts expired
certificates. The proxy security group admits only the ALB security group on
the proxy port, so no other client in the VPC can reach the listener.

### For production

If your policy requires certificates that a client can verify on every hop,
you can issue the proxy certificates from
[AWS Private Certificate Authority](https://docs.aws.amazon.com/privateca/latest/userguide/PcaWelcome.html)
instead. The ALB still does not validate them. In return for meeting that
policy, you take on certificate issuance, distribution to tasks, and rotation.
Also note that ECS Exec, which this sample enables, runs commands as root
([ECS Exec](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-exec.html)),
so an ECS Exec session can read `/tmp/tls/key.pem` in an Envoy task. Remove
ECS Exec if you do not need it.

## Prerequisites

### AWS

- An AWS account with permissions to create VPCs, ALBs, ECS clusters, VPC
  Lattice resources, IAM roles, and Amazon Cognito user pools
- **AWS CLI v2**, configured with credentials
- An **ACM certificate** in the same Region. gRPC requires TLS from the client
  to the ALB, so the HTTPS listener needs one. See
  [Requesting a public certificate](https://docs.aws.amazon.com/acm/latest/userguide/gs-acm-request-public.html).

Additional IAM permissions are needed for the Envoy base image (see below):

| Permission | Why |
|---|---|
| `ecr:CreatePullThroughCacheRule` | Create the cache rule. **Must** come from an identity-based IAM policy — a registry permissions policy cannot grant it |
| `ecr:BatchImportUpstreamImage` | Let Amazon ECR fetch the upstream image into your registry |
| `ecr:CreateRepository` | Create the cache repository on first pull |
| `secretsmanager:CreateSecret`, `secretsmanager:DescribeSecret` | Store the upstream credentials |

> **If your organization applies Service Control Policies**, check that they do
> not deny `ecr:CreateRepository` or `ecr:BatchImportUpstreamImage`. An SCP will
> make cache pulls fail *even after* the rule is created, and the error is not
> obvious. If a platform team already manages a Docker Hub cache rule for you,
> skip the credential setup entirely with `--skip-ptc`.

### Local tooling

- **[Finch](https://runfinch.com/) or Docker** — to build the container images
- **[grpcurl](https://github.com/fullstorydev/grpcurl)** — to call the gRPC endpoints
- **jq** — used by the test script

Nothing else needs installing: the Protocol Buffers compiler runs inside the
container build, so you do not need `protoc` locally.

### A Docker Hub account and a read-only access token

**Why this is needed.** Two of the three images build from Python on Amazon ECR
Public, which needs no credentials. The Envoy image is different: Envoy is
published **only to Docker Hub**. Rather than have this sample pull from Docker
Hub directly, the Envoy base image comes through an **[Amazon ECR pull through
cache](https://docs.aws.amazon.com/AmazonECR/latest/userguide/pull-through-cache.html)**
in your own account, so the image is served from a registry you control and your
own image scanning and lifecycle policies apply to it. Docker Hub requires
authentication for pull through cache, which is why a token is needed.

**Create a token** at Docker Hub → **Account settings → Personal access
tokens** ([docs](https://docs.docker.com/security/access-tokens/)):

- **Set the access permission to `Read` only.** Pulling a public image needs
  nothing more. A read-only token has almost no blast radius if it leaks.
- **Set an expiration date** in line with your own policy.
- **Prefer an Organization Access Token (OAT)** if you have a Docker
  organization. [Docker recommends OATs for proxy and CI/CD use](https://docs.docker.com/enterprise/security/access-tokens/)
  so that shared infrastructure does not depend on any individual's
  credentials.
- Use the **token**, never your account password.

**Rate limits.** Unauthenticated and Docker Personal accounts are subject to a
[6-hour pull rate limit](https://docs.docker.com/docker-hub/usage/repositories/);
Pro, Team and Business accounts are unlimited. The cache means Docker Hub is
contacted only on the **first** pull, so this normally only matters once.

**Where the token is stored.** `build-and-push.sh` puts it in an AWS Secrets
Manager secret named `ecr-pullthroughcache/docker-hub`, encrypted with the
default `aws/secretsmanager` key. Amazon ECR reads that secret; nothing else
does.

> Amazon ECR **requires** the default `aws/secretsmanager` key for these
> secrets and does not support a customer managed key. The secret must also be
> in the **same account and Region** as the cache rule.

**How the script handles it**, in order of preference — pick whichever suits
your environment:

| Approach | Does the script see your token? |
|---|---|
| `--skip-ptc` — a cache rule already exists | **No** |
| `--credential-arn <ARN>` — you created the secret yourself, in the Amazon ECR or Secrets Manager console | **No** |
| Interactive prompt (default) | Only in memory. Written to a `0600` temporary file, never to the process list, the environment, or your shell history |
| `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN` environment variables | Yes — for CI. Weaker: environment variables are readable by same-user processes and inherited by child processes |

**Never pass a token as a command-line argument** to this or any other tool — it
would be visible in `ps` to every user on the machine.

**To rotate the token later**, update the secret **value in place**:

```bash
aws secretsmanager put-secret-value \
  --secret-id ecr-pullthroughcache/docker-hub \
  --secret-string '{"username":"<user>","accessToken":"<new-token>"}' \
  --region <your-region>
```

Do **not** delete and recreate the secret. The cache rule stores the secret's
ARN, and a recreated secret gets a new ARN suffix — the rule would then point at
a secret that no longer exists. Secrets Manager has no managed rotation for
Docker Hub credentials, so plan on a short expiry and a manual refresh.

## Deploy

Clone the repository and run every command in this section from its root:

```bash
git clone https://github.com/aws-samples/sample-grpc-alb-jwt-vpc-lattice.git
cd sample-grpc-alb-jwt-vpc-lattice
```

### 1. Build and push the images

```bash
./build-and-push.sh --account <your-account-id> --region <your-region>
```

The script runs six phases:

1. **Pull through cache** — ensures the Docker Hub cache rule exists for the
   Envoy base image, creating the Secrets Manager secret and the rule if
   needed, then verifies the pinned Envoy digest resolves *through* the cache
   before building anything. On a first run this is where you are prompted for
   your Docker Hub username and read-only access token.
2. **Authenticate** to your ECR registry.
3. **Create the three ECR repositories** if absent, with `scanOnPush` enabled
   and AES256 encryption.
4. **Copy the `.proto` files** into the build contexts.
5. **Render `proxy-envoy/Dockerfile`** for your account and Region — see below.
6. **Build and push** `linux/amd64` images, tagged `latest` and a timestamp.

Everything is idempotent: re-running reuses an existing cache rule, secret and
repositories.

#### Why `proxy-envoy/Dockerfile` is rendered rather than edited

Its `FROM` line carries a placeholder registry (`123456789012` /
`us-east-1`), so the committed file references Amazon ECR rather than Docker
Hub. The script rewrites it to your own account and Region into a gitignored
`proxy-envoy/Dockerfile.rendered` and builds with `-f`.

**Do not hand-edit the `FROM` line, and do not build `proxy-envoy` with a bare
`docker build`** — it would try to pull from account `123456789012`, which is
not yours, and fail. Use the script.

#### Useful flags

| Flag | Use |
|---|---|
| `--skip-ptc` | A cache rule already exists, or a platform team manages one. No credential handling |
| `--credential-arn <ARN>` | You already created the Secrets Manager secret. The script never sees your token |
| `--ptc-prefix <PREFIX>` | Use a cache prefix other than `docker-hub` |
| `--dockerhub-user <USER>` | Supply the username; the token is still prompted for |
| `--help` | Full usage, including all credential-handling modes |

The script uses Finch if present and falls back to Docker. Override with
`CONTAINER_ENGINE=docker`.

### 2. Deploy the stack

```bash
ACCOUNT=<your-account-id>
REGION=<your-region>
REGISTRY=${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com

aws cloudformation deploy \
  --template-file cfn/grpc-lattice-sigv4-demo.yaml \
  --stack-name grpc-lattice-demo \
  --capabilities CAPABILITY_NAMED_IAM \
  --region ${REGION} \
  --parameter-overrides \
    CertificateArn=<your-acm-certificate-arn> \
    SdkProxyImageUri=${REGISTRY}/grpc-lattice-demo-proxy-sdk:latest \
    EnvoyProxyImageUri=${REGISTRY}/grpc-lattice-demo-proxy-envoy:latest \
    BackendImageUri=${REGISTRY}/grpc-lattice-demo-backend:latest
```

Deployment takes roughly 20–30 minutes, mostly waiting on the VPC endpoints
and the ECS services reaching a steady state.

### 3. Verify end to end

```bash
./test-auth-matrix.sh --stack grpc-lattice-demo --region ${REGION}
```

This checks that every boundary rejects unauthorized requests independently:

| # | Test | Expected |
|---|------|----------|
| 1 | Obtain a token from Cognito | success |
| 2 | SDK path → User Service | success, `serviceName: user-service` |
| 3 | Envoy path → Order Service | success, `serviceName: order-service` |
| 4 | No token | HTTP 401 at the ALB |
| 5 | Malformed token | HTTP 401 at the ALB |
| 6 | Unrouted gRPC package | HTTP 404 at the ALB |
| 7 | Cross-role request | denied by VPC Lattice |

Test 7 is the one that proves the authorization model rather than just
connectivity, and it is opt-in because it briefly changes a task definition:

```bash
./test-auth-matrix.sh --stack grpc-lattice-demo --region ${REGION} --test-cross-role
```

It repoints the SDK proxy at the Order Service, confirms VPC Lattice rejects a
**validly signed** request from the wrong workload identity, and then reverts
the change (including if the test fails). Two independent layers deny this
request. `SdkTaskRole`'s IAM policy allows `vpc-lattice-svcs:Invoke` only on the
User Service, and the Order Service auth policy admits only `EnvoyTaskRole`.
VPC Lattice requires an explicit allow from both
([how authorization works](https://docs.aws.amazon.com/vpc-lattice/latest/ug/auth-policies.html)),
so a valid signature is not sufficient. The error names the identity-based
policy because VPC Lattice evaluates that layer first.

> **Let this test finish.** The revert runs from an `EXIT` trap. If you
> interrupt the script (Ctrl-C, closed terminal), the trap may not fire and
> the SDK proxy will be left pointing at the Order Service. Recover by
> pointing the service back at the revision the script printed in "Reverting
> the SDK proxy to ...". If you did not capture it, find it with
> `aws ecs list-task-definitions --family-prefix <stack>-sdk --sort DESC --region ${REGION}`.
> Use the newest revision whose `LATTICE_USER_SVC` is the User Service DNS name.
>
> ```bash
> aws ecs update-service --cluster <stack>-proxy --service <stack>-sdk \
>   --task-definition <stack>-sdk:<revision> --region ${REGION}
> ```

## The 1:1 authorization mapping

| Signing approach | ECS task role | ALB path | VPC Lattice service | Auth policy admits |
|---|---|---|---|---|
| Native AWS SDK | `SdkTaskRole` | `/sdk.*` | User Service | `SdkTaskRole` only |
| Envoy filter | `EnvoyTaskRole` | `/envoy.*` | Order Service | `EnvoyTaskRole` only |

The path patterns match the gRPC **package name**: a call to
`/sdk.DemoService/GetInfo` begins with `/sdk.`, so it matches `/sdk.*`. Each
proxy rewrites the package to `demo.` before forwarding, because the backend
serves the canonical `demo` package.

This one-service-per-approach mapping exists to demonstrate that each signing
method produces a SigV4 identity that VPC Lattice resolves correctly, and that
per-service policies distinguish workload identities. **In production, pick a
single signing approach** for your proxy tier to reduce operational surface.
The per-service policies remain useful for controlling which workloads reach
which services.

## Repository layout

```
.
├── README.md
├── SECURITY-REVIEW.md          Security review, findings, and known limitations
├── build-and-push.sh           Builds and pushes the three images to your ECR
├── test-auth-matrix.sh         End-to-end verification of the security model
├── cfn/
│   └── grpc-lattice-sigv4-demo.yaml
├── proto/
│   ├── demo.proto              Backend contract (package demo)
│   ├── sdk_service.proto       SDK proxy inbound (package sdk)
│   └── envoy_service.proto     Envoy proxy inbound (package envoy)
├── backend/                    gRPC service, deployed twice (user, order)
├── proxy-sdk/                  Option 1: botocore SigV4 + httpx HTTP/2
└── proxy-envoy/                Option 2: aws_request_signing + Lua JWT decode
```

## Configuration

Template parameters worth knowing about:

| Parameter | Default | Notes |
|---|---|---|
| `CertificateArn` | — | Required. ACM certificate for the HTTPS listener. |
| `IngressVpcCidr` | `10.20.0.0/16` | Change if it collides with existing VPCs. |
| `BackendVpcCidr` | `10.21.0.0/16` | Change if it collides with existing VPCs. |
| `ProxyListenPort` | `8443` | Port both proxies listen on. The template passes it to the SDK proxy as `LISTEN_PORT`. The Envoy listener port is fixed at 8443 in `proxy-envoy/envoy.yaml`, so if you change this value, change that file to match and rebuild the image. |
| `BackendGrpcPort` | `50051` | Must match `GRPC_PORT` and the Lattice target group. |
| `ProxyDesiredCount` | `2` | Tasks per proxy service. |
| `BackendDesiredCount` | `2` | Tasks per backend service. |
| `LogRetentionDays` | `14` | CloudWatch Logs retention. |

### Container environment variables

| Variable | Component | Default | Set by the template |
|---|---|---|---|
| `LATTICE_USER_SVC` | SDK proxy | none (required; the proxy exits if unset) | Yes, User Service DNS name |
| `AWS_REGION` | SDK proxy | `us-east-1` | Yes, stack Region |
| `LISTEN_PORT` | SDK proxy | `8443` | Yes, `ProxyListenPort` |
| `LOG_LEVEL` | SDK proxy | `INFO` | Yes, `INFO` |
| `MAX_WORKERS` | SDK proxy | `10` | No |
| `UPSTREAM_TIMEOUT_SECS` | SDK proxy | `30.0` | No |
| `SHUTDOWN_GRACE_SECS` | SDK proxy | `10.0` | No |
| `CERT_EXPORT_PATH` | SDK proxy | `/tmp/tls-cert.pem` | No |
| `VPC_LATTICE_ENDPOINT` | Envoy proxy | none (required; the entrypoint exits if unset) | Yes, Order Service DNS name |
| `AWS_REGION` | Envoy proxy | none (required; the entrypoint exits if unset) | Yes, stack Region |
| `SERVICE_NAME` | Backend | `unknown` | Yes, `user-service` or `order-service` |
| `GRPC_PORT` | Backend | `50051` | Yes, `BackendGrpcPort` |
| `GRPC_MAX_WORKERS` | Backend | `10` | No |
| `SHUTDOWN_TIMEOUT` | Backend | `10` | No |
| `CERT_EXPORT_PATH` | Backend | `/tmp/tls-cert.pem` | No |

## Costs

The deployed resources incur charges while running. The main drivers are the
ALB, eight interface VPC endpoints (four per VPC), Fargate tasks, and VPC
Lattice. The template creates no NAT gateway, because nothing in the private
subnets needs internet egress. See
[ALB pricing](https://aws.amazon.com/elasticloadbalancing/pricing/),
[Fargate pricing](https://aws.amazon.com/fargate/pricing/),
[VPC Lattice pricing](https://aws.amazon.com/vpc/lattice/pricing/),
[PrivateLink pricing](https://aws.amazon.com/privatelink/pricing/), and
[Cognito pricing](https://aws.amazon.com/cognito/pricing/).

Delete the stack when you are done.

## Clean up

```bash
aws cloudformation delete-stack --stack-name grpc-lattice-demo --region ${REGION}
aws cloudformation wait stack-delete-complete --stack-name grpc-lattice-demo --region ${REGION}
```

ECR repositories are created by the build script rather than the stack, so they
are not removed with it. Delete them separately if you no longer need the
images:

```bash
for repo in backend proxy-sdk proxy-envoy; do
  aws ecr delete-repository --repository-name grpc-lattice-demo-${repo} \
    --force --region ${REGION}
done
```

The pull through cache rule, its cached repository and the credential secret are
also outside the stack. Remove them if you have no other use for them:

```bash
# the cached Envoy image
aws ecr delete-repository --repository-name docker-hub/envoyproxy/envoy \
  --force --region ${REGION}

# the cache rule
aws ecr delete-pull-through-cache-rule --ecr-repository-prefix docker-hub \
  --region ${REGION}

# the Docker Hub credentials
aws secretsmanager delete-secret --secret-id ecr-pullthroughcache/docker-hub \
  --force-delete-without-recovery --region ${REGION}
```

Leave the rule and secret in place if you expect to rebuild — they cost nothing
beyond Secrets Manager storage, and keeping them avoids re-entering the token.
**Also revoke the Docker Hub access token** at Docker Hub → Account settings →
Personal access tokens if it was created only for this sample.

## Before using this in production

This is a reference implementation for a blog post. `SECURITY-REVIEW.md`
records the full review, but the items most likely to matter to you:

- **gRPC server reflection is enabled** on all services so `grpcurl` works
  without a local `.proto` file. Reflection allows service enumeration —
  disable it in production.
- **ECS Exec is enabled** on every service to make the walkthrough debuggable.
  Remove it if you do not need it.
- **The SDK path is unary only.** Use the Envoy path for streaming.
- **The backend uses a self-signed certificate.** This is sufficient because
  VPC Lattice does not validate target certificates, and required because a
  `GRPC` protocol version target group needs an HTTPS target.
- **The proxies use self-signed certificates too.** The ALB target groups use
  `Protocol: HTTPS` with `ProtocolVersion: HTTP2`, so the JWT in the
  `authorization` header stays encrypted between the ALB and the proxy. Each
  proxy task generates an ECDSA P-256 certificate when it starts. This is
  sufficient because the ALB does not validate target certificates
  ([target groups](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-target-groups.html)), so there is no certificate authority to manage and no
  rotation to schedule. See
  [TLS between the ALB and the proxies](#tls-between-the-alb-and-the-proxies)
  for how each proxy creates and protects its key.
- **ALB JWT validation cannot check revocation.** A validly signed token is
  accepted until it expires, so this sample issues 5-minute access tokens.
- **Security group egress is scoped, with one deliberate exception.** The task
  security groups reach only the VPC Lattice managed prefix list, the interface
  VPC endpoints (ECR, CloudWatch Logs, SSM Messages), and S3 for ECR image
  layers — no internet egress at all. The ALB is the exception: JWT signature
  verification needs HTTPS to the public Cognito JSON Web Key Set (JWKS) host,
  which has no VPC endpoint. Because the ALB is an AWS-managed component with
  no customer code running on it, that rule is not a container-escape path.
  Neither VPC has a NAT gateway, and no private subnet has an internet route.
- **CloudWatch log groups use the default AWS-owned encryption key.** Log data is
  encrypted at rest, but with a key AWS manages rather than one you control. For
  production, set `KmsKeyId` on each log group to a customer-managed AWS KMS key and
  grant `logs.<region>.amazonaws.com` permission to use it, so key rotation and
  access are under your control.

### Base image provenance

All five `FROM` references resolve to Amazon ECR, and all are pinned by
immutable manifest digest:

| Image | Source |
|---|---|
| Python ×4 (builder + runtime, in `backend/` and `proxy-sdk/`) | `public.ecr.aws/docker/library/python:3.12.8-slim` — Amazon ECR Public, no credentials needed |
| Envoy ×1 (`proxy-envoy/`) | `<your-account>.dkr.ecr.<region>.amazonaws.com/docker-hub/envoyproxy/envoy:v1.39.1` — **your** registry, via pull through cache |

Envoy is published only to Docker Hub — it is not a Docker Official Image, so the
`public.ecr.aws/docker/library/` mirror does not cover it, and there is no Envoy
image on Amazon ECR Public, Quay or `registry.k8s.io`. The pull through cache is
how the image reaches a registry you control. See
[Prerequisites](#a-docker-hub-account-and-a-read-only-access-token) for the
one-time setup.

**What the cache does and does not buy you.** It means the image is served from
your registry, is scanned by your tooling, falls under your lifecycle policies,
and is insulated from Docker Hub rate limits and outages after the first pull.
It does **not** change the bytes: the same content still originates at Docker Hub
on that first pull. The integrity control is the **digest pin**, which is
verified by the container engine regardless of which registry served the image —
a digest-pinned pull from Docker Hub and one through the cache give identical
guarantees.

Docker Hub is contacted **once**, at build time, on the machine running
`build-and-push.sh`. It is not in the deploy path and not in the runtime path:
Amazon ECS pulls only from your own private registry.

**Version currency.** Envoy maintains roughly the last 12 months of minor
releases. `v1.39.1` was the newest release on a supported line when this was
validated (2026-08-29). A pin left unattended **will** fall out of support —
check [endoflife.date/envoy](https://endoflife.date/envoy) for the current window
and [Envoy releases](https://github.com/envoyproxy/envoy/releases) for the newest
patch, then re-run `test-auth-matrix.sh`. For anything long-lived, automate the
bump rather than relying on a manual review; Dependabot updates both the tag and
the digest for the `image:tag@sha256:...` form used here.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more
information.

## License

MIT-0. See [LICENSE](LICENSE).
