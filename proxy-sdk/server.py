# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""
ECS Proxy — Option 1: Native AWS SDK SigV4 signing.

Serves gRPC under package "sdk" (/sdk.DemoService/GetInfo -> matches ALB
/sdk.*). Extracts identity from the ALB-validated JWT, translates it into
stable policy headers, signs the outbound HTTP/2 request with SigV4, and
forwards to the VPC Lattice User Service (which serves the "demo"
package). This proxy's ECS task role (SdkTaskRole) is authorized only for
the User Service; a request to the Order Service is denied by VPC
Lattice, because neither this role's IAM policy nor the Order Service
auth policy allows it.

Hardening applied for this reference architecture:
  - Fail-fast startup validation of required configuration.
  - No internal error detail (stack traces, exception messages) leaked
    to gRPC clients; only generic messages cross the trust boundary.
  - JWT decode is size-guarded before any base64/JSON work.
  - Never logs a JWT or exception message that could contain token
    fragments -- only exception type names.
  - gRPC frame unframing validates the declared length against the
    buffer before slicing.
  - Cached botocore session (avoids a session lookup per request; the
    underlying credentials still auto-refresh via the ECS task role).
  - Connection-pooled, bounded httpx client; explicit shutdown.
  - Graceful shutdown on SIGTERM/SIGINT with a configurable grace period.
  - Serves TLS (HTTP/2, ALPN h2) with an ephemeral self-signed ECDSA P-256
    certificate generated at startup, so the JWT in the authorization
    header is encrypted between the ALB and this proxy. The ALB does not
    validate target certificates, so no CA or rotation is needed. The
    private key stays in memory and is never written to disk.

Security considerations:
  - Runs behind an ALB that validates OAuth2 JWTs via the jwt-validation
    listener action and re-encrypts to this proxy over HTTPS.
  - SigV4 signing uses ECS task role credentials (no static credentials).
  - Outbound TLS certificate verification is enabled for the VPC Lattice
    endpoint.
"""

import os
import re
import sys
import json
import base64
import signal
import struct
import logging
from concurrent import futures
from datetime import datetime, timedelta, timezone

# ALB strips the "te: trailers" header from HTTP/2 frames it forwards.
# grpcio rejects inbound calls without it unless this is disabled.
# Must be set BEFORE importing grpc.
os.environ["GRPC_ENFORCE_HTTP2_COMPLIANCE"] = "false"

import grpc  # noqa: E402
from grpc_health.v1 import health_pb2, health_pb2_grpc  # noqa: E402
from grpc_health.v1.health import HealthServicer  # noqa: E402
from grpc_reflection.v1alpha import reflection  # noqa: E402

import botocore.session  # noqa: E402
from botocore.auth import SigV4Auth  # noqa: E402
from botocore.awsrequest import AWSRequest  # noqa: E402
import httpx  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

# Incoming protocol (what clients call us with): sdk.DemoService
import sdk_service_pb2  # noqa: E402
import sdk_service_pb2_grpc  # noqa: E402

# Outgoing protocol (what we call on Lattice): demo.DemoService
import demo_pb2  # noqa: E402

# ---------------------------------------------------------------------------
# Configuration -- all tuneable via environment variables
# ---------------------------------------------------------------------------
LATTICE_USER_SVC = os.environ.get("LATTICE_USER_SVC", "")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8443"))
MAX_WORKERS = int(os.environ.get("MAX_WORKERS", "10"))
UPSTREAM_TIMEOUT = float(os.environ.get("UPSTREAM_TIMEOUT_SECS", "30.0"))
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
SHUTDOWN_GRACE_SECS = float(os.environ.get("SHUTDOWN_GRACE_SECS", "10.0"))
# The public certificate (never the private key) is written here so the
# container HEALTHCHECK can verify the TLS connection. Same pattern as
# backend/server.py.
CERT_EXPORT_PATH = os.environ.get("CERT_EXPORT_PATH", "/tmp/tls-cert.pem")

# Input validation limits
MAX_REQUEST_ID_LENGTH = 256
MAX_JWT_LENGTH = 16_384  # 16 KB -- reject oversized tokens before decoding
MAX_RESPONSE_BODY_SIZE = 4 * 1024 * 1024  # 4 MB

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("sdk-proxy")


# ---------------------------------------------------------------------------
# Startup validation
# ---------------------------------------------------------------------------
def _validate_config() -> None:
    """Fail fast if required configuration is missing or malformed."""
    if not LATTICE_USER_SVC:
        log.error("LATTICE_USER_SVC environment variable is required but not set.")
        sys.exit(1)
    if "/" in LATTICE_USER_SVC or " " in LATTICE_USER_SVC:
        log.error(
            "LATTICE_USER_SVC must be a hostname (no scheme or path): got %r",
            LATTICE_USER_SVC[:64],
        )
        sys.exit(1)
    if LISTEN_PORT < 1 or LISTEN_PORT > 65535:
        log.error("LISTEN_PORT must be 1-65535, got %d", LISTEN_PORT)
        sys.exit(1)


# ---------------------------------------------------------------------------
# TLS certificate generation (ALB -> proxy hop)
# ---------------------------------------------------------------------------
def _generate_self_signed_cert() -> tuple[bytes, bytes]:
    """
    Generate an ephemeral self-signed TLS certificate using ECDSA P-256.

    The ALB does not validate target certificates, so a self-signed cert
    is sufficient and needs no CA, storage, or rotation. A new key pair is
    generated every time a task starts.

    Returns:
        (cert_pem, key_pem) as bytes
    """
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "sdk-proxy.local"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "gRPC VPC Lattice Demo"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


# ---------------------------------------------------------------------------
# HTTP/2 client -- connection-pooled, reusable
# ---------------------------------------------------------------------------
_http_client: httpx.Client | None = None


def _get_http_client() -> httpx.Client:
    global _http_client
    if _http_client is None:
        _http_client = httpx.Client(
            http2=True,
            verify=True,  # TLS certificate verification for the Lattice endpoint
            timeout=httpx.Timeout(
                connect=5.0,
                read=UPSTREAM_TIMEOUT,
                write=5.0,
                pool=5.0,
            ),
            limits=httpx.Limits(
                max_connections=100,
                max_keepalive_connections=20,
                keepalive_expiry=30.0,
            ),
        )
    return _http_client


def _close_http_client() -> None:
    global _http_client
    if _http_client is not None:
        try:
            _http_client.close()
        except Exception as exc:
            # Teardown only -- log the type, never the message.
            log.debug("HTTP client close failed: %s", type(exc).__name__)
        _http_client = None


# ---------------------------------------------------------------------------
# AWS credentials -- cached session (credentials auto-refresh via the ECS
# task role container credential provider)
# ---------------------------------------------------------------------------
_botocore_session: botocore.session.Session | None = None


def _get_credentials():
    global _botocore_session
    if _botocore_session is None:
        _botocore_session = botocore.session.get_session()
    return _botocore_session.get_credentials().get_frozen_credentials()


# ---------------------------------------------------------------------------
# Header value sanitization
# ---------------------------------------------------------------------------
# Printable US-ASCII only (0x20-0x7E). Anything outside that range --
# CR, LF, NUL, other control characters, or non-ASCII bytes -- is dropped.
_UNSAFE_HEADER_CHARS = re.compile(r"[^\x20-\x7E]")


def _sanitize_header_value(value: str, max_length: int) -> str:
    """
    Make a JWT claim safe to use as an outbound HTTP header value.

    Why this matters: these values become x-client-id / x-client-scope /
    x-client-sub, which are covered by the SigV4 signature AND evaluated
    by VPC Lattice auth policies. A claim containing CR/LF could attempt
    header injection, and a claim containing control characters could
    cause a signature/verification mismatch between what we sign and what
    the upstream parses.

    We strip rather than reject so that a malformed-but-harmless claim
    degrades to a usable value instead of failing the request outright.
    Values are also length-bounded.
    """
    if not value:
        return ""
    cleaned = _UNSAFE_HEADER_CHARS.sub("", value)
    return cleaned[:max_length]


# ---------------------------------------------------------------------------
# JWT claim extraction
# ---------------------------------------------------------------------------
def _extract_claims(metadata: dict) -> dict:
    """
    Decode the JWT payload to extract identity claims.

    Security notes:
      - The ALB has already validated the token signature and expiry via
        the jwt-validation listener action; we only decode the payload
        (claims), we do NOT re-verify the signature here.
      - Size-limited to guard against memory-exhaustion via an oversized
        "Bearer" header.
      - Malformed tokens result in empty claims (safe default), never a
        crash, and never a logged token fragment.
    """
    claims: dict = {}
    auth_header = metadata.get("authorization", "")

    if not auth_header.lower().startswith("bearer "):
        return claims

    token = auth_header.split(" ", 1)[1]

    if len(token) > MAX_JWT_LENGTH:
        log.warning("JWT token exceeds maximum length (%d), skipping decode", MAX_JWT_LENGTH)
        return claims

    try:
        parts = token.split(".")
        if len(parts) < 2:
            log.warning("Malformed JWT: fewer than 2 segments")
            return claims

        payload_b64 = parts[1]
        padding_needed = 4 - (len(payload_b64) % 4)
        if padding_needed != 4:
            payload_b64 += "=" * padding_needed

        decoded_bytes = base64.urlsafe_b64decode(payload_b64)

        if len(decoded_bytes) > MAX_JWT_LENGTH:
            log.warning("Decoded JWT payload exceeds size limit")
            return claims

        payload = json.loads(decoded_bytes)
        if not isinstance(payload, dict):
            log.warning("JWT payload is not a JSON object")
            return claims

        # Extract only the claims we need, sanitized and length-bounded
        # before they are used as outbound header values.
        claims["client_id"] = _sanitize_header_value(str(payload.get("client_id", "")), 256)
        claims["scope"] = _sanitize_header_value(str(payload.get("scope", "")), 1024)
        claims["sub"] = _sanitize_header_value(str(payload.get("sub", "")), 256)

    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        # Log the exception category only -- never the message, which
        # could contain token fragments.
        log.warning("JWT decode failed: %s", type(exc).__name__)

    return claims


# ---------------------------------------------------------------------------
# gRPC framing helpers
# ---------------------------------------------------------------------------
def _grpc_status_from_code(raw: str) -> grpc.StatusCode:
    """
    Convert a numeric gRPC status string into a grpc.StatusCode.

    grpc.StatusCode members carry (number, name) tuples as their values, so
    grpc.StatusCode(7) raises ValueError. Comparing the numeric element is
    the reliable way to map a wire status onto the enum.

    Unknown or malformed values fall back to INTERNAL.
    """
    try:
        wanted = int(raw)
    except (TypeError, ValueError):
        return grpc.StatusCode.INTERNAL
    for code in grpc.StatusCode:
        if code.value[0] == wanted:
            return code
    return grpc.StatusCode.INTERNAL


def _grpc_frame(data: bytes) -> bytes:
    """Wrap serialized proto in a gRPC length-prefixed frame.

    Wire format: [1 byte compressed-flag] [4 bytes big-endian length] [payload]
    """
    return struct.pack(">BI", 0, len(data)) + data


def _grpc_unframe(data: bytes) -> bytes:
    """Extract the proto payload from a gRPC length-prefixed frame.

    Validates the declared length against the actual buffer before
    slicing, so a frame header claiming more bytes than were received
    cannot cause a read past the end of the buffer.

    Returns empty bytes on malformed input (safe default); the caller
    treats empty as an error.
    """
    if len(data) < 5:
        return b""

    # Byte 0 is the compressed flag. This proxy does not negotiate
    # message compression (it never sends grpc-encoding), so a non-zero
    # flag means the payload is not something we can parse -- reject it
    # rather than handing compressed bytes to the protobuf parser.
    if data[0] != 0:
        log.warning("gRPC frame declares compression, which is not supported by this proxy")
        return b""

    length = struct.unpack(">I", data[1:5])[0]
    if len(data) < 5 + length:
        log.warning("gRPC frame truncated: header says %d bytes, got %d", length, len(data) - 5)
        return b""
    return data[5 : 5 + length]


# ---------------------------------------------------------------------------
# SigV4 signing + upstream call
# ---------------------------------------------------------------------------
def _sign_and_send(path: str, body: bytes, identity_headers: dict) -> tuple[int, dict, bytes]:
    """
    Sign an HTTP/2 POST to VPC Lattice with SigV4 and send it.

    Returns (http_status_code, response_headers_dict, response_body).
    Raises on network/transport errors.
    """
    url = f"https://{LATTICE_USER_SVC}{path}"

    headers = {
        "content-type": "application/grpc",
        "te": "trailers",
        # UNSIGNED-PAYLOAD: the body is protected by TLS in transit; SigV4
        # signs the headers. VPC Lattice requires unsigned payloads.
        "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
    }
    headers.update(identity_headers)

    credentials = _get_credentials()
    aws_request = AWSRequest(method="POST", url=url, headers=headers, data=body)
    aws_request.context["payload_signing_enabled"] = False
    SigV4Auth(credentials, "vpc-lattice-svcs", AWS_REGION).add_auth(aws_request)

    signed_headers = dict(aws_request.headers)
    client = _get_http_client()
    response = client.post(url, content=body, headers=signed_headers)

    if len(response.content) > MAX_RESPONSE_BODY_SIZE:
        raise ValueError(
            f"Response body exceeds maximum size ({len(response.content)} > {MAX_RESPONSE_BODY_SIZE})"
        )

    return response.status_code, dict(response.headers), response.content


# ---------------------------------------------------------------------------
# gRPC servicer
# ---------------------------------------------------------------------------
class SdkProxyServicer(sdk_service_pb2_grpc.DemoServiceServicer):
    """Receives sdk.DemoService/GetInfo, forwards to the VPC Lattice
    User Service's demo.DemoService/GetInfo."""

    def GetInfo(self, request, context):
        if not request.id or len(request.id) > MAX_REQUEST_ID_LENGTH:
            context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                f"Field 'id' must be 1-{MAX_REQUEST_ID_LENGTH} characters",
            )
            return sdk_service_pb2.InfoResponse()

        incoming_metadata = dict(context.invocation_metadata())
        claims = _extract_claims(incoming_metadata)
        identity_headers = {
            "x-client-id": claims.get("client_id", "unknown"),
            "x-client-scope": claims.get("scope", ""),
            "x-client-sub": claims.get("sub", ""),
        }
        log.info(
            "Forwarding to User Service: client_id=%s, request_id_prefix=%s",
            identity_headers["x-client-id"][:32],
            request.id[:8],
        )

        outgoing_request = demo_pb2.InfoRequest(id=request.id)
        grpc_body = _grpc_frame(outgoing_request.SerializeToString())

        try:
            status_code, resp_headers, resp_body = _sign_and_send(
                "/demo.DemoService/GetInfo",
                grpc_body,
                identity_headers,
            )
        except httpx.TimeoutException:
            log.error("Upstream timeout calling VPC Lattice")
            context.abort(grpc.StatusCode.DEADLINE_EXCEEDED, "Upstream service timeout")
            return sdk_service_pb2.InfoResponse()
        except httpx.ConnectError as exc:
            log.error("Connection failed to VPC Lattice: %s", type(exc).__name__)
            context.abort(grpc.StatusCode.UNAVAILABLE, "Upstream service unavailable")
            return sdk_service_pb2.InfoResponse()
        except Exception as exc:
            # Generic message to the caller; details stay in server logs.
            log.error("Upstream call failed: %s", type(exc).__name__)
            context.abort(grpc.StatusCode.INTERNAL, "Internal proxy error")
            return sdk_service_pb2.InfoResponse()

        if status_code != 200:
            log.error("Upstream HTTP status %d (non-200)", status_code)
            if status_code == 403:
                context.abort(grpc.StatusCode.PERMISSION_DENIED, "Access denied by upstream")
            elif status_code == 429:
                context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED, "Rate limited by upstream")
            elif status_code >= 500:
                context.abort(grpc.StatusCode.UNAVAILABLE, "Upstream service error")
            else:
                context.abort(grpc.StatusCode.INTERNAL, "Unexpected upstream response")
            return sdk_service_pb2.InfoResponse()

        # KNOWN LIMITATION -- gRPC status may arrive in HTTP/2 TRAILERS
        # rather than headers, and httpx does not currently expose HTTP/2
        # trailers via response.headers. When grpc-status is trailer-only
        # it is absent here and this check sees the "0" default.
        #
        # This is safe in practice, but not because of this check: an
        # error response from VPC Lattice or the backend carries no valid
        # gRPC message body, so the unframe + protobuf parse validation
        # below rejects it and returns an error to the caller. Treat that
        # body validation -- not this status check -- as the authoritative
        # error path. The check is retained because it does fire when
        # grpc-status is sent in headers, which is how VPC Lattice returns
        # a policy denial for gRPC (HTTP 200, grpc-status 7).
        #
        # If you need strict trailer inspection, use a real gRPC client
        # for the outbound call (as the Envoy option does) instead of a
        # raw HTTP/2 client.
        grpc_status = resp_headers.get("grpc-status", "0")
        if grpc_status != "0":
            grpc_message = resp_headers.get("grpc-message", "Upstream error")
            log.error("Upstream gRPC status %s: %s", grpc_status, grpc_message[:128])

            # grpc.StatusCode is an enum whose *values* are (number, name)
            # tuples, not plain ints -- grpc.StatusCode(7) raises ValueError.
            # _grpc_status_from_code maps by the numeric element instead.
            #
            # This matters for fidelity: VPC Lattice signals an auth policy
            # denial as gRPC status 7 (PERMISSION_DENIED) with an
            # AccessDeniedException message. Mapping it correctly is what
            # lets the caller distinguish "denied" from "something broke".
            upstream_code = _grpc_status_from_code(grpc_status)

            if upstream_code is grpc.StatusCode.PERMISSION_DENIED:
                # An auth policy denial is actionable for the caller and is
                # not sensitive: it means this workload identity is not
                # permitted on the target service.
                context.abort(
                    grpc.StatusCode.PERMISSION_DENIED,
                    "Access denied by upstream authorization policy",
                )
                return sdk_service_pb2.InfoResponse()
            context.abort(upstream_code, "Upstream service returned an error")
            return sdk_service_pb2.InfoResponse()

        proto_bytes = _grpc_unframe(resp_body)
        if not proto_bytes:
            log.error("Failed to unframe upstream gRPC response")
            context.abort(grpc.StatusCode.INTERNAL, "Invalid upstream response framing")
            return sdk_service_pb2.InfoResponse()

        backend_resp = demo_pb2.InfoResponse()
        try:
            backend_resp.ParseFromString(proto_bytes)
        except Exception:
            log.error("Failed to parse upstream protobuf response")
            context.abort(grpc.StatusCode.INTERNAL, "Invalid upstream response payload")
            return sdk_service_pb2.InfoResponse()

        return sdk_service_pb2.InfoResponse(
            service_name=backend_resp.service_name,
            request_id=backend_resp.request_id,
            client_id=backend_resp.client_id,
            client_scope=backend_resp.client_scope,
            client_sub=backend_resp.client_sub,
            message=backend_resp.message,
        )


# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------
_server: grpc.Server | None = None


def _handle_shutdown(signum, _frame):
    sig_name = signal.Signals(signum).name
    log.info("Received %s -- initiating graceful shutdown (grace=%ss)", sig_name, SHUTDOWN_GRACE_SECS)

    if _server is not None:
        shutdown_event = _server.stop(grace=SHUTDOWN_GRACE_SECS)
        shutdown_event.wait()

    _close_http_client()
    log.info("Shutdown complete")
    sys.exit(0)


def serve() -> None:
    global _server

    _validate_config()

    _server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=MAX_WORKERS),
        options=[
            ("grpc.max_receive_message_length", 16 * 1024 * 1024),
            ("grpc.keepalive_time_ms", 30_000),
            ("grpc.keepalive_timeout_ms", 10_000),
            ("grpc.keepalive_permit_without_calls", True),
            ("grpc.http2.min_recv_ping_interval_without_data_ms", 10_000),
        ],
    )

    sdk_service_pb2_grpc.add_DemoServiceServicer_to_server(SdkProxyServicer(), _server)

    health = HealthServicer()
    health.set("", health_pb2.HealthCheckResponse.SERVING)
    health.set("sdk.DemoService", health_pb2.HealthCheckResponse.SERVING)
    health_pb2_grpc.add_HealthServicer_to_server(health, _server)

    service_names = (
        sdk_service_pb2.DESCRIPTOR.services_by_name["DemoService"].full_name,
        health_pb2.DESCRIPTOR.services_by_name["Health"].full_name,
        reflection.SERVICE_NAME,
    )
    reflection.enable_server_reflection(service_names, _server)

    # TLS on the listener. The key pair lives only in this process; the
    # private key is passed to gRPC in memory and never touches disk.
    cert_pem, key_pem = _generate_self_signed_cert()
    server_credentials = grpc.ssl_server_credentials([(key_pem, cert_pem)])
    try:
        with open(CERT_EXPORT_PATH, "wb") as fh:
            fh.write(cert_pem)
        os.chmod(CERT_EXPORT_PATH, 0o644)
    except OSError as exc:
        # Non-fatal: only the container HEALTHCHECK degrades.
        log.warning("Could not export health-check certificate: %s", type(exc).__name__)

    # All interfaces inside the task's awsvpc ENI. Reachability is bounded
    # by EcsProxySg, which admits only the ALB security group.
    listen_addr = f"0.0.0.0:{LISTEN_PORT}"
    _server.add_secure_port(listen_addr, server_credentials)

    signal.signal(signal.SIGTERM, _handle_shutdown)
    signal.signal(signal.SIGINT, _handle_shutdown)

    log.info(
        "SDK SigV4 proxy started: listen=%s, tls=enabled, upstream=%s, region=%s, workers=%d",
        listen_addr,
        LATTICE_USER_SVC[:64],
        AWS_REGION,
        MAX_WORKERS,
    )
    _server.start()
    _server.wait_for_termination()


if __name__ == "__main__":
    serve()
