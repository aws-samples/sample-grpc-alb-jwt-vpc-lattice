# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""
Backend gRPC service — runs behind Amazon VPC Lattice.

Deployed twice from this same image: as the User Service (reachable only
by SdkTaskRole via the SDK proxy) and as the Order Service (reachable only
by EnvoyTaskRole via the Envoy proxy), differentiated by the SERVICE_NAME
environment variable. This demonstrates VPC Lattice's per-service auth
policy enforcement by workload identity, not by client identity.

Hardening applied for this reference architecture:
  - Serves TLS with an ephemeral self-signed certificate. VPC Lattice
    target groups with ProtocolVersion: GRPC require Protocol: HTTPS on
    the target (VPC Lattice does not validate target certificates, so a
    self-signed cert is sufficient).
  - Input validation on the request id field.
  - Sanitized logging (no raw, unbounded user input in log lines).
  - Graceful shutdown on SIGTERM/SIGINT (ECS sends SIGTERM on task stop).
"""

import os
import re
import signal
import logging
import threading
from concurrent import futures
from datetime import datetime, timedelta, timezone

import grpc
from grpc_health.v1 import health_pb2, health_pb2_grpc
from grpc_health.v1.health import HealthServicer
from grpc_reflection.v1alpha import reflection
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

import demo_pb2
import demo_pb2_grpc

# ---------------------------------------------------------------------------
# Configuration — all tuneable via environment variables
# ---------------------------------------------------------------------------
SERVICE_NAME = os.environ.get("SERVICE_NAME", "unknown")
GRPC_PORT = os.environ.get("GRPC_PORT", "50051")
MAX_WORKERS = int(os.environ.get("GRPC_MAX_WORKERS", "10"))
SHUTDOWN_TIMEOUT = int(os.environ.get("SHUTDOWN_TIMEOUT", "10"))

# Path where the generated self-signed certificate is written so the
# container HEALTHCHECK can use it as its trust anchor. A self-signed
# certificate is its own CA, so this file is both the leaf and the root.
# The private key is never written to disk -- only the public certificate.
CERT_EXPORT_PATH = os.environ.get("CERT_EXPORT_PATH", "/tmp/tls-cert.pem")

# Input validation constraints
MAX_REQUEST_ID_LEN = 128
REQUEST_ID_PATTERN = re.compile(r"^[a-zA-Z0-9\-_.]+$")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
log = logging.getLogger(SERVICE_NAME)


# ---------------------------------------------------------------------------
# TLS certificate generation
# ---------------------------------------------------------------------------
def generate_self_signed_cert() -> tuple[bytes, bytes]:
    """
    Generate an ephemeral self-signed TLS certificate using ECDSA P-256.

    VPC Lattice does NOT validate the backend target's TLS certificate, so
    a self-signed cert is sufficient. ECDSA is used for a smaller key size
    and faster handshakes compared to RSA.

    Returns:
        (cert_pem, key_pem) as bytes
    """
    key = ec.generate_private_key(ec.SECP256R1())

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "grpc-backend.local"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "gRPC VPC Lattice Demo"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
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
# Input validation
# ---------------------------------------------------------------------------
def validate_request_id(request_id: str) -> str | None:
    """Return the sanitized request id, or None if invalid."""
    if not request_id:
        return ""
    if len(request_id) > MAX_REQUEST_ID_LEN:
        return None
    if not REQUEST_ID_PATTERN.match(request_id):
        return None
    return request_id


# ---------------------------------------------------------------------------
# Service implementation
# ---------------------------------------------------------------------------
class DemoServiceServicer(demo_pb2_grpc.DemoServiceServicer):
    """Implements demo.DemoService/GetInfo — echoes identity headers forwarded
    by the proxy tier through VPC Lattice, so the full auth chain
    (JWT -> proxy -> SigV4 -> Lattice) can be verified end to end."""

    def GetInfo(self, request, context):
        validated_id = validate_request_id(request.id)
        if validated_id is None:
            context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                f"Field 'id' must be 1-{MAX_REQUEST_ID_LEN} alphanumeric/"
                f"hyphen/dot/underscore characters",
            )
            return demo_pb2.InfoResponse()

        # Identity headers forwarded by the proxy tier through Lattice
        metadata = dict(context.invocation_metadata())
        client_id = metadata.get("x-client-id", "")
        client_scope = metadata.get("x-client-scope", "")
        client_sub = metadata.get("x-client-sub", "")

        # Sanitized log line — presence/length only, never raw header values
        log.info(
            "GetInfo called: id_len=%d client_id_present=%s",
            len(validated_id),
            bool(client_id),
        )

        return demo_pb2.InfoResponse(
            service_name=SERVICE_NAME,
            request_id=validated_id,
            client_id=client_id,
            client_scope=client_scope,
            client_sub=client_sub,
            message=f"Hello from {SERVICE_NAME}",
        )


# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------
def serve() -> None:
    """Start the gRPC+TLS server with graceful shutdown."""

    log.info("Generating ephemeral TLS certificate (ECDSA P-256)...")
    cert_pem, key_pem = generate_self_signed_cert()
    server_credentials = grpc.ssl_server_credentials([(key_pem, cert_pem)])
    log.info("TLS certificate generated")

    # Export the public certificate (never the private key) so the
    # container HEALTHCHECK can verify the TLS connection against it.
    # Without this, a health check using the default system trust store
    # cannot validate a self-signed certificate and always fails.
    try:
        with open(CERT_EXPORT_PATH, "wb") as fh:
            fh.write(cert_pem)
        os.chmod(CERT_EXPORT_PATH, 0o644)
        log.info("Exported public certificate for health checks: %s", CERT_EXPORT_PATH)
    except OSError as exc:
        # Non-fatal: the service still works, only the container
        # HEALTHCHECK degrades. Log the category, not the full path detail.
        log.warning("Could not export health-check certificate: %s", type(exc).__name__)

    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=MAX_WORKERS),
        options=[
            # Bound message size (defense against oversized payloads)
            ("grpc.max_receive_message_length", 4 * 1024 * 1024),
            ("grpc.max_send_message_length", 4 * 1024 * 1024),
            # Keepalive for long-lived Lattice connections
            ("grpc.keepalive_time_ms", 30_000),
            ("grpc.keepalive_timeout_ms", 10_000),
            ("grpc.keepalive_permit_without_calls", True),
        ],
    )

    demo_pb2_grpc.add_DemoServiceServicer_to_server(DemoServiceServicer(), server)

    # gRPC health check (used by health-check tooling; VPC Lattice's own
    # target group health check uses HTTP2 with a broad matcher, since
    # protocolVersion: GRPC health checks are not supported directly)
    health = HealthServicer()
    health.set("", health_pb2.HealthCheckResponse.SERVING)
    health.set("demo.DemoService", health_pb2.HealthCheckResponse.SERVING)
    health_pb2_grpc.add_HealthServicer_to_server(health, server)

    # Server reflection (convenience for grpcurl without a .proto file)
    service_names = (
        demo_pb2.DESCRIPTOR.services_by_name["DemoService"].full_name,
        health_pb2.DESCRIPTOR.services_by_name["Health"].full_name,
        reflection.SERVICE_NAME,
    )
    reflection.enable_server_reflection(service_names, server)

    server.add_secure_port(f"0.0.0.0:{GRPC_PORT}", server_credentials)

    shutdown_event = threading.Event()

    def _shutdown(signum, _frame):
        sig_name = signal.Signals(signum).name
        log.info("Received %s -- initiating graceful shutdown", sig_name)
        health.set("", health_pb2.HealthCheckResponse.NOT_SERVING)
        health.set("demo.DemoService", health_pb2.HealthCheckResponse.NOT_SERVING)
        shutdown_event.set()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    server.start()
    log.info(
        "Server started: service=%s port=%s tls=enabled reflection=enabled",
        SERVICE_NAME,
        GRPC_PORT,
    )

    shutdown_event.wait()

    log.info("Draining connections (timeout=%ds)...", SHUTDOWN_TIMEOUT)
    server.stop(grace=SHUTDOWN_TIMEOUT).wait()
    log.info("Server stopped cleanly")


if __name__ == "__main__":
    serve()
