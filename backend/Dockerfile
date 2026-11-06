# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# Backend gRPC service — security-hardened container image.
# Runs behind Amazon VPC Lattice with TLS (self-signed; VPC Lattice does
# not validate target certificates).
#
# Multi-stage build: compile proto stubs in builder, run in a minimal,
# non-root runtime image.

# Base images come from Amazon ECR Public (public.ecr.aws), which allows
# anonymous pulls. The /docker/library/ path mirrors Docker Official Images.
#
# Pinned to an exact patch tag for reproducibility. This image is byte-identical
# to docker.io/library/python:3.12.8-slim
# (sha256:2199a62885a12290dc9c5be3ca0681d367576ab7bf037da120e564723292a2f0).
FROM public.ecr.aws/docker/library/python:3.12.8-slim@sha256:2199a62885a12290dc9c5be3ca0681d367576ab7bf037da120e564723292a2f0 AS builder

WORKDIR /build

RUN pip install --no-cache-dir grpcio-tools==1.68.1 protobuf==5.29.2

# demo.proto is copied into this build context by build-and-push.sh
COPY demo.proto .
RUN python -m grpc_tools.protoc \
    --proto_path=. \
    --python_out=. \
    --grpc_python_out=. \
    demo.proto

# ---------------------------------------------------------------------------
FROM public.ecr.aws/docker/library/python:3.12.8-slim@sha256:2199a62885a12290dc9c5be3ca0681d367576ab7bf037da120e564723292a2f0 AS runtime

LABEL org.opencontainers.image.source="https://github.com/aws-samples" \
      description="gRPC backend (User/Order Service) for the VPC Lattice gRPC blog post"

RUN apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd -r grpc && useradd -r -g grpc -d /app -s /sbin/nologin grpc

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --no-compile -r requirements.txt

COPY --from=builder /build/demo_pb2.py /build/demo_pb2_grpc.py ./
COPY server.py .

RUN chown -R grpc:grpc /app
USER grpc

EXPOSE 50051

# Health check: gRPC health protocol over TLS.
# The server exports its self-signed public certificate to
# CERT_EXPORT_PATH at startup; we use it as the trust anchor here, since
# the default system trust store cannot validate a self-signed cert.
# ssl_target_name_override matches the certificate's CN/SAN.
HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "\
import os, grpc; \
from grpc_health.v1 import health_pb2, health_pb2_grpc; \
port = os.environ.get('GRPC_PORT', '50051'); \
cert_path = os.environ.get('CERT_EXPORT_PATH', '/tmp/tls-cert.pem'); \
root = open(cert_path, 'rb').read(); \
creds = grpc.ssl_channel_credentials(root_certificates=root); \
channel = grpc.secure_channel('localhost:' + port, creds, options=(('grpc.ssl_target_name_override', 'localhost'),)); \
stub = health_pb2_grpc.HealthStub(channel); \
resp = stub.Check(health_pb2.HealthCheckRequest(service=''), timeout=3); \
assert resp.status == health_pb2.HealthCheckResponse.SERVING \
" || exit 1

STOPSIGNAL SIGTERM

ENV PYTHONUNBUFFERED="1" \
    PYTHONDONTWRITEBYTECODE="1"

ENTRYPOINT ["python", "-u", "server.py"]
