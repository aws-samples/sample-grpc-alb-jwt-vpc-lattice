# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# ECS Proxy -- Option 1: Native AWS SDK SigV4 Signing.
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

# Proto files are copied into this build context by build-and-push.sh
COPY demo.proto sdk_service.proto ./

RUN python -m grpc_tools.protoc \
    --proto_path=. \
    --python_out=. \
    --grpc_python_out=. \
    demo.proto sdk_service.proto

# ---------------------------------------------------------------------------
FROM public.ecr.aws/docker/library/python:3.12.8-slim@sha256:2199a62885a12290dc9c5be3ca0681d367576ab7bf037da120e564723292a2f0 AS runtime

RUN apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /sbin/nologin appuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --no-compile -r requirements.txt

COPY --from=builder /build/*_pb2.py /build/*_pb2_grpc.py ./
COPY server.py .

RUN chown -R appuser:appuser /app
USER appuser

EXPOSE 8443

# Health check: gRPC health protocol over TLS.
# The proxy serves TLS with a self-signed certificate generated at startup
# and exports the public certificate to CERT_EXPORT_PATH; it is the trust
# anchor here. ssl_target_name_override matches the certificate SAN. Port
# is read from LISTEN_PORT so the check follows the configured listener.
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "\
import os, grpc; \
from grpc_health.v1 import health_pb2, health_pb2_grpc; \
port = os.environ.get('LISTEN_PORT', '8443'); \
root = open(os.environ.get('CERT_EXPORT_PATH', '/tmp/tls-cert.pem'), 'rb').read(); \
creds = grpc.ssl_channel_credentials(root_certificates=root); \
channel = grpc.secure_channel('localhost:' + port, creds, options=(('grpc.ssl_target_name_override', 'localhost'),)); \
stub = health_pb2_grpc.HealthStub(channel); \
resp = stub.Check(health_pb2.HealthCheckRequest(service=''), timeout=3); \
assert resp.status == health_pb2.HealthCheckResponse.SERVING \
" || exit 1

ENTRYPOINT ["python", "-u", "server.py"]
