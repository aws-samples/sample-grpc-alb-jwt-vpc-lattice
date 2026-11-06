#!/bin/sh
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# docker-entrypoint.sh -- Envoy SigV4 Signing Proxy (Option 2)
#
# Generates the listener's self-signed TLS certificate, substitutes
# environment variables into the Envoy config template, and launches the
# proxy. Fails fast if required variables are missing.
set -eu

# --- Validate required environment variables ---
: "${VPC_LATTICE_ENDPOINT:?ERROR: VPC_LATTICE_ENDPOINT must be set (e.g. order-svc-abc123.vpc-lattice-svcs.us-east-1.on.aws)}"
: "${AWS_REGION:?ERROR: AWS_REGION must be set (e.g. us-east-1)}"

# --- Self-signed TLS certificate for the ALB -> Envoy hop ---
# The ALB does not validate target certificates, so a per-task self-signed
# certificate is enough: no CA, no stored secret, no rotation. A new
# ECDSA P-256 key is generated on every container start. umask 077 makes
# the directory and key readable only by the envoy user.
TLS_DIR=/tmp/tls
(
  umask 077
  mkdir -p "${TLS_DIR}"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "${TLS_DIR}/key.pem" -out "${TLS_DIR}/cert.pem" \
    -days 365 -subj "/CN=envoy-proxy.local/O=gRPC VPC Lattice Demo" \
    -addext "subjectAltName=DNS:localhost"
)
# --- Substitute variables into the config template ---
# Written to /tmp (writable by the non-root envoy user; keeps the
# /etc/envoy config template read-only).
envsubst '${VPC_LATTICE_ENDPOINT} ${AWS_REGION}' \
  < /etc/envoy/envoy.yaml.template \
  > /tmp/envoy.yaml

# --- Launch Envoy ---
exec /usr/local/bin/envoy -c /tmp/envoy.yaml --log-level warn
