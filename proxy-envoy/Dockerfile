# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# Dockerfile -- Envoy SigV4 Signing Proxy for VPC Lattice (gRPC, Option 2)
#
# Security hardened:
#   - Runs as the non-root 'envoy' user
#   - Minimal package install (only gettext-base for envsubst)
#   - Config written to /tmp at runtime (read-only filesystem compatible)
#   - Listener serves TLS with a self-signed cert generated at startup by
#     docker-entrypoint.sh (openssl ships in the base image)
#   - Health check via the admin /ready endpoint on localhost only

# ---------------------------------------------------------------------------
# BASE IMAGE -- served through YOUR Amazon ECR pull through cache.
#
# DO NOT EDIT THE REGISTRY IN THE FROM LINE BY HAND.
# ./build-and-push.sh rewrites it to your own account and Region at build
# time. The 123456789012 / us-east-1 values below are the AWS documentation
# example account and a placeholder Region -- they are NOT a real registry
# and a direct `docker build` here will fail by design.
#
# Envoy publishes only to Docker Hub. Rather than reference Docker Hub
# directly, this sample pulls the image through an Amazon ECR pull through
# cache in your account, so the image is served from a registry you control
# and your own scanning and lifecycle policies apply to it.
#
# One-time setup is handled for you by ./build-and-push.sh, which will
# create the AWS Secrets Manager secret and the pull through cache rule if
# they do not already exist. See "Prerequisites" in README.md for what you
# need before running it (a Docker Hub account and access token).
#
# VERSION CURRENCY: v1.39.1 was the newest release on a SUPPORTED minor line
# when this was validated (2026-08-29). Envoy maintains roughly the last 12
# months of minor releases, so a pin left unattended WILL fall out of
# support -- the previous pin (v1.31.10) had been end-of-life since
# 2025-07-19. Check https://endoflife.date/envoy for the current support
# window and https://github.com/envoyproxy/envoy/releases for the newest
# patch, then re-run test-auth-matrix.sh after any change.
#
# The digest pin is deliberate: it makes the bytes tamper-evident and fails
# the build closed if upstream content ever changes.
# ---------------------------------------------------------------------------
FROM 123456789012.dkr.ecr.us-east-1.amazonaws.com/docker-hub/envoyproxy/envoy:v1.39.1@sha256:57e14a549d7bd43c8d3f6d03e8cfa653e037d4b38e133acd9b54f38c524401b4

# gettext-base provides envsubst (config templating).
# curl is required by the HEALTHCHECK below -- the envoyproxy/envoy base
# image does not ship curl or wget, so it must be installed explicitly.
# ca-certificates provides the trust store used for upstream TLS
# validation against the VPC Lattice endpoint.
USER root
RUN apt-get update && \
    apt-get install -y --no-install-recommends gettext-base ca-certificates curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /var/tmp/*

COPY envoy.yaml /etc/envoy/envoy.yaml.template
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh && \
    chmod 644 /etc/envoy/envoy.yaml.template

USER envoy

EXPOSE 8443

# Health check: Envoy's admin /ready endpoint, reachable on localhost
# only (the admin listener is bound to 127.0.0.1 in envoy.yaml).
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD ["sh", "-c", "curl -fsS http://127.0.0.1:9901/ready || exit 1"]

ENTRYPOINT ["/docker-entrypoint.sh"]
