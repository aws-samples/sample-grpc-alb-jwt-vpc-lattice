#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# Build and push container images for the gRPC VPC Lattice demo.
#
# Three images are built: backend (deployed twice at the ECS-service level as
# User Service and Order Service, differentiated by the SERVICE_NAME /
# GRPC_PORT environment variables -- not two separate images), proxy-sdk
# (Option 1), and proxy-envoy (Option 2).
#
# THE ENVOY BASE IMAGE comes through an Amazon ECR pull through cache in YOUR
# account rather than from Docker Hub directly, so the image is served from a
# registry you control and your own scanning and lifecycle policies apply.
# Envoy publishes only to Docker Hub, and Docker Hub requires authentication
# for pull through cache -- hence the one-time credential setup below.
#
# Usage:
#   ./build-and-push.sh --account <ACCOUNT_ID> [--region <REGION>]
#
# Credential handling, in order of preference:
#
#   1. --skip-ptc
#        The cache rule already exists (for example a platform team manages it
#        centrally). This script never touches credentials.
#
#   2. --credential-arn <ARN>
#        A Secrets Manager secret already holds the Docker Hub credentials --
#        created in the Amazon ECR or Secrets Manager console, or by someone
#        else. This script never sees the token.
#
#   3. Interactive prompt (default)
#        You are asked for a username and access token. The token is not
#        echoed, is written only to a 0600 temporary file, and never appears
#        in the process list, the environment, or your shell history.
#
#   4. DOCKERHUB_USERNAME / DOCKERHUB_TOKEN environment variables
#        For CI. Weaker than the prompt: environment variables are readable by
#        same-user processes, are inherited by children, and often end up in
#        shell history when set inline. Use short-lived, read-only tokens.
#
#   NEVER pass a token as a command-line argument to anything -- it would be
#   visible in `ps` to every user on the machine.
#
# Optional flags:
#   --ptc-prefix <PREFIX>    Cache prefix (default: docker-hub)
#   --skip-ptc               See 1 above
#   --credential-arn <ARN>   See 2 above
#   --dockerhub-user <USER>  Username only; the token is still prompted for
#
# Environment variables:
#   AWS_ACCOUNT_ID, AWS_REGION (default us-east-1),
#   DOCKERHUB_USERNAME, DOCKERHUB_TOKEN, CONTAINER_ENGINE (finch|docker)
#
# ROTATING THE DOCKER HUB TOKEN
#   Update the secret VALUE in place; do not delete and recreate it:
#     aws secretsmanager put-secret-value \
#       --secret-id ecr-pullthroughcache/<prefix> \
#       --secret-string '{"username":"<user>","accessToken":"<new-token>"}'
#   Deleting and recreating produces a new ARN suffix, and the cache rule
#   stores the ARN -- it would then point at a secret that no longer exists.
#
# PREREQUISITES: see "Prerequisites" in README.md.

set -euo pipefail

ECR_PREFIX="grpc-lattice-demo"
SERVICES=("backend" "proxy-sdk" "proxy-envoy")
PLATFORM="linux/amd64"

# Placeholder written into proxy-envoy/Dockerfile, rewritten at build time to
# the caller's own registry. Must stay in sync with that Dockerfile.
PLACEHOLDER_PTC_BASE="123456789012.dkr.ecr.us-east-1.amazonaws.com/docker-hub"
ENVOY_REF="envoyproxy/envoy:v1.39.1@sha256:57e14a549d7bd43c8d3f6d03e8cfa653e037d4b38e133acd9b54f38c524401b4"

PTC_PREFIX="docker-hub"
UPSTREAM_URL="registry-1.docker.io"
UPSTREAM_REGISTRY="docker-hub"
SKIP_PTC="false"
CREDENTIAL_ARN=""

CONTAINER_ENGINE="${CONTAINER_ENGINE:-finch}"
if ! command -v "${CONTAINER_ENGINE}" &>/dev/null; then
  if command -v docker &>/dev/null; then
    CONTAINER_ENGINE="docker"
  else
    echo "ERROR: neither finch nor docker found on PATH" >&2
    exit 1
  fi
fi

while [[ $# -gt 0 ]]; do
  case $1 in
    --account)         AWS_ACCOUNT_ID="$2"; shift 2 ;;
    --region)          AWS_REGION="$2"; shift 2 ;;
    --ptc-prefix)      PTC_PREFIX="$2"; shift 2 ;;
    --credential-arn)  CREDENTIAL_ARN="$2"; shift 2 ;;
    --dockerhub-user)  DOCKERHUB_USERNAME="$2"; shift 2 ;;
    --skip-ptc)        SKIP_PTC="true"; shift ;;
    -h|--help)         sed -n '5,63p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

ACCOUNT_ID="${AWS_ACCOUNT_ID:?'AWS_ACCOUNT_ID must be set via --account flag or environment variable'}"
REGION="${AWS_REGION:-us-east-1}"
ECR_REGISTRY="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"
PTC_BASE="${ECR_REGISTRY}/${PTC_PREFIX}"
SECRET_NAME="ecr-pullthroughcache/${PTC_PREFIX}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RENDERED_DOCKERFILE="${SCRIPT_DIR}/proxy-envoy/Dockerfile.rendered"
SECRET_TMP=""

cleanup() {
  [[ -n "${SECRET_TMP}" ]] && rm -f "${SECRET_TMP}"
  rm -f "${SCRIPT_DIR}/backend/demo.proto" \
        "${SCRIPT_DIR}/proxy-sdk/demo.proto" \
        "${SCRIPT_DIR}/proxy-sdk/sdk_service.proto" \
        "${RENDERED_DOCKERFILE}"
  return 0
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# create_ptc_rule -- create the cache rule, retrying on transient failure.
#
# Amazon ECR cannot always read a just-created secret immediately, so the
# first attempt after secret creation can fail and then succeed seconds later.
# Retrying avoids a first-run failure that looks like a broken sample.
# The real API error is printed if every attempt fails -- never swallowed.
# ---------------------------------------------------------------------------
create_ptc_rule() {
  local arn="$1" attempt=1 max_attempts=4 err=""
  while :; do
    if err="$(aws ecr create-pull-through-cache-rule \
                --ecr-repository-prefix "${PTC_PREFIX}" \
                --upstream-registry-url "${UPSTREAM_URL}" \
                --upstream-registry "${UPSTREAM_REGISTRY}" \
                --credential-arn "${arn}" \
                --region "${REGION}" 2>&1 >/dev/null)"; then
      return 0
    fi
    # Someone else created it in the meantime -- that is success for us.
    if printf '%s' "${err}" | grep -qi 'AlreadyExists'; then
      return 0
    fi
    if (( attempt >= max_attempts )); then
      echo "" >&2
      echo "ERROR: could not create the pull through cache rule after ${max_attempts} attempts." >&2
      echo "" >&2
      echo "  API error:" >&2
      printf '    %s\n' "${err}" >&2
      echo "" >&2
      echo "  Most likely causes:" >&2
      echo "   * Missing ecr:CreatePullThroughCacheRule. This must be granted by an" >&2
      echo "     identity-based IAM policy -- a registry permissions policy cannot" >&2
      echo "     grant it." >&2
      echo "   * A Service Control Policy denying ecr:CreateRepository or" >&2
      echo "     ecr:BatchImportUpstreamImage. An SCP makes cache pulls fail even" >&2
      echo "     after the rule exists." >&2
      echo "   * The secret is not in ${ACCOUNT_ID} / ${REGION}. Amazon ECR requires" >&2
      echo "     the secret to be in the same account and Region as the rule." >&2
      echo "   * The secret is encrypted with a customer managed KMS key. Amazon ECR" >&2
      echo "     requires the default aws/secretsmanager key for these secrets." >&2
      echo "" >&2
      echo "  If a platform team manages the rule, re-run with --skip-ptc." >&2
      return 1
    fi
    echo "    attempt ${attempt} failed, retrying in $(( attempt * 5 ))s..."
    sleep $(( attempt * 5 ))
    (( attempt++ ))
  done
}

echo "=============================================="
echo " gRPC VPC Lattice Demo -- Build & Push"
echo "=============================================="
echo " Account:    ${ACCOUNT_ID}"
echo " Region:     ${REGION}"
echo " Registry:   ${ECR_REGISTRY}"
echo " PTC prefix: ${PTC_PREFIX}"
echo " Platform:   ${PLATFORM}"
echo " Engine:     ${CONTAINER_ENGINE}"
echo "=============================================="

# ---------------------------------------------------------------------------
# [1/6] Pull through cache for the Envoy base image
# ---------------------------------------------------------------------------
echo ""
if [[ "${SKIP_PTC}" == "true" ]]; then
  echo "[1/6] Pull through cache: SKIPPED (--skip-ptc)."
  echo "      Assuming prefix '${PTC_PREFIX}' exists in ${ACCOUNT_ID}/${REGION}."
else
  echo "[1/6] Ensuring the Envoy pull through cache rule exists..."

  if aws ecr describe-pull-through-cache-rules \
        --ecr-repository-prefixes "${PTC_PREFIX}" \
        --region "${REGION}" &>/dev/null; then
    echo "  - cache rule '${PTC_PREFIX}' (exists)"
  else
    echo "  - cache rule '${PTC_PREFIX}' not found; creating it."

    if [[ -n "${CREDENTIAL_ARN}" ]]; then
      # Caller supplied an existing secret: no credential handling here at all.
      echo "  - using the supplied --credential-arn (no token handled by this script)"
    elif aws secretsmanager describe-secret \
            --secret-id "${SECRET_NAME}" --region "${REGION}" &>/dev/null; then
      echo "  - secret '${SECRET_NAME}' (exists, reusing)"
      CREDENTIAL_ARN="$(aws secretsmanager describe-secret \
        --secret-id "${SECRET_NAME}" --region "${REGION}" --query ARN --output text)"
    else
      echo ""
      echo "    Docker Hub requires authentication for pull through cache. The"
      echo "    credentials are stored in AWS Secrets Manager as"
      echo "    '${SECRET_NAME}' and are read by Amazon ECR, not by this script."
      echo ""
      echo "    Use a READ-ONLY access token, never your password. Pulling a"
      echo "    public image needs Read permission only -- not Write or Delete."
      echo "    Docker tokens can be scoped and given an expiry date:"
      echo "      https://docs.docker.com/security/access-tokens/"
      echo ""
      echo "    If you have a Docker organization, prefer an ORGANIZATION access"
      echo "    token (OAT) over a personal one. Docker recommends OATs for proxy"
      echo "    and CI/CD use, so shared infrastructure does not depend on any"
      echo "    individual's credentials."
      echo ""
      echo "    Note on rate limits: unauthenticated and Docker Personal accounts"
      echo "    are subject to a 6-hour pull rate limit. Pro, Team and Business"
      echo "    accounts are unlimited."
      echo ""
      echo "    Prefer not to type a token here? Create the secret in the Amazon"
      echo "    ECR or Secrets Manager console, then re-run with"
      echo "    --credential-arn <ARN>."
      echo ""

      if [[ -z "${DOCKERHUB_USERNAME:-}" ]]; then
        if [[ -t 0 ]]; then
          read -r -p "    Docker Hub username: " DOCKERHUB_USERNAME
        else
          echo "ERROR: DOCKERHUB_USERNAME is not set and there is no terminal to prompt on." >&2
          echo "       Set DOCKERHUB_USERNAME and DOCKERHUB_TOKEN, or use" >&2
          echo "       --credential-arn / --skip-ptc." >&2
          exit 1
        fi
      fi
      if [[ -z "${DOCKERHUB_TOKEN:-}" ]]; then
        if [[ -t 0 ]]; then
          read -r -s -p "    Docker Hub access token (not echoed): " DOCKERHUB_TOKEN
          echo ""
        else
          echo "ERROR: DOCKERHUB_TOKEN is not set and there is no terminal to prompt on." >&2
          exit 1
        fi
      fi
      [[ -n "${DOCKERHUB_USERNAME}" && -n "${DOCKERHUB_TOKEN}" ]] || {
        echo "ERROR: Docker Hub username and token are both required." >&2; exit 1; }

      # 0600 temp file rather than the command line, so the token never
      # appears in the process list.
      SECRET_TMP="$(umask 077; mktemp)"
      printf '{"username":"%s","accessToken":"%s"}' \
        "${DOCKERHUB_USERNAME}" "${DOCKERHUB_TOKEN}" > "${SECRET_TMP}"

      # No --kms-key-id: Amazon ECR requires the default aws/secretsmanager
      # key for pull through cache secrets and does not support a CMK.
      aws secretsmanager create-secret \
        --name "${SECRET_NAME}" \
        --description "Docker Hub credentials for the Amazon ECR pull through cache (gRPC VPC Lattice demo)" \
        --secret-string "file://${SECRET_TMP}" \
        --region "${REGION}" > /dev/null
      rm -f "${SECRET_TMP}"; SECRET_TMP=""
      unset DOCKERHUB_TOKEN
      echo "  - secret '${SECRET_NAME}' (created)"

      CREDENTIAL_ARN="$(aws secretsmanager describe-secret \
        --secret-id "${SECRET_NAME}" --region "${REGION}" --query ARN --output text)"
    fi

    create_ptc_rule "${CREDENTIAL_ARN}" || exit 1
    echo "  - cache rule '${PTC_PREFIX}' (created)"
  fi

  # --- preflight: prove the digest resolves THROUGH the cache --------------
  # The first pull populates the cache and is where a bad credential or a
  # digest mismatch surfaces. Failing here is far clearer than mid-build.
  echo ""
  echo "  Verifying the Envoy digest resolves through the cache..."
  if PULL_ERR="$("${CONTAINER_ENGINE}" pull "${PTC_BASE}/${ENVOY_REF}" 2>&1 >/dev/null)"; then
    echo "  - digest resolves through ${PTC_BASE}"
  else
    echo "" >&2
    echo "ERROR: could not pull the Envoy base image through the cache:" >&2
    echo "         ${PTC_BASE}/${ENVOY_REF}" >&2
    echo "" >&2
    echo "  Engine error:" >&2
    printf '    %s\n' "${PULL_ERR}" >&2
    echo "" >&2
    echo "  Most likely causes:" >&2
    echo "   * Invalid, expired or insufficiently scoped Docker Hub credentials." >&2
    echo "     Update the value in place -- do not delete and recreate the secret:" >&2
    echo "       aws secretsmanager put-secret-value --secret-id ${SECRET_NAME} \\" >&2
    echo "         --secret-string '{\"username\":\"<user>\",\"accessToken\":\"<token>\"}'" >&2
    echo "   * An SCP denying ecr:CreateRepository or ecr:BatchImportUpstreamImage." >&2
    echo "   * No route to the internet for the FIRST pull. Amazon ECR must reach" >&2
    echo "     Docker Hub to populate the cache; later pulls do not." >&2
    echo "   * Docker Hub rate limiting -- unauthenticated and Personal accounts" >&2
    echo "     have a 6-hour pull limit." >&2
    exit 1
  fi
fi

# ---------------------------------------------------------------------------
# [2/6] Authenticate to ECR
# ---------------------------------------------------------------------------
echo ""
echo "[2/6] Authenticating to ECR..."
aws ecr get-login-password --region "${REGION}" | \
  "${CONTAINER_ENGINE}" login --username AWS --password-stdin "${ECR_REGISTRY}"

# ---------------------------------------------------------------------------
# [3/6] Create ECR repositories (idempotent)
# ---------------------------------------------------------------------------
echo ""
echo "[3/6] Ensuring ECR repositories exist..."
for SERVICE in "${SERVICES[@]}"; do
  REPO_NAME="${ECR_PREFIX}-${SERVICE}"
  if aws ecr describe-repositories --repository-names "${REPO_NAME}" --region "${REGION}" &>/dev/null; then
    echo "  - ${REPO_NAME} (exists)"
  else
    aws ecr create-repository \
      --repository-name "${REPO_NAME}" \
      --region "${REGION}" \
      --image-scanning-configuration scanOnPush=true \
      --encryption-configuration encryptionType=AES256 \
      > /dev/null
    echo "  - ${REPO_NAME} (created)"
  fi
done

# ---------------------------------------------------------------------------
# [4/6] Copy proto files to build contexts
# ---------------------------------------------------------------------------
echo ""
echo "[4/6] Copying proto files to build contexts..."
PROTO_DIR="${SCRIPT_DIR}/proto"

# backend: only demo.proto (the canonical service, used for both the
# User Service and Order Service deployments)
cp "${PROTO_DIR}/demo.proto" "${SCRIPT_DIR}/backend/demo.proto"

# proxy-sdk: demo.proto (outgoing to Lattice) + sdk_service.proto (incoming from ALB)
cp "${PROTO_DIR}/demo.proto" "${SCRIPT_DIR}/proxy-sdk/demo.proto"
cp "${PROTO_DIR}/sdk_service.proto" "${SCRIPT_DIR}/proxy-sdk/sdk_service.proto"

# proxy-envoy: no proto copy needed (Envoy rewrites the path in Lua rather
# than using a compiled gRPC stub)

echo "  - demo.proto -> backend/, proxy-sdk/"
echo "  - sdk_service.proto -> proxy-sdk/"

# ---------------------------------------------------------------------------
# [5/6] Render the Envoy Dockerfile for this account and Region
#
# proxy-envoy/Dockerfile carries a placeholder registry so the committed file
# references Amazon ECR rather than Docker Hub. It is rendered to a separate,
# gitignored file rather than edited in place, so the repository stays clean
# and you never hand-edit a Dockerfile.
# ---------------------------------------------------------------------------
echo ""
echo "[5/6] Rendering proxy-envoy/Dockerfile for ${ECR_REGISTRY}..."
if ! grep -q "${PLACEHOLDER_PTC_BASE}" "${SCRIPT_DIR}/proxy-envoy/Dockerfile"; then
  echo "ERROR: placeholder '${PLACEHOLDER_PTC_BASE}' not found in" >&2
  echo "       proxy-envoy/Dockerfile. The Dockerfile and this script have" >&2
  echo "       drifted apart -- do not build until they agree." >&2
  exit 1
fi
sed "s|${PLACEHOLDER_PTC_BASE}|${PTC_BASE}|g" \
  "${SCRIPT_DIR}/proxy-envoy/Dockerfile" > "${RENDERED_DOCKERFILE}"
echo "  - ${PLACEHOLDER_PTC_BASE}"
echo "    -> ${PTC_BASE}"

# ---------------------------------------------------------------------------
# [6/6] Build and push images
# ---------------------------------------------------------------------------
echo ""
echo "[6/6] Building and pushing images..."
TAG="latest"
TIMESTAMP_TAG="$(date +%Y%m%d-%H%M%S)"

for SERVICE in "${SERVICES[@]}"; do
  SERVICE_DIR="${SCRIPT_DIR}/${SERVICE}"
  REPO_NAME="${ECR_PREFIX}-${SERVICE}"
  IMAGE_URI="${ECR_REGISTRY}/${REPO_NAME}"

  if [[ ! -f "${SERVICE_DIR}/Dockerfile" ]]; then
    echo "  - No Dockerfile in ${SERVICE_DIR}, skipping"
    continue
  fi

  # proxy-envoy builds from the rendered Dockerfile; the others need no
  # substitution and build from their own.
  DOCKERFILE_ARG=()
  if [[ "${SERVICE}" == "proxy-envoy" ]]; then
    DOCKERFILE_ARG=(-f "${RENDERED_DOCKERFILE}")
  fi

  echo ""
  echo "  Building ${SERVICE}..."
  # The ${arr[@]+"${arr[@]}"} guard is required: macOS ships bash 3.2, where
  # expanding an EMPTY array under `set -u` is an "unbound variable" error.
  # Newer bash tolerates "${arr[@]}" directly -- 3.2 does not.
  "${CONTAINER_ENGINE}" build \
    --platform "${PLATFORM}" \
    ${DOCKERFILE_ARG[@]+"${DOCKERFILE_ARG[@]}"} \
    -t "${IMAGE_URI}:${TAG}" \
    -t "${IMAGE_URI}:${TIMESTAMP_TAG}" \
    "${SERVICE_DIR}"

  echo "  Pushing ${SERVICE}..."
  "${CONTAINER_ENGINE}" push "${IMAGE_URI}:${TAG}"
  "${CONTAINER_ENGINE}" push "${IMAGE_URI}:${TIMESTAMP_TAG}"

  echo "  - ${SERVICE} -> ${IMAGE_URI}:${TAG}"
done

echo ""
echo "=============================================="
echo " Build complete!"
echo " Images tagged: ${TAG}, ${TIMESTAMP_TAG}"
echo ""
echo " Envoy base image served through: ${PTC_BASE}"
echo ""
echo " Backend image is deployed twice at the ECS-service level:"
echo "   User Service:  SERVICE_NAME=user-service"
echo "   Order Service: SERVICE_NAME=order-service"
echo "=============================================="
