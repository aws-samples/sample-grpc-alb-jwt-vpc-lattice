#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# End-to-end verification for the gRPC + Amazon VPC Lattice reference
# architecture. Confirms that each security boundary rejects unauthorized
# requests independently.
#
# Tests performed:
#   1. Obtain an access token from Amazon Cognito (client_credentials grant)
#   2. SDK path   -> User Service   (expect success)
#   3. Envoy path -> Order Service  (expect success)
#   4. No token                     (expect HTTP 401 at the ALB)
#   5. Malformed token              (expect HTTP 401 at the ALB)
#   6. Unknown gRPC package         (expect HTTP 404 at the ALB)
#   7. Cross-role denial            (expect PERMISSION_DENIED from VPC Lattice)
#
# Test 7 is opt-in: it briefly repoints the SDK proxy at the Order Service,
# where neither SdkTaskRole's IAM policy nor the auth policy allows it, then
# reverts the change automatically, including on failure.
#
# Usage:
#   ./test-auth-matrix.sh --stack <stack-name> [--region <region>]
#                         [--test-cross-role]
#
# Requirements: aws CLI v2, grpcurl, jq

set -euo pipefail

STACK=""
REGION="${AWS_REGION:-us-east-1}"
TEST_CROSS_ROLE=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --stack)           STACK="$2"; shift 2 ;;
    --region)          REGION="$2"; shift 2 ;;
    --test-cross-role) TEST_CROSS_ROLE=true; shift ;;
    -h|--help)
      sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

STACK="${STACK:?--stack <stack-name> is required}"

for tool in aws grpcurl jq; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "ERROR: '$tool' is required but not installed." >&2
    exit 1
  }
done

PASS=0
FAIL=0

ok()   { printf '  [PASS] %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  [FAIL] %s\n' "$1"; FAIL=$((FAIL+1)); }
info() { printf '  %s\n' "$1"; }

hr() { printf '%s\n' "------------------------------------------------------------"; }

# ---------------------------------------------------------------------------
# Read stack outputs
# ---------------------------------------------------------------------------
hr
echo "Reading outputs from stack: ${STACK} (${REGION})"
hr

outputs_json="$(aws cloudformation describe-stacks \
  --stack-name "${STACK}" --region "${REGION}" \
  --query 'Stacks[0].Outputs' --output json)"

get_output() {
  echo "${outputs_json}" | jq -r --arg k "$1" \
    '.[] | select(.OutputKey==$k) | .OutputValue'
}

ALB_DNS="$(get_output AlbDnsName)"
TOKEN_ENDPOINT="$(get_output CognitoTokenEndpoint)"
SCOPE="$(get_output CognitoScope)"
USER_POOL_ID="$(get_output CognitoUserPoolId)"
SDK_CLIENT_ID="$(get_output SdkClientId)"
ORDER_SVC_DNS="$(get_output OrderServiceDns)"
PROXY_CLUSTER="$(get_output ProxyClusterName)"

[[ -n "${ALB_DNS}" ]] || { echo "ERROR: could not read stack outputs." >&2; exit 1; }

info "ALB:            ${ALB_DNS}"
info "Token endpoint: ${TOKEN_ENDPOINT}"

# The sample ACM certificate will not match the ALB DNS name, so TLS
# verification is skipped for these tests. With a real certificate and a
# matching DNS record, drop -insecure.
GRPCURL_TLS="-insecure"

# ---------------------------------------------------------------------------
# 1. Obtain an access token
# ---------------------------------------------------------------------------
hr
echo "1. Obtain access token (client_credentials)"
hr

CLIENT_SECRET="$(aws cognito-idp describe-user-pool-client \
  --user-pool-id "${USER_POOL_ID}" \
  --client-id "${SDK_CLIENT_ID}" \
  --region "${REGION}" \
  --query 'UserPoolClient.ClientSecret' --output text)"

TOKEN="$(curl -sS -X POST "${TOKEN_ENDPOINT}" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "grant_type=client_credentials&client_id=${SDK_CLIENT_ID}&client_secret=${CLIENT_SECRET}&scope=${SCOPE}" \
  | jq -r '.access_token // empty')"

if [[ -n "${TOKEN}" ]]; then
  ok "token acquired (${#TOKEN} chars)"
  # Decode the payload to show the claims the proxy will translate.
  claims="$(echo "${TOKEN}" | cut -d. -f2 \
    | tr '_-' '/+' | sed 's/$/===/' | base64 -d 2>/dev/null \
    | jq -c '{client_id, scope}' 2>/dev/null || echo '{}')"
  info "claims: ${claims}"
else
  bad "could not obtain a token -- cannot continue"
  exit 1
fi

# ---------------------------------------------------------------------------
# Helper: call a gRPC method through the ALB
# ---------------------------------------------------------------------------
# Prints the raw grpcurl output; caller inspects it.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROTO_DIR="${SCRIPT_DIR}/proto"

# grpcurl requires -import-path when -proto is given as a path, so the proto
# is referenced by filename relative to the import path.
#
# The empty-header case is handled without an empty array expansion, because
# bash 3.2 (the macOS default) errors on "${arr[@]}" for an empty array when
# `set -u` is active.
call_grpc() {
  local proto="$1" method="$2" auth="$3" payload="${4:-{\"id\":\"test-1\"}}"
  if [[ -n "${auth}" ]]; then
    grpcurl "${GRPCURL_TLS}" \
      -H "authorization: Bearer ${auth}" \
      -d "${payload}" \
      -import-path "${PROTO_DIR}" -proto "${proto}" \
      -max-time 25 \
      "${ALB_DNS}:443" "${method}" 2>&1 || true
  else
    grpcurl "${GRPCURL_TLS}" \
      -d "${payload}" \
      -import-path "${PROTO_DIR}" -proto "${proto}" \
      -max-time 25 \
      "${ALB_DNS}:443" "${method}" 2>&1 || true
  fi
}

SDK_PROTO="sdk_service.proto"
ENVOY_PROTO="envoy_service.proto"

# ---------------------------------------------------------------------------
# 2. SDK path -> User Service (expect success)
# ---------------------------------------------------------------------------
hr
echo "2. SDK path: sdk.DemoService/GetInfo -> User Service"
hr

out="$(call_grpc "${SDK_PROTO}" sdk.DemoService/GetInfo "${TOKEN}")"
if echo "${out}" | grep -q '"serviceName": *"user-service"'; then
  ok "reached user-service through the SDK proxy"
  info "$(echo "${out}" | jq -c '{serviceName, clientId, clientScope}' 2>/dev/null || true)"
elif echo "${out}" | grep -q 'serviceName'; then
  bad "responded, but not from user-service"
  info "${out}"
else
  bad "call failed"
  info "${out}"
fi

# ---------------------------------------------------------------------------
# 3. Envoy path -> Order Service (expect success)
# ---------------------------------------------------------------------------
hr
echo "3. Envoy path: envoy.DemoService/GetInfo -> Order Service"
hr

out="$(call_grpc "${ENVOY_PROTO}" envoy.DemoService/GetInfo "${TOKEN}")"
if echo "${out}" | grep -q '"serviceName": *"order-service"'; then
  ok "reached order-service through the Envoy proxy"
  info "$(echo "${out}" | jq -c '{serviceName, clientId, clientScope}' 2>/dev/null || true)"
elif echo "${out}" | grep -q 'serviceName'; then
  bad "responded, but not from order-service"
  info "${out}"
else
  bad "call failed"
  info "${out}"
fi

# ---------------------------------------------------------------------------
# 4. No token (expect ALB 401)
# ---------------------------------------------------------------------------
hr
echo "4. No token (expect HTTP 401 at the ALB)"
hr

out="$(call_grpc "${SDK_PROTO}" sdk.DemoService/GetInfo "")"
if echo "${out}" | grep -qiE '401|Unauthenticated|Unauthorized'; then
  ok "rejected without a token"
else
  bad "expected 401/UNAUTHENTICATED"
  info "${out}"
fi

# ---------------------------------------------------------------------------
# 5. Malformed token (expect ALB 401)
# ---------------------------------------------------------------------------
hr
echo "5. Malformed token (expect HTTP 401 at the ALB)"
hr

out="$(call_grpc "${SDK_PROTO}" sdk.DemoService/GetInfo "not.a.valid.jwt")"
if echo "${out}" | grep -qiE '401|Unauthenticated|Unauthorized'; then
  ok "rejected an invalid token"
else
  bad "expected 401/UNAUTHENTICATED"
  info "${out}"
fi

# ---------------------------------------------------------------------------
# 6. Unknown gRPC package (expect ALB 404 via the default action)
# ---------------------------------------------------------------------------
hr
echo "6. Unknown package (expect HTTP 404 at the ALB default action)"
hr

# demo.* matches neither /sdk.* nor /envoy.*, so the listener default action
# validates the JWT and then returns 404.
out="$(call_grpc "demo.proto" demo.DemoService/GetInfo "${TOKEN}")"
if echo "${out}" | grep -qiE '404|Not Found|Unimplemented'; then
  ok "unrouted path rejected"
else
  bad "expected 404/Not Found"
  info "${out}"
fi

# ---------------------------------------------------------------------------
# 7. Cross-role denial (opt-in)
# ---------------------------------------------------------------------------
if [[ "${TEST_CROSS_ROLE}" == "true" ]]; then
  hr
  echo "7. Cross-role denial: SdkTaskRole -> Order Service (expect denial)"
  hr
  info "Temporarily repointing the SDK proxy at the Order Service."
  info "SdkTaskRole is not permitted on the Order Service, so VPC Lattice"
  info "should reject the signed request even though the signature is valid."

  SDK_SERVICE="${STACK}-sdk"
  ORIGINAL_TD="$(aws ecs describe-services \
    --cluster "${PROXY_CLUSTER}" --services "${SDK_SERVICE}" \
    --region "${REGION}" \
    --query 'services[0].taskDefinition' --output text)"

  revert() {
    info "Reverting the SDK proxy to ${ORIGINAL_TD##*/}"
    aws ecs update-service --cluster "${PROXY_CLUSTER}" --service "${SDK_SERVICE}" \
      --task-definition "${ORIGINAL_TD}" --region "${REGION}" >/dev/null
    aws ecs wait services-stable --cluster "${PROXY_CLUSTER}" \
      --services "${SDK_SERVICE}" --region "${REGION}" || true
    info "Revert complete."
  }
  trap revert EXIT

  # Build a task definition revision identical to the current one except that
  # LATTICE_USER_SVC points at the Order Service.
  aws ecs describe-task-definition --task-definition "${ORIGINAL_TD}" \
    --region "${REGION}" --query 'taskDefinition' --output json \
    > /tmp/td-original.json

  jq --arg dns "${ORDER_SVC_DNS}" '
    {
      family, networkMode, requiresCompatibilities, cpu, memory,
      executionRoleArn, taskRoleArn,
      containerDefinitions: (
        .containerDefinitions | map(
          .environment = (
            .environment | map(
              if .name == "LATTICE_USER_SVC" then .value = $dns else . end
            )
          )
        )
      )
    }' /tmp/td-original.json > /tmp/td-crossrole.json

  NEW_TD="$(aws ecs register-task-definition \
    --cli-input-json file:///tmp/td-crossrole.json \
    --region "${REGION}" \
    --query 'taskDefinition.taskDefinitionArn' --output text)"
  info "Registered ${NEW_TD##*/}"

  aws ecs update-service --cluster "${PROXY_CLUSTER}" --service "${SDK_SERVICE}" \
    --task-definition "${NEW_TD}" --region "${REGION}" >/dev/null
  info "Waiting for the SDK proxy to stabilize..."
  aws ecs wait services-stable --cluster "${PROXY_CLUSTER}" \
    --services "${SDK_SERVICE}" --region "${REGION}"

  out="$(call_grpc "${SDK_PROTO}" sdk.DemoService/GetInfo "${TOKEN}")"
  if echo "${out}" | grep -qiE 'PermissionDenied|Access denied|403'; then
    ok "VPC Lattice denied SdkTaskRole on the Order Service"
    info "Denied: neither SdkTaskRole's IAM policy nor the Order Service auth"
    info "policy allows SdkTaskRole on the Order Service."
  else
    bad "expected a permission denial"
    info "${out}"
  fi

  rm -f /tmp/td-original.json /tmp/td-crossrole.json
  # trap performs the revert
else
  hr
  echo "7. Cross-role denial -- skipped"
  hr
  info "Re-run with --test-cross-role to verify that VPC Lattice denies a"
  info "valid signature from the wrong workload identity. That test briefly"
  info "repoints the SDK proxy and then reverts it."
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
hr
printf 'Results: %d passed, %d failed\n' "${PASS}" "${FAIL}"
hr
[[ "${FAIL}" -eq 0 ]] || exit 1
