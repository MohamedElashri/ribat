#!/usr/bin/env bash
set -euo pipefail

if [[ "${RIBAT_DOCKER_LIVE_TESTS:-}" != "1" ]]; then
  echo "set RIBAT_DOCKER_LIVE_TESTS=1 to run live Docker Engine validation" >&2
  exit 2
fi

RIBAT_BIN="${RIBAT_BIN:-./bin/ribat}"
PROXY_ADDR="${RIBAT_PROXY_ADDR:-127.0.0.1:5055}"
TEST_IMAGE="${RIBAT_LIVE_TEST_IMAGE:-docker.io/library/alpine:latest}"
PROXY_IMAGE="${PROXY_ADDR}/${TEST_IMAGE}"
GHCR_IMAGE="${RIBAT_GHCR_TEST_IMAGE:-ghcr.io/stefanprodan/podinfo:latest}"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/ribat-live.XXXXXX")"
PROXY_PID=""

cleanup() {
  if [[ -n "${PROXY_PID}" ]]; then
    kill "${PROXY_PID}" >/dev/null 2>&1 || true
    wait "${PROXY_PID}" >/dev/null 2>&1 || true
  fi
  docker image rm "${PROXY_IMAGE}" >/dev/null 2>&1 || true
  rm -rf "${WORKDIR}"
}
trap cleanup EXIT

need_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 2
  fi
}

need_command docker
need_command curl
need_command awk

if [[ ! -x "${RIBAT_BIN}" ]]; then
  echo "ribat binary is not executable at ${RIBAT_BIN}; run make build or set RIBAT_BIN" >&2
  exit 2
fi

docker version >/dev/null

CONFIG_PATH="${WORKDIR}/config.yaml"
STATE_PATH="${WORKDIR}/state.db"
AUDIT_PATH="${WORKDIR}/audit.jsonl"
PROXY_LOG="${WORKDIR}/proxy.log"

cat >"${CONFIG_PATH}" <<EOF_CONFIG
version: 1

default_policy:
  mutable_tags:
    action: quarantine
    min_digest_age: 24h
    allow_first_seen_pull: false
  digest_pinned_images:
    action: allow
  failed_registry_resolution:
    action: deny
  failed_signature_check:
    action: deny

audit:
  path: "${AUDIT_PATH}"

state:
  backend: sqlite
  path: "${STATE_PATH}"
EOF_CONFIG

echo "starting Ribat proxy on ${PROXY_ADDR}"
"${RIBAT_BIN}" proxy --config "${CONFIG_PATH}" --listen "${PROXY_ADDR}" >"${PROXY_LOG}" 2>&1 &
PROXY_PID="$!"

for _ in $(seq 1 50); do
  if curl -fsS "http://${PROXY_ADDR}/v2/" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "${PROXY_PID}" >/dev/null 2>&1; then
    echo "ribat proxy exited early:" >&2
    cat "${PROXY_LOG}" >&2
    exit 1
  fi
  sleep 0.1
done

if ! curl -fsS "http://${PROXY_ADDR}/v2/" >/dev/null 2>&1; then
  echo "ribat proxy did not become ready at ${PROXY_ADDR}" >&2
  cat "${PROXY_LOG}" >&2
  exit 1
fi

echo "checking first-seen proxy pull denial for ${PROXY_IMAGE}"
set +e
DENIED_OUTPUT="$(docker pull "${PROXY_IMAGE}" 2>&1)"
DENIED_CODE=$?
set -e
if [[ "${DENIED_CODE}" -eq 0 ]]; then
  echo "expected first proxy pull to be denied, but it succeeded" >&2
  exit 1
fi
if [[ "${DENIED_OUTPUT}" != *"new digest observed"* && "${DENIED_OUTPUT}" != *"digest entered quarantine"* && "${DENIED_OUTPUT}" != *"403 Forbidden"* ]]; then
  echo "first proxy pull failed without the expected Ribat quarantine reason:" >&2
  echo "${DENIED_OUTPUT}" >&2
  exit 1
fi
if ! grep -q '"decision":"deny"' "${AUDIT_PATH}"; then
  echo "first proxy pull did not write a Ribat deny decision:" >&2
  cat "${AUDIT_PATH}" >&2
  exit 1
fi

DIGEST="$("${RIBAT_BIN}" inspect "${TEST_IMAGE}" | awk -F': ' '/^Remote digest:/ {print $2}')"
if [[ "${DIGEST}" != sha256:* ]]; then
  echo "could not resolve digest for ${TEST_IMAGE}; got ${DIGEST}" >&2
  exit 1
fi

echo "approving ${TEST_IMAGE}@${DIGEST}"
"${RIBAT_BIN}" approve --config "${CONFIG_PATH}" "${TEST_IMAGE}@${DIGEST}" --ttl 1h --reason "live Docker proxy validation" >/dev/null

echo "checking approved proxy pull for ${PROXY_IMAGE}"
docker pull "${PROXY_IMAGE}" >/dev/null

if [[ ! -s "${AUDIT_PATH}" ]]; then
  echo "audit log was not written at ${AUDIT_PATH}" >&2
  exit 1
fi
if ! grep -q '"decision":"deny"' "${AUDIT_PATH}" || ! grep -q '"decision":"allow"' "${AUDIT_PATH}"; then
  echo "audit log does not contain both deny and allow decisions:" >&2
  cat "${AUDIT_PATH}" >&2
  exit 1
fi

echo "proxy validation passed"

validate_proxy_image() {
  local image="$1"
  local proxied_image="${PROXY_ADDR}/${image}"
  local digest
  echo "checking first-seen proxy denial for ${proxied_image}"
  set +e
  local denied_output
  denied_output="$(docker pull "${proxied_image}" 2>&1)"
  local denied_code=$?
  set -e
  if [[ "${denied_code}" -eq 0 ]]; then
    echo "expected first proxy pull for ${proxied_image} to be denied, but it succeeded" >&2
    exit 1
  fi
  if [[ "${denied_output}" != *"new digest observed"* && "${denied_output}" != *"digest entered quarantine"* && "${denied_output}" != *"403 Forbidden"* ]]; then
    echo "first proxy pull for ${proxied_image} failed without the expected Ribat quarantine reason:" >&2
    echo "${denied_output}" >&2
    exit 1
  fi

  digest="$("${RIBAT_BIN}" inspect "${image}" | awk -F': ' '/^Remote digest:/ {print $2}')"
  if [[ "${digest}" != sha256:* ]]; then
    echo "could not resolve digest for ${image}; got ${digest}" >&2
    exit 1
  fi

  echo "approving ${image}@${digest}"
  "${RIBAT_BIN}" approve --config "${CONFIG_PATH}" "${image}@${digest}" --ttl 1h --reason "live Docker proxy validation for ${image}" >/dev/null
  echo "checking approved proxy pull for ${proxied_image}"
  docker pull "${proxied_image}" >/dev/null
  docker image rm "${proxied_image}" >/dev/null 2>&1 || true
}

if [[ "${RIBAT_VALIDATE_GHCR:-}" == "1" ]]; then
  validate_proxy_image "${GHCR_IMAGE}"
  echo "GHCR proxy validation passed"
fi

if [[ "${RIBAT_VALIDATE_COSIGN:-}" == "1" ]]; then
  need_command cosign
  COSIGN_IMAGE="${RIBAT_COSIGN_IMAGE:-}"
  COSIGN_ISSUER="${RIBAT_COSIGN_ISSUER:-https://token.actions.githubusercontent.com}"
  COSIGN_IDENTITY="${RIBAT_COSIGN_IDENTITY:-}"
  COSIGN_IDENTITY_REGEX="${RIBAT_COSIGN_IDENTITY_REGEX:-}"
  if [[ -z "${COSIGN_IMAGE}" ]]; then
    echo "set RIBAT_COSIGN_IMAGE to a known signed image when RIBAT_VALIDATE_COSIGN=1" >&2
    exit 2
  fi
  if [[ -z "${COSIGN_IDENTITY}" && -z "${COSIGN_IDENTITY_REGEX}" ]]; then
    echo "set RIBAT_COSIGN_IDENTITY or RIBAT_COSIGN_IDENTITY_REGEX for strict keyless verification" >&2
    exit 2
  fi

  COSIGN_CONFIG="${WORKDIR}/cosign-config.yaml"
  COSIGN_FAIL_CONFIG="${WORKDIR}/cosign-fail-config.yaml"
  COSIGN_STATE="${WORKDIR}/cosign-state.db"
  COSIGN_AUDIT="${WORKDIR}/cosign-audit.jsonl"
  COSIGN_FAIL_STATE="${WORKDIR}/cosign-fail-state.db"
  COSIGN_FAIL_AUDIT="${WORKDIR}/cosign-fail-audit.jsonl"
  COSIGN_DIGEST="$("${RIBAT_BIN}" inspect "${COSIGN_IMAGE}" | awk -F': ' '/^Remote digest:/ {print $2}')"
  if [[ "${COSIGN_DIGEST}" != sha256:* ]]; then
    echo "could not resolve digest for ${COSIGN_IMAGE}; got ${COSIGN_DIGEST}" >&2
    exit 1
  fi

  cat >"${COSIGN_CONFIG}" <<EOF_COSIGN
version: 1

default_policy:
  mutable_tags:
    action: quarantine
    min_digest_age: 24h
    allow_first_seen_pull: false
  digest_pinned_images:
    action: allow
  failed_registry_resolution:
    action: deny
  failed_signature_check:
    action: deny
  signatures:
    cosign:
      required: true
      mode: keyless
      issuer: "${COSIGN_ISSUER}"
EOF_COSIGN
  if [[ -n "${COSIGN_IDENTITY}" ]]; then
    printf '      identity: "%s"\n' "${COSIGN_IDENTITY}" >>"${COSIGN_CONFIG}"
  else
    printf '      identity_regex: "%s"\n' "${COSIGN_IDENTITY_REGEX}" >>"${COSIGN_CONFIG}"
  fi
  cat >>"${COSIGN_CONFIG}" <<EOF_COSIGN

audit:
  path: "${COSIGN_AUDIT}"

state:
  backend: sqlite
  path: "${COSIGN_STATE}"
EOF_COSIGN

  cat >"${COSIGN_FAIL_CONFIG}" <<EOF_COSIGN_FAIL
version: 1

default_policy:
  mutable_tags:
    action: quarantine
    min_digest_age: 24h
    allow_first_seen_pull: false
  digest_pinned_images:
    action: allow
  failed_registry_resolution:
    action: deny
  failed_signature_check:
    action: deny
  signatures:
    cosign:
      required: true
      mode: keyless
      issuer: "${COSIGN_ISSUER}"
      identity_regex: "^https://ribat.invalid/no/matching/identity$"

audit:
  path: "${COSIGN_FAIL_AUDIT}"

state:
  backend: sqlite
  path: "${COSIGN_FAIL_STATE}"
EOF_COSIGN_FAIL

  echo "checking Cosign allow path for ${COSIGN_IMAGE}@${COSIGN_DIGEST}"
  "${RIBAT_BIN}" decide --config "${COSIGN_CONFIG}" "${COSIGN_IMAGE}@${COSIGN_DIGEST}" | grep -q "Decision: ALLOW"
  grep -q '"cosign_verified":true' "${COSIGN_AUDIT}"

  echo "checking Cosign deny path for ${COSIGN_IMAGE}@${COSIGN_DIGEST}"
  set +e
  COSIGN_DENY_OUTPUT="$("${RIBAT_BIN}" decide --config "${COSIGN_FAIL_CONFIG}" "${COSIGN_IMAGE}@${COSIGN_DIGEST}" 2>&1)"
  COSIGN_DENY_CODE=$?
  set -e
  if [[ "${COSIGN_DENY_CODE}" -eq 0 ]]; then
    echo "expected Cosign verification with impossible identity to deny" >&2
    exit 1
  fi
  echo "${COSIGN_DENY_OUTPUT}" | grep -q "Decision: DENY"
  grep -q '"decision":"deny"' "${COSIGN_FAIL_AUDIT}"
  echo "Cosign live validation passed"
fi

if [[ "${RIBAT_VALIDATE_INSTALLED_AUTHZ:-}" == "1" ]]; then
  AUTHZ_SOCKET="${RIBAT_AUTHZ_SOCKET:-/run/docker/plugins/ribat.sock}"
  AUTHZ_IMAGE="${RIBAT_AUTHZ_TEST_IMAGE:-${TEST_IMAGE}}"
  echo "checking installed Docker AuthZ plugin at ${AUTHZ_SOCKET}"
  curl -fsS --unix-socket "${AUTHZ_SOCKET}" -X POST http://localhost/Plugin.Activate | grep -q '"authz"'

  set +e
  AUTHZ_OUTPUT="$(docker pull "${AUTHZ_IMAGE}" 2>&1)"
  AUTHZ_CODE=$?
  set -e
  if [[ "${AUTHZ_CODE}" -eq 0 ]]; then
    echo "installed AuthZ validation expected a denial for ${AUTHZ_IMAGE}, but pull succeeded" >&2
    echo "choose a fresh mutable tag or unset RIBAT_VALIDATE_INSTALLED_AUTHZ" >&2
    exit 1
  fi
  if [[ "${AUTHZ_OUTPUT}" != *"Pull blocked by Ribat"* && "${AUTHZ_OUTPUT}" != *"Ribat"* ]]; then
    echo "installed AuthZ pull failed without a Ribat denial message:" >&2
    echo "${AUTHZ_OUTPUT}" >&2
    exit 1
  fi
  echo "installed AuthZ validation passed"
fi

echo "live Docker validation completed"
