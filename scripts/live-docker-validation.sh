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
if [[ "${DENIED_OUTPUT}" != *"new digest observed"* && "${DENIED_OUTPUT}" != *"digest entered quarantine"* ]]; then
  echo "first proxy pull failed without the expected Ribat quarantine reason:" >&2
  echo "${DENIED_OUTPUT}" >&2
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
