#!/usr/bin/env bash
set -euo pipefail

if [[ "${RIBAT_HOST_LIVE_TESTS:-}" != "1" ]]; then
  echo "set RIBAT_HOST_LIVE_TESTS=1 to run installed host AuthZ validation" >&2
  exit 2
fi
if [[ "${RIBAT_HOST_LIVE_MUTATE_DOCKER:-}" != "1" ]]; then
  echo "set RIBAT_HOST_LIVE_MUTATE_DOCKER=1 to allow Docker daemon config changes and restarts" >&2
  exit 2
fi

INSTALL_MODE="${RIBAT_HOST_INSTALL_MODE:-installer}"
INSTALL_VERSION="${RIBAT_VERSION:-latest}"
TEST_IMAGE="${RIBAT_HOST_AUTHZ_TEST_IMAGE:-docker.io/library/busybox:latest}"
CONFIG_PATH="${RIBAT_HOST_CONFIG_PATH:-/etc/ribat/config.yaml}"
STATE_PATH="${RIBAT_HOST_STATE_PATH:-/var/lib/ribat/live-authz-state.db}"
AUDIT_PATH="${RIBAT_HOST_AUDIT_PATH:-/var/log/ribat/live-authz-audit.jsonl}"
DAEMON_JSON="${RIBAT_DOCKER_DAEMON_JSON:-/etc/docker/daemon.json}"
DROPIN_PATH="${RIBAT_DOCKER_DROPIN_PATH:-/etc/systemd/system/docker.service.d/10-ribat.conf}"
SERVICE_PATH="${RIBAT_SERVICE_PATH:-/etc/systemd/system/ribat.service}"
INSTALL_SCRIPT="${RIBAT_INSTALL_SCRIPT:-docs/static/install.sh}"
RIBAT_BIN="${RIBAT_SYSTEM_RIBAT_BIN:-/usr/local/bin/ribat}"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/ribat-host-authz.XXXXXX")"

need_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 2
  fi
}

need_command docker
need_command systemctl
need_command curl
need_command awk
need_command python3
need_command sudo

root_ready="0"

run_root() {
  if [[ "$(id -u)" == "0" ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

run_root_env() {
  if [[ "$(id -u)" == "0" ]]; then
    env "$@"
  else
    sudo -n env "$@"
  fi
}

run_step() {
  echo "$1"
  shift
  "$@"
}

run_root_step() {
  echo "$1"
  shift
  run_root "$@"
}

restart_docker_with_diagnostics() {
  local label="$1"
  echo "$label"
  if ! run_root systemctl restart docker; then
    echo "Docker restart failed; diagnostics follow" >&2
    echo "Docker daemon config at ${DAEMON_JSON}:" >&2
    run_root cat "$DAEMON_JSON" >&2 || true
    echo "Docker drop-in at ${DROPIN_PATH}:" >&2
    run_root cat "$DROPIN_PATH" >&2 || true
    echo "ribat.service status:" >&2
    run_root systemctl --no-pager status ribat.service >&2 || true
    echo "docker.service status:" >&2
    run_root systemctl --no-pager status docker.service >&2 || true
    echo "recent Ribat logs:" >&2
    run_root journalctl -u ribat.service -n 80 --no-pager >&2 || true
    echo "recent Docker logs:" >&2
    run_root journalctl -u docker.service -n 120 --no-pager >&2 || true
    return 1
  fi
}

file_existed() {
  local marker="$1"
  [[ -f "${marker}.exists" ]]
}

backup_file() {
  local path="$1"
  local name="$2"
  if run_root test -e "$path"; then
    run_root cp -a "$path" "${WORKDIR}/${name}"
    touch "${WORKDIR}/${name}.exists"
  fi
}

restore_file() {
  local path="$1"
  local name="$2"
  if file_existed "${WORKDIR}/${name}"; then
    run_root install -d -m 0755 "$(dirname "$path")"
    run_root cp -a "${WORKDIR}/${name}" "$path"
  else
    run_root rm -f "$path"
  fi
}

docker_was_active="unknown"
ribat_was_active="unknown"
ribat_was_enabled="unknown"
docker_had_ribat_authz="0"

cleanup() {
  set +e
  if [[ "$root_ready" != "1" ]]; then
    rm -rf "$WORKDIR"
    return
  fi
  echo "restoring Docker and Ribat host state"
  run_root systemctl stop ribat.service >/dev/null 2>&1
  restore_file "$DAEMON_JSON" daemon.json
  restore_file "$DROPIN_PATH" docker-ribat.conf
  restore_file "$SERVICE_PATH" ribat.service
  restore_file "$CONFIG_PATH" ribat-config.yaml
  restore_file "$RIBAT_BIN" ribat-bin
  run_root rm -f "$STATE_PATH" "$AUDIT_PATH"
  run_root systemctl daemon-reload >/dev/null 2>&1
  if [[ "$ribat_was_enabled" == "enabled" ]]; then
    run_root systemctl enable ribat.service >/dev/null 2>&1
  else
    run_root systemctl disable ribat.service >/dev/null 2>&1
  fi
  if [[ "$ribat_was_active" == "active" ]]; then
    run_root systemctl start ribat.service >/dev/null 2>&1
  fi
  if [[ "$docker_was_active" == "active" ]]; then
    run_root systemctl restart docker >/dev/null 2>&1
  fi
  docker version >/dev/null 2>&1 || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

if [[ "$(id -u)" != "0" ]]; then
  if ! sudo -n true >/dev/null 2>&1; then
    echo "passwordless sudo or root is required for installed host AuthZ validation" >&2
    exit 2
  fi
fi
root_ready="1"

docker_was_active="$(systemctl is-active docker 2>/dev/null || true)"
ribat_was_active="$(systemctl is-active ribat.service 2>/dev/null || true)"
ribat_was_enabled="$(systemctl is-enabled ribat.service 2>/dev/null || true)"
if docker info --format '{{json .SecurityOptions}}' 2>/dev/null | grep -qi 'ribat'; then
  docker_had_ribat_authz="1"
fi

backup_file "$DAEMON_JSON" daemon.json
backup_file "$DROPIN_PATH" docker-ribat.conf
backup_file "$SERVICE_PATH" ribat.service
backup_file "$CONFIG_PATH" ribat-config.yaml
backup_file "$RIBAT_BIN" ribat-bin

echo "installing Ribat host files with mode ${INSTALL_MODE}"
case "$INSTALL_MODE" in
  installer)
    run_root_env \
      RIBAT_VERSION="$INSTALL_VERSION" \
      RIBAT_INSTALL_SYSTEM=1 \
      RIBAT_INSTALL_DOCKER_DROPIN=1 \
      sh "$INSTALL_SCRIPT"
    ;;
  source)
    run_root_env "PATH=$PATH" make install
    run_root_env "PATH=$PATH" make install-docker-dropin
    ;;
  *)
    echo "unsupported RIBAT_HOST_INSTALL_MODE=${INSTALL_MODE}; use installer or source" >&2
    exit 2
    ;;
esac

run_root install -d -m 0755 "$(dirname "$CONFIG_PATH")"
run_root install -d -m 0750 "$(dirname "$STATE_PATH")"
run_root install -d -m 0750 "$(dirname "$AUDIT_PATH")"
run_root tee "$CONFIG_PATH" >/dev/null <<EOF_CONFIG
version: 1

default_policy:
  mutable_tags:
    action: quarantine
    min_digest_age: 720h
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

echo "enabling ribat.service"
run_root_step "reloading systemd daemon" systemctl daemon-reload
run_root_step "enabling and starting ribat.service" systemctl enable --now ribat.service

for _ in $(seq 1 50); do
  if run_root curl -fsS --unix-socket /run/docker/plugins/ribat.sock -X POST http://localhost/Plugin.Activate >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done
echo "checking ribat plugin activation"
run_root curl -fsS --unix-socket /run/docker/plugins/ribat.sock -X POST http://localhost/Plugin.Activate | grep -q '"authz"'

echo "configuring Docker authorization plugin"
run_root install -d -m 0755 "$(dirname "$DAEMON_JSON")"
run_root python3 - "$DAEMON_JSON" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
if path.exists() and path.read_text().strip():
    data = json.loads(path.read_text())
else:
    data = {}
plugins = data.get("authorization-plugins", [])
if not isinstance(plugins, list):
    raise SystemExit("authorization-plugins must be a JSON array")
if "ribat" not in plugins:
    plugins.append("ribat")
data["authorization-plugins"] = plugins
path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
PY

run_root_step "reloading systemd daemon after Docker config change" systemctl daemon-reload
restart_docker_with_diagnostics "restarting Docker with Ribat authorization plugin"
run_step "checking Docker API after restart" docker version
security_options="$(docker info --format '{{json .SecurityOptions}}')"
echo "Docker security options: ${security_options}"
if ! grep -qi 'ribat' <<<"${security_options}"; then
  echo "Docker info did not report Ribat in SecurityOptions; continuing with real pull enforcement check"
fi

echo "checking installed AuthZ first-seen denial for ${TEST_IMAGE}"
docker image rm "$TEST_IMAGE" >/dev/null 2>&1 || true
set +e
deny_output="$(docker pull "$TEST_IMAGE" 2>&1)"
deny_code=$?
set -e
if [[ "$deny_code" -eq 0 ]]; then
  echo "expected Docker pull to be denied by installed AuthZ plugin" >&2
  echo "Docker daemon config at ${DAEMON_JSON}:" >&2
  run_root cat "$DAEMON_JSON" >&2 || true
  echo "ribat.service status:" >&2
  run_root systemctl --no-pager status ribat.service >&2 || true
  echo "recent Docker logs:" >&2
  run_root journalctl -u docker.service -n 80 --no-pager >&2 || true
  exit 1
fi
if [[ "$deny_output" != *"Ribat"* && "$deny_output" != *"authorization denied"* ]]; then
  echo "Docker pull failed without an AuthZ/Ribat denial message:" >&2
  echo "$deny_output" >&2
  exit 1
fi

digest="$("$RIBAT_BIN" inspect "$TEST_IMAGE" | awk -F': ' '/^Remote digest:/ {print $2}')"
if [[ "$digest" != sha256:* ]]; then
  echo "could not resolve digest for ${TEST_IMAGE}; got ${digest}" >&2
  exit 1
fi

echo "approving ${TEST_IMAGE}@${digest}"
run_root "$RIBAT_BIN" approve --config "$CONFIG_PATH" "$TEST_IMAGE@$digest" --ttl 1h --reason "live installed AuthZ validation" --by live-host-validation >/dev/null

echo "checking installed AuthZ approved pull for ${TEST_IMAGE}"
docker pull "$TEST_IMAGE" >/dev/null

run_root grep -q '"decision":"deny"' "$AUDIT_PATH"
run_root grep -q '"decision":"allow"' "$AUDIT_PATH"

echo "checking service restart and logs"
run_root systemctl restart ribat.service
run_root curl -fsS --unix-socket /run/docker/plugins/ribat.sock -X POST http://localhost/Plugin.Activate | grep -q '"authz"'
run_root journalctl -u ribat.service -n 50 --no-pager >/dev/null

echo "checking rollback restores Docker without Ribat authorization"
restore_file "$DAEMON_JSON" daemon.json
restore_file "$DROPIN_PATH" docker-ribat.conf
run_root systemctl daemon-reload
restart_docker_with_diagnostics "restarting Docker after rollback"
docker version >/dev/null
if [[ "$docker_had_ribat_authz" != "1" ]]; then
  if docker info --format '{{json .SecurityOptions}}' | grep -qi 'ribat'; then
    echo "Docker still reports Ribat authorization after rollback" >&2
    exit 1
  fi
fi

echo "installed host AuthZ validation passed"
