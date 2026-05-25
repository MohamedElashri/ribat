#!/bin/sh
set -eu

repo="MohamedElashri/ribat"
version="${RIBAT_VERSION:-latest}"
system_install="${RIBAT_INSTALL_SYSTEM:-0}"
install_docker_dropin="${RIBAT_INSTALL_DOCKER_DROPIN:-0}"
config_path="${RIBAT_CONFIG_PATH:-/etc/ribat/config.yaml}"
state_dir="${RIBAT_STATE_DIR:-/var/lib/ribat}"
audit_dir="${RIBAT_AUDIT_DIR:-/var/log/ribat}"
systemd_unit_dir="${RIBAT_SYSTEMD_UNIT_DIR:-/etc/systemd/system}"
docker_dropin_dir="${RIBAT_DOCKER_DROPIN_DIR:-/etc/systemd/system/docker.service.d}"
use_sudo="${RIBAT_INSTALL_USE_SUDO:-auto}"

default_install_dir() {
  if [ "$system_install" = "1" ] || [ "$system_install" = "true" ]; then
    printf '%s\n' "/usr/local/bin"
    return
  fi
  if [ -n "${XDG_BIN_HOME:-}" ]; then
    printf '%s\n' "$XDG_BIN_HOME"
    return
  fi
  if [ -n "${HOME:-}" ]; then
    printf '%s\n' "$HOME/.local/bin"
    return
  fi
  echo "ribat install: HOME is not set; set RIBAT_INSTALL_DIR to a writable directory" >&2
  exit 1
}

install_dir="${RIBAT_INSTALL_DIR:-$(default_install_dir)}"

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ribat install: missing required command: $1" >&2
    exit 1
  fi
}

need curl
need sed
need tar
need uname
need awk
need install
need mkdir
need id
need dirname

as_root() {
  if [ "$use_sudo" = "0" ] || [ "$use_sudo" = "false" ] || [ "$(id -u)" = "0" ]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    echo "ribat install: root privileges are required for system files and sudo is not available" >&2
    exit 1
  fi
}

os="$(uname -s)"
arch="$(uname -m)"

case "$os" in
  Linux) os="linux" ;;
  Darwin) os="darwin" ;;
  *)
    echo "ribat install: unsupported operating system: $os" >&2
    exit 1
    ;;
esac

case "$arch" in
  x86_64|amd64) arch="amd64" ;;
  arm64|aarch64) arch="arm64" ;;
  *)
    echo "ribat install: unsupported CPU architecture: $arch" >&2
    exit 1
    ;;
esac

if [ "$version" = "latest" ]; then
  version="$(curl -fsSL "https://api.github.com/repos/${repo}/releases/latest" | sed -n 's/.*"tag_name":[[:space:]]*"\(v[^"]*\)".*/\1/p' | head -n 1)"
  if [ -z "$version" ]; then
    echo "ribat install: could not resolve latest release" >&2
    exit 1
  fi
fi

case "$version" in
  v*) tag="$version" ;;
  *) tag="v$version" ;;
esac

archive="ribat_${tag}_${os}_${arch}.tar.gz"
base_url="https://github.com/${repo}/releases/download/${tag}"
raw_url="https://raw.githubusercontent.com/${repo}/${tag}"
tmp="${TMPDIR:-/tmp}/ribat-install.$$"

cleanup() {
  rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

mkdir -p "$tmp/extract"

echo "ribat install: downloading ${archive}"
curl -fL "$base_url/$archive" -o "$tmp/$archive"

echo "ribat install: verifying checksum"
curl -fsSL "$base_url/checksums.txt" -o "$tmp/checksums.txt"
expected="$(awk -v archive="$archive" '$2 == archive { print $1 }' "$tmp/checksums.txt")"
if [ -z "$expected" ]; then
  echo "ribat install: checksum for ${archive} not found" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$tmp" && printf '%s  %s\n' "$expected" "$archive" | sha256sum -c - >/dev/null)
elif command -v shasum >/dev/null 2>&1; then
  actual="$(shasum -a 256 "$tmp/$archive" | awk '{ print $1 }')"
  if [ "$actual" != "$expected" ]; then
    echo "ribat install: checksum mismatch" >&2
    exit 1
  fi
else
  echo "ribat install: sha256sum or shasum not found; skipping checksum verification" >&2
fi

tar -xzf "$tmp/$archive" -C "$tmp/extract"
if [ ! -f "$tmp/extract/ribat" ]; then
  echo "ribat install: archive did not contain a ribat binary" >&2
  exit 1
fi
chmod +x "$tmp/extract/ribat"

if [ "$system_install" = "1" ] || [ "$system_install" = "true" ]; then
  as_root install -d -m 0755 "$install_dir"
  as_root install -m 0755 "$tmp/extract/ribat" "$install_dir/ribat"

  if [ "$os" = "linux" ]; then
    mkdir -p "$tmp/system"

    echo "ribat install: downloading systemd and config files for ${tag}"
    curl -fsSL "$raw_url/configs/ribat.example.yaml" -o "$tmp/system/config.yaml"
    curl -fsSL "$raw_url/packaging/systemd/ribat.service" -o "$tmp/system/ribat.service"
    curl -fsSL "$raw_url/packaging/systemd/docker-ribat.conf" -o "$tmp/system/docker-ribat.conf"
    sed "s#/usr/local/bin/ribat#${install_dir}/ribat#g" "$tmp/system/ribat.service" > "$tmp/system/ribat.service.install"

    as_root install -d -m 0755 "$(dirname "$config_path")"
    if [ -f "$config_path" ]; then
      echo "ribat install: keeping existing ${config_path}"
    else
      as_root install -m 0644 "$tmp/system/config.yaml" "$config_path"
    fi
    as_root install -d -m 0750 "$state_dir"
    as_root install -d -m 0750 "$audit_dir"
    as_root install -d -m 0755 "$systemd_unit_dir"
    as_root install -m 0644 "$tmp/system/ribat.service.install" "$systemd_unit_dir/ribat.service"

    if [ "$install_docker_dropin" = "1" ] || [ "$install_docker_dropin" = "true" ]; then
      as_root install -d -m 0755 "$docker_dropin_dir"
      as_root install -m 0644 "$tmp/system/docker-ribat.conf" "$docker_dropin_dir/10-ribat.conf"
    fi
  fi
else
  mkdir -p "$install_dir"
  install -m 0755 "$tmp/extract/ribat" "$install_dir/ribat"
fi

echo "ribat install: installed to ${install_dir}/ribat"
case ":${PATH:-}:" in
  *:"$install_dir":*) ;;
  *)
    echo "ribat install: add ${install_dir} to PATH to run ribat from any shell" >&2
    ;;
esac
"$install_dir/ribat" version
if [ "$system_install" = "1" ] || [ "$system_install" = "true" ]; then
  if [ "$os" = "linux" ]; then
    echo "ribat install: installed system files; review ${config_path}, then run: sudo systemctl daemon-reload && sudo systemctl enable --now ribat.service" >&2
    echo "ribat install: configure Docker authorization-plugins separately before restarting Docker" >&2
  fi
fi
