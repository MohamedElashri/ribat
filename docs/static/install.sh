#!/bin/sh
set -eu

repo="MohamedElashri/ribat"
version="${RIBAT_VERSION:-latest}"
system_install="${RIBAT_INSTALL_SYSTEM:-0}"

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
  if [ -w "$install_dir" ]; then
    mkdir -p "$install_dir"
    install -m 0755 "$tmp/extract/ribat" "$install_dir/ribat"
  elif command -v sudo >/dev/null 2>&1; then
    sudo mkdir -p "$install_dir"
    sudo install -m 0755 "$tmp/extract/ribat" "$install_dir/ribat"
  else
    echo "ribat install: ${install_dir} is not writable and sudo is not available" >&2
    exit 1
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
