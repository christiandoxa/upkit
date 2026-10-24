#!/bin/sh
set -eu

release=${UPKIT_RELEASE:-latest}
install_dir=${UPKIT_INSTALL_DIR:-"$HOME/.local/bin"}
while [ "$#" -gt 0 ]; do
  case "$1" in
    --release|--install-dir)
      [ "$#" -ge 2 ] || { echo "$1 requires a value" >&2; exit 1; }
      case "$1" in
        --release) release=$2 ;;
        --install-dir) install_dir=$2 ;;
      esac
      shift 2
      ;;
    --help|-h)
      echo 'Usage: install.sh [--release VERSION] [--install-dir DIR]'
      exit 0
      ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [ "$release" != latest ]; then
  printf '%s\n' "$release" | grep -Eq '^v?[0-9]+\.[0-9]+\.[0-9]+$' || {
    echo "Invalid release: $release" >&2; exit 1;
  }
  case "$release" in v*) ;; *) release="v$release" ;; esac
fi
[ -n "$install_dir" ] || { echo 'Install directory must not be empty' >&2; exit 1; }

case "$(uname -s)" in
  Linux) platform=unknown-linux-gnu ;;
  Darwin) platform=apple-darwin ;;
  *) echo 'Supported systems: Linux and macOS' >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=x86_64 ;;
  arm64|aarch64) arch=aarch64 ;;
  *) echo 'Supported architectures: x86_64 and ARM64' >&2; exit 1 ;;
esac
asset="upkit-$arch-$platform"
base_url=${UPKIT_RELEASE_BASE_URL:-}
if [ -z "$base_url" ]; then
  if [ "$release" = latest ]; then
    base_url=https://github.com/christiandoxa/upkit/releases/latest/download
  else
    base_url="https://github.com/christiandoxa/upkit/releases/download/$release"
  fi
fi
download() {
  if [ -f "$1" ]; then
    cp "$1" "$2"
  elif command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 3 "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$2" "$1"
  else
    echo 'curl or wget is required' >&2; exit 1
  fi
}

tmp_dir=$(mktemp -d)
staged=''
cleanup() {
  [ -z "$staged" ] || rm -f "$staged"
  rm -rf "$tmp_dir"
}
trap cleanup 0
trap 'exit 1' 1 2 15
download "${base_url%/}/SHA256SUMS" "$tmp_dir/SHA256SUMS"
download "${base_url%/}/$asset" "$tmp_dir/$asset"
expected=$(awk -v asset="$asset" '$2 == asset { print tolower($1); exit }' "$tmp_dir/SHA256SUMS")
printf '%s\n' "$expected" | grep -Eq '^[0-9a-f]{64}$' || {
  echo "Missing or invalid SHA256SUMS entry for $asset" >&2; exit 1;
}
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$tmp_dir/$asset" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  actual=$(shasum -a 256 "$tmp_dir/$asset" | awk '{print $1}')
else
  echo 'sha256sum or shasum is required' >&2; exit 1
fi
[ "$actual" = "$expected" ] || { echo "SHA256 mismatch for $asset" >&2; exit 1; }

mkdir -p "$install_dir"
staged=$(mktemp "$install_dir/.upkit.XXXXXX")
cp "$tmp_dir/$asset" "$staged"
chmod 755 "$staged"
version=$("$staged" --version)
printf '%s\n' "$version" | grep -Eq '^upkit [0-9]+\.[0-9]+\.[0-9]+$' || {
  echo 'Downloaded binary did not report a valid upkit version' >&2; exit 1;
}
if [ "$release" != latest ] && [ "$version" != "upkit ${release#v}" ]; then
  echo "Downloaded version $version does not match $release" >&2; exit 1
fi
mv -f "$staged" "$install_dir/upkit"
staged=''
printf 'Installed %s to %s/upkit\n' "$version" "$install_dir"
case ":$PATH:" in
  *":$install_dir:"*) ;;
  *) printf 'Add %s to your shell PATH before running upkit.\n' "$install_dir" ;;
esac
