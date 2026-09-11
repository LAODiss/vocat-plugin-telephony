#!/usr/bin/env bash
# Builds one plugin package per architecture.
#
# vocat looks up backend.commands by GOOS/GOARCH, so a package that ships one
# architecture must not advertise the others — otherwise vocat would try to
# execute a binary that is not in the ZIP.
set -euo pipefail

cd "$(dirname "$0")"

VERSION="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' vocat-plugin.json | head -1)"
OUT="dist"
ARCHES=("arm64" "amd64")

rm -rf "$OUT"
mkdir -p "$OUT"

sha_of() {
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  else sha256sum "$1" | awk '{print $1}'; fi
}

echo "running tests..."
go test ./... >/dev/null

for arch in "${ARCHES[@]}"; do
  echo "==> linux/$arch"
  stage="$(mktemp -d)"
  trap 'rm -rf "$stage"' EXIT
  mkdir -p "$stage/bin" "$stage/web"

  python3 - "$arch" <<'PY' > "$stage/vocat-plugin.json"
import json, sys
arch = sys.argv[1]
manifest = json.load(open("vocat-plugin.json"))
key = f"linux/{arch}"
commands = manifest["backend"]["commands"]
if key not in commands:
    raise SystemExit(f"manifest has no backend command for {key}")
manifest["backend"]["commands"] = {key: commands[key]}
json.dump(manifest, sys.stdout, ensure_ascii=False, indent=2)
PY

  # CGO off keeps the binary static, matching how vocat itself ships.
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags "-s -w" \
    -o "$stage/bin/telephony-linux-$arch" .

  cp web/panel.html web/panel.js web/callAudio.js \
     web/call-capture-processor.js web/call-playback-processor.js "$stage/web/"

  package="$PWD/$OUT/telephony-assistant-$VERSION-linux-$arch.zip"
  # -X drops extended attributes and __MACOSX entries, which vocat's extractor
  # rejects as unsafe paths.
  (cd "$stage" && zip -q -r -X "$package" vocat-plugin.json web bin)

  rm -rf "$stage"
  trap - EXIT

  printf '  %s\n  sha256: %s\n' "$package" "$(sha_of "$package")"
done

echo
echo "install: vocat 系统设置 → 插件 → 上传插件包，选择与服务器架构匹配的包"
echo "         (192.168.111.221 是 aarch64，用 linux-arm64)"
