#!/usr/bin/env bash
set -euo pipefail

KVD="${1:-./kvikdos}"
KVD="$(readlink -f "$KVD")"
if [[ ! -x "$KVD" ]]; then
  echo "error: kvikdos binary not found: $KVD" >&2
  exit 2
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/c/BIN" "$TMP/d" "$TMP/e" "$TMP/f"
# Minimal MZ file so parser and loader continue past argv processing.
printf 'MZ\x00\x00\x00\x00\x00\x00' > "$TMP/c/BIN/LINK.EXE"

set +e
OUT="$($KVD \
  --hlt-ok \
  --mount=C:"$TMP/c"/ \
  --mount=D:"$TMP/d"/ \
  --mount=E:"$TMP/e"/ \
  --mount=F:"$TMP/f"/ \
  --drive=d \
  '--cwd-dos=D:\\' \
  '--path-dos=C:\\BIN;C:\\' \
  '--env=PATH=C:\\BIN;C:\\' \
  '--env=TMP=F:\\' \
  '--prog=C:\\BIN\\LINK.EXE' \
  'C:\\BIN\\LINK.EXE' \
  /M /I '@D:\\end.rsp' 2>&1)"
RC=$?
set -e

if [[ $RC -eq 139 || $RC -eq 134 ]] || printf '%s\n' "$OUT" | grep -qiE 'segmentation fault|sanitizer:deadly signal'; then
  echo "FAIL: crash/signal (rc=$RC)" >&2
  printf '%s\n' "$OUT" >&2
  exit 1
fi

# Accept any graceful failure/success, but reject segfault-like behavior.
echo "PASS: cli-parse-no-crash (rc=$RC)"
exit 0
