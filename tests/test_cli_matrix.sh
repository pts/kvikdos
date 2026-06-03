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
printf 'MZ\x00\x00\x00\x00\x00\x00' > "$TMP/c/BIN/LINK.EXE"

run_no_crash() {
  local name="$1"; shift
  local out rc
  set +e
  out="$($KVD "$@" 2>&1)"
  rc=$?
  set -e
  if [[ $rc -eq 139 || $rc -eq 134 ]] || printf '%s\n' "$out" | grep -qiE 'segmentation fault|sanitizer:deadly signal'; then
    echo "FAIL: $name crashed (rc=$rc)" >&2
    printf '%s\n' "$out" >&2
    return 1
  fi
  echo "PASS: $name (rc=$rc)"
}

fails=0

COMMON=(
  --hlt-ok
  --mount=C:"$TMP/c"/
  --mount=D:"$TMP/d"/
  --mount=E:"$TMP/e"/
  --mount=F:"$TMP/f"/
)

run_no_crash "prog+positional-dos" \
  "${COMMON[@]}" --drive=d '--cwd-dos=D:\\' '--path-dos=C:\\BIN;C:\\' '--env=PATH=C:\\BIN;C:\\' '--prog=C:\\BIN\\LINK.EXE' 'C:\\BIN\\LINK.EXE' /M /I '@D:\\end.rsp' || fails=$((fails+1))

run_no_crash "invalid-drive-flag" \
  "${COMMON[@]}" --drive=z 'C:\\BIN\\LINK.EXE' || fails=$((fails+1))

run_no_crash "bad-mount-format" \
  --mount=C:"$TMP/c"/ --mount=Q:"$TMP/d"/ 'C:\\BIN\\LINK.EXE' || fails=$((fails+1))

run_no_crash "missing-flag-arg" \
  --mount=C:"$TMP/c"/ --env 'C:\\BIN\\LINK.EXE' || fails=$((fails+1))

run_no_crash "linux-positional-with-prog" \
  "${COMMON[@]}" --prog='C:\\BIN\\LINK.EXE' "$TMP/c/BIN/LINK.EXE" || fails=$((fails+1))

if [[ $fails -ne 0 ]]; then
  echo "FAIL: cli-matrix failures=$fails" >&2
  exit 1
fi

echo "PASS: cli-matrix"
