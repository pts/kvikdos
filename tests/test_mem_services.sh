#!/usr/bin/env bash
set -euo pipefail

KVD="${1:-./kvikdos}"
KVD="$(readlink -f "$KVD")"
if [[ ! -x "$KVD" ]]; then
  echo "error: kvikdos binary not found or not executable: $KVD" >&2
  exit 2
fi

if ! command -v nasm >/dev/null 2>&1; then
  echo "error: nasm is required for test_mem_services.sh" >&2
  exit 2
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/memsvc.nasm" <<'ASM'
bits 16
org 100h

start:
  xor si, si

  ; INT 2Fh AX=4300h: XMS installation check (AL should be 80h)
  mov ax, 4300h
  int 2fh
  cmp al, 80h
  je .xms_present
  or si, 0001h
.xms_present:

  ; INT 2Fh AX=4310h: get XMS entry point ES:BX
  mov ax, 4310h
  int 2fh
  mov [xms_off], bx
  mov [xms_seg], es
  mov ax, es
  or ax, bx
  jnz .xms_ptr_ok
  or si, 0002h
.xms_ptr_ok:

  ; XMS AH=08h: query free memory
  mov ah, 08h
  call far [xms_off]
  cmp ax, 1
  je .xms_q_ok
  or si, 0004h
.xms_q_ok:

  ; XMS AH=09h: allocate 64 KiB
  mov dx, 64
  mov ah, 09h
  call far [xms_off]
  cmp ax, 1
  je .xms_alloc_ok
  or si, 0008h
  jmp short .after_xms_alloc
.xms_alloc_ok:
  mov [xms_handle], dx
.after_xms_alloc:

  ; XMS AH=0Ah: free handle (if allocated)
  mov dx, [xms_handle]
  or dx, dx
  jz .xms_free_done
  mov ah, 0ah
  call far [xms_off]
  cmp ax, 1
  je .xms_free_done
  or si, 0010h
.xms_free_done:

  ; INT 67h AH=40h: EMS status
  mov ah, 40h
  int 67h
  cmp ah, 00h
  je .ems_status_ok
  or si, 0020h
.ems_status_ok:

  ; INT 67h AH=42h: get EMS pages
  mov ah, 42h
  int 67h
  cmp ah, 00h
  je .ems_pages_ok
  or si, 0040h
.ems_pages_ok:

  ; INT 21h AX=5802h: get UMB link state
  mov ax, 5802h
  int 21h
  jc .umb_get_fail
  jmp short .umb_set
.umb_get_fail:
  or si, 0080h

.umb_set:
  ; INT 21h AX=5803h: set UMB link state=1
  mov ax, 5803h
  mov bx, 1
  int 21h
  jc .umb_set_fail
  jmp short .umb_verify
.umb_set_fail:
  or si, 0100h

.umb_verify:
  mov ax, 5802h
  int 21h
  jc .umb_verify_fail
  cmp al, 1
  je .done
.umb_verify_fail:
  or si, 0200h

.done:
  mov ax, si
  and ax, 00ffh
  or ax, 4c00h
  int 21h

xms_off dw 0
xms_seg dw 0
xms_handle dw 0
ASM

nasm -f bin -o "$TMP/MEMSVC.COM" "$TMP/memsvc.nasm"

set +e
"$KVD" "$TMP/MEMSVC.COM" >/tmp/kvikdos_memsvc.out 2>/tmp/kvikdos_memsvc.err
rc=$?
set -e

if [[ "$rc" -ne 0 ]]; then
  echo "FAIL: mem-services (exit=$rc)" >&2
  echo "--- stdout ---" >&2
  sed -n '1,80p' /tmp/kvikdos_memsvc.out >&2
  echo "--- stderr ---" >&2
  sed -n '1,120p' /tmp/kvikdos_memsvc.err >&2
  exit 1
fi

echo "PASS: mem-services"
