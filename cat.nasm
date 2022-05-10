;
; cat.nasm: DOS .com program to print a file to stdout
; by pts@fazekas.hu at Fri Apr 22 17:15:42 CEST 2022
;
; Compile it with NASM >= 0.98.39 (or Yasm >=1.2.0, command `yasm'):
;
;   $ nasm -O0 -f bin -o cat.exe cat.nasm
;
; Disassemble it:
;
;   $ ndisasm -b 16 -o 0x100 cat.com
;
; This program is similar to the built-in DOS `type' command, but its
; binary-safe (e.g. it doesn't stop at a ^Z == 0x1a byte).
;
; This program is manually optimized for file size (except for the
; messages).
;

bits 16
cpu 8086
org 0x100

buf_size	equ 16384

_start:		mov di, 0x81
		mov bl, byte [di - 1]	; Length of Pascal string.
		mov bh, 0
		mov [di + bx], bh	; ASCIIZ string.
		cmp byte [di], ' '
		jne strict short .l1
		inc di			; Skip over initial space.
.l1:		; Now DI points to the filename from the command-line, ASCIIZ.
		cmp [di], bh
		jne strict short .l2
		; Empty command-line, so use stdin.
		xor bx, bx		; STDIN_FILENO == 0.
		jmp strict short read
.l2:		cmp word [di], '/' | '?' << 8  ; '/?'.
		jne strict short .l3
		cmp [di + 2], bh
		jne strict short .l3
		; /? on command-line, so display usage and exit.
		mov cx, usage_msg_size
		mov dx, usage_msg
		jmp strict short error_exit
.l3:		

open:		mov ax, 0x3d00		; open().
		mov dx, di
		int 0x21
		jc strict short io_error_exit
		xchg bx, ax		; BX := AX, AX := garbage.
		; Now BX contains the filehandle.

read:		mov ah, 0x3f		; read().
		mov cx, buf_size
		mov dx, buf
		int 0x21
		jc strict short io_error_exit
		test ax, ax
		jz strict short eof

write:		xchg cx, ax		; CX := AX, AX := garbage.
		mov ah, 0x40		; write().
		push bx
		mov bx, 1		; STDOUT_FILENO.
		; DX still points to buf.
		int 0x21
		pop bx
		jc strict short io_error_exit
		jmp strict short read
		
eof:		; No need to close (0x3e), DOS closes the file upon exit.
_exit:		ret			; Exit to DOS with EXIT_SUCCESS (0).

io_error_exit:	mov cx, error_msg_size
		mov dx, error_msg
error_exit:	mov ah, 0x40		; write().
		mov bx, 2		; STDERR_FILENO.
		int 0x21

exit_failure2:	mov ax, 0x4c02		; exit().
		int 0x21		; Exit to DOS with failure (2). 

error_msg:	db 'I/O error.', 13, 10
error_msg_size	equ $ - error_msg

usage_msg:	db 'Usage: cat [<filename>]', 13, 10
usage_msg_size	equ $ - usage_msg

buf:		; Buffer of size buf_size (16384 bytes).
