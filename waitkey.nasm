;
; waitkey.nasm: wait for a key to be pressed
; by pts@fazekas.hu at Fri Apr 22 17:15:42 CEST 2022
;
; Compile it with NASM >= 0.98.39 (or Yasm >=1.2.0, command `yasm'):
;
;   $ nasm -O0 -f bin -o waitkey.exe waitkey.nasm
;
; Disassemble it:
;
;   $ ndisasm -b 16 -o 0x100 waitkey.com
;

bits 16
cpu 8086
org 0x100

_start:		mov ah, 9
		mov dx, message1
		int 0x21

again:		mov ah, 1
		int 0x16
		jnz strict short got_key
		hlt  ; Make the CPU less busy, save CPU time on the host machine.
		jmp strict short again

got_key:	mov ah, 0
		int 0x16		; Read character from keyboard buffer.
		mov ah, 9
		mov dx, message2
		int 0x21

_exit:		ret			; Exit to DOS with EXIT_SUCCESS (0).

message1:	db 'Press a key...$'
message2:	db 13, 10, '$'
