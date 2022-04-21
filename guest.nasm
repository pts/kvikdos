; A DOS .com program which prints its command-line arguments and then it
; prints `Hello, World!' using multiple DOS APIs for each part.

bits 16
cpu 8086
org 0100h

		org 0100h

_start:		mov si, 81h  ; Command-line arguments.
.l1:		lodsb
		cmp al, 13
		je strict short .l2
		int 29h
		jmp strict short .l1
.l2:		mov al, '.'
		int 29h
		mov al, 13  ; CR.
		int 29h
		mov al, 10  ; LF.
		int 29h

		mov al, 'H'
		int 29h  ; Also calls `int 10h' with AH=0Eh.

		mov ax, 0Eh * 256 + 'e'
		mov bx, 0BFh
		int 10h

		mov ah, 6
		mov dl, 'l'
		int 21h

		mov ah, 2
		mov dl, 'l'
		int 21h

		mov ah, 0x40
		mov bx, 1  ; STDOUT.
		mov cx, message2 - message
		mov dx, message
		stc
		int 21h
		jc strict short _exit

		; This triggers KVM_EXIT_MMIO if the magic interrupt table
		; is read-only.
		;mov ax, 0
		;mov es, ax
		;mov word [es:0x345], 0xabcd

		mov ah, 9
		mov dx, message2
		int 21h

_exit:		ret
		;mov ax, 4c00h + 42
		;int 21h

		; 'Hell' has been printed above.
message:	db 'o, '
message2:	db 'World!', 13, 10, '$'
