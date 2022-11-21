;
; mallocs.nasm: a DOS program doing test calls of malloc, testing malloc strategies
; by pts@fazekas.hu at Mon Nov 21 11:19:42 CET 2022
;
; This program works in DOSBox 0.74, MS-DOS 6.22 (TODO: test again) and kvikdos.
;

bits 16
cpu 8086
org 0100h

		org 0100h

_start:		xor ax, ax
		mov sp, 0xf00
		push ax

		mov ah, 0x4a		; inplace_realloc(), PSP in ES.
		mov bx, 0x1000 >> 4	; 0x100 PSP + 0xf00 program bytes.
		int 0x21
		jc strict short error

		mov ah, 0x48		; malloc() a6. Size in BX.
		mov bx, -1
		int 0x21		; Returns block segment (MCB+1) in AX.
		jnc strict short error
		push bx
		xor ax, ax
		push ax			; Push NULL sentinel.
		
		push bx			; Largest block that can be allocated.
		mov ax, 'r1'
		call dump_reg

		mov ax, 0x5801		; Set memory allocation strategy.
		mov bx, 0		; First fit.
		int 0x21
		jc strict short error

		mov ah, 0x48		; malloc() a1. Size in BX.
		mov bx, 1
		int 0x21		; Returns block segment (MCB+1) in AX.
		jc strict short error
		push ax

		push ax
		mov ax, 'a1'
		call dump_reg

		mov ax, 0x5801		; Set memory allocation strategy.
		mov bx, 1		; Best fit.
		int 0x21
		jc strict short error

		mov ah, 0x48		; malloc() a2. Size in BX.
		mov bx, 2
		int 0x21		; Returns block segment (MCB+1) in AX.
		jc strict short error
		push ax

		push ax
		mov ax, 'a2'
		call dump_reg

		mov ax, 0x5801		; Set memory allocation strategy.
		mov bx, 2		; Last fit.
		int 0x21
		jc strict short error
		jmp strict short cont

error:		mov ah, 9
		mov dx, error_message
		int 0x21
		mov ax, 0x4c09
		int 0x21		; Exit to DOS with error code 9.

cont:		mov ah, 0x48		; malloc() a3. Size in BX.
		mov bx, 3
		int 0x21		; Returns block segment (MCB+1) in AX.
		jc strict short error
		push ax

		push ax
		mov ax, 'a3'
		call dump_reg

		mov ah, 0x48		; malloc() a4. Size in BX.
		mov bx, 4
		int 0x21		; Returns block segment (MCB+1) in AX.
		jc strict short error
		push ax

		push ax
		mov ax, 'a4'
		call dump_reg

		mov ah, 0x48		; malloc() a5. Size in BX.
		mov bx, 5
		int 0x21		; Returns block segment (MCB+1) in AX.
		jc strict short error
		push ax

		push ax
		mov ax, 'a5'
		call dump_reg

		mov ax, 0x5801		; Set memory allocation strategy.
		mov bx, 0		; First fit.
		int 0x21
		jc strict short error

		mov ah, 0x48		; malloc() a6. Size in BX.
		mov bx, 6
		int 0x21		; Returns block segment (MCB+1) in AX.
		jc strict short error
		push ax

		push ax
		mov ax, 'a6'
		call dump_reg

		; All paras are pushed, free them.
		mov ah, 9
		mov dx, crlf
		int 0x21
		;
free:		pop ax
		test ax, ax
		jz strict short done	; Popped NULL sentinel.
		;
		push ax
		push ax
		mov ax, 'fr'
		call dump_reg
		pop ax
		;
		mov es, ax
		mov ah, 0x49
		int 0x21
		jc strict short error
		jmp strict short free

done:		mov ah, 0x48		; malloc() a6. Size in BX.
		mov bx, -1
		int 0x21		; Returns block segment (MCB+1) in AX.
		jc strict short .1
		jmp strict near error
.1:		pop ax
		cmp ax, bx		; Initial largest block that can be allocated must be the same as the final one.
		je strict short .2
		jmp strict near error
.2:

		push bx			; Largest block that can be allocated.
		mov ax, 'r2'
		call dump_reg
		

_exit:		mov ah, 9
		mov dx, message
		int 0x21
		ret			; Exit to DOS with EXIT_SUCCESS (0).

; Prints a single 16-bit CPU register on DOS.
; Call it with `call strict near dump_reg' (or just `call dump_reg').
; Input: AX: 2-byte name of the register.
; Input: word [sp]: value of the register.
; Clobbers AX and FLAGS, doesn't modify anything else.
; Pops (discards) the word [sp].
dump_reg:	push ax
		mov al, ' '
		int 0x29
		pop ax
		int 0x29
		mov al, ah
		int 0x29
		cmp al, 'l'
		jne .0
		mov al, 'a'
		int 0x29
		mov al, 'g'
		int 0x29
		mov al, 's'
		int 0x29
.0:		mov al, ':'
		int 0x29
		push bp
		mov bp, sp
		mov al, [bp + 5]
		aam 0x10
		add ax, '00'
		xchg al, ah
		cmp al, 9 + '0'
		jna .1
		add al, 7 + 32
.1:		int 0x29
		xchg al, ah
		cmp al, 9 + '0'
		jna .2
		add al, 7 + 32
.2:		int 0x29
		mov al, [bp + 4]
		aam 0x10
		add ax, '00'
		xchg al, ah
		cmp al, 9 + '0'
		jna .3
		add al, 7 + 32
.3:		int 0x29
		xchg al, ah
		cmp al, 9 + '0'
		jna .4
		add al, 7 + 32
.4:		int 0x29
		pop bp
		ret 2

message:	db 13, 10, 'mallocs OK.'
crlf:		db 13, 10, '$'
error_message:	db 13, 10, 'mallocs error!', 13, 10, '$'
