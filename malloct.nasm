;
; malloct.nasm: a DOS program doing test calls of malloc, realloc and free
; by pts@fazekas.hu at Mon Apr 25 11:36:41 CEST 2022
;
; This program works in DOSBox 0.74.
; TODO(pts): Test in MS-DOS 6.22.
;

bits 16
cpu 8086
org 0100h

		org 0100h

_start:		xor ax, ax
		mov sp, 0xf00
		push ax

		mov ah, 0x4a		; realloc(), PSP in ES.
		mov bx, 0xffff		; New size in para. Too large.
		int 0x21
		jnc strict short error	; Expecting error.

		mov ah, 0x4a		; realloc(), PSP in ES.
		mov bx, es
		sub bx, 0xa000 + 1	; DOSBox 0.74 fails even without the +1.
		neg bx			; New size in para. Still too large.
		int 0x21
		jnc strict short error	; Expecting error.

		mov ah, 0x4a		; realloc(), PSP in ES.
		mov bx, 0x1000 >> 4	; 0x100 PSP + 0xf00 program bytes.
		int 0x21
		jc strict short error

		mov ah, 0x48		; malloc(). Size in BX.
		mov cx, ds
		add cx, 0x1000 >> 4
		mov bx, 0xa000 - 65	; DOSBox 0.74 fails with -1, MS-DOS 6.22 fails with -64, both instead of -65.
		sub bx, cx		; Just fits.
		int 0x21
		jc strict short error
		mov es, ax

		mov ah, 0x49		; free(). Para in ES.
		int 0x21
		jc strict short error
		int 0x21
		jc strict short error	; Double free() should be an error, but it's OK in DOSBox 0.74 and MS-DOS 6.22.

		xor ax, ax
		mov es, ax
		mov ah, 0x49		; free(). Para in ES.
		int 0x21
		jnc strict short error	; free(0) is an error in DOSBox.

		push ds
		pop ax
		inc ax
		mov es, ax
		mov ah, 0x49		; free(). Para in ES.
		int 0x21
		jnc strict short error	; free(not-an-mcb) is an error.

		mov ah, 0x48		; malloc(). Size in BX.
		mov cx, ds
		add cx, 0x1000 >> 4
		mov bx, 0xa000
		sub bx, cx		; Too large.
		int 0x21
		jnc strict short error
		xchg bx, ax		; BX := largest free para size, AX := garbage.
		mov dx, bx		; Save this large size for later.

		mov ah, 0x48		; malloc(). Size in BX.
		int 0x21
		jc strict short error
		mov es, ax

		mov ah, 0x49		; free(). Para in ES.
		int 0x21
		jc strict short error
		
		mov ah, 0x48		; malloc(). Size in BX.
		xor bx, bx
		int 0x21
		jc strict short error	; malloc(0) is OK.
		test ax, ax
		jz strict short error	; Allocated block must not be 0.
		mov es, ax

		mov ah, 0x49		; free(). Para in ES.
		int 0x21
		;jc strict short error
		jnc strict short cont

error:		mov ah, 9
		mov dx, error_message
		int 0x21
		mov ax, 0x4c09
		int 0x21		; Exit to DOS with error code 9.

		; Works up to this point in DOSBox 0.74 and MS-DOS 6.22.
cont:		
		; Allocate 256 blocks, starting with the first one.
		mov ah, 0x48		; malloc(). Size in BX.
		mov bx, 0
		int 0x21
		jc strict short error
		mov di, ax		; DI :+ (a copy of) pointer to last block

next_malloc:	xchg bp, ax		; BP := pointer to last block para, AX := garbage.

		mov ah, 0x48		; malloc(). Size in BX.
		inc bx
		int 0x21
		jc strict short error
		mov es, ax
		mov word [es:0], bp	; Save previous pointer.
		cmp bh, 0
		je next_malloc
		mov si, bp		; First odd para to free.
		jmp strict short next_free_even.first

next_free_even:	mov bp, word [es:0]
		mov es, bp		; Skip each odd para.
.first:		mov bp, word [es:0]
		mov ah, 0x49		; free(). Para in ES.
		int 0x21
		jc strict short error
		mov al, '#'
		int 0x29
%if 0  ; This confuses MS-DOS 6.22 (Memory allocation error; Cannot load COMMAND, system halted), but it works in DOSBox 0.74.
		push es
		mov ax, es
		dec ax
		mov es, ax
		inc byte [es:0]		; Ruin MCB.
		pop es
		mov ah, 0x49		; free(). Para in ES.
		int 0x21
		jnc strict short error	; free(not-an-MCB) is an error.
%endif
		mov ax, es
		cmp ax, di
		mov es, bp
		jne strict short next_free_even
.done:		mov bp, si
		;jmp strict short next_free_odd.first

next_free_odd:	mov es, bp
		mov bp, word [es:0]	; This is a memory location in a recently free()d block, but since nothing else is running, we reuse it.
		mov ah, 0x49		; free(). Para in ES.
		int 0x21
		jc strict short error
		mov al, '.'
		int 0x29
		cmp bp, di
		je strict short .done
		mov es, bp
		mov bp, word [es:0]
		jmp strict short next_free_odd
.done:

		mov ah, 0x48		; malloc(). Size in BX.
		mov cx, ds
		add cx, 0x1000 >> 4
		mov bx, 0xa000 - 65	; DOSBox 0.74 fails with -1, MS-DOS 6.22 fails with -64, both instead of -65.
		sub bx, cx		; Just fits.
		int 0x21
		jc strict short error
		mov es, ax

		mov ah, 0x49		; free(). Para in ES.
		int 0x21
		jc strict short error2

		; Works up to this point in DOSBox 0.74 and MS-DOS 6.22.

_exit:		mov ah, 9
		mov dx, message
		int 0x21
		ret			; Exit to DOS with EXIT_SUCCESS.

error2:		jmp strict near error


message:	db 'malloct OK.', 13, 10, '$'
error_message:	db 'malloct error!', 13, 10, '$'
