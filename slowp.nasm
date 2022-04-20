; A DOS .com program which prints a few dots very slowly.

bits 16
cpu 8086
org 0100h

		org 0100h

_start:		mov al, '.'
		mov dx, 32  ; Number of dots to print.

                ; Busy loop spinning the CPU.
.l0:		mov si, 2048
.l1:		xor cx, cx
.l2:		loop .l2
		dec si
		jnz .l1
		int 29h  ; Print '.' in AL.
		dec dx
		jnz .l0

		mov al, 13  ; CR.
		int 29h
		mov al, 10  ; LF.
		int 29h

_exit:		ret
