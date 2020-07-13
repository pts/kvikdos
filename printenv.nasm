;
; printenv.nasm: print environment variables, program name and command line
; by pts@fazekas.hu at Sun Jul 12 21:46:04 CEST 2020
;

org 0x100

mov ax, [es:0x2c]  ; TODO(pts): No need for es in .com.
mov ds, ax
xor si, si
mov ah, 2  ; PUTCHAR(dl).

%macro print_crlf 0
mov dl, 13
int 0x21
mov dl, 10
int 0x21
%endmacro

; Print environment entries.
next_entry:
cmp byte [si], 0
je end_entries
next_char:
mov dl, [si]
inc si
test dl, dl
jz end_entry
int 0x21
jmp short next_char
end_entry:
print_crlf
jmp short next_entry
end_entries:
inc si  ; Skip over '\0'.
inc si  ; Skip over a single byte of '\1' (low byte of number of subsequent variables).
inc si  ; Skip over '\0' (high byte of number of subsequent variables).

; Print the program name. It will be absolute pathname with the file extension (.EXE or .COM).
print_crlf
next_char2:
mov dl, [si]
inc si
test dl, dl
jz end_name2
int 0x21
jmp short next_char2
end_name2:
print_crlf

; Print the command-line.
; Both FreeDOS and DOSBox pass whitespace verbatim with multiplicity, can be spaces and tabs.
; Both FreeDOS and DOSBox pass at least one leading space.
; In FreeDOS, there can be trailing whitespace, DOSBox trims it.
;
; https://en.wikipedia.org/wiki/Program_Segment_Prefix mentions the CMDLINE
; environment variable (for longer than 126 characters), but that's only
; supported by 4DOS and MS-DOS 7.0+ (also FreeDOS 1.2, but not DOSBox) --
; previous versions just truncate the line. cstrt086.asm in OpenWatcom V2
; doesn't look at CMDLINE. For FreeDOS, CMDLINE also starts withe program name verbatim,
; but it is only present if the command-line is indeed long.
mov dl, '('
int 0x21
push es
pop ds
mov si, 0x81
xor bx, bx
mov bl, [si-1]  ; 0..127. We trust it.
mov byte [si+bx], 0
next_char3:
mov dl, [si]
inc si
test dl, dl
jz end_cmdline3
int 0x21
jmp short next_char3
end_cmdline3:
mov dl, ')'
int 0x21
print_crlf

ret
