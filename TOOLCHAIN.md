# kvikdos Toolchain Guide

This document shows known-good ways to run DOS C/ASM toolchains under `kvikdos`.

## Key rules

- Use DOS 8.3 names for source/object/output files when possible.
- Mount the correct directory as `C:` with `--mount=C:.` from that directory.
- For toolchains with separate `BIN`, `LIB`, `INCLUDE`, mount their parent root and call executables as `C:\BIN\...`.
- Set `LIB` and `INCLUDE` explicitly with `--env=...`.

## Minimal C source

Use this for widest compatibility:

```c
main(){return 0;}
```

## Microsoft C 4.0

```bash
cd '/home/xor/inertia_player/dos_compilers/Microsoft C v4'
printf 'main(){return 0;}\n' > HELLO.C
/home/xor/kvikdos/kvikdos --mount=C:. --env=LIB=lib --env=INCLUDE=inc C:\CL.EXE /c HELLO.C
/home/xor/kvikdos/kvikdos --mount=C:. --env=LIB=lib C:\LINK.EXE HELLO,,,SLIBFP
/home/xor/kvikdos/kvikdos --mount=C:. C:\HELLO.EXE
```

## Microsoft C 5.1

```bash
cd '/home/xor/inertia_player/dos_compilers/Microsoft C v5'
printf 'main(){return 0;}\n' > HELLO.C
/home/xor/kvikdos/kvikdos --mount=C:. --env=LIB=lib --env=INCLUDE=inc C:\CL.EXE /c HELLO.C
/home/xor/kvikdos/kvikdos --mount=C:. --env=LIB=lib C:\LINK.EXE HELLO,,,SLIBCE
/home/xor/kvikdos/kvikdos --mount=C:. C:\HELLO.EXE
```

## Microsoft C 6ax

```bash
cd '/home/xor/inertia_player/dos_compilers/Microsoft C v6ax'
printf 'main(){return 0;}\n' > HELLO.C
/home/xor/kvikdos/kvikdos --mount=C:. --env=LIB=C:\LIB --env=INCLUDE=C:\INCLUDE C:\BIN\CL.EXE /c /AS HELLO.C
/home/xor/kvikdos/kvikdos --mount=C:. --env=LIB=C:\LIB C:\BIN\LINK.EXE HELLO,,,SLIBCE
/home/xor/kvikdos/kvikdos --mount=C:. C:\HELLO.EXE
```

## Intel iC-86 Compiler v4.5

```bash
cd '/home/xor/inertia_player/dos_compilers/Intel iC-86 Compiler v4.5'
printf 'main(){return 0;}\n' > HELLO.C
/home/xor/kvikdos/kvikdos --mount=C:. C:\IC86.EXE HELLO.C small optimize\(3\) mod86 diagnostic\(2\) define\(INTELC\)
/home/xor/kvikdos/kvikdos --mount=C:. C:\LINK86.EXE libs\cstdoss.obj,HELLO.obj,c:\libs\cdoss.lib,u\cel87.lib,u\e8087.lib,u\de8087,libs\clib87.lib TO HELLO.EXE exe
/home/xor/kvikdos/kvikdos --mount=C:. C:\HELLO.EXE
```

## Borland Turbo C 2.0

```bash
cd '/home/xor/inertia_player/dos_compilers/Borland Turbo C v2'
printf 'main(){return 0;}\n' > HELLO.C
/home/xor/kvikdos/kvikdos --mount=C:. C:\TCC.EXE -ms -Z -O -G -Iinclude -Llib -eHELLO.EXE HELLO.C
/home/xor/kvikdos/kvikdos --mount=C:. C:\HELLO.EXE
```

## Borland Turbo C++ 1.01

```bash
cd '/home/xor/inertia_player/dos_compilers/Borland Turbo C++ v1'
printf 'main(){return 0;}\n' > HELLO.C
/home/xor/kvikdos/kvikdos --mount=C:. --env=LIB=C:\LIB --env=INCLUDE=C:\INCLUDE C:\BIN\TCC.EXE -ms -Z -O -G -IC:\INCLUDE -LC:\LIB -eHELLO.EXE HELLO.C
/home/xor/kvikdos/kvikdos --mount=C:. C:\HELLO.EXE
```

## Microsoft MASM 5.0

`MASM.EXE` works directly; `LINK.EXE` is easiest via stdin prompts.

```bash
cd '/home/xor/inertia_player/dos_compilers/Microsoft MASM v5/BIN'
cat > HELLO.ASM <<'EOA'
.MODEL SMALL
.STACK 100h
.CODE
start:
  mov ax,4C00h
  int 21h
END start
EOA
/home/xor/kvikdos/kvikdos --mount=C:. C:\MASM.EXE HELLO.ASM,HELLO.OBJ,NUL,NUL
printf 'HELLO.OBJ\nHELLO.EXE\nNUL\n\n\n' | /home/xor/kvikdos/kvikdos --mount=C:. C:\LINK.EXE
/home/xor/kvikdos/kvikdos --mount=C:. C:\HELLO.EXE
```

## Notes

- If compile succeeds but link cannot find CRT objects/libs, your `LIB` path is wrong for the mounted layout.
- If includes are missing, adjust `INCLUDE` to match the mounted layout.
- For old compilers, avoid modern signatures (`int main(void)`) and rely on K&R-style `main()` for compatibility.
