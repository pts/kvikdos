/*
 * kvikdos.c: a very fast DOS emulator for Linux
 * by pts@fazekas.hu at 2022-04-20
 *
 * This is free software, GNU GPL >=2.0. There is NO WARRANTY. Use at your risk.
 *
 * TODO(pts): Detect filenames in lower case (still simpler than DOSBox).
 * TODO(pts): DOS STDERR to Linux fd 1 (stdout) mapping.
 * TODO(pts): Turbo C, Turbo C++ and Borland C++ compatibility.
 * TODO(pts): udosrun integration.
 * TODO(pts): udosrun command-line flag compatibility.
 * TODO(pts): Run Linux ELF programs and scripts (#!), for convenience.
 * TODO(pts): Add support for .bat batch files (at least a subset).
 *
 * Since many parts of the DOS ABI is undocumented, the specific behavior of
 * kvikdos in corner cases is matched to:
 *
 * * FREEDOS 1.2
 *   (https://github.com/FDOS/kernel/blob/8c8d21311974e3274b3c03306f3113ee77ff2f45/kernel/task.c)
 * * DOSBox 0.74-4
 *   (https://github.com/svn2github/dosbox/blob/acd380bcde72db74f3b476253899016f686bc0ef/src/dos/dos_execute.cpp)
 * * MS-DOS 6.22 (source code not available).
 */

#define _GNU_SOURCE 1  /* For MAP_ANONYMOUS and memmem(). */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#ifdef USE_MINI_KVM  /* For systems with a broken linux/kvm.h. */
#  include "mini_kvm.h"
#else
#  include <linux/kvm.h>
#endif

#ifndef DEBUG
#define DEBUG 0
#endif

#if 0  /* We don't use ROM and BIOS area and then XMS above DOS_MEM_LIMIT, we just map DOS_MEM_LIMIT. */
#define MEM_SIZE (2 << 20)  /* In bytes. 2 MiB. */
#endif

/* Memory map for kvikdos:
 *
 * 0x00000...0x00400    +0x400  Interrupt vector table (IVT).
 * 0x00400...0x00500    +0x100  BIOS data area (BDA). Kept as 00s. https://stanislavs.org/helppc/bios_data_area.html  https://wiki.osdev.org/Memory_Map_(x86)  http://www.bioscentral.com/misc/bda.htm  http://staff.ustc.edu.cn/~xyfeng/research/cos/resources/BIOS/Resources/biosdata.htm
 * 0x00500...0x00534     +0x34  BIOS/DOS data area. Kept as 00s. https://stanislavs.org/helppc/bios_data_area.html
 * 0x00534...0x0053f      +0xb  Unused (00).
 * 0x0053f...0x00540        +1  `retf' opcode used by country case map.
 * 0x00540...0x00640    +0x100  INT_HLT_PARA. hlt instructions for interrupt entry points. Needed for getting the interrupt number in KVM_EXIT_HLT.
 * 0x00640...0x00ff0    +0xabc  ENV_PARA. Environment variables and program pathname.
 * 0x00ff0...0x01000     +0x10  PROGRAM_MCB_PARA. Memory Control Block (MCB) of PSP.
 * 0x01000...0x01100    +0x100  PSP_PARA. Program Segment Prefix (PSP).
 * 0x01100...0xa0000  +0x9ef00  Loaded program image, .bss and stack. This region is called ``conventional memory''.
 * 0xa0000                  +0  DOS_ALLOC_PARA_LIMIT and DOS_MEM_LIMIT.
 *
 * On a normal machine, there is also EBDA which ends at 0xa0000. You can
 * determine the size of the EBDA by using BIOS function `int 0x12', or by
 * examining the word at 0x413 in the BDA. Both of those methods
 * will tell you how much conventional memory is usable before the EBDA.
 *
 * Some other memory areas on a normal machine:
 *
 * 0xa0000.. 0xfffff            Upper memory block (UMB).
 * 0xffff0..0x10fff0  +0x10000  High memory area (HMA).
 * 0xa0000...0xc0000  +0x20000  Video display memory
 * 0xc0000...0xc8000  +0x08000  Video BIOS (ROM)
 * 0xc8000...0xf0000  +0x28000  BIOS Expansions (ROM)
 * 0xf0000.. 0xfffff  +0x10000  Motherboard BIOS.
 * 0xa0000                      EGA/VGA RAM for graphics display mode 0Dh & above
 * 0xb0000                      MDA RAM, Hercules graphics display RAM
 * 0xb8000                      CGA display RAM
 * 0xc0000                      EGA/VGA BIOS ROM (thru C7FF)
 * 0xc4000                      Video adapter ROM space
 * 0xc6000              +0x100  PGA communication area
 * 0xc8000                +16K  Hard disk adapter BIOS ROM
 * 0xc8005                      XT Hard disk ROM format, AH=Drive, AL=Interleave
 * 0xd0000                +32K  luster adapter BIOS ROM
 * 0xd8000                      PCjr conventionalsoftware cartridge address
 * 0xe0000                +64K  Expansion ROM space (hardwired on AT+)
 *                       +128K  PS/2 System ROM (thru 0xf0000)
 * 0xf0000                      System monitor ROM
 *                              PCjr: software cartridge override address
 * 0xf4000                      System expansion ROMs
 * 0xf6000                      IBM ROM BASIC (AT)
 * 0xf8000                      PCjr software cartridge override address
 * 0xfc000                      BIOS ROM
 * 0xff000                      System ROM
 * 0xfFa6e                      ROM graphics character table
 * 0xffff0                      ROM bootstrap code == soft reset. Ctl-Alt-<Del> or JMP FFFF:0. far jmp instruction to begin POST.
 * 0xffff5                +0x8  ROM BIOS date (not applicable for all clones) in ASCII.
 * 0xffffe                +0x1  ROM machine ID. IBM computer type code.
 */

/* Typical system interrupts, from http://www2.ift.ulaval.ca/~marchand/ift17583/dosints.pdf :
 *
 * int 0x00 - internal - DIVIDE ERROR
 * int 0x01 - internal - SINGLE-STEP
 * int 0x02 - hardware - NMI (NON-MASKABLE INTERRUPT)
 * int 0x03 - ONE-BYTE INTERRUPT
 * int 0x04 - internal - OVERFLOW
 * int 0x05 - PRINT-SCREEN KEY
 * int 0x05 - internal - BOUND CHECK FAILED (186/286)
 * int 0x06 - internal - UNDEFINED OPCODE (286)
 * int 0x07 - internal - NO MATH UNIT AVAILABLE (286)
 * int 0x08 - IRQ0 - TIMER INTERRUPT
 * int 0x09 - IRQ1 - KEYBOARD INTERRUPT
 * int 0x0a - IRQ2 - EGA VERTICAL RETRACE
 * int 0x0b - IRQ3 - COM2 INTERRUPT
 * int 0x0c - IRQ4 - COM1 INTERRUPT
 * int 0x0d - IRQ5 - FIXED DISK (PC), LPT2 (AT/PS)
 * int 0x0e - IRQ6 - DISKETTE INTERRUPT
 * int 0x0f - IRQ7 - PRINTER INTERRUPT
 * int 0x70 - IRQ8 (AT/XT286/PS50+) - REAL-TIME CLOCK
 * int 0x71 - IRQ9 (AT/XT286/PS50+) - LAN ADAPTER 1
 * int 0x72 - IRQ10 (AT/XT286/PS50+) - RESERVED
 * int 0x73 - IRQ11 (AT/XT286/PS50+) - RESERVED
 * int 0x74 - IRQ12 (PS50+) - MOUSE INTERRUPT
 * int 0x75 - IRQ13 (AT/XT286/PS50+) - 80287 ERROR
 * int 0x76 - IRQ14 (AT/XT286/PS50+) - FIXED DISK
 * int 0x77 - IRQ15 (AT/XT286/PS50+) - RESERVED
 *
 * Typical 286 protected-mode interrupts:
 *
 * int 0x08 - internal - DOUBLE FAULT
 * int 0x09 - internal - MATH UNIT PROTECTION FAULT
 * int 0x0a - internal - INVALID TASK STATE SEGMENT
 * int 0x0b - internal - NOT PRESENT
 * int 0x0c - internal - STACK FAULT (80286)
 * int 0x0d - internal - GENERAL PROTECTION VIOLATION
 *
 * Typial 386 interrupts:
 *
 * int 0x0e - internal - PAGE FAULT (386 native mode)
 */

#define INT_HLT_PARA 0x54

/* Start of Program Segment Prefix (PSP) in paragraphs (unit of 16 bytes).
 * It must be at leasge GUEST_MEM_MODULE_START >> 4, otherwise it isn't
 * writable by the program.
 *
 * Minimum value is 0x50, after the magic interrupt table (first 0x500 bytes
 * of DOS memory). Also there is the environment (up to ENV_LIMIT >> 4)
 * paragraphs between the magic interrup table and base.
 */
#define PSP_PARA 0x100

#define PROGRAM_MCB_PARA (PSP_PARA - 1)

/* Environment starts at this paragraph. */
#define ENV_PARA 0x64
/* How long the environment can be. */
#define ENV_LIMIT (PROGRAM_MCB_PARA << 4)

/* Must be a multiple of the Linux page size (0x1000), minimum value is
 * 0x500 (after magic interrupt table). Must be at most PSP_PARA << 4. Can
 * be 0. By setting it to nonzero (0x1000), we effectively make the magic
 * interrupt table read-only.
 */
#define GUEST_MEM_MODULE_START 0x1000

/* Points to 0x40:int_num, pointer encoded as cs:ip. */
#define MAGIC_INT_VALUE(int_num) ((unsigned)INT_HLT_PARA << 16 | (unsigned)int_num)

/* Maximum byte offset where the program (including .bss and stack) can end.
 * 640 KiB should be enough for everyone :-).
 */
#define DOS_MEM_LIMIT 0xa0000

/* Points after last paragraph which can be allocated by DOS, conventional memory. 640 KiB. */
#define DOS_ALLOC_PARA_LIMIT 0xa000

#define MAX_DOS_COM_SIZE 0xfee0  /* size + 0x100 bytes of PSP + 0x20 bytes of stack <= 0x10000 bytes. */

#define PROGRAM_HEADER_SIZE 26  /* Large enough for .exe header (prefix of 26 bytes) and other header detection. */

/* Returns true iff the byte at the specified DOS linear address is
 * user-writable (i.e. the program is allowed to write it).
 */
#define is_linear_byte_user_writable(linear) ((linear) - (ENV_PARA << 4) < (DOS_MEM_LIMIT - (ENV_PARA << 4)))

#define FINDFIRST_MAGIC 0xd5ba1ad0U

/* --- Memory allocation helpers. */

#define PROCESS_ID  0x192  /* Same as in DOSBox. */

#define MCB_TYPE(mcb) (*(char*)(mcb))  /* 'Z' indicates last member of MCB chain; 'M' would be non-last. */
#define MCB_PID(mcb) (*(unsigned short*)((char*)(mcb) + 1)) /* 0 indicates free block, PROCESS_ID indicates used block. */
#define MCB_SIZE_PARA(mcb) (*(unsigned short*)((char*)(mcb) + 3))  /* Block size in paragraphs (excluding MCB), must be at least 1 in kvikdos. */
#define MCB_PSIZE_PARA(mcb) (*(unsigned short*)((char*)(mcb) + 5))  /* Size of previous block (excluding MCB), or 0 if this is the first block. This is a kvikdos-specific field, DOS doesn't specify it. */

/* https://stanislavs.org/helppc/memory_control_block.html */
static const char default_program_mcb[16] = {
    'Z',  /* 'Z' indicates last member of MCB chain; 'M' would be non-last. */
    (char)PROCESS_ID,  /* \0\0 indicates free block. */
    (char)(PROCESS_ID >> 8),
    (char)(DOS_ALLOC_PARA_LIMIT - PSP_PARA),  /* Number of paragraphs low byte. */
    (char)((DOS_ALLOC_PARA_LIMIT - PSP_PARA) >> 8),  /* Number of paragraphs high byte. */
    0, 0,  /* Size of previous block. Unused for PROGRAM_MCB_PARA. */
    (char)0xb2,  /* Reserved bytes, random. */
    'K', 'V', '1', 'K', 'P', 'R', '0', 'G',  /* "KV1KPR0G". Program name. */
};

static const char freed_mcb[16] = {
    '\x88', '\xc9', '\xc0', '\x96', '\x1e', '\xc4', '\x42', '\xd5',  /* Random bytes, part of signature. */
    'K', 'V', '1', 'K', 'F', 'R', '3', '3',  /* "KV1KFR33". Program name signature. */
};

static char is_mcb_bad(void *mem, unsigned short block_para) {
  const char* mcb = (const char*)mem + (block_para << 4) - 16;
  unsigned short size_para;
  if (block_para < PSP_PARA) return 1;  /* MCB too low in memory. qblink.exe calls with block_para==0 many times, but it's still bad. */
  if (block_para >= DOS_ALLOC_PARA_LIMIT) return 2;  /* MCB too high in memory. */
  if (memcmp(mcb + 7, default_program_mcb + 7, 9) != 0) return 3;  /* MCB has bad signature. */
  if (MCB_TYPE(mcb) == 'Z') {
    if (MCB_PID(mcb) == 0) return 4;  /* Last MCB is free. */
  } else if (MCB_TYPE(mcb) != 'M') {
    return 5;  /* Bad MCB type. */
  }
  if (MCB_PID(mcb) != 0 && MCB_PID(mcb) != PROCESS_ID) return 6;  /* Bad MCB process ID. */
  size_para = MCB_SIZE_PARA(mcb);
  if (MCB_TYPE(mcb) == 'Z') {
    if (block_para + size_para > DOS_ALLOC_PARA_LIMIT) return 7;  /* Final MCB too long. */
  } else {
    const char * const next_mcb = mcb + 16 + (size_para << 4);
    if (block_para + size_para >= DOS_ALLOC_PARA_LIMIT) return 8;  /* Non-final MCB too long. */
    if (MCB_PSIZE_PARA(next_mcb) != size_para) return 9;  /* MCB size and next psize mismatch. */
    if (MCB_PID(mcb) == 0 && MCB_PID(next_mcb) == 0) return 10;  /* found adjacent free MCBs in next. */
  }
  if (block_para == PSP_PARA) {
    if (MCB_PSIZE_PARA(mcb) != 0) return 11;  /* Nonzero PSP MCB psize. */
    if (MCB_PID(mcb) == 0) return 12;  /* PSP MCB is free. */
  } else {
    const char * const prev_mcb = mcb - 16 - (MCB_PSIZE_PARA(mcb) << 4);
    if (block_para < PSP_PARA + 1 + MCB_PSIZE_PARA(prev_mcb)) return 13;  /* MCB psize too large. */
    if (MCB_TYPE(prev_mcb) != 'M') return 14;  /* Bad prev MCB type. */
    if (MCB_SIZE_PARA(prev_mcb) != MCB_PSIZE_PARA(mcb)) return 15;  /* MCB prev size and psize mismatch. */
    if (MCB_PID(mcb) == 0 && MCB_PID(prev_mcb) == 0) return 16;  /* Found adjacent free MCBs in prev. */
  }
  return 0;  /* MCB looks good. */
}

#if DEBUG
static void check_all_mcbs(void *mem) {
  unsigned block_para = PSP_PARA;
  for (;;) {
    const char mcb_error = is_mcb_bad(mem, block_para);
    const char * const mcb = (const char*)mem + (block_para << 4) - 16;
    if (mcb_error) {
      fprintf(stderr, "fatal: bad MCB for block_para=0x%04x: %d\n", block_para, mcb_error);
      exit(252);
    }
    if (MCB_TYPE(mcb) == 'Z') break;
    block_para += 1 + MCB_SIZE_PARA(mcb);
  }
}
#define DEBUG_CHECK_ALL_MCBS(mem) check_all_mcbs(mem)
#else
#define DEBUG_CHECK_ALL_MCBS(mem) do {} while (0)
#endif

/* --- */

static char is_same_ascii_nocase(const char *a, const char *b, unsigned size) {
  while (size-- != 0) {
    const unsigned char pa = *a++;
    const unsigned char pb = *b++;
    if (!(pa == pb || ((pa | 32) - 'a' + 0U <= 'z' - 'a' + 0U && (pa ^ 32) == pb))) return 0;
  }
  return 1;
}

#if !defined(__GLIBC__) && !defined(__UCLIBC__)
static void *my_memmem(const void *haystack, size_t haystacklen,
                       const void *needle, size_t needlelen) {
  const void *c, *haystack_end = (const char*)haystack + haystacklen - needlelen + 1;
  if (haystacklen < needlelen) return NULL;
  if (needlelen == 0) return (void*)haystack;
  if (needlelen == 1) return memchr(haystack, *(const char*)needle, haystacklen);
  for (c = memchr(haystack, *(const char*)needle, haystacklen); c;
       c = memchr(c, *(const char*)needle, (const char*)haystack_end - (const char*)c)) {
    if (memcmp(c, needle, needlelen) == 0) return (void*)c;
    c = (const void*)((const char*)c + 1);
  }
  return NULL;
}
#if 0  /* Test. */
fprintf(stderr, "(%s)\n", (const char *)memmem("foorxbard;", 9, "rd", 2));  /* Shoould print: (rd;) */
#endif
#define memmem my_memmem
#endif

/* Returns the total number of header bytes read from img_fd. */
static int detect_dos_executable_program(int img_fd, const char *filename, char *p) {
  int r;
  r = read(img_fd, p, PROGRAM_HEADER_SIZE);
  if (r < 0) {
    perror("fatal: error reading DOS executable program header");
    exit(252);
  }
  if (r == 0) {
    fprintf(stderr, "fatal: empty DOS executable program");
    exit(252);
  }
  if (r >= 2 && (('M' | 'Z' << 8) == *(unsigned short*)p || ('M' << 8 | 'Z') == *(unsigned short*)p)) {
    if (r < 26) {
      fprintf(stderr, "fatal: DOS .exe program too short: %s\n", filename);
      exit(252);
    }
  } else if (r >= 6 && is_same_ascii_nocase(p, "@echo ", 6)) {
    fprintf(stderr, "fatal: DOS .bat batch files not supported: %s\n", filename);
    exit(252);  /* !! add support */
  } else if (r >= 4 && 0 == memcmp(p, "\x7f""ELF", 4)) {  /* Typically Linux native executable. */
    fprintf(stderr, "fatal: ELF executable programs not supported: %s\n", filename);
    exit(252);  /* TODO(pts): Run them natively, without setting up KVM. */
  } else if (r >= 3 && ('#' | '!' << 8) == *(unsigned short*)p && (p[2] == ' ' || p[2] == '/')) {
    /* Unix script #! shebang detected. */
    fprintf(stderr, "fatal: Unix scripts not supported: %s\n", filename);
    exit(252);  /* TODO(pts): Run them natively, without setting up KVM. */
  }  /* Otheerwise it's a DOS .com program. */
  return r;
}

/* From exepack-1.3.0/src/stub.bin in https://www.bamsoftware.com/software/exepack/exepack-1.3.0.tar.gz */
static const unsigned char fixed_exepack_stub[283] = {
    0x89, 0xc5, 0x8c, 0xc3, 0x83, 0xc3, 0x10, 0x0e, 0x1f, 0x8b, 0x0e, 0x06,
    0x00, 0x89, 0xc8, 0x83, 0xc0, 0x0f, 0xd1, 0xd8, 0xd0, 0xe8, 0xd0, 0xe8,
    0xd0, 0xe8, 0x8c, 0xda, 0x01, 0xd0, 0x89, 0xda, 0x03, 0x16, 0x0c, 0x00,
    0x39, 0xd0, 0x73, 0x02, 0x89, 0xd0, 0x8e, 0xc0, 0x31, 0xf6, 0x31, 0xff,
    0xf3, 0xa4, 0x8e, 0xc2, 0x50, 0xb8, 0x6e, 0x00, 0x50, 0xcb, 0x83, 0xee,
    0x01, 0x73, 0x08, 0x8c, 0xde, 0x4e, 0x8e, 0xde, 0xbe, 0x0f, 0x00, 0x3e,
    0x8a, 0x04, 0xc3, 0x83, 0xef, 0x01, 0x73, 0x08, 0x8c, 0xc7, 0x4f, 0x8e,
    0xc7, 0xbf, 0x0f, 0x00, 0x26, 0x88, 0x05, 0xc3, 0x31, 0xf6, 0xe8, 0xd9,
    0xff, 0x3c, 0xff, 0x74, 0xf9, 0x46, 0x31, 0xff, 0xe8, 0xcf, 0xff, 0x88,
    0xc2, 0xe8, 0xca, 0xff, 0x88, 0xc5, 0xe8, 0xc5, 0xff, 0x88, 0xc1, 0x88,
    0xd0, 0x24, 0xfe, 0x3c, 0xb0, 0x75, 0x0c, 0xe8, 0xb8, 0xff, 0xe3, 0x15,
    0xe8, 0xc4, 0xff, 0xe2, 0xfb, 0xeb, 0x0e, 0x3c, 0xb2, 0x75, 0x60, 0xe3,
    0x08, 0xe8, 0xa6, 0xff, 0xe8, 0xb4, 0xff, 0xe2, 0xf8, 0xf6, 0xc2, 0x01,
    0x74, 0xca, 0x0e, 0x1f, 0xbe, 0x2d, 0x01, 0x31, 0xd2, 0xad, 0x89, 0xc1,
    0xe3, 0x19, 0xad, 0x89, 0xc7, 0x83, 0xe7, 0x0f, 0xd1, 0xe8, 0xd1, 0xe8,
    0xd1, 0xe8, 0xd1, 0xe8, 0x01, 0xd0, 0x01, 0xd8, 0x8e, 0xc0, 0x26, 0x01,
    0x1d, 0xe2, 0xe7, 0x80, 0xc6, 0x10, 0x75, 0xdd, 0x8b, 0x36, 0x0a, 0x00,
    0x01, 0xde, 0x8b, 0x3e, 0x08, 0x00, 0x01, 0x1e, 0x02, 0x00, 0x83, 0xeb,
    0x10, 0x8e, 0xdb, 0x8e, 0xc3, 0xfa, 0x8e, 0xd6, 0x89, 0xfc, 0xfb, 0x89,
    0xe8, 0xbb, 0x00, 0x00, 0x2e, 0xff, 0x2f, 0x90, 0x90, 0x90, 0x90, 0xb4,
    0x40, 0xbb, 0x02, 0x00, 0xb9, 0x16, 0x00, 0x8c, 0xca, 0x8e, 0xda, 0xba,
    0x17, 0x01, 0xcd, 0x21, 0xb8, 0xff, 0x4c, 0xcd, 0x21, 0x50, 0x61, 0x63,
    0x6b, 0x65, 0x64, 0x20, 0x66, 0x69, 0x6c, 0x65, 0x20, 0x69, 0x73, 0x20,
    0x63, 0x6f, 0x72, 0x72, 0x75, 0x70, 0x74 };

/* All offsets are in 2-byte words. */
#define EXE_SIGNATURE 0
#define EXE_LASTSIZE 1
#define EXE_NBLOCKS 2
#define EXE_NRELOC 3
#define EXE_HDRSIZE 4
#define EXE_MINALLOC 5
#define EXE_MAXALLOC 6
#define EXE_SS 7
#define EXE_SP 8
#define EXE_CHECKSUM 9  /* Ignored by kvikdos. */
#define EXE_IP 10
#define EXE_CS 11
#define EXE_RELOCPOS 12
#define EXE_NOVERLAY 13  /* Ignored and not even loaded by kvikdos. */

/* Load DOS executable program from (img_fd, filename, header, header_size)
 * to (mem, regs and sregs), return the size (para count) of the memory
 * block allocated in *block_size_para_out.
 *
 * r is the total number of header bytes alreday read from img_fd by
 * detect_dos_executable_program. Returns the psp (Program Segment Prefix)
 * address.
 */
static char *load_dos_executable_program(int img_fd, const char *filename, void *mem, const char *header, int header_size, struct kvm_regs *regs, struct kvm_sregs *sregs, unsigned short *block_size_para_out) {
#define MEMSIZE_AVAILABLE_PARA ((DOS_MEM_LIMIT >> 4) - PSP_PARA - 0x10 /* PSP */)
  const unsigned memsize_available_para = MEMSIZE_AVAILABLE_PARA;
  char *psp;
  if (header_size >= PROGRAM_HEADER_SIZE && (('M' | 'Z' << 8) == ((unsigned short*)header)[EXE_SIGNATURE] || ('M' << 8 | 'Z') == ((unsigned short*)header)[EXE_SIGNATURE])) {
    const unsigned short * const exehdr = (const unsigned short*)header;
    const unsigned short nblocks = exehdr[EXE_NBLOCKS] & 0x7ff;  /* Turbo C++ 3 BOSS NE stub. Mask to 1 MiB. */
    const unsigned exesize = exehdr[EXE_LASTSIZE] ? ((nblocks - 1) << 9) + exehdr[EXE_LASTSIZE] : nblocks << 9;
    const unsigned headsize = (unsigned)exehdr[EXE_HDRSIZE] << 4;
    const unsigned image_size = exesize - headsize;
    const unsigned memsize_min_para = (nblocks << 5) - exehdr[EXE_HDRSIZE] + exehdr[EXE_MINALLOC];  /* This includes .bss after the image. Please note that this doesn't depend on exehdr[EXE_LASTSIZE]. Formula is same as in MS-DOS 6.22, FREEDOS 1.2, DOSBox 0.74-4. */
    const unsigned memsize_max_para = (nblocks << 5) - exehdr[EXE_HDRSIZE] + exehdr[EXE_MAXALLOC];
    char * const image_addr = (char*)mem + (PSP_PARA << 4) + 0x100;
    const unsigned image_para = PSP_PARA + 0x10;
    unsigned reloc_count = exehdr[EXE_NRELOC];
    const unsigned stack_end_plus_0x100 = ((unsigned)(unsigned short)(exehdr[EXE_SS] + 0x10) << 4) + (exehdr[EXE_SP] ? exehdr[EXE_SP] : 0x10000);
    if (exehdr[EXE_LASTSIZE] > 0x200) {
      fprintf(stderr, "fatal: DOS .exe last block size too large (0x%04x > 0x200): %s\n", exehdr[EXE_LASTSIZE], filename);
      exit(252);
    }
    if (exehdr[EXE_MINALLOC] == 0 && exehdr[EXE_MAXALLOC] == 0) {
      fprintf(stderr, "fatal: loading DOS .exe to upper part of memory not supported: %s\n", filename);
      exit(252);
    }
    if (exesize <= headsize) {
      fprintf(stderr, "fatal: DOS .exe image smaller than header: %s\n", filename);
      exit(252);
    }
    if (stack_end_plus_0x100 > (memsize_min_para << 4) + 0x100) {  /* Some .exe files have it. */
      fprintf(stderr, "fatal: DOS .exe stack pointer after end of program memory (0x%x - 0x100 > 0x%x): %s\n", stack_end_plus_0x100, memsize_min_para << 4, filename);
      exit(252);
    }
    if (memsize_min_para > memsize_max_para) {
      fprintf(stderr, "fatal: DOS .exe minimum memory larger than maximum: %s\n", filename);
      exit(252);
    }
    if (memsize_min_para > memsize_available_para) {
      fprintf(stderr, "fatal: DOS .exe uses too much conventional memory: %s\n", filename);
      exit(252);
    }
    if (memsize_max_para > memsize_available_para)
    /* 0x10 and 0x100: Allow EXE_CS value of 0xfff0 to wrap around, and then cs would point to the PSP. */
    if (((unsigned)(unsigned short)(exehdr[EXE_CS] + 0x10) << 4) + exehdr[EXE_IP] >= image_size + 0x100) {
      fprintf(stderr, "fatal: DOS .exe entry point after end of image (0x%x >= 0x%x): %s\n", ((unsigned)exehdr[EXE_CS] << 4) + exehdr[EXE_IP], image_size, filename);
      exit(252);
    }
    if ((unsigned)lseek(img_fd, headsize, SEEK_SET) != headsize) {
      fprintf(stderr, "fatal: error seeking to image in DOS .exe: %s\n", filename);
      exit(252);
    }
    if ((unsigned)read(img_fd, image_addr, image_size) != image_size) {
      fprintf(stderr, "fatal: error reading image in DOS .exe: %s\n", filename);
      exit(252);
    }
    if (reloc_count) {  /* Process relocations. */
      unsigned short reloc[1024]; /* 2048 bytes on the stack. */
      if ((unsigned)lseek(img_fd, exehdr[EXE_RELOCPOS], SEEK_SET) != exehdr[EXE_RELOCPOS]) {
        fprintf(stderr, "fatal: error seeking to image relocations: %s\n", filename);
        exit(252);
      }
      while (reloc_count != 0) {
        const unsigned to_read = reloc_count > (sizeof(reloc) >> 2) ? sizeof(reloc) : reloc_count << 2;
        const unsigned got = read(img_fd, reloc, to_read);
        unsigned short *r, *rend;
        if (got != to_read) {
          fprintf(stderr, "fatal: error reading relocations in DOS .exe: %s\n", filename);
          exit(252);
        }
        reloc_count -= got >> 2;
        for (r = reloc, rend = r + (got >> 1); r != rend; r += 2) {
          *(unsigned short*)(image_addr + ((unsigned)r[1] << 4) + r[0]) += image_para;
        }
      }
    }
    psp = image_addr - 0x100;
    sregs->ds.selector = sregs->es.selector = image_para - 0x10; /* DS and ES point to PSP. */
    *(unsigned short*)&regs->rip = exehdr[EXE_IP];  /* DOS .exe entry point. */
    sregs->cs.selector = exehdr[EXE_CS] + image_para;
    *(unsigned short*)&regs->rsp = exehdr[EXE_SP];
    sregs->ss.selector = exehdr[EXE_SS] + image_para;
    *(unsigned*)(psp + 6) = 0xc0;  /* CP/M far call 5 service request address. Obsolete. */
    *block_size_para_out = ((memsize_max_para > memsize_available_para) ? memsize_available_para : memsize_max_para) + 0x10 /* PSP */;
    if (exehdr[EXE_IP] == 16 || exehdr[EXE_IP] == 18 || exehdr[EXE_IP] == 20) {  /* Detect exepack, find decompression stub within it, replace stub with fixed stub to avoid ``Packed file is corrupt'' error. DOS 5.0 does a similar fix. */
      /* More info about the A20 bug in the exepack stubs: https://github.com/joncampbell123/dosbox-x/issues/7#issuecomment-667653041
       * More info about the exepack file format: https://www.bamsoftware.com/software/exepack/
       * Example error with buggy (unfixed) stubs: fatal: KVM memory access denied phys_addr=00101103 value=0000000000000000 size=1 is_write=0
       */
      unsigned short * const packhdr = (unsigned short*)(image_addr + ((unsigned)exehdr[EXE_CS] << 4));
      const unsigned exepack_max_size = image_size - ((unsigned)exehdr[EXE_CS] << 4) - exehdr[EXE_IP];
      const unsigned exepack_stub_plus_reloc_size =  packhdr[3] - exehdr[EXE_IP];
      if (*(unsigned short*)((char*)packhdr + exehdr[EXE_IP] - 2) == ('R' | 'B' << 8) &&  /* exepack signature. */
          exepack_stub_plus_reloc_size >= 258 && exepack_stub_plus_reloc_size <= exepack_max_size) {
        char *after_packhdr = (char*)packhdr + exehdr[EXE_IP];
        const char *c = (const char*)memmem(after_packhdr, exepack_stub_plus_reloc_size, "\xcd\x21\xb8\xff\x4c\xcd\x21", 7);
        if (DEBUG) fprintf(stderr, "info: detected DOS .exe packed with exepack: header_size=%d exepack_max_size=%d exepack_stub_plus_reloc_size=%d\n", exehdr[EXE_IP], exepack_max_size, exepack_stub_plus_reloc_size);
        if (c) {
          const unsigned exepack_stub_size = (unsigned)(c + 7 + 22 - after_packhdr);
          if (exepack_stub_size >= 258 && exepack_stub_size <= 290) {
            if (DEBUG) fprintf(stderr, "info: detected DOS .exe packed with exepack: header_size=%d exepack_max_size=%d exepack_stub_plus_reloc_size=%d exepack_stub_size=%d\n", exehdr[EXE_IP], exepack_max_size, exepack_stub_plus_reloc_size, exepack_stub_size);
            /* Fix A20 bug (failure as ``Packed file is corrupt'' because ES
             * wraps around 0x10000) by replacing the stub.
             */
            memmove((char*)packhdr + 18 + sizeof(fixed_exepack_stub), after_packhdr + exepack_stub_size, exepack_stub_plus_reloc_size - exepack_stub_size);  /* Move packed reloc. */
            memcpy((char*)packhdr + 18, fixed_exepack_stub, sizeof(fixed_exepack_stub));  /* Copy fixed stub. */
            if (exehdr[EXE_IP] != 18) {
              if (exehdr[EXE_IP] == 16) {  /* Make it longer, because fixed_exepack_stub works only with an 18-byte header (it has org 18 in stub.asm). */
                *(unsigned short*)&regs->rip = 18;  /* Update DOS .exe entry point. */
                packhdr[7] = 1;  /* skip_len. */
              } else {  /* (exehdr[EXE_IP] == 20) */  /* Microsoft Macro Assembler 5.10A linker link.exe. */
                if (packhdr[4] != 0) {
                  fprintf(stderr, "fatal: unexpected packhdr[4] in 20-byte exepack header: 0x%04x\n", packhdr[4]);
                  exit(252);
                }
                packhdr[4] = packhdr[5];
                packhdr[5] = packhdr[6];
                packhdr[6] = packhdr[7];
                packhdr[7] = packhdr[8];
              }
              packhdr[8] = ('R' | 'B' << 8);  /* exepack signature. */
            }
          }
        }
      }
    }
  } else {
    /* Load DOS .com program. */
    char * const p = (char *)mem + (PSP_PARA << 4) + 0x100;
    int r;
    memcpy(p, header, header_size);
    r = read(img_fd, p + header_size, MAX_DOS_COM_SIZE + 1 - header_size);
    if (r < 0) { /*read_error:*/
      perror("fatal: error reading DOS executable program");
      exit(252);
    }
    r += header_size;
    if (r > MAX_DOS_COM_SIZE) {
      fprintf(stderr, "fatal: DOS executable program too long: %s\n", filename);
      exit(252);
    }
    /* No need to check for DOS_MEM_LIMIT, because (PSP_PARA << 4) + 0x100 + MAX_DOS_COM_SIZE + 0x10 < DOS_MEM_LIMIT. */
    sregs->cs.selector = sregs->ds.selector = sregs->es.selector = sregs->ss.selector = PSP_PARA;
    psp = (char*)mem + (PSP_PARA << 4);  /* Program Segment Prefix. */
    *(unsigned short*)&regs->rsp = 0xfffe;
    *(unsigned short*)(psp + *(unsigned short*)&regs->rsp) = 0;  /* Push a 0 byte. */
    *(unsigned short*)(psp + 6) = MAX_DOS_COM_SIZE + 0x100;  /* .COM bytes available in segment (CP/M). DOSBox doesn't initialize it. */
    /*memset(psp, 0, 0x100);*/  /* Not needed, mmap MAP_ANONYMOUS has done it. */
    *(unsigned short*)&regs->rip = 0x100;  /* DOS .com entry point. */
    { struct SA { int StaticAssert_MinimumComMemory : MEMSIZE_AVAILABLE_PARA + 0x10 >= 0x1000; }; }
    *block_size_para_out = memsize_available_para + 0x10 /* PSP */;  /* Minimum would be 0x1000 paras (65536 bytes), including PSP. */
  }
  /* https://stanislavs.org/helppc/program_segment_prefix.html */
  *(unsigned short*)(psp + 2) = DOS_MEM_LIMIT >> 4;  /* Top of memory. */
  psp[5] = (char)0xf4;  /* hlt instruction; this is machine code to jump to the CP/M dispatcher. */
  *(unsigned short*)(psp + 0x2c) = ENV_PARA;
  *(unsigned short*)(psp) = 0x20cd;  /* `int 0x20' opcode. */
  *(unsigned short*)(psp + 0x40) = 5;  /* DOS version number (DOSBox also reports 5). */
  *(unsigned short*)(psp + 0x50) = 0x21cd;  /* `int 0x21' opcode. */
  *(unsigned short*)(psp + 0x32) = 20;  /* `Number of bytes in JFT. */
  *(unsigned*)(psp + 0x34) = 0x18 | PSP_PARA << 16;  /* `Far pointer to JFT. */
  *(unsigned*)(psp + 0x38) = 0xffffffffU;  /* `Pointer to (lack of) previous PSP. */
  *(unsigned*)(psp + 0x0a) = *((unsigned*)mem + 0x22);  /* Copy of `int 0x22' vector. Program terminate address. Not an interrupt. */
  *(unsigned*)(psp + 0x0e) = *((unsigned*)mem + 0x23);  /* Copy of `int 0x23' vector. Ctrl-<Break> handler address. Not an interrupt.  */
  *(unsigned*)(psp + 0x12) = *((unsigned*)mem + 0x24);  /* Copy of `int 0x24' vector. Critical error handler. Do not execute directly (why?). */
  psp[0x52] = (char)0xcb;  /* `retf' opcode. */
  psp[5] = (char)0x9a;  /* Opcode for `call far segment:offset'. */
  /* These are the PSP fields we don't fill (but keep as 0 as returned by mmap MAP_ANONYMOUS):
   * 0x18 20 bytes  file handle array (Undocumented DOS 2.x+); if handle array element is FF then handle is available. Network redirectors often indicate remotes files by setting these to values between 80-FE. DOS 2+ Job File Table JFT), one byte per file handle, FFh = closed. https://en.wikipedia.org/wiki/Job_File_Table
   * 0x2e dword     SS:SP on entry to last INT 21 call (Undoc. 2.x+)
   * 0x38 dword     pointer to previous PSP (default FFFF:FFFF, Undoc. 3.x+), used by SHARE in DOS 3.3
   * 0x3c byte      DOS 4+ (DBCS) interim console flag (see AX=6301h) Novell DOS 7 DBCS interim flag as set with AX=6301h (possibly also used by Far East MS-DOS 3.2-3.3)
   * 0x3d byte      (APPEND) TrueName flag (see INT 2F/AX=B711h)
   * 0x3e byte      (Novell NetWare) flag: next byte initialized if CEh (OS/2) capabilities flag
   * 0x3f byte      (Novell NetWare) Novell task number if previous byte is CEh
   * 0x42 word      (MSWindows3) selector of next PSP (PDB) in linked list Windows keeps a linked list of Windows programs only
   * 0x44 word      (MSWindows3) "PDB_Partition"
   * 0x46 word      (MSWindows3) "PDB_NextPDB"
   * 0x5c 36 bytes  default unopened FCB #1 (parts overlayed by FCB #2)
   * 0x6c 20 bytes  default unopened FCB #2 (overlays part of FCB #1) (overwritten if FCB 1 is opened)
   */
  return psp;
}

static void dump_regs(const char *prefix, const struct kvm_regs *regs, const struct kvm_sregs *sregs) {
#define R16(name) (*(unsigned short*)&regs->r##name)
#define S16(name) (*(unsigned short*)&sregs->name.selector)
  fprintf(stderr, "%s: regs: cs:%04x ip:%04x ax:%04x bx:%04x cx:%04x dx:%04x si:%04x di:%04x sp:%04x bp:%04x flags:%08x ds:%04x es:%04x fs:%04x gs:%04x ss:%04x\n",
          prefix, S16(cs), R16(ip),
          R16(ax), R16(bx), R16(cx), R16(dx), R16(si), R16(di), R16(sp), R16(bp), *(unsigned*)&regs->rflags,
          S16(ds), S16(es), S16(fs), S16(gs), S16(ss));
  fflush(stdout);
}

static void copy_args_to_dos_args(char *p, char **args) {
  unsigned size = 1;
  while (*args) {
    const char *arg = *args++;
    const unsigned arg_size = strlen(arg);
    if (size + arg_size < size || size + arg_size > 127) {
      fprintf(stderr, "fatal: DOS command line args too long\n");
      exit(252);
    }
    p[size++] = ' ';  /* Initial space compatible with MS-DOS. */
    memcpy(p + size, arg, arg_size);
    size += arg_size;
  }
  p[size] = '\r';
  *p = --size;
}

/* Returns an fd for which min_fd >= fd (except if fd was negative).
 * As a side effect, if it returns a different fd, then it closes the original fd.
 */
static int ensure_fd_is_at_least(int fd, int min_fd) {
  if (fd >= 0 && fd + 0U < min_fd + 0U) {
    int fd2 = dup(fd), fd3;
    if (fd2 < 0) { perror("dup"); exit(252); }
    if (fd2 + 0U < min_fd + 0U) fd2 = ensure_fd_is_at_least(fd2, min_fd);
    if ((fd3 = open("/dev/null", O_RDWR)) >= 0) {
      if (fd3 == fd) {  /* Usually doesn't happen. */
        return fd2;  /* Keep /dev/null open as fd (see below). */
      } else if (dup2(fd3, fd) == fd) {
        close(fd3);
        return fd2;  /* Keep /dev/null open as fd (for which fd < min_fd), for faster operation subsequent many open() + close() calls with ensure_fd_is_at_least(). */
      } else {
        close(fd3);
      }
    }
    close(fd);
    fd = fd2;
  }
  return fd;
}

/* le is Linux errno. */
static unsigned short get_dos_error_code(int le, unsigned short default_code) {
  /* https://stanislavs.org/helppc/dos_error_codes.html */
  return le == ENOENT ? 2  /* File not found. */
       : le == EACCES ? 5  /* Access denied. */
       : le == EBADF ? 6  /* Invalid handle. */
       : default_code;  /* Example: 0x1f: General failure. */
}

struct kvm_fds {
  int kvm_fd, vm_fd, vcpu_fd;
};

static int get_linux_handle(unsigned short handle, const struct kvm_fds *kvm_fds) {
  return handle < 5 ? (
               handle == 3 ? 2  /* Emulate STDAUX with stderr. */
             : handle == 4 ? 1  /* Emulate STDPRN with stdout. */
             : handle)
       : (handle == kvm_fds->kvm_fd || handle == kvm_fds->vm_fd || handle == kvm_fds->vcpu_fd) ? -1  /* Disallow these handles from DOS for security. */
       : handle;
}

typedef struct DirState {
  char drive;  /* 'A', 'B', 'C' or 'D'. */
  char current_dir[4][128];  /* In DOS syntax. If current_dir[2] is "FOO\BAR\", then it corresponds to C:\FOO\BAR. */
  const char *linux_mount_dir[4];  /* Linux directory to which the specific drive has been mounted, with '/' suffix, or NULL. Owned externally. linux_mount_dir[2] == "/tmp/foo/" maps DOS path C:\MY\FILE.TXT to Linux path /tmp/foo/MY/FILE.TXT .  */
  const char *dos_prog_abs;  /* DOS absolute pathname of the program being run. Externally owned, can be NULL. */
  const char *linux_prog;  /* Linux pathname of the program being run. Externally owned, can be NULL. */
} DirState;

#define LINUX_PATH_SIZE 1024

/* out_buf is LINUX_PATH_SIZE bytes. */
static const char *get_linux_filename_r(const char *p, const DirState *dir_state, char *out_buf) {
  char *out_p = out_buf, *out_pend;
  const char *in_linux;
  const char *in_dos[2] = { "", "" };
  char drive_idx;
  if (*p == '\0') goto done;  /* Empty pathname is an error. */
  if (dir_state->dos_prog_abs && strcmp(p, dir_state->dos_prog_abs) == 0) {
    in_linux = dir_state->linux_prog;
  } else {
    if (p[0] != '\0' && p[1] == ':') {
      drive_idx = (p[0] & ~32) - 'A';
      if ((unsigned char)drive_idx >= 4) {  /* Bad or unknown drive letter. */  /* !! Report error 0x3 (Path not found) */
        /*fprintf(stderr, "fatal: DOS filename on wrong drive: 0x%02x\n", (unsigned char)p[0]);*/  /* !! Report error 0x3 (Path not found) */
        /*exit(252);*/
        goto done;
      }
      in_linux = dir_state->linux_mount_dir[(int)drive_idx];
      if (!in_linux) goto done;  /* !! Report error 0x3 (Path not found) */
      p += 2;
    } else {
      in_linux = NULL;
      drive_idx = dir_state->drive - 'A';
    }
    if (*p == '\\' || *p == '/') {
      for (++p; *p == '\\' || *p == '/'; ++p) {}
    } else {
      in_dos[0] = dir_state->current_dir[(int)drive_idx];
    }
    in_dos[1] = p;
  }
  out_pend = out_p + LINUX_PATH_SIZE - 1;
  if (in_linux) {
    const size_t size = strlen(in_linux);
    if (size > (size_t)(out_pend - out_p)) { too_long:  /* Pathname too long. !! Handle this error. !! Report error 0x3 (Path not found) or 0x44 (Network name limit exceeded). */
     error:
      out_p = out_buf;
      goto done;
    }
    memcpy(out_p, in_linux, size);
    out_p += size;
  }
  {  /* Convert pathnames in in_dos */
    const char * const *in_dosi;
    unsigned cc = 0;  /* Component count. */
    for (in_dosi = in_dos; in_dosi != in_dos + 2; ++in_dosi) {
      p = *in_dosi;
      for (; *p != '\0';) {
        if (p[0] == '.' && (p[1] == '\0' || p[1] == '\\' || p[1] == '/' || (p[1] == '.' && (p[2] == '\0' || p[2] == '\\' || p[2] == '/')))) {
          if (p[1] == '.') {
            /* Security: Too many levels up, outside linux_mount_dir with `..'. It's still possible to escape up if one of the pathname components is a symlink. */
            if (cc-- == 0) goto error;
          }
        } else {
          ++cc;
        }
        for (; *p != '\0';) {
          const char c = *p++;
          if (out_p == out_pend) goto too_long;
          if (c == '\\' || c == '/') {
            *out_p++ = '/';  /* Convert '\\' to '/'. */
            break;
          }
          *out_p++ = (c - 'a' + 0U <= 'z' - 'a' + 0U) ? c & ~32 : c;  /* Convert to uppercase. */
          /* TODO(pts) Truncate each component to 8.3 characters? */
        }
        for (; *p == '\\' || *p == '/'; ++p) {}
      }
    }
  }
 done:
  *out_p = '\0';
  if (strcmp(out_buf, "NUL") == 0) strcpy(out_buf, "/dev/null");
  return out_buf;
}

static void get_dos_abspath_r(const char *p, const DirState *dir_state, char *out_buf, unsigned out_size) {
  char *out_p = out_buf, *out_pend = out_buf + out_size;
  char drive_idx;
  const char *in_dos[2];
  if (DEBUG) fprintf(stderr, "debug: get_dos_abspath_r (%s)\n", p);
  if (*p == '\0' || out_size < 5) goto done;  /* Empty pathname is an error. */
  if (p[0] != '\0' && p[1] == ':') {
    drive_idx = (p[0] & ~32) - 'A';
    if ((unsigned char)drive_idx >= 4) {  /* Bad or unknown drive letter. */  /* !! Report error 0x3 (Path not found) */
      /*fprintf(stderr, "fatal: DOS filename on wrong drive: 0x%02x\n", (unsigned char)p[0]);*/  /* !! Report error 0x3 (Path not found) */
      /*exit(252);*/
      goto done;
    }
    p += 2;
  } else {
    drive_idx = dir_state->drive - 'A';
  }
  if (*p == '\\' || *p == '/') {
    for (++p; *p == '\\' || *p == '/'; ++p) {}
    in_dos[0] = "";
  } else {
    in_dos[0] = dir_state->current_dir[(int)drive_idx];
  }
  in_dos[1] = p;
  {  /* Convert pathnames in in_dos */
    const char * const *in_dosi;
    *out_p++ = drive_idx + 'A';
    *out_p++ = ':';
    *out_p++ = '\\';
    for (in_dosi = in_dos; in_dosi != in_dos + 2; ++in_dosi) {
      p = *in_dosi;
      for (; *p != '\0';) {
        const char c = *p++;
        if (out_p == out_pend) { out_p = out_buf; goto done; }
        if (c == '\\' || c == '/') {
          *out_p++ = '\\';  /* Convert '/' to '\\'. */
          for (++p; *p == '\\' || *p == '/'; ++p) {}
        } else {
          *out_p++ = (c - 'a' + 0U <= 'z' - 'a' + 0U) ? c & ~32 : c;  /* Convert to uppercase. */
          /* TODO(pts) Truncate each component to 8.3 characters? */
        }
      }
    }
  }
 done:
  *out_p = '\0';
  if (DEBUG) fprintf(stderr, "debug: get_dos_abspath_r=(%s)\n", out_buf);
}

static char fnbuf[LINUX_PATH_SIZE], fnbuf2[LINUX_PATH_SIZE];

#define get_linux_filename(p) get_linux_filename_r((p), &dir_state, fnbuf)

#define DOS_PATH_SIZE 64  /* See int 0x21 ah == 0x47 (get current directory) */
static char dosfnbuf[DOS_PATH_SIZE];

/* Converts Linux pathname p to DOS absolute pathname into out_buf (of
 * DOS_PATH_SIZE bytes). Always returns out_buf. On error, sets out_buf to
 * the empty string. */
static const char *get_dos_abs_filename_r(const char *p, const DirState *dir_state, char *out_buf) {
  char drive, best_drive;
  size_t best_mp_size;
  const char *p0;
  while (p[0] == '.' && p[1] == '/') {
    for (p += 2; p[0] == '/'; ++p) {}
  }
  p0 = p;
  best_drive = '\0'; best_mp_size = 0;
  for (drive = 'A'; drive <= 'D'; ++drive) {  /* TODO(pts): Find the longest matching linux_mount_dir. */
    const char *mp = dir_state->linux_mount_dir[drive - 'A'];
    if (mp) {
      const size_t mp_size = strlen(mp);
      if (0 == strncmp(p0, mp, mp_size) && mp_size >= best_mp_size) {  /* >= here ensures that we can find mp_size == 0 (default). */
        best_drive = drive;
        best_mp_size = best_mp_size;
      }
    }
  }
  if (best_drive == '\0') goto error;  /* No mounted drives. */
  {
    const char *mp = dir_state->linux_mount_dir[best_drive - 'A'];
    const size_t mp_size = strlen(mp);
    if (0 == strncmp(p0, mp, mp_size)) {
      char *r = out_buf;
      char *rend = out_buf + DOS_PATH_SIZE - 1;
      *r++ = best_drive;
      *r++ = ':';
      *r++ = '\\';
      for (p = p0 + mp_size; *p != '\0';) {
        const char c = *p++;
        if (r == rend) goto error;  /* DOS pathname too long. */
        if (c == '/') {
          for (; *p == '/'; ++p) {}  /* Skip subsequent slashes. */
        }
        /* TODO(pts): Check that each pathname component is at most 8.3 bytes long. */
        *r++ = (c == '/') ? '\\'  /* Convert '/' to '\\'. */
             : (c - 'a' + 0U <= 'z' - 'a' + 0U) ? c & ~32 : c;  /* Convert to uppercase. */
      }
      *r = '\0';
      return out_buf;
    }
  }
 error:
  *out_buf = '\0';  /* Mount point not found. */
  return out_buf;
}

/* `var' usually looks like `PATH=C:\value'. Everything before the '=' is converted to lowercase. */
static char *add_env(char *env, char *env_end, const char *var, char do_check) {
  if (do_check && *var == '=') {
    fprintf(stderr, "fatal: DOS environment variable has empty name\n");
    exit(252);
  }
  for (;;) {
    const char c = *var++;
    if (env == env_end) {
      fprintf(stderr, "fatal: DOS environment too long\n");
      exit(252);
    }
    if (c == '=') do_check = 0;  /*in_name = 0;*/
    *env++ = (c - 'a' + 0U <= 'z' - 'a' + 0U && do_check) ? c & ~32 : c;  /* Convert name to uppercase. */
    if (c == '\0') break;
  }
  if (do_check) {
    fprintf(stderr, "fatal: DOS environment variable has missing value\n");
    exit(252);
  }
  return env;
}

/* Example name_prefix: "PATH=". */
static const char *getenv_prefix(const char *name_prefix, const char **env, const char **env_end) {
  const size_t name_prefix_size = strlen(name_prefix);
  for (; env != env_end; ++env) {
    if (strncmp(*env, name_prefix, name_prefix_size) == 0) return *env + name_prefix_size;
  }
  return NULL;
}

/* Same extension lookup order as in DOS. */
static const char * const find_program_exts[] = { ".COM", ".com", ".EXE", ".exe", ".BAT", ".bat", NULL };
static const char * const find_program_no_exts[] = { "", NULL };

/* Both prog_filename and the return value are Linux pathnames.
 * Uses global variable fnbuf as temporary storage and possible return value.
 */
static const char *find_program(const char *prog_filename, const DirState *dir_state, const char *dos_path) {
  size_t size;
  const char *p, *pp, *pq;
  char *r;
  char c;
  const char * const * exts0;
  for (p = prog_filename; (c = *p) != '\0' && c != ':' && c != '/' && c != '\\'; ++p) {}
  if (*p != '\0') return prog_filename;  /* Too complicated, don't attempt DOS %PATH% lookup. */
  size = strlen(prog_filename);
  for (p = prog_filename + size; p != prog_filename && *--p != '.';) {}
  /* DOS allows only exts in find_program_exts, we allow anything the user specifies here. */
  exts0 = (*p != '.') ? find_program_exts : find_program_no_exts;
  if (DEBUG) fprintf(stderr, "debug: DOS path lookup prog_filename=%s p=%s dos_path=%s\n", prog_filename, p, dos_path);
  pp = pq = NULL;
  for (;;) {  /* Find in current directory first, then continue finding on DOS %PATH%. */
    const char * const * exts;
    r = fnbuf;
    if (pp) {
      char c;
      for (pq = pp; (c = *pp) != ';' && c != '\0'; ++pp) {}
      *(char*)pp = '\0';  /* Temporary terminator within dos_path, for get_linux_filename_r. */
      get_linux_filename_r(pq, dir_state, fnbuf);
      if (*fnbuf == '\0') goto end_of_pp;  /* TODO(pts): `return prog_filename' on too long. */
      *(char*)pp = c;
      r = fnbuf + strlen(fnbuf);
      if ((unsigned)(r - fnbuf)  >= sizeof(fnbuf)) return prog_filename;  /* Too long. */
      *r++ = '/';
    }
    if ((unsigned)(r - fnbuf) + size >= sizeof(fnbuf)) return prog_filename;  /* Too long. */
    memcpy(r, prog_filename, size);
    r += size;
    *r = '\0';
    if (DEBUG) fprintf(stderr, "debug: trying progs: %s\n", fnbuf);
    for (exts = exts0; *exts; ++exts) {
      const size_t ext_size = strlen(*exts);
      struct stat st;
      if ((unsigned)(r - fnbuf) + ext_size >= sizeof(fnbuf)) return prog_filename;  /* Too long. */
      memcpy(r, *exts, ext_size);
      r[ext_size] = '\0';
      if (DEBUG) fprintf(stderr, "debug: trying prog: %s\n", fnbuf);
      if (stat(fnbuf, &st) == 0 && S_ISREG(st.st_mode)) {
        if (DEBUG) fprintf(stderr, "debug: found prog: %s\n", fnbuf);
        return fnbuf;  /* Found program file. */
      }
    }
   end_of_pp:
    if (pp) {
    } else if (dos_path) {
      pp = dos_path;
    } else {
      break;
    }
    for (; *pp == ';'; ++pp) {}  /* Skip over %PATH% separator characters ';'. */
    if (*pp == '\0') break;
  }
  return prog_filename;
}

/* Sets interrupt vector for int_num to value_seg_ofs in IVT. Does some
 * checks. Returns 0 on success.
 */
static char set_int(unsigned char int_num, unsigned value_seg_ofs, void *mem, char had_get_ints) {
  unsigned * const p = (unsigned*)mem + int_num;
  if (DEBUG) {
    fprintf(stderr, "debug: set interrupt vector int:%02x to cs:%04x ip:%04x\n",
            int_num, (unsigned short)(value_seg_ofs >> 16), (unsigned short)value_seg_ofs);
  }
  if (int_num - 0x22 + 0U <= 0x24 - 022 +0U ||  /* Application Ctrl-<Break> handler == 0x23. We allow 0x22..0x24. */
      value_seg_ofs == *p ||  /* Unchanged. */
      value_seg_ofs == MAGIC_INT_VALUE(int_num) ||  /* Set back to original. */
      ((had_get_ints & 2) && int_num == 0x18) ||  /* TASM 3.2. */
      ((had_get_ints & 4) && int_num == 0x06) ||  /* TLINK 4.0. */
      ((had_get_ints & 1) && (int_num == 0x00 || int_num == 0x24 || int_num == 0x3f))  /* Turbo Pascal 7.0. */ ||
      ((had_get_ints & 1) && int_num == 0x75)  /* Microsoft QuickBASIC 4.50 compiler qbc.exe. */  ||
      ((had_get_ints & 1) && (int_num == 0x00 || int_num == 0x02 || int_num - 0x35 + 0U <= 0x3f - 0x35 + 0U))  /* Microsoft BASIC Professional Development System 7.10 compiler pbc.exe. */) {
    /* FYI kvikdos never sends Ctrl-<Break>. */
  } else {
    fprintf(stderr, "fatal: unsupported set interrupt vector int:%02x to cs:%04x ip:%04x\n",
            int_num, (unsigned short)(value_seg_ofs >> 16), (unsigned short)value_seg_ofs);
    return 1;
  }
  *p = value_seg_ofs;
  return 0;  /* Success. */
}

static const struct {
  unsigned short date_format;
  char currency[5];
  char thousands_separator[2];
  char decimal_separator[2];
  char date_separator[2];
  char time_separator[2];
  char currency_format, digits_after_decimal, time_format;
  unsigned short casemap_callback_ofs;  /* Points to a `retf' opcode. Natural alignment of 2 bytes. */
  unsigned short casemap_callback_seg;  /* Natural alignment of 2 bytes. */
  char data_separator[2];
} country_info = { 0, "$", ",", ".", "-", ":", 0, 2, 0, 0xf, INT_HLT_PARA - 1, "," };

static const char *get_dos_basename(const char *fn) {
  const char *fnp;
  if (fn[0] != '\0' && fn[1] == ':') fn += 2;
  for (fnp = fn + strlen(fn); fnp != fn && fnp[-1] != '\\'; --fnp) {}
  return fnp;
}

static const char *get_linux_basename(const char *fn) {
  const char *fnp;
  for (fnp = fn + strlen(fn); fnp != fn && fnp[-1] != '/'; --fnp) {}
  return fnp;
}

/* Returns bool indicating whether all components of the specified filename (as a DOS pathname, maybe absolute) are limited to DOS 8.3 characters. */
static char is_dos_filename_83(const char *fn) {
  unsigned u;
  if (fn[0] != '\0' && fn[1] == ':') fn += 2;
  for (u = 0; u <= 8 && *fn != '.' && *fn != '\0'; ++fn, ++u) {}
  if (u > 8) return 0;
  if (*fn == '.') {
    for (u = 0, ++fn; u <= 3 && *fn != '\0'; ++fn, ++u) {}
    if (u > 3) return 0;
  }
  return 1;
}

/* scancodes[i] is the US English keyboard scancode corresponding to ASCII
 * code i.
 *
 * Generated by scancode.py.
 * Based on https://stanislavs.org/helppc/scan_codes.html
 */
static const unsigned char scancodes[128] = {
    0x3e, 0x1e, 0x30, 0x2e, 0x20, 0x12, 0x21, 0x22, 0x0e, 0x0f, 0x24, 0x25,
    0x26, 0x0c, 0x31, 0x18, 0x19, 0x10, 0x13, 0x1f, 0x14, 0x16, 0x2f, 0x11,
    0x2d, 0x15, 0x2c, 0x01, 0x2b, 0x1b, 0x07, 0x0c, 0x39, 0x02, 0x28, 0x04,
    0x05, 0x06, 0x08, 0x28, 0x0a, 0x0b, 0x09, 0x0d, 0x33, 0x0c, 0x34, 0x35,
    0x0b, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x27, 0x27,
    0x33, 0x0d, 0x34, 0x35, 0x03, 0x1e, 0x30, 0x2e, 0x20, 0x12, 0x21, 0x22,
    0x23, 0x17, 0x24, 0x25, 0x26, 0x32, 0x31, 0x18, 0x19, 0x10, 0x13, 0x1f,
    0x14, 0x16, 0x2f, 0x11, 0x2d, 0x15, 0x2c, 0x1a, 0x2b, 0x1b, 0x07, 0x0c,
    0x29, 0x1e, 0x30, 0x2e, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25,
    0x26, 0x32, 0x31, 0x18, 0x19, 0x10, 0x13, 0x1f, 0x14, 0x16, 0x2f, 0x11,
    0x2d, 0x15, 0x2c, 0x1a, 0x2b, 0x1b, 0x29, 0x35 };

int main(int argc, char **argv) {
  struct kvm_fds kvm_fds;
  void *mem;
  struct kvm_userspace_memory_region region;
  int kvm_run_mmap_size, api_version, img_fd;
  struct kvm_run *run;
  struct kvm_regs regs;
  struct kvm_sregs sregs;
  const char *prog_filename;
  char header[PROGRAM_HEADER_SIZE];
  unsigned header_size;
  char had_get_ints;
  char **envp, **envp0;
  const char *dos_prog_abs = NULL;  /* Owned externally. */
  unsigned tick_count;
  unsigned char sphinx_cmm_flags;
  char ctrl_break_checking;  /* 0 or 1. Just a flag, doesn't have any use case. */
  DirState dir_state;
  unsigned dta_seg_ofs;  /* Disk transfer address (DTA). */
  unsigned ongoing_set_int;
  unsigned short last_dos_error_code;
  int tty_in_fd;
  char is_tty_in_error;

  { struct SA { int StaticAssert_AllocParaLimits : DOS_ALLOC_PARA_LIMIT <= (DOS_MEM_LIMIT >> 4); }; }
  { struct SA { int StaticAssert_CountryInfoSize : sizeof(country_info) == 0x18; }; }

  (void)argc;
  if (!argv[0] || !argv[1] || 0 == strcmp(argv[1], "--help")) {
    fprintf(stderr, "Usage: %s [<flag> ...] <dos-com-or-exe-file> [<dos-arg> ...]\n"
                    "Flags:\n"
                    "--env=<NAME>=<value>: Adds environment variable.\n"
                    "--prog=<dos-pathname>: Sets DOS pathname of program.\n",
                    argv[0]);
    exit(252);
  }

  dir_state.drive = 'C';
  dir_state.current_dir[0][0] = '\0';
  dir_state.current_dir[1][0] = '\0';
  dir_state.current_dir[2][0] = '\0';
  dir_state.current_dir[3][0] = '\0';
  dir_state.dos_prog_abs = NULL;  /* For security, use dos_prog_abs mapping only for read-only opens below. */
  dir_state.linux_mount_dir[0] = NULL;
  dir_state.linux_mount_dir[1] = NULL;
  dir_state.linux_mount_dir[2] = "";  /* By default: --mount=C:. */
  dir_state.linux_mount_dir[3] = NULL;

  envp = envp0 = ++argv;
  tty_in_fd = -1;
  is_tty_in_error = 0;
  while (argv[0]) {
    char *arg = *argv++;
    if (arg[0] != '-' || arg[1] == '\0') {
      --argv; break;
    } else if (arg[1] == '-' && arg[2] == '\0') {
      break;
    } else if (0 == strcmp(arg, "--env")) {
      if (!argv[0]) { missing_argument:
        fprintf(stderr, "fatal: missing argument for flag: %s\n", arg);
        exit(1);
      }
      *envp++ = *argv++;  /* Reuse the argv array. */
    } else if (0 == strncmp(arg, "--env=", 6)) {  /* Can be specified multiple times. */
      *envp++ = arg + 6;  /* Reuse the argv array. */
    } else if (0 == strcmp(arg, "--prog")) {
      if (!argv[0]) goto missing_argument;
      arg = *argv++;
     do_prog:
      dos_prog_abs = arg;  /* !! autopopulate it based on prog_filename and dir_state.linux_mount_dir[...]. */
    } else if (0 == strncmp(arg, "--prog=", 7)) {
      arg += 7;
      goto do_prog;
    } else if (0 == strcmp(arg, "--mount")) {  /* Can be specified multiple times. */
      if (!argv[0]) goto missing_argument;
      arg = *argv++;
     do_mount:  /* Default: --mount C:. */
      if ((arg[0] & ~32) - 'A' + 0U > 'D' - 'A' + 0U || arg[1] != ':') {
        fprintf(stderr, "fatal: mount argument must start with <drive>:, <drive> must be A, B, C or D: %s\n", arg);
        exit(1);
      } else {
        const char drive_idx = (arg[0] & ~32) - 'A';
        arg += 2;
        if (DEBUG) fprintf(stderr, "debug: mount %c: %s\n", drive_idx + 'A', arg);
        while (arg[0] == '.' && arg[1] == '/') {
          for (arg += 2; arg[0] == '/'; ++arg) {}
        }
        if (arg[0] == '.' && arg[1] == '\0') {
          ++arg;
        } else if (arg[0] != '\0') {
          char *p = arg + strlen(arg);
          if (arg[1] != '\0' && p[-1] == '.' && p[-2] == '/') *--p = '\0';  /* Remove trailing . if it ends with /. */
          if (p[-1] != '/') {
            fprintf(stderr, "fatal: mount directory target must end with /: %s\n", arg);
            exit(1);
          }
        }
        dir_state.linux_mount_dir[(unsigned)drive_idx] = arg;  /* argv retains ownership of arg. */
      }
    } else if (0 == strncmp(arg, "--mount=", 8)) {
      arg += 8;
      goto do_mount;
    } else if (0 == strcmp(arg, "--drive")) {  /* Can be specified multiple times. */
      if (!argv[0]) goto missing_argument;
      arg = *argv++;
     do_drive:  /* Default: --drive C: */
      if ((arg[0] & ~32) - 'A' + 0U > 'D' - 'A' + 0U || !(arg[1] == '\0' || (arg[1] == ':' && arg[2] == '\0'))) {
        fprintf(stderr, "fatal: drive argument must be <drive>:, <drive> must be A, B, C or D: %s\n", arg);
        exit(1);
      }
      dir_state.drive = arg[0] & ~32;
    } else if (0 == strncmp(arg, "--drive=", 8)) {
      arg += 8;
      goto do_drive;
    } else if (0 == strcmp(arg, "--tty-in")) {
      int char_count;
      if (!argv[0]) goto missing_argument;
      arg = *argv++;
     do_tty_in:
      if (sscanf(arg, "%d%n", &tty_in_fd, &char_count) < 1 || char_count + 0U != strlen(arg) || tty_in_fd < -2) {
        /* -1: use /dev/tty; -2: use 0 (stdin), but don't try to disable buffering. */
        fprintf(stderr, "fatal: tty-in argument must be nonnegative integer or -1 or -2: %s\n", arg);
        exit(1);
      }
      /* Now we've set tty_in_fd. */
    } else if (0 == strncmp(arg, "--tty-in=", 8)) {
      arg += 8;
      goto do_tty_in;
    } else {
      fprintf(stderr, "fatal: unknown command-line flag: %s\n", arg);
      exit(1);
    }
  }
  /* Now: argv contains remaining (non-flag) arguments. */
  if (!argv[0]) {
    fprintf(stderr, "fatal: missing <dos-com-or-exe-file> program filename\n");
    exit(1);
  }
  if (!dir_state.linux_mount_dir[dir_state.drive - 'A']) {
    /*dir_state.drive = 'C';*/
    fprintf(stderr, "fatal: no mount point for default drive (specify --mount=...): %c:\n", dir_state.drive);
    exit(1);
  }
#if 0  /* Tests for replacing the output with "" */
  fprintf(stderr, "!!! (%s)\n", get_linux_filename("C:\\foo\\.\\.\\\\bar\\."));
  fprintf(stderr, "!!! (%s)\n", get_linux_filename(".\\.\\."));
  fprintf(stderr, "!!! (%s)\n", get_linux_filename(".\\aaa\\..\\..\\.."));  /* "" */
  fprintf(stderr, "!!! (%s)\n", get_linux_filename(".\\aaa\\..\\.."));  /* "" */
  fprintf(stderr, "!!! (%s)\n", get_linux_filename(".\\aaa\\.."));
  fprintf(stderr, "!!! (%s)\n", get_linux_filename("C:\\foo\\.\\\\\\.\\bar\\.\\..\\.\\bazzzz\\.."));
#endif
  prog_filename = *argv++;  /* This is a Linux filename. */
  /* Remaining arguments in argv will be passed to the DOS program in PSP:0x80. */

  prog_filename = find_program(prog_filename, &dir_state, getenv_prefix("PATH=", (char const**)envp0, (char const**)envp));
  if (dos_prog_abs == NULL) {
    /* TODO(pts): Use pathnames in the DOS %PATH% instead to convert prog_filename back to DOS. */
    dos_prog_abs = get_dos_abs_filename_r(prog_filename, &dir_state, dosfnbuf);
    if (DEBUG) fprintf(stderr, "debug: dos_prog_abs=%s\n", dos_prog_abs);
    if (dos_prog_abs[0] == '\0') dos_prog_abs = "C:\\KVIKPROG.COM";  /* Not the same as in default_program_mcb. */
  }
  img_fd = open(prog_filename, O_RDONLY);
  if (img_fd < 0) {
    fprintf(stderr, "fatal: can not open DOS executable program: %s: %s\n", prog_filename, strerror(errno));
    exit(252);
  }
  header_size = detect_dos_executable_program(img_fd, prog_filename, header);

  if ((kvm_fds.kvm_fd = open("/dev/kvm", O_RDWR)) < 0) {
    perror("fatal: failed to open /dev/kvm");
    exit(252);
  }

  if ((api_version = ioctl(kvm_fds.kvm_fd, KVM_GET_API_VERSION, 0)) < 0) {
    perror("fatal: failed to create KVM vm");
    exit(252);
  }
  if (api_version != KVM_API_VERSION) {
    fprintf(stderr, "fatal: KVM API version mismatch: kernel=%d user=%d\n",
            api_version, KVM_API_VERSION);
  }

  if ((kvm_fds.vm_fd = ioctl(kvm_fds.kvm_fd, KVM_CREATE_VM, 0)) < 0) {
    perror("fatal: failed to create KVM vm");
    exit(252);
  }

  if ((mem = mmap(NULL, DOS_MEM_LIMIT, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0)) ==
      NULL) {
    perror("fatal: mmap");
    exit(252);
  }

  memset(&region, 0, sizeof(region));
  region.slot = 0;
  region.guest_phys_addr = GUEST_MEM_MODULE_START;  /* Must be a multiple of the Linux page size (0x1000), otherwise KVM_SET_USER_MEMORY_REGION returns EINVAL. */
  region.memory_size = DOS_MEM_LIMIT - GUEST_MEM_MODULE_START;
  region.userspace_addr = (uintptr_t)mem + GUEST_MEM_MODULE_START;
  /*region.flags = KVM_MEM_READONLY;*/  /* Not needed, read-write is default. */
  if (ioctl(kvm_fds.vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
    perror("fatal: ioctl KVM_SET_USER_MEMORY_REGION");
    exit(252);
  }
  if (GUEST_MEM_MODULE_START != 0) {
    memset(&region, 0, sizeof(region));
    region.slot = 1;
    region.guest_phys_addr = 0;
    region.memory_size = 0x1000;  /* Magic interrupt table: 0x500 bytes, rounded up to page boundary. */
    region.userspace_addr = (uintptr_t)mem;
    region.flags = KVM_MEM_READONLY;
    if (ioctl(kvm_fds.vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
      perror("fatal: ioctl KVM_SET_USER_MEMORY_REGION");
      exit(252);
    }
  }
  /* Any read/write outside the regions above will trigger a KVM_EXIT_MMIO. */
  /* Fill magic interrupt table. */
  { unsigned u;
    for (u = 0; u < 0x100; ++u) { ((unsigned*)mem)[u] = MAGIC_INT_VALUE(u); }
    memset((char*)mem + (INT_HLT_PARA << 4), 0xf4, 0x100);  /* 256 hlt instructions, one for each int. TODO(pts): Is hlt+iret faster? */
  }
  /* !! Initialize more BIOS data area until 0x534, move magic interrupt table later.
   * https://stanislavs.org/helppc/bios_data_area.html
   */
  *(unsigned short*)((char*)mem + 0x410) = 0x22;  /* BIOS equipment flags. https://stanislavs.org/helppc/int_11.html */
  ((char*)mem)[(INT_HLT_PARA << 4) - 1] = (char)0xcb;  /* `retf' opcode used by country case map.. */

  if ((kvm_fds.vcpu_fd = ioctl(kvm_fds.vm_fd, KVM_CREATE_VCPU, 0)) < 0) {
    perror("fatal: can not create KVM vcpu");
    exit(252);
  }
  kvm_run_mmap_size = ioctl(kvm_fds.kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
  if (kvm_run_mmap_size < 0) {
    perror("fatal: ioctl KVM_GET_VCPU_MMAP_SIZE");
    exit(252);
  }
  run = (struct kvm_run *)mmap(
      NULL, kvm_run_mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, kvm_fds.vcpu_fd, 0);
  if (run == NULL) {
    perror("fatal: mmap kvm_run: %d\n");
    exit(252);
  }
  if (ioctl(kvm_fds.vcpu_fd, KVM_GET_REGS, &regs) < 0) {  /* We don't use the result; but we just check here that ioctl KVM_GET_REGS works. */
    perror("fatal: KVM_GET_REGS");
    exit(252);
  }
  if (ioctl(kvm_fds.vcpu_fd, KVM_GET_SREGS, &sregs) < 0) {
    perror("fatal: KVM_GET_SREGS");
    exit(252);
  }
  memset(&regs, '\0', sizeof(regs));
  /*memcpy(initial_sregs, &sregs, sizeof(sregs));*/  /* Not completely 0, but sregs.Xs.selector is 0. */
  sregs.fs.selector = sregs.gs.selector = ENV_PARA;  /* Random value after magic interrupt table. */

  memcpy((char*)mem + (PROGRAM_MCB_PARA << 4), default_program_mcb, 16);
  { char *psp = load_dos_executable_program(img_fd, prog_filename, mem, header, header_size, &regs, &sregs, &MCB_SIZE_PARA((char*)mem + (PROGRAM_MCB_PARA << 4)));
    copy_args_to_dos_args(psp + 0x80, argv);
  }
  close(img_fd);

  /* http://www.techhelpmanual.com/346-dos_environment.html */
  { char *env = (char*)mem + (ENV_PARA << 4), *env0 = env;
    char * const env_end = (char*)mem + ENV_LIMIT;
#if 0
    env = add_env(env, env_end, "PATH=D:\\foo;C:\\bar", 1);
    env = add_env(env, env_end, "heLLo=World!", 1);
#endif
    while (envp0 != envp) {
      /* No attempt is made to deduplicate environment variables by name.
       * The user should supply unique names.
       */
      env = add_env(env, env_end, *envp0++, 1);
    }
    if (env == env0) env = add_env(env, env_end, "$=", 1);  /* Some programs such as pbc.exe would fail with an empty environment, so we create a fake variable. */
    env = add_env(env, env_end, "", 0);  /* Empty var marks end of env. */
    env = add_env(env, env_end, "\1", 0);  /* Number of subsequent variables (1). */
    env = add_env(env, env_end, dos_prog_abs, 0);  /* Full program pathname. */
  }

/* We have to set both selector and base, otherwise it won't work. A `mov
 * ds, ax' instruction in the 16-bit KVM guest will set both.
 */
#define FIX_SREG(name) do { sregs.name.base = sregs.name.selector << 4; } while(0)
  FIX_SREG(cs);
  FIX_SREG(ds);
  FIX_SREG(es);
  FIX_SREG(ss);
  FIX_SREG(fs);
  FIX_SREG(gs);

  /* EFLAGS https://en.wikipedia.org/wiki/FLAGS_register */
  *(unsigned short*)&regs.rflags = 1 << 1;  /* Reserved bit. */
  /**(unsigned short*)&regs.rflags |= 1 << 9;*/  /* IF=1, enable interrupts. */

  had_get_ints = 0;  /* 1 << 0: int 0x00; 1 << 1: int 0x18. */
  tick_count = 0;
  sphinx_cmm_flags = 0;
  ctrl_break_checking = 0;
  dir_state.linux_prog = prog_filename;
  dta_seg_ofs = 0x80 | PSP_PARA << 16;
  ongoing_set_int = 0;  /* No set_int operation ongoing. */
  last_dos_error_code = 0;

  if (DEBUG) dump_regs("debug", &regs, &sregs);

  /* !! Security: close all filehandles except for 0, 1, 2 and kvm_fds, so that read and write from DOS won't be able to touch them. */

 set_sregs_regs_and_continue:
  if (ioctl(kvm_fds.vcpu_fd, KVM_SET_SREGS, &sregs) < 0) {
    perror("fatal: KVM_SET_SREGS");
    exit(252);
  }
  if (ioctl(kvm_fds.vcpu_fd, KVM_SET_REGS, &regs) < 0) {
    perror("fatal: KVM_SET_REGS\n");
    exit(252);
  }

  /* !! Trap it if it tries to enter protected mode (cr0 |= 1). Is this possible? */
  for (;;) {
    int ret = ioctl(kvm_fds.vcpu_fd, KVM_RUN, 0);
    if (ret < 0) {
      fprintf(stderr, "KVM_RUN failed");
      exit(252);
    }
    if (ioctl(kvm_fds.vcpu_fd, KVM_GET_REGS, &regs) < 0) {
      perror("fatal: KVM_GET_REGS");
      exit(252);
    }
    if (ioctl(kvm_fds.vcpu_fd, KVM_GET_SREGS, &sregs) < 0) {
      perror("fatal: KVM_GET_REGS");
      exit(252);
    }
    if (DEBUG) dump_regs("debug", &regs, &sregs);

    switch (run->exit_reason) {
     case KVM_EXIT_IO:
      if (DEBUG) fprintf(stderr, "debug: IO port: port=0x%02x data=%04x size=%d direction=%d\n", run->io.port, *(int *)((char *)(run) + run->io.data_offset), run->io.size, run->io.direction);
      sleep(1);
      break;  /* Continue as if the in/out hasn't happened. */
     case KVM_EXIT_SHUTDOWN:  /* How do we trigger it? */
      fprintf(stderr, "fatal: shutdown\n");
      exit(252);
     case KVM_EXIT_HLT:
      if ((unsigned)sregs.cs.selector == INT_HLT_PARA && (unsigned)((unsigned)regs.rip - 1) < 0x100) {  /* hlt caused by int through our magic interrupt table. */
        const unsigned char int_num = ((unsigned)regs.rip - 1) & 0xff;
        const unsigned short *csip_ptr = (const unsigned short*)((char*)mem + ((unsigned)sregs.ss.selector << 4) + (*(unsigned short*)&regs.rsp));  /* !! What if rsp wraps around 64 KiB boundary? Test it. Also calculate int_cs again. */
        const unsigned short int_ip = csip_ptr[0], int_cs = csip_ptr[1];  /* Return address. */  /* !! Security: check bounds, also check that rsp <= 0xfffe. */
        const unsigned char ah = ((unsigned)regs.rax >> 8) & 0xff;
        if (DEBUG) fprintf(stderr, "debug: int 0x%02x ah:%02x cs:%04x ip:%04x\n", int_num, ah, int_cs, int_ip);
        fflush(stdout);
        (void)ah;
        /* Documentation about DOS and BIOS int calls: https://stanislavs.org/helppc/idx_interrupt.html */
        if (int_num == 0x29) {
          const char c = regs.rax;
          (void)!write(1, &c, 1);
        } else if (int_num == 0x20) {
          exit(0);  /* EXIT_SUCCESS. */
        } else if (int_num == 0x21) {  /* DOS file and memory sevices. */
          /* !! Should we set CF=0 by default? What does MS-DOS do? */
          if (ah == 0x4c) {
            exit((unsigned)regs.rax & 0xff);
          } else if (ah == 0x06 && (unsigned char)regs.rdx != 0xff) {  /* Direct console I/O, output. */
            const char c = (unsigned char)regs.rdx;
            (void)!write(1, &c, 1);
          } else if (ah == 0x02) {  /* Display output. */
            const char c = (unsigned char)regs.rdx;
            (void)!write(1, &c, 1);
          } else if (ah == 0x04) {  /* Output to STDAUX. */
            const char c = (unsigned char)regs.rdx;
            (void)!write(2, &c, 1);  /* Emulate STDAUX with stderr. */
          } else if (ah == 0x05) {  /* Output to STDPRN. */
            const char c = (unsigned char)regs.rdx;
            (void)!write(1, &c, 1);  /* Emulate STDPRN with stdout. */
          } else if (ah == 0x30) {  /* Get DOS version number. */
            const unsigned char al = (unsigned char)regs.rax;
            *(unsigned short*)&regs.rax = 5 | 0 << 8;  /* 5.0. */
            *(unsigned short*)&regs.rbx = al == 1 ? 0x1000 :  /* DOS in HMA. */
                0xff00;  /* MS-DOS with high 8 bits of OEM serial number in BL. */
            *(unsigned short*)&regs.rcx = 0;  /* Low 16 bits of OEM serial number in CX. */
          } else if (ah == 0x40) {  /* Write using handle. */
            const int fd = get_linux_handle(*(unsigned short*)&regs.rbx, &kvm_fds);
            if (fd < 0) {
             error_invalid_handle:
              *(unsigned short*)&regs.rax = 6;  /* Invalid handle. */
             error_on_21:
              { last_dos_error_code = *(unsigned short*)&regs.rax;
                if (last_dos_error_code > 0x12) *(unsigned short*)&regs.rax = 0x0d;  /* Invalid data. Use int 0x21 call with ah == 0x59 to get the real error. */
              }
              *(unsigned short*)&regs.rflags |= 1 << 0;  /* CF=1. */
            } else {
              const char *p = (char*)mem + ((unsigned)sregs.ds.selector << 4) + (*(unsigned short*)&regs.rdx);  /* !! Security: check bounds. */
              const int size = (int)*(unsigned short*)&regs.rcx;
              const int got = write(fd, p, size);
              if (got < 0) {
                *(unsigned short*)&regs.rax = 0x1d;  /* Write fault. */
                goto error_on_21;
              }
              *(unsigned short*)&regs.rflags &= ~(1 << 0);  /* CF=0. */
              *(unsigned short*)&regs.rax = got;
            }
          } else if (ah == 0x3f) {  /* Read using handle. */
            const int fd = get_linux_handle(*(unsigned short*)&regs.rbx, &kvm_fds);
            if (fd < 0) {
              goto error_invalid_handle;
            } else {
              char *p = (char*)mem + ((unsigned)sregs.ds.selector << 4) + (*(unsigned short*)&regs.rdx);  /* !! Security: check bounds. */
              const int size = (int)*(unsigned short*)&regs.rcx;
              const int got = read(fd, p, size);
              if (got < 0) {
                *(unsigned short*)&regs.rax = 0x1e;  /* Read fault. */
                goto error_on_21;
              }
              *(unsigned short*)&regs.rflags &= ~(1 << 0);  /* CF=0. */
              *(unsigned short*)&regs.rax = got;
            }
          } else if (ah == 0x09) {  /* Print string. */
            unsigned short dx = *(unsigned short*)&regs.rdx, dx0 = dx;
            const char *p = (char*)mem + ((unsigned)sregs.ds.selector << 4);
            for (;;) {
              if (p[dx] == '$') break;
              ++dx;
              if (dx == 0) {
                fprintf(stderr, "fatal: !! offset overflow in print\n");  /* TODO(pts): Implement it.  */
                exit(252);
              }
            }
            (void)!write(1, p + dx0, dx - dx0);
          } else if (ah == 0x2c) {  /* Get time. */
            time_t ts = time(0);
            struct tm *tm = localtime(&ts);
            const unsigned char hundredths = 0;  /* TODO(pts): Use gettimeofday(2) to get it. */
            *(unsigned short*)&regs.rcx = tm->tm_hour << 8 | tm->tm_min;
            *(unsigned short*)&regs.rdx = tm->tm_sec << 8 | hundredths;
          } else if (ah == 0x2a) {  /* Get date. */
            time_t ts = time(0);
            struct tm *tm = localtime(&ts);
            *(unsigned char*)&regs.rax = tm->tm_wday;
            *(unsigned short*)&regs.rcx = tm->tm_year + 1900;
            *(unsigned short*)&regs.rdx = (tm->tm_mon + 1) << 8 | tm->tm_mday;
          } else if (ah == 0x19) {  /* Get current drive. */
            *(unsigned char*)&regs.rax = dir_state.drive - 'A';
          } else if (ah == 0x47) {  /* Get current directory. */
            char *p, *p0, *pend;
            const char *s;
            /* Input: DL: 0 = current drive, 1: A: */
            if (*(unsigned char*)&regs.rdx != 0) { error_invalid_drive:
              *(unsigned short*)&regs.rax = 0xf;  /* Invalid drive specified. */
              goto error_on_21;
            }
            p0 = p = (char*)mem + ((unsigned)sregs.ds.selector << 4) + *(unsigned short*)&regs.rdx;
            pend = p + 63;
            s = dir_state.current_dir[dir_state.drive - 'A'];
            for (; *s != '\0' && p != pend; ++s, ++p) {
              *p = *s;
            }
            if (p != p0 && p[-1] == '/') --p;  /* Remove trailing '/'. */
            *p = '\0';  /* Silently truncate to 64 bytes. */
          } else if (ah == 0x3d || ah == 0x3c) {  /* Open to handle (open()). Create to handle (creat()). */
            const char * const p = (char*)mem + ((unsigned)sregs.ds.selector << 4) + (*(unsigned short*)&regs.rdx);  /* !! Security: check bounds. */
            const int flags = (ah == 0x3c) ? O_RDWR | O_CREAT | O_TRUNC :
                *(unsigned char*)&regs.rax & 3;  /* O_RDONLY == 0, O_WRONLY == 1, O_RDWR == 2 same in DOS and Linux. */
            /* For create, CX contains attributes (read-only, hidden, system, archive), we just ignore it.
             * https://stanislavs.org/helppc/file_attributes.html
             */
            int fd;
            const char *linux_filename;
            if (DEBUG) fprintf(stderr, "debug: dos_open(%s)\n", p);
            dir_state.dos_prog_abs = flags == O_RDONLY ? dos_prog_abs : NULL;  /* For loading the overlay from prog_filename, even if not mounted. */
            linux_filename = get_linux_filename(p);
            dir_state.dos_prog_abs = NULL;  /* For security. */
            if ((fd = open(linux_filename, flags, 0644)) < 0) { error_from_linux:
              *(unsigned short*)&regs.rax = get_dos_error_code(errno, 0x1f);  /* By default: General failure. */
              goto error_on_21;
            }
            if (fd < 5) fd = ensure_fd_is_at_least(fd, 5);  /* Skip the first 5 DOS standard handles. */
            if ((fd + 0U) >> 16) {
              *(unsigned short*)&regs.rax = 4;  /* Too many open files. */
              goto error_on_21;
            }
            *(unsigned short*)&regs.rflags &= ~(1 << 0);  /* CF=0. */
            *(unsigned short*)&regs.rax = fd;
          } else if (ah == 0x57) {  /* Get/set file date and time using handle. */
            const unsigned char al = (unsigned char)regs.rax;
            if (al < 2 ) {
              const int fd = get_linux_handle(*(unsigned short*)&regs.rbx, &kvm_fds);
              if (fd < 0) goto error_invalid_handle;
              if (al == 0) {  /* Get. */
                struct stat st;
                struct tm *tm;
                if (fstat(fd, &st) != 0) goto error_from_linux;
                tm = localtime(&st.st_mtime);
                *(unsigned short*)&regs.rcx = tm->tm_sec >> 1 | tm->tm_min << 5 | tm->tm_hour << 11;
                *(unsigned short*)&regs.rdx = tm->tm_mday | (tm->tm_mon + 1) << 5 | (tm->tm_year - 1980) << 9;
              } else if (al == 0) {  /* Set. */
                /* !! Implement this with utime(2). */
                fprintf(stderr, "fatal: unimplemented: set file date and time: fd=%d cx:%04x dx:%04x\n", fd, *(unsigned short*)&regs.rcx, *(unsigned short*)&regs.rdx);
                goto fatal;
              }
            } else { error_invalid_parameter:
              *(unsigned short*)&regs.rax = 0x57;  /* Invalid parameter. */
              goto error_on_21;
            }
          } else if (ah == 0x3e) {  /* Close using handle. */
            const int fd = get_linux_handle(*(unsigned short*)&regs.rbx, &kvm_fds);
            if (fd < 0) goto error_invalid_handle;  /* Not strictly needed, close(...) would check. */
            if (close(fd) != 0) goto error_from_linux;
            *(unsigned short*)&regs.rflags &= ~(1 << 0);  /* CF=0. */
          } else if (ah == 0x45) {  /* Duplicate handle (dup()). */
            const int fd = get_linux_handle(*(unsigned short*)&regs.rbx, &kvm_fds);
            int fd2;
            if (fd < 0) goto error_invalid_handle;
            fd2 = dup(fd);
            if (fd < 0) {
              *(unsigned short*)&regs.rax = get_dos_error_code(errno, 4);  /* By default: Too many open files. */
              goto error_on_21;
            }
            if (fd2 < 5) fd2 = ensure_fd_is_at_least(fd2, 5);  /* Skip the first 5 DOS standard handles. */
            if ((fd2 + 0U) >> 16) {
              *(unsigned short*)&regs.rax = 4;  /* Too many open files. */
              goto error_on_21;
            }
            *(unsigned short*)&regs.rflags &= ~(1 << 0);  /* CF=0. */
            *(unsigned short*)&regs.rax = fd2;
          } else if (ah == 0x41) {  /* Delete file. */
            const char * const p = (char*)mem + ((unsigned)sregs.ds.selector << 4) + (*(unsigned short*)&regs.rdx);  /* !! Security: check bounds. */
            int fd = unlink(get_linux_filename(p));
            if (fd < 0) goto error_from_linux;
            *(unsigned short*)&regs.rflags &= ~(1 << 0);  /* CF=0. */
          } else if (ah == 0x56) {  /* Rename file. */
            const char * const p_old = (char*)mem + ((unsigned)sregs.ds.selector << 4) + (*(unsigned short*)&regs.rdx);  /* !! Security: check bounds. */
            const char * const p_new = (char*)mem + ((unsigned)sregs.es.selector << 4) + (*(unsigned short*)&regs.rdi);  /* !! Security: check bounds. */
            int fd = rename(get_linux_filename(p_old), get_linux_filename_r(p_new, &dir_state, fnbuf2));
            if (fd < 0) goto error_from_linux;
            *(unsigned short*)&regs.rflags &= ~(1 << 0);  /* CF=0. */
          } else if (ah == 0x25) {  /* Set interrupt vector. */
            if (set_int((unsigned char)regs.rax, *(unsigned short*)&regs.rdx | sregs.ds.selector << 16, mem, had_get_ints)) goto fatal;
          } else if (ah == 0x35) {  /* Get interrupt vector. */
            /* !! Implement this. */
            const unsigned char get_int_num = (unsigned char)regs.rax;
            if (get_int_num == 0) had_get_ints |= 1;  /* Turbo Pascal 7.0 programs start with this. */
            if (get_int_num == 0x18) had_get_ints |= 2;  /* TASM 3.2, for memory allocation. */
            if (get_int_num == 0x06) had_get_ints |= 4;  /* TLINK 4.0. */
            if (had_get_ints & 1 ||
                get_int_num - 0x22 + 0U <= 0x24 - 0x22 + 0U ||  /* Microsoft BASIC Professional Development System 7.10 linker pblink.exe gets interrupt vector 0x24. */
                get_int_num == 0x18 ||  /* TASM 3.2, used for memory allocation. */
                get_int_num == 0x06) {  /* TLINK 4.0. */
              const unsigned short *pp = (const unsigned short*)((char*)mem + (get_int_num << 2));
              if (DEBUG) fprintf(stderr, "debug: get interrupt vector int:%02x is cs:%04x ip:%04x\n", get_int_num, pp[1], pp[0]);
              (*(unsigned short*)&regs.rbx) = pp[0];
              sregs.es.selector = pp[1];
            } else {
              fprintf(stderr, "fatal: unsupported get interrupt vector int:%02x\n", get_int_num);
              goto fatal;
            }
          } else if (ah == 0x0b) {  /* Check input status. */
            *(unsigned char*)&regs.rax = 0;  /* No input ready. 0xff would be input. */
            /* If we detect Ctrl-<Break>, we should run `int 0x23'. */
          } else if (ah == 0x42) {  /* Seek using handle. */
            const int fd = get_linux_handle(*(unsigned short*)&regs.rbx, &kvm_fds);
            if (fd < 0) goto error_invalid_handle;
            {
              const unsigned whence = *(unsigned char*)&regs.rax;  /* SEEK_SET == 0, SEEK_CUR == 1, SEEK_END == 2, same in DOS and Linux. */
              const int offset = *(unsigned short*)&regs.rcx << 16 | *(unsigned short*)&regs.rdx;  /* It's important that this is signed, because we may want to pass -1 to lseek() even on 64-bit systems. */
              int got;
              if (whence > 2) goto error_invalid_parameter;
              got = lseek(fd, offset, whence);
              if (got < 0) {
                *(unsigned short*)&regs.rax = 0x19;  /* Seek error. (Is this the relevant code?) */
                goto error_on_21;
              }
              *(unsigned short*)&regs.rflags &= ~(1 << 0);  /* CF=0. */
              *(unsigned short*)&regs.rdx = (unsigned)got >> 16;
              *(unsigned short*)&regs.rax = got;
            }
          } else if (ah == 0x44) {  /* I/O control (ioctl). */
            const unsigned char al = (unsigned char)regs.rax;
            if (al == 1 && (*(unsigned short*)&regs.rdx >> 8)) goto error_invalid_parameter;
            if (al < 2) {  /* Get device information (1), set device information (2). */
              const int fd = get_linux_handle(*(unsigned short*)&regs.rbx, &kvm_fds);
              struct stat st;
              if (fd < 0) goto error_invalid_handle;
              if (fstat(fd, &st) != 0) goto error_from_linux;
              if (al == 0) {  /* Get. */
                *(unsigned short*)&regs.rdx = 1 << 5  /* binary */ | (S_ISCHR(st.st_mode) ? 1 : 0) << 7  /* character device */;
                *(unsigned short*)&regs.rflags &= ~(1 << 0);  /* CF=0. */
              } else {
                if (!S_ISCHR(st.st_mode)) goto error_invalid_drive;  /* We want to indicate that it's not a character device. */
                /* TLIB 3.01 sets (dx & 0x80) to zero, to disable binary mode (and enable translation). */
                /* We just ignore the setting. */
              }
            } else if (al == 8) {  /* Get whether drive is removable. */
              unsigned char bl = (unsigned char)regs.rax;
              if (bl == 0) bl = dir_state.drive - 'A' + 1;
              if (bl > 4 || !dir_state.linux_mount_dir[(int)bl - 1]) goto error_invalid_drive;
              *(unsigned char*)&regs.rax = bl > 2;  /* A: (1) and B: (2) are removable (0), C: (3) etc. aren't (1). */
            } else {
              fprintf(stderr, "fatal: unsupported DOS ioctl call: 0x%02x\n", al);
              goto fatal;
            }
            *(unsigned short*)&regs.rflags &= ~(1 << 0);  /* CF=0. */
          } else if (ah == 0x4a) {  /* Modify allocated memory block (inplace_realloc()). */
            const unsigned new_size_para = *(unsigned short*)&regs.rbx;
            const unsigned short block_para = sregs.es.selector;
            unsigned available_para, old_size_para;
            char * const mcb = (char*)mem + (block_para << 4) - 16;
            char *next_mcb;
            if (is_mcb_bad(mem, block_para) || MCB_PID(mcb) == 0) {
              if (DEBUG) fprintf(stderr, "debug: inplace_realloc bad block_para=0x%04x new_size_para=0x%04x\n", block_para, new_size_para);
             error_bad_mcb:
              /*fprintf(stderr, "fatal: bad MCB\n"); goto fatal;*/
              *(unsigned short*)&regs.rax = 7;  /* Memory control blocks destroyed. */
              goto error_on_21;
            }
            if (DEBUG) fprintf(stderr, "debug: inplace_realloc block_para=0x%04x new_size_para=0x%04x\n", block_para, new_size_para);
            DEBUG_CHECK_ALL_MCBS(mem);  /* No need, the is_mcb_bad calls below do all the checks. */
            old_size_para = MCB_SIZE_PARA(mcb);
            if (old_size_para != new_size_para) {
              next_mcb = MCB_TYPE(mcb) != 'Z' ? (mcb + 16 + (old_size_para << 4)) : NULL;
              if (next_mcb && is_mcb_bad(mem, block_para + 1 + old_size_para)) goto error_bad_mcb;
              available_para = !next_mcb ? (unsigned)(DOS_ALLOC_PARA_LIMIT - block_para) : MCB_PID(next_mcb) != 0 ? old_size_para : old_size_para + 1 + MCB_SIZE_PARA(next_mcb);
              if (new_size_para > available_para) {
                *(unsigned short*)&regs.rbx = available_para;
               error_insufficient_memory:
                *(unsigned short*)&regs.rax = 8;  /* Insufficient memory. */
                goto error_on_21;
              }
              if (DEBUG) fprintf(stderr, "debug: inplace_realloc block_para=0x%04x new_size_para=0x%04x available_para=0x%04x\n", block_para, new_size_para, available_para);
              if (!next_mcb) {
                MCB_SIZE_PARA(mcb) = new_size_para;
              } else if (MCB_PID(next_mcb) != 0) {  /* Insert a free block after the current block. */
                char * const free_mcb = mcb + 16 + (new_size_para << 4);
                memcpy(free_mcb, default_program_mcb, 16);
                MCB_TYPE(free_mcb) = 'M';
                MCB_PID(free_mcb) = 0;  /* Mark as free. */
                MCB_SIZE_PARA(free_mcb) = MCB_PSIZE_PARA(next_mcb) = old_size_para - new_size_para - 1;
                MCB_PSIZE_PARA(free_mcb) = MCB_SIZE_PARA(mcb) = new_size_para;
              } else if (new_size_para == available_para) {  /* Exact size match. Merge the following free block into the current block. */
                const unsigned next_mcb_size_para = MCB_SIZE_PARA(next_mcb);
                memset(next_mcb, 0, 16);
                next_mcb = next_mcb + 16 + (next_mcb_size_para << 4);
                MCB_PSIZE_PARA(next_mcb) = MCB_SIZE_PARA(mcb) = available_para;
              } else {  /* Make the following free block smaller or larger. */
                char * const next_mcb2 = mcb + 16 + (new_size_para << 4);
                memcpy(next_mcb2, default_program_mcb, 16);
                MCB_TYPE(next_mcb2) = 'M';
                MCB_PID(next_mcb2) = 0;  /* Mark as free. */
                MCB_PSIZE_PARA(next_mcb + 16 + (MCB_SIZE_PARA(next_mcb) << 4)) =
                    MCB_SIZE_PARA(next_mcb2) = MCB_SIZE_PARA(next_mcb) + old_size_para - new_size_para;
                MCB_PSIZE_PARA(next_mcb2) = MCB_SIZE_PARA(mcb) = new_size_para;
                memset(next_mcb, 0, 16);
              }
              if (is_mcb_bad(mem, block_para)) {
                fprintf(stderr, "fatal: bad MCB after inplace_realloc()\n");
                exit(252);
              }
              if (next_mcb && is_mcb_bad(mem, available_para = block_para + 1 + MCB_SIZE_PARA((char*)mem + (block_para << 4) - 16))) {
                fprintf(stderr, "fatal: bad next/free MCB after inplace_realloc(): %d\n", is_mcb_bad(mem, available_para));
                exit(252);
              }
            }
            *(unsigned short*)&regs.rflags &= ~(1 << 0);  /* CF=0. */
          } else if (ah == 0x48) {  /* Allocate memory (malloc()). */
            const unsigned alloc_size_para = *(unsigned short*)&regs.rbx;
            if (DEBUG) fprintf(stderr, "debug: malloc(0x%04x)\n", alloc_size_para);
            /*DEBUG_CHECK_ALL_MCBS(mem);*/  /* No need, the is_mcb_bad calls below do all the checks. */
            {
              unsigned best_fit_waste_para = (unsigned)-1;
              unsigned best_fit_block_para = 0;
              unsigned best_fit_prev_block_para = 0;  /* Preceding block. */
              unsigned largest_available_para = 0;
              { /* Try to find best match. */
                unsigned block_para = PSP_PARA, prev_block_para = 0;
                for (;;) {
                  const char * const mcb = (const char*)mem + (block_para << 4) - 16;
                  unsigned size_para;
                  if (is_mcb_bad(mem, block_para)) goto error_bad_mcb;
                  if (DEBUG) fprintf(stderr, "debug: malloc find block=0x%04x...0x%04x size=0x%04x psize=0x%04x mcb_type=%c is_used=%d\n", block_para, block_para + MCB_SIZE_PARA(mcb), MCB_SIZE_PARA(mcb), MCB_PSIZE_PARA(mcb), MCB_TYPE(mcb), MCB_PID(mcb) != 0);
                  size_para = MCB_SIZE_PARA(mcb);
                  if (MCB_TYPE(mcb) == 'Z') {  /* Last block (must be non-free), try afterwards. */
                    prev_block_para = block_para;
                    block_para += 1 + size_para;
                    if (block_para == DOS_ALLOC_PARA_LIMIT + 1) break;  /* There is nothing after the last block. */
                    size_para = DOS_ALLOC_PARA_LIMIT - block_para;
                    goto try_fit;
                  } else if (MCB_PID(mcb) == 0) {  /* A free block. */
                   try_fit:
                    if (size_para >= alloc_size_para) {
                      const unsigned waste_para = size_para - alloc_size_para;
                      if (DEBUG) fprintf(stderr, "debug: malloc fit prev_block=0x%04x block=0x%04x waste=0x%04x\n", prev_block_para, block_para, waste_para);
                      if (waste_para < best_fit_waste_para) {
                        best_fit_waste_para = waste_para;
                        best_fit_block_para = block_para;
                        best_fit_prev_block_para = prev_block_para;
                      }
                    } else if (size_para > largest_available_para) {
                      largest_available_para = size_para;
                    }
                    if (MCB_PID(mcb) != 0) break;  /* Last block (non-free). */
                  }
                  prev_block_para = block_para;
                  block_para += 1 + size_para;
                }
              }
              if (best_fit_waste_para == (unsigned)-1) {
                *(unsigned short*)&regs.rbx = largest_available_para - (largest_available_para > 0);
                goto error_insufficient_memory;
              } else {
                char * const prev_mcb = (char*)mem + (best_fit_prev_block_para << 4) - 16;
                char * const mcb = (char*)mem + (best_fit_block_para << 4) - 16;
                char * const free_mcb = (char*)mem + ((best_fit_block_para + alloc_size_para) << 4);
                char mcb_error;
                if (MCB_TYPE(prev_mcb) == 'Z') {  /* Append after last block. */
                  if (DEBUG) {
                    fprintf(stderr, "debug: malloc append prev_block=0x%04x block=0x%04x free=0x%04x\n",
                            best_fit_prev_block_para, best_fit_block_para, best_fit_block_para + alloc_size_para + 1);
                  }
                  memcpy(mcb, default_program_mcb, 16);
                  /*MCB_TYPE(mcb) = 'Z';*/  /* Already set. */
                  /*MCB_PID(mcb) = PROCESS_ID;*/  /* Already set. */
                  MCB_TYPE(prev_mcb) = 'M';
                  MCB_SIZE_PARA(mcb) = alloc_size_para;
                  MCB_PSIZE_PARA(mcb) = MCB_SIZE_PARA(prev_mcb);
                } else {  /* Change existing free block. */
                  char * const next_mcb = mcb + (MCB_SIZE_PARA(mcb) << 4) + 16;
                  MCB_PID(mcb) = PROCESS_ID;  /* Mark as in use. */
                  if (DEBUG) {
                    fprintf(stderr, "debug: malloc middle prev_block=0x%04x block=0x%04x next=0x%04x free=0x%04x is_exact_fit=%d\n",
                            best_fit_prev_block_para, best_fit_block_para, best_fit_block_para + MCB_SIZE_PARA(mcb) + 1, best_fit_block_para + alloc_size_para + 1,
                            best_fit_block_para + MCB_SIZE_PARA(mcb) + 1 == best_fit_block_para + alloc_size_para + 1);
                  }
                  if (free_mcb == next_mcb) {  /* Exact fit. */
                    if (DEBUG) fprintf(stderr, "debug: malloc exact fit\n");
                  } else {  /* Not an exact fit, append a free block. */
                    const unsigned size_para = MCB_SIZE_PARA(mcb);
                    memcpy(free_mcb, default_program_mcb, 16);
                    /*MCB_TYPE(mcb) = 'M';*/  /* Not needed, already set. */
                    MCB_PSIZE_PARA(free_mcb) = MCB_SIZE_PARA(mcb) = alloc_size_para;
                    /* MCB_PSIZE_PARA(mcb) is already correct. */
                    MCB_TYPE(free_mcb) = 'M';
                    MCB_PID(free_mcb) = 0;
                    MCB_PSIZE_PARA(next_mcb) = MCB_SIZE_PARA(free_mcb) = size_para - alloc_size_para - 1;
                    mcb_error = is_mcb_bad(mem, best_fit_block_para + alloc_size_para + 1);
                    if (mcb_error) {  /* free_mcb. */
                      fprintf(stderr, "fatal: bad free MCB after malloc(): %d\n", mcb_error);
                      exit(252);
                    }
                  }
                }
                mcb_error = is_mcb_bad(mem, best_fit_block_para);
                if (mcb_error) {
                  fprintf(stderr, "fatal: bad MCB after malloc(): %d\n", mcb_error);
                  exit(252);
                }
              }
              if (DEBUG) fprintf(stderr, "debug: malloc(0x%04x) == 0x%04x\n", alloc_size_para, best_fit_block_para);
              *(unsigned short*)&regs.rax = best_fit_block_para;  /* Insufficient memory. */
              *(unsigned short*)&regs.rflags &= ~(1 << 0);  /* CF=0. */
            }
          } else if (ah == 0x49) {  /* Free allocated memory (free()). */
            const unsigned block_para = *(unsigned short*)&sregs.es.selector;
            char *mcb = (char*)mem + (block_para << 4) - 16;
            if (DEBUG) fprintf(stderr, "debug: free(0x%04x)\n", block_para);
            DEBUG_CHECK_ALL_MCBS(mem);
            if (block_para == PSP_PARA) {  /* It's not allowed to free the program image. */
              goto error_invalid_parameter;
            } else if (block_para > PSP_PARA && block_para < DOS_ALLOC_PARA_LIMIT && mcb[0] == freed_mcb[0] && memcmp(mcb, freed_mcb, 16) == 0) {  /* Already free, has been freed. Succeed as noop just like DOSBox 0.74 and MS-DOS 6.22 do. */
              if (DEBUG) fprintf(stderr, "debug: free: already freed\n");
            } else if (is_mcb_bad(mem, block_para)) {
              if (DEBUG) fprintf(stderr, "debug: free: bad MCB para=0x%04x: %d\n", block_para, is_mcb_bad(mem, block_para));
              goto error_bad_mcb;
            } else if (MCB_PID(mcb) == 0) {  /* Already free. Succeed as noop just like DOSBox 0.74 and MS-DOS 6.22 do. */
              if (DEBUG) fprintf(stderr, "debug: free: already free\n");
            } else if (is_mcb_bad(mem, block_para - MCB_PSIZE_PARA(mcb) - 1)) {
              if (DEBUG) fprintf(stderr, "debug: free: bad prev MCB para=0x%04x: %d\n", block_para - MCB_PSIZE_PARA(mcb) - 1, is_mcb_bad(mem, block_para - MCB_PSIZE_PARA(mcb) - 1));
              goto error_bad_mcb;
            } else if (MCB_TYPE(mcb) != 'Z' && is_mcb_bad(mem, block_para + MCB_SIZE_PARA(mcb) + 1)) {
              if (DEBUG) fprintf(stderr, "debug: free: bad next MCB para=0x%04x: %d\n", block_para + MCB_SIZE_PARA(mcb) + 1, is_mcb_bad(mem, block_para + MCB_SIZE_PARA(mcb) + 1));
              goto error_bad_mcb;
            } else {
              char *prev_mcb = mcb - 16 - (MCB_PSIZE_PARA(mcb) << 4);  /* Always exists since block_para != PSP_PARA. */
              char *next_mcb = mcb + 16 + (MCB_SIZE_PARA(mcb) << 4);
              if (MCB_TYPE(mcb) != 'Z' && MCB_PID(next_mcb) == 0) {  /* Merge it with the following free block. */
                char *next_mcb2 = next_mcb + 16 + (MCB_SIZE_PARA(next_mcb) << 4);
                const unsigned next_para2 = block_para + MCB_SIZE_PARA(mcb) + 1 + MCB_SIZE_PARA(next_mcb) + 1;
                const char next_type = MCB_TYPE(next_mcb);
                if (DEBUG) fprintf(stderr, "debug: free: merge with next free\n");
                if (next_type != 'Z' && is_mcb_bad(mem, next_para2)) {
                  if (DEBUG) fprintf(stderr, "debug: free: bad next2 MCB block_para=%04x next_para=0x%04x next_para2=0x%04x: %d\n", block_para, block_para + MCB_SIZE_PARA(mcb) + 1, next_para2, is_mcb_bad(mem, next_para2));
                  goto error_bad_mcb;
                }
                MCB_SIZE_PARA(mcb) += 1 + MCB_SIZE_PARA(next_mcb);
                memset(next_mcb, 0, 16);
                if (next_type != 'Z') MCB_PSIZE_PARA(next_mcb2) = MCB_SIZE_PARA(mcb);
                MCB_TYPE(mcb) = next_type;
              }
              MCB_PID(mcb) = 0;  /* Mark it as free. */
              if (MCB_PID(prev_mcb) == 0) {  /* Merge it with the preceding free block. */
                const char mcb_type = MCB_TYPE(mcb);
                if (DEBUG) fprintf(stderr, "debug: free: merge with prev free\n");
                MCB_SIZE_PARA(prev_mcb) += 1 + MCB_SIZE_PARA(mcb);
                memcpy(mcb, freed_mcb, 16);
                if (mcb_type != 'Z') MCB_PSIZE_PARA(next_mcb) = MCB_SIZE_PARA(prev_mcb);
                MCB_TYPE(prev_mcb) = mcb_type;
                mcb = prev_mcb;
              }
              if (MCB_TYPE(mcb) == 'Z') {  /* Delete it as last free MCB. */
                if (DEBUG) fprintf(stderr, "debug: free: delete last\n");
                prev_mcb = mcb - 16 - (MCB_PSIZE_PARA(mcb) << 4);
                memcpy(mcb, freed_mcb, 16);
                MCB_TYPE(prev_mcb) = 'Z';
              }
            }
            if (DEBUG) fprintf(stderr, "debug: free(0x%04x) OK\n", block_para);
            DEBUG_CHECK_ALL_MCBS(mem);
            *(unsigned short*)&regs.rflags &= ~(1 << 0);  /* CF=0. */
          } else if (ah == 0x43) {  /* Get/set file attributes. */
            const unsigned char al = (unsigned char)regs.rax;
            const char * const p = (char*)mem + ((unsigned)sregs.ds.selector << 4) + (*(unsigned short*)&regs.rdx);  /* !! Security: check bounds. */
            const char *fn;
            if (al > 1) goto error_invalid_parameter;
            fn = get_linux_filename(p);
            if (al == 0) {  /* Get. */
              struct stat st;
              if (stat(fn, &st) != 0) goto error_from_linux;
              *(unsigned short*)&regs.rflags &= ~(1 << 0);  /* CF=0. */
              *(unsigned short*)&regs.rax = (st.st_mode & 0200) ? 0 : 1;  /* Indicate DOS read-only flag if owner doesn't have write permissions on Linux. */
            } else {  /* Set. */
              fprintf(stderr, "fatal: unimplemented: set file attributes: attr=0x%04x filename=%s\n", *(unsigned short*)&regs.rcx, fn);
              goto fatal;
            }
          } else if (ah == 0x33) {  /* Get/set system values. */
            const unsigned char al = (unsigned char)regs.rax;
            const unsigned char dl = (unsigned char)regs.rdx;
            if (al == 0) {
              *(unsigned char*)&regs.rdx = ctrl_break_checking;  /* 0 or 1. */
            } else if (al == 1) {
              ctrl_break_checking = (dl > 0);
            } else if (al == 2) {
              const unsigned char old = ctrl_break_checking;
              ctrl_break_checking = (dl > 0);
              *(unsigned char*)&regs.rdx = old;
            } else if (al == 5) {
              *(unsigned char*)&regs.rdx = 'C' - 'A' + 1;  /* Boot drive. */
            } else if (al == 6) {
              *(unsigned short*)&regs.rbx = 0x500;  /* DOS 5.0. */
              *(unsigned short*)&regs.rdx = 0x100;  /* DL contains DOS revision number 0. */
            } else {
              fprintf(stderr, "fatal: unimplemented: get/set system values: al:%04x dl:%04x\n", al, dl);
              goto fatal;
            }
          } else if (ah == 0x0e) {  /* Select disk. */
            /* TODO(pts): Use the default drive specified here (dl + 'A') in get_linux_filename_r(...). */
            const unsigned char dl = (unsigned char)regs.rdx;
            if (dl < 4 && dir_state.linux_mount_dir[dl]) dir_state.drive = dl + 'A';
            *(unsigned char*)&regs.rax = 26;  /* 26 drives: 'A' .. 'Z'. */
          } else if (ah == 0x2f) {  /* Get disk transfer address (DTA). */
            sregs.es.selector = dta_seg_ofs >> 16;
            sregs.es.selector = PSP_PARA;
            *(unsigned short*)&regs.rbx = dta_seg_ofs;
          } else if (ah == 0x1a) {  /* Set disk transfer address (DTA). */
            dta_seg_ofs = *(unsigned short*)&regs.rdx | sregs.ds.selector << 16 ;
          } else if (ah == 0x63) {  /* Get lead byte table. Multibyte support in MS-DOS 2.25. */
            *(unsigned short*)&regs.rax = 1;  /* Invalid function number. */
            goto error_on_21;
          } else if (ah == 0x38) {  /* Get/set country dependent information. */
            const unsigned char al = (unsigned char)regs.rax;
            char * const p = (char*)mem + ((unsigned)sregs.ds.selector << 4) + (*(unsigned short*)&regs.rdx);  /* !! Security: check bounds. */
            if (al == 0x00) {  /* Get. */
              memcpy(p, &country_info, 0x18);
              *(unsigned short*)&regs.rax = *(unsigned short*)&regs.rbx = 1;
            } else {
              fprintf(stderr, "fatal: unsupported subcall for country: 0x%02x\n", al);
              goto fatal;
            }
            *(unsigned short*)&regs.rflags &= ~(1 << 0);  /* CF=0. */
          } else if (ah == 0x37) {  /* Get/set switch character (for command-line flags). */
            const unsigned char al = (unsigned char)regs.rax;
            if (al == 0x00) {  /* Get. */
              *(unsigned char*)&regs.rax = 0;  /* Success. */
              *(unsigned char*)&regs.rdx = '/';
            } else {
              fprintf(stderr, "fatal: unsupported subcall for switch character: 0x%02x\n", al);
              goto fatal;
            }
          } else if (ah == 0x4e) {  /* Find first matching file (findfirst). */
            const unsigned short attrs = *(unsigned short*)&regs.rcx;
            const char * const pattern = (char*)mem + ((unsigned)sregs.ds.selector << 4) + (*(unsigned short*)&regs.rdx);  /* !! Security: check bounds. */
            const char *fn, *fnb;
            const unsigned dta_linear = (dta_seg_ofs & 0xffff) + (dta_seg_ofs >> 16 << 4);
            if (!is_linear_byte_user_writable(dta_linear) || !is_linear_byte_user_writable(dta_linear + 0x2b - 1)) goto error_invalid_parameter;
            if (attrs & 8) {  /* Volume label requested. */
             no_more_files:
              *(unsigned short*)&regs.rax = 0x12;  /* No more files. */
              goto error_on_21;
            }
            if (strchr(pattern, '*') || strchr(pattern, '?')) {  /* TODO(pts): What happens if there are wildcards in earlier pathname components? */
              fprintf(stderr, "fatal: unsupported wildcards in findfirst pattern: %s\n", pattern);
              goto fatal;
            }
            if (!is_dos_filename_83(get_dos_basename(pattern))) goto no_more_files;
            fn = get_linux_filename(pattern);
            fnb = get_linux_basename(fn);
            if (strlen(fnb) > 12) {
              goto no_more_files;  /* is_dos_filename_83 ensures this, but let's double check for security of the strcpy(...) below. */
            } else {
              char *dta;
              struct stat st;
              struct tm *tm;
              if (stat(fn, &st) != 0) {
                if (errno == ENOENT) goto no_more_files;
                goto error_from_linux;
              }
              if (S_ISDIR(st.st_mode) && !(attrs & 0x10)) goto no_more_files;
              dta = (char*)mem + dta_linear;
              memset(dta, '\0', 0x16);
              tm = localtime(&st.st_mtime);
              *(unsigned*)dta = FINDFIRST_MAGIC;  /* Just a random value which findnext can identify. */
              *(unsigned short*)(dta + 0x16) = tm->tm_sec >> 1 | tm->tm_min << 5 | tm->tm_hour << 11;
              *(unsigned short*)(dta + 0x18) = tm->tm_mday | (tm->tm_mon + 1) << 5 | (tm->tm_year - 1980) << 9;
              *(unsigned*)(dta + 0x1a) = (sizeof(st.st_size) > 4 && st.st_size >> (32 * (sizeof(st.st_size) > 4))) ?
                  0xffffffffU : st.st_size;  /* Cap file size at 0xffffffff, no way to return more than 32 bits. */
              strcpy(dta + 0x1e, fnb);  /* Secure because of the strlen(fnb) check above. */
              /* We use 0x1e + 13 == 0x2b bytes in dta. */
              if (DEBUG) fprintf(stderr, "debug: found Linux file: %s\n", fnb);
            }
            *(unsigned short*)&regs.rflags &= ~(1 << 0);  /* CF=0. */
          } else if (ah == 0x4f) {  /* Find next matching file (findnext). */
            const unsigned dta_linear = (dta_seg_ofs & 0xffff) + (dta_seg_ofs >> 16 << 4);
            if (!is_linear_byte_user_writable(dta_linear) || !is_linear_byte_user_writable(dta_linear + 0x2b - 1)) goto error_invalid_parameter;
            { char * const dta = (char*)mem + dta_linear;
              if (*(unsigned*)dta != FINDFIRST_MAGIC) goto error_invalid_parameter;
              goto no_more_files;
            }
          } else if (ah == 0x37) {  /* Get/set switch character (for command-line flags). */
            const unsigned char al = (unsigned char)regs.rax;
            if (al == 0x00) {  /* Get. */
              *(unsigned char*)&regs.rax = 0;  /* Success. */
              *(unsigned char*)&regs.rdx = '/';
            } else {
              fprintf(stderr, "fatal: unsupported subcall for switch character: 0x%02x\n", al);
              goto fatal;
            }
          } else if (ah == 0x51 || ah == 0x62) {  /* Get process ID (PSP) (0x51). Get PSP (0x62). */
            *(unsigned short*)&regs.rbx = PSP_PARA;
          } else if (ah == 0x59) {  /* Get extended error information. */
            *(unsigned short*)&regs.rax = last_dos_error_code;
            if (last_dos_error_code == 0)  {  /* No error. */
              *(unsigned short*)&regs.rbx = 0xd << 8  /* error class: unknown */ | 6  /* ignore */;
              *(unsigned short*)&regs.rcx = *(unsigned char*)&regs.rcx | 1 << 8;  /* CH: Locus: unknown. */
            } else {
              *(unsigned short*)&regs.rbx = 6 << 8  /* error class: system failure */ | 4  /* abort with cleanup */;
              *(unsigned short*)&regs.rcx = *(unsigned char*)&regs.rcx | 2 << 8;  /* CH: Locus: block device. */
            }
          } else if (ah == 0x60) {  /* Get fully qualified filename. */
            const char * const fn = (char*)mem + ((unsigned)sregs.ds.selector << 4) + (*(unsigned short*)&regs.rsi);  /* !! Security: check bounds. */
            char * const path_out = (char*)mem + ((unsigned)sregs.es.selector << 4) + (*(unsigned short*)&regs.rdi);  /* 128 bytes of buffer. */  /* !! Security: check bounds. */
            get_dos_abspath_r(fn, &dir_state, path_out, 128);
            if (*path_out == '\0') {
              *(unsigned short*)&regs.rax = 0x100;  /* We set AH to some arbitrary error code. */
              goto error_on_21;
            }
            *(unsigned short*)&regs.rflags &= ~(1 << 0);  /* CF=0. */
          } else if (ah == 0x67) {  /* Set handle count. */
            /* https://stanislavs.org/helppc/int_21-67.html Says that only the first 20 handles are copied to the child process. */
            *(unsigned short*)&regs.rflags &= ~(1 << 0);  /* CF=0. */
          } else if (ah == 0x52) {  /* Get pointer to INVARS. */
            /* Microsoft Macro Assembler 6.00B driver masm.exe. */
            (*(unsigned short*)&regs.rbx) = 0x80;
            sregs.es.selector = 0xfff0;
          } else {
            goto fatal_int;
          }
        } else if (int_num == 0x10) {  /* Video output. */
          if (ah == 0x0e) {  /* Teletype output. */
            const char c = regs.rax;
            (void)!write(1, &c, 1);
          } else if (ah == 0x0f) {  /* Get video state. https://stanislavs.org/helppc/int_10-f.html */
            sphinx_cmm_flags |= 1;
            *(unsigned short*)&regs.rax = 80 << 8 | 3;  /* 80x25. */
            ((unsigned char*)&regs.rbx)[1] = 0;  /* BH := page (0). */
          } else if (ah == 0x08) {  /* Read character and attribute at cursor. */
            *(unsigned short*)&regs.rax = 0;  /* AH == attribute, AL == character. */
          } else if (ah == 0x12) {  /* Video subsystem configuration. https://stanislavs.org/helppc/int_10-12.html */
            const unsigned char bl = (unsigned char)regs.rbx;
            if (bl == 0x10) {  /* Get video configuration information. */
              sphinx_cmm_flags |= 2;
              *(unsigned short*)&regs.rbx = 1 << 8 | 0;  /* Mono, 64 KiB EGA memory. */
              *(unsigned short*)&regs.rcx = 0;  /* Feature bits and switch settings. */
            } else {
              fprintf(stderr, "fatal: unsupported subcall for video subsystem configuration: 0x%02x\n", bl);
              goto fatal;
            }
            *(unsigned short*)&regs.rax = 80 << 8 | 3;  /* 80x25. */
            ((unsigned char*)&regs.rbx)[1] = 0;  /* BH := page (0). */
          } else {
            goto fatal_int;
          }
        } else if (int_num == 0x1a) {  /* Timer. */
          if (ah == 0x00) {  /* Read system clock counter. */
            ++tick_count;  /* We don't emulate a real clock, we just increment the tick counter whenever queried. */
            *(unsigned char*)&regs.rax = 0;  /* No midnight yet. */
            *(unsigned short*)&regs.rcx = tick_count >> 16;
            *(unsigned short*)&regs.rdx = tick_count;
          } else {
            goto fatal_int;
          }
        } else if (int_num == 0x16) {  /* Keyboard. */
          if (ah == 0x12) {  /* Get extended keyboard status. */
            *(unsigned short*)&regs.rax = *(const unsigned short*)((const char*)mem + 0x417);  /* In BDA, 0 by default, no modifier keys pressed. */
          } else if (ah == 0x00) {  /* Wait for keystroke and read. */
            char c;
            /* TODO(pts): Disable line buffering if isatty(0). Enable it again at exit if needed. */
            int got;
            struct termios tio;
            tcflag_t old_lflag = 0;
            if (tty_in_fd == -1) {
              if ((tty_in_fd = open("/dev/tty", O_RDWR)) < 0) {  /* Current controlling terminal. */
                tty_in_fd = -2;
              } else {
                tty_in_fd = ensure_fd_is_at_least(tty_in_fd, 5);
              }
            }
            if (!is_tty_in_error) {
              if (tcgetattr(tty_in_fd, &tio) != 0) {
                is_tty_in_error = 1;
              } else {
                old_lflag = tio.c_lflag;
                /* TODO(pts): Handle Ctrl-<C> and other signals. */
                tio.c_lflag &= ~(ICANON | ECHO);  /* As a side effect, ECHOCTL is also disabled, so Ctrl-<C> won't show up as ^C, but it will still send SIGINT. */
                if (tcsetattr(tty_in_fd, 0, &tio) != 0) {
                  is_tty_in_error = 1;
                }
              }
            }
            if ((got = read(tty_in_fd == -2 ? 0 : tty_in_fd, &c, 1)) < 1) c = 26;  /* Ctrl-<Z>, simulate EOF. Most programs won't recognize it. */
            if (!is_tty_in_error) {
              tio.c_lflag = old_lflag;
              /* TODO(pts): Also change it back upon exit. Even if it's a signal exit. */
              if (tcsetattr(tty_in_fd, 0, &tio) != 0) {
                is_tty_in_error = 1;
              }
            }
            *(unsigned short*)&regs.rax = (c & ~0x7f ? 0x3f : scancodes[(int)c]) << 8 | (c & 0xff);
          } else {
            goto fatal_int;
          }
        } else if (int_num == 0x2a) {  /* Network. */
          if (ah == 0x00) {  /* Network installation query. */
            /* By returning ah == 0x00 we indicate that the network is not installed. */
          } else {
            goto fatal_int;
          }
        } else if (int_num == 0x11) {  /* Get BIOS equipment flags. */
          *(unsigned short*)&regs.rax = *(const unsigned short*)((const char*)mem + 0x410);
        } else if (int_num == 0x2f) {  /* Installation checks. */
          const unsigned char al = (unsigned char)regs.rax;
          if (al == 0x00) {  /* Installation check. */
            if (ah < 2 || ah == 0x15) goto fatal_uic;  /* Doesn't follow the standard format. */
            *(unsigned char*)&regs.rax = 0;  /* Not installed, OK to install. */
          } else { fatal_uic:
            fprintf(stderr, "fatal: unsupported int 0x%02x ax:%04x", int_num, *(const unsigned short*)&regs.rax);
            goto fatal;
          }
        } else if (int_num == 0x00) {  /* Division by zero. */
          /* This is called only if the program doesn't override the interrupt vector.
           * Example instructions: `xor ax, ax', `div ax'.
           */
          fprintf(stderr, "fatal: unhandled division by zero cs:%04x ip:%04x\n", int_cs, int_ip);
        } else {
         fatal_int:
          fprintf(stderr, "fatal: unsupported int 0x%02x ah:%02x cs:%04x ip:%04x\n", int_num, ah, int_cs, int_ip);
          goto fatal;
        }
        /* Return from the interrupt. */
        sregs.cs.base = (sregs.cs.selector = int_cs) << 4;
        regs.rip = int_ip;
        *(unsigned short*)&regs.rsp += 6;  /* pop ip, pop cs, pop flags. */
        goto set_sregs_regs_and_continue;
      } else {
        fprintf(stderr, "fatal: unexpected hlt\n");
        goto fatal;
      }
     case KVM_EXIT_MMIO:
      { const char mmio_len = run->mmio.len;
        const unsigned addr = (unsigned)run->mmio.phys_addr;
        char highmsg[2];
        /* CS:IP points to the instruction doing the memory operation (not after). */
        if (sizeof(run->mmio.phys_addr) > 4 && run->mmio.phys_addr >> (32 * (sizeof(run->mmio.phys_addr) > 4))) {  /* Physical address is larger than 32 bits. */
          highmsg[0] = '+'; highmsg[1] = '\0';
          goto bad_memory_access;
        } else if (addr == 0xfffea && mmio_len == 1 && !run->mmio.is_write && (sphinx_cmm_flags & 3) == 3) {
          /* SPHiNX C-- 1.04 compiler does this, just ignore. */
        } else if (addr - (ENV_PARA << 4) < (PROGRAM_MCB_PARA - 1 - ENV_PARA) << 4 && run->mmio.is_write && mmio_len <= 16) {  /* Overwrites environment area. */
          /* Microsoft BASIC Professional Development System 7.10 linker pblink.exe. It overwrites length and program name with program name and args. */
          /* This emulation is a little bit slow (because of the ioctl(... KVM_RUN ...) overhead), but it's called only less than 75 times at startup. */
          memcpy((char*)mem + addr, run->mmio.data, mmio_len);
        } else if (addr == 0xffffe && !run->mmio.is_write && mmio_len == 1) {  /* BASIC programs compiled by Microsoft BASIC Professional Development System 7.10 compiler pbc.exe */
          run->mmio.data[0] = 0xfc;  /* Machine ID is regular OC (0xfc). Same as default in src/ints/bios.cpp in DOSBox 0.74. */
        } else if (addr < 0x400 && run->mmio.is_write && addr + mmio_len <= 0x400 && ((mmio_len == 2 && (addr & 1) == 0) || (mmio_len == 4 && (addr & 3) == 0))) {  /* Set interrupt vector directly (not via int 0x21 call with ah == 0x25). */
          /* Microsoft BASIC Professional Development System 7.10 compiler pbc.exe */
          const unsigned char set_int_num = addr >> 2;
          if (mmio_len == 2) {  /* There are subsequent sets (segment and offset parts), we buffer them, and call set_int only once. */
            if (addr & 2) {  /* Set segment part. */
              if ((ongoing_set_int & 0xff) == set_int_num && (ongoing_set_int & 0x100)) {
                *(unsigned*)run->mmio.data = *(unsigned short*)run->mmio.data << 16 | ongoing_set_int >> 16;
                goto do_set_int;
              } else {
                ongoing_set_int = 0x200 | set_int_num | *(unsigned short*)run->mmio.data << 16;
                break;  /* Prevent `ongoing_set_int = 0' below. */
              }
            } else {  /* Set offset part. */
              if ((ongoing_set_int & 0xff) == set_int_num && (ongoing_set_int & 0x200)) {
                *(unsigned*)run->mmio.data = *(unsigned short*)run->mmio.data | ongoing_set_int >> 16 << 16;
                goto do_set_int;
              } else {
                ongoing_set_int = 0x100 | set_int_num | *(unsigned short*)run->mmio.data << 16;
                break;  /* Prevent `ongoing_set_int = 0' below. */
              }
            }
          } else { do_set_int:
            if (set_int(set_int_num, *(unsigned*)run->mmio.data, mem, had_get_ints)) goto fatal;
          }
        } else if (addr == 0xa003e && mmio_len == 2 && !run->mmio.is_write) {
          /* Microsoft Macro Assembler 6.00B driver masm.exe. */
          *(unsigned short*)run->mmio.data = 0;
        } else {
          highmsg[0] = '\0';
         bad_memory_access:
          fprintf(stderr, "fatal: KVM memory access denied phys_addr=%08x%s value=%08x%08x size=%d is_write=%d\n", addr, highmsg, ((unsigned*)run->mmio.data)[1], ((unsigned*)run->mmio.data)[0], mmio_len, run->mmio.is_write);
          goto fatal;
        }
      }
      ongoing_set_int = 0;  /* No set_int operation ongoing. */
      break;  /* Just continue at following cs:ip. */
     case KVM_EXIT_INTERNAL_ERROR:
      fprintf(stderr, "fatal: KVM internal error suberror=%d\n", (unsigned)run->internal.suberror);
      /* We get this for an int call if we don't map
       * (KVM_SET_USER_MEMORY_REGION) or initialize the interrupt table
       * properly. However, we can't continue the emulation, because KVM_RUN
       * will return the same error again. !! Can we fix it?
       */
      /* if (run->internal.suberror == KVM_INTERNAL_ERROR_DELIVERY_EV && p[0] == (char)0xcd) { */
      goto fatal;
     default:
      fprintf(stderr, "fatal: unexpected KVM exit: reason=%d\n", run->exit_reason);
      goto fatal;
    }
  }
 fatal:
  dump_regs("fatal", &regs, &sregs);
#if 0  /* The Linux kernel does this at process exit. */
  close(kvm_fds.vcpu_fd);
  close(kvm_fds.vm_fd);
  close(kvm_fds.kvm_fd);
#endif
  return 252;
}
