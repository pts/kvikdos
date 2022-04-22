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
#include <unistd.h>

#ifdef USE_MINI_KVM  /* For systems with a broken linux/kvm.h. */
#  include "mini_kvm.h"
#else
#  include <linux/kvm.h>
#endif

#if 0  /* We don't use ROM and BIOS area and then XMS above DOS_MEM_LIMIT, we just map DOS_MEM_LIMIT. */
#define MEM_SIZE (2 << 20)  /* In bytes. 2 MiB. */
#endif

/* Minimum value is 0x50, after the magic interrupt table (first 0x500 bytes
 * of DOS memory). Also there is the environment (up to ENV_LIMIT >> 4)
 * paragraphs between the magic interrup table and base. ``para'' means
 * paragraph of 16 bytes.
 *
 * Minimum BASE_PARA value to avoid the A20 bug in exepack is 0x1000.
 * However, we fix that bug in load_dos_executable_program differently, by
 * replacing the stub.
 * https://github.com/joncampbell123/dosbox-x/issues/7#issuecomment-667653041
 * https://www.bamsoftware.com/software/exepack/
 */
#define BASE_PARA 0x100

/* Environment starts at this paragraph. */
#define ENV_PARA 0x50
/* How long the environment can be. */
#define ENV_LIMIT (BASE_PARA << 4)

/* Must be a multiple of the Linux page size (0x1000), minimum value is
 * 0x500 (after magic interrupt table). Must be at most BASE_PARA << 4. Can
 * be 0. By setting it to nonzero (0x1000), we effectively make the magic
 * interrupt table read-only.
 */
#define GUEST_MEM_MODULE_START 0x1000

/* Points to 0x40:int_num, pointer encoded as cs:ip. */
#define MAGIC_INT_VALUE(int_num) (0x400000U | (unsigned)int_num)

#define DOS_MEM_LIMIT 0xa0000  /* 640 KiB should be enough for everyone :-). */

/* Points after last paragraph which can be allocated by DOS, conventional memory. 640 KiB. */
#define DOS_ALLOC_PARA_LIMIT 0xa000

#define MAX_DOS_COM_SIZE 0xfee0  /* size + 0x100 bytes of PSP + 0x20 bytes of stack <= 0x10000 bytes. */

#ifndef DEBUG
#define DEBUG 0
#endif

#define PROGRAM_HEADER_SIZE 28  /* Large enough for .exe header (28 bytes). */

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
    if (r < PROGRAM_HEADER_SIZE) {
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

/* r is the total number of header bytes alreday read from img_fd by
 * detect_dos_executable_program. Returns the psp (Program Segment Prefix)
 * address.
 */
static char *load_dos_executable_program(int img_fd, const char *filename, void *mem, const char *header, int header_size, struct kvm_regs *regs, struct kvm_sregs *sregs) {
  char *psp;
  if (header_size >= PROGRAM_HEADER_SIZE && (('M' | 'Z' << 8) == *(unsigned short*)header || ('M' << 8 | 'Z') == *(unsigned short*)header)) {
    const unsigned short * const exehdr = (const unsigned short*)header;
    const unsigned exesize = exehdr[1] ? ((exehdr[2] - 1) << 9) + exehdr[1] : exehdr[2] << 9;
    const unsigned headsize = (unsigned)exehdr[4] << 4;
    unsigned memsize = (unsigned)exehdr[5] << 4;  /* Minimum size. */
    const unsigned image_size = exesize - headsize;
    char * const image_addr = (char*)mem + (BASE_PARA << 4) + 0x100;
    const unsigned image_para = BASE_PARA + 0x10;
    unsigned reloc_count = exehdr[3];
    const unsigned stack_end = ((unsigned)exehdr[7] << 4) + exehdr[8];
    if (exehdr[5] == 0 && exehdr[6] == 0) {  /* min_memory == max_memory == 0. */
      fprintf(stderr, "fatal: loading DOS .exe to upper part of memory not supported: %s\n", filename);
      exit(252);
    }
    if (exesize <= headsize) {
      fprintf(stderr, "fatal: DOS .exe image smaller than header: %s\n", filename);
      exit(252);
    }
    if (memsize < image_size) memsize = image_size;  /* Some .exe files have it. */
    if (stack_end > memsize) {  /* Some .exe files have it. */
      memsize = stack_end;
      /*fprintf(stderr, "fatal: DOS .exe stack pointer after end of program memory: %s\n", filename);*/
    }
    if ((BASE_PARA << 4) + 0x100 + memsize > DOS_MEM_LIMIT) {
      fprintf(stderr, "fatal: DOS .exe uses too much conventional memory: %s\n", filename);
      exit(252);
    }
    if (((unsigned)exehdr[11] << 4) + exehdr[10] >= image_size) {
      fprintf(stderr, "fatal: DOS .exe entry point after end of image: %s\n", filename);
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
      if ((unsigned)lseek(img_fd, exehdr[12], SEEK_SET) != exehdr[12]) {
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
    *(unsigned*)&regs->rip = exehdr[10];  /* DOS .exe entry point. */
    sregs->cs.selector = exehdr[11] + image_para;
    *(unsigned*)&regs->rsp = exehdr[8];
    sregs->ss.selector = exehdr[7] + image_para;
    if (exehdr[10] == 16 || exehdr[10] == 18) {  /* Detect exepack, find decompression stub within it, replace stub with fixed stub to avoid ``Packed file is corrupt'' error. DOS 5.0 does a similar fix. */
      /* More info about the A20 bug in the exepack stubs: https://github.com/joncampbell123/dosbox-x/issues/7#issuecomment-667653041
       * More info about the exepack file format: https://www.bamsoftware.com/software/exepack/
       * Example error with buggy (unfixed) stubs: fatal: KVM memory access denied phys_addr=00101103 value=0000000000000000 size=1 is_write=0
       */
      unsigned short * const packhdr = (unsigned short*)(image_addr + ((unsigned)exehdr[11] << 4));
      const unsigned exepack_max_size = image_size - ((unsigned)exehdr[11] << 4) - exehdr[10];
      const unsigned exepack_stub_plus_reloc_size =  packhdr[3] - exehdr[10];
      if (*(unsigned short*)((char*)packhdr + exehdr[10] - 2) == ('R' | 'B' << 8) &&  /* exepack signature. */
          exepack_stub_plus_reloc_size >= 258 && exepack_stub_plus_reloc_size <= exepack_max_size) {
        char *after_packhdr = (char*)packhdr + exehdr[10];
        const char *c = (const char*)memmem(after_packhdr, exepack_stub_plus_reloc_size, "\xcd\x21\xb8\xff\x4c\xcd\x21", 7);
        if (DEBUG) fprintf(stderr, "info: detected DOS .exe packed with exepack: header_size=%d exepack_max_size=%d exepack_stub_plus_reloc_size=%d\n", exehdr[10], exepack_max_size, exepack_stub_plus_reloc_size);
        if (c) {
          const unsigned exepack_stub_size = (unsigned)(c + 7 + 22 - after_packhdr);
          if (exepack_stub_size >= 258 && exepack_stub_size <= 290) {
            if (DEBUG) fprintf(stderr, "info: detected DOS .exe packed with exepack: header_size=%d exepack_max_size=%d exepack_stub_plus_reloc_size=%d exepack_stub_size=%d\n", exehdr[10], exepack_max_size, exepack_stub_plus_reloc_size, exepack_stub_size);
            /* Fix A20 bug (failure as ``Packed file is corrupt'' because ES
             * wraps around 0x10000) by replacing the stub.
             */
            memmove((char*)packhdr + 18 + sizeof(fixed_exepack_stub), after_packhdr + exepack_stub_size, exepack_stub_plus_reloc_size - exepack_stub_size);  /* Move packed reloc. */
            memcpy((char*)packhdr + 18, fixed_exepack_stub, sizeof(fixed_exepack_stub));  /* Copy fixed stub. */
            if (exehdr[10] == 16) {  /* Make it longer, because fixed_exepack_stub works only with an 18-byte header (it has org 18 in stub.asm). */
              *(unsigned*)&regs->rip = 18;  /* Update DOS .exe entry point. */
              packhdr[8] = ('R' | 'B' << 8);  /* exepack signature. */
              packhdr[7] = 1;  /* skip_len. */
            }
          }
        }
      }
    }
  } else {
    /* Load DOS .com program. */
    char * const p = (char *)mem + (BASE_PARA << 4) + 0x100;  /* !! Security: check bounds (of mem). */
    unsigned sp;
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
    /* No need to check for DOS_MEM_LIMIT, because (BASE_PARA << 4) + 0x100 + MAX_DOS_COM_SIZE + 0x10 < DOS_MEM_LIMIT. */
    sregs->cs.selector = sregs->ds.selector = sregs->es.selector = sregs->ss.selector = BASE_PARA;
    psp = (char*)mem + (BASE_PARA << 4);  /* Program Segment Prefix. */
    *(unsigned*)&regs->rsp = sp = 0xfffe;
    *(short*)(psp + sp) = 0;  /* Push a 0 byte. */
    *(unsigned short*)(psp + 6) = MAX_DOS_COM_SIZE + 0x100;  /* .COM bytes available in segment (CP/M). DOSBox doesn't initialize it. */
    /*memset(psp, 0, 0x100);*/  /* Not needed, mmap MAP_ANONYMOUS has done it. */
    *(unsigned*)&regs->rip = 0x100;  /* DOS .com entry point. */
  }
  /* https://stanislavs.org/helppc/program_segment_prefix.html */
  *(unsigned short*)(psp + 2) = DOS_MEM_LIMIT >> 4;  /* Top of memory. */
  /* https://stanislavs.org/helppc/program_segment_prefix.html */
  psp[5] = (char)0xf4;  /* hlt instruction; this is machine code to jump to the CP/M dispatcher. */
  *(unsigned short*)(psp + 0x2c) = ENV_PARA;
  *(short*)(psp) = 0x20cd;  /* `int 0x20' opcode. */
  /* !! Fill more elements of the PSP for DOS .com and .EXE. */
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

static int ensure_fd_is_at_least(int fd, int min_fd) {
  if (fd + 0U < min_fd + 0U) {
    int fd2 = dup(fd);
    if (fd2 < 0) { perror("dup"); exit(252); }
    if (fd2 + 0U < min_fd + 0U) fd2 = ensure_fd_is_at_least(fd2, min_fd);
    close(fd);  /* !! TODO(pts): Keep /dev/null open, for faster operation of many open() + close() calls. */
    fd = fd2;
  }
  return fd;
}

/* le is Linux errno. */
static unsigned short get_dos_error_code(int le) {
  /* https://stanislavs.org/helppc/dos_error_codes.html */
  return le == ENOENT ? 2  /* File not found. */
       : le == EACCES ? 5  /* Access denied. */
       : le == EBADF ? 6  /* Invalid handle. */
       : 0x1f;  /* General failure. */
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

static char fnbuf[128], fnbuf2[128];

static const char *get_linux_filename_r(const char *p, char *out_buf) {
  const char *q, *p_end = p + 126;  /* DOS supports even less, DOSBox supports 80. */
  char *out_p;
  for (q = p; q != p_end && *q != '\0'; ++q) {}
  if (*q != '\0') {
    fprintf(stderr, "fatal: DOS filename too long\n");  /* !! Report error 0x3 (Path not found) or 0x44 (Network name limit exceeded). */
    exit(252);
  }
  if (p[1] == ':') {
    if ((p[0] & ~32) == 'C') {
      p += 2;  /* Convert drive-relative to absolute. */
    } else {
      fprintf(stderr, "fatal: DOS filename on wrong drive: 0x%02x\n", (unsigned char)p[0]);  /* !! Report error 0x3 (Path not found) */
      exit(252);
    }
  }
  for (; *p == '\\'; ++p) {}  /* Convert relative to absolute. */
  for (out_p = out_buf; *p != '\0';) {
    const char c = *p++;
    *out_p++ = (c == '\\') ? '/'  /* Convert '\\' to '/'. */
             : (c - 'a' + 0U <= 'z' - 'a' + 0U) ? c & ~32 : c;  /* Convert to uppercase. */
  }
  *out_p = '\0';
  return out_buf;
}

#define get_linux_filename(p) get_linux_filename_r((p), fnbuf)

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

int main(int argc, char **argv) {
  struct kvm_fds kvm_fds;
  void *mem;
  struct kvm_userspace_memory_region region;
  int kvm_run_mmap_size, api_version, img_fd;
  struct kvm_run *run;
  struct kvm_regs regs;
  struct kvm_sregs sregs;
  const char *filename;
  char header[PROGRAM_HEADER_SIZE];
  unsigned header_size;
  char had_get_int0;
  char **envp, **envp0;
  char *prog_dos_pathname = "C:\\PROG.COM";
  unsigned tick_count;
  unsigned char sphinx_cmm_flags;
  unsigned last_heap_block_para, last_heap_block_end_para, base_heap_block_end_para;

  (void)argc;
  if (!argv[0] || !argv[1] || 0 == strcmp(argv[1], "--help")) {
    fprintf(stderr, "Usage: %s [<flag> ...] <dos-com-or-exe-file> [<dos-arg> ...]\n"
                    "Flags:\n"
                    "--env=<NAME>=<value>: Adds environment variable.\n"
                    "--prog=<dos-pathname>: Sets DOS pathname of program.\n",
                    argv[0]);
    exit(252);
  }
  envp = envp0 = ++argv;
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
    } else if (0 == strncmp(arg, "--env=", 6)) {
      *envp++ = arg + 6;  /* Reuse the argv array. */
    } else if (0 == strcmp(arg, "--prog")) {
      if (!argv[0]) goto missing_argument;
      prog_dos_pathname = *argv++;
    } else if (0 == strncmp(arg, "--prog=", 7)) {
      prog_dos_pathname = arg + 7;
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
  filename = *argv++;

  img_fd = open(filename, O_RDONLY);
  if (img_fd < 0) {
    fprintf(stderr, "fatal: can not open DOS executable program: %s: %s\n", filename, strerror(errno));
    exit(252);
  }
  header_size = detect_dos_executable_program(img_fd, filename, header);

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
    memset((char*)mem + 0x400, 0xf4, 256);  /* 256 hlt instructions, one for each int. */
  }
  /* !! Initialize BIOS data area until 0x534, move magic interrupt table later.
   * https://stanislavs.org/helppc/bios_data_area.html
   */

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
  if (ioctl(kvm_fds.vcpu_fd, KVM_GET_REGS, &regs) < 0) {
    perror("fatal: KVM_GET_REGS");
    exit(252);
  }
  if (ioctl(kvm_fds.vcpu_fd, KVM_GET_SREGS, &(sregs)) < 0) {
    perror("fatal: KVM_GET_SREGS");
    exit(252);
  }
  sregs.fs.selector = sregs.gs.selector = 0x50;  /* Random value after magic interrupt table. */
  /* EFLAGS https://en.wikipedia.org/wiki/FLAGS_register */
  regs.rflags = 1 << 1;  /* Reserved bit. */
  /*regs.rflags |= 1 << 9;*/  /* IF=1, enable interrupts. */

  { char *psp = load_dos_executable_program(img_fd, filename, mem, header, header_size, &regs, &sregs);
    copy_args_to_dos_args(psp + 0x80, argv);
  }
  close(img_fd);

  { char *env = (char*)mem + (ENV_PARA << 4);
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
    env = add_env(env, env_end, "", 0);  /* Empty var marks end of env. */
    env = add_env(env, env_end, ".", 0);  /* Just skip 2 bytes, DOSBox also does it. */
    env = add_env(env, env_end, prog_dos_pathname, 0);  /* Full program pathname. */
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

  had_get_int0 = 0;
  tick_count = 0;
  sphinx_cmm_flags = 0;
  /* Initially there is only a single heap block: the program image (starting with PSP). We remember it so that the program can resize it using int 0x21 ah == 0x4a. */
  last_heap_block_para = BASE_PARA;
  base_heap_block_end_para = last_heap_block_end_para = DOS_ALLOC_PARA_LIMIT;
  { struct SA { int StaticAssert_AllocParaLimits : DOS_ALLOC_PARA_LIMIT <= (DOS_MEM_LIMIT >> 4); }; }

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
      if ((unsigned)sregs.cs.selector == 0x40 && (unsigned)((unsigned)regs.rip - 1) < 0x100) {  /* hlt caused by int through our magic interrupt table. */
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
            *(unsigned short*)&regs.rax = 5 | 0 << 8;  /* 5.0. */
            *(unsigned short*)&regs.rbx = 0xff00;  /* MS-DOS with high 8 bits of OEM serial number in BL. */
            *(unsigned short*)&regs.rcx = 0;  /* Low 16 bits of OEM serial number in CX. */
          } else if (ah == 0x40) {  /* Write using handle. */
            const int fd = get_linux_handle(*(unsigned short*)&regs.rbx, &kvm_fds);
            if (fd < 0) {
             error_invalid_handle:
              *(unsigned short*)&regs.rax = 6;  /* Invalid handle. */
             error_on_21:
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
            *(unsigned char*)&regs.rax = 'C' - 'A';
          } else if (ah == 0x47) {  /* Get current directory. */
            /* Input: DL: 0 = current drive, 1: A: */
            if (*(unsigned char*)&regs.rdx != 0) {
              *(unsigned short*)&regs.rax = 0xf;  /* Invalid drive specified. */
              goto error_on_21;
            }
            /* Current directory is \ (\ stripped from both sides). */
            *((char*)mem + ((unsigned)sregs.ds.selector << 4) + (*(unsigned short*)&regs.rdx)) = '\0';  /* !! Security: check bounds, should be 64 bytes supplied by the caller. */
          } else if (ah == 0x3d || ah == 0x3c) {  /* Open to handle. Create to handle. */
            const char * const p = (char*)mem + ((unsigned)sregs.ds.selector << 4) + (*(unsigned short*)&regs.rdx);  /* !! Security: check bounds. */
            const int flags = (ah == 0x3c) ? O_RDWR | O_CREAT | O_TRUNC :
                *(unsigned char*)&regs.rax & 3;  /* O_RDONLY == 0, O_WRONLY == 1, O_RDWR == 2 same in DOS and Linux. */
            /* For create, CX contains attributes (read-only, hidden, system, archive), we just ignore it.
             * https://stanislavs.org/helppc/file_attributes.html
             */
            int fd = open(get_linux_filename(p), flags, 0644);
            if (fd < 0) { error_from_linux:
              *(unsigned short*)&regs.rax = get_dos_error_code(errno);
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
          } else if (ah == 0x41) {  /* Delete file. */
            const char * const p = (char*)mem + ((unsigned)sregs.ds.selector << 4) + (*(unsigned short*)&regs.rdx);  /* !! Security: check bounds. */
            int fd = unlink(get_linux_filename(p));
            if (fd < 0) goto error_from_linux;
            *(unsigned short*)&regs.rflags &= ~(1 << 0);  /* CF=0. */
          } else if (ah == 0x56) {  /* Rename file. */
            const char * const p_old = (char*)mem + ((unsigned)sregs.ds.selector << 4) + (*(unsigned short*)&regs.rdx);  /* !! Security: check bounds. */
            const char * const p_new = (char*)mem + ((unsigned)sregs.es.selector << 4) + (*(unsigned short*)&regs.rdi);  /* !! Security: check bounds. */
            int fd = rename(get_linux_filename(p_old), get_linux_filename_r(p_new, fnbuf2));
            if (fd < 0) goto error_from_linux;
            *(unsigned short*)&regs.rflags &= ~(1 << 0);  /* CF=0. */
          } else if (ah == 0x25) {  /* Set interrupt vector. */
            /* !! Implement this. */
            const unsigned char set_int_num = (unsigned char)regs.rax;
            const unsigned short dx = *(unsigned short*)&regs.rdx;
            const unsigned short ds = sregs.ds.selector;
            const unsigned value = ds << 16 | dx;
            unsigned *p = (unsigned*)mem + set_int_num;
            if (set_int_num == 0x23 ||  /* Application Ctrl-<Break> handler. */
                value == *p ||  /* Unchanged. */
                value == MAGIC_INT_VALUE(set_int_num) ||  /* Set back to original. */
                (had_get_int0 && (set_int_num == 0x00 || set_int_num == 0x24 || set_int_num == 0x3f))  /* Turbo Pascal 7.0. 0x24 is the critical error handler. */) {
              /* We will never send Ctrl-<Break>. */
              *p = value;
            } else {
              fprintf(stderr, "fatal: unsupported set interrupt vector int:%02x to cs:%04x ip:%04x\n",
                      set_int_num, ds, dx);
              goto fatal;
            }
          } else if (ah == 0x35) {  /* Get interrupt vector. */
            /* !! Implement this. */
            const unsigned char get_int_num = (unsigned char)regs.rax;
            if (get_int_num == 0) had_get_int0 = 1;  /* Turbo Pascal 7.0 programs start with this. */
            if (had_get_int0) {
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
            if (al == 0) {  /* Get device information. */
              const int fd = get_linux_handle(*(unsigned short*)&regs.rbx, &kvm_fds);
              struct stat st;
              if (fd < 0) goto error_invalid_handle;
              if (fstat(fd, &st) != 0) goto error_from_linux;
              *(unsigned short*)&regs.rdx = 1 << 5  /* binary */ | (S_ISCHR(st.st_mode) ? 1 : 0) << 7  /* character device */;
              *(unsigned short*)&regs.rflags &= ~(1 << 0);  /* CF=0. */
            } else {
              fprintf(stderr, "fatal: unsupported DOS ioctl call: 0x%02x\n", al);
              goto fatal;
            }
          } else if (ah == 0x4a) {  /* Modify allocated memory block. */
            const unsigned new_size_para = *(unsigned short*)&regs.rbx;
            const unsigned short es = sregs.es.selector;
            if (es != last_heap_block_para) {
              /*fprintf(stderr, "fatal: unsupported block resize: old_para=0x%04x new_size_para=0x%04x\n", es, new_size_para);*/
              /*goto fatal;*/
              *(unsigned short*)&regs.rbx = 1;  /* We don't know how large it was. */
              goto error_insufficient_memory;
            }
            if (new_size_para > DOS_ALLOC_PARA_LIMIT - last_heap_block_para) {
              *(unsigned short*)&regs.rbx = DOS_ALLOC_PARA_LIMIT - last_heap_block_para;
             error_insufficient_memory:
              *(unsigned short*)&regs.rax = 8;  /* Insufficient memory. */
              goto error_on_21;
            }
            last_heap_block_end_para = last_heap_block_para + new_size_para;
            if (last_heap_block_para == BASE_PARA) base_heap_block_end_para = last_heap_block_end_para;
            *(unsigned short*)&regs.rflags &= ~(1 << 0);  /* CF=0. */
          } else if (ah == 0x48) {  /* Allocate memory. */
            const unsigned size_para = *(unsigned short*)&regs.rbx;
            const unsigned available_para = DOS_ALLOC_PARA_LIMIT - last_heap_block_end_para;
            if (size_para > available_para) {
              *(unsigned short*)&regs.rbx = available_para;
              goto error_insufficient_memory;
            }
            *(unsigned short*)&regs.rax = last_heap_block_para = last_heap_block_end_para;
            last_heap_block_end_para = last_heap_block_para + size_para;
            *(unsigned short*)&regs.rflags &= ~(1 << 0);  /* CF=0. */
          } else if (ah == 0x49) {  /* Free allocated memory. */
            const unsigned block_para = *(unsigned short*)&sregs.es.selector;
            if (block_para < base_heap_block_end_para) {  /* It's not allowed to free the program image. */
              goto error_invalid_parameter;
            }
            /* This is really best effort: we have enough info only for freeing the very last block. */
            if (block_para == last_heap_block_para) {
              if (last_heap_block_para == base_heap_block_end_para) {
                last_heap_block_para = BASE_PARA;
                last_heap_block_end_para = base_heap_block_end_para;
              } else {
                last_heap_block_end_para = last_heap_block_para;
                /* Unfortunately we don't have enough info to make last_heap_block_para smaller, so we will leak memory. */
              }  /* Unfortunately we don't keep enough info to free something in the middle of the heap, so we leak memory here. */
            }
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
          } else if (ah == 0x63) {  /* Get lead byte table. Multibyte support in MS-DOS 2.25. */
            *(unsigned short*)&regs.rax = 1;  /* Invalid function number. */
            goto error_on_21;
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
      if ((unsigned)run->mmio.phys_addr == 0xfffea && run->mmio.len == 1 && !run->mmio.is_write && (sphinx_cmm_flags & 3) == 3) {
        /* SPHiNX C-- 1.04 compiler does this, just ignore. */
        break;
      } else {
        fprintf(stderr, "fatal: KVM memory access denied phys_addr=%08x value=%08x%08x size=%d is_write=%d\n", (unsigned)run->mmio.phys_addr, ((unsigned*)run->mmio.data)[1], ((unsigned*)run->mmio.data)[0], run->mmio.len, run->mmio.is_write);
      }
      /*break;*/  /* Just continue at following cs:ip. */
      goto fatal;
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
