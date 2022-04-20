#define _GNU_SOURCE 1  /* For MAP_ANONYMOUS. */
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define MEM_SIZE (2 << 20)  /* In bytes. 2 MiB. */
/* Minimum value is 0x50, after the magic interrupt table (first 0x500 bytes of DOS memory).
 * ``para'' means paragraph of 16 bytes.
 */
#define BASE_PARA 0x100
/* Must be a multiple of the Linux page size (0x1000), minimum value is
 * 0x500 (after magic interrupt table). Must be at most BASE_PARA << 4. Can
 * be 0. By setting it to nonzero (0x1000), we effectively make the magic
 * interrupt table read-only.
 */
#define GUEST_MEM_MODULE_START 0x1000

#define DOS_MEM_LIMIT 0xa0000  /* 640 KiB should be enough for everyone :-). */

#define MAX_DOS_COM_SIZE 0xfee0  /* size + 0x100 bytes of PSP + 0x20 bytes of stack <= 0x10000 bytes. */

#ifndef DEBUG
#define DEBUG 0
#endif

char is_same_ascii_nocase(const char *a, const char *b, unsigned size) {
  while (size-- != 0) {
    const unsigned char pa = *a++;
    const unsigned char pb = *b++;
    if (!(pa == pb || ((pa | 32) - 'a' + 0U <= 'z' - 'a' + 0U && (pa ^ 32) == pb))) return 0;
  }
  return 1;
}

static void load_dos_executable_program(const char *filename, void *mem) {
  char *p;
  int r, r2;
  const int img_fd = open(filename, O_RDONLY);
  if (img_fd < 0) {
    fprintf(stderr, "fatal: can not open DOS executable program: %s: %s\n", filename, strerror(errno));
    exit(252);
  }
  p = (char *)mem + (BASE_PARA << 4) + 0x100;  /* !! Security: check bounds (of mem). */
  r = read(img_fd, p, 28);
  if (r < 0) { read_error:
    perror("fatal: error reading DOS executable program");
    exit(252);
  }
  if (r == 0) {
    fprintf(stderr, "fatal: empty DOS executable program");
    exit(252);
  }
  if (r >= 2 && ('M' | 'Z' << 8) == *(unsigned short*)p) {
    if (r < 28) {
      fprintf(stderr, "fatal: DOS .exe program too short: %s\n", filename);
      exit(252);
    }
    fprintf(stderr, "fatal: DOS .exe programs not supported: %s\n", filename);
    exit(252);  /* !! add support */
  }
  if (r >= 6 && is_same_ascii_nocase(p, "@echo ", 6)) {
    fprintf(stderr, "fatal: DOS .bat batch files not supported: %s\n", filename);
    exit(252);  /* !! add support */
  }
  if (r >= 4 && 0 == memcmp(p, "\x7f""ELF", 4)) {  /* Typically Linux native executable. */
    fprintf(stderr, "fatal: ELF executable programs not supported: %s\n", filename);
    exit(252);  /* TODO(pts): Run them natively, without setting up KVM. */
  }
  if (r >= 3 && ('#' | '!' << 8) == *(unsigned short*)p && (p[2] == ' ' || p[2] == '/')) {
    /* Unix script #! shebang detected. */
    fprintf(stderr, "fatal: Unix scripts not supported: %s\n", filename);
    exit(252);  /* TODO(pts): Run them natively, without setting up KVM. */
  }

  /* Load DOS .com program. */
  if (r == 28) {
    r2 = read(img_fd, p + r, MAX_DOS_COM_SIZE + 1 - r);
    if (r2 < 0) goto read_error;
    r += r2;
    if (r > MAX_DOS_COM_SIZE) {
      fprintf(stderr, "fatal: DOS executable program too long: %s\n", filename);
      exit(252);
    }
  }
  close(img_fd);
}

static void dump_regs(const char *prefix, struct kvm_regs *regs, struct kvm_sregs *sregs) {
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

int main(int argc, char **argv) {
  int kvm_fd;
  int vm_fd;
  int vcpu_fd;
  void *mem;
  char *psp;
  struct kvm_userspace_memory_region region;
  int kvm_run_mmap_size;
  struct kvm_run *run;
  struct kvm_regs regs;
  struct kvm_sregs sregs;
  unsigned sp;

  (void)argc;
  if (!argv[0] || !argv[1]) {
    fprintf(stderr, "Usage: %s <dos-com-or-exe-file> [<dos-arg> ...]\n", argv[0]);
    exit(252);
  }

  if ((kvm_fd = open("/dev/kvm", O_RDWR)) < 0) {
    perror("fatal: failed to open /dev/kvm");
    exit(252);
  }

  if ((vm_fd = ioctl(kvm_fd, KVM_CREATE_VM, 0)) < 0) {
    perror("fatal: failed to create KVM vm");
    exit(252);
  }

  if ((mem = mmap(NULL, MEM_SIZE, PROT_READ | PROT_WRITE,
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
  if (ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
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
    if (ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
      perror("fatal: ioctl KVM_SET_USER_MEMORY_REGION");
      exit(252);
    }
  }
  /* Any read/write outside these regions will trigger a KVM_EXIT_MMIO. */

  load_dos_executable_program(argv[1], mem);

  if ((vcpu_fd = ioctl(vm_fd, KVM_CREATE_VCPU, 0)) < 0) {
    perror("fatal: can not create KVM vcpu");
    exit(252);
  }
  kvm_run_mmap_size = ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
  if (kvm_run_mmap_size < 0) {
    perror("fatal: ioctl KVM_GET_VCPU_MMAP_SIZE");
    exit(252);
  }
  run = (struct kvm_run *)mmap(
      NULL, kvm_run_mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpu_fd, 0);
  if (run == NULL) {
    perror("fatal: mmap kvm_run: %d\n");
    exit(252);
  }

  if (ioctl(vcpu_fd, KVM_GET_REGS, &regs) < 0) {
    perror("fatal: KVM_GET_REGS");
    exit(252);
  }
  if (ioctl(vcpu_fd, KVM_GET_SREGS, &(sregs)) < 0) {
    perror("fatal: KVM_GET_SREGS");
    exit(252);
  }

  /* Fill magic interrupt table. */
  { unsigned u;
    for (u = 0; u < 0x100; ++u) { ((unsigned*)mem)[u] = 0x400000 | u; }
    memset((char*)mem + 0x400, 0xf4, 256);  /* 256 hlt instructions, one for each int. */
  }

/* We have to set both selector and base, otherwise it won't work. A `mov
 * ds, ax' instruction in the 16-bit KVM guest will set both.
 */
#define SET_SEGMENT_REG(name, para_value) do { sregs.name.base = (sregs.name.selector = para_value) << 4; } while(0)
  SET_SEGMENT_REG(cs, BASE_PARA);
  SET_SEGMENT_REG(ds, BASE_PARA);
  SET_SEGMENT_REG(es, BASE_PARA);
  SET_SEGMENT_REG(fs, BASE_PARA);
  SET_SEGMENT_REG(gs, BASE_PARA);

  SET_SEGMENT_REG(ss, BASE_PARA);
  regs.rsp = sp = 0xfffe;
  psp = (char*)mem + (BASE_PARA << 4);  /* Program Segment Prefix. */
  *(short*)(psp + sp) = 0;  /* Push a 0 byte. */
  *(short*)(psp) = 0x20cd;  /* `int 0x20' opcode. */
  *(unsigned short*)(psp + 2) = 0xa000;  /* Top of memory = 0xa0000 */
  psp[0x80] = 0;  /* Empty command-line arguments. */
  copy_args_to_dos_args(psp + 0x80, argv + 2);
  /* !! Fill more elements of the PSP for DOS .com. */

  /* EFLAGS https://en.wikipedia.org/wiki/FLAGS_register */
  regs.rflags = 1 << 1;  /* Reserved bit. */
  regs.rip = 0x100;  /* DOS .com entry point. */

  if (DEBUG) dump_regs("debug", &regs, &sregs);

 set_sregs_regs_and_continue:
  if (ioctl(vcpu_fd, KVM_SET_SREGS, &sregs) < 0) {
    perror("fatal: KVM_SET_SREGS");
    exit(252);
  }
  if (ioctl(vcpu_fd, KVM_SET_REGS, &regs) < 0) {
    perror("fatal: KVM_SET_REGS\n");
    exit(252);
  }

  /* !! Trap it if it tries to enter protected mode (cr0 |= 1). Is this possible? */
  for (;;) {
    int ret = ioctl(vcpu_fd, KVM_RUN, 0);
    if (ret < 0) {
      fprintf(stderr, "KVM_RUN failed");
      exit(252);
    }
    if (ioctl(vcpu_fd, KVM_GET_REGS, &regs) < 0) {
      perror("fatal: KVM_GET_REGS");
      exit(252);
    }
    if (ioctl(vcpu_fd, KVM_GET_SREGS, &sregs) < 0) {
      perror("fatal: KVM_GET_REGS");
      exit(252);
    }
    if (DEBUG) dump_regs("debug", &regs, &sregs);

    switch (run->exit_reason) {
     case KVM_EXIT_IO:
      if (DEBUG) fprintf(stderr, "debug: IO port: port=0x%02x data=%04x size=%d direction=%d\n", run->io.port,
	     *(int *)((char *)(run) + run->io.data_offset),
	     run->io.size, run->io.direction);
      sleep(1);
      break;  /* Continue as if the in/out hasn't happened. */
     case KVM_EXIT_SHUTDOWN:  /* How do we trigger it? */
      fprintf(stderr, "fatal: shutdown\n");
      exit(252);
     case KVM_EXIT_HLT:
      if ((unsigned)sregs.cs.selector == 0x40 && (unsigned)((unsigned)regs.rip - 1) < 0x100) {  /* hlt caused by int through our magic interrupt table. */
        const unsigned char int_num = ((unsigned)regs.rip - 1) & 0xff;
        const unsigned short *csip_ptr = (const unsigned short*)((char*)mem + ((unsigned)sregs.ss.selector << 4) + ((unsigned)regs.rsp & 0xffff));
        const unsigned short int_ip = csip_ptr[0], int_cs = csip_ptr[1];  /* Return address. */  /* !! Security: check bounds, also check that rsp <= 0xfffe. */
        const unsigned char ah = ((unsigned)regs.rax >> 8) & 0xff;
        if (DEBUG) fprintf(stderr, "debug: int 0x%02x ah:%02x cs:%04x ip:%04x\n", int_num, ah, int_cs, int_ip);
        fflush(stdout);
        (void)ah;
        if (int_num == 0x29) {
          const char c = regs.rax;
          (void)!write(1, &c, 1);
        } else if (int_num == 0x20) {
          exit(0);  /* EXIT_SUCCESS. */
        } else if (int_num == 0x21) {
          if (ah == 0x4c) {
            exit((unsigned)regs.rax & 0xff);
          } else if (ah == 0x06 && (unsigned char)regs.rdx != 0xff) {  /* Direct console I/O, output. */
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
            unsigned fd = (unsigned short)regs.rbx;
            if (fd > 4) {  /* Handle too large. */
              /* https://stanislavs.org/helppc/dos_error_codes.html */
              *(unsigned short*)&regs.rax = 6;  /* Invalid handle. */
             error_on_21:
              *(unsigned short*)&regs.rflags |= 1 << 0;  /* CF=1. */
            } else {
              int got;
              const char *p = (char*)mem + ((unsigned)sregs.ds.selector << 4) + ((unsigned)regs.rdx & 0xffff);  /* !! Security: check bounds. */
              const int size = (int)(unsigned short)regs.rcx;
              if (fd == 3) fd = 2;  /* Emulate STDAUX with stderr. */
              else if (fd == 4) fd = 0;  /* Emulate STDPRN with stdout. */
              got = write(fd, p, size);
              if (got < 0) {
                *(unsigned short*)&regs.rax = 0x1d;  /* Write fault. */
                goto error_on_21;
              }
              *(unsigned short*)&regs.rflags &= ~(1 << 0);  /* CF=0. */
              *(unsigned short*)&regs.rax = got;
            }
          } else if (ah == 0x3f) {  /* Read using handle. */
            unsigned fd = (unsigned short)regs.rbx;
            if (fd > 4) {  /* Handle too large. */
              /* https://stanislavs.org/helppc/dos_error_codes.html */
              *(unsigned short*)&regs.rax = 6;  /* Invalid handle. */
              goto error_on_21;
            } else {
              int got;
              char *p = (char*)mem + ((unsigned)sregs.ds.selector << 4) + ((unsigned)regs.rdx & 0xffff);  /* !! Security: check bounds. */
              const int size = (int)(unsigned short)regs.rcx;
              if (fd == 3) fd = 2;  /* Emulate STDAUX with stderr. */
              else if (fd == 4) fd = 0;  /* Emulate STDPRN with stdout. */
              got = read(fd, p, size);
              if (got < 0) {
                *(unsigned short*)&regs.rax = 0x1e;  /* Read fault. */
                goto error_on_21;
              }
              *(unsigned short*)&regs.rflags &= ~(1 << 0);  /* CF=0. */
              *(unsigned short*)&regs.rax = got;
            }
          } else if (ah == 0x09) {  /* Print string. */
            unsigned short dx = (unsigned short)regs.rdx, dx0 = dx;
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
          } else {
            goto fatal_int;
          }
        } else if (int_num == 0x10) {
          if (ah == 0x0e) {  /* Teletype output. */
            const char c = regs.rax;
            (void)!write(1, &c, 1);
          } else {
            goto fatal_int;
          }
        } else {
         fatal_int:
          fprintf(stderr, "fatal: unsupported int 0x%02x ah:%02x cs:%04x ip:%04x\n", int_num, ah, int_cs, int_ip);
          goto fatal;
        }
        /* Return from the interrupt. */
        SET_SEGMENT_REG(cs, int_cs);
        regs.rip = int_ip;
        *(unsigned*)&regs.rsp += 6;  /* pop ip, pop cs, pop flags. */
        goto set_sregs_regs_and_continue;
      } else {
        fprintf(stderr, "fatal: unexpected hlt\n");
        goto fatal;
      }
     case KVM_EXIT_MMIO:
      fprintf(stderr, "fatal: KVM memory access denied phys_addr=%08x value=%08x%08x size=%d is_write=%d\n", (unsigned)run->mmio.phys_addr, ((unsigned*)run->mmio.data)[1], ((unsigned*)run->mmio.data)[0], run->mmio.len, run->mmio.is_write);
      /*break;*/  /* Just continue at following cs:ip. */
      goto fatal;
     default:
      fprintf(stderr, "fatal: unexpected KVM exit: reason=%d\n", run->exit_reason);
      goto fatal;
    }
  }
 fatal:
  dump_regs("fatal", &regs, &sregs);
  close(kvm_fd);
  return 252;
}
