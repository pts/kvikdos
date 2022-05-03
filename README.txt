kvikdos: a very fast headless DOS emulator for Linux
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
kvikdos is a very fast emulator for running noninteractive DOS programs on
Linux. Such programs are old compilers, assemblers and other build tools.
kvikdos implements a very small subset of DOS, BIOS and IBM PC harware, so
it can keep the overhead low, so it can be very fast. It uses Linux KVM
under the hood for emulating the CPU, which is also very fast.

kvikdos is free software, GNU GPL >=2.0. There is NO WARRANTY. Use at your risk.

kvikdos should be pronunced as ``quick DOS''. the initials ``kv'' refers to
KVM, the underlying virtualization technology.

Requirements:

* Linux operating system running on i386 (x86, i686) or amd64 (x86_64)
  architecture.
* Hardware virtualization (Intel VT-x or AMD-V) enabled on the host.
  Modern CPUs (even some in 2008) support it.
* KVM enabled for your Linux user (see below).

Limitations:

* kvikdos needs a Linux amd64 system with KVM. (Windows and macOS have
  similar virtualization technologies, but kvikdos hasn't been ported to
  them yet. Alternatively, on old Linux i386 systems, the vm86(2) system
  call could be used, but that's not implemented in kvikdos either.)
  macOS users should use udosrun insteda of kvikdos, others should use
  DOSBox or DOSBox-X.

* kvikdos can run 16-bit DOS programs (written for the 8086, 186 or 286
  processors, but not 16-bit 286 protected mode), it can't run 32-bit DOS
  programs (written for 386, 486, Pentium processors or above) or 64-bit
  programs. Use udosrun if you want to run 32-bit DOS programs.

* kvikdos can run a single DOS program at a time. (But you can run multiple
  independent instances of kvikdos in parallel.) Use udosrun (with the
  `-text' or `-gui' flag) or DOSBox if you want to run multiple DOS programs
  after each other or nested.

* The DOS program can use up to 635 KiB of (conventional) memory, including
  the program code and the variables (data and BSS). The 635 KiB excludes:
  environment variables, command-line arguments (in the Program Segment
  Prefix), Interrupt Vector Table, Program Segment Prefix, program stack
  (last 768 bytes), BIOS Data Area, helper code, the user code written for
  Linux.

  kvikdos doesn't support memory types UMB (up to 384 KiB more), HMA (63
  KiB more), XMS (up to hundreds of megabytes more) or EMS (also up to
  hundres of megabytes, overlapping with XMS).

  If your DOS programs need mre memory, use udosrun or DOSBox instead.

* kvikdos doesn't support graphics. Use udosrun or DOSBox instead.

* kvikdos doesn't support interactive text mode (moving the cursor, changing
  the cursor shape, changing the font), so e.g. Volkov Commander doesn't
  work. Something could be emulated using ncurses, but it's not the focus of
  kvikdos. However, kvikdos can supply line-based input (terminated by
  <Enter>) from the terminal to DOS programs. For interactive text mode
  programs in DOS, use udosrun or DOSBox.

* kvikdos doesn't emulate any special hardware (e.g. sound card, MIDI,
  joystick, mouse, CD-ROM). Use DOSBox instead.

* kvikdos implements a tiny subset of the DOS ABI (int 21h etc.), PC BIOS
  ABI (int 10h etc.) and IBM PC hardware interfaces (in and out
  instructions). Thus random DOS programs won't work out of the box. Simple
  API calls can be added on the fly to kvikdos.c. However, many famous build
  tools (e.g. compilers and assemblers) released in the 1980s and 1990s
  already work, see the compatibility list below. To get good chances for
  running any random DOS program, use udosrun or DOSBox instead.

Features and advantages:

* kvikdos is very fast, it runs CPU-intensive code at almost native speeds
  with Linux KVM. For I/O-intensive code, kvikdos tries to satisfy DOS I/O
  calls using the corresponding Linux system calls (mapping as directly as
  possible), thus it has less overhead than other emulators. See
  benchmark/benchmark.md for a comparison between kvikdos, DOSBox and QEMU.
  For CPU-intensive worklad, kvikdos and QEMU + KVM are on par, each of them
  is about 11.49 times faster than the next emulator. For mixed CPU and I/O
  workload, kvikdos is 4.507 times faster than anything else.

* All features of a modern Intel CPU (such as floating point instructions
  and 32-bit registers), except for protected mode and using more than 1 MiB
  of memory, are available for DOS programs, because the host CPU features
  are used directly

* Since very little hardware is emulated, kvikdos starts up very quickly,
  it's possible to run dozens of short-lived kvikdos instances per second.

* After installation (and enabling KVM for the Linux user), kvikdos doesn't
  need special privileges (i.e. root or sudo not needed).

* kvikdos integrates DOS command-line tools to the Linux (Unix) command-line:
  its standard input, output etc. can be redirected, it propagatates the DOS
  exit code to Unix, it can pass environment variables to DOS etc. It also
  works very well headless (i.e. without GUI or interactive text UI), e.g.
  as part of continous build pipelines.

How to install kvikdos:

* (You don't have to install QEMU, kvikdos doesn't need it.)

* To check for hardware virtualization (Intel VT-x or AMD-V),
  run this command on your Linux system (without the leading `$'):

    $ awk '/^flags/&&/( vmx | svm)/{print"OK";exit}' </proc/cpuinfo 
    OK

  If it doesn't display OK (as indicated above), then consult this
  tutorial: https://www.linux-kvm.org/page/FAQ#How_can_I_tell_if_I_have_Intel_VT_or_AMD-V.3F
  . You may have to enable it in the BIOS.

* To check that KVM works on your Linux system,
  run (just the line starting with `$', without the `$'):

    $ cat /dev/kvm
    cat: /dev/kvm: Invalid argument

  If you get `Invalid argument' (as above), then it's OK.

  If you get `No such file or directory' instead, then your kernel doesn't
  have KVM. Ubuntu and mainstream Linux distributions have it. Consult the
  support channels of your Linux distribution about enabling KVM.

  If you get `Permission denied' instead, then you need to give permissions
  for your Linux user to /dev/kvm. Typically, on Ubuntu, run the following,
  and reboot:

    $ sudo adduser "$(id -nu)" kvm

* Download the precompiled kvikdos binary (kvikdos.linux.i386). Rename the
  file to kvikdos, and make it executable:

    $ mv kvikdos.linux.i386 kvikdos
    $ chmod 755 kvikdos

* Download a test DOS program (guest.com) to the same directory, and run it:

    $ ./kvikdos guest.com
    .
    Hello, World!

  If it displays the dot and the `Hello, World!' message, then it's OK.

Software compatibility, i.e. DOS programs known to work in kvikdos:

* Turbo Pascal 7.0 compiler tpc.exe. It produces .exe program files
  directly.

* A86 macro assembler 3.14 .. 4.05 (practically all popular versions)
  a86.com. It produces .com program files directly or OMF .obj files.

* Turbo Assembler (TASM) 2.51, 3.0, 3.1, 3.2 and 4.0 tasm.exe.
  There is no newer 16-bit real mode TASM, packages 5.0 and 5.2 contain the
  tasm.exe of TASM 4.1. It produces OMF .obj files.

* Turbo Link (TLINK) linker 3.01 and 4.0 tlink.exe. There is no newer 16-bit
  real mode TLINK, newer versions of tlink.exe use 16-bit 286 protected
  mode, which kvikdos doesn't support. It reads OMF .obj and .lib files,
  and it produces .exe and .com program files.

* TLIB library builder 3.01 and 3.02 tlib.exe. There is no newer 16-bit
  real mode TLIB, newer versions of tlib.exe use 32-bit protected
  mode, which kvikdos doesn't support.  It produces OBF .lib files
  from OMF .obj files.

* Sphinx C-- compiler 1.04 c--.exe: It produces .com program files.

* Microsoft QuickBASIC compiler 4.50 bc.exe and the corresponding linker
  link.exe. The compiler produces OMF .obj files, and the linker reads
  OMF .obj and .lib files, and it produces .exe program files.

  Please note that the generated .exe files are correct (they are identical
  to those generated in DOSBox by the same tools), but they don't work yet
  in kvikdos, even the hello-world doesn't work yet.

* Microsoft BASIC Professional Development System compiler 7.10 bc.exe and
  the corresponding linker link.exe. The compiler produces OMF .obj files,
  and the linker reads OMF .obj and .lib files, and it produces .exe program
  files.

  Please note that the generated .exe files are correct (they are identical
  to those generated in DOSBox by the same tools), but they don't work yet
  in kvikdos, even the hello-world doesn't work yet.

* BAssPasC Compiler v3.0pre2 bapc3.exe. It produces .asm (TASM) assembly
  source files from .bp3 source files.

* Netwide Assembler (NASM) 0.98.39. The 16-bit versions downloaded from
  here:
  https://www.ibiblio.org/pub/micro/pc-stuff/freedos/files/devel/asm/nasm/0.98.39/
  This is the last version of nasm which uses 32-bit integers internally
  (thus it compiles on 16-bit systems), newer versions use 64-bit integers
  or even longer.
  It produces OMF .obj files, .com program files or others (use `nasm -hf'
  to get a list of output formats).

  Download links:

  * https://www.ibiblio.org/pub/micro/pc-stuff/freedos/files/devel/asm/nasm/0.98.39/8086host/nasm-0.98.39-16bit-8086-12oct2019-Rugxulo.zip
  * https://www.ibiblio.org/pub/micro/pc-stuff/freedos/files/devel/asm/nasm/0.98.39/8086host/nasm16.zip
  * https://www.ibiblio.org/pub/micro/pc-stuff/freedos/files/devel/asm/nasm/0.98.39/8086host/nasmlite.zip
  * https://www.ibiblio.org/pub/micro/pc-stuff/freedos/files/devel/asm/nasm/0.98.39/nsm09839.zip

* Turbo C, Turbo C++ and Borland C++ compilers haven't been tested.
  (TODO(pts): Test them.)

* (TODO(pts): Add tutorial for compiling hello-world with the tools above.)

* (Please note that installers typically don't work. So you should run the
  installer in `udosrun -gui' or DOSBox, and then run the installed programs
  in kvikdos.)

Alternatives of kvikdos:

* udosrun (unreleased): A wrapper around pts-fast-dosbox and DOSBox to run
  DOS command-line tools conveniently and directly within the Linux
  terminal. It has fast startup time, because it doesn't open a separate
  window, and it doesn't emulate most of the hardware. It supports 63 MiB of
  memory and it can run 32-bit programs (just like DOSBox).

* DOSBox or DOSBox-X: It can run 32-bit programs, can display graphics,
  emulates lots of hardware (sound card, MIDI, joystick, mouse, CD-ROM etc.)
  Can run many games. It works out of the box, no need to install FreeDOS,
  MS-DOS etc. It supports up to 63 MiB of memory. Disadvantage: it doesn't
  support headless operation or running DOS command-line tools directly
  within the Linux terminal.

* pts-fast-dosbox (unreleased): a fork of DOSBox 0.74 for Linux, optimized
  for fast startup and fast operation (both faster than regular DOSBox, but
  not as fast as kvikdos). By default it doesn't open a separate window, it
  doesn't emulate most of the hardware, and it has an embedded dosbox.conf
  file optimized for (CPU) speed. It also features a command prompt (`C:\>')
  within the Linux terminal. You can use it most conveniently by driving it
  with udosrun (see above).

* !! doscmd

* !! dosrun and dosrunner

* !! dosemu (how does it work on amd64?)

  DOSEMU2 also supports KVM: https://github.com/stsp/dosemu2/blob/42bc36c8adee504db92e5de9c6db95633c76813d/src/base/emu-i386/kvm.c

  It would be very interesting to see this supported in DOSBox-X. It would probably enable very good Windows 9x support. DOSEMU2 runs up to Windows 3.x and QEMU with KVM has difficulty with Windows 9x (was quite unstable when I tried it).

  !! Is KVM 64-bit only?

Recommendations on using DOSBox interactively, in a GUI:

* Create a directory, and copy everything relevant (e.g. the DOS program)
  there.

* In your terminal window, cd into that directory.

* Run `dosbox .'.

* Use DOSBox in the appearing (black) window. All programs and files of the
  work directory are there. (Use `dir' to see them.)

* Run `exit' in DOSBox to exit (and destroy the black window).

Future work:

* Embed an alternative (but slow) CPU emulator, to make kvikdos
  system-independent (i.e. no KVM) on the host. Example such emulators:

  * https://github.com/ecm-pushbx/8086tiny
  * https://github.com/adriancable/8086tiny  (base of ecm-pushbx/8086tiny)
  * https://github.com/retrohun/8086tiny
  * The CPU emulator of DOSBox. It supports 386, 486, Pentium etc.
  * https://sourceforge.net/projects/fake86/
  * http://ioccc.org/2013/cable3/
  * https://github.com/koutheir/i8086sim
  * https://github.com/DispatchCode/NaTE
  * https://github.com/moesay/Elegant86
  * https://codegolf.stackexchange.com/questions/4732/emulate-an-intel-8086-cpu
  * https://github.com/zsteve/hard86
  * https://github.com/Thraetaona/EXACT (written in WebAssembly)
  * https://github.com/Mati365/ts-c99-compiler (written in TypeScript)

* As an alternative to KVM, use Virtual 8086 mode (vm86(2) system call) on
  Linux i386. Known limitations:

  * It doesn't work if the Linux kernel is targeted to amd64 (i.e. most
    modern systems), because it's not possible to switch back from 64-bit
    mode (long mode) to 32-bit mode, except using virtualization (as done by
    KVM).

  * It won't be able to run protected mode DOS programs (i.e. most 32-bit
    DOS programs), except possibly with a DPMI server. It's not obvious if a
    DPMI server is possible in Linux userspace code (especially the `int
    0x21' remapping within the host process).

  * vm86(2) needs to use the first 1 MiB of the Linux process address space,
    but Linux disallows the mmap(2) of the first 64 KiB for non-root users.
    There may be (slow) workarounds. This effectively redues the memory
    available for the DOS program from 635 KiB to 575 KiB.

!! Speed measurements.

__END__