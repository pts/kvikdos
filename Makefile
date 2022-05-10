.PHONY: all clean run
.SUFFIXES:
MAKEFLAGS += -r

ALL = kvikdos guest.com slowp.com malloct.com printenv.com cat.com

CFLAGS = -ansi -pedantic -s -O2 -W -Wall -Wextra -Werror=implicit-function-declaration -Werror=int-conversion -fno-strict-aliasing $(XCFLAGS)
XCFLAGS =  # To be overridden from the command-line.

SRCDEPS = kvikdos.c mini_kvm.h

all: $(ALL)

clean:
	rm -f $(ALL) kvikdos32 kvikdos64 kvikdos.static

run: kvikdos guest.com
	./kvikdos guest.com hello world

%.com: %.nasm
	nasm -O0 -f bin -o $@ $<

kvikdos: $(SRCDEPS)
	gcc $(CFLAGS) -o $@ $<

kvikdos32: $(SRCDEPS)
	gcc -m32 -fno-pic -march=i686 -mtune=generic $(CFLAGS) -o $@ $<

kvikdos64: $(SRCDEPS)
	gcc -m64 -march=k8 -mtune=generic $(CFLAGS) -o $@ $<

kvikdos.static: $(SRCDEPS)
	xstatic gcc -m32 -fno-pic -D_FILE_OFFSET_BITS=64 -DUSE_MINI_KVM -march=i686 -mtune=generic $(CFLAGS) -o $@ $<
