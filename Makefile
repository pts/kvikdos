.PHONY: all clean run
.SUFFIXES:
MAKEFLAGS += -r

ALL = kvikdos guest.com slowp.com

CFLAGS = -ansi -pedantic -s -O2 -W -Wall -Wextra -fno-strict-aliasing

all: $(ALL)

clean:
	rm -f $(ALL) kvikdos32 kvikdos64

run: kvikdos guest.com
	./kvikdos guest.com hello world

%.com: %.nasm
	nasm -O0 -f bin -o $@ $<

kvikdos: kvikdos.c
	gcc $(CFLAGS) -o $@ $<

kvikdos32: kvikdos.c
	gcc -m32 -fno-pic -march=i686 -mtune=generic $(CFLAGS) -o $@ $<

kvikdos64: kvikdos.c
	gcc -m64 -march=k8 -mtune=generic $(CFLAGS) -o $@ $<
