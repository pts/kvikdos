.PHONY: all clean run test test-batch test-mem test-cli test-cli-matrix test-static test-sanitizers test-valgrind test-tooling
.SUFFIXES:
MAKEFLAGS += -r

ALL = kvikdos guest.com slowp.com malloct.com mallocs.com printenv.com cat.com waitkey.com

# -Werror=int-conversion: GCC 4.8.4 fails.
CFLAGS = -ansi -pedantic -s -O2 -W -Wall -Wextra -Wuninitialized -Wmaybe-uninitialized -Werror -fno-strict-aliasing -Wno-overlength-strings $(XCFLAGS)
XCFLAGS =  # To be overridden from the command-line.

SRCDEPS = kvikdos.c mini_kvm.h

all: $(ALL)

clean:
	rm -f $(ALL) kvikdos32 kvikdos64 kvikdos.static

run: kvikdos guest.com
	./kvikdos guest.com hello world

test: test-batch test-mem test-cli test-cli-matrix

test-batch: kvikdos
	./tests/test_batch.sh ./kvikdos

test-mem: kvikdos
	./tests/test_mem_services.sh ./kvikdos

test-cli: kvikdos
	./tests/test_cli_parse.sh ./kvikdos

test-cli-matrix: kvikdos
	./tests/test_cli_matrix.sh ./kvikdos

test-static:
	./tests/test_static.sh

test-sanitizers:
	./tests/test_sanitizers.sh

test-valgrind: kvikdos
	./tests/test_valgrind.sh ./kvikdos

test-tooling: test-static test-sanitizers test-valgrind

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

kvikdos.diet: $(SRCDEPS)
	minicc --gcc=4.8 --diet -DUSE_MINI_KVM -fno-strict-aliasing -o kvikdos.diet kvikdos.c
