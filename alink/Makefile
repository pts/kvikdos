CC ?= gcc
CLANG ?= clang
SAN_CC ?= gcc
CLANG_TIDY ?= clang-tidy
CLANG_FORMAT ?= clang-format
SCAN_BUILD ?= scan-build
CPPCHECK ?= cppcheck
VALGRIND ?= valgrind

CPPFLAGS ?=
CSTD ?= -std=gnu89
BASE_CFLAGS ?= -O2
COMMON_WARNINGS := -Wall -Werror -Wformat=2 -Werror=uninitialized -Wno-pointer-sign
GCC_WARNINGS := -Werror=maybe-uninitialized -Winit-self
CLANG_WARNINGS := -Wconditional-uninitialized
CFLAGS ?= $(BASE_CFLAGS) $(CSTD) $(COMMON_WARNINGS) $(GCC_WARNINGS)
LDFLAGS ?=
LDLIBS ?=

TARGET ?= alink
SAN_TARGET ?= alink.san
SOURCES := ALINK.C COMBINE.C UTIL.C OUTPUT.C OBJLOAD.C COFF.C COFFLIB.C
OBJECTS := $(SOURCES:.C=.o)
FORMAT_FILES := $(SOURCES) ALINK.H
SANITIZER_FLAGS := -O1 -g3 -fno-omit-frame-pointer -fsanitize=address,undefined
CLANG_ANALYZE_FLAGS := -Xanalyzer -analyzer-output=text -Xanalyzer -analyzer-checker=core.uninitialized.Assign,core.uninitialized.Branch

.PHONY: all clean format format-check tidy cppcheck scan-build analyze sanitizers valgrind ci

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.C ALINK.H
	$(CC) $(CPPFLAGS) $(CFLAGS) -x c -c -o $@ $<

$(SAN_TARGET): $(SOURCES) ALINK.H
	$(SAN_CC) $(CPPFLAGS) $(CSTD) $(COMMON_WARNINGS) $(GCC_WARNINGS) $(SANITIZER_FLAGS) -x c $(SOURCES) -o $@ $(LDLIBS)

format:
	$(CLANG_FORMAT) -i $(FORMAT_FILES)

format-check:
	$(CLANG_FORMAT) --dry-run --Werror $(FORMAT_FILES)

tidy:
	$(CLANG_TIDY) $(SOURCES) -- $(CPPFLAGS) $(CSTD) $(COMMON_WARNINGS) $(CLANG_WARNINGS) -x c

cppcheck:
	$(CPPCHECK) --enable=warning,performance,portability --std=c89 --language=c --force --inconclusive --error-exitcode=1 $(SOURCES)

scan-build:
	$(SCAN_BUILD) --status-bugs $(MAKE) clean all CC=$(CLANG)

analyze:
	@tmp=$$(mktemp); \
	$(CLANG) $(CPPFLAGS) $(CSTD) $(BASE_CFLAGS) $(COMMON_WARNINGS) $(CLANG_WARNINGS) $(CLANG_ANALYZE_FLAGS) --analyze -x c $(SOURCES) 2>&1 | tee $$tmp; \
	! grep -E 'core\\.uninitialized' $$tmp

sanitizers: $(SAN_TARGET)

valgrind: $(SAN_TARGET)
	$(VALGRIND) --error-exitcode=1 --leak-check=full --show-leak-kinds=all ./$(TARGET) -h

ci: clean all format-check tidy cppcheck analyze sanitizers valgrind

clean:
	rm -f $(OBJECTS) $(TARGET) $(SAN_TARGET)
