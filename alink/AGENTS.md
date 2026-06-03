# Repository Notes

## Build

- `make` builds the Linux host binary `alink`
- `make sanitizers` builds `alink.san` with AddressSanitizer and UBSan

## Checks

- `make format-check`
- `make tidy`
- `make cppcheck`
- `make analyze`
- `make valgrind`
- `make ci`

## Conventions

- Source files use uppercase DOS-era filenames and must be compiled as C, not C++
- Linux path handling must continue to accept both `/` and `\`
- Compiler warnings are treated as errors in the maintained build targets
