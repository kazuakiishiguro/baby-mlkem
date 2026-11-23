# c8 Correctness and Reproducibility Validation

This validation set covers source commit `400dbe4` (`c8b7823`), the same
product commit used by the c8 speed and size reports.

## Results

- Clang and GCC native KAT plus product tests pass.
- Clang and GCC AVX2-only KAT plus product tests pass.
- Clang and GCC scalar KAT plus product tests pass.
- Clang and GCC native and AVX2 stage validators pass with 1,000 iterations.
- Clang native AddressSanitizer plus UndefinedBehaviorSanitizer KAT and stage validation pass.
- GCC native UndefinedBehaviorSanitizer KAT and stage validation pass.
- `make check-ntt-roots` passes.
- Sixteen core, product, upstream, and PQClean paths emit the same 381,228-byte corpus.

The shared corpus SHA-256 is
`e4d8f908f9a3c59171deeed712925760b194d692b0c571861f204eabef976b67`.
The raw logs beside this README retain the complete KAT output, stage range
output, sanitizer output, and cross-path comparison.

The Clang sanitizer run sets `ASAN_OPTIONS=detect_leaks=0` because
LeakSanitizer cannot initialize under the sandbox's ptrace restriction. Address
and undefined-behavior instrumentation remain enabled; the GCC run uses
UndefinedBehaviorSanitizer without LeakSanitizer.

## Reproduction

Run the ordinary KAT/product matrix in an isolated checkout so each profile is
built from clean objects:

```bash
for compiler in clang gcc; do
  for flags in native avx2 scalar; do
    case "$flags" in
      native) arch=-march=native ;;
      avx2) arch="-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f" ;;
      scalar) arch="-mno-avx -mno-avx2 -mno-avx512f -mno-avx512bw -mno-bmi2" ;;
    esac
    make -B CC="$compiler" AVX2_BACKEND=core ARCH_CFLAGS="$arch" \
      test test-product
  done
done
make -B CC=clang AVX2_BACKEND=core ARCH_CFLAGS=-march=native \
  bench-stages
./bench_core_stagesc 1000
make check-ntt-roots
```

Run the cross-path corpus check with bounded parallelism:

```bash
JOBS=2 CROSS_PATH_KEEP_DIR=0 ./scripts/verify_cross_path_corpus.sh
```

For sanitizer validation, build in a clean checkout with the sanitizer flags
in `CFLAGS`, then run the same KAT/product and stage targets:

```bash
ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 \
  make -B CC=clang ARCH_CFLAGS=-march=native \
  CFLAGS="-D_GNU_SOURCE -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer" \
  test test-product bench-stages
ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 \
  ./bench_core_stagesc 1000

UBSAN_OPTIONS=halt_on_error=1 \
  make -B CC=gcc ARCH_CFLAGS=-march=native \
  CFLAGS="-D_GNU_SOURCE -O1 -g -fsanitize=undefined -fno-omit-frame-pointer" \
  test test-product bench-stages
UBSAN_OPTIONS=halt_on_error=1 ./bench_core_stagesc 1000
```
