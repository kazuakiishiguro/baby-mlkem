# Production artifact versus inline benchmark

This diagnostic quantifies how much the historical single-translation-unit
`benchc` result differs from timing the finalized production artifact through
its exported API. It is not an external implementation comparison.

## Environment

- baby-mlkem commit: `9f76700`
- CPU: AMD Ryzen Threadripper 7980X 64-Cores, pinned to logical CPU 0
- OS: Linux 6.8.0-124-generic
- Clang: Ubuntu clang 18.1.3
- GCC: Ubuntu GCC 13.3.0
- measured pairs: 15 after 3 untimed warmup pairs
- iterations per binary and pair: 100,000
- pair order: inline then product for odd pairs, product then inline for even pairs
- interval: deterministic 20,000-sample paired bootstrap 95% CI

The ratio is `inline_time / product_time`. A value below 1.0 means that the
production artifact is slower. The native profile uses the Makefile default
`-march=native`; AVX2-only uses
`-mavx2 -mbmi2 -mpopcnt -mno-avx512f`.

## No-cache core results

| Profile | Compiler | Keygen ratio (95% CI) | Encaps ratio (95% CI) | Decaps ratio (95% CI) | Roundtrip ratio (95% CI) |
|---|---|---:|---:|---:|---:|
| native | Clang | 1.0008 (0.9957-1.0068) | 1.0044 (0.9963-1.0125) | 1.0020 (0.9924-1.0127) | 1.0017 (0.9955-1.0082) |
| native | GCC | 0.9928 (0.9822-1.0004) | 0.9937 (0.9820-1.0039) | 0.9856 (0.9716-0.9965) | 0.9921 (0.9847-0.9981) |
| AVX2-only | Clang | 1.0004 (0.9950-1.0050) | 1.0001 (0.9936-1.0077) | 0.9963 (0.9910-1.0022) | 0.9982 (0.9960-1.0004) |
| AVX2-only | GCC | 1.0005 (0.9958-1.0065) | 0.9972 (0.9939-0.9995) | 0.9893 (0.9811-0.9983) | 1.0012 (0.9981-1.0049) |

Clang is effectively aligned at this resolution. GCC exposes a repeatable
production-boundary cost in decapsulation: about 1.44% native and 1.07%
AVX2-only by paired geometric mean. Native GCC roundtrip is also about 0.79%
slower. Generated GCC AVX2-only decapsulation bodies are the same size in both
binaries; the production binary additionally crosses its exported API wrapper.
Code placement and the finalized LTO boundary may also contribute, so the full
difference must not be attributed to the wrapper call alone.

The result invalidates the historical assumption that the inline harness and
production artifact are interchangeable. External speed claims must use
`bench_productc`; `benchc` remains useful only for internal candidate A/B work.

## Reproduction

```bash
RUNS=15 WARMUP_RUNS=3 KEM_ITERS=100000 PIN_CPU=0 \
  BOOTSTRAP_SAMPLES=20000 C_COMPILER=clang \
  ./scripts/bench_product_ab.sh

RUNS=15 WARMUP_RUNS=3 KEM_ITERS=100000 PIN_CPU=0 \
  BOOTSTRAP_SAMPLES=20000 C_COMPILER=gcc \
  ./scripts/bench_product_ab.sh

RUNS=15 WARMUP_RUNS=3 KEM_ITERS=100000 PIN_CPU=0 \
  BOOTSTRAP_SAMPLES=20000 C_COMPILER=clang \
  ARCH_CFLAGS='-mavx2 -mbmi2 -mpopcnt -mno-avx512f' \
  ./scripts/bench_product_ab.sh

RUNS=15 WARMUP_RUNS=3 KEM_ITERS=100000 PIN_CPU=0 \
  BOOTSTRAP_SAMPLES=20000 C_COMPILER=gcc \
  ARCH_CFLAGS='-mavx2 -mbmi2 -mpopcnt -mno-avx512f' \
  ./scripts/bench_product_ab.sh
```

Complete cached and no-cache operation rows are retained in the four adjacent
`.txt` files.
