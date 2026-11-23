# Clang native keygen NTT pair sharing

This report records the code optimization in commit `c8b7823`, measured against
the preceding accepted native size commit `b955d0b`.

## Change

The Clang AVX512 compact NTT factors now use `vpermt2w` with the index vector
as both the first source and the selector. This removes the zero-vector setup
from each factor expansion. Key generation transforms `shat` and `ehat` in
pairs, so each block expands its six low/high factors once and reuses them for
both transforms. The compact tables are padded to permit the aligned-width
load without reading past the generated object.

No cache, external object, runtime library, vendor backend, API, algorithm, or
wire-format dependency was added.

## Size

Clang native production artifact, built with `-march=native` and the normal
no-cache product flags:

| Artifact | Code | Read-only | Primary | Writable | Artifact bytes |
|---|---:|---:|---:|---:|---:|
| `b955d0b` | 42,535 B | 8,582 B | 51,117 B | 18,001 B | 76,792 B |
| `c8b7823` | 42,493 B | 8,678 B | 51,171 B | 18,001 B | 77,016 B |
| `mlkem-native` comparator | 43,714 B | 7,472 B | 51,186 B | 0 B | n/a |

The candidate is 15 bytes below the current `mlkem-native` primary-size
artifact. Its product-object SHA-256 is:

`c47cad9cc0e62351c14ee1e84e07cecdaabc3d0a8af622f6325fa0e04204feea`

## Internal A/B

- CPU: AMD Ryzen Threadripper 7980X 64-Cores, pinned to logical CPU 0
- Compiler: Clang 18.1.3
- Iterations: 70,000 per run
- Warmup: 3 alternating pairs
- Measured samples: 15 alternating pairs
- Order: candidate first on odd pairs, `b955d0b` first on even pairs
- Metric: `b955d0b time / c8b7823 time`
- Product build: no persistent KEM caches

| Operation | b955 mean ns/op | c8b7823 mean ns/op | Paired geometric mean | Wins |
|---|---:|---:|---:|---:|
| keygen | 4,056.603 | 4,013.626 | 1.010732x | 12/15 |
| encaps | 3,583.837 | 3,566.161 | 1.004929x | 11/15 |
| decaps | 2,877.049 | 2,852.835 | 1.008387x | 10/15 |
| roundtrip | 10,606.295 | 10,529.308 | 1.007307x | 12/15 |

Raw output is preserved in [`speed-ab.txt`](speed-ab.txt).

SHA-256: `0dc68aaa2e52af2dc1cc1e4815e4f5904f29a952c6a630a79c5642bd70e48852`

## Correctness

The following checks passed for the candidate source:

- Clang native KAT, product KAT, and generated-root check
- Clang AVX2-only KAT, product KAT, and generated-root check
- GCC native KAT, product KAT, and generated-root check
- Clang native ASan+UBSan KAT and stage harness
- GCC native UBSan KAT and stage harness

## Goal status

This is an internal improvement over `b955d0b`, not a replacement for the
formal ten-comparator speed reports. The existing native and AVX2 comparator
reports target an older code revision and must be rerun before claiming a
current external speed gate. The full multi-comparator size matrix and
cross-platform artifact comparison also remain open, so this commit does not
define baby-mlkem as globally fastest or smallest.

## Reproduction

```bash
make -B -j2 CC=clang ARCH_CFLAGS='-march=native' \
  test product test-product bench-product check-ntt-roots
./scripts/measure_product_size.sh baby_mlkem768_product.o
```

The paired product screen uses two separately built `bench_productc` binaries,
`taskset -c 0`, three warmup pairs, and fifteen measured pairs at 70,000
iterations.
