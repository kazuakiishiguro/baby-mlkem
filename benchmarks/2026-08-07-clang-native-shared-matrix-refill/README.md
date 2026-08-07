# Clang Native Shared Matrix Refill

Commit `e57be3711d2f5a08e2cc42edfe0ec86e3e89c01b` shares the rare
single-lane continuation in Clang native AVX512 matrix rejection sampling. Its
parent is `d86557f`, whose algorithm state is `3dccb27`.

The x8 SHAKE128 producer normally supplies enough candidates in its first
three rates. The existing refill path checks all eight lanes and continues
only deficient lanes with scalar Keccak. Clang previously fully inlined that
continuation eight times because the lane count is fixed. The candidate keeps
the eight inexpensive common-path deficiency tests fully unrolled but moves
the continuation into one noinline helper. GCC and non-AVX512 source paths are
unchanged.

This is a production code-size optimization. It adds no external object,
runtime library, persistent cache, table, API, or wire-format dependency.

## Production Size

Both artifacts use Clang 18.1.3 production/no-cache flags with `-march=native`
on the AMD Ryzen Threadripper 7980X host.

| Native product metric | Parent `3dccb27` | Candidate `e57be37` | Delta |
|---|---:|---:|---:|
| Refill continuation code | 1,979 B | 829 B | -1,150 B |
| Total code | 75,516 B | 74,366 B | -1,150 B |
| Read-only data | 20,341 B | 20,341 B | 0 B |
| Primary | 95,857 B | 94,707 B | -1,150 B (-1.20%) |
| Zero-fill/writable | 18,001 B | 18,001 B | 0 B |
| ELF file | 131,600 B | 130,552 B | -1,048 B |

The candidate refill code is a 244-byte continuation plus a 585-byte dispatcher.
Its product SHA-256 is
`6e2e0d031e3af16a8b90c6cf1b33b250ab1f0cf3e654487b062e0e767b157fd4`.
See [`native-size.txt`](native-size.txt).

## Stack

Eight guarded alternate-stack runs report a 64-byte increase from the new call
boundary. Stack remains separate from the primary-size gate.

| Operation | Parent | Candidate | Delta |
|---|---:|---:|---:|
| Keygen | 8,696 B | 8,760 B | +64 B |
| Encaps | 6,840 B | 6,904 B | +64 B |
| Decaps valid | 9,336 B | 9,400 B | +64 B |
| Decaps invalid | 9,336 B | 9,400 B | +64 B |
| Maximum | 9,336 B | 9,400 B | +64 B |

The maximum remains 640 bytes below the pre-hash-tail 10,040-byte baseline.
See [`native-stack.txt`](native-stack.txt).

## Paired Native Gate

Two independent batches each used three warmup pairs and 15 alternating-order
pairs of 100,000 iterations pinned to CPU 0. Ratios are
`parent_time / candidate_time`. Because both batches contain the same number of
pairs, the combined value is the geometric mean of their batch geometric
means, equal to the geometric mean over all 30 measured pairs.

| Operation | Batch 1 | Batch 2 | Combined 30-pair geometric mean | Gate |
|---|---:|---:|---:|---:|
| Keygen | 1.0024x | 0.9987x | 1.0005x | PASS |
| Encaps | 1.0021x | 1.0068x | 1.0044x | PASS |
| Decaps | 0.9946x | 0.9988x | 0.9967x | PASS |
| Roundtrip | 0.9998x | 1.0013x | 1.0005x | PASS |
| Keygen core | 1.0040x | 1.0008x | 1.0024x | PASS |
| Encaps core | 1.0074x | 1.0042x | 1.0058x | PASS |
| Decaps core | 0.9943x | 1.0053x | 0.9998x | PASS |
| Roundtrip core | 0.9994x | 1.0011x | 1.0002x | PASS |

The minimum combined value is `0.9967x`, above the internal `0.995x`
operation floor. Individual batches expose the measurement spread rather than
hiding it. See [`native-ab-batch1-15x100k.txt`](native-ab-batch1-15x100k.txt),
[`native-ab-batch2-15x100k.txt`](native-ab-batch2-15x100k.txt), and
[`native-ab-combined-30x100k.txt`](native-ab-combined-30x100k.txt).

A focused 1,024-seed `sample_ntt8_matrix()` harness used 15 alternating pairs
of 1,000,000 calls after three warmups. Its paired geometric mean is `1.0067x`
with 10/15 candidate wins. This diagnostic supports that the first KEM batch's
low decapsulation averages were not a repeatable refill-path regression. See
[`targeted-sampler-ab.txt`](targeted-sampler-ab.txt) and
[`targeted_sampler_bench.c`](targeted_sampler_bench.c).

## Correctness And Isolation

The accepted candidate passed:

- GCC and Clang native, AVX2-only, and scalar KAT, product, and complete stage
  validation.
- Clang native ASan+UBSan and GCC native UBSan KAT, direct-linked product, and
  complete stage validation.
- Clang- and GCC-generated NTT table reproducibility checks.
- All 16 cross-path corpus variants, each 381,228 bytes with SHA-256
  `e4d8f908f9a3c59171deeed712925760b194d692b0c571861f204eabef976b67`.
- Byte-identical Clang AVX2-only and GCC native products, retaining SHA-256
  `444e4b7e99fcef956dfe7655ff66de308f3e32a134848868e810ab90d4d82584`
  and
  `76cb2e25b1f7860268de66a191534f677ec44655a07444e94b7d9cb93e9377c0`.
- Byte-identical code for every native production section except the two
  refill helpers.

See [`correctness-matrix.txt`](correctness-matrix.txt),
[`sanitizers.txt`](sanitizers.txt),
[`cross-path-corpus.txt`](cross-path-corpus.txt),
[`ntt-roots.txt`](ntt-roots.txt),
[`avx2-identity.txt`](avx2-identity.txt),
[`gcc-native-identity.txt`](gcc-native-identity.txt), and
[`common-section-identity.txt`](common-section-identity.txt). File hashes are
recorded in [`SHA256SUMS`](SHA256SUMS).

LeakSanitizer was disabled with `ASAN_OPTIONS=detect_leaks=0`; AddressSanitizer
and UndefinedBehaviorSanitizer remained enabled.

## Remaining Size Gap

A same-method diagnostic against pinned mlkem-native commit
`56962f6b36d0a718b108b9610ceb9f90b9e617db` reports:

| Native metric | baby-mlkem | mlkem-native | Delta |
|---|---:|---:|---:|
| Primary | 94,707 B | 51,186 B | +43,521 B |
| Maximum stack | 9,400 B | 20,448 B | -11,048 B |

Repository updating was disabled for this targeted diagnostic, so it is not a
completion-qualifying all-comparator run. The primary-size gate still fails.
See [`native-mlkem-size.txt`](native-mlkem-size.txt).

## Reproduction

```bash
make clean
make -j"$(nproc)" product test-product CC=clang \
  ARCH_CFLAGS=-march=native
./scripts/measure_product_size.sh baby_mlkem768_product.o

RUNS=15 WARMUP_RUNS=3 RUN_ORDER=alternating SUITES=kem \
  KEM_ITERS=100000 PIN_CPU=0 C_COMPILER=clang \
  ARCH_CFLAGS=-march=native ./scripts/bench_core_ab.sh d86557f

JOBS="$(nproc)" ./scripts/verify_cross_path_corpus.sh
make check-ntt-roots HOSTCC=clang
make check-ntt-roots HOSTCC=gcc

COMMON='-D_GNU_SOURCE -O3 -fno-semantic-interposition -fvisibility=hidden \
  -Wall -Wextra -std=c99 -fomit-frame-pointer -fno-stack-protector \
  -falign-loops=64 -fno-unwind-tables -fno-asynchronous-unwind-tables \
  -fno-strict-aliasing -march=native -ffunction-sections -fdata-sections \
  -Wno-unused-function -DMLKEM_ENABLE_KECCAK_AVX512VL_ASM \
  -DMLKEM_ENABLE_KECCAKF8_MATRIX_AVX512_ASM'
clang $COMMON -I. \
  benchmarks/2026-08-07-clang-native-shared-matrix-refill/targeted_sampler_bench.c \
  sha3_256_1184_avx512vl.S keccakf8_matrix_avx512.S \
  bench_keccakf4_avx2.S -Wa,--noexecstack -Wl,--gc-sections \
  -o /tmp/targeted-sampler
taskset -c 0 /tmp/targeted-sampler 1000000
```

Build the focused harness at both revisions and alternate their execution order
to reproduce the targeted paired comparison.
