# Clang Native d10 Encode Batch Outline

Commit `411ce5c2821f796c68cbc9cbbf68a403a68a108e` shares Clang native
encryption's three fixed d10 polynomial encoders behind one private compact
batch boundary. Its baseline is
`21a68fdd77d3e2257fbfac4b418f777c524f6983`.

Clang had expanded `compress_encode_poly_d10_avx2()` three times inside
`kpke_encrypt_prepared_public()`. The new non-unrolled K=3 helper calls that
unchanged encoder for `u[0]`, `u[1]`, and `u[2]` in the original order and at
the original 320-byte output offsets. The following d4 encoder for `v` is
unchanged.

The helper is selected only for Clang with AVX512F and AVX512BW. GCC,
AVX2-only, and scalar builds retain the original loop. This is
repository-local code-layout work: it changes no compression arithmetic,
cache, external object, runtime library, table, API, algorithm, or wire
format.

## Environment

- CPU: AMD Ryzen Threadripper 7980X 64-Cores.
- Clang: Ubuntu Clang 18.1.3.
- GCC: Ubuntu GCC 13.3.0.
- Linker: GNU ld 2.42.
- Timed runs: CPU 0, three warmup pairs, sixteen alternating measured pairs
  per batch, five independent batches.

Exact flags, kernel, microcode, governor, commits, timestamps, and raw-run
times are in [`environment.txt`](environment.txt).

## Production Size

All products use the normal production/no-cache speed flags.

| Profile | Compiler | Baseline primary | Candidate primary | Delta | Candidate code | Candidate read-only | Candidate writable |
|---|---|---:|---:|---:|---:|---:|---:|
| native | Clang | 77,675 B | 73,048 B | -4,627 B | 53,409 B | 19,639 B | 18,001 B |
| AVX2-only | Clang | 59,307 B | 59,307 B | 0 B | 47,242 B | 12,065 B | 26,593 B |
| scalar | Clang | 62,193 B | 62,193 B | 0 B | 60,160 B | 2,033 B | 18,944 B |
| native | GCC | 59,571 B | 59,571 B | 0 B | 56,006 B | 3,565 B | 33,728 B |
| AVX2-only | GCC | 53,614 B | 53,614 B | 0 B | 49,829 B | 3,785 B | 34,920 B |
| scalar | GCC | 23,267 B | 23,267 B | 0 B | 21,530 B | 1,737 B | 19,488 B |

The prepared-encryption section shrinks from 6,150 to 1,381 bytes. The new
compact helper is 238 bytes, so code falls by 4,531 bytes overall. Compiler
read-only constants fall another 96 bytes, producing the 4,627-byte primary
reduction. Writable storage is unchanged.

The accepted product has SHA-256
`7e881e02eb4bd5ba75cfdb00afd34c16a70131d8d941484d0a798ec60e5f2e3e`.
The implementation-commit smoke build, correctness build, and final clean
build are byte-identical. All five non-target compiler/profile products are
byte-identical to the baseline. See [`size.txt`](size.txt), the twelve raw
size reports, [`artifact-identity.txt`](artifact-identity.txt),
[`final-native-smoke.txt`](final-native-smoke.txt), and
[`section-accounting.txt`](section-accounting.txt).

## Valid KEM Regression Gate

Five independent Clang-native batches each used three warmup pairs and sixteen
alternating-order measured pairs of 100,000 iterations. Ratios are baseline
time divided by candidate time. Equal-size batches are combined
geometrically.

| Operation | Batch 1 | Batch 2 | Batch 3 | Batch 4 | Batch 5 | Combined 80-pair gmean |
|---|---:|---:|---:|---:|---:|---:|
| Decaps | 1.0051x | 1.0013x | 1.0037x | 1.0029x | 1.0061x | 1.003819x |
| Decaps core | 0.9916x | 1.0138x | 1.0005x | 1.0110x | 0.9973x | 1.002805x |
| Encaps | 1.0104x | 1.0065x | 1.0067x | 1.0034x | 1.0053x | 1.006457x |
| Encaps core | 0.9966x | 0.9995x | 0.9960x | 0.9936x | 0.9938x | 0.995898x |
| Keygen | 1.0082x | 1.0010x | 0.9984x | 0.9982x | 1.0015x | 1.001453x |
| Keygen core | 1.0049x | 0.9986x | 0.9978x | 0.9975x | 1.0025x | 1.000256x |
| Roundtrip | 1.0041x | 1.0004x | 0.9992x | 0.9998x | 1.0028x | 1.001258x |
| Roundtrip core | 1.0001x | 1.0033x | 0.9982x | 1.0010x | 0.9991x | 1.000338x |

The minimum is `0.995898x`, above the `0.995x` operation-regression floor.
Timing movement is used only as no-regression evidence; no KEM speed gain is
credited. The native stage screen puts complete cached and uncached K-PKE at
`1.0079x` and `1.0044x` geometric mean. Its unchanged direct single-polynomial
d10 diagnostic is `0.9865x`; that row does not invoke the new x3 production
helper, so the integrated 80-pair gate is authoritative.

The affected Clang AVX512 non-VNNI build also passes KAT, product, and complete
stage validation. Cached and uncached K-PKE are `0.9963x` and `1.0049x`
geometric mean. See [`native-ab-combined.txt`](native-ab-combined.txt), the
five raw KEM reports, [`stage-summary.txt`](stage-summary.txt),
[`stage-screen-9x30k.txt`](stage-screen-9x30k.txt),
[`non-vnni-summary.txt`](non-vnni-summary.txt), and
[`non-vnni-stage-screen-9x30k.txt`](non-vnni-stage-screen-9x30k.txt).

## Stack

Eight guarded alternate-stack runs produced an unchanged 8,056-byte maximum:

| Operation | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Keygen | 6,648 B | 6,648 B | 0 B |
| Encaps | 6,776 B | 6,776 B | 0 B |
| Decaps valid | 8,056 B | 8,056 B | 0 B |
| Decaps invalid | 8,056 B | 8,056 B | 0 B |
| Maximum | 8,056 B | 8,056 B | 0 B |

See [`stack.txt`](stack.txt).

## Alternative Forms

Two larger layouts were removed after comparison with the accepted compact
x3 boundary:

| Candidate | Primary | Delta | Decisive result |
|---|---:|---:|---|
| One ordinary no-inline d10 encoder | 74,638 B | -3,037 B | Two-batch combined minimum about `0.99758x`; 1,590 B larger than accepted |
| Normal-optimization x3 wrapper | 74,624 B | -3,051 B | 80-pair minimum `0.997178x`; 1,576 B larger than accepted |
| Compact x3 wrapper | 73,048 B | -4,627 B | 80-pair minimum `0.995898x`; accepted |

The compact form is strictly smaller and still clears the same formal
operation floor. Details and raw reports are in
[`rejected-candidates.txt`](rejected-candidates.txt) and the files prefixed
with `rejected-`.

## Correctness And Isolation

The exact implementation commit passed:

- GCC and Clang native, AVX2-only, and scalar KAT, production API, and complete
  stage-oracle validation.
- Clang native ASan+UBSan and GCC native UBSan KAT, directly linked production
  API, and complete stage validation.
- Clang AVX512 without VNNI KAT, production API, and complete stage validation.
- All 16 core, product, upstream, and PQClean corpus paths, each producing
  381,228 bytes with SHA-256
  `e4d8f908f9a3c59171deeed712925760b194d692b0c571861f204eabef976b67`.
- Clang and GCC NTT-root generator reproducibility plus generator ASan+UBSan.
- The same public and unresolved runtime symbols as the parent.
- Every common text section except prepared encryption is byte-identical; the
  candidate adds only the private compact d10 x3 helper section.
- Byte-identical products for all five non-target compiler/profile builds.

See [`correctness-matrix.txt`](correctness-matrix.txt),
[`sanitizers.txt`](sanitizers.txt),
[`cross-path-corpus.txt`](cross-path-corpus.txt),
[`ntt-roots.txt`](ntt-roots.txt), [`abi-audit.txt`](abi-audit.txt), and
[`source-audit.txt`](source-audit.txt).

## Remaining Size Gap

Using the pinned same-method mlkem-native size of 51,186 bytes, the native
deficit falls from 26,489 to 21,862 bytes. The unchanged AVX2-only OpenSSL
deficit remains 14,258 bytes. This is not a complete same-revision
ten-comparator size or speed rerun, and both production-size gates still fail.
This commit therefore does not complete the overall optimization Goal.

## Reproduction

```bash
make clean
make -j"$(nproc)" product test-product CC=clang ARCH_CFLAGS=-march=native
./scripts/measure_product_size.sh baby_mlkem768_product.o

STACK_RUNS=8 STACK_USABLE_BYTES=1048576 C_COMPILER=clang \
  STACK_CFLAGS='-O2 -march=native -fomit-frame-pointer -fno-stack-protector' \
  ./scripts/measure_stack_highwater.sh baby_mlkem768_product.o local

RUNS=16 WARMUP_RUNS=3 RUN_ORDER=alternating SUITES=kem \
  KEM_ITERS=100000 PIN_CPU=0 C_COMPILER=clang \
  ./scripts/bench_core_ab.sh 21a68fd

JOBS="$(nproc)" ./scripts/verify_cross_path_corpus.sh
make check-ntt-roots HOSTCC=clang
make check-ntt-roots HOSTCC=gcc
```

Run the A/B command five times to reproduce the 80-pair combined gate. File
integrity for this directory is recorded in `checksums.sha256`.
