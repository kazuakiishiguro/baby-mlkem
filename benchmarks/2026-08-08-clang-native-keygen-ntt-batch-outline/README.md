# Clang Native Keygen Forward-NTT Batch Outline

Commit `7bf31373408c6dd8a9b9006678f6a58e040c1c7d` shares Clang native
key generation's six forward NTTs behind one private batch boundary. Its
baseline is `c6d56968a33c253eb06469fd82867aa4a79e4ad2`.

Clang retained the outer K=3 loop in `kpke_keygen()`, but expanded one complete
lower three-stage tail for `shat[i]` and another for `ehat[i]` inside that loop.
The new non-unrolled six-transform helper keeps the exact original order:
`shat[0]`, `ehat[0]`, through `shat[2]`, `ehat[2]`. It calls the existing
shared head and unchanged tail once per transform from one emitted loop body,
then runs the existing canonicalizer only for each `ehat` transform. The
`shat` outputs retain their existing lazy range for the fused keygen consumer.

This is repository-local code-layout work. It changes no butterfly, twiddle,
Montgomery reduction, range contract, accumulator, key/result cache, external
object, runtime library, source table, API, algorithm, or wire format.

## Environment

- CPU: AMD Ryzen Threadripper 7980X 64-Cores.
- Clang: Ubuntu Clang 18.1.3.
- GCC: Ubuntu GCC 13.3.0.
- Linker: GNU ld 2.42.
- Timed runs: CPU 0, three warmup pairs, sixteen alternating measured pairs
  per batch, five independent batches.

Exact flags, kernel, microcode, governor, commits, and timestamps are in
[`environment.txt`](environment.txt).

## Production Size

All products use the normal production/no-cache speed flags.

| Profile | Compiler | Baseline primary | Candidate primary | Delta | Candidate code | Candidate read-only | Candidate writable |
|---|---|---:|---:|---:|---:|---:|---:|
| native | Clang | 79,361 B | 77,675 B | -1,686 B | 57,940 B | 19,735 B | 18,001 B |
| AVX2-only | Clang | 59,307 B | 59,307 B | 0 B | 47,242 B | 12,065 B | 26,593 B |
| scalar | Clang | 62,193 B | 62,193 B | 0 B | 60,160 B | 2,033 B | 18,944 B |
| native | GCC | 59,571 B | 59,571 B | 0 B | 56,006 B | 3,565 B | 33,728 B |
| AVX2-only | GCC | 53,614 B | 53,614 B | 0 B | 49,829 B | 3,785 B | 34,920 B |
| scalar | GCC | 23,267 B | 23,267 B | 0 B | 21,530 B | 1,737 B | 19,488 B |

The keypair export shrinks from 6,522 to 2,105 bytes and the new helper is
2,475 bytes, a net code reduction of 1,942 bytes. Compiler-generated read-only
constants grow 256 bytes, so primary size falls 1,686 bytes. Writable storage
is unchanged.

The accepted product has SHA-256
`70dd2c05485d7f5dd4c1986129f93f6e820025c3b7111fa542a33f0dcade62a5`.
The screen, clean implementation-commit build, and correctness-matrix product
are byte-identical. All five non-target compiler/profile products are
byte-identical to the baseline. See [`size.txt`](size.txt), the twelve raw size
reports, [`artifact-identity.txt`](artifact-identity.txt), and
[`section-accounting.txt`](section-accounting.txt).

## Valid KEM Regression Gate

Five independent Clang-native batches each used three warmup pairs and sixteen
alternating-order measured pairs of 100,000 iterations. Ratios are baseline
time divided by candidate time. Equal-size batches are combined geometrically.

| Operation | Batch 1 | Batch 2 | Batch 3 | Batch 4 | Batch 5 | Combined 80-pair gmean |
|---|---:|---:|---:|---:|---:|---:|
| Decaps | 1.0011x | 0.9958x | 1.0019x | 1.0058x | 1.0028x | 1.001475x |
| Decaps core | 0.9974x | 1.0006x | 0.9943x | 0.9971x | 0.9942x | 0.996717x |
| Encaps | 0.9939x | 0.9970x | 0.9975x | 0.9997x | 0.9971x | 0.997038x |
| Encaps core | 1.0044x | 1.0012x | 1.0029x | 1.0027x | 0.9962x | 1.001476x |
| Keygen | 1.0080x | 1.0000x | 1.0011x | 0.9972x | 0.9952x | 1.000290x |
| Keygen core | 1.0045x | 1.0012x | 0.9998x | 0.9961x | 0.9950x | 0.999314x |
| Roundtrip | 1.0051x | 1.0016x | 1.0012x | 1.0000x | 1.0002x | 1.001618x |
| Roundtrip core | 1.0039x | 1.0011x | 0.9981x | 0.9989x | 0.9966x | 0.999717x |

The minimum is `0.996717x`, above the `0.995x` operation-regression floor.
Timing movement is used only as no-regression evidence; no KEM speed gain is
credited. The nine-pair `kpke_keygen_full` stage screen is `1.0004x`. See
[`native-ab-combined.txt`](native-ab-combined.txt), the five raw KEM reports,
[`stage-summary.txt`](stage-summary.txt), and
[`stage-screen-9x30k.txt`](stage-screen-9x30k.txt).

The affected Clang AVX512 non-VNNI build also passes KAT, product, and complete
stage validation. Its `kpke_keygen_full` stage geometric mean is `0.9968x`.
See [`non-vnni-summary.txt`](non-vnni-summary.txt) and
[`non-vnni-stage-screen-9x30k.txt`](non-vnni-stage-screen-9x30k.txt).

## Stack

Eight guarded alternate-stack runs produced an unchanged 8,056-byte maximum:

| Operation | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Keygen | 6,712 B | 6,648 B | -64 B |
| Encaps | 6,776 B | 6,776 B | 0 B |
| Decaps valid | 8,056 B | 8,056 B | 0 B |
| Decaps invalid | 8,056 B | 8,056 B | 0 B |
| Maximum | 8,056 B | 8,056 B | 0 B |

See [`stack.txt`](stack.txt).

## Rejected Forms

Three smaller layouts were removed because they changed transform locality or
failed the operation gate:

| Candidate | Primary | Size delta | Decisive result |
|---|---:|---:|---|
| Existing K=3 helper for `shat` only | 77,249 B | -2,112 B | `kpke_keygen_full 0.9687x` stage gmean |
| Existing K=3 helper for both vectors | 73,728 B | -5,633 B | 80-pair `decaps_core 0.994419x` |
| No-inline wrapper around both K=3 batches | 73,988 B | -5,373 B | `kpke_keygen_full 0.9845x` stage gmean |

Only the accepted mixed-six form preserves the original per-index transform
order and clears the formal operation gate. Details and raw reports are in
[`rejected-candidates.txt`](rejected-candidates.txt).

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
- Every common text section except the targeted keypair export is
  byte-identical; the candidate adds only the private shared batch section.
- Byte-identical products for all five non-target compiler/profile builds.

See [`correctness-matrix.txt`](correctness-matrix.txt),
[`sanitizers.txt`](sanitizers.txt),
[`cross-path-corpus.txt`](cross-path-corpus.txt),
[`ntt-roots.txt`](ntt-roots.txt), [`abi-audit.txt`](abi-audit.txt), and
[`source-audit.txt`](source-audit.txt).

## Remaining Size Gap

Using the pinned same-method mlkem-native size of 51,186 bytes, the native
deficit falls from 28,175 to 26,489 bytes. The unchanged AVX2-only OpenSSL
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
  ./scripts/bench_core_ab.sh c6d5696

JOBS="$(nproc)" ./scripts/verify_cross_path_corpus.sh
make check-ntt-roots HOSTCC=clang
make check-ntt-roots HOSTCC=gcc
```

Run the A/B command five times to reproduce the 80-pair combined gate. File
integrity for this directory is recorded in `checksums.sha256`.
