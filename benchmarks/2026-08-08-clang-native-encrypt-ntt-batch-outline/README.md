# Clang Native Encryption Forward-NTT Batch Outline

Commit `d6eada53621ffc1dc907e4a5ae7a83b922df1042` shares Clang's three
complete forward NTTs at the fused encryption boundary. Its baseline is
`b0f4d0f3b5c824ad1fe3ead76e62267e6c9af8d5`.

The fused K=3 encryption function previously called the complete-transform
wrapper three times. Clang kept the existing forward-NTT head out of line but
expanded the 1,687-byte lower three-stage tail after every head call. The new
private helper loops over the same three polynomials in the same order, calls
the same shared head, and keeps one copy of the unchanged tail. Disabling only
the outer K=3 loop's unrolling is what prevents the three duplicate tails.

This is repository-local code-layout work. It changes no butterfly, twiddle,
Montgomery reduction, range contract, accumulator, key/result cache, external
object, runtime library, source table, API, algorithm, or wire format.

## Environment

- CPU: AMD Ryzen Threadripper 7980X 64-Cores.
- Clang: Ubuntu Clang 18.1.3.
- GCC: Ubuntu GCC 13.3.0.
- Linker: GNU ld 2.42.
- Timed runs: CPU 0, three warmup pairs, sixteen alternating measured pairs
  per batch, three independent batches.

Exact flags, kernel, microcode, governor, commits, and timestamps are in
[`environment.txt`](environment.txt).

## Production Size

All products use the normal production/no-cache speed flags.

| Profile | Compiler | Baseline primary | Candidate primary | Delta | Candidate code | Candidate read-only | Candidate writable |
|---|---|---:|---:|---:|---:|---:|---:|
| native | Clang | 82,687 B | 79,361 B | -3,326 B | 59,882 B | 19,479 B | 18,001 B |
| AVX2-only | Clang | 59,307 B | 59,307 B | 0 B | 47,242 B | 12,065 B | 26,593 B |
| scalar | Clang | 62,193 B | 62,193 B | 0 B | 60,160 B | 2,033 B | 18,944 B |
| native | GCC | 59,571 B | 59,571 B | 0 B | 56,006 B | 3,565 B | 33,728 B |
| AVX2-only | GCC | 53,614 B | 53,614 B | 0 B | 49,829 B | 3,785 B | 34,920 B |
| scalar | GCC | 23,267 B | 23,267 B | 0 B | 21,530 B | 1,737 B | 19,488 B |

The fused function shrinks from 6,418 to 1,102 bytes and the new shared batch
is 1,862 bytes, a net code reduction of 3,454 bytes. Compiler-generated
read-only constants grow 128 bytes, so primary size falls 3,326 bytes.
Writable storage is unchanged.

The accepted product has SHA-256
`768a7650bddf002fc8bd54584a2b0b1c42f52faa0c732e29dc63b20d6e6c1c85`.
The screen, clean implementation-commit build, and correctness-matrix product
are byte-identical. All five non-target compiler/profile products are
byte-identical to the baseline. See [`size.txt`](size.txt), the twelve raw
size reports, [`artifact-identity.txt`](artifact-identity.txt), and
[`section-accounting.txt`](section-accounting.txt).

## Valid KEM Regression Gate

Three independent Clang-native batches each used three warmup pairs and
sixteen alternating-order measured pairs of 100,000 iterations. Ratios are
baseline time divided by candidate time. Equal-size batches are combined
geometrically.

| Operation | Batch 1 | Batch 2 | Batch 3 | Combined 48-pair gmean |
|---|---:|---:|---:|---:|
| Decaps | 0.9973x | 1.0030x | 1.0002x | 1.000164x |
| Decaps core | 1.0039x | 0.9966x | 1.0039x | 1.001461x |
| Encaps | 1.0001x | 1.0028x | 0.9997x | 1.000866x |
| Encaps core | 0.9936x | 1.0016x | 0.9986x | 0.997928x |
| Keygen | 0.9985x | 1.0027x | 1.0023x | 1.001165x |
| Keygen core | 1.0000x | 1.0036x | 1.0041x | 1.002565x |
| Roundtrip | 0.9967x | 1.0010x | 0.9991x | 0.998932x |
| Roundtrip core | 0.9986x | 1.0020x | 0.9998x | 1.000132x |

The minimum is `0.997928x`, above the `0.995x` operation-regression floor.
Timing movement is used only as no-regression evidence; no KEM speed gain is
credited. The nine-pair direct fused-stage screen is `0.9987x`; its noisier
unrelated rows are diagnostic only. See [`native-ab-combined.txt`](native-ab-combined.txt),
the three raw KEM reports, [`stage-summary.txt`](stage-summary.txt), and
[`stage-screen-9x30k.txt`](stage-screen-9x30k.txt).

The affected Clang AVX512 non-VNNI build also passes KAT, product, and complete
stage validation. Its direct fused, cached-encryption, and uncached-encryption
stage geometric means are `0.9998x`, `1.0028x`, and `1.0175x`. See
[`non-vnni-summary.txt`](non-vnni-summary.txt) and
[`non-vnni-stage-screen-9x30k.txt`](non-vnni-stage-screen-9x30k.txt).

## Stack

Eight guarded alternate-stack runs produced exactly the baseline values:

| Operation | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Keygen | 6,712 B | 6,712 B | 0 B |
| Encaps | 6,776 B | 6,776 B | 0 B |
| Decaps valid | 8,056 B | 8,056 B | 0 B |
| Decaps invalid | 8,056 B | 8,056 B | 0 B |
| Maximum | 8,056 B | 8,056 B | 0 B |

See [`stack.txt`](stack.txt).

## Rejected Forms

Four broader or differently placed boundaries were removed:

| Candidate | Primary | Size delta | Decisive result |
|---|---:|---:|---|
| Global tail `noinline` | 72,476 B | -10,211 B | `keygen_core 0.9870x`, `roundtrip_core 0.9941x` |
| Three individual shared-tail calls | 79,256 B | -3,431 B | 48-pair `decaps_core 0.994908x` |
| Three complete-wrapper calls | 79,260 B | -3,427 B | versus accepted batch: `encaps_core 0.9836x` |
| Tail-only K=3 batch | 79,507 B | -3,180 B | `encaps_core 0.9896x`, `roundtrip_core 0.9905x` |

The accepted complete K=3 batch is the only tested shared form that clears the
formal operation gate. Details and raw reports are in
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
- Every common text section except the targeted fused function is
  byte-identical; the candidate adds only the private shared batch section.
- Byte-identical products for all five non-target compiler/profile builds.

See [`correctness-matrix.txt`](correctness-matrix.txt),
[`sanitizers.txt`](sanitizers.txt),
[`cross-path-corpus.txt`](cross-path-corpus.txt),
[`ntt-roots.txt`](ntt-roots.txt), [`abi-audit.txt`](abi-audit.txt), and
[`source-audit.txt`](source-audit.txt).

## Remaining Size Gap

Using the pinned same-method mlkem-native size of 51,186 bytes, the native
deficit falls from 31,501 to 28,175 bytes. The unchanged AVX2-only OpenSSL
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
  ./scripts/bench_core_ab.sh b0f4d0f

JOBS="$(nproc)" ./scripts/verify_cross_path_corpus.sh
make check-ntt-roots HOSTCC=clang
make check-ntt-roots HOSTCC=gcc
```

Run the A/B command three times to reproduce the 48-pair combined gate. File
integrity for this directory is recorded in `checksums.sha256`.
