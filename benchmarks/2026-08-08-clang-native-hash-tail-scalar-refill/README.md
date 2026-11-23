# Clang Native Hash-Tail Scalar Refill

Commit `7f03bcce40c3b5ee80c9292730d0d21aa454883c` replaces the rare
matrix-tail continuation inside Clang's shared native hash/sampler helper with
an equivalent scalar Keccak continuation. The baseline is
`8c221d8f6d46ac83611618fc8f94bae55365936b`.

The first 504 sampler bytes are still produced by the existing three x4
Keccak permutations. Once those bytes have been parsed, only x4 lane 1 can
need another matrix block. The baseline nevertheless inlined another complete
x4 Keccak body for that rare branch. The accepted implementation copies all
25 words of lane 1 into the already-consumed `stream` scratch, advances that
state with the existing scalar `keccakf()`, and parses its 168-byte rate.
Repeated refills stay scalar. The common no-refill path and all public outputs
are unchanged.

This is a repository-local core optimization. It adds no cache, external
object, runtime library, table, dispatch, API, algorithm, or wire-format
dependency.

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
| native | Clang | 85,689 B | 82,687 B | -3,002 B | 63,336 B | 19,351 B | 18,001 B |
| AVX2-only | Clang | 59,307 B | 59,307 B | 0 B | 47,242 B | 12,065 B | 26,593 B |
| scalar | Clang | 62,193 B | 62,193 B | 0 B | 60,160 B | 2,033 B | 18,944 B |
| native | GCC | 59,571 B | 59,571 B | 0 B | 56,006 B | 3,565 B | 33,728 B |
| AVX2-only | GCC | 53,614 B | 53,614 B | 0 B | 49,829 B | 3,785 B | 34,920 B |
| scalar | GCC | 23,267 B | 23,267 B | 0 B | 21,530 B | 1,737 B | 19,488 B |

The changed helper shrinks from 8,443 to 5,409 bytes. Code falls by 3,034
bytes, compiler-generated read-only constants grow by 32 bytes, and primary
size therefore falls by 3,002 bytes. Writable storage is unchanged.

The accepted product has SHA-256
`345d507a054d8196b342ec88ad6e3b946473f60a423d5abe33ee9dd30cd6468e`.
A clean implementation-commit build is byte-identical to the product used by
the timed gate. Direct baseline/candidate rebuilds prove that Clang
AVX2/scalar and all three GCC products are byte-identical.

See [`size.txt`](size.txt), [`section-accounting.txt`](section-accounting.txt),
[`artifact-identity.txt`](artifact-identity.txt), and the raw `size-*` reports.

## Stack

Eight guarded alternate-stack runs produced:

| Operation | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Keygen | 6,712 B | 6,712 B | 0 B |
| Encaps | 6,776 B | 6,776 B | 0 B |
| Decaps valid | 8,056 B | 8,056 B | 0 B |
| Decaps invalid | 8,056 B | 8,056 B | 0 B |
| Maximum | 8,056 B | 8,056 B | 0 B |

See [`stack.txt`](stack.txt) and the two raw stack reports.

## Valid KEM Regression Gate

Three independent Clang-native batches each used three warmup pairs and
sixteen alternating-order measured pairs of 100,000 iterations. Ratios are
baseline time divided by candidate time. Equal-size batches are combined
geometrically.

| Operation | Batch 1 | Batch 2 | Batch 3 | Combined 48-pair gmean |
|---|---:|---:|---:|---:|
| Decaps | 0.9977x | 0.9939x | 1.0087x | 1.000080x |
| Decaps core | 1.0005x | 0.9874x | 1.0000x | 0.995948x |
| Encaps | 0.9967x | 0.9967x | 1.0016x | 0.998331x |
| Encaps core | 1.0032x | 0.9940x | 0.9935x | 0.996890x |
| Keygen | 1.0051x | 0.9980x | 0.9939x | 0.998989x |
| Keygen core | 1.0060x | 1.0000x | 0.9982x | 1.001394x |
| Roundtrip | 1.0038x | 0.9987x | 1.0011x | 1.001198x |
| Roundtrip core | 1.0033x | 0.9955x | 0.9950x | 0.997926x |

The minimum is `0.995948x`, above the `0.995x` operation-regression floor.
The batches timed the working-tree source that became `7f03bcc`; the
implementation-commit product is byte-identical. Timing movement is used only
as no-regression evidence, and no KEM speed gain is credited.

The nine-pair stage screen put the integrated `kpke_keygen_full`,
`kpke_encrypt_uncached`, and scalar-refill sampler rows at `1.0161x`,
`1.0140x`, and `1.0080x` geometric mean. These short diagnostics are not used
as a speed claim.

See [`native-ab-combined.txt`](native-ab-combined.txt), the three raw
`native-ab-batch*` reports, [`native-screen-9x50k.txt`](native-screen-9x50k.txt),
and [`stage-screen-9x30k.txt`](stage-screen-9x30k.txt).

## Rare-Path Execution

A Clang instrumentation build ran 4,000 calls through the changed helper.
The initial stream was short eighteen times, and coverage records eighteen
executions of both scalar `keccakf(stream)` and its parser call. The optimized
branch was therefore exercised rather than accepted as untested dead code.
See [`refill-coverage.txt`](refill-coverage.txt).

## Rejected D12 Alternatives

Five compact d12 decoder layouts reduced the 85,689-byte baseline, but each
failed a direct or KEM regression gate:

| Candidate | Primary | Size delta | Decisive result |
|---|---:|---:|---|
| two-block VBMI | 83,789 B | -1,900 B | d12 `0.8335x`; `encaps_core` `0.9869x` |
| one-block masked VBMI | 83,822 B | -1,867 B | formal `encaps_core` `0.9907x`; second-batch `decaps_core` `0.9822x` |
| valid two-count unroll | 83,790 B | -1,899 B | d12 `0.7376x`; uncached decrypt `0.9865x` |
| seven loads plus masked tail | 83,943 B | -1,746 B | d12 `0.9855x`; uncached decrypt `0.9920x` |
| shifted unmasked tail | 83,983 B | -1,706 B | `decaps_core` `0.9886x` |

All were removed. The earlier shared-three-polynomial d12 helper was not
repeated: its existing formal result already put `decaps_core` and
`encaps_core` at `0.9929x` and `0.9928x`. See
[`rejected-candidates.txt`](rejected-candidates.txt) and the retained raw
reports.

## Correctness And Isolation

The exact implementation commit passed:

- GCC and Clang native, AVX2-only, and scalar KAT, production API, and complete
  stage-oracle validation.
- Clang native ASan+UBSan and GCC native UBSan KAT, directly linked production
  API, and complete stage validation.
- All 16 core, product, upstream, and PQClean corpus paths, each producing
  381,228 bytes with SHA-256
  `e4d8f908f9a3c59171deeed712925760b194d692b0c571861f204eabef976b67`.
- Clang and GCC NTT-root generator reproducibility plus generator ASan+UBSan.
- The same three KEM symbols and unresolved runtime symbols as the parent.
- Every common text section except the targeted hash-tail helper is
  byte-identical.
- Byte-identical products for all five non-target compiler/profile builds.

See [`correctness-matrix.txt`](correctness-matrix.txt),
[`sanitizers.txt`](sanitizers.txt),
[`cross-path-corpus.txt`](cross-path-corpus.txt),
[`ntt-roots.txt`](ntt-roots.txt), [`abi-audit.txt`](abi-audit.txt), and
[`source-audit.txt`](source-audit.txt).

## Remaining Size Gap

Using the pinned same-method mlkem-native size of 51,186 bytes, the native
deficit falls from 34,503 to 31,501 bytes. The unchanged AVX2-only OpenSSL
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
  ./scripts/bench_core_ab.sh 8c221d8

JOBS="$(nproc)" ./scripts/verify_cross_path_corpus.sh
make check-ntt-roots HOSTCC=clang
make check-ntt-roots HOSTCC=gcc
```

Run the A/B command three times to reproduce the 48-pair combined gate. File
integrity for this evidence directory is recorded in
[`checksums.sha256`](checksums.sha256).
