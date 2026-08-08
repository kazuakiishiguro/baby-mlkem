# Clang Native Shared Forward-Tail Table

Commit `62111bcc9562509bda6a72e71c1582205f806534` makes Clang's two
outlined native forward-NTT callers reference one generated lower-tail factor
table. Its baseline is `50b54e5d6fabf345779b93f65c7bf1b3025e58d3`.

Clang previously folded the same 24 low and 24 high ZMM vectors into each of
`keygen_ntt6_mixed_shared_clang_avx512()` and
`ntt3_full_mont_lazy_raw_shared_clang_avx512()`. The candidate keeps direct
constant access for the generic NTT path, but makes those two production
callers use volatile read-only accesses to the existing generated table. The
compile-time selector is always inlined, so no runtime branch is emitted.

This is repository-local data-layout work. It changes no butterfly, twiddle
value, Montgomery reduction, transform order, range contract, API, wire
format, persistent cache, or external dependency. The low/high Montgomery
factor decomposition remains the externally known and disclosed NTT design;
only removal of Clang's duplicate physical copies is claimed here.

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
| native | Clang | 73,048 B | 69,976 B | -3,072 B | 53,409 B | 16,567 B | 18,001 B |
| AVX2-only | Clang | 52,874 B | 52,874 B | 0 B | 44,705 B | 8,169 B | 26,593 B |
| scalar | Clang | 62,193 B | 62,193 B | 0 B | 60,160 B | 2,033 B | 18,944 B |
| native | GCC | 59,571 B | 59,571 B | 0 B | 56,006 B | 3,565 B | 33,728 B |
| AVX2-only | GCC | 53,614 B | 53,614 B | 0 B | 49,829 B | 3,785 B | 34,920 B |
| scalar | GCC | 23,267 B | 23,267 B | 0 B | 21,530 B | 1,737 B | 19,488 B |

Baseline compiler `.rodata` contains 6,144 bytes of forward-tail vectors: two
copies of the same 3,072-byte table. Candidate compiler `.rodata` falls by
6,144 bytes and two named generated sections retain one 1,536-byte low table
and one 1,536-byte high table. Code is unchanged, so read-only and primary
size fall exactly 3,072 bytes.

All 48 candidate vectors are 64 bytes. A byte search found every vector
exactly twice in the baseline object, for 96 successful comparisons. Both
target function sizes and their instruction-mnemonic counts are unchanged.
The accepted product has SHA-256
`0bdc8790a1f44a2f1e20244155dffe07930547a15a708d88d799770d512c0f9e`.
The screen, six-build matrix, and post-commit products are byte-identical; all
five non-target products are byte-identical to the baseline.

See [`size-baseline-clang-native.txt`](size-baseline-clang-native.txt),
[`size-candidate-clang-native.txt`](size-candidate-clang-native.txt),
[`section-accounting.txt`](section-accounting.txt),
[`table-identity.txt`](table-identity.txt), and
[`artifact-identity.txt`](artifact-identity.txt).

## Product Performance Gate

Three independent Clang-native batches each used three warmup pairs and
sixteen alternating-order measured pairs of 100,000 iterations. Ratios are
baseline time divided by candidate time. Equal-size batch geometric means are
combined geometrically.

| Operation | Batch 1 | Batch 2 | Batch 3 | Combined 48-pair gmean |
|---|---:|---:|---:|---:|
| Decaps | 1.0026x | 1.0043x | 1.0021x | 1.003000x |
| Decaps core | 1.0026x | 1.0043x | 1.0021x | 1.003000x |
| Encaps | 1.0022x | 1.0027x | 1.0004x | 1.001766x |
| Encaps core | 1.0022x | 1.0027x | 1.0004x | 1.001766x |
| Keygen | 1.0047x | 1.0012x | 1.0039x | 1.003266x |
| Keygen core | 1.0047x | 1.0012x | 1.0039x | 1.003266x |
| Roundtrip | 1.0018x | 1.0032x | 1.0033x | 1.002766x |
| Roundtrip core | 1.0018x | 1.0032x | 1.0033x | 1.002766x |

The minimum is `1.001766x`, above the `0.995x` operation-regression floor.
This timing is no-regression evidence only; no KEM speed gain is credited.
The generic `bench_ntt.o` and linked `bench_nttc` are byte-identical between
the two revisions, proving that the compatibility path did not alter generic
NTT code.

See [`product-ab-combined.txt`](product-ab-combined.txt), the three raw A/B
reports, and [`generic-ntt-identity.txt`](generic-ntt-identity.txt).

## Stack

Eight guarded alternate-stack runs produced exactly the baseline values:

| Operation | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Keygen | 6,648 B | 6,648 B | 0 B |
| Encaps | 6,776 B | 6,776 B | 0 B |
| Decaps valid | 8,056 B | 8,056 B | 0 B |
| Decaps invalid | 8,056 B | 8,056 B | 0 B |
| Maximum | 8,056 B | 8,056 B | 0 B |

See [`stack.txt`](stack.txt) and the two raw stack reports.

## Correctness And Isolation

The exact implementation commit passed:

- GCC and Clang native, AVX2-only, and scalar KAT, production API, and complete
  stage-oracle validation.
- Clang native ASan+UBSan and GCC native UBSan KAT, directly linked production
  API, and complete stage validation.
- All 16 core, product, upstream, and PQClean corpus paths, each producing
  381,228 bytes with SHA-256
  `e4d8f908f9a3c59171deeed712925760b194d692b0c571861f204eabef976b67`.
- Clang and GCC NTT-root generator reproducibility.
- The same three public KEM and five unresolved runtime symbols as the parent,
  with a non-executable GNU stack declaration.
- Byte-identical AVX2-only, scalar, and all GCC production artifacts.
- Byte-identical generic NTT object and benchmark executable.

See [`correctness-matrix.txt`](correctness-matrix.txt),
[`sanitizers.txt`](sanitizers.txt),
[`cross-path-corpus.txt`](cross-path-corpus.txt),
[`ntt-roots.txt`](ntt-roots.txt), [`abi-audit.txt`](abi-audit.txt),
[`source-audit.txt`](source-audit.txt), and [`final-smoke.txt`](final-smoke.txt).

## Dependency And Attribution Boundary

The qualifying production artifact uses the default independent baby-mlkem
core and links no external cryptographic library or vendored Kyber/PQClean KEM
backend. The shared factors come from repository-local generated source that
was already present in the baseline. This change does not make the underlying
Montgomery butterfly or factor decomposition an independently invented design;
their existing upstream attribution in `THIRD_PARTY_NOTICES.md` still applies.

## Remaining Size Gap

Using the pinned same-method mlkem-native size of 51,186 bytes, the native
deficit falls from 21,862 to 18,790 bytes. The unchanged AVX2-only OpenSSL
deficit remains 7,825 bytes. This is not a complete same-revision
ten-comparator speed and size rerun, and both production-size gates still fail.
This commit therefore does not complete the overall optimization Goal.

## Reproduction

```bash
make clean
make -j"$(nproc)" product test-product CC=clang ARCH_CFLAGS=-march=native
./scripts/measure_product_size.sh baby_mlkem768_product.o

STACK_RUNS=8 STACK_USABLE_BYTES=1048576 C_COMPILER=clang \
  STACK_CFLAGS='-O2 -march=native -fomit-frame-pointer -fno-stack-protector' \
  ./scripts/measure_stack_highwater.sh baby_mlkem768_product.o local

RUNS=16 WARMUP_RUNS=3 RUN_ORDER=alternating SUITES=product \
  KEM_ITERS=100000 PIN_CPU=0 C_COMPILER=clang ARCH_CFLAGS=-march=native \
  ./scripts/bench_core_ab.sh 50b54e5

JOBS="$(nproc)" ./scripts/verify_cross_path_corpus.sh
make check-ntt-roots HOSTCC=clang
make check-ntt-roots HOSTCC=gcc
```

Run the A/B command three times to reproduce the 48-pair gate. File integrity
for this directory is recorded in `checksums.sha256`.
