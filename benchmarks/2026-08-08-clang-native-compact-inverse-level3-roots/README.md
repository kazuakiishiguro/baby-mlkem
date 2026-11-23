# Clang Native Compact Inverse Level-3 Roots

Commit `54ea49d534e2375c1da99e9de00eadb57edfbbff` compacts the
Clang-native AVX512 inverse-NTT level-3 low Montgomery factors. Its baseline
is `f1dc83021bbc2e76162a0cbe5ff866b849740cea`.

The shared four-output inverse/add path needs a lane-shaped factor, so the
candidate replaces eight 64-byte ZMM low vectors with eight 32-byte YMM
splats and broadcasts each YMM into a ZMM. Clang's single-output
inverse/recover path instead uses generated 16-bit low/high scalar mirrors.
Forcing both paths onto either representation failed a direct or production
speed gate. Levels 0 through 2 remain dense low ZMM vectors, and all four
high levels remain dense for the shared path.

This is repository-local generated-data layout work. It changes no factor
value, butterfly arithmetic, transform order, range contract, API, wire
format, persistent cache, external object, or runtime dependency. The
Montgomery factor design and butterfly remain externally known and disclosed;
only this physical representation split is claimed here.

## Environment

- CPU: AMD Ryzen Threadripper 7980X 64-Cores.
- Clang: Ubuntu Clang 18.1.3.
- GCC: Ubuntu GCC 13.3.0.
- Linker: GNU ld 2.42.
- Timed runs: CPU 0, three warmup pairs, two independent fifteen-pair
  batches, and reversed starting order in the second batch.

Exact flags, kernel, microcode, governor, commits, and timestamp are in
[`environment.txt`](environment.txt).

## Production Size

All products use the normal production/no-cache speed flags.

| Profile | Compiler | Baseline primary | Candidate primary | Delta | Candidate code | Candidate read-only | Candidate writable |
|---|---|---:|---:|---:|---:|---:|---:|
| native | Clang | 69,976 B | 69,775 B | -201 B | 53,432 B | 16,343 B | 18,001 B |
| AVX2-only | Clang | 52,874 B | 52,874 B | 0 B | 44,705 B | 8,169 B | 26,593 B |
| scalar | Clang | 62,193 B | 62,193 B | 0 B | 60,160 B | 2,033 B | 18,944 B |
| native | GCC | 59,571 B | 59,571 B | 0 B | 56,006 B | 3,565 B | 33,728 B |
| AVX2-only | GCC | 53,614 B | 53,614 B | 0 B | 49,829 B | 3,785 B | 34,920 B |
| scalar | GCC | 23,267 B | 23,267 B | 0 B | 21,530 B | 1,737 B | 19,488 B |

The named low dense table falls from 2,048 to 1,536 bytes. The new YMM table
costs 256 bytes and the two scalar mirrors cost 32 bytes, so read-only data
falls 224 bytes. Code grows 23 bytes, leaving a 201-byte primary reduction.
`baby_mlkem768_decaps` grows 22 bytes and the shared add4 function grows one
byte. The clean post-commit build reproduces the measured candidate SHA-256
`83fe2ee3d41348b47e8d0ce87ad404f45776324b15ea5cd005f986837baf26ff`.
All five non-target compiler/profile products are byte-identical.

See [`size-baseline-clang-native.txt`](size-baseline-clang-native.txt),
[`size-candidate-clang-native.txt`](size-candidate-clang-native.txt),
[`size-profile-matrix.txt`](size-profile-matrix.txt),
[`section-accounting.txt`](section-accounting.txt), and
[`artifact-identity.txt`](artifact-identity.txt).

## Focused Performance Gate

The focused harness directly calls the production shared add4 function and
an outlined single-output inverse/recover target. It used two fifteen-pair
batches at 500,000 and 1,000,000 iterations. Ratios are baseline time divided
by candidate time.

| Path | Combined pairs | Gmean | 95% CI | Wins |
|---|---:|---:|---:|---:|
| Shared add4, rotating ring | 30 | 0.9981x | 0.9954x..1.0005x | 12/30 |
| Shared add4, copy included | 30 | 0.9984x | 0.9957x..1.0005x | 15/30 |
| Single-output recover, rotating ring | 30 | 1.0060x | 1.0021x..1.0112x | 23/30 |
| Single-output recover, copy included | 30 | 1.0034x | 1.0014x..1.0052x | 25/30 |

All four geometric means clear the `0.995x` internal regression floor and all
paired sinks match. The recover improvement is credited only to this focused
target; the shared add4 result is neutral no-regression evidence.

See [`targeted-inverse-level3-ab.txt`](targeted-inverse-level3-ab.txt),
[`targeted-inverse-level3-raw.tsv`](targeted-inverse-level3-raw.tsv), and
[`targeted_inverse_level3_bench.c`](targeted_inverse_level3_bench.c).

## Product Performance Gate

Two independent Clang-native batches used three warmup pairs and fifteen
alternating measured pairs of 100,000 iterations. The second batch reversed
the starting order. Equal-size batch geometric means combine geometrically.

| Operation | Batch 1 | Batch 2 | Combined gmean | Combined 95% CI |
|---|---:|---:|---:|---:|
| Keygen core | 0.9995x | 0.9976x | 0.9986x | 0.9927x..1.0041x |
| Encaps core | 0.9968x | 0.9991x | 0.9979x | 0.9903x..1.0067x |
| Decaps core | 1.0045x | 1.0058x | 1.0052x | 0.9968x..1.0143x |
| Roundtrip core | 1.0001x | 0.9975x | 0.9988x | 0.9935x..1.0043x |

Every batch and combined operation gmean clears the `0.995x` floor. This is
complete-KEM no-regression evidence only; no broad KEM speed gain is credited.
The baseline and candidate benchmark binaries have different recorded hashes,
while their three linked production API entry addresses are unchanged.

See [`product-ab-batch1-15x100k.txt`](product-ab-batch1-15x100k.txt),
[`product-ab-batch2-reversed-15x100k.txt`](product-ab-batch2-reversed-15x100k.txt),
[`product-ab-combined-30x100k.txt`](product-ab-combined-30x100k.txt),
[`product-ab-raw.tsv`](product-ab-raw.tsv), and
[`bench-product-hashes.txt`](bench-product-hashes.txt).

## Stack

Eight guarded alternate-stack runs produced exactly the baseline values:

| Operation | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Keygen | 6,648 B | 6,648 B | 0 B |
| Encaps | 6,776 B | 6,776 B | 0 B |
| Decaps valid | 8,056 B | 8,056 B | 0 B |
| Decaps invalid | 8,056 B | 8,056 B | 0 B |
| Maximum | 8,056 B | 8,056 B | 0 B |

See [`stack.txt`](stack.txt), [`stack-baseline.txt`](stack-baseline.txt), and
[`stack-candidate.txt`](stack-candidate.txt).

## Correctness And Isolation

The exact implementation commit passed:

- GCC and Clang native, AVX2-only, and scalar KAT, production API, and
  complete 1,000-iteration stage-oracle validation.
- Clang native ASan+UBSan and GCC native UBSan KAT, directly linked production
  API, and complete stage validation.
- All 16 core, product, upstream, and PQClean corpus paths, each producing
  381,228 bytes with SHA-256
  `e4d8f908f9a3c59171deeed712925760b194d692b0c571861f204eabef976b67`.
- Clang and GCC NTT-root generator reproducibility.
- The same three public KEM and five unresolved runtime symbols as the parent,
  with a non-executable GNU stack declaration.
- Byte-identical AVX2-only, scalar, and all GCC production artifacts.

See [`correctness-matrix.txt`](correctness-matrix.txt),
[`sanitizers.txt`](sanitizers.txt),
[`cross-path-corpus.txt`](cross-path-corpus.txt),
[`ntt-roots.txt`](ntt-roots.txt), [`abi-audit.txt`](abi-audit.txt),
[`source-audit.txt`](source-audit.txt), and
[`final-smoke.txt`](final-smoke.txt).

## Rejected Representations

Seven alternatives were removed. Compacting both low and high level-3 roots,
compacting only high, compacting only low without mirrors, and using a scalar
low table each failed a direct or complete-KEM gate. Reusing the full dense
high table for scalar recover passed direct timing but grew code more and put
keygen at `0.9943x`. Outlining inverse grew primary size, and a broader
external root-sharing experiment failed a direct forward-path gate.

Exact exploratory sizes and gate results are in
[`rejected-candidates.txt`](rejected-candidates.txt).

## Dependency And Attribution Boundary

The qualifying production artifact uses the default independent baby-mlkem
core and links no external cryptographic library or vendored Kyber/PQClean KEM
backend. The factors are generated from repository-local source. This change
does not make the underlying Montgomery butterfly or factor decomposition an
independently invented design; their existing attribution in
`THIRD_PARTY_NOTICES.md` still applies.

## Remaining Size Gap

Using the pinned same-method mlkem-native size of 51,186 bytes, the native
deficit falls from 18,790 to 18,589 bytes. The unchanged AVX2-only OpenSSL
deficit remains 7,825 bytes. This is not a complete same-revision
ten-comparator speed and size rerun, and both production-size gates still
fail. This commit therefore does not complete the overall optimization Goal.

## Reproduction

```bash
make clean
make -j"$(nproc)" product test-product CC=clang ARCH_CFLAGS=-march=native
./scripts/measure_product_size.sh baby_mlkem768_product.o

STACK_RUNS=8 STACK_USABLE_BYTES=1048576 C_COMPILER=clang \
  STACK_CFLAGS='-O3 -march=native -fomit-frame-pointer -fno-stack-protector' \
  ./scripts/measure_stack_highwater.sh baby_mlkem768_product.o local

RUNS=15 WARMUP_RUNS=3 RUN_ORDER=alternating SUITES=product \
  KEM_ITERS=100000 PIN_CPU=0 C_COMPILER=clang ARCH_CFLAGS=-march=native \
  ./scripts/bench_core_ab.sh f1dc830

clang -D_GNU_SOURCE -O3 -ffunction-sections -fdata-sections \
  -march=native -Wno-unused-function \
  '-DCORE_SOURCE="/absolute/path/to/baby-mlkem.c"' \
  targeted_inverse_level3_bench.c -Wl,--gc-sections -o inverse_level3_bench
taskset -c 0 ./inverse_level3_bench 1000000

JOBS="$(nproc)" ./scripts/verify_cross_path_corpus.sh
make check-ntt-roots HOSTCC=clang
make check-ntt-roots HOSTCC=gcc
```

Run the product command twice with the second batch starting candidate-first.
Compile the focused harness once against the baseline source and once against
the candidate source, then alternate the two binaries. File integrity for
this directory is recorded in `checksums.sha256`.
