# Clang AVX2 Inverse-Final/d4 Fusion

Commit `07c105095c43b3bc46cffd2796033dfe5041eae6` fuses the final
inverse-NTT/message/noise result directly into d4 ciphertext encoding in the
Clang AVX2-only production core. Its baseline is
`85e0cb3584d0a9a6900aad278534cc476e030918`.

The baseline already evaluated `inverse_final(v) + e2 + message` in one pass,
but it still wrote all 256 canonical coefficients to the 512-byte `v`
polynomial and immediately reloaded them for d4 compression. The accepted path
keeps two 16-coefficient results live at a time, compresses and packs their 32
d4 values into 16 ciphertext bytes, and never materializes the final
polynomial. This removes 512 bytes of intermediate stores and 512 bytes of
immediate reloads per encryption.

The three input terms are canonical before the last reduction. Their largest
sum is `2*(Q-1) + (Q+1)/2 = 8321`, which is nonnegative, below `3Q`, and below
`INT16_MAX`. Exactly two conditional subtractions therefore replace the
general signed Barrett canonicalizer. The report harness checks every integer
from 0 through 8,321 against `% Q` before testing complete transforms.

## Environment

- CPU: AMD Ryzen Threadripper 7980X 64-Cores.
- Clang: Ubuntu Clang 18.1.3.
- GCC: Ubuntu GCC 13.3.0.
- Linker: GNU ld 2.42.
- Product KEM: CPU 0, three independent batches, three warmup pairs and
  sixteen alternating measured pairs per batch, 100,000 iterations.
- Direct fused finish: CPU 0, thirty-one alternating measured pairs,
  2,000,000 calls after 10,000 warmup calls in each process.

Exact flags, kernel, microcode, governor, commits, and run settings are in
[`environment.txt`](environment.txt).

## Production Size

Both artifacts use the normal production/no-cache speed flags. Primary size
is allocatable executable plus read-only data.

| Profile | Compiler | Baseline | Candidate | Delta | Candidate code | Candidate read-only | Candidate writable |
|---|---|---:|---:|---:|---:|---:|---:|
| AVX2-only | Clang | 50,847 B | 50,790 B | -57 B | 43,234 B | 7,556 B | 26,593 B |

The linked change decomposes as follows:

| Component | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| `kpke_encrypt_finish_avx2` | 3,900 B | 3,841 B | -59 B |
| Net code | 43,293 B | 43,234 B | -59 B |
| Compiler read-only pools | 7,554 B | 7,556 B | +2 B |
| Net primary | 50,847 B | 50,790 B | -57 B |

All twenty-one common text sections outside the changed caller are
byte-identical, and no text section is added or removed. The two-byte read-only
increase is confined to compiler-generated pools. The clean committed product
has SHA-256
`f70fcf311b8de744b63d8d75c0f647186ecd3db21a076d5aae1be662d03baefd`.

See [`size-baseline.txt`](size-baseline.txt),
[`size-candidate.txt`](size-candidate.txt),
[`section-accounting.txt`](section-accounting.txt), and
[`source-audit.txt`](source-audit.txt).

## Direct Oracle And Timing

The committed-source harness first checks the bounded canonicalizer for all
8,322 possible input integers. It then compares the old materialize-and-encode
expression with the fused direct encoder over 16,384 deterministic random
canonical transforms and four boundary patterns. Every d4 output byte is
identical.

Ratios below are baseline time divided by candidate time.

| Boundary | Paired gmean | 95% CI | Paired median | Ratio of medians | Wins |
|---|---:|---:|---:|---:|---:|
| Inverse final, message/noise add, and d4 encode | 1.055840910x | 1.053636058x-1.058125057x | 1.054844903x | 1.054675038x | 31/31 |

Candidate-first and baseline-first medians are `1.054260387x` and
`1.055253393x`, so the result is not explained by run order. This establishes
a 5.58% focused gain in the affected operation. It is not a broad KEM speed
claim. See [`direct-inverse-final-d4-31x2m.txt`](direct-inverse-final-d4-31x2m.txt)
and [`direct-inverse-final-d4-harness.c`](direct-inverse-final-d4-harness.c).

## Product Regression Gate

Three independent batches use fixed baseline and candidate product objects and
one byte-identical benchmark harness. Every process confirms that the normal
and `*_core` metrics are equal because the product API disables internal
caches. All samples, including the visibly disturbed first batch, are retained.

| Operation | Batch 1 | Batch 2 | Batch 3 | Combined 48-pair gmean |
|---|---:|---:|---:|---:|
| Keygen | 0.994845182x | 1.001577138x | 1.003188961x | 0.999863887x |
| Encaps | 0.996443958x | 1.004234096x | 1.000345218x | 1.000336035x |
| Decaps | 0.993200011x | 1.012407335x | 0.994912697x | 1.000135840x |
| Roundtrip | 0.994580279x | 1.006942854x | 0.999499599x | 1.000328012x |

The minimum combined operation ratio is `1.000135840x`, above the internal
`0.995x` regression floor. Every product confidence interval includes 1.0, so
these measurements are used only as no-regression evidence and no broad KEM
gain is credited.

The product timing was collected before the implementation commit from the
accepted temporary source copy. Its product-object SHA differs from the clean
commit because the ELF symbol/build-id metadata records a different source
filename. The complete product disassembly is byte-identical with SHA-256
`15e60899a50f992052370a42570b2ecee6c30b4d85f6bb1e6d30eb2679a5bce9`,
and the linked benchmark disassembly is likewise identical with SHA-256
`ad7cb7d0c62a3f91ac6a775a13beea95df76a342d0d4faf17469d78a4a9fa59c`.
The direct 31-pair result above was rerun from the committed worktree itself.

See [`product-ab-combined-48x100k.txt`](product-ab-combined-48x100k.txt),
the three `product-ab-batch*-16x100k.txt` files, and
[`artifact-identity.txt`](artifact-identity.txt).

## Correctness And Isolation

The exact implementation commit passes:

- GCC and Clang native, AVX2-only, and scalar KAT, production API, and complete
  1,000-iteration stage-oracle validation;
- Clang AVX2 ASan+UBSan KAT, directly linked production API, and complete
  stage-oracle validation with no diagnostics;
- all 16 core, product, upstream, and PQClean corpus paths, each producing
  381,228 bytes with SHA-256
  `e4d8f908f9a3c59171deeed712925760b194d692b0c571861f204eabef976b67`;
- byte-identical products in all five non-target compiler/profile builds;
- Clang and GCC NTT-root generator reproducibility;
- the same KEM API and unresolved `bcmp`, `memcpy`, and `memset` symbols;
- no AVX512 register or symbol in the AVX2-only product; and
- a non-executable GNU stack declaration.

The clean post-commit build reproduces the validated product hash, size, and
stage sink. See [`correctness-matrix.txt`](correctness-matrix.txt),
[`sanitizers.txt`](sanitizers.txt),
[`cross-path-corpus.txt`](cross-path-corpus.txt),
[`abi-audit.txt`](abi-audit.txt), [`ntt-roots.txt`](ntt-roots.txt), and
[`postcommit-smoke.txt`](postcommit-smoke.txt).

## Stack

Eight guarded alternate-stack runs are unchanged:

| Operation | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Keygen | 4,512 B | 4,512 B | 0 B |
| Encaps | 4,144 B | 4,144 B | 0 B |
| Decaps valid | 4,512 B | 4,512 B | 0 B |
| Decaps invalid | 4,512 B | 4,512 B | 0 B |
| Maximum | 4,512 B | 4,512 B | 0 B |

See [`stack.txt`](stack.txt) and the two raw stack reports.

## Rejected Alternatives

Pairwise direct packing with the general signed canonicalizer reduced primary
size by only 19 bytes and regressed the direct boundary to `0.989778375x`, with
one win in nine pairs. Processing four vectors per batch grew primary size by
951 bytes and measured `0.995635061x`, with three wins in nine pairs. Omitting
canonicalization entirely failed the exhaustive domain oracle at input 6,762.
All three forms were removed. See
[`rejected-candidates.txt`](rejected-candidates.txt).

## Dependency Boundary

The accepted change links no external object or runtime library and adds no
persistent cache, benchmark cache, runtime dispatch, API, table, algorithm, or
wire-format dependency. It changes only repository-local lifetime scheduling,
bounded reduction, and packing in an existing ciphertext path. Production and
direct benchmarks use the independent core with internal caches disabled.

## Remaining Goal Gap

Using the pinned same-method comparator sizes, the Clang AVX2-only deficit to
OpenSSL falls from 5,798 to 5,741 bytes. The unchanged native deficit to
mlkem-native remains 18,425 bytes. The required ten-comparator speed and size
gates have not been rerun on this same revision, and both primary-size gates
still fail. This commit therefore does not complete the optimization Goal.

## Reproduction

```bash
make clean
make -j"$(nproc)" product test-product CC=clang \
  ARCH_CFLAGS="-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f"
./product_testc
./scripts/measure_product_size.sh baby_mlkem768_product.o

clang -O3 -fno-semantic-interposition -fvisibility=hidden \
  -fomit-frame-pointer -fno-stack-protector -falign-loops=64 \
  -fno-unwind-tables -fno-asynchronous-unwind-tables \
  -fno-strict-aliasing -march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt \
  -mno-avx512f \
  benchmarks/2026-08-08-clang-avx2-inverse-final-d4-fusion/direct-inverse-final-d4-harness.c \
  ntt_roots_avx2_constants.S -o /tmp/direct-inverse-final-d4
/tmp/direct-inverse-final-d4 base 1
/tmp/direct-inverse-final-d4 candidate 1

RUNS=16 WARMUP_RUNS=3 RUN_ORDER=alternating SUITES=product \
  KEM_ITERS=100000 PIN_CPU=0 C_COMPILER=clang \
  ARCH_CFLAGS="-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f" \
  ./scripts/bench_core_ab.sh 85e0cb3

STACK_RUNS=8 STACK_USABLE_BYTES=1048576 C_COMPILER=clang \
  STACK_CFLAGS='-O2 -march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f -fomit-frame-pointer -fno-stack-protector' \
  ./scripts/measure_stack_highwater.sh baby_mlkem768_product.o local

JOBS="$(nproc)" ./scripts/verify_cross_path_corpus.sh
make check-ntt-roots HOSTCC=clang
make check-ntt-roots HOSTCC=gcc
```

Run the A/B command three times to reproduce the 48-pair regression gate.
File integrity for this directory is recorded in `checksums.sha256`.
