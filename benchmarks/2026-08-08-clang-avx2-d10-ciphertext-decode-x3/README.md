# Clang AVX2 d10 Ciphertext Decode x3

Commit `db9a20853e05a78110fc585ce7414f91f96bb6e2` gives the
Clang AVX2-only decapsulation path one private loop for all three d10
ciphertext polynomials. Its baseline is
`ed3b9dc73b9ed7ccd2fda4b63bb985e1fc3c7a46`.

Clang previously expanded the 256-coefficient decode/decompress loop three
times inside `baby_mlkem768_decaps`. The accepted helper receives the enclosing
three-polynomial output object and walks all 768 coefficients in one loop. It
keeps the existing byte shuffle and exact 16-bit decompression identity.

`kpke_decrypt` checks the complete ciphertext length before entering this
path. The three d10 polynomials occupy the first 960 bytes, and the final
unaligned vector load remains within the following d4 ciphertext bytes of the
fixed 1,088-byte input. Passing the enclosing output array, rather than a
pointer to its first subarray, also makes the byte-wise traversal cover one
declared object. ASan+UBSan validates the complete path.

## Environment

- CPU: AMD Ryzen Threadripper 7980X 64-Cores.
- Clang: Ubuntu Clang 18.1.3.
- GCC: Ubuntu GCC 13.3.0.
- Linker: GNU ld 2.42.
- Product KEM: CPU 0, three batches, three warmup pairs and sixteen measured
  pairs per batch, 100,000 iterations, alternating order.
- Direct x3 decode: CPU 0, thirty-one alternating pairs, 5,000,000 calls after
  10,000 warmup calls in each process.

Exact flags, kernel, microcode, governor, commits, and run settings are in
[`environment.txt`](environment.txt).

## Production Size

Both artifacts use the normal production/no-cache speed flags. Primary size
is allocatable executable plus read-only data.

| Profile | Compiler | Baseline | Candidate | Delta | Candidate code | Candidate read-only | Candidate writable |
|---|---|---:|---:|---:|---:|---:|---:|
| AVX2-only | Clang | 50,790 B | 50,480 B | -310 B | 42,925 B | 7,555 B | 26,593 B |

The linked change decomposes as follows:

| Component | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| `baby_mlkem768_decaps` | 4,397 B | 3,949 B | -448 B |
| `decompress_decode_poly_d10_ct_x3_avx2` | 0 B | 139 B | +139 B |
| Net code | 43,234 B | 42,925 B | -309 B |
| Compiler read-only pools | 7,556 B | 7,555 B | -1 B |
| Net primary | 50,790 B | 50,480 B | -310 B |

All twenty-one common text sections outside decapsulation are byte-identical.
Decapsulation changes, and one private helper section is added. Compiler pool
contents move because the three expanded copies disappear; their net size
falls one byte. The clean committed product has SHA-256
`7cc168832d6f820e7ae1cd0e1d8fc01a80aa0a503042635ac574db1c7c2fd0d8`.

See [`size.txt`](size.txt), [`size-baseline.txt`](size-baseline.txt),
[`size-candidate.txt`](size-candidate.txt), and
[`section-accounting.txt`](section-accounting.txt).

## Direct Oracle And Timing

The standalone harness first packs and checks all 1,024 possible d10 values.
It then compares scalar, three-expanded-loop, and one-x3-loop forms over 16,384
deterministic random ciphertexts and four boundary patterns. All 17,412 cases,
or 13,372,416 decoded coefficients per implementation, are identical.

The direct model emits a 396-byte baseline function and a 137-byte candidate
function. The linked production helper is 139 bytes because its single caller
lets Clang specialize the output address. Ratios below are baseline time
divided by candidate time.

| Boundary | Paired gmean | 95% CI | Paired median | Ratio of medians | Wins |
|---|---:|---:|---:|---:|---:|
| Three d10 ciphertext polynomials | 1.001924793x | 0.998669572x-1.005368036x | 0.999156632x | 1.000234032x | 15/31 |

Candidate-first and baseline-first medians are `0.997566054x` and
`1.006761522x`. The confidence interval includes 1.0 and the order split is
large, so no focused speed gain is credited. Its lower bound remains above the
`0.995x` direct no-regression floor.

See [`direct-validation.txt`](direct-validation.txt),
[`direct-d10-x3-31x5m.txt`](direct-d10-x3-31x5m.txt), and
[`direct-d10-x3-harness.c`](direct-d10-x3-harness.c).

## Product Regression Gate

Baseline and candidate product objects are fixed for all 96 measured
processes. Both binaries link the same benchmark object with SHA-256
`dbb898fba2eaea946e24274382339f6622b8234918377e085850d8ef84f49985`.
Every process confirms that normal and `*_core` metrics are equal because the
product API disables internal caches. Every sample is retained.

| Operation | Batch 1 | Batch 2 | Batch 3 | Combined 48-pair gmean |
|---|---:|---:|---:|---:|
| Keygen | 1.000577641x | 0.996722745x | 0.998851975x | 0.998716209x |
| Encaps | 1.003145543x | 0.994726149x | 1.000957595x | 0.999603391x |
| Decaps | 1.009238704x | 0.992067036x | 0.998727134x | 0.999986005x |
| Roundtrip | 1.002278044x | 0.998304414x | 1.001210493x | 1.000596241x |

The minimum combined operation ratio is keygen at `0.998716209x`, above the
internal `0.995x` point-estimate floor. Confidence intervals include 1.0, and
the source change does not affect three of the four operations. These results
are no-regression evidence only; no broad KEM gain is credited.

The candidate object timed above has the same SHA-256 as the clean
implementation commit. See
[`product-ab-combined-48x100k.txt`](product-ab-combined-48x100k.txt), the three
`product-ab-batch*-16x100k.txt` files, and
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

The clean post-commit build reproduces the timed product hash, size, and stage
sink. See [`correctness-matrix.txt`](correctness-matrix.txt),
[`sanitizers.txt`](sanitizers.txt),
[`cross-path-corpus.txt`](cross-path-corpus.txt),
[`abi-audit.txt`](abi-audit.txt), [`ntt-roots.txt`](ntt-roots.txt), and
[`postcommit-smoke.txt`](postcommit-smoke.txt). The mechanical evidence audit
is recorded in [`evidence-check.txt`](evidence-check.txt).

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

Calling one ordinary helper three times reduced primary size by 248 bytes, but
the direct d10 boundary fell to `0.9875x` and the nine-pair product decaps
gmean fell to `0.9940x`. A safe nested x3 helper passed its 15-pair product
screen but retained 89 more primary bytes than the complete-array linear loop.
Both forms were removed. See [`rejected-candidates.txt`](rejected-candidates.txt).

## Dependency Boundary

The accepted change links no external object or runtime library and adds no
persistent cache, benchmark cache, runtime dispatch, API, table, algorithm, or
wire-format dependency. It only shares existing repository-local decode and
decompression arithmetic across the three fixed ciphertext polynomials.

## Remaining Goal Gap

Using the pinned same-method comparator sizes, the Clang AVX2-only deficit to
OpenSSL falls from 5,741 to 5,431 bytes. The unchanged native deficit to
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
  benchmarks/2026-08-08-clang-avx2-d10-ciphertext-decode-x3/direct-d10-x3-harness.c \
  -o /tmp/direct-d10-x3
/tmp/direct-d10-x3 validate
/tmp/direct-d10-x3 base 5000000
/tmp/direct-d10-x3 candidate 5000000

RUNS=16 WARMUP_RUNS=3 RUN_ORDER=alternating SUITES=product \
  KEM_ITERS=100000 PIN_CPU=0 C_COMPILER=clang \
  ARCH_CFLAGS="-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f" \
  ./scripts/bench_core_ab.sh ed3b9dc

STACK_RUNS=8 STACK_USABLE_BYTES=1048576 C_COMPILER=clang \
  STACK_CFLAGS='-O2 -march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f -fomit-frame-pointer -fno-stack-protector' \
  ./scripts/measure_stack_highwater.sh baby_mlkem768_product.o local

JOBS="$(nproc)" ./scripts/verify_cross_path_corpus.sh
make check-ntt-roots HOSTCC=clang
make check-ntt-roots HOSTCC=gcc
```

Run the A/B command three times to reproduce the 48-pair regression gate.
File integrity for this directory is recorded in
[`checksums.sha256`](checksums.sha256).
