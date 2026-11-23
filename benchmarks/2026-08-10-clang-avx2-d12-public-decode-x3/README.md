# Clang AVX2 d12 Public Decode x3

Commit `7219cad508ae199475d8b1cc2a2f0404479991b7` routes the three
contiguous public-key d12 polynomials in Clang AVX2-only public preparation
through the linear x3 decoder introduced by
`975d2e2d5651c302c895097e9670738582ec8302`. The intervening commit changes
documentation only and produces the same baseline product.

`kpke_prepare_public_no_cache` previously retained three copies of the
256-coefficient decoder, including three loop boundaries and three masked
tails. The accepted path decodes 47 ordinary 24-byte blocks and one masked
24-byte tail at offset 1,128. It consumes exactly the 1,152-byte polynomial
prefix of the fixed 1,184-byte K-PKE public key; the following 32-byte `rho`
seed is not read. The shuffle, nibble selection, 12-bit mask, output order, and
wire representation are unchanged.

## Environment

- CPU: AMD Ryzen Threadripper 7980X 64-Cores.
- Clang: Ubuntu Clang 18.1.3.
- GCC: Ubuntu GCC 13.3.0.
- Linker: GNU ld 2.42.
- Product KEM: CPU 0, three batches, three warmup pairs and sixteen measured
  pairs per batch, 100,000 iterations, alternating order.

Exact flags, kernel, microcode, governor, commits, and run settings are in
[`environment.txt`](environment.txt).

## Production Size

Both artifacts use the normal production/no-cache speed flags. Primary size
is allocatable executable plus read-only data.

| Profile | Compiler | Baseline | Candidate | Delta | Candidate code | Candidate read-only | Candidate writable |
|---|---|---:|---:|---:|---:|---:|---:|
| AVX2-only | Clang | 50,096 B | 49,712 B | -384 B | 42,157 B | 7,555 B | 26,593 B |

The complete linked reduction is isolated to one section:

| Component | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| `kpke_prepare_public_no_cache` | 3,976 B | 3,592 B | -384 B |
| Net code | 42,541 B | 42,157 B | -384 B |
| Read-only data | 7,555 B | 7,555 B | 0 B |
| Net primary | 50,096 B | 49,712 B | -384 B |

All twenty-two other text sections and all fifteen read-only sections are
byte-identical, including `baby_mlkem768_decaps`. Writable storage is
unchanged. The clean committed product has SHA-256
`827f362023df33ba047637df373b28eee9349448e9becc419b882570fabb792a`.

See [`size.txt`](size.txt), [`size-baseline.txt`](size-baseline.txt),
[`size-candidate.txt`](size-candidate.txt), and
[`section-accounting.txt`](section-accounting.txt).

## Decoder Oracle

The decoder body is unchanged from the preceding secret-key optimization. Its
standalone oracle compares scalar, three-single-polynomial, and linear x3 forms
for all 4,096 d12 values, 16,384 deterministic random objects, and four
boundary patterns. All 20,484 cases, or 15,731,712 decoded coefficients per
implementation, are identical. The fixed baseline and candidate functions are
589 and 205 bytes.

The retained 15-pair focused run measured `1.002636199x` by paired geometric
mean, with a `1.001756681x..1.003511678x` interval and 14/15 wins. This proves
the reused decoder itself did not slow down in that run, but the integrated KEM
result below is the acceptance gate and no speed gain is credited.

See [`direct-validation.txt`](direct-validation.txt),
[`direct-d12-x3-15x50m.txt`](direct-d12-x3-15x50m.txt), and
[`direct-d12-x3-harness.c`](direct-d12-x3-harness.c).

## Product Regression Gate

Baseline and candidate product objects are fixed for all 48 measured pairs.
Both binaries link the same benchmark object with SHA-256
`dbb898fba2eaea946e24274382339f6622b8234918377e085850d8ef84f49985`.
Every process confirms that normal and `*_core` metrics are equal because the
product API disables internal caches. Every sample is retained.

| Operation | Batch 1 | Batch 2 | Batch 3 | Combined 48 | 95% CI |
|---|---:|---:|---:|---:|---:|
| Keygen | 1.002393383x | 0.999281160x | 1.001114085x | 1.000928728x | 0.997970111x-1.003720796x |
| Encaps | 1.002277113x | 0.997612315x | 1.002657769x | 1.000846434x | 0.997314976x-1.004110953x |
| Decaps | 0.999239678x | 0.993661094x | 0.996197004x | 0.996363316x | 0.988424301x-1.004046282x |
| Roundtrip | 1.002616735x | 0.997099008x | 0.999968033x | 0.999892053x | 0.996848415x-1.002918432x |

The minimum combined operation is decapsulation at `0.996363316x`, above the
internal `0.995x` point-estimate floor. Decapsulation's product section is
byte-identical, and its paired median is `1.000754917x`; the lower geometric
mean comes from the same discrete process modes observed in the preceding
report. Confidence intervals include 1.0 for every operation. The target
encapsulation result is also neutral, so this report credits no broad or
operation-level speed improvement.

See [`product-ab-combined-48x100k.txt`](product-ab-combined-48x100k.txt), the
three `product-ab-batch*-16x100k.txt` files,
[`product-ab-screen-18x50k.txt`](product-ab-screen-18x50k.txt), and
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

LeakSanitizer alone is disabled because it cannot run under this environment's
ptrace restriction; AddressSanitizer and UndefinedBehaviorSanitizer remain
enabled. The clean post-commit build reproduces the timed product hash, size,
and stage sink.

See [`correctness-matrix.txt`](correctness-matrix.txt),
[`sanitizers.txt`](sanitizers.txt),
[`cross-path-corpus.txt`](cross-path-corpus.txt),
[`abi-audit.txt`](abi-audit.txt), [`ntt-roots.txt`](ntt-roots.txt), and
[`postcommit-smoke.txt`](postcommit-smoke.txt).

The machine-checkable audit is [`verify-evidence.sh`](verify-evidence.sh); its
retained successful output is [`evidence-check.txt`](evidence-check.txt).

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

## Rejected Broader Routing

Routing the decapsulation-side public-key decode through the same helper as
well reduced primary size by 766 bytes to 49,330 bytes. Its retained 18-pair
50,000-iteration screen put decapsulation at `0.990293311x`, below the floor,
so that second call-site change was removed. The accepted product's entire
decapsulation section is therefore byte-identical to the baseline. See
[`rejected-both-public-sites-18x50k.txt`](rejected-both-public-sites-18x50k.txt).

## Dependency Boundary

The accepted change links no external object or runtime library and adds no
persistent cache, benchmark cache, runtime dispatch, API, table, algorithm, or
wire-format dependency. It reuses repository-local AVX2 d12 extraction
arithmetic only at the existing cache-disabled public preparation boundary.

## Remaining Goal Gap

Using the pinned same-method comparator sizes, the Clang AVX2-only deficit to
OpenSSL falls from 5,047 to 4,663 bytes. The unchanged native deficit to
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
  benchmarks/2026-08-10-clang-avx2-d12-public-decode-x3/direct-d12-x3-harness.c \
  -o /tmp/direct-d12-public-x3
/tmp/direct-d12-public-x3 validate

RUNS=16 WARMUP_RUNS=3 RUN_ORDER=alternating SUITES=product \
  KEM_ITERS=100000 PIN_CPU=0 C_COMPILER=clang \
  ARCH_CFLAGS="-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f" \
  ./scripts/bench_core_ab.sh 975d2e2

STACK_RUNS=8 STACK_USABLE_BYTES=1048576 C_COMPILER=clang \
  STACK_CFLAGS='-O2 -march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f -fomit-frame-pointer -fno-stack-protector' \
  ./scripts/measure_stack_highwater.sh baby_mlkem768_product.o local

JOBS="$(nproc)" ./scripts/verify_cross_path_corpus.sh
make check-ntt-roots HOSTCC=clang
make check-ntt-roots HOSTCC=gcc
```

Run the A/B command three times to reproduce the 48-pair regression gate. File
integrity for this directory is recorded in
[`checksums.sha256`](checksums.sha256).
