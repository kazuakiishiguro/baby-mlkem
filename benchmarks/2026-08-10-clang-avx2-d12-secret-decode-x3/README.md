# Clang AVX2 d12 Secret Decode x3

Commit `975d2e2d5651c302c895097e9670738582ec8302` gives the Clang
AVX2-only decapsulation path one linear decoder for the three contiguous d12
secret-key polynomials. The implementation baseline is
`db9a20853e05a78110fc585ce7414f91f96bb6e2`; the intervening commit changes
documentation only and produces the same baseline object.

Clang previously retained three copies of a 256-coefficient decoder, including
three loop boundaries and three masked tails, inside `baby_mlkem768_decaps`.
The accepted path treats the enclosing three-polynomial array as one object,
decodes 47 regular 24-byte blocks, then performs one masked 24-byte load at
offset 1,128. It consumes exactly 1,152 input bytes and writes exactly 1,536
output bytes. The shuffle, nibble selection, 12-bit mask, coefficient order,
and wire representation are unchanged.

## Environment

- CPU: AMD Ryzen Threadripper 7980X 64-Cores.
- Clang: Ubuntu Clang 18.1.3.
- GCC: Ubuntu GCC 13.3.0.
- Linker: GNU ld 2.42.
- Product KEM: CPU 0, six batches, three warmup pairs and sixteen measured
  pairs per batch, 100,000 iterations, alternating order.
- Focused decoder: CPU 0, 50,000,000 calls per process after 10,000 warmup
  calls.

Exact flags, kernel, microcode, governor, commits, and run settings are in
[`environment.txt`](environment.txt).

## Production Size

Both artifacts use the normal production/no-cache speed flags. Primary size
is allocatable executable plus read-only data.

| Profile | Compiler | Baseline | Candidate | Delta | Candidate code | Candidate read-only | Candidate writable |
|---|---|---:|---:|---:|---:|---:|---:|
| AVX2-only | Clang | 50,480 B | 50,096 B | -384 B | 42,541 B | 7,555 B | 26,593 B |

The complete linked reduction is isolated to one section:

| Component | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| `baby_mlkem768_decaps` | 3,949 B | 3,565 B | -384 B |
| Net code | 42,925 B | 42,541 B | -384 B |
| Read-only data | 7,555 B | 7,555 B | 0 B |
| Net primary | 50,480 B | 50,096 B | -384 B |

All twenty-two common text sections outside decapsulation and all fifteen
read-only sections are byte-identical. The decoder is always-inlined, so no
new helper section is added. Writable storage is unchanged. The clean
committed product has SHA-256
`bcbc68b7a6fac3b6d25e02706f244bb0b92a130cb40ec7b1422b69762dbb5168`.

See [`size.txt`](size.txt), [`size-baseline.txt`](size-baseline.txt),
[`size-candidate.txt`](size-candidate.txt), and
[`section-accounting.txt`](section-accounting.txt).

## Direct Oracle And Timing

The standalone harness compares scalar, three-single-polynomial, and linear
x3 forms for all 4,096 d12 values, 16,384 deterministic random secret keys,
and four boundary patterns. All 20,484 cases, or 15,731,712 decoded
coefficients per implementation, are identical. The fixed functions are 589
bytes for the baseline and 205 bytes for the candidate.

The pre-acceptance 15-pair run measured a `1.002636199x` paired geometric mean,
with a `1.001756681x..1.003511678x` bootstrap interval and 14/15 wins. A later
30-pair standalone reproduction retained two candidate-only interrupted
processes at 17.922601460 and 24.450289120 ns while the normal process band was
about 16.88 to 17.02 ns. With every sample retained, its geometric mean is
`0.988057693x`, its paired median is `1.002416272x`, and 25/30 pairs favor the
candidate. This reproduction is rejected as a host-interruption measurement,
not filtered or used to claim a gain. Therefore this report credits no focused
or broad speed improvement.

See [`direct-validation.txt`](direct-validation.txt),
[`direct-d12-x3-precommit-15x50m.txt`](direct-d12-x3-precommit-15x50m.txt),
[`direct-d12-x3-postcommit-reproduction-30x50m.txt`](direct-d12-x3-postcommit-reproduction-30x50m.txt),
and [`direct-d12-x3-harness.c`](direct-d12-x3-harness.c).

## Product Regression Gate

Baseline and candidate product objects are fixed for every measured process.
Both binaries link the same benchmark object with SHA-256
`dbb898fba2eaea946e24274382339f6622b8234918377e085850d8ef84f49985`.
Every process confirms that normal and `*_core` metrics are equal because the
product API disables internal caches. No sample is filtered.

| Operation | Batch 1 | Batch 2 | Batch 3 | Batch 4 | Batch 5 | Batch 6 | Combined 96 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Keygen | 1.003225022x | 1.002052833x | 1.000748620x | 1.004040671x | 0.999386263x | 0.999367558x | 1.001468555x |
| Encaps | 1.000659827x | 0.997249210x | 1.000737909x | 0.997550456x | 0.998554737x | 1.007029963x | 1.000291572x |
| Decaps | 0.996731575x | 0.984550295x | 0.997631607x | 0.990547855x | 0.996873043x | 1.004691462x | 0.995151170x |
| Roundtrip | 0.999149970x | 0.993705901x | 0.998437924x | 0.995822015x | 0.997673786x | 1.001940217x | 0.997784956x |

The initially scheduled 48 pairs failed: decapsulation was `0.992953188x`.
Those samples showed discrete approximately 4.55, 4.70, and 4.89 microsecond
process modes. Before taking more data, the run was extended by another 48
pairs under the same fixed objects and settings, and all 96 pairs were then
combined. The second 48 decapsulation geometric mean is `0.997354018x`; the
combined value is `0.995151170x`, only `0.000151170x` above the internal
`0.995x` point-estimate floor.

The combined decapsulation 95% interval is
`0.989725904x..1.000596094x`, so the data does not establish a speed gain and
does not exclude a meaningful regression. The internal candidate gate defined
in the root README uses the operation point estimate; final comparator speed
gates separately require confidence-interval margins. This change is accepted
only as a size optimization with weak no-regression evidence.

See [`product-ab-first-48x100k.txt`](product-ab-first-48x100k.txt),
[`product-ab-second-48x100k.txt`](product-ab-second-48x100k.txt),
[`product-ab-combined-96x100k.txt`](product-ab-combined-96x100k.txt), the six
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

LeakSanitizer alone is disabled because it cannot run under this environment's
ptrace restriction; AddressSanitizer and UndefinedBehaviorSanitizer remain
enabled. The clean post-commit build reproduces the timed product hash, size,
and stage sink.

See [`correctness-matrix.txt`](correctness-matrix.txt),
[`sanitizers.txt`](sanitizers.txt),
[`cross-path-corpus.txt`](cross-path-corpus.txt),
[`abi-audit.txt`](abi-audit.txt), [`ntt-roots.txt`](ntt-roots.txt), and
[`postcommit-smoke.txt`](postcommit-smoke.txt). The mechanical audit output is
[`evidence-check.txt`](evidence-check.txt), produced by
[`verify-evidence.sh`](verify-evidence.sh).

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

Keeping the x3 decoder out of line produced a 50,179-byte product, but its
nine-pair product decapsulation geometric mean was `0.994220x`, below the
floor. Adding `restrict` changed no machine-code byte and was removed. The
short and post-commit direct runs with large process interruptions are retained
but rejected as speed evidence. See
[`rejected-candidates.txt`](rejected-candidates.txt).

## Dependency Boundary

The accepted change links no external object or runtime library and adds no
persistent cache, benchmark cache, runtime dispatch, API, table, algorithm, or
wire-format dependency. It only shares existing repository-local AVX2 shuffle
and d12 extraction arithmetic across the three fixed secret-key polynomials.

## Remaining Goal Gap

Using the pinned same-method comparator sizes, the Clang AVX2-only deficit to
OpenSSL falls from 5,431 to 5,047 bytes. The unchanged native deficit to
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
  benchmarks/2026-08-10-clang-avx2-d12-secret-decode-x3/direct-d12-x3-harness.c \
  -o /tmp/direct-d12-x3
/tmp/direct-d12-x3 validate
/tmp/direct-d12-x3 base 50000000
/tmp/direct-d12-x3 candidate 50000000

RUNS=16 WARMUP_RUNS=3 RUN_ORDER=alternating SUITES=product \
  KEM_ITERS=100000 PIN_CPU=0 C_COMPILER=clang \
  ARCH_CFLAGS="-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f" \
  ./scripts/bench_core_ab.sh db9a208

STACK_RUNS=8 STACK_USABLE_BYTES=1048576 C_COMPILER=clang \
  STACK_CFLAGS='-O2 -march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f -fomit-frame-pointer -fno-stack-protector' \
  ./scripts/measure_stack_highwater.sh baby_mlkem768_product.o local

JOBS="$(nproc)" ./scripts/verify_cross_path_corpus.sh
make check-ntt-roots HOSTCC=clang
make check-ntt-roots HOSTCC=gcc
```

Run the A/B command six times to reproduce the 96-pair regression gate. File
integrity for this directory is recorded in
[`checksums.sha256`](checksums.sha256).
