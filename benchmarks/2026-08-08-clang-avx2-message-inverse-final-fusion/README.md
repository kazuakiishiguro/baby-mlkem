# Clang AVX2 Message/Inverse-Final Fusion

Commit `3a93975f17001c03f3a3671d57b6c9ea531803e3` fuses the message
addition into the inverse-NTT final add in the Clang AVX2-only production
core. Its baseline is `3d435b70434b4c5dba10a7c5cd240c2a1936d7c8`.

The baseline first materialized
`canonical(e2 + message)` across all 256 coefficients, then performed the
inverse final scale and materialized
`canonical(inverse_final(v) + previous_result)`. The accepted path computes
the equivalent modular expression
`canonical(inverse_final(v) + e2 + message)` in one pass. This removes one
complete read/write traversal of `e2` and one canonicalization from the fixed
32-byte ML-KEM encryption path.

The three terms are each bounded before the final reduction: inverse-final
scale and `e2` are in `[0,3328]`, and the message term is either 0 or 1,665.
Their largest sum is 8,321, below `INT16_MAX`. The fallback for a non-32-byte
private input remains unchanged.

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
| AVX2-only | Clang | 51,773 B | 50,847 B | -926 B | 43,293 B | 7,554 B | 26,593 B |

The linked change decomposes as follows:

| Component | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| `kpke_encrypt_finish_avx2` | 4,802 B | 3,900 B | -902 B |
| Net code | 44,195 B | 43,293 B | -902 B |
| Compiler read-only pools | 7,578 B | 7,554 B | -24 B |
| Net primary | 51,773 B | 50,847 B | -926 B |

All twenty-one common text sections outside the changed caller are
byte-identical, and no text section is added. The read-only delta is a 16-byte
reduction in `.rodata.cst16` and an 8-byte reduction in `.rodata.cst8`;
`.rodata` and `.rodata.cst32` change content without changing size. The
accepted product has SHA-256
`b7d3a42108f5442c6a177133b7e1e5357d6f5b0a14d8f107d0baa720a6c5bffa`.

See [`size-baseline.txt`](size-baseline.txt),
[`size-candidate.txt`](size-candidate.txt),
[`section-accounting.txt`](section-accounting.txt),
[`source-audit.txt`](source-audit.txt), and
[`artifact-identity.txt`](artifact-identity.txt).

## Direct Oracle And Timing

The report harness first checks the AVX2 canonicalizer for every integer from
0 through 8,321. It then compares the old two-pass expression with the fused
expression over 16,384 deterministic random canonical transforms and four
boundary patterns. Every output is byte-identical.

Ratios below are baseline time divided by candidate time.

| Boundary | Paired gmean | 95% CI | Paired median | Ratio of medians | Wins |
|---|---:|---:|---:|---:|---:|
| Inverse final plus `e2` and message | 1.0584x | 1.0560x-1.0609x | 1.0589x | 1.0594x | 31/31 |

The baseline-first and candidate-first medians are 1.0571x and 1.0596x, so
the result is not explained by run order. This establishes a 5.84% focused
gain in the affected operation. It is not a broad KEM speed claim. See
[`direct-fused-message-final-31x2m.txt`](direct-fused-message-final-31x2m.txt)
and
[`direct-fused-message-final-harness.c`](direct-fused-message-final-harness.c).

## Product Regression Gate

Three independent batches use fixed baseline and candidate product objects
and one byte-identical benchmark harness. The product API disables internal
caches, so each normal operation value is exactly its `*_core` value. Ratios
below are geometric means over unrounded paired ratios.

| Operation | Batch 1 | Batch 2 | Batch 3 | Combined 48-pair gmean |
|---|---:|---:|---:|---:|
| Keygen | 1.0061x | 1.0019x | 1.0076x | 1.005197725x |
| Encaps | 1.0043x | 1.0019x | 1.0042x | 1.003486551x |
| Decaps | 0.9925x | 1.0093x | 1.0053x | 1.002353694x |
| Roundtrip | 0.9998x | 1.0045x | 1.0048x | 1.003048456x |

The minimum combined operation ratio is `1.002353694x`, above the internal
`0.995x` regression floor. Several product confidence intervals include 1.0,
so these measurements are used only as no-regression evidence and no broad
KEM gain is credited. All 96 processes also pass the normal/core alias check.

See [`product-ab-combined-48x100k.txt`](product-ab-combined-48x100k.txt)
and the three `product-ab-batch*-16x100k.txt` files.

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

The clean post-commit build reproduces the validated artifact hash, size, and
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

Removing the now-constant `mlen` parameter and source branch produced
identical machine-code disassembly and the same 51,773-byte primary size;
Clang had already eliminated that condition interprocedurally. Outlining the
accepted fused body with `noinline,minsize` produced a 51,233-byte product,
386 bytes larger than the accepted inline layout, so it was rejected before
timing. See [`rejected-candidates.txt`](rejected-candidates.txt).

## Dependency Boundary

The accepted change links no external object or runtime library and adds no
persistent cache, benchmark cache, runtime dispatch, API, table, algorithm, or
wire-format dependency. It changes only the repository-local scheduling of an
existing modular expression. The production and direct benchmarks use the
independent core with internal caches disabled.

## Remaining Goal Gap

Using the pinned same-method comparator sizes, the Clang AVX2-only deficit to
OpenSSL falls from 6,724 to 5,798 bytes. The unchanged native deficit to
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
  benchmarks/2026-08-08-clang-avx2-message-inverse-final-fusion/direct-fused-message-final-harness.c \
  ntt_roots_avx2_constants.S \
  -o /tmp/direct-fused-message-final
/tmp/direct-fused-message-final base 1
/tmp/direct-fused-message-final candidate 1

RUNS=16 WARMUP_RUNS=3 RUN_ORDER=alternating SUITES=product \
  KEM_ITERS=100000 PIN_CPU=0 C_COMPILER=clang \
  ARCH_CFLAGS="-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f" \
  ./scripts/bench_core_ab.sh 3d435b7

STACK_RUNS=8 STACK_USABLE_BYTES=1048576 C_COMPILER=clang \
  STACK_CFLAGS='-O2 -march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f -fomit-frame-pointer -fno-stack-protector' \
  ./scripts/measure_stack_highwater.sh baby_mlkem768_product.o local

JOBS="$(nproc)" ./scripts/verify_cross_path_corpus.sh
make check-ntt-roots HOSTCC=clang
make check-ntt-roots HOSTCC=gcc
```

Run the A/B command three times to reproduce the 48-pair combined gate. File
integrity for this directory is recorded in `checksums.sha256`.
