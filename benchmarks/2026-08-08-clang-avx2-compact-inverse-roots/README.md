# Clang AVX2 Compact Inverse-NTT Roots

Commit `36a773f0388d1c264cb413181ae3b8cfda0401b6` changes how the
Clang AVX2-only core stores inverse-NTT Montgomery factors. Its baseline is
`93c1b0932497f55fe3d0a3297d95db979500ac74`.

The baseline C header contains 38 low and 38 high `__m256i` vectors. The first
24 vectors are lane-shaped factors for inverse levels 0..2. The remaining 14
vectors are uniform splats for levels 3..5. Clang retained the complete
2,432-byte C tables and also emitted 1,408 bytes of function-local `cst32`
operands.

The candidate generates a repository-local assembly object with:

- the 24 non-uniform low vectors and 24 non-uniform high vectors;
- fourteen 16-bit low factors and fourteen 16-bit high factors for the uniform
  levels; and
- hidden ELF visibility and a non-executable stack declaration.

The inverse body still loads the non-uniform factors as vectors and still uses
`vpbroadcastw` for every uniform factor. Keeping the latter scalar avoids the
full-vector load regression observed in the rejected candidates. The assembly
and header come from the same `scripts/generate_ntt_constants.c` arithmetic and
are both checked by `make check-ntt-roots`.

This path is selected only for x86-64 ELF Clang builds with AVX2 and without
AVX512F. It adds no external library, external cryptographic runtime object,
third-party implementation, cache, runtime dispatch, API, algorithm, or wire
format. Native AVX512, GCC, and scalar products remain byte-identical.

## Environment

- CPU: AMD Ryzen Threadripper 7980X 64-Cores.
- Clang: Ubuntu Clang 18.1.3.
- GCC: Ubuntu GCC 13.3.0.
- Linker: GNU ld 2.42.
- Stage: CPU 0, two warmup pairs, nine alternating measured pairs per batch,
  two batches, 30,000 iterations.
- KEM: CPU 0, three warmup pairs, sixteen alternating measured pairs per
  batch, two batches, 100,000 iterations.

Exact flags, kernel, microcode, governor, commits, and run settings are in
[`environment.txt`](environment.txt).

## Production Size

All products use the normal production/no-cache speed flags.

| Profile | Compiler | Baseline primary | Candidate primary | Delta | Candidate code | Candidate read-only | Candidate writable |
|---|---|---:|---:|---:|---:|---:|---:|
| native | Clang | 73,048 B | 73,048 B | 0 B | 53,409 B | 19,639 B | 18,001 B |
| AVX2-only | Clang | 56,328 B | 54,150 B | -2,178 B | 44,701 B | 9,449 B | 26,593 B |
| scalar | Clang | 62,193 B | 62,193 B | 0 B | 60,160 B | 2,033 B | 18,944 B |
| native | GCC | 59,571 B | 59,571 B | 0 B | 56,006 B | 3,565 B | 33,728 B |
| AVX2-only | GCC | 53,614 B | 53,614 B | 0 B | 49,829 B | 3,785 B | 34,920 B |
| scalar | GCC | 23,267 B | 23,267 B | 0 B | 21,530 B | 1,737 B | 19,488 B |

The size change decomposes exactly as follows:

| Component | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Inverse function code | 3,416 B | 3,510 B | +94 B |
| Dense/scalar inverse tables | 2,432 B | 1,592 B | -840 B |
| Compiler-local `.rodata.cst32` | 5,920 B | 4,512 B | -1,408 B |
| Other `.rodata` | 136 B | 112 B | -24 B |
| Net primary | 56,328 B | 54,150 B | -2,178 B |

The accepted product has SHA-256
`d732f4858aa8675acbfb496f5963317426d7aeea9f7a8a26b0044d41c343ebcc`.
See [`size-baseline.txt`](size-baseline.txt),
[`size-candidate.txt`](size-candidate.txt),
[`section-accounting.txt`](section-accounting.txt), and
[`artifact-identity.txt`](artifact-identity.txt).

## KEM Regression Gate

Ratios are baseline time divided by candidate time. The two equal-size batches
are combined geometrically.

| Operation | Batch 1 | Batch 2 | Combined 32-pair gmean |
|---|---:|---:|---:|
| Decaps | 0.9906x | 1.0031x | 0.996830x |
| Decaps core | 0.9981x | 1.0143x | 1.006167x |
| Encaps | 0.9928x | 1.0012x | 0.996991x |
| Encaps core | 0.9940x | 1.0025x | 0.998241x |
| Keygen | 0.9931x | 1.0081x | 1.000572x |
| Keygen core | 0.9958x | 1.0069x | 1.001335x |
| Roundtrip | 0.9921x | 1.0049x | 0.998479x |
| Roundtrip core | 0.9952x | 1.0082x | 1.001679x |

The first batch moved broadly against the candidate, including key generation,
which does not call the changed inverse transform. The independent second
batch moved in the opposite direction. The combined minimum is `0.996830x`,
above the `0.995x` internal operation-regression floor. No speed gain is
credited.

See [`kem-combined.txt`](kem-combined.txt),
[`kem-batch1-16x100k.txt`](kem-batch1-16x100k.txt), and
[`kem-batch2-16x100k.txt`](kem-batch2-16x100k.txt).

## Stage Screen

The directly affected and complete K-PKE rows combine as follows:

| Stage | Combined 18-pair gmean |
|---|---:|
| Decrypt accumulator plus inverse | 0.999200x |
| Inverse butterflies | 1.000149x |
| Encrypt accumulator plus inverse | 0.997446x |
| Encrypt inverse `u` path | 0.997049x |
| Encrypt inverse `v` path | 0.998646x |
| Complete cached encryption | 0.999300x |
| Complete uncached encryption | 0.999100x |
| Complete cached decryption | 1.009713x |
| Complete uncached decryption | 1.012128x |
| Complete K-PKE key generation | 1.025748x |

The selected minimum is `0.997049x`. The raw reports retain every exploratory
micro-stage row rather than filtering unrelated timing excursions. See
[`stage-combined.txt`](stage-combined.txt),
[`stage-batch1-9x30k.txt`](stage-batch1-9x30k.txt), and
[`stage-batch2-9x30k.txt`](stage-batch2-9x30k.txt).

## Generated-Factor Identity

An independent extractor read the first 24 vectors and the first lane of each
uniform vector from the legacy header representation. Its 1,592 output bytes
are byte-identical to the four assembly sections:

```text
legacy_sha256=713b1a535b7ff9c958a61a9bf21cdf470f7340e5bb374be7e75994ac9f617ff3
assembly_sha256=713b1a535b7ff9c958a61a9bf21cdf470f7340e5bb374be7e75994ac9f617ff3
```

Clang and GCC generate identical header and assembly files. The generator also
passes ASan+UBSan, rejects an unknown output mode, and survives a forced
parallel dependency-regeneration build. See [`ntt-roots.txt`](ntt-roots.txt)
and [`build-regeneration.txt`](build-regeneration.txt).

## Correctness And Isolation

The implementation commit passes:

- GCC and Clang native, AVX2-only, and scalar KAT, production API, and complete
  stage-oracle validation;
- Clang AVX2 ASan+UBSan and GCC AVX2 UBSan KAT, directly linked production API,
  and complete stage validation;
- all 16 core, product, upstream, and PQClean corpus paths, each producing
  381,228 bytes with SHA-256
  `e4d8f908f9a3c59171deeed712925760b194d692b0c571861f204eabef976b67`;
- the same three KEM API functions and unresolved runtime symbols as the
  baseline;
- no AVX512 register or symbol in the AVX2-only product; and
- a non-executable GNU stack declaration.

See [`correctness-matrix.txt`](correctness-matrix.txt),
[`sanitizers.txt`](sanitizers.txt),
[`cross-path-corpus.txt`](cross-path-corpus.txt),
[`abi-audit.txt`](abi-audit.txt), [`source-audit.txt`](source-audit.txt), and
the exact-commit [`final-smoke.txt`](final-smoke.txt).

## Stack

Eight guarded alternate-stack runs leave every operation unchanged:

| Operation | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Keygen | 4,544 B | 4,544 B | 0 B |
| Encaps | 4,176 B | 4,176 B | 0 B |
| Decaps valid | 4,512 B | 4,512 B | 0 B |
| Decaps invalid | 4,512 B | 4,512 B | 0 B |
| Maximum | 4,544 B | 4,544 B | 0 B |

See [`stack.txt`](stack.txt), [`stack-baseline.txt`](stack-baseline.txt), and
[`stack-candidate.txt`](stack-candidate.txt).

## Rejected Candidates

A volatile full-vector table reached 54,927 bytes but failed the stage screen:
`encrypt_accum_inv` was `0.9846x` with zero wins and cached encryption was
`0.9890x`. A hidden full 38-vector assembly table reached 54,890 bytes but
changed the fourteen uniform factors from broadcasts to full-vector loads and
was not advanced. See [`rejected-candidates.txt`](rejected-candidates.txt) and
the retained
[`rejected-volatile-full-table-stage-9x30k.txt`](rejected-volatile-full-table-stage-9x30k.txt).

## Remaining Size Gap

Using the pinned same-method OpenSSL AVX2-only size of 45,049 bytes, the Clang
AVX2 primary deficit falls from 11,279 to 9,101 bytes. The unchanged native
mlkem-native deficit remains 21,862 bytes. This is not a complete same-revision
ten-comparator size or speed rerun, so both size gates and the overall
optimization Goal remain incomplete.

## Reproduction

```bash
make clean
make -j"$(nproc)" product test-product CC=clang \
  ARCH_CFLAGS="-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f"
./scripts/measure_product_size.sh baby_mlkem768_product.o

make check-ntt-roots HOSTCC=clang
make check-ntt-roots HOSTCC=gcc

RUNS=16 WARMUP_RUNS=3 RUN_ORDER=alternating SUITES=kem \
  KEM_ITERS=100000 PIN_CPU=0 C_COMPILER=clang \
  ARCH_CFLAGS="-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f" \
  ./scripts/bench_core_ab.sh 93c1b09

JOBS="$(nproc)" ./scripts/verify_cross_path_corpus.sh
```

Run the A/B command twice to reproduce the 32-pair combined gate. File
integrity for this directory is recorded in `checksums.sha256`.
