# Clang AVX2 Shared Scalar Matrix Refill

Commit `36cbd84354ef47d12141474a9de71bc8400a1ae8` shares the rare
scalar SHAKE128 continuation used by six Clang AVX2 matrix-sampling call
sites. Its baseline is
`3a3e9d021069b92daaead7890935852f584235d1`.

Each caller still performs the same vectorized first three SHAKE128 rates and
the same rejection parsing. Only a lane that remains short after those rates
crosses a private 60-byte compact boundary for subsequent scalar Keccak and
parsing. The helper preserves the state, output, accepted-coefficient count,
rate, and loop condition.

The helper is selected only inside the AVX2 implementation for Clang builds
without AVX512F. Native AVX512, GCC, and scalar products retain their prior
code. This is repository-local code-layout work: it changes no sampling
arithmetic, cache, external object, runtime library, table, API, algorithm,
or wire format.

## Environment

- CPU: AMD Ryzen Threadripper 7980X 64-Cores.
- Clang: Ubuntu Clang 18.1.3.
- GCC: Ubuntu GCC 13.3.0.
- Linker: GNU ld 2.42.
- Stage runs: CPU 0, two warmup pairs, nine alternating measured pairs per
  batch, two independent batches, 30,000 iterations.
- KEM runs: CPU 0, three warmup pairs, sixteen alternating measured pairs per
  batch, two independent batches, 100,000 iterations.

Exact flags, kernel, microcode, governor, commits, timestamps, and raw-run
times are in [`environment.txt`](environment.txt).

## Production Size

All products use the normal production/no-cache speed flags.

| Profile | Compiler | Baseline primary | Candidate primary | Delta | Candidate code | Candidate read-only | Candidate writable |
|---|---|---:|---:|---:|---:|---:|---:|
| native | Clang | 73,048 B | 73,048 B | 0 B | 53,409 B | 19,639 B | 18,001 B |
| AVX2-only | Clang | 59,307 B | 56,328 B | -2,979 B | 44,607 B | 11,721 B | 26,593 B |
| scalar | Clang | 62,193 B | 62,193 B | 0 B | 60,160 B | 2,033 B | 18,944 B |
| native | GCC | 59,571 B | 59,571 B | 0 B | 56,006 B | 3,565 B | 33,728 B |
| AVX2-only | GCC | 53,614 B | 53,614 B | 0 B | 49,829 B | 3,785 B | 34,920 B |
| scalar | GCC | 23,267 B | 23,267 B | 0 B | 21,530 B | 1,737 B | 19,488 B |

Clang AVX2 code falls by 2,635 bytes and compiler-generated read-only data by
344 bytes. The four changed caller sections save 2,695 bytes before adding
the 60-byte helper:

| Text section | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| `sample_ntt4` | 4,014 B | 3,239 B | -775 B |
| `mlkem_keygen_noise2_sample_matrix2_avx2` | 3,648 B | 2,776 B | -872 B |
| `hash_matrix_x3_parse_group` | 1,791 B | 799 B | -992 B |
| `mlkem_encrypt_prf_cbd_eta2_32_sample_tail_avx2` | 4,402 B | 4,346 B | -56 B |
| shared refill helper | 0 B | 60 B | +60 B |
| Net code | - | - | -2,635 B |

The accepted product has SHA-256
`b995a643dc4b884f5202f79213d6c70fcb77bfe5f3411224f81e7aaa75e2f704`.
The measured candidate and final clean rebuild are byte-identical. All five
non-target compiler/profile products are byte-identical to the baseline. See
the seven raw size reports, [`section-accounting.txt`](section-accounting.txt),
[`artifact-identity.txt`](artifact-identity.txt), and
[`final-smoke.txt`](final-smoke.txt).

## Valid KEM Regression Gate

Two independent Clang AVX2-only batches each used three warmup pairs and
sixteen alternating-order measured pairs of 100,000 iterations. Ratios are
baseline time divided by candidate time. Equal-size batches are combined
geometrically.

| Operation | Batch 1 | Batch 2 | Combined 32-pair gmean |
|---|---:|---:|---:|
| Decaps | 1.0073x | 1.0002x | 1.003744x |
| Decaps core | 1.0126x | 1.0015x | 1.007035x |
| Encaps | 0.9959x | 1.0064x | 1.001136x |
| Encaps core | 0.9949x | 1.0100x | 1.002422x |
| Keygen | 0.9978x | 1.0036x | 1.000696x |
| Keygen core | 0.9991x | 1.0044x | 1.001746x |
| Roundtrip | 0.9998x | 1.0025x | 1.001149x |
| Roundtrip core | 1.0037x | 1.0059x | 1.004799x |

The minimum combined result is `1.000696x`, above the `0.995x` internal
operation-regression floor. Timing movement is used only as no-regression
evidence; no KEM speed gain is credited. See
[`kem-combined.txt`](kem-combined.txt) and the two raw KEM reports.

## Stage Screen

The two focused nine-pair stage batches give these equal-weight combined
geometric means:

| Stage | Combined 18-pair gmean |
|---|---:|
| Matrix sample | 0.997392x |
| Matrix sample with scalar refill | 0.997750x |
| Keygen matrix and noise | 1.003344x |
| Complete K-PKE keygen | 1.001598x |
| Public-key preparation without cache | 1.004047x |
| Complete cached encryption | 1.000150x |
| Complete uncached encryption | 1.000950x |

The second diagnostic batch reports `0.9748x`/`0.9717x` geometric means for
cached/uncached decryption even though their medians are `0.9992x`/`0.9981x`.
Those unchanged product sections are not callers of the new helper, and the
subsequent 32-pair KEM decapsulation results are `1.003744x` and `1.007035x`.
The stage excursion is retained as raw evidence rather than interpreted as an
affected-path regression. See [`stage-combined.txt`](stage-combined.txt) and
the two raw stage reports.

## Refill Coverage

Instrumented Clang AVX2 KAT execution calls the helper five times but does not
need an additional rate. The complete stage harness calls it 845 times and
executes the refill loop 140 times, proving both the common no-refill return
and the rare continuation body. The stage sink remains
`8086079251842987743`. See [`refill-coverage.txt`](refill-coverage.txt) and
the raw coverage excerpts.

## Stack

Eight guarded alternate-stack runs leave the 4,544-byte maximum unchanged:

| Operation | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Keygen | 4,544 B | 4,544 B | 0 B |
| Encaps | 4,352 B | 4,176 B | -176 B |
| Decaps valid | 4,512 B | 4,512 B | 0 B |
| Decaps invalid | 4,512 B | 4,512 B | 0 B |
| Maximum | 4,544 B | 4,544 B | 0 B |

See [`stack.txt`](stack.txt).

## Rejected Native Candidate

A separate Clang-native compact x3 wrapper for secret-key d12 decoding reduced
primary size by 873 bytes, from 73,048 to 72,175 bytes. It was removed because
the nine-pair stage screen put cached and uncached decryption at `0.9769x` and
`0.9766x`, with zero wins in both rows. See
[`rejected-candidates.txt`](rejected-candidates.txt) and the two raw files
prefixed with `rejected-secret-d12-`.

## Correctness And Isolation

The exact implementation commit passed:

- GCC and Clang native, AVX2-only, and scalar KAT, production API, and complete
  stage-oracle validation.
- Clang AVX2 ASan+UBSan and GCC AVX2 UBSan KAT, directly linked production
  API, and complete stage validation.
- All 16 core, product, upstream, and PQClean corpus paths, each producing
  381,228 bytes with SHA-256
  `e4d8f908f9a3c59171deeed712925760b194d692b0c571861f204eabef976b67`.
- Clang and GCC NTT-root generator reproducibility plus generator ASan+UBSan.
- The same three exported KEM functions and the same unresolved runtime
  symbols as the parent.
- No AVX512 register or symbol in the AVX2-only product and a non-executable
  stack declaration.
- Byte-identical products for all five non-target compiler/profile builds.

See [`correctness-matrix.txt`](correctness-matrix.txt),
[`sanitizers.txt`](sanitizers.txt),
[`cross-path-corpus.txt`](cross-path-corpus.txt),
[`ntt-roots.txt`](ntt-roots.txt), [`abi-audit.txt`](abi-audit.txt), and
[`source-audit.txt`](source-audit.txt).

## Remaining Size Gap

Using the pinned same-method OpenSSL AVX2-only size of 45,049 bytes, the AVX2
deficit falls from 14,258 to 11,279 bytes. The unchanged native mlkem-native
deficit remains 21,862 bytes. This is not a complete same-revision
ten-comparator size or speed rerun, and both production-size gates still fail.
This commit therefore does not complete the overall optimization Goal.

## Reproduction

```bash
make clean
make -j"$(nproc)" product test-product CC=clang \
  ARCH_CFLAGS="-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f"
./scripts/measure_product_size.sh baby_mlkem768_product.o

STACK_RUNS=8 STACK_USABLE_BYTES=1048576 C_COMPILER=clang \
  STACK_CFLAGS='-O2 -march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt \
  -mno-avx512f -fomit-frame-pointer -fno-stack-protector' \
  ./scripts/measure_stack_highwater.sh baby_mlkem768_product.o local

RUNS=16 WARMUP_RUNS=3 RUN_ORDER=alternating SUITES=kem \
  KEM_ITERS=100000 PIN_CPU=0 C_COMPILER=clang \
  ARCH_CFLAGS="-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f" \
  ./scripts/bench_core_ab.sh 3a3e9d0

JOBS="$(nproc)" ./scripts/verify_cross_path_corpus.sh
make check-ntt-roots HOSTCC=clang
make check-ntt-roots HOSTCC=gcc
```

Run the A/B command twice to reproduce the 32-pair combined gate. File
integrity for this directory is recorded in `checksums.sha256`.
