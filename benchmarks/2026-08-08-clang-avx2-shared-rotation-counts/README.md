# Clang AVX2 Shared Keccak Rotation Counts

Commit `66bfaaa4a48b190e0ad697fab6c958e4b9f2eab8` makes two outlined
single-state Keccak permutations share one rotation-count table in the Clang
AVX2-only production core. Its baseline is
`baece397146f1c40fac2cc9c14523e7657c8229b`.

Clang previously folded the same twelve 256-bit rotation-count vectors into
both the generic permutation and the fixed 1,184-byte H(pk) permutation. The
two compiler-local copies occupied 384 bytes each. A Clang AVX2-only volatile
vector load now keeps the existing six left-count and six right-count source
vectors materialized once instead of constant-propagating them independently
into both outlined functions. Other compilers and ISA profiles retain the
ordinary intrinsic load.

This changes only compiler-local constant representation. The seven-YMM state
layout and round mapping remain the XKCP/CRYPTOGAMS-derived implementation
identified in `keccakf1600_avx2.h` and `THIRD_PARTY_NOTICES.md`. This report
does not claim that schedule as a baby-mlkem invention.

## Environment

- CPU: AMD Ryzen Threadripper 7980X 64-Cores.
- Clang: Ubuntu Clang 18.1.3.
- GCC: Ubuntu GCC 13.3.0.
- Linker: GNU ld 2.42.
- Product KEM: CPU 0, three warmup pairs, sixteen alternating measured pairs,
  100,000 iterations.
- Generic Keccak: CPU 0, four warmup pairs, thirty-one alternating pairs,
  1,000,000 permutations.
- Fixed H(pk): CPU 0, four warmup pairs, thirty-one alternating pairs,
  100,000 fixed 1,184-byte hashes.

Exact flags, kernel, microcode, governor, commits, and run settings are in
[`environment.txt`](environment.txt).

## Production Size

Both artifacts use the normal production/no-cache speed flags. Primary size
is allocatable executable plus read-only data.

| Profile | Compiler | Baseline primary | Candidate primary | Delta | Candidate code | Candidate read-only | Candidate writable |
|---|---|---:|---:|---:|---:|---:|---:|
| AVX2-only | Clang | 52,651 B | 52,195 B | -456 B | 44,459 B | 7,736 B | 26,593 B |

The linked section change decomposes as follows:

| Component | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Generic `mlkem_keccakf1600_avx2` code | 1,004 B | 1,013 B | +9 B |
| Fixed `sha3_256_1184_avx2` code | 1,770 B | 1,721 B | -49 B |
| Compiler `.rodata.cst32` | 4,512 B | 3,712 B | -800 B |
| Named left/right rotation tables | 0 B | 384 B | +384 B |
| Net code | 44,499 B | 44,459 B | -40 B |
| Net read-only | 8,152 B | 7,736 B | -416 B |
| Net primary | 52,651 B | 52,195 B | -456 B |

The logical rotation vectors fall from two byte-identical 384-byte sets to
one 384-byte set. The additional 32-byte linked read-only reduction comes
from constant-pool layout and alignment. The accepted product has SHA-256
`86f0f636e8cf18b7db4e8c74fb4b8f3ae258a0450eead10f3c683bcd1d655d45`.

See [`size-baseline.txt`](size-baseline.txt),
[`size-candidate.txt`](size-candidate.txt),
[`section-accounting.txt`](section-accounting.txt),
[`source-audit.txt`](source-audit.txt), and
[`artifact-identity.txt`](artifact-identity.txt).

## Direct Timing

Ratios are baseline time divided by candidate time.

| Boundary | Paired gmean | 95% CI | Paired median | Ratio of medians | Wins |
|---|---:|---:|---:|---:|---:|
| Generic Keccak | 1.0021x | 0.9967x-1.0077x | 0.9987x | 0.9985x | 6/31 |
| Fixed 1,184-byte H(pk) | 1.0069x | 1.0062x-1.0075x | 1.0069x | 1.0070x | 31/31 |

The generic permutation is neutral. The fixed hash improves consistently,
which is compatible with its 49-byte smaller body and shared constant working
set, but that explanation is an inference from code generation and timing,
not a hardware-counter result.

See [`direct-stats.txt`](direct-stats.txt),
[`direct-generic-keccak-31x1m.txt`](direct-generic-keccak-31x1m.txt),
[`direct-fixed-hash-31x100k.txt`](direct-fixed-hash-31x100k.txt),
[`direct-keccak-harness.c`](direct-keccak-harness.c), and
[`fixed-hash-harness.c`](fixed-hash-harness.c).

## Product Regression Gate

| Operation | Paired gmean | Paired median | Wins |
|---|---:|---:|---:|
| Decaps core | 0.9994x | 1.0014x | 10/16 |
| Encaps core | 1.0009x | 0.9993x | 7/16 |
| Keygen core | 1.0109x | 1.0047x | 13/16 |
| Roundtrip core | 1.0029x | 1.0014x | 10/16 |

The minimum operation geometric mean is `0.9994x`, above the `0.995x`
internal regression floor. Key generation improves in this batch, but the
other complete-KEM operations are neutral, so no broad KEM speed gain is
credited. See [`kem-product-16x100k.txt`](kem-product-16x100k.txt).

## Correctness And Isolation

The exact implementation source passes:

- GCC and Clang native, AVX2-only, and scalar KAT, production API, and complete
  1,000-iteration stage-oracle validation;
- Clang AVX2 ASan+UBSan KAT, directly linked production API, and complete
  stage-oracle validation;
- all 16 core, product, upstream, and PQClean corpus paths, each producing
  381,228 bytes with SHA-256
  `e4d8f908f9a3c59171deeed712925760b194d692b0c571861f204eabef976b67`;
- byte-identical Clang native/scalar and GCC native/AVX2/scalar products;
- Clang and GCC NTT-root generator reproducibility;
- the same three public KEM symbols and unresolved `bcmp`, `memcpy`, and
  `memset` symbols;
- no AVX512 register or symbol in the AVX2-only product; and
- a non-executable GNU stack declaration.

The clean post-commit build reproduces the validated Clang AVX2 artifact hash
and 52,195-byte primary footprint. See
[`correctness-matrix.txt`](correctness-matrix.txt),
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

See [`stack.txt`](stack.txt).

## Rejected Alternatives

The apparent keygen/encryption x4 Keccak duplication is already one 1,457-byte
ELF body exposed through two local aliases. An external assembly-table variant
saved 384 read-only bytes but added 369 code bytes, reducing primary size by
only 15 bytes. Both directions were rejected in favor of the source-table
form. See [`rejected-candidates.txt`](rejected-candidates.txt).

## Dependency Boundary

The accepted change links no external object or runtime library and adds no
persistent cache, benchmark cache, runtime dispatch, API, algorithm, or wire-
format dependency. It only changes how Clang materializes constants already in
the repository-local core. The underlying Keccak schedule remains explicitly
third-party-derived and attributed.

## Remaining Goal Gap

Using the pinned same-method comparator sizes, the Clang AVX2-only deficit to
OpenSSL falls from 7,602 to 7,146 bytes. The unchanged native deficit to
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

RUNS=16 WARMUP_RUNS=3 RUN_ORDER=alternating SUITES=product \
  KEM_ITERS=100000 PIN_CPU=0 C_COMPILER=clang \
  ARCH_CFLAGS="-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f" \
  ./scripts/bench_core_ab.sh baece39

STACK_RUNS=8 STACK_USABLE_BYTES=1048576 C_COMPILER=clang \
  STACK_CFLAGS='-O2 -march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f -fomit-frame-pointer -fno-stack-protector' \
  ./scripts/measure_stack_highwater.sh baby_mlkem768_product.o local

JOBS="$(nproc)" ./scripts/verify_cross_path_corpus.sh
make check-ntt-roots HOSTCC=clang
make check-ntt-roots HOSTCC=gcc
```

File integrity for this directory is recorded in `checksums.sha256`.
