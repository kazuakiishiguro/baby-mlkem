# Clang Static NTT Root Tables (2026-08-07)

This report evaluates commit `cfd2b097c0de0f5b92b1e7558db4aaf0f73b6b8d`
against its parent `ce4707cc14de49e1eafbea133982c3e3c5cf1dcb`. The
change replaces Clang's runtime NTT-root expansion and readiness branch with
generated immutable constants. GCC retains the previous cold runtime
initializer because pre-expanded constants enlarge its LTO products.

This is an internal optimization report plus an OpenSSL-only size diagnostic.
It is not the ten-comparator size gate or either all-comparator speed gate.

## Environment

- CPU: AMD Ryzen Threadripper 7980X 64-Cores
- Microcode: `0xa108108`
- OS: Ubuntu 24.04.4 LTS, Linux 6.8.0-124-generic x86-64
- Clang: Ubuntu Clang 18.1.3
- GCC: GCC 13.3.0
- Native flags: the normal compiler-specific speed flags plus `-march=native`
- AVX2-only ISA flags: `-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f`
- Product policy: deterministic ML-KEM-768 APIs with internal caches disabled

## Implementation

`scripts/generate_ntt_constants.c` independently derives all scalar, AVX2,
and AVX512 root and Montgomery-factor tables. `make check-ntt-roots` regenerates
the checked-in header and compares it byte for byte. GCC and Clang generator
builds both produced `ntt_roots_generated.h` with SHA-256
`4d1e3c560ce96b7897ff234e9fc9bc89dcb8d1da764a7393a79a94b390334f11`.

The inverse Montgomery tables omit unused matrix slots. Each Clang table stores
38 vectors rather than a padded 6-by-8 matrix: eight vectors for each of levels
0 through 3, four for level 4, and two for level 5. Tests derive all 128 `ZETA`
and `GAMMA` entries with independent bit-reversal and modular-exponentiation
helpers rather than reusing the generator implementation.

## Product Size

Primary footprint is allocatable code plus read-only data. Ratios and deltas
below are candidate minus parent.

| Profile | Compiler | Parent code | Parent read-only | Parent primary | Candidate code | Candidate read-only | Candidate primary | Primary change |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| native | Clang | 100,630 B | 5,305 B | 105,935 B | 83,112 B | 20,373 B | 103,485 B | -2,450 B (-2.31%) |
| AVX2-only | Clang | 68,130 B | 5,513 B | 73,643 B | 56,031 B | 12,743 B | 68,774 B | -4,869 B (-6.61%) |
| native | GCC | 56,006 B | 3,565 B | 59,571 B | 56,006 B | 3,565 B | 59,571 B | byte-identical |
| AVX2-only | GCC | 51,429 B | 3,809 B | 55,238 B | 51,429 B | 3,809 B | 55,238 B | byte-identical |

For completeness, the candidate scalar products measure 62,229 B code plus
2,033 B read-only data, or 64,262 B primary, with Clang; GCC measures 21,530 B
code plus 1,737 B read-only data, or 23,267 B primary.

Clang native zero-fill storage falls from 31,954 B to 18,001 B, a 13,953 B
reduction. AVX2-only zero-fill falls from 34,850 B to 28,641 B, a 6,209 B
reduction. The immutable tables move live bytes to read-only storage while
removing more initializer code and mutable capacity than they add.

Product artifact SHA-256:

| Profile | Parent | Candidate |
|---|---|---|
| Clang native | `a0dca1b194f82022263a956ea2e7df302b6f0b9aa6a55ffc0a476d2e1918b8e1` | `e1d33f3360d21207fb7197d0ab1c6d7e98013b93c70b60b2cfa57ff170d47d30` |
| Clang AVX2-only | `63251ade0bb1798d88b3c2244cf0cba60235a72e7369162c9bdbb8e13ac83a30` | `444d0a9afb6b949c17e384b41aab401fad229412c9d8d0a21b1eb1b95eb7ffca` |
| GCC native, both revisions | `76cb2e25b1f7860268de66a191534f677ec44655a07444e94b7d9cb93e9377c0` | same |
| GCC AVX2-only, both revisions | `b73dcab0e87e6bf0938c4ea3c864d5734ab0e433c823ede01e10c860c8a25c5a` | same |

The GCC benchmark executables are also byte-identical: native SHA-256
`79d893cf9aba4a43a0990cbb1cea1d5b59c034209bc931686363c19c1c9c283d`
and AVX2-only SHA-256
`b557e447685f56950ed568e2ddc49f8ad140cff3f485d97b3b37c8c3c7104b4d`.
This establishes exactly zero GCC performance change without relying on a
noisy timing estimate.

## Stack

The guarded alternate-stack probe used eight input runs and both sentinel
patterns. It includes cold and warm keygen plus valid and invalid decapsulation.

| Profile | Operation | Parent | Candidate | Change |
|---|---|---:|---:|---:|
| native | keygen | 11,640 B | 8,696 B | -2,944 B |
| native | encaps | 8,568 B | 8,568 B | 0 B |
| native | decaps valid/invalid | 10,040 B | 10,040 B | 0 B |
| native | maximum | 11,640 B | 10,040 B | -1,600 B |
| AVX2-only | keygen | 4,832 B | 4,832 B | 0 B |
| AVX2-only | encaps | 4,640 B | 4,512 B | -128 B |
| AVX2-only | decaps valid/invalid | 5,856 B | 5,856 B | 0 B |
| AVX2-only | maximum | 5,856 B | 5,856 B | 0 B |

## Internal Speed A/B

The exact `bench_productc` artifacts were pinned to CPU 0 and compared over 15
paired 100,000-iteration runs after three warmups, alternating execution order.
The paired geometric-mean interval uses 20,000 deterministic bootstrap samples.
Ratios are `parent time / candidate time`; values below one indicate a
candidate regression. The internal operation acceptance floor is `0.995x`.

| Profile | Operation | Geometric mean | Paired 95% CI | Wins | Result |
|---|---|---:|---:|---:|---|
| native | keygen | 1.0089x | 1.0062x-1.0112x | 14/15 | PASS |
| native | encaps | 1.0073x | 1.0028x-1.0138x | 14/15 | PASS |
| native | decaps | 0.9987x | 0.9864x-1.0115x | 10/15 | PASS, 0.13% regression |
| native | roundtrip | 1.0060x | 1.0022x-1.0101x | 12/15 | PASS |
| AVX2-only | keygen | 1.0102x | 1.0010x-1.0212x | 11/15 | PASS |
| AVX2-only | encaps | 1.0112x | 1.0041x-1.0192x | 13/15 | PASS |
| AVX2-only | decaps | 1.0067x | 0.9949x-1.0146x | 13/15 | PASS |
| AVX2-only | roundtrip | 1.0085x | 1.0023x-1.0141x | 13/15 | PASS |

Candidate benchmark SHA-256 is
`9d35dcf7fb69719b96478cc7369dd7ea85d69fb2eb9b70270d54e3e10bc25bde`
native and
`e0e17272fe12616c4519eb732129428e8b2ce99af58beb503c743b2a7ba78eae`
AVX2-only. The checked-in metric files contain all 15 values used by each
report.

## Correctness

The final compiler split passed:

- GCC and Clang native, AVX2-only, and scalar KEM/KAT tests.
- Product roundtrip and implicit-rejection smoke tests in all six builds.
- Complete stage-oracle validation in all six builds.
- Clang native ASan+UBSan KAT and complete stage-oracle validation.
- GCC native UBSan KAT and complete stage-oracle validation.
- All 16 cross-path corpus variants, each 381,228 bytes with SHA-256
  `e4d8f908f9a3c59171deeed712925760b194d692b0c571861f204eabef976b67`.

Complete stage sinks were `5236638352469415403` native,
`8086079251842987743` AVX2-only, and `3075663932904715540` scalar for both
compilers.

## OpenSSL-Only Diagnostic

The normalized internal-core OpenSSL verifier was rerun at the candidate commit
against clean OpenSSL commit
`def638aa2d6895d36648cbccfb16444e24311683`. Repository update was skipped, so
these runs are current-candidate diagnostics rather than a fresh authoritative
ten-comparator completion run.

| Profile | baby-mlkem primary | OpenSSL primary | Primary delta | baby-mlkem stack | OpenSSL stack | OpenSSL-only size gate |
|---|---:|---:|---:|---:|---:|---|
| native | 103,485 B | 103,552 B | -67 B | 10,040 B | 9,624 B | PASS |
| AVX2-only | 68,774 B | 45,049 B | +23,725 B | 5,856 B | 9,112 B | FAIL |

The native OpenSSL primary gap is closed, but the 67-byte margin is small. The
AVX2-only production footprint remains the immediate size bottleneck.

## Reproduction

```bash
make check-ntt-roots HOSTCC=clang
make check-ntt-roots HOSTCC=gcc

JOBS="$(nproc)" ./scripts/verify_cross_path_corpus.sh

PROFILE=native C_COMPILER=clang \
  OPENSSL_DIR=/tmp/baby-mlkem-goal-comparators/openssl-native-current \
  UPDATE_REPOS=0 SIZE_ENFORCE=0 \
  REPORT_FILE=/tmp/goal-openssl-native-cfd2b09.txt \
  ./scripts/verify_goal_openssl_size.sh

PROFILE=avx2 C_COMPILER=clang \
  OPENSSL_DIR=/tmp/baby-mlkem-goal-comparators/openssl-native-current \
  UPDATE_REPOS=0 SIZE_ENFORCE=0 \
  REPORT_FILE=/tmp/goal-openssl-avx2-cfd2b09.txt \
  ./scripts/verify_goal_openssl_size.sh
```

## Decision

The compiler-specific static-root optimization is accepted. It reduces both
required Clang production footprints, improves aggregate speed, does not exceed
the 0.5% operation-regression limit, and leaves GCC exactly unchanged. The Goal
remains open because AVX2-only is still 23,725 bytes larger than OpenSSL and the
full ten-comparator size and post-change speed gates have not been rerun.
