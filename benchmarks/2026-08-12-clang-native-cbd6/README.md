# Clang Native Six-Way CBD Widening

Date: 2026-08-12

Baseline: `91aa1d7`

Candidate: `b90b5fb`

## Change

The Clang native AVX512/BW/DQ six-output ETA2 CBD path now widens decoded
signed bytes directly into 16-bit coefficient vectors and stores them with
ZMM-to-YMM stores. The previous path materialized each 32-byte result in a
stack buffer and reused AVX2 signed stores. The output representation,
centered range, PRF inputs, NTT inputs, API, and wire format are unchanged.

This is a narrow native compiler/code-layout optimization. It adds no cache,
external object, runtime library, API, algorithm, table, or wire-format
dependency. The benchmark is not credited as a speed gain: the decapsulation
geometric mean is below the repository speed-credit floor, although its paired
median remains above the floor.

## Environment And Build

- Compiler: Ubuntu Clang 18.1.3; GCC cross-check 13.3.0.
- Host: AMD Ryzen Threadripper 7980X 64-Cores, x86-64 Linux.
- Timing: CPU 0, 15 alternating baseline/candidate pairs, 100,000 iterations
  per process.
- Product artifacts: `BABY_MLKEM_DISABLE_INTERNAL_CACHES`.
- Architecture: `-march=native` for the native product.
- Product flags: `-O3 -fno-semantic-interposition -fvisibility=hidden
  -fomit-frame-pointer -fno-stack-protector -falign-loops=64
  -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-strict-aliasing`.

The ratio is `baseline ns/op / candidate ns/op`; values above `1.0x` favor the
candidate. Raw process output is in
[`product-ab-15x100k.txt`](product-ab-15x100k.txt). The build and profile
identities are recorded in [`size-baseline.txt`](size-baseline.txt),
[`size-candidate.txt`](size-candidate.txt), [`stack.txt`](stack.txt), and
[`profile-identity.txt`](profile-identity.txt).

## Product Size

`Primary` is executable code plus read-only data. Writable storage and the
relocatable artifact are reported separately.

| Quantity | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Product code | 49,822 B | 49,525 B | -297 B |
| Read-only data | 16,198 B | 16,262 B | +64 B |
| Primary | 66,020 B | 65,787 B | -233 B |
| Writable storage | 18,001 B | 18,001 B | 0 B |
| Relocatable artifact | 93,560 B | 93,360 B | -200 B |
| Keypair export symbol | 0x820 (2,080 B) | 0x820 (2,080 B) | 0 B |

The primary footprint falls by 0.35%. The maximum stack high-water remains
`8,056 B` for valid and invalid decapsulation.

## Product A/B

| Operation | Gmean | Paired median | Wins |
|---|---:|---:|---:|
| Keygen | `1.000451x` | `1.000243x` | 8/15 |
| Encaps | `1.001074x` | `0.999258x` | 6/15 |
| Decaps | `0.992701x` | `0.997385x` | 4/15 |
| Roundtrip | `1.000785x` | `0.999257x` | 7/15 |

The paired medians remain above the repository's `0.995x` size-optimization
floor, but decapsulation's geometric mean is below it because the run is
outlier-sensitive. Consequently this report credits only the 233-byte primary
size reduction and makes no speed or full no-regression claim.

The parent and candidate products are byte-identical for the standard Clang
AVX2-only, Clang scalar, and GCC native profiles. Only the intended Clang
native profile changes.

## Correctness

The candidate passed Clang native normal KAT/test, Product API roundtrip and
implicit-rejection checks, NTT-root regeneration, and the stack probe. GCC
native, Clang AVX2-only, and Clang scalar product/KAT cross-checks also passed.
The post-commit command summary is in
[`postcommit-smoke.txt`](postcommit-smoke.txt).
