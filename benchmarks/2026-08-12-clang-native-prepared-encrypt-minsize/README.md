# Clang Native Prepared-Encryption `minsize`

Date: 2026-08-12

Baseline: `2d96e7c`

Candidate: `b6e4039`

## Change

The Clang native prepared-public encryption body now has a `minsize` boundary.
The attribute is enabled only for Clang builds with AVX2, AVX512F, and
AVX512BW. GCC, AVX2-only, and scalar builds retain the existing declaration
and schedule. Arithmetic, output encoding, API, cache policy, and wire format
are unchanged.

This is a size-only compiler-layout optimization. It adds no cache, external
object, runtime library, API, algorithm, table, or wire-format dependency. No
speed gain is claimed.

## Environment And Build

- Compiler: Ubuntu Clang 18.1.3.
- Host: AMD Ryzen Threadripper 7980X 64-Cores, x86-64 Linux.
- Timing: CPU 0, 15 alternating baseline/candidate pairs, 50,000 iterations
  per process.
- Product artifacts: `BABY_MLKEM_DISABLE_INTERNAL_CACHES`.
- Architecture: `-march=native`.
- Product flags: `-O3 -fno-semantic-interposition -fvisibility=hidden
  -fomit-frame-pointer -fno-stack-protector -falign-loops=64
  -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-strict-aliasing`.

The ratio is `baseline ns/op / candidate ns/op`; values above `1.0x` favor the
candidate. Raw process output is in
[`product-ab-15x50k.txt`](product-ab-15x50k.txt). Size and stack output are in
[`size-baseline.txt`](size-baseline.txt),
[`size-candidate.txt`](size-candidate.txt), [`stack.txt`](stack.txt), and
[`profile-identity.txt`](profile-identity.txt).

## Product Size

`Primary` is executable code plus read-only data. Writable storage and the
relocatable artifact are reported separately.

| Quantity | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Product code | 49,841 B | 49,822 B | -19 B |
| Read-only data | 16,454 B | 16,198 B | -256 B |
| Primary | 66,295 B | 66,020 B | -275 B |
| Writable storage | 18,001 B | 18,001 B | 0 B |
| Relocatable artifact | 93,880 B | 93,560 B | -320 B |
| Prepared-encryption symbol | 0x558 (1,368 B) | 0x545 (1,349 B) | -19 B |

The primary footprint falls by 0.42%. The small symbol reduction is amplified
by the Clang caller layout and constant-pool selection.
The stack high-water maximum remains `8,056 B` for valid and invalid
decapsulation.

## Product A/B

| Operation | Gmean | 95% bootstrap CI | Paired median | Wins |
|---|---:|---:|---:|---:|
| Keygen | `1.0009x` | `0.9971x..1.0055x` | `0.9998x` | 5/15 |
| Encaps | `0.9984x` | `0.9914x..1.0064x` | `0.9983x` | 3/15 |
| Decaps | `0.9981x` | `0.9901x..1.0057x` | `0.9980x` | 6/15 |
| Roundtrip | `0.9992x` | `0.9961x..1.0026x` | `0.9987x` | 4/15 |

Every operation remains above the repository's `0.995x` size-optimization
regression floor. The confidence intervals cross `1.0x`, so this report
credits only the size reduction.

The parent and candidate product hashes are identical for Clang AVX2-only,
GCC native, and Clang scalar builds. Only the intended Clang native profile
changes.

## Correctness

The candidate passed normal KAT/test, the Product API roundtrip and
implicit-rejection check, the NTT-root regeneration check, and the stack probe
correctness smoke. The post-commit command summary is in
[`postcommit-smoke.txt`](postcommit-smoke.txt).
