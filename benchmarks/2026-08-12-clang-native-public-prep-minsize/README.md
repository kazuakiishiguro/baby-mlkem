# Clang Native Public-Preparation `minsize`

Date: 2026-08-12

Baseline: `58718f5`

Candidate: `f6ff06c`

## Change

The shared uncached public-key preparation helper now has a Clang-only
`noinline,minsize` boundary. It is used by the public d12 decode, eight-way
matrix setup, and existing hash/matrix-tail handoff shared by encapsulation
and decapsulation. The change affects only Clang x86-64 builds with AVX2,
AVX512F, and AVX512BW; GCC, AVX2-only, and scalar product artifacts are
byte-identical.

This is a size-only compiler-layout optimization. It changes no arithmetic,
algorithm, cache policy, API, ciphertext format, or external dependency. No
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
[`product-ab-15x50k.txt`](product-ab-15x50k.txt), and the size, stack, and
cross-profile identity records are in [`size-baseline.txt`](size-baseline.txt),
[`size-candidate.txt`](size-candidate.txt), [`stack.txt`](stack.txt), and
[`profile-identity.txt`](profile-identity.txt).

## Product Size

`Primary` is executable code plus read-only data. Writable storage and the
relocatable artifact are reported separately.

| Quantity | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Product code | 53,285 B | 52,443 B | -842 B |
| Read-only data | 16,326 B | 16,326 B | 0 B |
| Primary | 69,611 B | 68,769 B | -842 B |
| Writable storage | 18,001 B | 18,001 B | 0 B |
| Relocatable artifact | 99,720 B | 98,008 B | -1,712 B |
| Shared helper symbol | 0x5a8 (1,448 B) | 0x85 (133 B) | -1,315 B |

The primary footprint falls by 1.21%. The stack high-water maximum remains
`8,056 B` for valid and invalid decapsulation.

## Product A/B

| Operation | Gmean | 95% bootstrap CI | Paired median | Wins |
|---|---:|---:|---:|---:|
| Keygen | `0.9964x` | `0.9890x..1.0022x` | `1.0000x` | 8/15 |
| Encaps | `0.9952x` | `0.9852x..1.0056x` | `0.9999x` | 7/15 |
| Decaps | `0.9980x` | `0.9843x..1.0100x` | `0.9992x` | 6/15 |
| Roundtrip | `0.9972x` | `0.9909x..1.0029x` | `0.9989x` | 7/15 |

Every operation remains above the repository's `0.995x` size-optimization
regression floor. The confidence intervals cross `1.0x`, so this report
credits only the size reduction.

## Profile Identity

The source guard was checked by building the parent and candidate commits in
Clang AVX2-only, GCC native, and Clang scalar profiles. Their product hashes
are identical; only the intended Clang native profile changes.

## Correctness

The candidate passed normal KAT/test, the Product API roundtrip and
implicit-rejection check, the NTT-root regeneration check, and the stack probe
correctness smoke. The post-commit command summary is in
[`postcommit-smoke.txt`](postcommit-smoke.txt).

A larger sibling candidate that also marked the shared hash/matrix-tail body
`minsize` reduced primary size further, but its three-run screen regressed
encapsulation and decapsulation by roughly 2%; it was not retained.
