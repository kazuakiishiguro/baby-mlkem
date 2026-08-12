# Clang Native Shared NTT `minsize`

Date: 2026-08-12

Baseline: `8590282`

Candidate: `2d96e7c`

## Change

The Clang native three-polynomial lazy forward-NTT helper now has a
`noinline,minsize` boundary. It keeps the existing loop order, six lazy
levels, final canonicalization, and coefficient contract; only the compiler
layout policy changes. The helper is already inside a Clang native guard, so
GCC and narrower ISA products are unchanged.

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
[`size-candidate.txt`](size-candidate.txt), and [`stack.txt`](stack.txt).

## Product Size

`Primary` is executable code plus read-only data. Writable storage and the
relocatable artifact are reported separately.

| Quantity | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Product code | 51,238 B | 49,841 B | -1,397 B |
| Read-only data | 16,582 B | 16,454 B | -128 B |
| Primary | 67,820 B | 66,295 B | -1,525 B |
| Writable storage | 18,001 B | 18,001 B | 0 B |
| Relocatable artifact | 96,520 B | 93,880 B | -2,640 B |
| Shared NTT helper symbol | 0x746 (1,894 B) | 0x1d1 (465 B) | -1,429 B |

The primary footprint falls by 2.25%. The stack high-water maximum remains
`8,056 B` for valid and invalid decapsulation.

## Product A/B

| Operation | Gmean | 95% bootstrap CI | Paired median | Wins |
|---|---:|---:|---:|---:|
| Keygen | `0.9989x` | `0.9895x..1.0084x` | `0.9999x` | 7/15 |
| Encaps | `1.0026x` | `0.9912x..1.0142x` | `1.0005x` | 9/15 |
| Decaps | `0.9960x` | `0.9887x..1.0028x` | `1.0000x` | 8/15 |
| Roundtrip | `0.9972x` | `0.9903x..1.0041x` | `0.9983x` | 6/15 |

Every operation remains above the repository's `0.995x` size-optimization
regression floor. The confidence intervals cross `1.0x`, so this report
credits only the size reduction.

## Rejected Sibling

The x7 sparse Keccak helper's `minsize` form reduced primary by only 17 bytes.
It was screened and removed without a formal product gate; the evidence is in
[`rejected-x7-minsize.txt`](rejected-x7-minsize.txt).

## Correctness

The candidate passed normal KAT/test, the Product API roundtrip and
implicit-rejection check, the NTT-root regeneration check, and the stack probe
correctness smoke. The post-commit command summary is in
[`postcommit-smoke.txt`](postcommit-smoke.txt).
