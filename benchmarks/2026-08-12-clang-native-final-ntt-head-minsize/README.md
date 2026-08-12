# Clang Native Final-NTT Head `minsize`

Date: 2026-08-12

Baseline: `f6ff06c`

Candidate: `8590282`

## Change

The native Clang final forward-NTT head used by the K=3 keygen and prepared
encryption paths now has a `minsize` function boundary. The arithmetic,
Montgomery factors, coefficient ranges, and output representation are
unchanged. The boundary is active only in the existing Clang native AVX512
path; narrower ISAs and GCC keep their previous schedules.

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
| Product code | 52,443 B | 51,238 B | -1,205 B |
| Read-only data | 16,326 B | 16,582 B | +256 B |
| Primary | 68,769 B | 67,820 B | -949 B |
| Writable storage | 18,001 B | 18,001 B | 0 B |
| Relocatable artifact | 98,008 B | 96,520 B | -1,488 B |
| Final-NTT head symbol | 0xad3 (2,771 B) | 0x61e (1,566 B) | -1,205 B |

The primary footprint falls by 1.38%. The stack high-water maximum remains
`8,056 B` for valid and invalid decapsulation.

## Product A/B

| Operation | Gmean | 95% bootstrap CI | Paired median | Wins |
|---|---:|---:|---:|---:|
| Keygen | `1.0000x` | `0.9932x..1.0067x` | `0.9993x` | 7/15 |
| Encaps | `1.0005x` | `0.9945x..1.0079x` | `0.9986x` | 7/15 |
| Decaps | `1.0065x` | `0.9975x..1.0203x` | `0.9995x` | 7/15 |
| Roundtrip | `1.0009x` | `0.9937x..1.0085x` | `0.9995x` | 7/15 |

Every operation remains above the repository's `0.995x` size-optimization
regression floor. The confidence intervals cross `1.0x`, so this report
credits only the size reduction.

## Rejected Sibling

Marking the larger shared inverse/add helper `minsize` reduced primary by
2,234 bytes, but decapsulation fell to `0.9820x` with a 95% bootstrap interval
ending at `0.9916x`. The complete evidence is in
[`rejected-inverse-minsize.txt`](rejected-inverse-minsize.txt); no code from
that candidate remains.

## Correctness

The candidate passed normal KAT/test, the Product API roundtrip and
implicit-rejection check, the NTT-root regeneration check, and the stack probe
correctness smoke. The post-commit command summary is in
[`postcommit-smoke.txt`](postcommit-smoke.txt).
