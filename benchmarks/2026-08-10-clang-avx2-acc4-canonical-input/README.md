# Clang AVX2 Canonical K=3 Accumulation Inputs

Commit `6947295` removes three per-block centerization sequences from
`ntt_mul_acc4_madd_avx2()`. All production callers pass canonical NTT-domain
polynomials in `[0,Q)`. With six signed 16-bit products per pair, the largest
accumulated product sum is `6*(Q-1)^2`, which fits in signed 32-bit arithmetic;
the centerization was therefore redundant.

This is an AVX2-only core change. It adds no cache, vendored backend call,
external cryptographic object, runtime library, table, API, algorithm, or
wire-format dependency.

## Revisions And Environment

- Baseline: `86b7e41` (parent of the implementation commit).
- Candidate: `6947295`.
- CPU: AMD Ryzen Threadripper 7980X 64-Cores, pinned to CPU 2.
- Clang: Ubuntu Clang 18.1.3.
- GCC: Ubuntu GCC 13.3.0.
- Backend: `AVX2_BACKEND=core`.
- Flags: `-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f`.
- Stage A/B: 9 alternating pairs, 30,000 iterations per process.
- Product A/B: 9 alternating pairs, 100,000 iterations per process.

The complete raw outputs are in [`stage-ab-9x30k.txt`](stage-ab-9x30k.txt)
and [`product-ab-9x100k.txt`](product-ab-9x100k.txt).

## Size

| Quantity | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Primary product size | 47,501 B | 47,460 B | -41 B |
| Code | 41,546 B | 41,539 B | -7 B |
| Read-only data | 5,955 B | 5,921 B | -34 B |
| Writable storage | 26,593 B | 26,593 B | 0 B |
| Relocatable artifact | 73,152 B | 73,048 B | -104 B |

The timed candidate artifact has SHA-256
`be587561d931491003ecbcbe8575fb3ee031ca7a045a2ac08de05d58f0e4002f`.
The baseline artifact has SHA-256
`bdf2c0a541ff857137991666d08f904e9952664fdf192ad75053aa60502f3a8d`.
The raw size reports are [`size-baseline.txt`](size-baseline.txt) and
[`size-candidate.txt`](size-candidate.txt).

## Stage A/B

Ratios are `baseline / candidate`; values above `1.0x` favor the candidate.
The table reports the 9-run median, with no sample removed.

| Metric | Baseline median | Candidate median | Ratio |
|---|---:|---:|---:|
| K=3 `ntt_mul_acc4_madd_avx2` | 684.72 ns | 678.17 ns | 1.009658x |
| Encryption accumulation, combined | 711.54 ns | 703.10 ns | 1.012004x |
| Encryption accumulation + inverse-add | 915.07 ns | 914.51 ns | 1.000612x |
| K-PKE encryption, cached | 1,544.43 ns | 1,537.33 ns | 1.004618x |
| K-PKE encryption, uncached | 3,751.06 ns | 3,739.11 ns | 1.003196x |

## Product A/B

| Operation | Baseline median | Candidate median | Ratio |
|---|---:|---:|---:|
| Keygen | 5,641.27 ns | 5,642.97 ns | 0.999699x |
| Encaps | 4,504.51 ns | 4,493.77 ns | 1.002390x |
| Decaps | 4,490.72 ns | 4,488.55 ns | 1.000483x |
| Roundtrip | 14,929.33 ns | 14,923.05 ns | 1.000421x |

The product result is a small positive-to-neutral change because the modified
accumulator is only one part of each KEM operation. The direct K=3 and
integrated encryption rows show the stronger signal; no cache speedup is used
in this comparison.

## Correctness

Clang AVX2-only `make test`, `make test-product`, and the complete stage
harness passed. GCC AVX2-only `make test`, `make test-product`, and the stage
harness also passed. The implementation is restricted to the non-AVX512 AVX2
path; native AVX512 and scalar paths are unchanged.

The exact commands and recorded smoke results are in
[`environment.txt`](environment.txt) and [`correctness.txt`](correctness.txt).
File hashes are in [`checksums.sha256`](checksums.sha256).

This is a local core optimization milestone, not the final ten-comparator
speed/size gate. The overall smallest-and-fastest goal remains open.
