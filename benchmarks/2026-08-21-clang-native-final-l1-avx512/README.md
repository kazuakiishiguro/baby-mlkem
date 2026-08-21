# Clang Native Final-l1 AVX512 Two-Stage Preparation

Commit `a6c3c1e` changes only the Clang native AVX512 final-`l1` preparation
boundary. The two levels immediately before the existing final `l1` consumer
now use a repository-local ZMM helper. The final `l1` and canonicalization
remain unchanged. GCC native and AVX2-only builds retain the established
two-stage AVX2 preparation path.

This is a native product-size change. It changes no arithmetic contract,
algorithm, API, wire format, cache, vendored backend, external object, or
runtime-library dependency. The product no longer reaches the old native L12
low/high factor sections. No speed gain is credited.

## Revisions And Environment

- Baseline: `ee0ebdf`
- Candidate: `a6c3c1e`
- Compiler: Ubuntu Clang 18.1.3
- GCC: Ubuntu GCC 13.3.0
- Linker: GNU ld 2.42
- Kernel: Linux 6.8.0-124-generic
- CPU: AMD Ryzen Threadripper 7980X 64-Cores
- Product profile: `CC=clang ARCH_CFLAGS=-march=native`
- Product timing: 3 warmups, 15 alternating pairs, 100,000 iterations
- CPU pinning: none in this hand-run A/B; results are a size screen only
- Backend: `AVX2_BACKEND=core`

The exact flags and source scope are in [`environment.txt`](environment.txt)
and [`source-audit.txt`](source-audit.txt).

## Size

`Primary` is executable code plus read-only data. Writable storage is reported
separately.

| Quantity | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Primary product size | 60,926 B | 59,720 B | -1,206 B |
| Code | 46,104 B | 46,306 B | +202 B |
| Read-only data | 14,822 B | 13,414 B | -1,408 B |
| Writable storage | 18,001 B | 18,001 B | 0 B |
| Relocatable artifact | 88,120 B | 86,640 B | -1,480 B |

The raw measurements are [`size-baseline.txt`](size-baseline.txt) and
[`size-candidate.txt`](size-candidate.txt). The candidate product hash is
`d98dd32e1a1a3ff66fa0fc9db49a0be3e964acf7189aaf732c58407cef39d936`.

## Product A/B

Values are operations per second. Ratios are `candidate / baseline`, so values
above `1.0x` favor the candidate. The hand-run was not CPU-pinned, all ratios
remain above the `0.995x` regression floor, and the result is treated as
size-only rather than a throughput claim.

| Operation | Baseline mean ops/s | Candidate mean ops/s | Paired gmean | Paired median | Wins |
|---|---:|---:|---:|---:|---:|
| Keygen | 255,016.66 | 254,253.80 | 0.996859x | 1.001186x | 8/15 |
| Encaps | 283,996.72 | 283,613.07 | 0.998552x | 0.998897x | 6/15 |
| Decaps | 357,867.19 | 357,222.34 | 0.998116x | 1.001999x | 10/15 |
| Roundtrip | 96,710.60 | 96,468.12 | 0.997411x | 0.998554x | 6/15 |

Bootstrap 95% bounds are `0.985421x..1.004806x` for keygen,
`0.986542x..1.008710x` for encapsulation, `0.988943x..1.004664x` for
decapsulation, and `0.988090x..1.004042x` for roundtrip. The raw alternating
samples are in [`product-ab-15x100k.txt`](product-ab-15x100k.txt); the parsed
statistics are in [`product-ab-summary.txt`](product-ab-summary.txt).

## Cross-Profile Identity

Clang native is the only changed product. The other five products are
byte-identical to the baseline revision, as recorded in
[`profile-identity.txt`](profile-identity.txt).

| Profile | Candidate primary | Candidate SHA-256 | Parent-identical |
|---|---:|---|---|
| Clang native | 59,720 B | `d98dd32e...` | no |
| GCC native | 59,148 B | `4a2b129b...` | yes |
| Clang AVX2 | 45,032 B | `b6fd46a0...` | yes |
| GCC AVX2 | 53,019 B | `c2816644...` | yes |
| Clang scalar | 62,098 B | `b3d4f765...` | yes |
| GCC scalar | 22,994 B | `2bccdaa6...` | yes |

The instruction and table audit is in
[`instruction-audit.txt`](instruction-audit.txt). The old native L12 factor
symbols are absent from the linked product.

## Validation

The candidate passed the Clang native product test, normal KAT, complete
30,000-iteration stage harness, `make check-ntt-roots`, and the complete stage
range oracle. The stage output is in [`stage-candidate.txt`](stage-candidate.txt);
all reported `ge_q` range counters are zero.

Clang native ASan+UBSan passed with no diagnostic. LeakSanitizer was disabled
because ptrace is unavailable in this environment. The 8-run guarded stack
probe reports a maximum of 8,056 B, with valid and invalid decapsulation both
at 8,056 B; see [`stack-candidate.txt`](stack-candidate.txt) and
[`sanitizer.txt`](sanitizer.txt).

## Goal Status

At the current comparator sizes, native Clang passes Kyber, fair Kyber, and
PQClean, but remains 8,520 B larger than mlkem-native. Clang AVX2 remains
45,032 B and passes all pinned AVX2 primary-size comparisons, including
OpenSSL by 17 B.

The final same-revision all-library speed rerun and the mlkem-native native
size gate remain open. The overall fastest-and-smallest goal is not claimed.
