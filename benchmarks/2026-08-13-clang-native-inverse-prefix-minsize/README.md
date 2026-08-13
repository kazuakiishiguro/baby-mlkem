# Clang Native Inverse Prefix `minsize`

Commit `987d9e4` adds a Clang native-only `noinline,minsize` boundary around
`ntt_inv_mont_before_final_avx512()`, the shared inverse-Montgomery prefix used
before the final output handling. The arithmetic, range contract, output
format, API, and call order are unchanged.

The boundary is enabled only for Clang builds with AVX2, AVX512F, and AVX512BW.
GCC native, AVX2-only, and scalar profiles retain the original declaration and
remain byte-identical. No cache, external object, vendored backend, runtime
library, table, or wire-format dependency is added.

## Revisions And Environment

- Baseline: `059ac6a` (binary-equivalent to the prior `a04304b` candidate)
- Candidate: `987d9e4`
- Target: `ntt_inv_mont_before_final_avx512`
- Backend: `AVX2_BACKEND=core`
- Compiler: Ubuntu Clang 18.1.3
- CPU: AMD Ryzen Threadripper 7980X 64-Cores, pinned to CPU 0 for A/B
- Product timing: 3 warmups, 15 alternating pairs, 100,000 iterations
- Flags: `-march=native`
- Optimization: `-O3 -fno-semantic-interposition -fvisibility=hidden`

The full environment and source scope are in [`environment.txt`](environment.txt)
and [`source-audit.txt`](source-audit.txt).

## Size

`Primary` is executable code plus read-only data. Writable storage is reported
separately.

| Quantity | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Primary product size | 63,553 B | 61,086 B | -2,467 B |
| Code | 47,739 B | 46,264 B | -1,475 B |
| Read-only data | 15,814 B | 14,822 B | -992 B |
| Writable storage | 18,001 B | 18,001 B | 0 B |
| Relocatable artifact | 91,096 B | 88,376 B | -2,720 B |

The target helper had no standalone symbol in the baseline because its body was
inlined into its callers. The candidate emits a 670-byte (`0x29e`) helper and
reduces the `baby_mlkem768_decaps` symbol from 8,822 bytes (`0x2276`) to 6,677
bytes (`0x1a15`). Raw product measurements are in
[`size-baseline.txt`](size-baseline.txt) and
[`size-candidate.txt`](size-candidate.txt).

## Product A/B

Values are operations per second; ratios are `candidate / baseline`, so values
above `1.0x` favor the candidate. This is a size optimization and no speed gain
is credited.

| Operation | Baseline mean ops/s | Candidate mean ops/s | Paired gmean | Paired median | Wins |
|---|---:|---:|---:|---:|---:|
| Keygen | 254,925.05 | 255,385.66 | 1.001844x | 1.000306x | 8/15 |
| Encaps | 282,863.66 | 283,734.82 | 1.003120x | 1.001060x | 9/15 |
| Decaps | 352,951.42 | 354,718.45 | 1.005235x | 1.001054x | 9/15 |
| Roundtrip | 96,258.62 | 96,418.35 | 1.001689x | 0.997264x | 6/15 |

The deterministic 20,000-sample paired bootstrap 95% intervals are, in the
same order, `0.996417x..1.008271x`, `0.997612x..1.010442x`,
`0.991131x..1.021511x`, and `0.996519x..1.007805x`. All geometric means clear
the `0.995x` screen floor, but this short size screen is not a speed claim.
Raw samples are in [`product-ab-15x100k.txt`](product-ab-15x100k.txt), with
parsed values in [`product-ab-summary.txt`](product-ab-summary.txt).

## Cross-Profile Identity

Only Clang native changes relative to the parent. The other five products are
byte-identical, as recorded in [`profile-identity.txt`](profile-identity.txt).

| Profile | Candidate primary | Candidate SHA-256 | Parent-identical |
|---|---:|---|---|
| Clang native | 61,086 B | `e4e6a73b...` | no |
| GCC native | 59,148 B | `4a2b129b...` | yes |
| Clang AVX2 | 45,032 B | `b6fd46a0...` | yes |
| GCC AVX2 | 53,019 B | `c2816644...` | yes |
| Clang scalar | 62,098 B | `b3d4f765...` | yes |
| GCC scalar | 22,994 B | `2bccdaa6...` | yes |

## Validation

The candidate passed the Clang native KAT, product API test, complete 30,000
iteration stage harness, `make check-ntt-roots`, and an 8-run stack probe.
Stage ranges and candidate stage timings are in
[`stage-summary.txt`](stage-summary.txt) and
[`stage-candidate.txt`](stage-candidate.txt). Maximum stack remains 8,056 B.

Clang native ASan+UBSan KAT passed with `ASAN_OPTIONS=detect_leaks=0`; no
sanitizer diagnostic was emitted. LeakSanitizer is disabled because the
execution environment uses ptrace. Native AVX512 disassembly and linkage scope
are recorded in [`instruction-audit.txt`](instruction-audit.txt).

## Goal Status

At the current pinned native comparator sizes, 61,086 B fails Kyber by 54 B,
PQClean by 136 B, and mlkem-native by 9,900 B. It passes the fair Kyber
comparator by 989 B and the other six pinned native gates. The Clang AVX2
primary size remains 45,032 B, 17 B below the pinned OpenSSL comparator, and
passes all 10 pinned AVX2 size comparisons.

A fresh authoritative all-library size and same-revision speed rerun is still
required. The overall fastest-and-smallest goal remains open.
