# Clang AVX2 Helper Layout

Commit `fdd2c6a` adds Clang AVX2-only `noinline,minsize` boundaries around
four fixed-size helpers. Commit `aeb1c35` preserves the existing `noinline`
attribute for every non-Clang-AVX2 profile. The affected helpers are:

- `hash_matrix_x3_parse_group`
- `sample_ntt_parse_stream_avx2_ready`
- `decompress_decode_poly_d10_ct_x3_avx2`
- `sha3_256_1184_avx2`

This is a compiler-layout optimization only. It changes no arithmetic, API,
wire format, cache, random source, external object, vendored backend, or
runtime library. The Clang AVX2 product is the only intentionally changed
profile.

## Revisions And Environment

- Baseline: `a38271f`
- Candidate: `aeb1c35`
- Implementation commit: `fdd2c6a`
- Backend: `AVX2_BACKEND=core`
- Compiler: Ubuntu Clang 18.1.3
- CPU: AMD Ryzen Threadripper 7980X 64-Cores, pinned to CPU 0 for A/B
- Product timing: 3 warmups, 15 alternating pairs, 100,000 iterations
- Flags: `-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f`
- Optimization: `-O3 -fno-semantic-interposition -fvisibility=hidden`

The complete environment is in [`environment.txt`](environment.txt). The
source and attribute audit is in [`source-audit.txt`](source-audit.txt).

## Size

`Primary` is executable code plus read-only data. Writable storage is reported
separately.

| Quantity | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Primary product size | 45,824 B | 45,032 B | -792 B |
| Code | 40,475 B | 39,762 B | -713 B |
| Read-only data | 5,349 B | 5,270 B | -79 B |
| Writable storage | 26,593 B | 26,593 B | 0 B |
| Relocatable artifact | 71,240 B | 70,464 B | -776 B |

The raw reports are [`size-baseline.txt`](size-baseline.txt) and
[`size-candidate.txt`](size-candidate.txt). The candidate is 17 bytes smaller
than the pinned 45,049-byte OpenSSL AVX2 comparator.

## Product A/B

Ratios are `baseline / candidate`; values above `1.0x` favor the candidate.
This is a size optimization, so no speed gain is credited.

| Operation | Baseline mean ns/op | Candidate mean ns/op | Paired gmean | Paired median | Wins |
|---|---:|---:|---:|---:|---:|
| Keygen | 5,576.68 | 5,548.62 | 1.0050x | 1.0011x | 7/15 |
| Encaps | 4,437.43 | 4,417.86 | 1.0044x | 1.0007x | 10/15 |
| Decaps | 4,437.40 | 4,395.87 | 1.0092x | 1.0016x | 12/15 |
| Roundtrip | 14,745.24 | 14,671.17 | 1.0050x | 1.0012x | 10/15 |

The lower bootstrap confidence bounds are 0.9987x, 1.0003x, 1.0012x, and
1.0011x respectively. This is a single 15-pair screen, not the final
multi-batch speed gate. Raw measurements are in
[`product-ab-15x100k.txt`](product-ab-15x100k.txt), with parsed values in
[`product-ab-summary.txt`](product-ab-summary.txt).

## Cross-Profile Identity

The final candidate was rebuilt with all six compiler/ISA profiles. Only
Clang AVX2 changed relative to the parent. The other five products are
byte-identical, as recorded in [`profile-identity.txt`](profile-identity.txt).

| Profile | Candidate primary | Candidate SHA-256 | Parent-identical |
|---|---:|---|---|
| Clang native | 65,787 B | `818a53b9...` | yes |
| GCC native | 59,148 B | `4a2b129b...` | yes |
| Clang AVX2 | 45,032 B | `b6fd46a0...` | no |
| GCC AVX2 | 53,019 B | `c2816644...` | yes |
| Clang scalar | 62,098 B | `b3d4f765...` | yes |
| GCC scalar | 22,994 B | `2bccdaa6...` | yes |

## Validation

The candidate passed the Clang AVX2 KAT, product API test, complete 30,000
iteration stage harness, `make check-ntt-roots`, and an 8-run stack probe.
Stage range and timing readouts are in [`stage-summary.txt`](stage-summary.txt)
and the complete raw stage output is in [`stage-30000.txt`](stage-30000.txt).

The candidate also passed Clang AVX2 ASan+UBSan KAT with
`ASAN_OPTIONS=detect_leaks=0`; LeakSanitizer cannot run under this environment's
ptrace wrapper. The result is recorded in [`sanitizer.txt`](sanitizer.txt).
The AVX512 opcode/register scan passed; see
[`avx512-audit.txt`](avx512-audit.txt). Baseline and candidate stack results
are in [`stack-baseline.txt`](stack-baseline.txt) and
[`stack-candidate.txt`](stack-candidate.txt); maximum stack remains 4,512 B.

## Goal Status

Using the pinned comparator matrix, the Clang AVX2 primary-size gate now passes
10/10, including OpenSSL by 17 B. The native Clang artifact remains 65,787 B
and fails four pinned comparator gates. A fresh authoritative all-comparator
speed and size rerun at this exact revision is still required, so the project
does not claim that the overall fastest-and-smallest goal is complete.
