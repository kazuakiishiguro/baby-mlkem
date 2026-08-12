# Clang Native Inverse-Final `minsize`

Commit `a04304b` adds a Clang native-only `noinline,minsize` boundary around
`ntt_inv_add4_eta2_i8_mont_final_shared_avx512()`. The function performs the
four-output inverse-final step used by prepared encryption, including the
int8 ETA2 noise and message fold. The arithmetic, range contract, output
format, API, and call order are unchanged.

The boundary is enabled only for Clang builds with AVX2, AVX512F, and
AVX512BW. GCC native, AVX2-only, and scalar profiles retain the existing
`noinline` attribute and are byte-identical. No cache, external object,
vendored backend, runtime library, table, or wire-format dependency is added.

## Revisions And Environment

- Baseline: `3ef9c35`
- Candidate: `a04304b`
- Backend: `AVX2_BACKEND=core`
- Compiler: Ubuntu Clang 18.1.3
- CPU: AMD Ryzen Threadripper 7980X 64-Cores, pinned to CPU 0 for A/B
- Product timing: 3 warmups, 15 alternating pairs, 100,000 iterations
- Flags: `-march=native`
- Optimization: `-O3 -fno-semantic-interposition -fvisibility=hidden`

The full environment is in [`environment.txt`](environment.txt). The source
scope and profile guard are recorded in [`source-audit.txt`](source-audit.txt).

## Size

`Primary` is executable code plus read-only data. Writable storage is reported
separately.

| Quantity | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Primary product size | 65,787 B | 63,553 B | -2,234 B |
| Code | 49,525 B | 47,739 B | -1,786 B |
| Read-only data | 16,262 B | 15,814 B | -448 B |
| Writable storage | 18,001 B | 18,001 B | 0 B |
| Relocatable artifact | 93,360 B | 91,096 B | -2,264 B |

The target helper shrinks from 4,622 to 2,836 bytes. Raw product reports are
[`size-baseline.txt`](size-baseline.txt) and
[`size-candidate.txt`](size-candidate.txt).

## Product A/B

Values are operations per second; ratios are `candidate / baseline`, so values
above `1.0x` favor the candidate. This is a size optimization and no speed
gain is credited.

| Operation | Baseline mean ops/s | Candidate mean ops/s | Paired gmean | Paired median | Wins |
|---|---:|---:|---:|---:|---:|
| Keygen | 253,264.39 | 255,236.08 | 1.007937x | 1.005450x | 11/15 |
| Encaps | 282,636.74 | 283,704.21 | 1.003895x | 1.000781x | 9/15 |
| Decaps | 358,113.36 | 359,074.45 | 1.002663x | 1.004036x | 10/15 |
| Roundtrip | 96,501.29 | 97,035.75 | 1.005626x | 1.001544x | 12/15 |

The bootstrap 95% lower bounds are `0.999566x`, `0.994626x`, `0.996442x`, and
`0.999780x`. The encapsulation lower bound is disclosed because this is a
single 15-pair size screen, not the final multi-batch speed gate. Raw samples
are in [`product-ab-15x100k.txt`](product-ab-15x100k.txt), with parsed values
in [`product-ab-summary.txt`](product-ab-summary.txt).

## Cross-Profile Identity

Only Clang native changes relative to the parent. The other five products are
byte-identical, as recorded in [`profile-identity.txt`](profile-identity.txt).

| Profile | Candidate primary | Candidate SHA-256 | Parent-identical |
|---|---:|---|---|
| Clang native | 63,553 B | `c65269e0...` | no |
| GCC native | 59,148 B | `4a2b129b...` | yes |
| Clang AVX2 | 45,032 B | `b6fd46a0...` | yes |
| GCC AVX2 | 53,019 B | `c2816644...` | yes |
| Clang scalar | 62,098 B | `b3d4f765...` | yes |
| GCC scalar | 22,994 B | `2bccdaa6...` | yes |

## Validation

The candidate passed the Clang native KAT, product API test, complete 30,000
iteration stage harness, `make check-ntt-roots`, and an 8-run stack probe.
Stage range and timing evidence is in [`stage-summary.txt`](stage-summary.txt)
and [`stage-30000.txt`](stage-30000.txt). Maximum stack remains 8,056 B.

Clang native ASan+UBSan KAT passed with `ASAN_OPTIONS=detect_leaks=0`;
LeakSanitizer is disabled because the execution environment uses ptrace and
emits no ASan or UBSan diagnostic. The result is recorded in
[`sanitizer.txt`](sanitizer.txt). Native AVX512 disassembly and linkage scope
are recorded in [`instruction-audit.txt`](instruction-audit.txt).

## Goal Status

Using the pinned comparator matrix, the current native primary size of
63,553 B still fails four comparators: Kyber by 2,521 B, Kyber fair by
1,478 B, PQClean by 2,603 B, and mlkem-native by 12,367 B. The current AVX2
primary size of 45,032 B remains 17 B below the pinned OpenSSL comparator and
passes all 10 pinned AVX2 size comparisons. A fresh authoritative all-library
size and same-revision speed rerun is still required; the overall
fastest-and-smallest goal remains open.
