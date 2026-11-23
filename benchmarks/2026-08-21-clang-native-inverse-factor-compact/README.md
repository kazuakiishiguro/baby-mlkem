# Clang Native Inverse Montgomery Factor Compaction

Commit `cb4bfe9` compacts the repeated inverse-Montgomery factor
representations used by the Clang native AVX512 path. The generator emits
24x8 compact signed 16-bit source matrices for the low/high factors. The
native helper reconstructs levels 0..2 with broadcast plus `vpermw`; level 3
uses scalar mirrors.

This is an independent core implementation change. It does not add a vendor
backend, external cryptographic object, persistent cache, API change, algorithm
change, or wire-format change. No broad speed gain is claimed because the
decapsulation interval crosses 1.0x.

## Revisions And Environment

- Baseline: `8555ff2`
- Candidate: `cb4bfe9`
- Compiler: Ubuntu Clang 18.1.3
- GCC: Ubuntu GCC 13.3.0
- Linker: GNU ld 2.42
- CPU: AMD Ryzen Threadripper 7980X 64-Cores
- Kernel: Linux 6.8.0-124-generic
- Product profile: `CC=clang ARCH_CFLAGS=-march=native`
- Backend: `AVX2_BACKEND=core`
- Product cache mode: `BABY_MLKEM_DISABLE_INTERNAL_CACHES`
- Benchmark API: `USE_BABY_MLKEM_PRODUCT_API`
- Timing: CPU 0, 15 alternating pairs, 100,000 iterations, 3 warmups

Exact compiler flags and source scope are in [`environment.txt`](environment.txt)
and [`source-audit.txt`](source-audit.txt).

## Size

`Primary` is executable code plus read-only data. Writable storage is reported
separately.

| Quantity | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Primary product size | 59,720 B | 57,492 B | -2,228 B |
| Code | 46,306 B | 46,510 B | +204 B |
| Read-only data | 13,414 B | 10,982 B | -2,432 B |
| Writable storage | 18,001 B | 18,001 B | 0 B |
| Relocatable artifact | 86,640 B | 84,408 B | -2,232 B |
| Maximum stack | 8,056 B | 8,056 B | 0 B |

The exact footprint records are [`size-baseline.txt`](size-baseline.txt) and
[`size-candidate.txt`](size-candidate.txt). The candidate artifact hash is
`6cd81216a7d6bb02ba4ec20b03b28fdfaf73ef21b4816a916d702142e83d0e77`.

## Product A/B

Ratios use `baseline_time / candidate_time`, so values above `1.0x` favor the
candidate. The benchmark binary has internal caches disabled; no benchmark
cache or precomputed KEM result is used.

| Operation | Speedup gmean | 95% interval | Median | Wins |
|---|---:|---:|---:|---:|
| Keygen | 1.084343x | 1.078885x..1.089980x | 1.081214x | 15/15 |
| Encaps | 1.050244x | 1.044762x..1.056430x | 1.046448x | 15/15 |
| Decaps | 1.012762x | 0.999768x..1.029343x | 0.998974x | 6/15 |
| Roundtrip | 1.051205x | 1.044173x..1.059002x | 1.046528x | 15/15 |

All four geometric means clear the `0.995x` no-regression floor. The
decapsulation interval includes `1.0x`, so this commit is classified as a
size improvement with no broad formal speed claim. Keygen, encapsulation, and
roundtrip have intervals whose lower bounds are above `1.0x`.

The complete raw run record is in
[`product-ab-15x100k.txt`](product-ab-15x100k.txt), and the parsed summary is
in [`product-ab-summary.txt`](product-ab-summary.txt).

## Cross-Profile Identity

Only Clang native is changed by this commit. GCC native, Clang AVX2-only, GCC
AVX2-only, Clang scalar, and GCC scalar artifacts are byte-identical to the
baseline; full hashes are in [`profile-identity.txt`](profile-identity.txt).

| Profile | Candidate primary | Candidate SHA-256 | Parent-identical |
|---|---:|---|---|
| Clang native | 57,492 B | `6cd81216...` | no |
| GCC native | 59,148 B | `4a2b129b...` | yes |
| Clang AVX2-only | 45,032 B | `b6fd46a0...` | yes |
| GCC AVX2-only | 53,019 B | `c2816644...` | yes |
| Clang scalar | 62,098 B | `b3d4f765...` | yes |
| GCC scalar | 22,994 B | `2bccdaa6...` | yes |

The instruction and linked-symbol audit is in
[`instruction-audit.txt`](instruction-audit.txt). The old native L12 factor
symbols are absent from the candidate product.

## Validation

The candidate passed native Clang KAT/product smoke, the normal Clang KAT,
the generated NTT-root reproducibility check, and product tests for Clang and
GCC native, AVX2-only, and scalar profiles. The command-level record is in
[`validation.txt`](validation.txt). The guarded stack probe reports a maximum
of `8,056 B`; details are in [`stack-candidate.txt`](stack-candidate.txt).

This report does not claim a new ASan/UBSan or complete stage-harness rerun;
those gates remain separate evidence in the historical reports.

## Remaining Work

The current Clang native primary size is still `6,292 B` above the pinned
mlkem-native comparator. Clang AVX2-only remains `45,032 B` and passes the
pinned AVX2 size matrix. The repository therefore does not claim to be the
fastest or smallest implementation. The next credible core targets are the
direct Keccak/rate-store boundary and permutation work, followed by a
same-revision full comparator rerun.

The report file hashes are in [`checksums.sha256`](checksums.sha256).
