# Clang Native Gamma Low-Factor Pair Compaction

Commit `e73b71d` stores one low Montgomery factor from each adjacent `x,-x`
pair in the Clang native AVX512 gamma table. The existing high-factor table
remains dense. The two Clang native consumers reconstruct the 16-lane low
factor vector at use; GCC, AVX2-only, and scalar paths are unchanged.

This is an independent core implementation change. It adds no vendor backend,
external cryptographic object, persistent cache, API change, algorithm change,
or wire-format change. The generator rejects a factor sequence that does not
satisfy the checked-in sign-pair invariant.

## Revisions And Environment

- Baseline: `7171440`
- Candidate: `e73b71d`
- Compiler: Ubuntu Clang 18.1.3
- GCC: Ubuntu GCC 13.3.0
- Linker: GNU ld 2.42
- CPU: AMD Ryzen Threadripper 7980X 64-Cores
- Kernel: Linux 6.8.0-124-generic
- Product profile: `CC=clang ARCH_CFLAGS=-march=native`
- Backend: `AVX2_BACKEND=core`
- Product cache mode: `BABY_MLKEM_DISABLE_INTERNAL_CACHES`
- Product timing: CPU 0, 3 warmups, 15 alternating pairs, 100,000 iterations

Exact flags and source scope are in [`environment.txt`](environment.txt) and
[`source-audit.txt`](source-audit.txt).

## Size

`Primary` is executable code plus read-only data. Writable storage is reported
separately.

| Quantity | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Primary product size | 57,492 B | 57,424 B | -68 B |
| Code | 46,510 B | 46,570 B | +60 B |
| Read-only data | 10,982 B | 10,854 B | -128 B |
| Writable storage | 18,001 B | 18,001 B | 0 B |
| Relocatable artifact | 84,408 B | 84,344 B | -64 B |

The exact measurements are [`size-baseline.txt`](size-baseline.txt) and
[`size-candidate.txt`](size-candidate.txt). The candidate artifact hash is
`f80ad1c126e40c26d338fa7440d2e031045bc69fba25dbccf5cc074e776ba867`.

## Product A/B

Ratios use `baseline_time / candidate_time`, so values above `1.0x` favor the
candidate. The recorded geometric means are all above the `0.995x` size-screen
floor. The confidence intervals cross `1.0x`, so no speed gain is credited.

| Operation | Speedup gmean | 95% interval | Median | Wins |
|---|---:|---:|---:|---:|
| Keygen | 0.999251x | 0.993492x..1.005366x | 0.996261x | 4/15 |
| Encaps | 0.998652x | 0.991365x..1.005228x | 1.000054x | 8/15 |
| Decaps | 1.000013x | 0.986110x..1.012185x | 0.998392x | 5/15 |
| Roundtrip | 0.999739x | 0.994613x..1.004375x | 1.000161x | 8/15 |

The raw alternating samples are in
[`product-ab-15x100k.txt`](product-ab-15x100k.txt); parsed statistics are in
[`product-ab-summary.txt`](product-ab-summary.txt).

## Cross-Profile Identity

Only Clang native changes. GCC native, Clang AVX2-only, GCC AVX2-only, Clang
scalar, and GCC scalar artifacts are byte-identical to the baseline; full
hashes are in [`profile-identity.txt`](profile-identity.txt).

| Profile | Candidate primary | Candidate SHA-256 | Parent-identical |
|---|---:|---|---|
| Clang native | 57,424 B | `f80ad1c1...` | no |
| GCC native | 59,148 B | `4a2b129b...` | yes |
| Clang AVX2-only | 45,032 B | `b6fd46a0...` | yes |
| GCC AVX2-only | 53,019 B | `c2816644...` | yes |
| Clang scalar | 62,098 B | `b3d4f765...` | yes |
| GCC scalar | 22,994 B | `2bccdaa6...` | yes |

## Validation

The candidate passed `make check-ntt-roots`, Clang native normal tests and
product tests, and Clang AVX2-only, scalar, and GCC product tests. The command
record is in [`validation.txt`](validation.txt). No new ASan/UBSan or complete
stage-harness rerun is claimed by this size-screen report.

## Remaining Work

Native Clang remains about 6,224 B larger than the pinned `mlkem-native`
comparator. Clang AVX2-only remains 45,032 B and passes the pinned AVX2
primary-size matrix. The repository therefore does not claim to be the fastest
or smallest implementation. The next credible core targets remain the direct
Keccak rate-store/parser boundary and a same-revision full comparator rerun.

The report file hashes are in [`checksums.sha256`](checksums.sha256).
