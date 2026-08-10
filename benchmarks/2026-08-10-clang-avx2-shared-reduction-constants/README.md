# Clang AVX2 Shared Reduction Constants

Commit `b5f0ea8` shares three repeated 16-bit AVX2 reduction constants through
one repository-local hidden YMM constant section:

- `Q = 3329`
- `Q - 1 = 3328`
- the signed 16-bit Barrett reciprocal `20159`

The Clang AVX2 path now references these constants from
`avx2_shared_constants.S` instead of retaining repeated compiler-local pools.
This is an object-size optimization in the local core implementation. It adds
no cache, vendored backend call, external cryptographic object, runtime
library, API, algorithm, or wire-format dependency.

## Revisions And Environment

- Baseline: parent `6930a60`.
- Candidate: `b5f0ea8`.
- Backend: `AVX2_BACKEND=core`.
- Compiler: Ubuntu Clang 18.1.3.
- CPU: AMD Ryzen Threadripper 7980X 64-Cores, pinned to CPU 0.
- Product timing: 3 warmups, 15 alternating baseline/candidate pairs,
  100,000 iterations per process.
- Flags: `-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f`,
  `-O3 -fno-semantic-interposition -fvisibility=hidden`,
  `-fomit-frame-pointer -fno-stack-protector -falign-loops=64`
  `-fno-unwind-tables -fno-asynchronous-unwind-tables -fno-strict-aliasing`.

The full environment is recorded in [`environment.txt`](environment.txt).

## Size

`Primary` is executable code plus read-only data. Writable storage is reported
separately because this change does not alter the writable footprint.

| Quantity | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Primary product size | 47,460 B | 46,772 B | -688 B |
| Code | 41,539 B | 41,423 B | -116 B |
| Read-only data | 5,921 B | 5,349 B | -572 B |
| Writable storage | 26,593 B | 26,593 B | 0 B |
| Relocatable artifact | 73,048 B | 72,408 B | -640 B |

The primary footprint is reduced by 1.45%. The detailed section accounting is
in [`section-accounting.txt`](section-accounting.txt); the raw size reports are
[`size-baseline.txt`](size-baseline.txt) and [`size-candidate.txt`](size-candidate.txt).

The largest individual change is a 608-byte reduction in `.rodata.cst32`. The
new `.rodata.MLKEM_AVX2_SHARED_CONSTANTS` section is 160 bytes, so the net
read-only reduction is 572 bytes after all compiler-pool changes.

## Product A/B

Ratios are `baseline / candidate`; values above `1.0x` favor the candidate.
The table reports paired geometric means and medians over all 15 pairs, with no
sample removed.

| Operation | Baseline mean ns/op | Candidate mean ns/op | Paired geometric mean | Paired median | Wins |
|---|---:|---:|---:|---:|---:|
| Keygen | 5,714.57 | 5,655.85 | 1.010227x | 1.002889x | 12/15 |
| Encaps | 4,571.72 | 4,550.29 | 1.004715x | 1.003081x | 11/15 |
| Decaps | 4,588.01 | 4,545.50 | 1.009093x | 1.001406x | 10/15 |
| Roundtrip | 15,173.41 | 15,039.89 | 1.008828x | 1.002686x | 13/15 |

This is a single 15-pair screen, not the project's final multi-batch speed
gate. The measurements show no regression, but no independent speed gain is
credited to this change. Raw measurements are in
[`product-ab-15x100k.txt`](product-ab-15x100k.txt), with the parsed summary in
[`product-ab-summary.txt`](product-ab-summary.txt).

## Cross-Profile Identity

The Clang AVX2 product is the only intended changed profile. GCC AVX2, Clang
native, Clang scalar, GCC native, and GCC scalar candidate products are all
byte-identical to their matching baselines. SHA-256 values and the comparison
are recorded in [`cross-profile-identity.txt`](cross-profile-identity.txt).

## Correctness And ABI

The candidate passed:

- `make test` with the exact Clang AVX2 flags above
- `make product test-product` with the exact Clang AVX2 flags above
- `make check-ntt-roots`
- the product API KAT
- product KATs for all six compiler/ISA profiles in the identity check

The product still has exactly three undefined runtime symbols: `bcmp`,
`memcpy`, and `memset`. The public product symbols and wire format are
unchanged. File hashes for the recorded text evidence are in
[`checksums.sha256`](checksums.sha256).

## Interpretation

The latest pinned local OpenSSL AVX2 comparator has a 45,049-byte primary
footprint. The candidate remains 1,723 bytes larger; the complete ten-library
matrix has not been rerun at this revision. Therefore the overall
smallest-and-fastest goal remains open. The next meaningful size work should
continue with compiler-generated AVX2 constant pools or larger code/data
duplication, while keeping non-Clang-AVX2 profiles byte-identical.
