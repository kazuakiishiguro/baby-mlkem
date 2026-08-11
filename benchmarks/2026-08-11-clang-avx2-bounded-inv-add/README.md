# AVX2 Bounded Inverse-Add Correction

Commit `8dde3e5` replaces the generic AVX2 Barrett canonicalization after the
inverse-NTT final noise add with one masked subtraction of `Q`. The change is
limited to `ntt_inv_add_mont_final_avx2()`; `ntt_inv_add2()` and inverse
subtraction keep their existing wider-range reducers.

The range proof is local and explicit. `ntt_inv_mont_scale_pair_i16x16()`
returns canonical `[0,Q)` values, and the ETA2 noise/message add operands are
also canonical `[0,Q)`. Their sum is at most `2*(Q-1)`, so signed 16-bit lanes
cannot overflow and one `Q` subtraction is sufficient. The correction uses a
comparison mask, not a secret-dependent branch. No cache, vendor backend,
external object, runtime library, API, algorithm, or wire-format dependency is
added.

## Revisions And Environment

- Baseline: parent `e87b66c`.
- Candidate: `8dde3e5`.
- Backend: `AVX2_BACKEND=core`.
- Compiler: Clang 18.1.3 and GCC 13.3.0.
- Host: x86-64 Linux, pinned to CPU 0.
- Clang product timing: 15 alternating baseline/candidate pairs, 50,000
  iterations per process.
- GCC product timing: 9 alternating baseline/candidate pairs, 30,000
  iterations per process.
- Architecture flags: `-mavx2 -mbmi2 -mpopcnt -mno-avx512f`.
- Clang default loop alignment: `-falign-loops=32`.
- Product artifacts: `BABY_MLKEM_DISABLE_INTERNAL_CACHES`.

The ratio is `baseline ns/op / candidate ns/op`; values above `1.0x` favor the
candidate. Raw samples are in
[`product-ab-15x50k.txt`](product-ab-15x50k.txt) and
[`gcc-avx2-product-ab-9x30k.txt`](gcc-avx2-product-ab-9x30k.txt). Parsed ratios
are summarized in [`product-ab-summary.txt`](product-ab-summary.txt).

## Product Size

`Primary` is executable code plus read-only data. Writable storage is reported
separately.

### Clang AVX2

| Quantity | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Primary product size | 46,100 B | 45,069 B | -1,031 B |
| Code | 40,751 B | 39,720 B | -1,031 B |
| Read-only data | 5,349 B | 5,349 B | 0 B |
| Writable storage | 26,593 B | 26,593 B | 0 B |
| Relocatable artifact | 71,480 B | 70,600 B | -880 B |

### GCC AVX2

| Quantity | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Primary product size | 53,005 B | 52,926 B | -79 B |
| Code | 49,249 B | 49,170 B | -79 B |
| Read-only data | 3,756 B | 3,756 B | 0 B |
| Writable storage | 34,864 B | 34,864 B | 0 B |
| Relocatable artifact | 80,984 B | 80,888 B | -96 B |

The raw accounting is in the four `size-*.txt` files in this directory.

## Product A/B

| Compiler/profile | Operation | Paired gmean | Paired median | Wins |
|---|---|---:|---:|---:|
| Clang AVX2 | Keygen | 1.003610x | 0.999719x | 7/15 |
| Clang AVX2 | Encaps | 1.007330x | 1.005370x | 14/15 |
| Clang AVX2 | Decaps | 1.015220x | 1.007600x | 12/15 |
| Clang AVX2 | Roundtrip | 1.006910x | 1.007260x | 14/15 |
| GCC AVX2 | Keygen | 1.001180x | 1.001730x | 5/9 |
| GCC AVX2 | Encaps | 1.010720x | 1.011210x | 9/9 |
| GCC AVX2 | Decaps | 1.012320x | 1.012680x | 8/9 |
| GCC AVX2 | Roundtrip | 1.010260x | 1.008700x | 9/9 |

Keygen is treated as neutral because its Clang median is below `1.0x` and its
win count is mixed. The encapsulation, decapsulation, and roundtrip gains are
consistent across both AVX2 compilers. These are cache-disabled product
measurements; no benchmark cache is involved.

## Artifact Identity

| Profile | Baseline SHA-256 | Candidate SHA-256 |
|---|---|---|
| Clang AVX2 | `c9c9a3559f2f6b181c18f1d72233691b817b19b046fe06eb24bcb135d065ba93` | `7bda31c8ff2982286c48da6f50b433d65ece2b3b6ebe25b848b7d34a600ef0d1` |
| GCC AVX2 | `13b687b089db35c42a7d1a4a7bcf084f961f553c1db997607fd516cfe4190120` | `31d845b0faed46eba8f756fcec44183ba2d8699f72fedb28b228439b52280b5a` |

The implementation is guarded to AVX2-only builds; AVX512 and scalar builds do
not enter the new helper. This focused report does not claim fresh AVX512
sanitizer coverage.

## Correctness

The candidate passed the Clang AVX2 normal test, Clang product test, GCC AVX2
normal test, GCC scalar normal test, and the complete stage process without a
validation mismatch. The smoke command transcript is in
[`postcommit-smoke.txt`](postcommit-smoke.txt). `git diff --check` also passed.

All report files are covered by [`checksums.sha256`](checksums.sha256).
