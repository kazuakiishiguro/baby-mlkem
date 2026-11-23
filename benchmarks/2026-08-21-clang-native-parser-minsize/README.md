# Native Clang Rejection Parser `minsize`

Commit `f17bb13` adds a native Clang-only `minsize` attribute to the
repository-local rejection parser `sample_ntt_parse_stream_avx2_ready()`.
The attribute is enabled only for `__clang__` builds defining
`__AVX512F__`, `__AVX512VBMI2__`, and `__AVX512VL__`. The existing `noinline`
boundary and the parser algorithm remain unchanged.

This is a core compiler-layout optimization. It does not add a vendor backend,
external cryptographic object, runtime library, cache, precomputed KEM result,
table, API, algorithm, or wire-format dependency. The parser's native Clang
symbol shrinks from `0x1ec` to `0x1b2` bytes. The AVX2-only, scalar, and GCC
preprocessor paths do not receive the attribute.

## Revisions And Environment

- Baseline: `98cc87fccffa69f47039b0b46277cf93c3a652d6`
- Candidate: `f17bb13c7bcb0a18617cbce607a31c8bdb8cab1e`
- Compiler: Ubuntu Clang 18.1.3
- GCC: Ubuntu GCC 13.3.0
- Linker: GNU ld 2.42
- CPU: AMD Ryzen Threadripper 7980X 64-Cores
- Product profile: `CC=clang ARCH_CFLAGS=-march=native`
- Backend: `AVX2_BACKEND=core`
- Cache mode: `BABY_MLKEM_DISABLE_INTERNAL_CACHES`
- Product timing: CPU 0, 3 warmups, 15 alternating pairs, 100,000 iterations
- Stage timing: CPU 0, 3 warmups, 9 alternating pairs, 30,000 iterations

Exact flags and host details are in [`environment.txt`](environment.txt).

## Size

`Primary` is executable code plus read-only data. Writable storage is reported
separately.

| Quantity | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Primary product size | 57,264 B | 57,046 B | -218 B |
| Code | 46,410 B | 46,352 B | -58 B |
| Read-only data | 10,854 B | 10,694 B | -160 B |
| Writable storage | 18,001 B | 18,001 B | 0 B |
| Relocatable artifact | 84,216 B | 84,024 B | -192 B |

The exact measurements and hashes are [`size-baseline.txt`](size-baseline.txt)
and [`size-candidate.txt`](size-candidate.txt).

## Product A/B

Ratios use `baseline_time / candidate_time`, so values above `1.0x` favor the
candidate. Every operation remains above the repository's `0.995x` size-only
screen floor. This is recorded as a size/no-regression step; no formal broad
speed improvement is claimed.

| Operation | Speedup gmean | Median | Wins |
|---|---:|---:|---:|
| Keygen | 1.001574x | 1.000518x | 9/15 |
| Encaps | 1.006358x | 1.001233x | 12/15 |
| Decaps | 0.999977x | 1.003739x | 11/15 |
| Roundtrip | 1.002328x | 1.001435x | 10/15 |

The raw alternating samples and parsed ratios are in
[`product-ab-15x100k.txt`](product-ab-15x100k.txt) and
[`product-ab-summary.txt`](product-ab-summary.txt).

## Stage Attribution

The focused stage screen shows the expected improvement at the parser-bearing
x8 raw boundary, while the Keccak producer/store boundary remains neutral:

| Stage | Speedup gmean | Median | Wins |
|---|---:|---:|---:|
| `sample_matrix` | 1.001325x | 1.003904x | 6/9 |
| `sample_ntt8_full_raw` | 1.010018x | 1.009884x | 5/9 |
| `sample_ntt8_keccak3_only` | 1.002042x | 1.000651x | 5/9 |
| `sample_ntt8_keccak_store3` | 0.999039x | 0.998407x | 3/9 |

This attribution is directional and noisy, not a standalone speed claim. The
complete stage output is [`stage-ab-9x30000.txt`](stage-ab-9x30000.txt), with
the selected ratios summarized in [`stage-ab-summary.txt`](stage-ab-summary.txt).

## Cross-Profile Identity

Only native Clang changes. GCC native and all AVX2/scalar artifacts are
byte-identical to the baseline; their full hashes and primary sizes are in
[`profile-identity.txt`](profile-identity.txt).

| Profile | Candidate primary | Baseline-identical |
|---|---:|---:|
| Clang native | 57,046 B | no |
| GCC native | 58,814 B | yes |
| Clang AVX2-only | 45,032 B | yes |
| GCC AVX2-only | 53,019 B | yes |
| Clang scalar | 62,098 B | yes |
| GCC scalar | 22,994 B | yes |

## Validation And Remaining Work

The native core and product KATs pass. Product KATs and size builds also pass
for GCC native, Clang/GCC AVX2-only, and Clang/GCC scalar profiles. The
validation record is [`validation.txt`](validation.txt).

This step does not make baby-mlkem the fastest or smallest implementation.
Native Clang still has an open primary-size gap to the pinned `mlkem-native`
comparator, and the authoritative same-revision all-library speed matrix is
still open. The next credible core target is the larger x8 producer/parser
boundary and its rate-store dataflow; another isolated parser shuffle is not
supported by the current evidence. No benchmark cache or vendored backend is
part of this result.

The report file hashes are in [`checksums.sha256`](checksums.sha256).
