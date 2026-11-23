# Clang Native Keygen NTT Loop Compaction

This report records commit `b0366cc`, which compacts the Clang native
`keygen_ntt6_mixed_shared_clang_avx512()` helper.

## Change

The helper keeps its existing native-only `noinline` boundary and receives
`__attribute__((minsize))`. Its six-transform outer loop is changed from
`unroll(disable)` to `unroll_count(2)`. This keeps two transforms in each
compiled group while avoiding the full six-way duplicate body.

The change is limited to Clang builds with the existing native AVX512 path.
GCC, AVX2-only, and scalar preprocessor paths are unchanged. No algorithm,
wire format, API, cache, table, vendored cryptographic object, or new runtime
dependency is introduced.

## Size

| Native Clang product | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Code | 46,352 B | 44,677 B | -1,675 B |
| Read-only data | 10,694 B | 10,758 B | +64 B |
| Primary | 57,046 B | 55,435 B | -1,611 B |
| Relocatable artifact | 84,024 B | 81,616 B | -2,408 B |
| Writable | 18,001 B | 18,001 B | 0 B |

The detailed `product-size` captures are in [size-baseline.txt](size-baseline.txt)
and [size-candidate.txt](size-candidate.txt).

## Product Screen

CPU 0 was pinned. Each side received three warmups followed by 15 alternating
pairs at 100,000 iterations. Ratios are baseline time divided by candidate
time, so values above `1.0x` favor the candidate.

| Operation | Geometric mean | Paired median | Wins |
|---|---:|---:|---:|
| Keygen | 0.999551x | 1.001176x | 8/15 |
| Encaps | 0.996314x | 0.997241x | 7/15 |
| Decaps | 0.999666x | 0.995746x | 4/15 |
| Roundtrip | 1.001256x | 1.003184x | 8/15 |

All operation geometric means clear the repository `0.995x` no-regression
floor. No broad speed gain is claimed; the keygen stage result is the focused
positive signal. Raw outputs are in [product-15](product-15), with the summary
in [product-ab-summary.txt](product-ab-summary.txt).

## Stage Attribution

The nine-pair stage screen used CPU 0, three warmups, and 30,000 iterations.
It is an attribution screen, not a broad operation-speed claim.

| Stage | Geometric mean | Paired median | Wins |
|---|---:|---:|---:|
| `kpke_keygen_full` | 1.002035x | 1.006870x | 7/9 |
| `keygen_noise_ntt` | 1.000213x | 0.999053x | 4/9 |
| `sample_matrix` | 0.982270x | 0.989286x | 2/9 |
| `sample_ntt8_full_raw` | 0.994490x | 1.003080x | 5/9 |

The source change does not touch the matrix sampler. The negative standalone
matrix row is therefore treated as normal whole-binary layout noise, not as a
source-level regression attribution. Raw outputs are in [stage-9](stage-9),
with the summary in [stage-ab-summary.txt](stage-ab-summary.txt).

## Profile Identity

The native Clang artifact changes as intended. GCC native, Clang/GCC AVX2-only,
and Clang/GCC scalar artifacts are byte-identical to the preceding revision.
The full hashes and profile sizes are in [profile-identity.txt](profile-identity.txt).

## Validation

Native Clang `make test`, `make test-product`, `make product-size`, and
`make check-ntt-roots` pass. Product KAT and size builds also pass for GCC
native, Clang/GCC AVX2-only, and Clang/GCC scalar profiles. See
[validation.txt](validation.txt). The next unresolved gates remain the final
same-revision comparator speed matrix and the native primary-size comparison
against `mlkem-native`.
