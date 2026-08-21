# Clang Native x4 Keccak Round Compaction

This report records commit `14f85e4`, which compacts the native Clang
`keccakf4()` round loop used by the shared SHA3/sample-NTT path.

## Change

When Clang builds the existing AVX512 path, the 24-round x4 Keccak loop now
uses `#pragma clang loop unroll(disable)`. The pragma is guarded by
`__clang__ && __AVX512F__`; AVX2-only and scalar Clang paths, plus all GCC
paths, retain their previous generated code.

This changes only compiler scheduling and code layout. The Keccak algorithm,
state layout, rate stores, parser, API, wire format, cache policy, and external
dependency set are unchanged. The code is repository-local and does not link a
vendored Keccak object.

## Size

| Native Clang product | Baseline `53b5e81` | Candidate `14f85e4` | Delta |
|---|---:|---:|---:|
| Code | 44,677 B | 42,405 B | -2,272 B |
| Read-only data | 10,758 B | 10,758 B | 0 B |
| Primary | 55,435 B | 53,163 B | -2,272 B |
| Relocatable artifact | 81,616 B | 79,312 B | -2,304 B |
| Writable | 18,001 B | 18,001 B | 0 B |

The shared `sha3_sample_ntt_tail_shared_clang_avx512` symbol falls from
`0x1521` to `0xc41` bytes. Detailed captures are in
[size-baseline.txt](size-baseline.txt) and [size-candidate.txt](size-candidate.txt).

## Product Screen

CPU 0 was pinned. Each side received three warmups followed by 15 alternating
pairs at 100,000 iterations. Ratios are baseline time divided by candidate
time, so values above `1.0x` favor the candidate.

| Operation | Geometric mean | Paired median | Wins |
|---|---:|---:|---:|
| Keygen | 1.003378x | 1.001333x | 9/15 |
| Encaps | 1.002328x | 1.002666x | 10/15 |
| Decaps | 0.996470x | 0.998002x | 4/15 |
| Roundtrip | 0.998976x | 0.999110x | 7/15 |

All operation geometric means clear the repository `0.995x` size-only
no-regression floor. No broad speed gain is claimed. Raw outputs are in
[product-15](product-15), with the summary in
[product-ab-summary.txt](product-ab-summary.txt).

## Stage Attribution

The nine-pair stage screen used CPU 0, three warmups, and 30,000 iterations.
It is an attribution screen, not a broad operation-speed claim.

| Stage | Geometric mean | Paired median | Wins |
|---|---:|---:|---:|
| `kpke_keygen_full` | 1.019965x | 1.005408x | 7/9 |
| `kpke_encrypt_uncached` | 0.996812x | 0.998447x | 4/9 |
| `kpke_prepare_public_no_cache` | 1.003387x | 1.003460x | 6/9 |
| `sample_matrix` | 1.011122x | 1.014313x | 5/9 |
| `sample_matrix_sparse_first_x8` | 1.025045x | 1.020754x | 7/9 |
| `sample_ntt8_full_raw` | 0.987430x | 0.997672x | 4/9 |

The source change does not touch the x8 producer, assembly, or parser. The
negative x8 standalone row is therefore treated as whole-binary layout noise,
not as a source-level regression attribution. Raw outputs are in
[stage-9](stage-9), with the summary in [stage-ab-summary.txt](stage-ab-summary.txt).

## Profile Identity

The native Clang artifact changes as intended. Native GCC, both AVX2-only
profiles, and both scalar profiles are byte-identical to the preceding
revision. Full profile captures and hashes are in
[profile-identity.txt](profile-identity.txt) and [profiles](profiles).

## Rejected Variant

Adding `__attribute__((minsize))` to the shared SHA3 helper reduced the native
primary further, but decapsulation fell to `0.990104x` in the same 15-pair
product screen. That variant was not retained.

## Validation

Native Clang `make test`, `make test-product`, `make product-size`, and
`make check-ntt-roots` pass. Product KAT and size builds also pass for native
GCC, Clang/GCC AVX2-only, and Clang/GCC scalar profiles. See
[validation.txt](validation.txt). The remaining completion gates are the final
same-revision comparator speed matrix and the native primary-size comparison
against `mlkem-native`.
