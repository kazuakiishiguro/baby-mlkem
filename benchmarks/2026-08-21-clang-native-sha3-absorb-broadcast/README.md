# Fixed SHA3 Absorb Qword-Broadcast Size Step

Commit `c05f714` changes the fixed 1,184-byte SHA3-256 public-key absorb
assembly. The rate and tail macros now use EVEX qword-broadcast memory XORs
instead of a temporary `vmovq` into `%xmm31` followed by a separate XOR. The
Keccak state is lane-independent at qword granularity, so the low qword result
consumed by this fixed hash is unchanged. The API, algorithm, wire format, and
cache behavior are unchanged.

This is an independent core assembly change. It does not add a vendor backend,
external cryptographic object, runtime library dependency, persistent cache, or
precomputed KEM result. The implementation and audit scope are in
[`source-audit.txt`](source-audit.txt).

## Revisions And Environment

- Baseline: `e73b71d`
- Candidate: `c05f714`
- Compiler: Ubuntu Clang 18.1.3
- GCC: Ubuntu GCC 13.3.0
- Linker: GNU ld 2.42
- CPU: AMD Ryzen Threadripper 7980X 64-Cores
- Product profile: `CC=clang ARCH_CFLAGS=-march=native`
- Backend: `AVX2_BACKEND=core`
- Cache mode: `BABY_MLKEM_DISABLE_INTERNAL_CACHES`
- Product timing: CPU 0, 3 warmups, 15 alternating pairs, 100,000 iterations

Exact flags and host details are in [`environment.txt`](environment.txt).

## Size

`Primary` is executable code plus read-only data. Writable storage is reported
separately.

| Quantity | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Primary product size | 57,424 B | 57,264 B | -160 B |
| Code | 46,570 B | 46,410 B | -160 B |
| Read-only data | 10,854 B | 10,854 B | 0 B |
| Writable storage | 18,001 B | 18,001 B | 0 B |
| Relocatable artifact | 84,344 B | 84,216 B | -128 B |

The exact measurements and hashes are [`size-baseline.txt`](size-baseline.txt)
and [`size-candidate.txt`](size-candidate.txt). The candidate artifact hash is
`830a73b5954571913d73b592c44c0d068dfc55aefba6dc4c9f4e95e5ef73a570`.

The GCC native size check independently moves primary/code/artifact from
`59,148`/`55,640`/`73,416` bytes to `58,814`/`55,306`/`73,096` bytes. Its
read-only data, unwind bytes, and writable storage are unchanged. The exact
GCC measurements are [`gcc-size-baseline.txt`](gcc-size-baseline.txt) and
[`gcc-size-candidate.txt`](gcc-size-candidate.txt).

## Product A/B

Ratios use `baseline_time / candidate_time`, so values above `1.0x` favor the
candidate. All four geometric means remain above the repository's `0.995x`
size-only screen floor, but the focused intervals were not used to credit a
speed improvement.

| Operation | Speedup gmean | Median | Wins |
|---|---:|---:|---:|
| Keygen | 0.99524x | 0.99968x | 7/15 |
| Encaps | 0.99811x | 1.00040x | 9/15 |
| Decaps | 1.00544x | 0.99950x | 7/15 |
| Roundtrip | 0.99918x | 1.00163x | 10/15 |

The raw alternating samples are in
[`product-ab-15x100k.txt`](product-ab-15x100k.txt); parsed values are in
[`product-ab-summary.txt`](product-ab-summary.txt).

The direct fixed `H(pk)` probe is neutral-to-slightly-slower: `0.999258x`
geometric mean, `0.999122x` median, and `1/15` wins. Its raw samples and
summary are [`fixed-h-ab-15x100k.txt`](fixed-h-ab-15x100k.txt) and
[`fixed-h-summary.txt`](fixed-h-summary.txt). No speed gain is claimed for the
fixed hash or the product API.

## Cross-Profile Identity

Clang and GCC native change. Clang AVX2-only, GCC AVX2-only, Clang scalar, and
GCC scalar artifacts are byte-identical to the parent; full hashes and primary
sizes are in [`profile-identity.txt`](profile-identity.txt).

| Profile | Candidate primary | Parent-identical |
|---|---:|---:|
| Clang native | 57,264 B | no |
| GCC native | 58,814 B | no |
| Clang AVX2-only | 45,032 B | yes |
| GCC AVX2-only | 53,019 B | yes |
| Clang scalar | 62,098 B | yes |
| GCC scalar | 22,994 B | yes |

## Validation And Status

The candidate passes NTT-root reproducibility, KAT/product checks, and the
Clang native fixed-H benchmark. The command record is in
[`validation.txt`](validation.txt). This focused report does not claim a new
ASan/UBSan or complete stage-harness rerun.

This is a size-only accepted step. The implementation is not yet the fastest or
smallest: native Clang remains roughly 6.1 KiB larger than the pinned
`mlkem-native` comparator, and the authoritative same-revision full comparator
speed rerun remains open. The next credible core work is the larger x8
Keccak producer/parser dataflow boundary or another native size reduction, not
further credit for this fixed-H change.

The report file hashes are in [`checksums.sha256`](checksums.sha256).
