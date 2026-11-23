# Clang Native Default Loop Alignment 32

Commits `c3d955d` and `9166ea2` narrow the Clang loop-alignment choice for
native AVX512BW and AVX2-only builds. When the compiler is Clang on x86_64 ELF
and the effective architecture enables the selected AVX2/AVX512 feature set,
the Makefile or official goal-profile helper changes the default
`-falign-loops=64` to `-falign-loops=32`. A direct Makefile
`EXTRA_CFLAGS` selection remains authoritative.

This is a code-layout and product-size change. It changes no arithmetic,
algorithm, API, wire format, cache, vendored backend, external object, or
runtime library dependency. No speed gain is credited.

## Revisions And Environment

- Baseline: `e991ae3`
- Candidate: `9166ea2`
- Compiler: Ubuntu Clang 18.1.3
- GCC: Ubuntu GCC 13.3.0
- Linker: GNU ld 2.42
- Kernel: Linux 6.8.0-124-generic
- CPU: AMD Ryzen Threadripper 7980X 64-Cores
- Product profile: `CC=clang ARCH_CFLAGS=-march=native`
- Product timing: 3 warmups, 15 alternating pairs, 100,000 iterations
- CPU pinning: CPU 0
- Backend: `AVX2_BACKEND=core`

The exact build flags, source guard, and reproducibility commands are in
[`environment.txt`](environment.txt) and [`source-audit.txt`](source-audit.txt).

## Size

`Primary` is executable code plus read-only data. Writable storage is reported
separately.

| Quantity | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Primary product size | 61,086 B | 60,926 B | -160 B |
| Code | 46,264 B | 46,104 B | -160 B |
| Read-only data | 14,822 B | 14,822 B | 0 B |
| Writable storage | 18,001 B | 18,001 B | 0 B |
| Relocatable artifact | 88,376 B | 88,120 B | -256 B |

The raw reports are [`size-baseline.txt`](size-baseline.txt) and
[`size-candidate.txt`](size-candidate.txt). The candidate product hash is
`6945c720043acea20904683853208d57d860e1ff3fc00459a5476af000ebcc3b`.

## Product A/B

Values are operations per second. Ratios are `candidate / baseline`, so values
above `1.0x` favor the candidate. The result is treated as size-only.

| Operation | Baseline mean ops/s | Candidate mean ops/s | Paired gmean | Paired median | Wins |
|---|---:|---:|---:|---:|---:|
| Keygen | 255,019.49 | 255,414.86 | 1.001538x | 1.002682x | 12/15 |
| Encaps | 284,042.75 | 283,246.93 | 0.997132x | 0.999396x | 6/15 |
| Decaps | 350,672.36 | 356,962.59 | 1.018526x | 1.011603x | 13/15 |
| Roundtrip | 96,322.94 | 96,443.54 | 1.001262x | 1.003398x | 9/15 |

The bootstrap 95% lower and upper bounds are `0.994786x..1.007168x` for
keygen, `0.988857x..1.004348x` for encapsulation,
`1.007770x..1.033549x` for decapsulation, and
`0.996285x..1.006164x` for roundtrip. These are product size-screen results,
not a claim that loop alignment improves throughput.

Raw alternating samples are in [`product-ab-15x100k.txt`](product-ab-15x100k.txt)
and the parsed values are in [`product-ab-summary.txt`](product-ab-summary.txt).

## Cross-Profile Identity

The native Clang product is the only changed profile. The other five products
are byte-identical to the baseline, as recorded in
[`profile-identity.txt`](profile-identity.txt).

| Profile | Candidate primary | Candidate SHA-256 | Parent-identical |
|---|---:|---|---|
| Clang native | 60,926 B | `6945c720...` | no |
| GCC native | 59,148 B | `4a2b129b...` | yes |
| Clang AVX2 | 45,032 B | `b6fd46a0...` | yes |
| GCC AVX2 | 53,019 B | `c2816644...` | yes |
| Clang scalar | 62,098 B | `b3d4f765...` | yes |
| GCC scalar | 22,994 B | `2bccdaa6...` | yes |

An explicit native Clang
`EXTRA_CFLAGS='... -falign-loops=64 ...'` build restores the baseline
61,086-byte product and hash `e4e6a73b...`.

## Validation

The candidate passed the native product test, normal KAT, complete 30,000
iteration stage harness, `make check-ntt-roots`, and an 8-run stack probe.
The stage range and timing output is in
[`stage-candidate.txt`](stage-candidate.txt); maximum stack remains 8,056 B.

Clang native ASan+UBSan KAT passed with
`ASAN_OPTIONS=detect_leaks=0`; no sanitizer diagnostic was emitted. LeakSanitizer
is disabled because the execution environment uses ptrace. The profile hashes
and build commands are retained in the companion files.

## Goal Status

At the current same-revision native comparator sizes, 60,926 B passes Kyber by
106 B, fair Kyber by 1,149 B, and PQClean by 24 B, but remains 9,726 B larger
than mlkem-native. Clang AVX2 remains 45,032 B and passes all pinned AVX2
primary-size comparisons, including OpenSSL by 17 B.

The final same-revision all-library speed rerun and the mlkem-native native
size gate remain open. The overall fastest-and-smallest goal is not claimed.
