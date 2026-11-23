# Clang AVX2 Default Loop Alignment

Commit `bf5b5bc` changes only the Makefile's default Clang loop-alignment flag
for the AVX2-only product path. When no explicit `EXTRA_CFLAGS` is supplied and
`ARCH_CFLAGS` contains `-mavx2 -mno-avx512f`, the default
`-falign-loops=64` is replaced with `-falign-loops=32`.

This is a compiler layout and product-size optimization. It does not change
the core algorithm, API, wire format, key/result cache behavior, or external
dependencies. It is not a claim that baby-mlkem's core is faster than upstream
AVX2 because of this change.

## Revisions And Environment

- Baseline: parent `0d79d92`.
- Candidate: `bf5b5bc`.
- Backend: `AVX2_BACKEND=core`.
- Compiler: Ubuntu Clang 18.1.3.
- Host: x86-64 Linux, pinned to CPU 0.
- Product timing: two independent alternating batches, 16 baseline/candidate
  pairs per batch, 100,000 iterations per process.
- Architecture flags: `-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f`.
- Baseline extra flags: `-fomit-frame-pointer -fno-stack-protector
  -falign-loops=64 -fno-unwind-tables -fno-asynchronous-unwind-tables
  -fno-strict-aliasing`.
- Candidate extra flags: the same flags with `-falign-loops=32`.

The ratio is `baseline ns/op / candidate ns/op`; values above `1.0x` favor the
candidate. The individual process outputs are in
[`product-ab-batch1-16x100k.txt`](product-ab-batch1-16x100k.txt) and
[`product-ab-batch2-16x100k.txt`](product-ab-batch2-16x100k.txt). The parsed
values are in [`product-ab-summary.txt`](product-ab-summary.txt).

## Product Size

`Primary` is executable code plus read-only data. Writable storage is reported
separately.

| Quantity | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Primary product size | 46,772 B | 46,100 B | -672 B |
| Code | 41,423 B | 40,751 B | -672 B |
| Read-only data | 5,349 B | 5,349 B | 0 B |
| Writable storage | 26,593 B | 26,593 B | 0 B |
| Relocatable artifact | 72,408 B | 71,480 B | -928 B |

The primary footprint is reduced by 1.44%. The raw size reports are
[`size-baseline.txt`](size-baseline.txt) and
[`size-candidate.txt`](size-candidate.txt).

## Product A/B

| Operation | Batch 1 gmean | Batch 2 gmean | Combined gmean | Combined wins |
|---|---:|---:|---:|---:|
| Keygen | 1.008853x | 1.000102x | 1.004468x | 19/32 |
| Encaps | 0.999262x | 1.002212x | 1.000736x | 16/32 |
| Decaps | 0.992588x | 0.998477x | 0.995528x | 17/32 |
| Roundtrip | 1.000800x | 1.000741x | 1.000771x | 18/32 |

Combined baseline/candidate means were `5705.78/5680.00 ns/op` for keygen,
`4566.34/4562.77 ns/op` for encaps, `4555.13/4576.32 ns/op` for decaps, and
`15120.19/15108.60 ns/op` for roundtrip. Batch 1 decaps regresses to
`0.992588x`; an earlier independent screen also had a batch-level keygen
regression. Therefore this change receives no speed credit. It is accepted for
the reproducible size reduction with aggregate non-regression evidence only.

## Cross-Profile Identity

The intended changed profile is Clang AVX2 only. Candidate product hashes for
the other checked profiles are byte-identical to their matching baselines.

| Profile | Baseline SHA-256 | Candidate SHA-256 | Result |
|---|---|---|---|
| Clang AVX2 | `f7805de3d2cc0edb4ae8371329cb56370ba4e3783ed144a9f595ee00efeeb557` | `c9c9a3559f2f6b181c18f1d72233691b817b19b046fe06eb24bcb135d065ba93` | intended size change |
| Clang scalar | `b3d4f765b924692c035e5d8394f638df4d2f1624b1065130089e848fecc4b7d2` | same | byte-identical |
| GCC AVX2 | `909b0a75840c32502b7beceba2f12f1b47da6e35518dec69a66b1c5251348eb9` | same | byte-identical |
| Clang native | `9b534f8f47a282baeb9eeed8916f4648800d05854c72d9e2e729ba3739478ec2` | same | byte-identical |

The complete profile evidence is in
[`profile-identity.txt`](profile-identity.txt).

All recorded report files are covered by
[`checksums.sha256`](checksums.sha256).

## Correctness

The candidate passed the exact-profile test, product KAT, normal test, NTT
root check, and product-size accounting. The post-commit command summary is in
[`postcommit-smoke.txt`](postcommit-smoke.txt).

Explicit `EXTRA_CFLAGS` overrides remain untouched, so users who provide their
own alignment or other extra flags retain control of the build.
