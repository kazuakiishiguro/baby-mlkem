# Clang AVX2 Selective Keccak Mask Reuse

Commit `424a14181f08559e55749be5f9eb4601d94f7252` moves the two
32-byte `vpshufb` masks used for 8- and 56-bit Keccak lane rotations into one
repository-local read-only assembly section. Only two schedule-insensitive
copies use the shared symbols:

- the x3 matrix/hash path in `kpke_prepare_public_no_cache`; and
- the existing noinline x4 Keccak helper used by encryption.

The hot `sample_ntt4` and PRF/CBD copies retain their compiler-local masks.
Sharing all four copies reduced another 128 primary bytes, but changed Clang's
instruction scheduling and failed the retained product screen. The accepted
selection keeps every text section byte-identical to the baseline.

This is an independent baby-mlkem core size optimization. The constants and
assembly object are repository-local and add no vendored backend call,
external cryptographic object, runtime library, persistent cache, algorithm,
API, or wire-format dependency. The provenance of the pre-existing Keccak
schedule is unchanged and remains disclosed in `THIRD_PARTY_NOTICES.md`.

## Environment

- CPU: AMD Ryzen Threadripper 7980X 64-Cores.
- Clang: Ubuntu Clang 18.1.3.
- GCC: Ubuntu GCC 13.3.0.
- Linker: GNU ld 2.42.
- Product timing: CPU 0, three batches, three warmup pairs and sixteen
  measured pairs per batch, 100,000 iterations, alternating process order.

Exact host, kernel, microcode, governor, flags, revisions, and run settings
are in [`environment.txt`](environment.txt).

## Production Size

Both artifacts use the normal Clang AVX2 production/no-cache flags. Primary
size is allocatable executable plus read-only data.

| Profile | Baseline | Candidate | Delta | Candidate code | Candidate read-only | Candidate writable |
|---|---:|---:|---:|---:|---:|---:|
| Clang AVX2-only | 48,210 B | 48,146 B | -64 B | 42,191 B | 5,955 B | 26,593 B |

The section accounting is:

| Section | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| `.rodata.cst32` | 3,040 B | 2,912 B | -128 B |
| `.rodata.MLKEM_AVX2_SHARED_CONSTANTS` | 0 B | 64 B | +64 B |
| All 23 text sections | 42,191 B | 42,191 B | 0 B, byte-identical |
| Net primary | 48,210 B | 48,146 B | -64 B |

The relocatable ELF file grows from 74,248 to 74,272 bytes because it gains a
section and two hidden symbol records. ELF container metadata is outside the
primary metric; allocatable code plus read-only data falls by 64 bytes.
Writable storage and stack are unchanged.

The accepted object has SHA-256
`668bc7877907af53e849dcf85693f15600142c9f6a7ed965d39a094548bcf98c`.
See [`size-baseline.txt`](size-baseline.txt),
[`size-candidate.txt`](size-candidate.txt), and
[`section-accounting.txt`](section-accounting.txt).

## Product Regression Gate

The baseline/candidate objects and benchmark executable pair are fixed for all
48 measured pairs. Every process confirms that normal and `*_core` metrics are
equal because the product API disables internal caches. No sample is filtered.

| Operation | Batch 1 | Batch 2 | Batch 3 | Combined 48 | 95% CI |
|---|---:|---:|---:|---:|---:|
| Keygen | 0.995277482x | 1.001705179x | 1.011497614x | 1.002804606x | 0.998129574x-1.007940340x |
| Encaps | 0.994472985x | 1.003107087x | 1.001075600x | 0.999545086x | 0.995877184x-1.003367107x |
| Decaps | 1.003105342x | 0.991198317x | 0.994815767x | 0.996360694x | 0.989869882x-1.002613325x |
| Roundtrip | 0.997291881x | 0.999725054x | 1.002471043x | 0.999827088x | 0.996978081x-1.002817815x |

Each individual batch has at least one operation below the `0.995x` floor;
all three files are retained. The predefined decision statistic is the
combined 48-pair geometric mean. Its minimum is decapsulation at
`0.996360694x`, so the combined non-regression gate passes. Because every text
section is byte-identical and the measurements are noisy, no speed gain is
credited.

See [`product-ab-combined-48x100k.txt`](product-ab-combined-48x100k.txt),
the three `product-ab-batch*-16x100k.txt` files, and the retained
[`product-ab-screen-16x50k.txt`](product-ab-screen-16x50k.txt).

## Correctness And Isolation

The implementation commit passes:

- GCC and Clang native, AVX2-only, and scalar KAT, product API, and complete
  1,000-iteration stage-oracle validation;
- Clang AVX2 ASan+UBSan KAT, direct-linked product API, complete stage harness,
  and both generated NTT outputs with no sanitizer diagnostics;
- all 16 core, product, upstream, and PQClean corpus paths, each producing
  381,228 bytes with SHA-256
  `e4d8f908f9a3c59171deeed712925760b194d692b0c571861f204eabef976b67`;
- byte-identical products in all five non-target compiler/profile builds;
- the same public API functions and unresolved symbols, with only two new
  hidden internal read-only symbols;
- no AVX512 instruction registers and no executable GNU stack; and
- a clean committed product byte-identical to the timed and validation object.

See [`correctness-matrix.txt`](correctness-matrix.txt),
[`sanitizers.txt`](sanitizers.txt),
[`cross-path-corpus.txt`](cross-path-corpus.txt),
[`abi-audit.txt`](abi-audit.txt), and
[`postcommit-smoke.txt`](postcommit-smoke.txt).

## Stack

Eight guarded alternate-stack runs are unchanged:

| Operation | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Keygen | 4,512 B | 4,512 B | 0 B |
| Encaps | 4,144 B | 4,144 B | 0 B |
| Decaps valid | 4,512 B | 4,512 B | 0 B |
| Decaps invalid | 4,512 B | 4,512 B | 0 B |
| Maximum | 4,512 B | 4,512 B | 0 B |

See [`stack.txt`](stack.txt), [`stack-baseline-raw.txt`](stack-baseline-raw.txt),
and [`stack-candidate-raw.txt`](stack-candidate-raw.txt).

## Rejected Broader Sharing

Sharing both masks across all four inline copies reached 48,018 primary bytes,
a 192-byte reduction, but the 16-pair screen failed at decapsulation
`0.992980325x`. Sharing either mask alone reached only 48,178 bytes because
`sample_ntt4` grew 64 code bytes. Both forms were rejected. GNU gold can merge
all mergeable constants during a second relocatable link, but that packaging
normalization was not adopted because it was not applied consistently to every
Goal comparator.

See [`rejected-candidates.txt`](rejected-candidates.txt) and
[`rejected-broad-product-screen-16x50k.txt`](rejected-broad-product-screen-16x50k.txt).

## Goal Impact

Using the still-pinned OpenSSL AVX2-only product at 45,049 primary bytes, the
residual gap falls from 3,161 to 3,097 bytes. That comparator was not rebuilt
for this local A/B, and the complete ten-comparator matrix has not been rerun.
The primary-size gate therefore still fails, and the overall fastest-and-
smallest Goal remains incomplete.

Run the self-contained evidence audit with:

```bash
./benchmarks/2026-08-10-clang-avx2-selective-keccak-mask-reuse/verify-evidence.sh
```
