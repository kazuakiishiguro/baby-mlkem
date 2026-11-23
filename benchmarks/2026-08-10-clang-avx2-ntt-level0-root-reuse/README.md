# Clang AVX2 Forward/Inverse NTT Level-0 Root Reuse

Commit `df1501ffb2efb6cfbc8563b4a7e0d8d93960feec` extends the existing
Clang AVX2 forward/inverse root sharing to forward level 0. The level-0 low
and high Montgomery factors already occur in the linked inverse tables under
the same relation used by levels 1 and 2:

```text
forward[level][vector][lane]
  == inverse[2 - level][7 - vector][15 - lane]
```

Level 0 repeats each factor across eight lanes. Swapping the two existing
eight-lane gather and store arguments therefore realizes the required lane
reversal without adding a shuffle. The butterfly arithmetic, coefficient
result order, API, and wire format are unchanged. The generator now checks
the relation for all three forward tail levels.

This is independent baby-mlkem core code. It reuses a repository-local table
that the product already links; it adds no vendored backend call, external
cryptographic object, runtime library, persistent cache, or new table. The
underlying Montgomery decomposition remains attributed to upstream Kyber in
`THIRD_PARTY_NOTICES.md`.

## Environment

- CPU: AMD Ryzen Threadripper 7980X 64-Cores.
- Clang: Ubuntu Clang 18.1.3.
- GCC: Ubuntu GCC 13.3.0.
- Linker: GNU ld 2.42.
- Product timing: CPU 0, three batches, three warmup pairs and sixteen
  measured pairs per batch, 100,000 iterations, alternating order.

Exact host, kernel, microcode, governor, flags, revisions, and run settings
are in [`environment.txt`](environment.txt).

## Production Size

Both artifacts use the normal Clang AVX2 production/no-cache flags. Primary
size is allocatable executable plus read-only data.

| Profile | Baseline | Candidate | Delta | Candidate code | Candidate read-only | Candidate writable |
|---|---:|---:|---:|---:|---:|---:|
| Clang AVX2-only | 48,722 B | 48,210 B | -512 B | 42,191 B | 6,019 B | 26,593 B |

The complete linked difference is isolated to one same-size text section and
one smaller compiler constant-pool section:

| Section | Baseline | Candidate | Delta | Result |
|---|---:|---:|---:|---|
| `.text.ntt_mont_lazy_avx2` | 3,618 B | 3,618 B | 0 B | changed lane/register schedule |
| `.rodata.cst32` | 3,552 B | 3,040 B | -512 B | redundant level-0 factors removed |
| Net primary | 48,722 B | 48,210 B | -512 B | accepted |

All twenty-two other text sections and all twelve other read-only sections
are byte-identical. Writable storage is unchanged. The timed, six-profile
validation, and clean post-commit products all have SHA-256
`a75152c5f4502528809633747b2502a4b0cfeadc83daa428f92ddb4e3f86738f`.

See [`size-baseline.txt`](size-baseline.txt),
[`size-candidate.txt`](size-candidate.txt),
[`section-accounting.txt`](section-accounting.txt), and
[`artifact-identity.txt`](artifact-identity.txt).

## Direct Forward NTT Gate

The focused harness runs the complete production forward NTT over 64 rotating
polynomials. All 32 measured pairs are retained.

| Metric | Result |
|---|---:|
| Paired geometric mean | 1.005638165x |
| 95% bootstrap interval | 0.990275623x-1.024295784x |
| Wins | 18/32 |
| Candidate-first median | 0.990673454x |
| Baseline-first median | 1.008172441x |
| Checksum matches | 32/32 |

The point estimate passes the internal `0.995x` floor, but the opposing order
medians show a strong process-order effect. No direct NTT speed gain is
credited. See [`direct-forward-ntt-32x2m.txt`](direct-forward-ntt-32x2m.txt)
and [`direct-forward-ntt-harness.c`](direct-forward-ntt-harness.c).

## Product Regression Gate

The baseline and candidate objects and both benchmark executables are fixed
for all 48 measured pairs. Every process confirms that normal and `*_core`
metrics are equal because the product API disables internal caches. No sample
is filtered.

| Operation | Batch 1 | Batch 2 | Batch 3 | Combined 48 | 95% CI |
|---|---:|---:|---:|---:|---:|
| Keygen | 0.996375603x | 1.001620039x | 1.004001939x | 1.000660785x | 0.996286506x-1.004991504x |
| Encaps | 1.000510389x | 0.993055377x | 1.002296597x | 0.998612754x | 0.993365958x-1.003080931x |
| Decaps | 0.996971996x | 0.995735029x | 1.000615499x | 0.997772026x | 0.991967444x-1.003901306x |
| Roundtrip | 0.997864913x | 0.998807739x | 1.002984514x | 0.999883249x | 0.996453874x-1.003287442x |

The minimum combined operation is decapsulation at `0.997772026x`, above the
`0.995x` operation-regression floor. This accepts the size reduction as
non-regressing; it does not claim a broad KEM speedup.

See [`product-ab-combined-48x100k.txt`](product-ab-combined-48x100k.txt),
the three `product-ab-batch*-16x100k.txt` files, and the retained
[`product-ab-screen-16x50k.txt`](product-ab-screen-16x50k.txt).

## Correctness And Isolation

The exact implementation commit passes:

- GCC and Clang native, AVX2-only, and scalar KAT, product API, and complete
  1,000-iteration stage-oracle validation;
- Clang AVX2 ASan+UBSan KAT, product API, complete stage validation, and both
  generator outputs with no diagnostics;
- all 16 core, product, upstream, and PQClean corpus paths, each producing
  381,228 bytes with SHA-256
  `e4d8f908f9a3c59171deeed712925760b194d692b0c571861f204eabef976b67`;
- byte-identical products in all five non-target compiler/profile builds;
- identical global and unresolved symbols, no AVX512 registers or symbols in
  the AVX2-only product, and non-executable GNU stack declarations; and
- a clean committed product identical to the timed and validation products.

LeakSanitizer alone is disabled because it cannot run under the environment's
ptrace restriction; AddressSanitizer and UndefinedBehaviorSanitizer remain
enabled.

See [`correctness-matrix.txt`](correctness-matrix.txt),
[`sanitizers.txt`](sanitizers.txt),
[`cross-path-corpus.txt`](cross-path-corpus.txt),
[`abi-audit.txt`](abi-audit.txt), [`root-relation.txt`](root-relation.txt),
[`ntt-roots.txt`](ntt-roots.txt), and
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

## Goal Impact

Using the still-pinned OpenSSL AVX2-only product at 45,049 primary bytes, the
residual gap falls from 3,673 to 3,161 bytes. That comparator was not rebuilt
for this local A/B, and the complete ten-comparator matrix has not been rerun.
The primary-size gate therefore still fails and the overall fastest-and-
smallest Goal remains incomplete.

Run the self-contained evidence audit with:

```bash
./benchmarks/2026-08-10-clang-avx2-ntt-level0-root-reuse/verify-evidence.sh
```
