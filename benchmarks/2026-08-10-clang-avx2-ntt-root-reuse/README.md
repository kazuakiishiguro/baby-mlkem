# Clang AVX2 Forward/Inverse NTT Root Reuse

Commit `1809825900eb257ad1baf240423281748b267a0b` removes the two
Clang AVX2-only forward-NTT level-1/2 Montgomery root tables. Those 1,024
read-only bytes duplicate the first 1,024 bytes of the already linked inverse
low/high tables in reverse 16-bit lane order.

The accepted implementation reverses each level's existing coefficient gather
and store arguments. It can therefore load the inverse vectors directly, with
no runtime shuffle. Each butterfly still receives the same coefficients and
factor, and the reversed stores restore the original coefficient order. The
arithmetic, output representation, API, and wire format are unchanged.

The generator now asserts the relation

```text
forward[level][vector][lane]
  == inverse[2 - level][7 - vector][15 - lane]
```

for both low and high factors at forward levels 1 and 2. An independent ELF
section check reaches the same result. See
[`root-relation.txt`](root-relation.txt).

## Environment

- CPU: AMD Ryzen Threadripper 7980X 64-Cores.
- Clang: Ubuntu Clang 18.1.3.
- GCC: Ubuntu GCC 13.3.0.
- Linker: GNU ld 2.42.
- Product KEM: CPU 0, three batches, three warmup pairs and sixteen measured
  pairs per batch, 100,000 iterations, alternating order.

Exact kernel, microcode, governor, flags, revisions, and run settings are in
[`environment.txt`](environment.txt).

## Production Size

Both artifacts use the normal production/no-cache speed flags. Primary size is
allocatable executable plus read-only data.

| Profile | Compiler | Baseline | Candidate | Delta | Candidate code | Candidate read-only | Candidate writable |
|---|---|---:|---:|---:|---:|---:|---:|
| AVX2-only | Clang | 49,712 B | 48,722 B | -990 B | 42,191 B | 6,531 B | 26,593 B |

The complete linked difference is isolated to one text section and two removed
read-only sections:

| Component | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| `ntt_mont_lazy_avx2` | 3,584 B | 3,618 B | +34 B |
| `ZETA_NTT_TAIL_MONT_LO_L12` | 512 B | 0 B | -512 B |
| `ZETA_NTT_TAIL_MONT_HI_L12` | 512 B | 0 B | -512 B |
| Net primary | 49,712 B | 48,722 B | -990 B |

All twenty-two other text sections and all thirteen retained read-only sections
are byte-identical. Writable storage is unchanged. The clean committed product
has SHA-256
`6d2f660ef7a830827b5e35aa8cbde0d13f90aebda481a1f69ac94f8df949bb91`.

See [`size-baseline.txt`](size-baseline.txt),
[`size-candidate.txt`](size-candidate.txt), and
[`section-accounting.txt`](section-accounting.txt).

## Direct Forward NTT Gate

The focused harness runs the complete production forward NTT over 64 rotating
polynomials. All 32 measured pairs are retained.

| Metric | Result |
|---|---:|
| Paired geometric mean | 1.004281636x |
| 95% bootstrap interval | 0.990387608x-1.018797939x |
| Wins | 17/32 |
| Candidate-first median | 0.991797205x |
| Baseline-first median | 1.015907876x |
| Checksum matches | 32/32 |

The point estimate passes the internal `0.995x` floor, but the interval and
opposite order medians expose a strong first/second-process effect. No direct
NTT speed gain is credited. See
[`direct-forward-ntt-32x2m.txt`](direct-forward-ntt-32x2m.txt) and
[`direct-forward-ntt-harness.c`](direct-forward-ntt-harness.c).

## Product Regression Gate

Baseline and candidate product objects are fixed for all 48 measured pairs.
Both benchmark executables reproduce byte-for-byte when linked from the same
benchmark object with SHA-256
`dbb898fba2eaea946e24274382339f6622b8234918377e085850d8ef84f49985`.
Every process confirms that normal and `*_core` metrics are equal because the
product API disables internal caches. Every sample is retained.

| Operation | Batch 1 | Batch 2 | Batch 3 | Combined 48 | 95% CI |
|---|---:|---:|---:|---:|---:|
| Keygen | 0.996972872x | 1.002530865x | 1.001705582x | 1.000400106x | 0.995594425x-1.005242288x |
| Encaps | 0.998121721x | 1.002599757x | 0.998528846x | 0.999748066x | 0.995180369x-1.004463732x |
| Decaps | 1.013711392x | 1.017012462x | 1.008093739x | 1.012932502x | 1.005501480x-1.021612057x |
| Roundtrip | 1.001433747x | 1.008834237x | 1.000957463x | 1.003735348x | 1.000118321x-1.007490517x |

The minimum combined operation is encapsulation at `0.999748066x`, above the
`0.995x` operation-regression floor. This report accepts the size reduction as
non-regressing. It does not turn the noisy direct result into a broad speed
claim.

See [`product-ab-combined-48x100k.txt`](product-ab-combined-48x100k.txt),
the three `product-ab-batch*-16x100k.txt` files, the retained
[`product-ab-screen-16x50k.txt`](product-ab-screen-16x50k.txt), and
[`artifact-identity.txt`](artifact-identity.txt).

## Correctness And Isolation

The exact implementation commit passes:

- GCC and Clang native, AVX2-only, and scalar KAT, production API, and complete
  1,000-iteration stage-oracle validation;
- Clang AVX2 ASan+UBSan KAT, directly linked production API, complete stage
  validation, and generator execution with no diagnostics;
- all 16 core, product, upstream, and PQClean corpus paths, each producing
  381,228 bytes with SHA-256
  `e4d8f908f9a3c59171deeed712925760b194d692b0c571861f204eabef976b67`;
- byte-identical products in all five non-target compiler/profile builds;
- identical global and unresolved symbols, no AVX512 register or symbol in the
  AVX2-only product, and non-executable GNU stack declarations; and
- a clean post-commit artifact identical to the timed and validation product.

LeakSanitizer alone is disabled because it cannot run under the environment's
ptrace restriction; AddressSanitizer and UndefinedBehaviorSanitizer remain
enabled.

See [`correctness-matrix.txt`](correctness-matrix.txt),
[`sanitizers.txt`](sanitizers.txt),
[`cross-path-corpus.txt`](cross-path-corpus.txt),
[`abi-audit.txt`](abi-audit.txt), [`ntt-roots.txt`](ntt-roots.txt), and
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

See [`stack.txt`](stack.txt) and the two raw stack reports.

## Rejected Runtime Shuffles

Three otherwise smaller table-sharing candidates loaded inverse vectors and
reversed them with `vpermq`/`vpshufd`, `vpermd`, or a hybrid. They reached
48,764 primary bytes, but direct forward NTT geometric means were
`0.974160573x`, `0.970389614x`, and `0.955631975x`, all with 0/15 wins. The
first candidate also failed the product floor at `0.994669408x`. All three were
removed. See [`rejected-candidates.txt`](rejected-candidates.txt) and the
retained rejected raw runs.

## Dependency Boundary

The accepted change links no external object or runtime library and adds no
cache, runtime dispatch, table, API, algorithm, or wire-format dependency. It
removes two repository-local immutable tables and reuses the already linked
inverse table. The Montgomery low/high decomposition remains explicitly
attributed to upstream Kyber in `THIRD_PARTY_NOTICES.md`; this commit claims a
repository-local data-layout reuse, not invention of that arithmetic.

## Remaining Goal Gap

Using the pinned same-method comparator sizes, the Clang AVX2-only deficit to
OpenSSL falls from 4,663 to 3,673 bytes. The unchanged native deficit to
mlkem-native remains 18,425 bytes. The required ten-comparator speed and size
gates have not been rerun on this same revision, and both primary-size gates
still fail. This commit therefore does not complete the optimization Goal.

## Reproduction

```bash
make clean
make -j"$(nproc)" product test-product CC=clang \
  ARCH_CFLAGS="-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f"
./scripts/measure_product_size.sh baby_mlkem768_product.o

JOBS="$(nproc)" ./scripts/verify_cross_path_corpus.sh
make check-ntt-roots HOSTCC=clang
make check-ntt-roots HOSTCC=gcc

STACK_RUNS=8 STACK_USABLE_BYTES=1048576 C_COMPILER=clang \
  STACK_CFLAGS='-O2 -march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f -fomit-frame-pointer -fno-stack-protector' \
  ./scripts/measure_stack_highwater.sh baby_mlkem768_product.o local
```

The cross-path script invokes `make clean`; run it in a clean checkout or
snapshot. The machine-checkable retained audit is
[`verify-evidence.sh`](verify-evidence.sh), with successful output in
[`evidence-check.txt`](evidence-check.txt).
