# Clang Native Forward-NTT First-Splat Compaction

Commits `a207a8fdbd50ce6ada9346a784785b8cdb2c5e3d` and
`2420c08aa35c1f44bed8b70a110e6fe7c2a180bf` compact the first Clang
AVX512 forward-NTT Montgomery-factor splat. Their baseline is
`d36b685e55f3da84a61a1c8baaadc8a80525f6cf`.

The first low/high factor pair is reused by four ZMM butterflies. Clang already
loads each repeated 64-byte constant with `vpbroadcastw`, so retaining 32 equal
lanes wastes read-only data without reducing the instruction count. The final
form stores that pair as two 16-bit values and keeps the other fourteen pairs
as dense ZMM constants. A volatile read prevents Clang from rematerializing the
two scalar values as full vectors.

The two forward values share the existing low/high scalar pools with the six
uniform inverse-NTT factors. This avoids adding ELF sections solely for two-byte
objects. GCC and non-AVX512 paths retain their prior representations.

This is a production size optimization. It adds no external object, runtime
library, persistent cache, API, or wire-format dependency. It claims no speed
gain.

## Production Size

Both artifacts use Clang 18.1.3 production/no-cache flags with
`-march=native` on the AMD Ryzen Threadripper 7980X host.

| Native product metric | Baseline `d36b685` | Final `2420c08` | Delta |
|---|---:|---:|---:|
| Forward-head low/high factor data | 1,920 B | 1,796 B | -124 B |
| Total code | 74,366 B | 74,366 B | 0 B |
| Read-only data | 19,597 B | 19,473 B | -124 B |
| Primary | 93,963 B | 93,839 B | -124 B (-0.13%) |
| Zero-fill/writable | 18,001 B | 18,001 B | 0 B |
| ELF file | 130,296 B | 130,144 B | -152 B |
| ELF section count | 73 | 73 | 0 |

The dense low/high tables are 896 bytes each. The forward contribution to the
shared scalar pools is two bytes per side. The final product SHA-256 is
`664040834ecc2c0def235f256c9b4d0f240fa47a928820f3bf7c6823320c8f04`.
See [`native-size.txt`](native-size.txt),
[`artifact-identity.txt`](artifact-identity.txt), and
[`section-identity.txt`](section-identity.txt).

## Stack

Eight guarded alternate-stack runs reproduce the baseline values exactly:

| Operation | Baseline | Final | Delta |
|---|---:|---:|---:|
| Keygen | 8,760 B | 8,760 B | 0 B |
| Encaps | 6,904 B | 6,904 B | 0 B |
| Decaps valid | 9,400 B | 9,400 B | 0 B |
| Decaps invalid | 9,400 B | 9,400 B | 0 B |
| Maximum | 9,400 B | 9,400 B | 0 B |

See [`native-stack.txt`](native-stack.txt).

## Paired Native Gate

The primary KEM gate used three independent batches, each with three warmup
pairs and 15 alternating-order pairs of 100,000 iterations pinned to CPU 0.
Ratios are `baseline_time / candidate_time`.

| Operation | Batch 1 | Batch 2 | Batch 3 | Combined 45-pair geometric mean | Gate |
|---|---:|---:|---:|---:|---:|
| Keygen | 0.9979x | 1.0026x | 1.0093x | 1.0033x | PASS |
| Encaps | 1.0005x | 0.9995x | 1.0013x | 1.0004x | PASS |
| Decaps | 0.9984x | 0.9999x | 1.0044x | 1.0009x | PASS |
| Roundtrip | 0.9987x | 0.9976x | 1.0040x | 1.0001x | PASS |
| Keygen core | 0.9969x | 1.0051x | 1.0083x | 1.0035x | PASS |
| Encaps core | 1.0001x | 0.9944x | 0.9966x | 0.9970x | PASS |
| Decaps core | 0.9977x | 1.0007x | 1.0014x | 0.9999x | PASS |
| Roundtrip core | 0.9972x | 0.9988x | 1.0035x | 0.9998x | PASS |

The minimum combined value is `0.997032685x`, above the internal `0.995x`
operation floor. These 45 pairs measured `a207a8f`. Pool consolidation in
`2420c08` leaves every product text section byte-identical to `a207a8f` and
keeps the same 993 relocations. A separate final-layout 15-pair run passes all
eight KEM metrics; its minimum is `0.997560069x`.

See [`native-ab-batch1-15x100k.txt`](native-ab-batch1-15x100k.txt),
[`native-ab-batch2-15x100k.txt`](native-ab-batch2-15x100k.txt),
[`native-ab-batch3-15x100k.txt`](native-ab-batch3-15x100k.txt),
[`native-ab-combined-45x100k.txt`](native-ab-combined-45x100k.txt),
[`final-kem-ab-15x100k.txt`](final-kem-ab-15x100k.txt), and
[`pool-text-identity.txt`](pool-text-identity.txt).

A focused final-layout harness measured six direct head transforms with and
without fixture copies, plus six complete forward transforms. Across two
15-pair batches, the combined geometric means are `1.000709x`, `1.002088x`,
and `0.999876x`; the paired medians are `1.001073x`, `1.003755x`, and
`1.000484x`. See [`targeted-forward-ab.txt`](targeted-forward-ab.txt) and
[`targeted_forward_bench.c`](targeted_forward_bench.c).

## Correctness And Isolation

The final candidate passed:

- GCC and Clang native, AVX2-only, and scalar KAT, product, and complete stage
  validation.
- Clang native ASan+UBSan and GCC native UBSan KAT, direct-linked product, and
  complete stage validation.
- Clang- and GCC-generated NTT table reproducibility checks; the generator also
  passed ASan+UBSan with LeakSanitizer disabled for the sandbox.
- All 16 cross-path corpus variants, each 381,228 bytes with SHA-256
  `e4d8f908f9a3c59171deeed712925760b194d692b0c571861f204eabef976b67`.
- Byte-identical Clang AVX2-only and GCC native products, retaining SHA-256
  `444e4b7e99fcef956dfe7655ff66de308f3e32a134848868e810ab90d4d82584`
  and
  `76cb2e25b1f7860268de66a191534f677ec44655a07444e94b7d9cb93e9377c0`.
- Byte-identical Clang native code in every section except the 1,089-byte
  forward-head section. Its instruction count remains 169, the whole-product
  `vpbroadcastw` count remains 64, and all three public API sections are byte
  identical.

See [`correctness-matrix.txt`](correctness-matrix.txt),
[`sanitizers.txt`](sanitizers.txt),
[`cross-path-corpus.txt`](cross-path-corpus.txt),
[`ntt-roots.txt`](ntt-roots.txt),
[`artifact-identity.txt`](artifact-identity.txt), and
[`section-identity.txt`](section-identity.txt). File hashes are recorded in
[`SHA256SUMS`](SHA256SUMS).

## Rejected Wider Forms

Clang folds an unguarded scalar table back into the original full-vector
constants, producing the exact baseline artifact. Forcing all 15 pairs to stay
scalar saves 1,032 primary bytes but reduces direct six-head throughput to
about `0.73x`. Prefixes of three and seven pairs similarly reduce primary size
by 179 and 623 bytes but regress the direct head to about `0.81x` and `0.76x`.
Only the first pair is retained because Clang already broadcasts it in the
baseline instruction schedule.

See [`rejected-candidates.txt`](rejected-candidates.txt).

## Remaining Size Gap

Using the previously pinned same-method mlkem-native result of 51,186 primary
bytes, the targeted native gap falls from 42,777 to 42,653 bytes. This is not a
completion-qualifying all-comparator rerun, and the primary-size gate still
fails.

## Reproduction

```bash
make clean
make -j"$(nproc)" product test-product CC=clang \
  ARCH_CFLAGS=-march=native
./scripts/measure_product_size.sh baby_mlkem768_product.o

RUNS=15 WARMUP_RUNS=3 RUN_ORDER=alternating SUITES=kem \
  KEM_ITERS=100000 PIN_CPU=0 C_COMPILER=clang \
  ARCH_CFLAGS=-march=native ./scripts/bench_core_ab.sh d36b685

JOBS="$(nproc)" ./scripts/verify_cross_path_corpus.sh
make check-ntt-roots HOSTCC=clang
make check-ntt-roots HOSTCC=gcc
```

Build the focused harness at both revisions and alternate their execution order
to reproduce the direct forward-NTT comparison.
