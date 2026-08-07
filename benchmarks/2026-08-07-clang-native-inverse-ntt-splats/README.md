# Clang Native Inverse-NTT Splat Compaction

Commit `8173a06770dbfccfd4ac12d4ebc17164bb2cf048` compacts the static
Clang AVX512 inverse-NTT Montgomery-factor tables. Its parent is
`ea4cc07e9f6d4a7eb9abd619ba309bb3dca13464`.

Inverse levels 0..3 require 32 lane-shaped ZMM factors per low/high table.
Levels 4..5 require only six uniform splats. The parent stored those six
values as twelve 64-byte vectors. The candidate stores them as twelve
16-bit scalars and broadcasts each value at its existing use site. A bounded
Clang-only tail helper prevents full unrolling from duplicating the four-output
body. GCC and non-AVX512 paths retain their prior representation.

This is a production size optimization. It adds no external object, runtime
library, persistent cache, API, or wire-format dependency. It claims no speed
gain.

## Production Size

Both artifacts use Clang 18.1.3 production/no-cache flags with
`-march=native` on the AMD Ryzen Threadripper 7980X host.

| Native product metric | Parent `ea4cc07` | Candidate `8173a06` | Delta |
|---|---:|---:|---:|
| Inverse low/high factor data | 4,864 B | 4,120 B | -744 B |
| Total code | 74,366 B | 74,366 B | 0 B |
| Read-only data | 20,341 B | 19,597 B | -744 B |
| Primary | 94,707 B | 93,963 B | -744 B (-0.79%) |
| Zero-fill/writable | 18,001 B | 18,001 B | 0 B |
| ELF file | 130,552 B | 130,296 B | -256 B |

The dense tables are 2,048 bytes each. The scalar tails are 12 bytes each.
The candidate product SHA-256 is
`d65195d40e7640c67dbe6850efc1e4a318e49472318db6d5f08e6795c97cae2b`.
See [`native-size.txt`](native-size.txt) and
[`artifact-identity.txt`](artifact-identity.txt).

## Stack

Eight guarded alternate-stack runs reproduce the parent values exactly:

| Operation | Parent | Candidate | Delta |
|---|---:|---:|---:|
| Keygen | 8,760 B | 8,760 B | 0 B |
| Encaps | 6,904 B | 6,904 B | 0 B |
| Decaps valid | 9,400 B | 9,400 B | 0 B |
| Decaps invalid | 9,400 B | 9,400 B | 0 B |
| Maximum | 9,400 B | 9,400 B | 0 B |

See [`native-stack.txt`](native-stack.txt).

## Paired Native Gate

Three independent batches each used three warmup pairs and 15
alternating-order pairs of 100,000 iterations pinned to CPU 0. Ratios are
`parent_time / candidate_time`. Because the batches have equal counts, the
combined value is the geometric mean of their batch geometric means, equal to
the geometric mean over all 45 measured pairs.

| Operation | Batch 1 | Batch 2 | Batch 3 | Combined 45-pair geometric mean | Gate |
|---|---:|---:|---:|---:|---:|
| Keygen | 0.9984x | 1.0022x | 1.0001x | 1.0002x | PASS |
| Encaps | 0.9994x | 0.9923x | 0.9974x | 0.9964x | PASS |
| Decaps | 0.9990x | 1.0006x | 0.9955x | 0.9984x | PASS |
| Roundtrip | 0.9970x | 0.9994x | 0.9968x | 0.9977x | PASS |
| Keygen core | 1.0009x | 1.0032x | 1.0008x | 1.0016x | PASS |
| Encaps core | 0.9950x | 1.0023x | 0.9971x | 0.9981x | PASS |
| Decaps core | 0.9977x | 1.0016x | 0.9994x | 0.9996x | PASS |
| Roundtrip core | 0.9946x | 1.0011x | 0.9984x | 0.9980x | PASS |

The minimum combined value is `0.9964x`, above the internal `0.995x`
operation floor. Individual batches are retained to expose scheduler outliers
rather than hide them. See
[`native-ab-batch1-15x100k.txt`](native-ab-batch1-15x100k.txt),
[`native-ab-batch2-15x100k.txt`](native-ab-batch2-15x100k.txt),
[`native-ab-batch3-15x100k.txt`](native-ab-batch3-15x100k.txt), and
[`native-ab-combined-45x100k.txt`](native-ab-combined-45x100k.txt).

A focused inverse harness measured the shared four-output encryption inverse
and the decrypt inverse/subtract boundary. Two batches used 15 alternating
pairs at 200,000 and 500,000 iterations. Their combined paired medians are
`0.999148x` and `0.999360x`. Large scheduling outliers affected opposite
binaries, so this is supporting diagnostic evidence; the complete KEM gate
above is primary. See [`targeted-inverse-ab.txt`](targeted-inverse-ab.txt) and
[`targeted_inverse_bench.c`](targeted_inverse_bench.c).

## Correctness And Isolation

The accepted candidate passed:

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
- Byte-identical Clang native code in every section except the shared inverse
  section. That section remains 4,621 bytes; all three public API sections are
  byte-identical.

See [`correctness-matrix.txt`](correctness-matrix.txt),
[`sanitizers.txt`](sanitizers.txt),
[`cross-path-corpus.txt`](cross-path-corpus.txt),
[`ntt-roots.txt`](ntt-roots.txt),
[`artifact-identity.txt`](artifact-identity.txt), and
[`section-identity.txt`](section-identity.txt). File hashes are recorded in
[`SHA256SUMS`](SHA256SUMS).

## Rejected Wider Forms

Two more aggressive table shapes were measured and removed:

- Reconstructing every Montgomery-low vector from the high table saved 2,112
  primary bytes, but the direct shared inverse median fell to `0.989529x`.
- Scalar-broadcasting levels 3..5 saved 1,733 primary bytes, but the decrypt
  inverse/subtract geometric mean and median fell to `0.993776x` and
  `0.991496x`.

See [`rejected-candidates.txt`](rejected-candidates.txt). The accepted shape
keeps level 3 dense and introduces no extra multiply.

## Remaining Size Gap

Using the previously pinned same-method mlkem-native result of 51,186 primary
bytes, the targeted native gap falls from 43,521 to 42,777 bytes. This is not a
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
  ARCH_CFLAGS=-march=native ./scripts/bench_core_ab.sh ea4cc07

JOBS="$(nproc)" ./scripts/verify_cross_path_corpus.sh
make check-ntt-roots HOSTCC=clang
make check-ntt-roots HOSTCC=gcc

COMMON='-O3 -march=native -fno-semantic-interposition \
  -fvisibility=hidden -fomit-frame-pointer -fno-stack-protector \
  -falign-loops=64 -fno-unwind-tables -fno-asynchronous-unwind-tables \
  -fno-strict-aliasing -ffunction-sections -fdata-sections \
  -Wall -Wextra -Wno-unused-function -std=c99 -D_GNU_SOURCE \
  -DBABY_MLKEM_DISABLE_INTERNAL_CACHES \
  -DMLKEM_ENABLE_KECCAK_AVX512VL_ASM \
  -DMLKEM_ENABLE_KECCAKF8_MATRIX_AVX512_ASM'
clang $COMMON -I. \
  "-DSTAGE_SOURCE=\"$PWD/bench_core_stages.c\"" \
  benchmarks/2026-08-07-clang-native-inverse-ntt-splats/targeted_inverse_bench.c \
  sha3_256_1184_avx512vl.S keccakf8_matrix_avx512.S \
  bench_keccakf4_avx2.S -Wa,--noexecstack -Wl,--gc-sections \
  -o /tmp/targeted-inverse
taskset -c 0 /tmp/targeted-inverse 500000
```

Build the focused harness at both revisions and alternate their execution
order to reproduce the targeted comparison.
