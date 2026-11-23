# Clang Native Inverse-Final Add4 Splat Compaction

Commit `626da41d4fbfa165e17e11aad86d2dcc87ebbdf9` compacts the final
Montgomery factors used by Clang's four-output AVX512 inverse-NTT/add path.
The baseline is `01c14d4a87286985fc7efde84ded9c1225370bf4`.

Clang already materialized the three final factors with `vpbroadcastw`, but
also retained one 64-byte ZMM splat for each value. The accepted form stores
`512`, `-32522`, and `-266` as three generated `int16_t` values. The low scale
keeps the baseline `vpsllw $9` sequence rather than introducing another
multiply. The change is deliberately limited to
`ntt_inv_add4_eta2_i8_mont_final_shared_avx512`; applying the same
representation to decapsulation's inverse/recover path failed the performance
gate and was removed.

This is a production size optimization. It adds no external object, runtime
library, persistent cache, API, or wire-format dependency, and it claims no
speed gain.

## Environment

- CPU: AMD Ryzen Threadripper 7980X 64-Cores, microcode `0xa108108`.
- OS kernel: Linux 6.8.0-124-generic x86_64.
- Clang: Ubuntu Clang 18.1.3.
- GCC: Ubuntu GCC 13.3.0.
- Linker: GNU ld 2.42.
- Native profile: `-march=native`; timed runs pinned to CPU 0.

Exact compiler flags and the recording time are in
[`environment.txt`](environment.txt).

## Production Size

Both products use Clang 18.1.3's normal production/no-cache flags with
`-march=native`.

| Native product metric | Baseline `01c14d4` | Candidate `626da41` | Delta |
|---|---:|---:|---:|
| Total code | 74,366 B | 74,366 B | 0 B |
| Read-only data | 19,473 B | 19,287 B | -186 B |
| Primary | 93,839 B | 93,653 B | -186 B (-0.20%) |
| Zero-fill/writable | 18,001 B | 18,001 B | 0 B |
| ELF file | 130,144 B | 130,216 B | +72 B |
| ELF sections | 73 | 74 | +1 |
| Relocations | 942 | 942 | 0 |
| `vpbroadcastw` instructions | 64 | 64 | 0 |

The ordinary `.rodata` pool falls by 192 bytes, exactly three 64-byte splats.
The generated scalar section adds 6 bytes, for a net primary reduction of 186
bytes. The ELF container grows because the extra named section adds
non-allocatable section/symbol metadata; ELF file size is not the production
footprint gate.

Seventeen of eighteen executable sections are byte-identical. The only changed
section is the 4,621-byte four-output inverse/add function, and its size is
unchanged. The inlined inverse/recover path and all public API sections remain
byte-identical. The final product SHA-256 is
`8ca9abbab594a7a3a76270c59bba0f5d16304ca8d98b2bc01b19bd54a3f6ccd8`.

See [`native-size.txt`](native-size.txt) and
[`section-identity.txt`](section-identity.txt).

## Stack

Eight guarded alternate-stack runs reproduce the baseline values:

| Operation | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Keygen | 8,760 B | 8,760 B | 0 B |
| Encaps | 6,904 B | 6,904 B | 0 B |
| Decaps valid | 9,400 B | 9,400 B | 0 B |
| Decaps invalid | 9,400 B | 9,400 B | 0 B |
| Maximum | 9,400 B | 9,400 B | 0 B |

See [`native-stack.txt`](native-stack.txt).

## Paired Native Gate

The KEM gate used two independent batches with three warmup pairs and 15
alternating-order pairs of 100,000 iterations per batch, pinned to CPU 0. The
second batch reversed which binary ran first in odd pairs. Ratios are
`baseline_time / candidate_time`; the combined column is the geometric mean of
the two equal-size batch geometric means.

| Operation | Batch 1 | Batch 2 | Combined 30-pair geometric mean | Gate |
|---|---:|---:|---:|---:|
| Keygen | 0.9977x | 0.9976x | 0.9976x | PASS |
| Encaps | 1.0001x | 1.0001x | 1.0001x | PASS |
| Decaps | 1.0007x | 1.0017x | 1.0012x | PASS |
| Roundtrip | 0.9982x | 0.9989x | 0.9985x | PASS |
| Keygen core | 0.9985x | 0.9973x | 0.9979x | PASS |
| Encaps core | 0.9994x | 0.9952x | 0.9973x | PASS |
| Decaps core | 1.0025x | 1.0059x | 1.0042x | PASS |
| Roundtrip core | 0.9999x | 0.9978x | 0.9988x | PASS |

Every combined operation value is above the internal `0.995x` regression
floor. These neutral results support a size-only claim, not a speedup claim.
See [`native-ab-batch1-15x100k.txt`](native-ab-batch1-15x100k.txt),
[`native-ab-batch2-reversed-15x100k.txt`](native-ab-batch2-reversed-15x100k.txt),
and [`native-ab-combined-30x100k.txt`](native-ab-combined-30x100k.txt).

A focused harness separately measured the changed add4 function and the
unchanged recover control. Two balanced 15-pair batches used 500,000 iterations
per process:

| Direct metric | Combined geometric mean | Median | Wins | Gate |
|---|---:|---:|---:|---:|
| Add4, resident ring | 0.999162723x | 0.999902375x | 14/30 | PASS |
| Add4, fixture copy | 1.000646867x | 0.999627632x | 11/30 | PASS |
| Recover control, resident ring | 1.003024926x | 1.000523995x | 19/30 | PASS |
| Recover control, fixture copy | 0.995710039x | 0.997744427x | 7/30 | PASS |

Every baseline/candidate sink matched. See
[`targeted-inverse-final-ab.txt`](targeted-inverse-final-ab.txt) and
[`targeted_inverse_final_bench.c`](targeted_inverse_final_bench.c).

## Correctness And Isolation

The candidate passed:

- GCC and Clang native, AVX2-only, and scalar KAT, product, and complete stage
  validation.
- Clang native ASan+UBSan and GCC native UBSan KAT, directly linked product,
  and complete stage validation.
- Clang- and GCC-generated NTT table reproducibility checks; the generator also
  passed ASan+UBSan with LeakSanitizer disabled for the sandbox.
- All 16 cross-path corpus variants, each 381,228 bytes with SHA-256
  `e4d8f908f9a3c59171deeed712925760b194d692b0c571861f204eabef976b67`.
- Byte-identical Clang AVX2-only and GCC native products, retaining SHA-256
  `444e4b7e99fcef956dfe7655ff66de308f3e32a134848868e810ab90d4d82584`
  and
  `76cb2e25b1f7860268de66a191534f677ec44655a07444e94b7d9cb93e9377c0`.
- A post-commit product rebuild at `626da41` exactly reproduced the measured
  candidate artifact.

See [`correctness-matrix.txt`](correctness-matrix.txt),
[`sanitizers.txt`](sanitizers.txt),
[`cross-path-corpus.txt`](cross-path-corpus.txt),
[`ntt-roots.txt`](ntt-roots.txt), and
[`artifact-identity.txt`](artifact-identity.txt). File hashes are recorded in
[`SHA256SUMS`](SHA256SUMS).

## Rejected Wider Forms

Scalarizing both add4 and inverse/recover reduced primary size by 386 bytes,
but direct recover geometric means fell to `0.969528535x` and `0.966759777x`.
Its 15-pair KEM run also put `decaps_core` at `0.9927x`, below the operation
floor. Reserving `zmm15` for an early factor load was worse, with direct recover
at `0.946749350x` and `0.943219294x`. Both forms were removed; only add4 uses
the scalar factors.

See [`rejected-candidates.txt`](rejected-candidates.txt).

## Remaining Size Gap

Using the previously pinned same-method mlkem-native result of 51,186 primary
bytes, the targeted native gap falls from 42,653 to 42,467 bytes. This is not a
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
  ARCH_CFLAGS=-march=native ./scripts/bench_core_ab.sh 01c14d4

JOBS="$(nproc)" ./scripts/verify_cross_path_corpus.sh
make check-ntt-roots HOSTCC=clang
make check-ntt-roots HOSTCC=gcc
```

Build the focused harness against each revision and alternate their execution
order to reproduce the direct comparison. Reverse the odd-pair starting binary
for the second KEM batch to reproduce the balanced 30-pair order.
