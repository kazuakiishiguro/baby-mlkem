# Clang Native Shared Public Preparation

Commit `13b3ea1227ce2892e8ac89dd967d888628affa40` shares Clang native
AVX512's uncached public-key preparation between encapsulation and
decapsulation. The baseline is
`626da41d4fbfa165e17e11aad86d2dcc87ebbdf9`.

Both callers need the same three-polynomial d12 decode and eight-way matrix
setup before entering the already shared hash/matrix-tail helper. The baseline
kept one copy in `kpke_prepare_public_no_cache` and emitted another inside
decapsulation. The accepted helper owns the complete public preparation:

1. Decode the three public-key polynomials.
2. Start the first eight matrix streams.
3. Tail-call the existing shared SHA3-256/SHA3-512 and ninth-matrix-stream
   helper with a mode argument.

Encapsulation still makes one public-preparation call, rather than calling a
new decode helper from inside its old boundary. Decapsulation's secret-key
decode remains inline. This narrower boundary is important: sharing all three
emitted d12 decode copies saved more space but failed the operation-level
performance gate.

The change is limited to Clang with AVX2, AVX512F, and AVX512BW. It adds no
external object, runtime library, persistent cache, API, table, or wire-format
dependency, and it claims no speed gain.

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

| Native product metric | Baseline `626da41` | Candidate `13b3ea1` | Delta |
|---|---:|---:|---:|
| Total code | 74,366 B | 72,981 B | -1,385 B (-1.86%) |
| Read-only data | 19,287 B | 19,287 B | 0 B |
| Primary | 93,653 B | 92,268 B | -1,385 B (-1.48%) |
| Zero-fill/writable | 18,001 B | 18,001 B | 0 B |
| ELF file | 130,216 B | 127,632 B | -2,584 B |
| ELF sections | 74 | 74 | 0 |
| Relocations | 942 | 891 | -51 |

The executable-section accounting is exact:

| Section change | Bytes |
|---|---:|
| Remove `.text.kpke_prepare_public_no_cache` | -1,436 B |
| Add `.text.kpke_prepare_public_hash_no_cache_shared_clang_avx512` | +1,448 B |
| Shrink `.text.baby_mlkem768_decaps` | -1,408 B |
| Grow `.text.baby_mlkem768_encaps_derand` | +11 B |
| Net code change | -1,385 B |

Fifteen of seventeen common executable sections are byte-identical. The
read-only total is unchanged; Clang reordered four constant-pool sections as
the callers changed, while the other twelve read-only sections are
byte-identical. Writable storage and layout are unchanged. The final product
SHA-256 is
`15153b7e9d0c6c0d440637029c5156260a790ee4605fd3824cd1d258c8d2165b`.

See [`native-size.txt`](native-size.txt),
[`section-identity.txt`](section-identity.txt), and
[`artifact-identity.txt`](artifact-identity.txt).

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

The KEM gate used two independent batches. Each batch used four warmup pairs
and sixteen alternating-order measured pairs of 100,000 iterations, pinned to
CPU 0. Each batch is balanced at eight baseline-first and eight
candidate-first pairs. Ratios are `baseline_time / candidate_time`; the
combined column is the geometric mean of the two equal-size batch geometric
means.

| Operation | Batch 1 | Batch 2 | Combined 32-pair geometric mean | Gate |
|---|---:|---:|---:|---:|
| Keygen | 1.0015x | 0.9991x | 1.000299x | PASS |
| Encaps | 0.9961x | 0.9982x | 0.997149x | PASS |
| Decaps | 0.9996x | 0.9933x | 0.996445x | PASS |
| Roundtrip | 0.9987x | 0.9967x | 0.997699x | PASS |
| Keygen core | 0.9984x | 0.9982x | 0.998300x | PASS |
| Encaps core | 1.0064x | 1.0070x | 1.006700x | PASS |
| Decaps core | 1.0026x | 0.9965x | 0.999545x | PASS |
| Roundtrip core | 1.0002x | 0.9977x | 0.998949x | PASS |

The minimum combined value is `0.996445x`, above the internal `0.995x`
operation floor. Batch 2's cache-assisted decapsulation result alone was
`0.9933x`; the changed cache-disabled decapsulation path remained `0.9965x`
in that batch, and the balanced 32-pair result passes. These measurements
support a size-only claim, not a speedup claim.

See [`native-ab-batch1-16x100k.txt`](native-ab-batch1-16x100k.txt),
[`native-ab-batch2-16x100k.txt`](native-ab-batch2-16x100k.txt), and
[`native-ab-combined-32x100k.txt`](native-ab-combined-32x100k.txt).

## Correctness And Isolation

The committed candidate passed:

- GCC and Clang native, AVX2-only, and scalar KAT, product, and complete stage
  validation.
- Clang native ASan+UBSan and GCC native UBSan KAT, directly linked product,
  and complete stage validation.
- Clang- and GCC-generated NTT table reproducibility checks; the generator also
  passed ASan+UBSan with LeakSanitizer disabled.
- All 16 cross-path corpus variants, each 381,228 bytes with SHA-256
  `e4d8f908f9a3c59171deeed712925760b194d692b0c571861f204eabef976b67`.
- Byte-identical products in all five non-target compiler/profile pairs:
  Clang AVX2-only and scalar, plus GCC native, AVX2-only, and scalar.
- A clean post-commit native product rebuild that exactly reproduced the
  measured candidate artifact.

See [`correctness-matrix.txt`](correctness-matrix.txt),
[`sanitizers.txt`](sanitizers.txt),
[`cross-path-corpus.txt`](cross-path-corpus.txt),
[`ntt-roots.txt`](ntt-roots.txt), and
[`artifact-identity.txt`](artifact-identity.txt). The complete non-target
artifact matrix is in
[`non-target-identity.txt`](non-target-identity.txt). File hashes are recorded in
[`SHA256SUMS`](SHA256SUMS).

## Rejected Wider Forms

Sharing only the K=3 d12 decode behind one helper removed all three emitted
copies and reduced primary size by 2,829 bytes to 90,824 bytes. Its balanced
16-pair KEM run put `decaps_core` and `encaps_core` at `0.9929x` and
`0.9928x`, below the operation floor. It was removed in favor of the complete
public-preparation boundary, which leaves secret decode inline and preserves
encapsulation's existing call depth.

The no-source-change `-fmerge-all-constants` experiment increased primary
size by 49 bytes to 93,702 bytes and was rejected before performance testing.

See [`rejected-candidates.txt`](rejected-candidates.txt).

## Remaining Size Gap

Using the previously pinned same-method mlkem-native result of 51,186 primary
bytes, the targeted native gap falls from 42,467 to 41,082 bytes. This is not a
completion-qualifying all-comparator rerun, and the primary-size gate still
fails. AVX2-only is byte-identical and retains its 19,970-byte OpenSSL deficit.

## Reproduction

```bash
make clean
make -j"$(nproc)" product test-product CC=clang \
  ARCH_CFLAGS=-march=native
./scripts/measure_product_size.sh baby_mlkem768_product.o

RUNS=16 WARMUP_RUNS=4 RUN_ORDER=alternating SUITES=kem \
  KEM_ITERS=100000 PIN_CPU=0 C_COMPILER=clang \
  ARCH_CFLAGS=-march=native ./scripts/bench_core_ab.sh 626da41

JOBS="$(nproc)" ./scripts/verify_cross_path_corpus.sh
make check-ntt-roots HOSTCC=clang
make check-ntt-roots HOSTCC=gcc
```

Run the paired command twice to reproduce the two equal-size batches.
