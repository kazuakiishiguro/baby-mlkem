# Clang Native Shared Hash Tail

Commit `3dccb273afc3ddd95cf0447d4e0a955d8b0874f8` factors the duplicated
Clang AVX512 hash/matrix-tail work from
`sha3_256_sample_ntt_tail_avx2()` and
`sha3_512_sample_ntt_tail_avx2()` into one private noinline helper. The
parent is `9ecfe41b5505e1435b57ea2072d73d598077af10`.

Both callers need three initial four-lane Keccak permutations while lane 1
produces the final matrix polynomial. One caller simultaneously absorbs the
1,184-byte public key for SHA3-256; the other hashes `m || H(pk)` with
SHA3-512. Clang previously inlined a separate three-permutation body into each
caller. The shared helper keeps those permutations within one call boundary
and selects the public-key continuation with a public, fixed mode argument.

This is a size optimization, not a claimed speedup. It applies only to Clang
with AVX512 enabled. GCC and non-AVX512 builds retain their previous source
paths. It adds no external object, runtime library, persistent cache, table,
API, or wire-format dependency.

## Production Size

The parent and candidate use Clang 18.1.3 production/no-cache flags with
`-march=native` on the AMD Ryzen Threadripper 7980X host.

| Native product metric | Parent `9ecfe41` | Candidate `3dccb27` | Delta |
|---|---:|---:|---:|
| Code | 83,112 B | 75,516 B | -7,596 B |
| Read-only data | 20,373 B | 20,341 B | -32 B |
| Primary | 103,485 B | 95,857 B | -7,628 B (-7.37%) |
| Zero-fill/writable | 18,001 B | 18,001 B | 0 B |
| ELF file | 139,248 B | 131,600 B | -7,648 B |

The candidate product SHA-256 is
`448de741bd771c21c3c83089c720feb9c5611a029ee605f6743d7fcbb3caadf5`.
See [`native-size.txt`](native-size.txt).

## Stack

Eight guarded alternate-stack runs show a lower maximum:

| Operation | Parent | Candidate | Delta |
|---|---:|---:|---:|
| Keygen | 8,696 B | 8,696 B | 0 B |
| Encaps | 8,568 B | 6,840 B | -1,728 B |
| Decaps valid | 10,040 B | 9,336 B | -704 B |
| Decaps invalid | 10,040 B | 9,336 B | -704 B |
| Maximum | 10,040 B | 9,336 B | -704 B |

The complete candidate probe is [`native-stack.txt`](native-stack.txt).

## Paired Native Gate

Two independent measurements pinned the product benchmark to CPU 0. Each used
three untimed warmup pairs followed by 15 alternating-order pairs of 100,000
iterations. Ratios are `parent_time / candidate_time`.

| Operation | First paired geometric mean | Repeat paired geometric mean |
|---|---:|---:|
| Keygen | 0.9977x | 1.0047x |
| Encaps | 0.9989x | 0.9985x |
| Decaps | 1.0059x | 1.0082x |
| Roundtrip | 0.9983x | 1.0019x |
| Keygen core | 0.9975x | 1.0019x |
| Encaps core | 1.0021x | 1.0071x |
| Decaps core | 1.0118x | 1.0128x |
| Roundtrip core | 1.0037x | 1.0071x |

Every operation remains above the internal `0.995x` regression floor in both
runs. The intervals were not used to claim a speed improvement. Complete
summaries are [`native-ab-15x100k.txt`](native-ab-15x100k.txt) and
[`native-ab-repeat-15x100k.txt`](native-ab-repeat-15x100k.txt).

## Correctness And Isolation

The accepted candidate passed:

- GCC and Clang native, AVX2-only, and scalar KAT, product, and complete stage
  validation.
- Clang native ASan+UBSan and GCC native UBSan KAT, direct-linked product, and
  complete stage validation.
- Clang- and GCC-generated NTT table reproducibility checks.
- All 16 cross-path corpus variants. Each emitted 381,228 bytes with SHA-256
  `e4d8f908f9a3c59171deeed712925760b194d692b0c571861f204eabef976b67`.
- Byte-identical non-target production artifacts: Clang AVX2-only retained
  SHA-256
  `444e4b7e99fcef956dfe7655ff66de308f3e32a134848868e810ab90d4d82584`,
  and GCC native retained
  `76cb2e25b1f7860268de66a191534f677ec44655a07444e94b7d9cb93e9377c0`.

See [`correctness-matrix.txt`](correctness-matrix.txt),
[`sanitizers.txt`](sanitizers.txt),
[`cross-path-corpus.txt`](cross-path-corpus.txt),
[`ntt-roots.txt`](ntt-roots.txt),
[`avx2-identity.txt`](avx2-identity.txt), and
[`gcc-native-identity.txt`](gcc-native-identity.txt). File hashes are recorded
in [`SHA256SUMS`](SHA256SUMS).

LeakSanitizer was disabled with `ASAN_OPTIONS=detect_leaks=0`; AddressSanitizer
and UndefinedBehaviorSanitizer remained enabled.

## Remaining Size Gap

A same-method native diagnostic against the pinned mlkem-native commit
`56962f6b36d0a718b108b9610ceb9f90b9e617db` reports:

| Native metric | baby-mlkem | mlkem-native | Delta |
|---|---:|---:|---:|
| Primary | 95,857 B | 51,186 B | +44,671 B |
| Maximum stack | 9,336 B | 20,448 B | -11,112 B |

Repository updating was intentionally disabled for this targeted diagnostic,
so it is not a completion-qualifying all-comparator size run. The primary-size
gate still fails. See [`native-mlkem-size.txt`](native-mlkem-size.txt).

## Reproduction

```bash
make clean
make -j"$(nproc)" product test-product CC=clang \
  ARCH_CFLAGS=-march=native
./scripts/measure_product_size.sh baby_mlkem768_product.o

STACK_RUNS=8 STACK_USABLE_BYTES=1048576 C_COMPILER=clang \
  STACK_CFLAGS='-O3 -fno-semantic-interposition -fvisibility=hidden \
  -march=native -fomit-frame-pointer -fno-stack-protector \
  -falign-loops=64 -fno-unwind-tables -fno-asynchronous-unwind-tables \
  -fno-strict-aliasing -std=c99' \
  ./scripts/measure_stack_highwater.sh baby_mlkem768_product.o local

JOBS="$(nproc)" ./scripts/verify_cross_path_corpus.sh
make check-ntt-roots HOSTCC=clang
make check-ntt-roots HOSTCC=gcc
```
