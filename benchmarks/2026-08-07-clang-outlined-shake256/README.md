# Clang Outlined Generic SHAKE256

Commit `588c9d40137f1ffa5f2722bc6f492c318c1505a9` keeps Clang from
cloning the generic SHAKE256 sponge into the ML-KEM decapsulation body. The
baseline is `27c85e67bee35ed3e40015e7d560abba7a3ad4a1`, whose implementation
is `1cf6605259682402d9733d452ee1ae5d39875d4a`.

In the production/no-cache artifact, the remaining variable-length SHAKE256
call is the implicit-rejection hash of `z || c`. Clang had inlined its generic
absorb, finalize, and squeeze control flow into `baby_mlkem768_decaps`. The new
Clang-only `noinline,minsize` boundary emits one compact private function and
removes a larger inlined copy. GCC keeps its previous declaration and all
three GCC production artifacts remain byte-identical.

This is a compiler-layout optimization. It does not change Keccak arithmetic,
the implicit-rejection input, the public API, the wire format, or the cache
policy. It adds no external object, runtime library, persistent cache, or
table, and it claims no speed gain.

## Environment

- CPU: AMD Ryzen Threadripper 7980X 64-Cores, microcode `0xa108108`.
- OS kernel: Linux 6.8.0-124-generic x86_64.
- Clang: Ubuntu Clang 18.1.3.
- GCC: Ubuntu GCC 13.3.0.
- Linker: GNU ld 2.42.
- Timed runs: CPU 0, alternating baseline/candidate order.

Exact flags and the recording time are in
[`environment.txt`](environment.txt).

## Production Size

All products use the normal production/no-cache flags.

| Profile | Baseline primary | Candidate primary | Delta | Candidate code | Candidate read-only |
|---|---:|---:|---:|---:|---:|
| Clang native | 90,937 B | 90,116 B | -821 B (-0.90%) | 70,829 B | 19,287 B |
| Clang AVX2-only | 63,892 B | 63,296 B | -596 B (-0.93%) | 50,955 B | 12,341 B |
| Clang scalar | 63,006 B | 62,576 B | -430 B (-0.68%) | 60,543 B | 2,033 B |

Read-only data and writable storage are unchanged in every profile. Native
decapsulation shrinks by 1,259 bytes and adds one 438-byte `shake256` function,
for the exact 821-byte code reduction. AVX2-only shrinks decapsulation by
1,054 bytes and adds a 458-byte helper; scalar shrinks it by 860 bytes and
adds a 430-byte helper.

The final native and AVX2 artifact SHA-256 values are
`7e406f670c30cc55d0fe8e0c21256ea26de51cff1f4be7095ec26e6d6b72a338`
and
`e34636dd5934a1c6f04fa1a8571fc17cc20050eddf34edc76ada39d51ece401a`.
Clean post-commit builds reproduced all six expected artifacts.

See [`size.txt`](size.txt),
[`section-accounting.txt`](section-accounting.txt), and
[`artifact-identity.txt`](artifact-identity.txt).

## Stack

Eight guarded alternate-stack runs produced:

| Profile and operation | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Native keygen | 8,760 B | 8,760 B | 0 B |
| Native encaps | 6,776 B | 6,776 B | 0 B |
| Native decaps valid/invalid | 9,400 B | 9,144 B | -256 B |
| AVX2 keygen | 4,832 B | 4,832 B | 0 B |
| AVX2 encaps | 4,320 B | 4,320 B | 0 B |
| AVX2 decaps valid/invalid | 5,856 B | 5,632 B | -224 B |

Maximum stack therefore falls from 9,400 to 9,144 bytes native and from 5,856
to 5,632 bytes AVX2-only. See [`stack.txt`](stack.txt).

## Paired KEM Gates

Each profile used four warmup pairs and sixteen alternating-order measured
pairs of 100,000 iterations on CPU 0. Ratios are baseline time divided by
candidate time.

| Operation | Native geometric mean | AVX2 geometric mean |
|---|---:|---:|
| Keygen | 0.9959x | 0.9970x |
| Encaps | 1.0053x | 0.9997x |
| Decaps | 1.0007x | 0.9969x |
| Roundtrip | 1.0021x | 0.9978x |
| Keygen core | 0.9976x | 0.9994x |
| Encaps core | 0.9965x | 1.0020x |
| Decaps core | 0.9971x | 1.0044x |
| Roundtrip core | 0.9964x | 1.0013x |

The minimum is `0.9959x` native and `0.9969x` AVX2-only, both above the
`0.995x` operation floor. The result accepts this as a size optimization;
timing movement is not credited as a speed claim.

See [`native-ab-16x100k.txt`](native-ab-16x100k.txt) and
[`avx2-ab-16x100k.txt`](avx2-ab-16x100k.txt).

## Invalid Decapsulation Diagnostic

Because the outlined SHAKE256 call is reached by implicit rejection rather
than valid decapsulation, a separate product-API harness cycles through 64
different invalid ciphertexts. Native 16-pair 100,000-iteration A/B has a
`1.006109x` geometric mean and `0.998245x` median.

The first AVX2-only 16-pair batch has a `0.996047x` geometric mean and
`0.999240x` median. A repeat received four candidate-side outliers around 6%
and has a `0.989601x` geometric mean despite a `0.998644x` median. The combined
32-pair geometric mean is therefore `0.992819x`, below the internal operation
floor, while its median is `0.998748x`. This failed diagnostic is retained
rather than filtered.

Increasing each timed process fivefold to 500,000 decapsulations reduces the
influence of per-process outliers: eight additional pairs have a `1.000443x`
geometric mean, `0.998488x` median, and order-split medians of
`0.997095x`/`0.999326x`. This supports no sustained invalid-path regression,
but no speed gain is claimed. The formal valid-KEM gates above remain the
acceptance gate.

See [`bench-invalid-decaps.c`](bench-invalid-decaps.c),
[`run-invalid-decaps-ab.sh`](run-invalid-decaps-ab.sh),
[`invalid-decaps-provenance.txt`](invalid-decaps-provenance.txt),
[`native-invalid-ab-16x100k.txt`](native-invalid-ab-16x100k.txt),
[`avx2-invalid-ab-batch1-16x100k.txt`](avx2-invalid-ab-batch1-16x100k.txt),
[`avx2-invalid-ab-batch2-16x100k.txt`](avx2-invalid-ab-batch2-16x100k.txt),
and [`avx2-invalid-ab-8x500k.txt`](avx2-invalid-ab-8x500k.txt).

## Correctness And Isolation

The exact committed implementation passed:

- GCC and Clang native, AVX2-only, and scalar KAT, production API, and complete
  stage-oracle validation.
- Clang native ASan+UBSan and GCC native UBSan KAT, directly linked production
  API, and complete stage validation. LeakSanitizer alone was disabled because
  it is incompatible with the execution environment's ptrace supervision.
- All 16 core, product, upstream, and PQClean corpus paths, each producing
  381,228 bytes with SHA-256
  `e4d8f908f9a3c59171deeed712925760b194d692b0c571861f204eabef976b67`.
- Clang and GCC NTT-root generator reproducibility plus generator ASan+UBSan
  validation.
- No AVX512 register or opmask instruction in the AVX2-only artifact.
- Byte-identical GCC native, AVX2-only, and scalar production artifacts.

See [`correctness-matrix.txt`](correctness-matrix.txt),
[`sanitizers.txt`](sanitizers.txt),
[`cross-path-corpus.txt`](cross-path-corpus.txt),
[`ntt-roots.txt`](ntt-roots.txt), and [`isa-audit.txt`](isa-audit.txt).

## Rejected Wider Form

Adding Clang's `cold` attribute to the outlined function changed no primary
size in any profile and increased every ELF file by 8 bytes. It was removed;
the accepted helper uses only `noinline,minsize`. See
[`rejected-candidates.txt`](rejected-candidates.txt).

## Remaining Size Gap

Using the pinned same-method comparator sizes, the targeted native gap against
mlkem-native falls from 39,751 to 38,930 bytes. The limiting AVX2-only gap
against OpenSSL falls from 18,843 to 18,247 bytes. This is not a complete
same-revision ten-comparator rerun, and both production-size gates still fail.

## Reproduction

```bash
make clean
make -j"$(nproc)" product test-product CC=clang \
  AVX2_BACKEND=core ARCH_CFLAGS=-march=native
./scripts/measure_product_size.sh baby_mlkem768_product.o

make clean
make -j"$(nproc)" product test-product CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f"
./scripts/measure_product_size.sh baby_mlkem768_product.o

RUNS=16 WARMUP_RUNS=4 RUN_ORDER=alternating SUITES=kem \
  KEM_ITERS=100000 PIN_CPU=0 C_COMPILER=clang \
  ARCH_CFLAGS=-march=native ./scripts/bench_core_ab.sh 27c85e6

RUNS=16 WARMUP_RUNS=4 RUN_ORDER=alternating SUITES=kem \
  KEM_ITERS=100000 PIN_CPU=0 C_COMPILER=clang \
  ARCH_CFLAGS="-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f" \
  ./scripts/bench_core_ab.sh 27c85e6

JOBS="$(nproc)" ./scripts/verify_cross_path_corpus.sh
make check-ntt-roots HOSTCC=clang
make check-ntt-roots HOSTCC=gcc
```
