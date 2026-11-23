# Clang Fixed-Length SHA3-512 Production Split

Commit `1cf6605259682402d9733d452ee1ae5d39875d4a` separates Clang's
fixed-length ML-KEM SHA3-512 path from the generic sponge implementation. The
baseline is `d059bf9a780eb5fe2658ece2e82f044c211db7a6`, whose implementation is
`13b3ea1227ce2892e8ac89dd967d888628affa40`.

ML-KEM-768's production call sites hash only a 33-byte `d || 0x03` input or a
64-byte `m || H(ek)` input. Clang previously kept those fast cases and the
arbitrary-length absorb/finalize/squeeze path in one 1,379-byte native
function because key generation still needed the 33-byte generic case. The
new private helper accepts only 33 or 64 bytes, and every production call site
uses it directly. Section GC can therefore remove the generic sponge from the
production artifact while the standalone SHA3 API and its long-input tests
remain unchanged.

The change is limited to Clang. All three GCC production artifacts are
byte-identical to the baseline. It adds no external object, runtime library,
persistent cache, table, API, or wire-format dependency, and it claims no
speed gain.

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
| Clang native | 92,268 B | 90,937 B | -1,331 B (-1.44%) | 71,650 B | 19,287 B |
| Clang AVX2-only | 65,019 B | 63,892 B | -1,127 B (-1.73%) | 51,551 B | 12,341 B |
| Clang scalar | 64,262 B | 63,006 B | -1,256 B (-1.95%) | 60,973 B | 2,033 B |

Read-only and writable totals are unchanged in all three profiles. Native and
AVX2 relocation counts fall from 891 to 887 and from 523 to 519. Their ELF
files shrink by 1,472 and 1,280 bytes.

Native executable-section accounting is exact:

| Section change | Bytes |
|---|---:|
| Remove `.text.sha3_512` | -1,379 |
| Add `.text.sha3_512_mlkem_fixed` | +129 |
| Shrink `.text.baby_mlkem768_encaps_derand` | -81 |
| Net code change | -1,331 |

AVX2-only removes the 1,123-byte generic section, adds a 151-byte fixed
helper, shrinks encapsulation by 91 bytes, and shrinks decapsulation by 64
bytes, for a net 1,127-byte code reduction.

The final native and AVX2 artifact SHA-256 values are
`9f5f6d3178424b616d71950eae05b02f50f0effddc1698fa6ad0089dee1d2438`
and
`e61bc5ad1fb8906d8f4f55c273846d8eec37a8d3c9244ff0ef163f42fb43029b`.
Both were reproduced by clean builds from the implementation commit.

See [`size.txt`](size.txt),
[`section-accounting.txt`](section-accounting.txt), and
[`artifact-identity.txt`](artifact-identity.txt).

## Stack

Eight guarded alternate-stack runs produced:

| Profile and operation | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Native keygen | 8,760 B | 8,760 B | 0 B |
| Native encaps | 6,904 B | 6,776 B | -128 B |
| Native decaps valid/invalid | 9,400 B | 9,400 B | 0 B |
| AVX2 keygen | 4,832 B | 4,832 B | 0 B |
| AVX2 encaps | 4,512 B | 4,320 B | -192 B |
| AVX2 decaps valid/invalid | 5,856 B | 5,856 B | 0 B |

Maximum stack remains 9,400 bytes native and 5,856 bytes AVX2-only. See
[`stack.txt`](stack.txt).

## Paired KEM Gates

Each profile used four warmup pairs and sixteen alternating-order measured
pairs of 100,000 iterations on CPU 0. Ratios are baseline time divided by
candidate time.

| Operation | Native geometric mean | AVX2 geometric mean |
|---|---:|---:|
| Keygen | 1.0042x | 1.0019x |
| Encaps | 1.0035x | 1.0030x |
| Decaps | 1.0097x | 1.0036x |
| Roundtrip | 0.9996x | 1.0019x |
| Keygen core | 1.0034x | 1.0017x |
| Encaps core | 1.0019x | 0.9989x |
| Decaps core | 1.0036x | 0.9997x |
| Roundtrip core | 1.0030x | 1.0013x |

The minimum is `0.9996x` native and `0.9989x` AVX2-only, both above the
`0.995x` operation floor. The results accept this as a size optimization; the
small positive timing movement is not credited as a speed claim.

See [`native-ab-16x100k.txt`](native-ab-16x100k.txt) and
[`avx2-ab-16x100k.txt`](avx2-ab-16x100k.txt).

## Correctness And Isolation

The exact implementation source passed:

- GCC and Clang native, AVX2-only, and scalar KAT, production API, and complete
  stage-oracle validation.
- Clang native ASan+UBSan and GCC native UBSan KAT, directly linked production
  API, and complete stage validation.
- All 16 core, product, upstream, and PQClean corpus paths, each producing
  381,228 bytes with SHA-256
  `e4d8f908f9a3c59171deeed712925760b194d692b0c571861f204eabef976b67`.
- Clang and GCC NTT-root generator reproducibility plus generator
  ASan+UBSan validation.
- Byte-identical GCC native, AVX2-only, and scalar production artifacts.

See [`correctness-matrix.txt`](correctness-matrix.txt),
[`sanitizers.txt`](sanitizers.txt),
[`cross-path-corpus.txt`](cross-path-corpus.txt),
[`ntt-roots.txt`](ntt-roots.txt), and
[`gcc-identity.txt`](gcc-identity.txt).

## Rejected Wider Forms

Routing every compiler through the split helper reduced GCC native by only 8
bytes and increased GCC AVX2-only by 54 bytes. That form was removed; the
accepted implementation keeps every GCC product byte-identical. An initial
three-length production helper also tested 33 before the hotter 64-byte case.
Restricting its contract to the actual 33/64-byte production inputs removed
another 6 bytes and restored a one-comparison 64-byte dispatch.

See [`rejected-candidates.txt`](rejected-candidates.txt).

## Remaining Size Gap

Using the pinned same-method comparator sizes, the targeted native gap against
mlkem-native falls from 41,082 to 39,751 bytes. The limiting AVX2-only gap
against OpenSSL falls from 19,970 to 18,843 bytes. This is not a complete
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
  ARCH_CFLAGS=-march=native ./scripts/bench_core_ab.sh d059bf9

RUNS=16 WARMUP_RUNS=4 RUN_ORDER=alternating SUITES=kem \
  KEM_ITERS=100000 PIN_CPU=0 C_COMPILER=clang \
  ARCH_CFLAGS="-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f" \
  ./scripts/bench_core_ab.sh d059bf9

JOBS="$(nproc)" ./scripts/verify_cross_path_corpus.sh
make check-ntt-roots HOSTCC=clang
make check-ntt-roots HOSTCC=gcc
```
