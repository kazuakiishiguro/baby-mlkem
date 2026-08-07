# AVX2 Shared Three-Lane PRF/CBD

Commit `58858b8a5224d4e9c3f928f71cd3ea8defa9e440` removes the
production duplication between the AVX2 four-output and three-output
ML-KEM-768 eta2 noise samplers. The baseline is
`4c0780b348f3856c827555e46e15dae991a97ab8`.

Encryption samples nonces `0,1,2,3` first and then nonces `4,5,6`. Both of the
previous x4 and x3 helpers initialized the same four-lane Keccak state and ran
the same `keccakf4_mem()` permutation. The x3 helper differed only in decoding
three CBD outputs instead of four.

The accepted implementation lets the x4 state decoder receive a null fourth
output. It then decodes lanes 0 and 1 together and lane 2 alone, without
decoding or storing the unused lane 3. The second encryption call uses this
x4-plus-null path. The separate x3 helper remains available to internal
diagnostic benchmarks, but is no longer reachable from the production API and
is removed by production section GC.

This is a repository-local core size optimization. It adds no external object,
runtime library, persistent cache, table, API, algorithm, or wire-format
dependency.

## Environment

- CPU: AMD Ryzen Threadripper 7980X 64-Cores.
- Clang: Ubuntu Clang 18.1.3.
- GCC: Ubuntu GCC 13.3.0.
- Linker: GNU ld 2.42.
- Timed runs: CPU 0, four warmup pairs, alternating baseline/candidate order.

Exact flags, kernel, microcode, governor, commits, and recording times are in
[`environment.txt`](environment.txt).

## Production Size

All products use the normal production/no-cache flags.

| Profile | Compiler | Baseline primary | Candidate primary | Delta | Candidate code | Candidate read-only | Candidate writable |
|---|---|---:|---:|---:|---:|---:|---:|
| native | Clang | 89,861 B | 89,861 B | 0 B | 70,574 B | 19,287 B | 18,001 B |
| AVX2-only | Clang | 60,996 B | 59,307 B | -1,689 B | 47,242 B | 12,065 B | 26,593 B |
| scalar | Clang | 62,193 B | 62,193 B | 0 B | 60,160 B | 2,033 B | 18,944 B |
| native | GCC | 59,571 B | 59,571 B | 0 B | 56,006 B | 3,565 B | 33,728 B |
| AVX2-only | GCC | 55,238 B | 53,614 B | -1,624 B | 49,829 B | 3,785 B | 34,920 B |
| scalar | GCC | 23,267 B | 23,267 B | 0 B | 21,530 B | 1,737 B | 19,488 B |

For Clang, the old x3 and x4 sections were 1,807 and 1,850 bytes. The shared
x4 section is 2,061 bytes, while the x3 production section disappears. Total
code falls by 1,541 bytes and read-only data by 148 bytes. The exported
encapsulation wrapper grows by 55 bytes, which is included in that net result.

For GCC, the old x3 and x4 functions were 2,109 and 1,950 bytes. The shared x4
function is 2,379 bytes, the x3 symbol disappears, total code falls by 1,600
bytes, and read-only data falls by 24 bytes.

Native and scalar artifacts for both compilers are byte-identical to the
baseline. Clean post-commit AVX2 builds reproduce SHA-256
`1fbd2356a5c10467ff896e31b7b5dcb46a8c12f131975cffd9c23051246c704a`
for Clang and
`baa60f056156bfbf6d02262854fc6a9f9019610b9d6d2cea81b3b507acbb59d5`
for GCC. Both are byte-identical to the products saved before the timed gates.

See [`size.txt`](size.txt), [`section-accounting.txt`](section-accounting.txt),
[`artifact-identity.txt`](artifact-identity.txt), and the six
`size-<compiler>-<profile>.txt` reports.

## Stack

Eight guarded alternate-stack runs produced:

| Profile and operation | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Clang AVX2 keygen | 4,544 B | 4,544 B | 0 B |
| Clang AVX2 encaps | 4,320 B | 4,352 B | +32 B |
| Clang AVX2 decaps valid/invalid | 4,512 B | 4,512 B | 0 B |
| Clang AVX2 maximum | 4,544 B | 4,544 B | 0 B |
| GCC AVX2 keygen | 4,864 B | 4,864 B | 0 B |
| GCC AVX2 encaps | 4,608 B | 4,608 B | 0 B |
| GCC AVX2 decaps valid/invalid | 5,920 B | 5,920 B | 0 B |
| GCC AVX2 maximum | 5,920 B | 5,920 B | 0 B |

The unchanged Clang native artifact retains its 8,760-byte maximum. See
[`stack.txt`](stack.txt) and the five raw `stack-*.txt` reports.

## Valid KEM Regression Gate

Each compiler ran two independent AVX2-only batches. Every batch used four
warmup pairs and sixteen alternating-order measured pairs of 100,000
iterations on CPU 0. Ratios are baseline time divided by candidate time. The
table combines the two equal-size batches geometrically.

| Operation | Clang combined gmean | GCC combined gmean |
|---|---:|---:|
| Decaps | 1.000450x | 1.000050x |
| Decaps core | 0.998681x | 0.998395x |
| Encaps | 1.001150x | 1.001350x |
| Encaps core | 1.002450x | 1.005050x |
| Keygen | 1.001597x | 0.995598x |
| Keygen core | 1.002145x | 0.996450x |
| Roundtrip | 1.001699x | 0.997250x |
| Roundtrip core | 1.001700x | 1.000500x |

The minima are `0.998681x` for Clang and `0.995598x` for GCC, both above the
`0.995x` operation-regression floor. Key generation does not call the changed
helper, but remains in the gate so layout and measurement effects are not
silently excluded. Timing movement is treated only as evidence of no
regression; no speed gain is credited.

A focused Clang stage screen measured cached and uncached K-PKE encryption at
`1.0030x` and `0.9982x`. See [`kem-combined.txt`](kem-combined.txt), the four
`*-avx2-ab-batch*-16x100k.txt` reports, and
[`clang-avx2-stage-screen-7x30k.txt`](clang-avx2-stage-screen-7x30k.txt).

## Rejected Dummy-Lane Store

The first sharing form passed the third output as both x4 outputs 2 and 3 and
used nonce vector `4,5,6,6`. It removed the x3 production body, but decoded the
dummy fourth lane and wrote it over the same output. Its seven-pair Clang
screen produced `0.9949x` for encapsulation, below the acceptance floor. The
accepted null-output form avoids both the unused decode and the aliasing store.
No rejected code remains.

See [`rejected-candidates.txt`](rejected-candidates.txt) and
[`rejected-fourth-lane-store-screen-7x50k.txt`](rejected-fourth-lane-store-screen-7x50k.txt).

## Correctness And Isolation

The exact implementation commit passed:

- GCC and Clang native, AVX2-only, and scalar KAT, production API, and complete
  stage-oracle validation.
- Clang native ASan+UBSan and GCC native UBSan KAT, directly linked production
  API, and complete stage validation.
- All 16 core, product, upstream, and PQClean corpus paths, each producing
  381,228 bytes with SHA-256
  `e4d8f908f9a3c59171deeed712925760b194d692b0c571861f204eabef976b67`.
- Clang and GCC NTT-root generator reproducibility plus generator ASan+UBSan.
- No AVX512 register or opmask instruction in either AVX2-only artifact.
- Exactly three exported KEM symbols and parent-identical unresolved runtime
  symbols for both compilers.
- Byte-identical Clang decapsulation, keypair, encryption-tail,
  encryption-finish, and x4 Keccak helper sections.

See [`correctness-matrix.txt`](correctness-matrix.txt),
[`sanitizers.txt`](sanitizers.txt),
[`cross-path-corpus.txt`](cross-path-corpus.txt),
[`ntt-roots.txt`](ntt-roots.txt), [`isa-audit.txt`](isa-audit.txt), and
[`source-audit.txt`](source-audit.txt).

## Remaining Size Gap

Using the pinned same-method comparator sizes, native remains 38,675 bytes
larger than mlkem-native. The limiting AVX2-only gap against OpenSSL falls from
15,947 to 14,258 bytes. This is not a complete same-revision ten-comparator
rerun, and both production-size gates still fail. This commit therefore does
not complete the overall optimization Goal.

## Reproduction

```bash
make clean
make -j"$(nproc)" product test-product CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f"
./scripts/measure_product_size.sh baby_mlkem768_product.o

RUNS=16 WARMUP_RUNS=4 RUN_ORDER=alternating SUITES=kem \
  KEM_ITERS=100000 PIN_CPU=0 C_COMPILER=clang \
  ARCH_CFLAGS="-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f" \
  ./scripts/bench_core_ab.sh 4c0780b

RUNS=16 WARMUP_RUNS=4 RUN_ORDER=alternating SUITES=kem \
  KEM_ITERS=100000 PIN_CPU=0 C_COMPILER=gcc \
  ARCH_CFLAGS="-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f" \
  ./scripts/bench_core_ab.sh 4c0780b

JOBS="$(nproc)" ./scripts/verify_cross_path_corpus.sh
make check-ntt-roots HOSTCC=clang
make check-ntt-roots HOSTCC=gcc
```

Run each A/B command twice to reproduce the 32-pair combined gate. File
integrity for the complete evidence directory is recorded in
[`checksums.sha256`](checksums.sha256).
