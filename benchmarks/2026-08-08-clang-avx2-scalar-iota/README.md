# Clang AVX2 Scalar Iota Reuse

Commit `b181d8f6d50f91ae701003c8f2f3d9b8c5b11bdf` removes a
duplicate Keccak Iota table from the Clang AVX2-only production core. Its
baseline is `7bdb3bbb43a504539003bdd2ab7c8594568f3fa8`.

The single-state seven-YMM Keccak schedule previously retained the same 24
64-bit round constants twice:

- `rc[24]`, used by scalar and memory-resident Keccak paths; and
- `mlkem_keccakf1_iota4[24][4]`, a 768-byte four-lane expansion used by the
  seven-YMM path.

The candidate gives `keccakf1600_avx2.h` a caller-supplied Iota expression.
Only Clang AVX2 builds without AVX512F supply an `_mm256_set1_epi64x()` from
the existing `rc[round]`; all other builds retain the original table and code
generation. Clang lowers the target loop to a scalar constant load and YMM
broadcast. The canonical wrapper gains one instruction and four code bytes,
while section GC removes the complete 768-byte duplicate table.

The seven-vector state layout and round schedule remain the existing
XKCP/CRYPTOGAMS-derived implementation disclosed in the source and
`THIRD_PARTY_NOTICES.md`; this report does not claim that schedule as a new
baby-mlkem design. The compiler-scoped table deduplication is repository-local
and adds no external object or runtime library.

## Environment

- CPU: AMD Ryzen Threadripper 7980X 64-Cores.
- Clang: Ubuntu Clang 18.1.3.
- GCC: Ubuntu GCC 13.3.0.
- Linker: GNU ld 2.42.
- KEM: CPU 0, three warmup pairs, sixteen alternating measured pairs per
  batch, four batches, 100,000 iterations.
- Generic Keccak: CPU 0, four warmup pairs, thirty-one alternating pairs per
  batch, two batches, 1,000,000 iterations.
- Fixed H(pk): CPU 0, four warmup pairs, thirty-one alternating pairs,
  100,000 fixed 1,184-byte hashes.

Exact flags, kernel, microcode, governor, commits, and run settings are in
[`environment.txt`](environment.txt).

## Production Size

Both products use the normal production/no-cache speed flags.

| Profile | Compiler | Baseline primary | Candidate primary | Delta | Candidate code | Candidate read-only | Candidate writable |
|---|---|---:|---:|---:|---:|---:|---:|
| AVX2-only | Clang | 53,638 B | 52,874 B | -764 B | 44,705 B | 8,169 B | 26,593 B |

The size change decomposes exactly as follows:

| Component | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| `mlkem_keccakf1600_avx2` code | 1,000 B | 1,004 B | +4 B |
| Fixed `sha3_256_1184_avx2` code | 1,770 B | 1,770 B | 0 B |
| Four-lane Iota table | 768 B | 0 B | -768 B |
| Existing scalar `rc` table | 192 B | 192 B | 0 B |
| Net primary | 53,638 B | 52,874 B | -764 B |

Every other linked section retains its size. The accepted product has SHA-256
`311a344ff02756a4fad0ca936d4ff0f9baf3dd4a03e40308c7a4c1845363ab03`.
See [`size-baseline.txt`](size-baseline.txt),
[`size-candidate.txt`](size-candidate.txt),
[`section-accounting.txt`](section-accounting.txt), and
[`artifact-identity.txt`](artifact-identity.txt).

## Direct Timing

Ratios are baseline time divided by candidate time. The generic permutation
uses the canonical-state wrapper, while the fixed hash keeps the seven-YMM
state live across all nine permutations of H(pk).

| Boundary | Paired gmean | Paired median | Wins |
|---|---:|---:|---:|
| Generic Keccak batch 1 | 1.001718408x | 0.999862990x | 14/31 |
| Generic Keccak batch 2 | 1.002540200x | 1.000688702x | 18/31 |
| Generic Keccak combined | 1.002129220x | 1.000218441x | 32/62 |
| Fixed 1,184-byte H(pk) | 1.006657782x | 1.008777167x | 29/31 |

The generic wrapper is neutral. The fixed public-key hash consistently
improves despite the extra broadcast instruction, which is consistent with
the smaller round-constant working set; this explanation is an inference from
the code and measurements, not a hardware-counter result. No complete-KEM
speed gain is credited.

See [`direct-combined.txt`](direct-combined.txt),
[`keccak-batch1-31x1m.txt`](keccak-batch1-31x1m.txt),
[`keccak-batch2-31x1m.txt`](keccak-batch2-31x1m.txt),
[`fixed-hash-31x100k.txt`](fixed-hash-31x100k.txt),
[`direct-keccak-harness.c`](direct-keccak-harness.c), and
[`fixed-hash-harness.c`](fixed-hash-harness.c).

## KEM Regression Gate

Four equal-size batches are combined geometrically:

| Operation | Batch 1 | Batch 2 | Batch 3 | Batch 4 | Combined 64-pair gmean |
|---|---:|---:|---:|---:|---:|
| Decaps | 0.9968x | 0.9999x | 0.9994x | 1.0078x | 1.000966572x |
| Decaps core | 1.0088x | 0.9945x | 0.9971x | 1.0170x | 1.004309065x |
| Encaps | 1.0018x | 0.9900x | 0.9947x | 1.0026x | 0.997261401x |
| Encaps core | 1.0002x | 0.9989x | 0.9963x | 1.0009x | 0.999073456x |
| Keygen | 1.0005x | 1.0033x | 0.9939x | 1.0011x | 0.999693836x |
| Keygen core | 0.9989x | 1.0057x | 0.9943x | 1.0012x | 1.000016546x |
| Roundtrip | 0.9997x | 1.0008x | 0.9972x | 1.0030x | 1.000172819x |
| Roundtrip core | 1.0036x | 0.9994x | 0.9962x | 1.0058x | 1.001243112x |

The combined minimum is `0.997261401x`, above the `0.995x` internal operation
regression floor. The individual batches move in both directions, so the KEM
result is used only to establish no material regression.

See [`kem-combined.txt`](kem-combined.txt) and the four
`kem-batch*-16x100k.txt` raw reports in this directory.

## Correctness And Isolation

The implementation commit passes:

- GCC and Clang native, AVX2-only, and scalar KAT, production API, and complete
  stage-oracle validation;
- Clang AVX2 ASan+UBSan and GCC AVX2 UBSan KAT, directly linked production API,
  and complete stage validation;
- the dedicated Keccak benchmark's exact scalar/AVX2 validators;
- all 16 core, product, upstream, and PQClean corpus paths, each producing
  381,228 bytes with SHA-256
  `e4d8f908f9a3c59171deeed712925760b194d692b0c571861f204eabef976b67`;
- byte-identical Clang native/scalar and GCC native/AVX2/scalar products;
- the same three KEM API functions and unresolved runtime symbols;
- no AVX512 register or symbol in the AVX2-only product; and
- a non-executable GNU stack declaration.

See [`correctness-matrix.txt`](correctness-matrix.txt),
[`sanitizers.txt`](sanitizers.txt),
[`cross-path-corpus.txt`](cross-path-corpus.txt),
[`abi-audit.txt`](abi-audit.txt), [`source-audit.txt`](source-audit.txt),
[`ntt-roots.txt`](ntt-roots.txt), and [`final-smoke.txt`](final-smoke.txt).

## Stack

Eight guarded alternate-stack runs leave every operation unchanged:

| Operation | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Keygen | 4,544 B | 4,544 B | 0 B |
| Encaps | 4,176 B | 4,176 B | 0 B |
| Decaps valid | 4,512 B | 4,512 B | 0 B |
| Decaps invalid | 4,512 B | 4,512 B | 0 B |
| Maximum | 4,544 B | 4,544 B | 0 B |

See [`stack.txt`](stack.txt).

## Dependency Boundary

The accepted change reuses an existing repository-local scalar constant table
inside the existing independently linked baby-mlkem core. It adds no external
object, runtime library, persistent cache, benchmark cache, API, algorithm, or
wire-format dependency. The underlying seven-YMM round mapping is still
third-party-derived source with its attribution retained; the benchmark result
must not be described as an independently invented Keccak schedule.

## Remaining Size Gap

Using the pinned same-method OpenSSL AVX2-only size of 45,049 bytes, the Clang
AVX2 primary deficit falls from 8,589 to 7,825 bytes. The unchanged native
mlkem-native deficit remains 21,862 bytes. This is not a complete
same-revision ten-comparator size or speed rerun, so both size gates and the
overall optimization Goal remain incomplete.

## Reproduction

```bash
make clean
make -j"$(nproc)" product test-product CC=clang \
  ARCH_CFLAGS="-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f"
./scripts/measure_product_size.sh baby_mlkem768_product.o

make check-ntt-roots HOSTCC=clang
make check-ntt-roots HOSTCC=gcc

RUNS=16 WARMUP_RUNS=3 RUN_ORDER=alternating SUITES=kem \
  KEM_ITERS=100000 PIN_CPU=0 C_COMPILER=clang \
  ARCH_CFLAGS="-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f" \
  ./scripts/bench_core_ab.sh 7bdb3bb

JOBS="$(nproc)" ./scripts/verify_cross_path_corpus.sh
```

Run the A/B command four times to reproduce the 64-pair combined gate. File
integrity for this directory is recorded in `checksums.sha256`.
