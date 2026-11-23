# Clang Fixed-Length Implicit-Rejection SHAKE256

Commit `e7094b81d58c7ea492572f08fc41face5ff4cd46` specializes the
ML-KEM-768 implicit-rejection hash for Clang. The baseline is
`f56750f97f262abfa8a9ca43d2890f1461474fae`, whose implementation is
`588c9d40137f1ffa5f2722bc6f492c318c1505a9`.

ML-KEM-768 always hashes `z[32] || c[1088]` to produce the 32-byte rejection
secret. The specialized helper absorbs those two inputs directly instead of
constructing a 1,120-byte concatenation buffer and entering the arbitrary-
length SHAKE256 sponge. It preserves the generic fallback for direct calls
whose ciphertext length is not 1,088 bytes.

The fixed input occupies one SHAKE256 rate block containing all 32 bytes of
`z` and the first 104 bytes of `c`, seven complete 136-byte ciphertext blocks,
and a final block containing 32 ciphertext bytes plus the unchanged `0x1f`
domain separator and final `0x80` pad. Both forms therefore execute the same
nine Keccak-f[1600] permutations and produce identical output.

The rejected initial form moved Clang's hot fixed SHA3-512 helper by 16 bytes
in the LTO benchmark layout and caused a repeatable cached-encapsulation
regression. The final form explicitly aligns that existing helper to 32 bytes.
This restores the baseline hot helper layout without increasing production
code, read-only data, or primary size.

This is repository-local core work. It adds no external object, runtime
library, persistent cache, table, API, algorithm, or wire-format dependency.

## Environment

- CPU: AMD Ryzen Threadripper 7980X 64-Cores.
- Clang: Ubuntu Clang 18.1.3.
- GCC: Ubuntu GCC 13.3.0.
- Linker: GNU ld 2.42.
- Timed runs: CPU 0, alternating baseline/candidate order.

Exact flags, kernel, microcode, governor, commits, and recording times are in
[`environment.txt`](environment.txt).

## Production Size

All products use the normal production/no-cache flags.

| Profile | Baseline primary | Candidate primary | Delta | Candidate code | Candidate read-only | Candidate writable |
|---|---:|---:|---:|---:|---:|---:|
| Clang native | 90,116 B | 89,861 B | -255 B | 70,574 B | 19,287 B | 18,001 B |
| Clang AVX2-only | 63,296 B | 63,030 B | -266 B | 50,689 B | 12,341 B | 26,593 B |
| Clang scalar | 62,576 B | 62,193 B | -383 B | 60,160 B | 2,033 B | 18,944 B |

The native product replaces a 438-byte generic SHAKE256 helper with a 208-byte
fixed helper and reduces decapsulation by 25 bytes. AVX2-only replaces 458
bytes with 223 bytes and reduces decapsulation by 31 bytes. Scalar replaces
430 bytes with 210 bytes and reduces decapsulation by 163 bytes. These account
exactly for the three code deltas above.

Clean post-commit builds reproduced all expected artifacts. The candidate
Clang native, AVX2-only, and scalar SHA-256 values are respectively
`2064f0446a04720df937dc176da088e377eedb59647a06b5af247ceacb49d26a`,
`c66b73aabb8cc8bd3afadb5a7e7fe5ff889171d4a6f1ec7ba4f64e2a76cab4e1`,
and
`34b87fe2f6d7431e81530df71d0d1ecc8cb14e1cf1845673536508e2b0ecc47c`.
All three GCC products remain byte-identical to the baseline.

See [`size.txt`](size.txt), [`section-accounting.txt`](section-accounting.txt),
[`artifact-identity.txt`](artifact-identity.txt), and the six
`size-<compiler>-<profile>.txt` reports.

## Stack

Eight guarded alternate-stack runs produced:

| Profile and operation | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Native keygen | 8,760 B | 8,760 B | 0 B |
| Native encaps | 6,776 B | 6,776 B | 0 B |
| Native decaps valid/invalid | 9,144 B | 8,056 B | -1,088 B |
| Native maximum | 9,144 B | 8,760 B | -384 B |
| AVX2 keygen | 4,832 B | 4,832 B | 0 B |
| AVX2 encaps | 4,320 B | 4,320 B | 0 B |
| AVX2 decaps valid/invalid | 5,632 B | 4,512 B | -1,120 B |
| AVX2 maximum | 5,632 B | 4,832 B | -800 B |

The fixed helper removes the complete concatenation buffer from production
decapsulation. See [`stack.txt`](stack.txt), [`native-stack.txt`](native-stack.txt),
and [`avx2-stack.txt`](avx2-stack.txt).

## Valid KEM Regression Gates

Each profile used two independent batches. Every batch had four warmup pairs
and sixteen alternating-order measured pairs of 100,000 iterations on CPU 0.
The table combines the two equal-size batches geometrically. Ratios are
baseline time divided by candidate time.

| Operation | Native 32-pair gmean | AVX2 32-pair gmean |
|---|---:|---:|
| Keygen | 0.995679x | 1.001700x |
| Encaps | 0.995900x | 0.996200x |
| Decaps | 0.999948x | 0.997545x |
| Roundtrip | 0.996941x | 0.999750x |
| Keygen core | 0.996376x | 0.998950x |
| Encaps core | 1.000348x | 0.999350x |
| Decaps core | 0.998325x | 1.000672x |
| Roundtrip core | 0.998888x | 1.000548x |

The minimum is `0.995679x` native and `0.996200x` AVX2-only, both above the
`0.995x` operation floor. The batch-level script emits four decimal places;
[`kem-combined.txt`](kem-combined.txt) records that the displayed combined
values are calculated from those reported batch gmeans. Normal valid-KEM
movement is treated only as a no-regression result, not as a speed gain.

See [`native-ab-batch1-16x100k.txt`](native-ab-batch1-16x100k.txt),
[`native-ab-batch2-16x100k.txt`](native-ab-batch2-16x100k.txt),
[`avx2-ab-batch1-16x100k.txt`](avx2-ab-batch1-16x100k.txt), and
[`avx2-ab-batch2-16x100k.txt`](avx2-ab-batch2-16x100k.txt).

## Invalid Decapsulation

The dedicated product-API harness cycles through 64 deterministically mutated
ciphertexts. It measures the path that actually calls the new helper.

| Profile | Paired gmean | Paired median | Wins |
|---|---:|---:|---:|
| Native | 1.013610x | 1.011558x | 14/16 |
| AVX2-only | 1.012231x | 1.006947x | 15/16 |

This supports a narrow claim: invalid-ciphertext decapsulation is about
1.2-1.4% faster on this host. It does not claim that valid decapsulation or the
complete KEM became faster.

See [`bench-invalid-decaps.c`](bench-invalid-decaps.c),
[`run-invalid-decaps-ab.sh`](run-invalid-decaps-ab.sh),
[`invalid-decaps-provenance.txt`](invalid-decaps-provenance.txt),
[`native-invalid-ab-16x100k.txt`](native-invalid-ab-16x100k.txt), and
[`avx2-invalid-ab-16x100k.txt`](avx2-invalid-ab-16x100k.txt).

## Rejected Layouts

The initial unaligned implementation was not accepted despite having the same
production primary size. Two native KEM batches put cached encapsulation at
`0.9950x` and `0.9863x`; their reported-gmean combination is `0.990640x`.
Inspection showed that the existing hot fixed SHA3-512 helper moved from a
32-byte boundary. Marking the rejection helper `cold` recovered cached encaps
only to `0.995973x` with 0/9 wins and increased the ELF by 16 bytes.

Aligning fixed SHA3-512 to 32 bytes restored the relevant hot symbol addresses
and function sizes to their baseline layout. Its targeted cached-encapsulation
screen was `1.001134x` gmean before the complete 32-pair gates above. Raw data
and decisions are retained in [`rejected-candidates.txt`](rejected-candidates.txt)
and the `rejected-*.txt` reports.

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
- Clang and GCC NTT-root generator reproducibility plus generator ASan+UBSan.
- No AVX-512 register or opmask instruction in the AVX2-only artifact.
- Exactly three exported KEM symbols, no new external dependency, and
  byte-identical GCC native, AVX2-only, and scalar production artifacts.

See [`correctness-matrix.txt`](correctness-matrix.txt),
[`sanitizers.txt`](sanitizers.txt),
[`cross-path-corpus.txt`](cross-path-corpus.txt),
[`ntt-roots.txt`](ntt-roots.txt), [`isa-audit.txt`](isa-audit.txt), and
[`source-audit.txt`](source-audit.txt).

## Remaining Size Gap

Using the pinned same-method comparator sizes, the targeted native gap against
mlkem-native falls from 38,930 to 38,675 bytes. The limiting AVX2-only gap
against OpenSSL falls from 18,247 to 17,981 bytes. This is not a complete
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
  ARCH_CFLAGS=-march=native ./scripts/bench_core_ab.sh f56750f

RUNS=16 WARMUP_RUNS=4 RUN_ORDER=alternating SUITES=kem \
  KEM_ITERS=100000 PIN_CPU=0 C_COMPILER=clang \
  ARCH_CFLAGS="-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f" \
  ./scripts/bench_core_ab.sh f56750f

JOBS="$(nproc)" ./scripts/verify_cross_path_corpus.sh
```

Run each A/B command twice to reproduce the 32-pair combined gate. File
integrity for the complete evidence directory is recorded in
[`checksums.sha256`](checksums.sha256).
