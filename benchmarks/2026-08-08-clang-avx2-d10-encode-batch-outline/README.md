# Clang AVX2 d10 Encode Batch Outline

Commit `a32efa8e26e1ada223ce126805352774d0d530ba` outlines the fixed
three-polynomial d10 ciphertext encoder in the Clang AVX2-only production
core. Its baseline is `ed903ae02e53d14b42f533c24ab7237870d549ff`.

`kpke_encrypt_finish_avx2` always encodes `u[0]`, `u[1]`, and `u[2]` at
320-byte strides. Clang previously retained all three encoder loops in the
finish function. A private `noinline,minsize` K=3 helper now emits that loop
body once while preserving the input order, output offsets, compression
arithmetic, and following d4 encoder.

## Environment

- CPU: AMD Ryzen Threadripper 7980X 64-Cores.
- Clang: Ubuntu Clang 18.1.3.
- GCC: Ubuntu GCC 13.3.0.
- Linker: GNU ld 2.42.
- Product KEM: CPU 0, five independent batches, three warmup pairs and
  sixteen alternating measured pairs per batch, 100,000 iterations.
- Direct d10 x3: CPU 0, thirty-one alternating measured pairs, 5,000,000
  calls after 100,000 warmup calls in each process.

Exact flags, kernel, microcode, governor, commits, and run settings are in
[`environment.txt`](environment.txt).

## Production Size

Both artifacts use the normal production/no-cache speed flags. Primary size
is allocatable executable plus read-only data.

| Profile | Compiler | Baseline | Candidate | Delta | Candidate code | Candidate read-only | Candidate writable |
|---|---|---:|---:|---:|---:|---:|---:|
| AVX2-only | Clang | 52,195 B | 51,773 B | -422 B | 44,195 B | 7,578 B | 26,593 B |

The linked change decomposes as follows:

| Component | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| `kpke_encrypt_finish_avx2` | 5,304 B | 4,802 B | -502 B |
| Shared d10 x3 helper | 0 B | 238 B | +238 B |
| Net code | 44,459 B | 44,195 B | -264 B |
| Compiler read-only pools | 7,736 B | 7,578 B | -158 B |
| Net primary | 52,195 B | 51,773 B | -422 B |

The read-only delta is a 160-byte reduction in `.rodata.cst32`, a 2-byte
increase in `.rodata`, and a size-neutral `.rodata.cst8` reorder. All twenty
common text sections outside the changed caller are byte-identical. The only
new text section is the private helper. The accepted product has SHA-256
`707c90499c2dd27a8cb634cb1d148a8a553052ae9a44fa0b62d77002767910f2`.

See [`size-baseline.txt`](size-baseline.txt),
[`size-candidate.txt`](size-candidate.txt),
[`section-accounting.txt`](section-accounting.txt),
[`source-audit.txt`](source-audit.txt), and
[`artifact-identity.txt`](artifact-identity.txt).

## Direct Timing

The same executable contains a normal-optimization baseline K=3 loop and the
accepted compact helper. It first checks byte-identical output over 4,096
deterministic canonical inputs and one ramp pattern. Ratios are baseline
time divided by candidate time.

| Boundary | Paired gmean | 95% CI | Paired median | Ratio of medians | Wins |
|---|---:|---:|---:|---:|---:|
| d10 encode, three polynomials | 1.006971x | 1.004323x-1.010222x | 1.005454x | 1.005749x | 26/31 |

The direct executable emits 495-byte and 232-byte baseline/candidate
functions; the exact production helper is 238 bytes because its surrounding
section layout differs. This direct result establishes that the added call and
compact loop do not slow the affected operation. It is diagnostic evidence,
not a broad KEM speed claim. See
[`direct-d10x3-31x5m.txt`](direct-d10x3-31x5m.txt) and
[`direct-d10x3-harness.c`](direct-d10x3-harness.c).

## Product Regression Gate

Five independent batches use fixed baseline and candidate product objects and
one byte-identical benchmark harness. The product API disables internal
caches, so each normal operation value is exactly its `*_core` value. Ratios
below are geometric means over unrounded paired ratios.

| Operation | Batch 1 | Batch 2 | Batch 3 | Batch 4 | Batch 5 | Combined 80-pair gmean |
|---|---:|---:|---:|---:|---:|---:|
| Keygen | 0.999411x | 1.008147x | 0.997703x | 1.001039x | 1.002207x | 1.001695x |
| Encaps | 1.000942x | 0.995754x | 0.994934x | 1.002674x | 1.010135x | 1.000873x |
| Decaps | 0.989374x | 1.006316x | 1.001897x | 1.004198x | 1.000948x | 1.000529x |
| Roundtrip | 0.996027x | 1.004184x | 0.998487x | 1.001110x | 1.002471x | 1.000452x |

The minimum combined operation ratio is `1.000451502x`, above the internal
`0.995x` regression floor. The first short screen and individual batches show
large scheduler outliers, so all eighty pairs are retained without outlier
removal. Timing is used only as no-regression evidence; no broad KEM speed gain
is credited.

See [`product-ab-combined-80x100k.txt`](product-ab-combined-80x100k.txt)
and the five `product-ab-batch*-16x100k.txt` files.

## Correctness And Isolation

The exact implementation commit passes:

- GCC and Clang native, AVX2-only, and scalar KAT, production API, and complete
  1,000-iteration stage-oracle validation;
- Clang AVX2 ASan+UBSan KAT, directly linked production API, and complete
  stage-oracle validation;
- all 16 core, product, upstream, and PQClean corpus paths, each producing
  381,228 bytes with SHA-256
  `e4d8f908f9a3c59171deeed712925760b194d692b0c571861f204eabef976b67`;
- byte-identical Clang native/scalar and GCC native/AVX2/scalar products;
- Clang and GCC NTT-root generator reproducibility;
- the same KEM API and unresolved `bcmp`, `memcpy`, and `memset` symbols;
- no AVX512 register or symbol in the AVX2-only product; and
- a non-executable GNU stack declaration.

The clean post-commit build reproduces the validated artifact hash, size, and
stage sink. See [`correctness-matrix.txt`](correctness-matrix.txt),
[`sanitizers.txt`](sanitizers.txt),
[`cross-path-corpus.txt`](cross-path-corpus.txt),
[`abi-audit.txt`](abi-audit.txt), [`ntt-roots.txt`](ntt-roots.txt), and
[`postcommit-smoke.txt`](postcommit-smoke.txt).

## Stack

Eight guarded alternate-stack runs are unchanged:

| Operation | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Keygen | 4,512 B | 4,512 B | 0 B |
| Encaps | 4,144 B | 4,144 B | 0 B |
| Decaps valid | 4,512 B | 4,512 B | 0 B |
| Decaps invalid | 4,512 B | 4,512 B | 0 B |
| Maximum | 4,512 B | 4,512 B | 0 B |

See [`stack.txt`](stack.txt) and the two raw stack reports.

## Rejected Alternatives

Reducing global Clang loop alignment produced smaller artifacts but failed the
complete-product speed floor. `-falign-loops=32` reached 51,299 bytes but an
independent 20-pair confirmation put decapsulation at `0.991303x`.
`-falign-loops=16` reached 50,859 bytes but put key generation at `0.991921x`.
Both remain rejected. See [`rejected-candidates.txt`](rejected-candidates.txt).

## Dependency Boundary

The accepted change links no external object or runtime library and adds no
persistent cache, benchmark cache, runtime dispatch, API, table, algorithm, or
wire-format dependency. It only changes Clang's code-generation boundary
around an existing repository-local encoder.

## Remaining Goal Gap

Using the pinned same-method comparator sizes, the Clang AVX2-only deficit to
OpenSSL falls from 7,146 to 6,724 bytes. The unchanged native deficit to
mlkem-native remains 18,425 bytes. The required ten-comparator speed and size
gates have not been rerun on this same revision, and both primary-size gates
still fail. This commit therefore does not complete the optimization Goal.

## Reproduction

```bash
make clean
make -j"$(nproc)" product test-product CC=clang \
  ARCH_CFLAGS="-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f"
./product_testc
./scripts/measure_product_size.sh baby_mlkem768_product.o

RUNS=16 WARMUP_RUNS=3 RUN_ORDER=alternating SUITES=product \
  KEM_ITERS=100000 PIN_CPU=0 C_COMPILER=clang \
  ARCH_CFLAGS="-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f" \
  ./scripts/bench_core_ab.sh ed903ae

STACK_RUNS=8 STACK_USABLE_BYTES=1048576 C_COMPILER=clang \
  STACK_CFLAGS='-O2 -march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f -fomit-frame-pointer -fno-stack-protector' \
  ./scripts/measure_stack_highwater.sh baby_mlkem768_product.o local

JOBS="$(nproc)" ./scripts/verify_cross_path_corpus.sh
make check-ntt-roots HOSTCC=clang
make check-ntt-roots HOSTCC=gcc
```

Run the A/B command five times to reproduce the 80-pair combined gate. File
integrity for this directory is recorded in `checksums.sha256`.
