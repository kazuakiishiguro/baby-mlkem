# Clang Native Keygen Sampler Outline

Commit `149b3d59f2a6043e8a21f4a411b4400a9bfbfdbc` gives Clang's
native AVX512 key-generation sampler one private `noinline,minsize` boundary.
The baseline is `ae12e77be733f9adc59bb94262d5c770782cd3e6`.

The helper performs the existing mixed eight-lane operation: six SHAKE256
eta2 streams for key-generation noise, one SHAKE128 `(2,2)` matrix-tail
stream, and one empty lane. Its body, inputs, outputs, Keccak schedule, CBD
decode, and matrix continuation are unchanged. Only Clang receives the
outline/minsize attributes; GCC and non-AVX512 builds retain their previous
source path.

This is a repository-local core size and stack optimization. It adds no cache,
external object, runtime library, table, dispatch, API, algorithm, or
wire-format dependency.

## Environment

- CPU: AMD Ryzen Threadripper 7980X 64-Cores.
- Clang: Ubuntu Clang 18.1.3.
- GCC: Ubuntu GCC 13.3.0.
- Linker: GNU ld 2.42.
- Timed runs: CPU 0, four warmup pairs, sixteen alternating measured pairs per
  batch.

Exact flags, kernel, microcode, governor, commits, and timestamps are in
[`environment.txt`](environment.txt).

## Production Size

All products use the normal production/no-cache flags.

| Profile | Compiler | Baseline primary | Candidate primary | Delta | Candidate code | Candidate read-only | Candidate writable |
|---|---|---:|---:|---:|---:|---:|---:|
| native | Clang | 89,861 B | 87,514 B | -2,347 B | 68,195 B | 19,319 B | 18,001 B |
| AVX2-only | Clang | 59,307 B | 59,307 B | 0 B | 47,242 B | 12,065 B | 26,593 B |
| scalar | Clang | 62,193 B | 62,193 B | 0 B | 60,160 B | 2,033 B | 18,944 B |
| native | GCC | 59,571 B | 59,571 B | 0 B | 56,006 B | 3,565 B | 33,728 B |
| AVX2-only | GCC | 53,614 B | 53,614 B | 0 B | 49,829 B | 3,785 B | 34,920 B |
| scalar | GCC | 23,267 B | 23,267 B | 0 B | 21,530 B | 1,737 B | 19,488 B |

The inlined keypair export shrinks from 11,259 to 6,522 bytes. The outlined
helper is 2,358 bytes, so executable code falls by 2,379 bytes. Read-only data
rises by 32 bytes after Clang redistributes generated constants, leaving a net
2,347-byte primary reduction. Writable storage is unchanged.

The accepted product has SHA-256
`c9120218ea041db43fe4b776f1e1a1d43a0bdef546d44d2e5f077c9bf78c7737`.
A clean post-commit build is byte-identical to the product saved before the
timed gate. Clang AVX2/scalar and all three GCC products retain their exact
parent hashes.

See [`size.txt`](size.txt), [`section-accounting.txt`](section-accounting.txt),
[`artifact-identity.txt`](artifact-identity.txt), and the raw `size-*.txt`
reports.

## Stack

Eight guarded alternate-stack runs produced:

| Operation | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Keygen | 8,760 B | 6,712 B | -2,048 B |
| Encaps | 6,776 B | 6,776 B | 0 B |
| Decaps valid | 8,056 B | 8,056 B | 0 B |
| Decaps invalid | 8,056 B | 8,056 B | 0 B |
| Maximum | 8,760 B | 8,056 B | -704 B |

The call boundary ends the large mixed-sampler live range before the rest of
key generation. Maximum product stack therefore moves from keygen to
decapsulation. See [`stack.txt`](stack.txt) and the two raw stack reports.

## Valid KEM Regression Gate

Two independent Clang-native batches each used four warmup pairs and sixteen
alternating-order measured pairs of 100,000 iterations. Ratios are baseline
time divided by candidate time. The equal-size batches are combined
geometrically.

| Operation | Batch 1 | Batch 2 post-commit | Combined 32-pair gmean |
|---|---:|---:|---:|
| Decaps | 0.9989x | 0.9992x | 0.999049989x |
| Decaps core | 1.0022x | 0.9981x | 1.000147899x |
| Encaps | 1.0006x | 1.0075x | 1.004044073x |
| Encaps core | 1.0076x | 1.0054x | 1.006499399x |
| Keygen | 0.9980x | 0.9995x | 0.998749718x |
| Keygen core | 0.9984x | 0.9987x | 0.998549989x |
| Roundtrip | 0.9989x | 1.0009x | 0.999899500x |
| Roundtrip core | 1.0040x | 1.0012x | 1.002599023x |

The minimum is `0.998549989x`, above the `0.995x` operation-regression floor.
The first batch timed the unchanged working-tree source that became `149b3d5`;
the second batch ran after the implementation commit. Timing movement is used
only as no-regression evidence, and no complete-KEM speed gain is credited.

See [`native-ab-combined.txt`](native-ab-combined.txt) and the two raw
`native-ab-*.txt` reports.

## Focused Helper Check

A sixteen-pair, 500,000-iteration focused harness measured the mixed helper at
`1.014007914x` geometric mean with 15/16 wins. The encryption x7 helper is a
byte-identical control and produced a `1.000452500x` paired median with balanced
order medians; its apparent `1.005165910x` geometric mean is treated as noise
from one baseline outlier.

See [`focused-helper-ab.txt`](focused-helper-ab.txt),
[`focused-helper-bench.c`](focused-helper-bench.c), and the four focused raw
sample files.

## Rejected Broader Sharing

A broader prototype made encryption's hot sparse x7 permutation and keygen's
mixed x8 permutation enter one branch-selecting helper. It reduced primary size
by 2,759 bytes, 412 bytes more than the accepted outline, but changed Clang's
x7 constant propagation and register schedule. Even after fixed-nonce and
branch-order variants, the formal KEM screen regressed decapsulation and
encapsulation to `0.9862x` and `0.9908x`, below the acceptance floor. It was
removed completely.

See [`rejected-candidates.txt`](rejected-candidates.txt) and the retained
diagnostic [`rejected-shared-eta2.patch`](rejected-shared-eta2.patch).

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
- Exactly three public KEM APIs and parent-identical unresolved runtime
  symbols.
- Byte-identical encryption x7, encapsulation, decapsulation, hashing,
  accumulation, and inverse-add sections.
- Byte-identical products for all five non-target compiler/profile builds.

See [`correctness-matrix.txt`](correctness-matrix.txt),
[`sanitizers.txt`](sanitizers.txt),
[`cross-path-corpus.txt`](cross-path-corpus.txt),
[`ntt-roots.txt`](ntt-roots.txt), [`abi-audit.txt`](abi-audit.txt), and
[`source-audit.txt`](source-audit.txt).

## Remaining Size Gap

Using the pinned same-method comparator size of 51,186 bytes, the native
mlkem-native deficit falls from 38,675 to 36,328 bytes. The unchanged AVX2-only
OpenSSL deficit remains 14,258 bytes. This is not a complete same-revision
ten-comparator size or speed rerun, and both production-size gates still fail.
This commit therefore does not complete the overall optimization Goal.

## Reproduction

```bash
make clean
make -j"$(nproc)" product test-product CC=clang ARCH_CFLAGS=-march=native
./scripts/measure_product_size.sh baby_mlkem768_product.o

STACK_RUNS=8 STACK_USABLE_BYTES=1048576 C_COMPILER=clang \
  STACK_CFLAGS='-O2 -march=native -fomit-frame-pointer -fno-stack-protector' \
  ./scripts/measure_stack_highwater.sh baby_mlkem768_product.o local

RUNS=16 WARMUP_RUNS=4 RUN_ORDER=alternating SUITES=kem \
  KEM_ITERS=100000 PIN_CPU=0 C_COMPILER=clang \
  ./scripts/bench_core_ab.sh ae12e77

JOBS="$(nproc)" ./scripts/verify_cross_path_corpus.sh
make check-ntt-roots HOSTCC=clang
make check-ntt-roots HOSTCC=gcc
```

Run the A/B command twice to reproduce the 32-pair combined gate. File
integrity for this evidence directory is recorded in
[`checksums.sha256`](checksums.sha256).
