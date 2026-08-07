# Clang AVX2 Shared Keygen Keccak

Commit `6ba81de0903437ae09d6f0ce000617997fe1f712` removes two
Clang AVX2-only copies of the x4 Keccak-f[1600] body. The baseline is
`e7094b81d58c7ea492572f08fc41face5ff4cd46`.

Clang had already emitted a private 1,457-byte
`mlkem_encrypt_keccakf4_mem_parity_avx2()` helper for the decapsulation-side
encryption path. Key generation still inlined the same permutation into its
matrix/noise and final row helpers. The accepted implementation gives those
keygen call sites an ELF-local assembler alias for the existing helper. The
alias hides the new keygen edge from Clang's optimizer, while the linker
resolves both local names to the same section and address.

The one caller that did not already maintain theta parity reconstructs its
five parity vectors before the call. The other two callers pass their live
parity vectors directly. GCC, Clang native AVX512, scalar builds, and non-ELF
Clang AVX2 builds retain the original inline path.

This is a production-size optimization, not a speed claim. It adds no external
object, runtime library, persistent cache, table, API, algorithm, or wire-format
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

| Profile | Baseline primary | Candidate primary | Delta | Candidate code | Candidate read-only | Candidate writable |
|---|---:|---:|---:|---:|---:|---:|
| Clang native | 89,861 B | 89,861 B | 0 B | 70,574 B | 19,287 B | 18,001 B |
| Clang AVX2-only | 63,030 B | 60,996 B | -2,034 B | 48,783 B | 12,213 B | 26,593 B |
| Clang scalar | 62,193 B | 62,193 B | 0 B | 60,160 B | 2,033 B | 18,944 B |

The AVX2 code reduction is exactly 1,906 bytes: the keygen matrix/noise
section shrinks by 1,408 bytes and the final matrix-row section shrinks by 498
bytes. Clang also removes 128 bytes from `.rodata.cst32`, for a 2,034-byte
primary reduction. Writable storage is unchanged.

The existing decapsulation section, mixed encryption tail, and 1,457-byte
Keccak helper remain byte-identical to the baseline. The helper remains section
40, and the mixed tail to helper distance remains `0x1140`. This isolates the
size win from the hot decapsulation layout.

Clean post-commit builds reproduce SHA-256
`296fcb5623a7073e740609fef7c216b9ab209a972be8e53c0aea59372cdb7344`.
The exact object saved before the timed gate and the post-commit object are
byte-identical. All five non-target compiler/profile products are
byte-identical to the baseline.

See [`size.txt`](size.txt), [`section-accounting.txt`](section-accounting.txt),
[`artifact-identity.txt`](artifact-identity.txt), and the six
`size-<compiler>-<profile>.txt` reports.

## Stack

Eight guarded alternate-stack runs produced:

| Profile and operation | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Native keygen | 8,760 B | 8,760 B | 0 B |
| Native encaps | 6,776 B | 6,776 B | 0 B |
| Native decaps valid/invalid | 8,056 B | 8,056 B | 0 B |
| Native maximum | 8,760 B | 8,760 B | 0 B |
| AVX2 keygen | 4,832 B | 4,544 B | -288 B |
| AVX2 encaps | 4,320 B | 4,320 B | 0 B |
| AVX2 decaps valid/invalid | 4,512 B | 4,512 B | 0 B |
| AVX2 maximum | 4,832 B | 4,544 B | -288 B |

See [`stack.txt`](stack.txt), [`native-stack.txt`](native-stack.txt), and
[`avx2-stack.txt`](avx2-stack.txt).

## Valid KEM Regression Gate

Two independent AVX2-only batches each used four warmup pairs and sixteen
alternating-order measured pairs of 100,000 iterations on CPU 0. The table
combines the two equal-size batches geometrically. Ratios are baseline time
divided by candidate time.

| Operation | Batch 1 gmean | Batch 2 gmean | Combined gmean |
|---|---:|---:|---:|
| Keygen | 1.0067x | 1.0011x | 1.003896x |
| Encaps | 1.0020x | 0.9985x | 1.000248x |
| Decaps | 1.0052x | 0.9955x | 1.000338x |
| Roundtrip | 1.0092x | 1.0016x | 1.005393x |
| Keygen core | 1.0048x | 0.9997x | 1.002247x |
| Encaps core | 1.0036x | 0.9983x | 1.000946x |
| Decaps core | 1.0055x | 1.0016x | 1.003548x |
| Roundtrip core | 1.0052x | 1.0030x | 1.004099x |

The minimum reported-gmean combination is `1.000248x`, above the `0.995x`
operation regression floor. The batch script reports four decimal places, so
the combined values are derived from those displayed values. Timing movement
is treated only as evidence of no regression; no speed gain is credited.

See [`avx2-ab-batch1-16x100k.txt`](avx2-ab-batch1-16x100k.txt),
[`avx2-ab-batch2-16x100k.txt`](avx2-ab-batch2-16x100k.txt), and
[`kem-combined.txt`](kem-combined.txt).

## Rejected Sharing Forms

A normal C helper achieved larger size reductions but exposed all callers to
Clang's optimizer and changed hot-section placement. Fully outlining the x4
permutation reduced AVX2 primary size by 7,514 bytes, but regressed complete
sampling, matrix generation, public preparation, and `encaps_core`. Restoring
hot callers incrementally recovered size and speed inconsistently.

A direct C alias retained a 2,034-byte primary reduction, but moved the shared
helper from its baseline section 40 to section 2. Two formal 16-pair batches
combined to `0.994249x` for `encaps_core`, below the acceptance floor. The
accepted assembler alias keeps the call edge out of optimizer IR and restores
the established section order. No rejected candidate code remains.

See [`rejected-candidates.txt`](rejected-candidates.txt) and the two
`rejected-direct-alias-*.txt` raw reports.

## Correctness And Isolation

The exact implementation commit passed:

- GCC and Clang native, AVX2-only, and scalar KAT, production API, and complete
  stage-oracle validation.
- Clang native ASan+UBSan and GCC native UBSan KAT, directly linked production
  API, and complete stage validation. LeakSanitizer alone was disabled because
  it is incompatible with the execution environment's ptrace supervision.
- All 16 core, product, upstream, and PQClean corpus paths, each producing
  381,228 bytes with SHA-256
  `e4d8f908f9a3c59171deeed712925760b194d692b0c571861f204eabef976b67`.
- Clang and GCC NTT-root generator reproducibility plus generator ASan+UBSan.
- No AVX512 register or opmask instruction in the AVX2-only artifact.
- Exactly three exported KEM symbols and the same six unresolved runtime
  symbols as the baseline.
- Both local helper symbols resolve to the same 1,457-byte section-40 body.
- A Clang AVX2 build with `-U__ELF__` passes KAT and production API tests,
  proving that the portable inline fallback remains usable.

See [`correctness-matrix.txt`](correctness-matrix.txt),
[`sanitizers.txt`](sanitizers.txt),
[`cross-path-corpus.txt`](cross-path-corpus.txt),
[`ntt-roots.txt`](ntt-roots.txt), [`isa-audit.txt`](isa-audit.txt),
[`source-audit.txt`](source-audit.txt), and
[`non-elf-fallback.txt`](non-elf-fallback.txt).

## Remaining Size Gap

Using the pinned same-method comparator sizes, native remains 38,675 bytes
larger than mlkem-native. The limiting AVX2-only gap against OpenSSL falls from
17,981 to 15,947 bytes. This is not a complete same-revision ten-comparator
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
  ./scripts/bench_core_ab.sh e7094b8

JOBS="$(nproc)" ./scripts/verify_cross_path_corpus.sh
make check-ntt-roots HOSTCC=clang
make check-ntt-roots HOSTCC=gcc
```

Run the A/B command twice to reproduce the 32-pair combined gate. File
integrity for the complete evidence directory is recorded in
[`checksums.sha256`](checksums.sha256).
