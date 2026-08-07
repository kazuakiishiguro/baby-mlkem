# Clang Native D10 Decoder Outline

Commit `f8019f88969f3a321c05fe7ae15775bb3db8c423` gives Clang's
native AVX512 decapsulation path one private, normal-optimization
`noinline` boundary around the exact-buffer-safe AVX2 d10 decoder. The
baseline is `1989ac5b37cf03a0ce833883ee9aff74d95ff3c4`.

Clang previously inlined the decoder into each of the three unrolled DU
polynomial calls in decapsulation. The accepted boundary keeps one 928-byte
copy and replaces the three expanded copies with calls. The decoder's
arithmetic, exact final-block loads, inputs, outputs, and callers are
unchanged. The attribute is limited to Clang builds with AVX512F and AVX512BW;
Clang AVX2/scalar and every GCC build retain their previous products.

This is a repository-local core size optimization. It adds no cache, external
object, runtime library, table, dispatch, API, algorithm, or wire-format
dependency.

## Environment

- CPU: AMD Ryzen Threadripper 7980X 64-Cores.
- Clang: Ubuntu Clang 18.1.3.
- GCC: Ubuntu GCC 13.3.0.
- Linker: GNU ld 2.42.
- Timed runs: CPU 0, four warmup pairs, sixteen alternating measured pairs per
  batch, three independent batches.

Exact flags, kernel, microcode, governor, commits, and timestamps are in
[`environment.txt`](environment.txt).

## Production Size

All products use the normal production/no-cache speed flags.

| Profile | Compiler | Baseline primary | Candidate primary | Delta | Candidate code | Candidate read-only | Candidate writable |
|---|---|---:|---:|---:|---:|---:|---:|
| native | Clang | 87,514 B | 85,689 B | -1,825 B | 66,370 B | 19,319 B | 18,001 B |
| AVX2-only | Clang | 59,307 B | 59,307 B | 0 B | 47,242 B | 12,065 B | 26,593 B |
| scalar | Clang | 62,193 B | 62,193 B | 0 B | 60,160 B | 2,033 B | 18,944 B |
| native | GCC | 59,571 B | 59,571 B | 0 B | 56,006 B | 3,565 B | 33,728 B |
| AVX2-only | GCC | 53,614 B | 53,614 B | 0 B | 49,829 B | 3,785 B | 34,920 B |
| scalar | GCC | 23,267 B | 23,267 B | 0 B | 21,530 B | 1,737 B | 19,488 B |

The decapsulation export shrinks from 11,583 to 8,830 bytes and the new helper
is 928 bytes, exactly accounting for the 1,825-byte code and primary
reduction. Read-only and writable storage are unchanged.

The accepted product has SHA-256
`46d22deee6f7452b6397d2e0a224b1b0db4e03764f64817d29677ebf6c32df0f`.
A clean implementation-commit build is byte-identical to the product used by
the timed gate. Direct baseline/candidate rebuilds prove that Clang
AVX2/scalar and all three GCC products are byte-identical.

See [`size.txt`](size.txt), [`section-accounting.txt`](section-accounting.txt),
[`artifact-identity.txt`](artifact-identity.txt), and the raw `size-*.txt`
reports.

## Stack

Eight guarded alternate-stack runs produced:

| Operation | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Keygen | 6,712 B | 6,712 B | 0 B |
| Encaps | 6,776 B | 6,776 B | 0 B |
| Decaps valid | 8,056 B | 8,056 B | 0 B |
| Decaps invalid | 8,056 B | 8,056 B | 0 B |
| Maximum | 8,056 B | 8,056 B | 0 B |

See [`stack.txt`](stack.txt) and the two raw stack reports.

## Valid KEM Regression Gate

Three independent Clang-native batches each used four warmup pairs and
sixteen alternating-order measured pairs of 100,000 iterations. Ratios are
baseline time divided by candidate time. Equal-size batches are combined
geometrically.

| Operation | Batch 1 | Batch 2 | Batch 3 | Combined 48-pair gmean |
|---|---:|---:|---:|---:|
| Decaps | 1.0017x | 0.9977x | 0.9982x | 0.999198417x |
| Decaps core | 0.9966x | 1.0003x | 1.0018x | 0.999564276x |
| Encaps | 0.9987x | 1.0042x | 1.0028x | 1.001897280x |
| Encaps core | 0.9916x | 0.9989x | 1.0023x | 0.997590000x |
| Keygen | 0.9989x | 1.0013x | 0.9965x | 0.998898078x |
| Keygen core | 0.9970x | 1.0006x | 0.9975x | 0.998365398x |
| Roundtrip | 0.9973x | 1.0005x | 0.9978x | 0.998532345x |
| Roundtrip core | 0.9962x | 1.0022x | 1.0002x | 0.999530219x |

The minimum is `0.997590000x`, above the `0.995x` operation-regression floor.
The batches timed the unchanged working-tree source that became `f8019f8`;
the implementation-commit product is byte-identical. Timing movement is used
only as no-regression evidence, and no KEM speed gain is credited.

See [`native-ab-combined.txt`](native-ab-combined.txt) and the three raw
`native-ab-batch*.txt` reports.

## Rejected Broader Outlines

Adding Clang `minsize` to the d10 helper reduced primary size by another 769
bytes, to 84,920 bytes, but the nine-pair screen put `keygen_core` at
`0.9944x`, below the acceptance floor. It was removed.

Outlining all of `kpke_decrypt` without `minsize` increased primary size by 40
bytes because the generic decode/decompress bodies remained separately
reachable. Adding `minsize` increased primary size by 1,401 bytes. Both were
rejected before a formal speed gate.

See [`rejected-candidates.txt`](rejected-candidates.txt) and
[`rejected-minsize-screen-9x50k.txt`](rejected-minsize-screen-9x50k.txt).

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
- The same three KEM symbols and unresolved runtime symbols as the parent.
- Eighteen byte-identical common non-decapsulation text sections; only the
  decapsulation export changes and the private d10 section is added.
- Byte-identical products for all five non-target compiler/profile builds.

See [`correctness-matrix.txt`](correctness-matrix.txt),
[`sanitizers.txt`](sanitizers.txt),
[`cross-path-corpus.txt`](cross-path-corpus.txt),
[`ntt-roots.txt`](ntt-roots.txt), [`abi-audit.txt`](abi-audit.txt), and
[`source-audit.txt`](source-audit.txt).

## Remaining Size Gap

Using the pinned same-method mlkem-native size of 51,186 bytes, the native
deficit falls from 36,328 to 34,503 bytes. The unchanged AVX2-only OpenSSL
deficit remains 14,258 bytes. This is not a complete same-revision
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
  ./scripts/bench_core_ab.sh 1989ac5

JOBS="$(nproc)" ./scripts/verify_cross_path_corpus.sh
make check-ntt-roots HOSTCC=clang
make check-ntt-roots HOSTCC=gcc
```

Run the A/B command three times to reproduce the 48-pair combined gate. File
integrity for this evidence directory is recorded in
[`checksums.sha256`](checksums.sha256).
