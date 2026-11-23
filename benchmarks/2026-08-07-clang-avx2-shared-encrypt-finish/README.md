# Clang AVX2 Shared Encryption Finish

Commit `a03a486` factors the duplicated Clang AVX2-only encryption finish from
encapsulation and decapsulation into one private noinline helper. It reuses one
`u`/`v` scratch allocation and one machine-code body for forward NTT input
conversion, four-output multiplication, inverse-add, message folding, and
ciphertext compression. The arithmetic, API, wire format, and deterministic
outputs are unchanged.

This is a size optimization, not a claimed speedup. It applies only to Clang
when AVX2 is enabled and AVX512 is disabled. GCC keeps its previous body because
the GCC product is already smaller with that form. Native AVX512 and scalar
paths are unchanged. No external object, runtime library, persistent cache, or
new table is introduced.

## Production Size

The candidate and parent were built with Clang 18.1.3 using:

```text
-O3 -fno-semantic-interposition -fvisibility=hidden
-fomit-frame-pointer -fno-stack-protector -falign-loops=64
-fno-unwind-tables -fno-asynchronous-unwind-tables -fno-strict-aliasing
-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f
```

| AVX2-only product metric | Parent `f4bc404` | Candidate `a03a486` | Delta |
|---|---:|---:|---:|
| Code | 56,031 B | 52,678 B | -3,353 B |
| Read-only data | 12,743 B | 12,341 B | -402 B |
| Primary | 68,774 B | 65,019 B | -3,755 B (-5.46%) |
| Zero-fill/writable | 28,641 B | 26,593 B | -2,048 B (-7.15%) |
| Primary + writable | 97,415 B | 91,612 B | -5,803 B (-5.96%) |
| ELF file | 102,608 B | 94,896 B | -7,712 B |

Product SHA-256 changed from
`444d0a9afb6b949c17e384b41aab401fad229412c9d8d0a21b1eb1b95eb7ffca`
to
`444e4b7e99fcef956dfe7655ff66de308f3e32a134848868e810ab90d4d82584`.
The complete reports are under [`size/`](size/).

## Stack

Eight guarded alternate-stack runs show no maximum-stack increase:

| Operation | Parent | Candidate |
|---|---:|---:|
| Keygen | 4,832 B | 4,832 B |
| Encaps | 4,512 B | 4,512 B |
| Decaps valid | 5,856 B | 5,856 B |
| Decaps invalid | 5,856 B | 5,856 B |
| Maximum | 5,856 B | 5,856 B |

The complete reports are under [`stack/`](stack/).

## Paired AVX2-Only Gate

The product benchmark was pinned to CPU 0. Three untimed warmups preceded 15
paired 100,000-iteration runs. Odd pairs ran parent then candidate; even pairs
ran candidate then parent. Ratios below are `parent_time / candidate_time`.

| Operation | Parent median ns | Candidate median ns | Ratio of medians | Paired geometric mean | 95% CI | Wins | Parent-first / candidate-first median |
|---|---:|---:|---:|---:|---:|---:|---:|
| Keygen | 5,637.24 | 5,637.18 | 1.0000x | 1.0000x | 0.9920-1.0084x | 8/15 | 0.9977x / 1.0005x |
| Encaps | 4,504.02 | 4,495.62 | 1.0019x | 1.0007x | 0.9968-1.0045x | 9/15 | 1.0004x / 1.0028x |
| Decaps | 4,468.49 | 4,487.48 | 0.9958x | 0.9986x | 0.9945-1.0028x | 7/15 | 0.9999x / 0.9977x |
| Roundtrip | 14,968.62 | 15,007.76 | 0.9974x | 0.9995x | 0.9957-1.0033x | 7/15 | 1.0006x / 0.9993x |

All operation-level geometric means remain above the `0.995x` regression
floor. The intervals span neutral performance, so no speed gain is credited.
The checked-in metric files preserve all values in measured run order. The
candidate benchmark SHA-256 is
`f19ee71acedba07d80a9653b928e1a35dc42632340138ae7d45446a31dbe29de`;
the parent SHA-256 is
`e0e17272fe12616c4519eb732129428e8b2ce99af58beb503c743b2a7ba78eae`.

## Correctness

The final candidate passed:

- GCC and Clang native, AVX2-only, and scalar KEM/KAT tests.
- Product roundtrip and implicit-rejection tests in all six builds.
- Complete stage-oracle validation in all six builds.
- Clang AVX2 ASan+UBSan KAT, direct-linked product test, and complete stage
  validation.
- Clang native ASan+UBSan and GCC native UBSan KAT plus complete stage
  validation.
- Both Clang- and GCC-generated NTT table reproducibility checks.
- All 16 cross-path corpus variants, each 381,228 bytes with SHA-256
  `e4d8f908f9a3c59171deeed712925760b194d692b0c571861f204eabef976b67`.

Complete stage sinks were `5236638352469415403` native,
`8086079251842987743` AVX2-only, and `3075663932904715540` scalar for both
compilers. Clang native and GCC native/AVX2-only product and benchmark artifacts
were byte-identical to the parent. See [`verification.txt`](verification.txt)
and [`cross-path-corpus.txt`](cross-path-corpus.txt).

LeakSanitizer was disabled with `ASAN_OPTIONS=detect_leaks=0` because it cannot
run under the managed environment's ptrace layer. AddressSanitizer and
UndefinedBehaviorSanitizer remained enabled.

## OpenSSL-Only Diagnostic

The normalized OpenSSL internal-core comparison was rerun without repository
updates, so it is diagnostic rather than a completion-qualifying ten-comparator
run.

| AVX2-only metric | baby-mlkem | OpenSSL | Delta |
|---|---:|---:|---:|
| Primary | 65,019 B | 45,049 B | +19,970 B |
| Maximum stack | 5,856 B | 9,112 B | -3,256 B |

The primary gap falls from 23,725 bytes to 19,970 bytes but remains open. The
full report is [`openssl-avx2-only.txt`](openssl-avx2-only.txt).

## Reproduction

```bash
AVX2_FLAGS="-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f"

make clean
make -j"$(nproc)" CC=clang ARCH_CFLAGS="$AVX2_FLAGS" \
  testc product_testc bench_productc bench_core_stagesc
./testc
./product_testc
./bench_core_stagesc 1
./scripts/measure_product_size.sh baby_mlkem768_product.o

JOBS="$(nproc)" ./scripts/verify_cross_path_corpus.sh
make check-ntt-roots HOSTCC=clang
make check-ntt-roots HOSTCC=gcc
```
