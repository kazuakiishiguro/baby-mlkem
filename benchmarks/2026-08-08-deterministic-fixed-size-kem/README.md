# Deterministic Fixed-Size KEM Paths

Commit `c2ae4e21cf2b1cdce3f456f39472add63be34054` specializes the
deterministic ML-KEM-768 product paths. Its baseline is
`5f39ccef9b16e723d5a504eae83a8b8a24cc5a23`.

The deterministic keypair and encapsulation entry points now call seeded
internal cores directly instead of entering wrappers that also support
`randombytes`. Internal K-PKE encryption always emits the fixed ML-KEM-768
1,088-byte ciphertext, so its private length output and the decapsulation
re-encryption length temporary are removed. The public deterministic API also
states its existing non-null input contract to GCC and Clang.

The generic random APIs remain available in ordinary core/test builds. The
production artifact still exports the same three deterministic KEM symbols and
uses the same FIPS 203 algorithm and wire format. This change removes dead
random/error handling from the deterministic production artifact rather than
claiming faster entropy collection or a cryptographic arithmetic redesign.

## Environment

- CPU: AMD Ryzen Threadripper 7980X 64-Cores.
- Clang: Ubuntu Clang 18.1.3.
- GCC: Ubuntu GCC 13.3.0.
- Linker: GNU ld 2.42.
- Timed runs: CPU 0, three untimed warmup pairs, fifteen alternating measured
  pairs per compiler/profile.
- Clang used 200,000 iterations per measured process; GCC used 100,000.

Exact flags, kernel, microcode, governor, commits, and timestamp are in
[`environment.txt`](environment.txt).

## Production Size

All products use the normal production/no-cache speed flags. Primary size is
allocatable executable plus read-only data.

| Profile | Compiler | Baseline primary | Candidate primary | Delta | Candidate code | Candidate read-only | Candidate writable |
|---|---|---:|---:|---:|---:|---:|---:|
| native | Clang | 69,775 B | 69,611 B | -164 B | 53,285 B | 16,326 B | 18,001 B |
| AVX2-only | Clang | 52,874 B | 52,651 B | -223 B | 44,499 B | 8,152 B | 26,593 B |
| scalar | Clang | 62,193 B | 62,098 B | -95 B | 60,082 B | 2,016 B | 18,944 B |
| native | GCC | 59,571 B | 59,148 B | -423 B | 55,640 B | 3,508 B | 33,728 B |
| AVX2-only | GCC | 53,614 B | 53,443 B | -171 B | 49,687 B | 3,756 B | 34,920 B |
| scalar | GCC | 23,267 B | 22,994 B | -273 B | 21,238 B | 1,756 B | 19,488 B |

All six primary footprints shrink. Clang native loses 147 code bytes and 17
read-only bytes; Clang AVX2-only loses 206 code bytes and 17 read-only bytes.
GCC native has the largest reduction at 423 bytes. Writable storage does not
increase in any profile.

The clean post-commit Clang-native artifact reproduces SHA-256
`9b534f8f47a282baeb9eeed8916f4648800d05854c72d9e2e729ba3739478ec2`.
See [`size-profile-matrix.txt`](size-profile-matrix.txt), the six
`size-*.txt` files, and [`postcommit-build.txt`](postcommit-build.txt).

## Product Performance Gate

Ratios are baseline time divided by candidate time. The acceptance floor is
`0.995x` for every operation-level paired geometric mean.

| Compiler/profile | Keygen core | Encaps core | Decaps core | Roundtrip core | Minimum |
|---|---:|---:|---:|---:|---:|
| Clang native | 0.9984x | 1.0005x | 1.0075x | 1.0012x | 0.9984x |
| Clang AVX2-only | 1.0012x | 1.0018x | 1.0028x | 1.0024x | 1.0012x |
| GCC native | 0.9989x | 0.9991x | 1.0014x | 0.9988x | 0.9988x |
| GCC AVX2-only | 1.0003x | 1.0035x | 0.9988x | 1.0025x | 0.9988x |

Every row clears the regression floor. Clang-native decapsulation has a
`1.0075x` gmean and `1.0005x` paired-bootstrap 95% lower bound, but aggregate
roundtrip is neutral. No broad complete-KEM speed gain is credited.

See [`clang-product-ab-15x200k.txt`](clang-product-ab-15x200k.txt),
[`clang-product-ab-raw.tsv`](clang-product-ab-raw.tsv),
[`gcc-native-product-ab-15x100k.txt`](gcc-native-product-ab-15x100k.txt),
[`gcc-avx2-product-ab-15x100k.txt`](gcc-avx2-product-ab-15x100k.txt), and
[`bench-product-hashes.txt`](bench-product-hashes.txt).

## Stack

Eight guarded alternate-stack runs used the exact Clang-native baseline and
candidate products.

| Operation | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Keygen | 6,648 B | 6,648 B | 0 B |
| Encaps | 6,776 B | 6,712 B | -64 B |
| Decaps valid | 8,056 B | 8,056 B | 0 B |
| Decaps invalid | 8,056 B | 8,056 B | 0 B |
| Maximum | 8,056 B | 8,056 B | 0 B |

See [`stack.txt`](stack.txt).

The AVX2-only product was measured with the same `-O2` probe flags as its
preceding report. Keygen and encapsulation each fall 32 bytes; decapsulation
is unchanged, reducing the profile maximum from 4,544 to 4,512 bytes.

## Correctness And Isolation

The exact implementation source passed:

- GCC and Clang native, AVX2-only, and scalar KAT, production API, and complete
  1,000-iteration stage-oracle validation.
- Clang native ASan+UBSan and GCC native UBSan KAT, directly linked production
  API, and complete 1,000-iteration stage validation.
- All 16 core, product, upstream, and PQClean corpus paths, each producing
  381,228 bytes with SHA-256
  `e4d8f908f9a3c59171deeed712925760b194d692b0c571861f204eabef976b67`.
- Clang and GCC NTT-root generator reproducibility.
- AVX2-only products contain no AVX512 mask/ZMM register use and all products
  retain non-executable GNU stack declarations.
- The three public deterministic KEM symbols are unchanged.

See [`correctness-matrix.txt`](correctness-matrix.txt),
[`sanitizers.txt`](sanitizers.txt),
[`cross-path-corpus.txt`](cross-path-corpus.txt),
[`ntt-roots.txt`](ntt-roots.txt), [`abi-audit.txt`](abi-audit.txt), and
[`source-audit.txt`](source-audit.txt).

## Dependency Boundary

The baseline Clang-native deterministic product had unresolved `bcmp`, `exit`,
`memcpy`, `perror`, and `syscall` references. The candidate has only `bcmp`
and `memcpy`. Other compiler/profile products have only ordinary memory
operation references. The deterministic product therefore removes its dead
OS-random and fatal-error runtime dependency; it does not add a backend,
library, cache, precomputed key, or external cryptographic object.

## Remaining Goal Gap

Using the pinned same-method comparator sizes, the native deficit to
mlkem-native falls from 18,589 to 18,425 bytes. The AVX2-only deficit to
OpenSSL falls from 7,825 to 7,602 bytes. These comparator values were not
rebuilt in this local change report, and the required ten-comparator speed and
size gates have not been rerun on this same revision. Both primary-size gates
still fail, so this commit does not complete the optimization Goal.

## Reproduction

```bash
make clean
make -j"$(nproc)" test test-product bench-stages product \
  CC=clang ARCH_CFLAGS=-march=native
./bench_core_stagesc 1000
./scripts/measure_product_size.sh baby_mlkem768_product.o

RUNS=15 WARMUP_RUNS=3 RUN_ORDER=alternating SUITES=product \
  KEM_ITERS=100000 PIN_CPU=0 C_COMPILER=gcc \
  ARCH_CFLAGS=-march=native \
  ./scripts/bench_core_ab.sh 5f39cce

STACK_RUNS=8 STACK_USABLE_BYTES=1048576 C_COMPILER=clang \
  STACK_CFLAGS='-O3 -march=native -fomit-frame-pointer -fno-stack-protector' \
  ./scripts/measure_stack_highwater.sh baby_mlkem768_product.o local

JOBS="$(nproc)" ./scripts/verify_cross_path_corpus.sh
make check-ntt-roots HOSTCC=clang
make check-ntt-roots HOSTCC=gcc
```

Run the same product A/B with the documented AVX2-only flags and with Clang.
File integrity for this directory is recorded in `checksums.sha256`.
