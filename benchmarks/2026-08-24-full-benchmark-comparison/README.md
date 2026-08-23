# Full Benchmark and Library Comparison

This report collects the complete local benchmark set and the formal
comparison matrix for the current baby-mlkem product. The product code is
source commit `400dbe4`; repository commits after that point only add
benchmark evidence and documentation. The current repository head is
`6d30aaf`.

The local benchmark binaries were rebuilt on 2026-08-24 with Clang 18.1.3 and
CPU 0 pinning. The external library matrix is the completion-qualifying c8
measurement from 2026-08-22: ten comparator suites, fifteen paired runs,
three warmups, 100,000 iterations per run, alternating order, and 20,000
paired bootstrap samples. Its raw evidence is linked below rather than
duplicated.

## Executive Summary

- The product API single-run roundtrip was `15,051.86 ns/op` native and
  `14,755.25 ns/op` AVX2-only under the local survey conditions.
- The formal external matrix passes all 40 native/AVX2 operation rows.
- The narrowest formal speedup is `1.3282x` native keygen and `1.1062x`
  AVX2-only keygen; their paired CI lower bounds are `1.3209x` and `1.1002x`.
- The local primary footprint is `51,171 B` native and `45,032 B` AVX2-only.
- The full size matrix passes all 20 rows. The closest size points are
  mlkem-native by `29 B` native and OpenSSL by `17 B` AVX2-only.
- The local product has no external cryptographic runtime dependency. Vendor
  code is used only by the explicitly named comparator or vendor benchmark
  paths.

## Measurement Scope

| Area | Profiles and workload | Result |
|---|---|---|
| KEM core diagnostic | `benchc`, 100,000 iterations, native and AVX2 | 17 lines per profile, including cache-enabled and cache-disabled core metrics |
| KEM product API | `bench_productc`, 100,000 iterations, native and AVX2 | 17 lines per profile; this is the no-cache product measurement |
| NTT | `bench_nttc`, 20,000 iterations, native and AVX2 | 84 timed metrics per profile |
| Keccak and sampling | local `bench_keccakc` and vendor `bench_keccak_vendorc`, 50,000 iterations | local/vendor paths recorded separately |
| Stage oracle | `bench_core_stagesc`, 1,000 iterations, native and AVX2 | 571 lines per profile, including range checks and stage timings |
| External speed | 10 comparator suites, native and AVX2 | 40 operation rows, formal c8 evidence |
| External size | 10 comparator suites, native and AVX2 | 20 primary-footprint rows, formal c8 evidence |

The complete local outputs are in [`internal-native/`](internal-native/) and
[`internal-avx2/`](internal-avx2/). Empty `.stderr` files are retained as an
explicit successful-error-channel check.

## Local Product Benchmarks

The `benchc` default columns include the internal cache-enabled diagnostic
path. The `_core` columns disable internal caches and are the comparable core
path. `bench_productc` always uses the exported product API and disables the
cache-bearing diagnostic path.

| Profile / binary | Keygen ns/op | Encaps ns/op | Decaps ns/op | Roundtrip ns/op |
|---|---:|---:|---:|---:|
| Native `benchc` default | 5,611.57 | 1,715.20 | 2,235.93 | 9,584.86 |
| Native `benchc` no-cache core | 5,540.60 | 4,425.84 | 4,401.49 | 14,691.23 |
| Native `bench_productc` | 5,556.26 | 4,427.63 | 4,729.51 | 15,051.86 |
| AVX2 `benchc` default | 5,612.35 | 1,748.66 | 2,259.53 | 9,647.35 |
| AVX2 `benchc` no-cache core | 5,597.19 | 4,453.71 | 4,409.75 | 14,742.20 |
| AVX2 `bench_productc` | 5,554.61 | 4,433.20 | 4,483.19 | 14,755.25 |

These are single 100,000-iteration local survey runs, not the formal paired
speed claim. Use the product rows and the formal report for external claims.

### Representative Core Metrics

All NTT and stage metrics remain in the raw files. The following values make
the main current bottlenecks directly visible.

| Metric | Native ns/op | AVX2-only ns/op |
|---|---:|---:|
| NTT inplace | 57.58 | 65.23 |
| NTT inplace lazy input | 59.77 | 65.39 |
| NTT inverse | 81.92 | 81.75 |
| NTT inverse add | 86.39 | 86.30 |
| NTT inverse Montgomery add | 103.91 | 103.08 |
| NTT K=3 accumulation | 84.65 | 84.21 |
| NTT K=3 factored accumulation | 86.33 | 84.97 |
| Keccak 4-way local | 290.01 | 289.71 |
| Keccak 4-way vendor | 308.57 | 308.13 |
| SHA3-256 public-key path, local | 1,687.37 | 1,687.60 |
| SHA3-256 public-key path, vendor binary | 1,687.64 | 1,691.13 |
| Full sample_ntt | 617.54 | 616.82 |
| Keygen accumulation and encode stage | 482.49 | 487.93 |
| Encrypt accumulation and inverse stage | 865.66 | 867.39 |
| Encrypt inverse/add/final encode stage | 368.99 | 367.02 |
| Decrypt inverse/subtract stage | 279.00 | 277.24 |
| Decrypt NTT/accumulate/recover stage | 372.84 | 369.12 |

The vendor Keccak path is slower than the repository-local Keccak path in this
direct four-way permutation benchmark. This is an implementation observation,
not a runtime dependency claim: the product build uses the local core path.

## Formal Speed Comparison

The speedup is comparator time divided by baby-mlkem time. Values above `1.0x`
favor baby-mlkem. The values below are the complete 40-row operation matrix
from the [native formal report](../2026-08-22-goal-native-speed-c8/README.md)
and [AVX2 formal report](../2026-08-22-goal-avx2-speed-c8/README.md).

| Comparator | Native keygen | Native encaps | Native decaps | Native roundtrip | AVX2 keygen | AVX2 encaps | AVX2 decaps | AVX2 roundtrip |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Kyber upstream AVX2 | 1.3282x | 1.4628x | 2.0377x | 1.5715x | 1.1762x | 1.4501x | 1.6062x | 1.3754x |
| Kyber fair flags | 1.3325x | 1.4579x | 2.0382x | 1.5709x | 1.1898x | 1.4548x | 1.6178x | 1.3912x |
| mlkem-native | 1.5864x | 1.8957x | 3.0822x | 2.0763x | 1.1271x | 1.5048x | 1.9677x | 1.4699x |
| PQClean AVX2 | 1.7595x | 1.9434x | 2.7721x | 2.1052x | 1.1894x | 1.4701x | 1.6941x | 1.4219x |
| liboqs | 1.5117x | 1.8106x | 2.9902x | 1.9990x | 1.2771x | 1.6885x | 2.1652x | 1.6495x |
| BoringSSL | 3.1285x | 2.9950x | 5.1334x | 3.5729x | 2.4907x | 2.8720x | 3.8676x | 2.9701x |
| libcrux Rust | 1.6156x | 1.9527x | 2.6739x | 2.0009x | 1.4184x | 1.8771x | 2.0690x | 1.7278x |
| libjade Kyber768 AVX2 | 1.5632x | 2.3380x | 2.3383x | 2.0392x | 1.1062x | 1.8457x | 1.4823x | 1.4349x |
| Botan ML-KEM | 7.7280x | 6.5875x | 10.3313x | 8.0501x | 5.6477x | 5.4543x | 6.9456x | 5.9738x |
| OpenSSL ML-KEM | 5.0374x | 3.1260x | 6.0984x | 4.6173x | 3.6584x | 2.8317x | 4.2870x | 3.5207x |

The machine-readable form is [`speed-summary.tsv`](speed-summary.tsv). The
narrowest formal roundtrip ratio and CI lower bound are `1.5709x/1.5563x`
native and `1.3754x/1.3388x` AVX2-only. The formal speed verifier reports
PASS for all 40 rows.

## Primary Size Comparison

Primary size is code plus read-only data plus required metadata. Writable data
and maximum stack are listed separately. A negative delta means the local
product is smaller than that comparator.

| Comparator | Native comparator primary | Native local delta | AVX2 comparator primary | AVX2 local delta |
|---|---:|---:|---:|---:|
| Kyber upstream AVX2 | 61,032 B | -9,861 B | 62,970 B | -17,938 B |
| Kyber fair flags | 61,371 B | -10,200 B | 63,373 B | -18,341 B |
| mlkem-native | 51,200 B | -29 B | 51,279 B | -6,247 B |
| PQClean AVX2 | 60,950 B | -9,779 B | 61,827 B | -16,795 B |
| liboqs | 70,206 B | -19,035 B | 81,316 B | -36,284 B |
| BoringSSL | 208,736 B | -157,565 B | 134,969 B | -89,937 B |
| libcrux Rust | 137,086 B | -85,915 B | 142,302 B | -97,270 B |
| libjade Kyber768 AVX2 | 109,633 B | -58,462 B | 109,633 B | -64,601 B |
| Botan ML-KEM | 183,712 B | -132,541 B | 146,600 B | -101,568 B |
| OpenSSL ML-KEM | 103,552 B | -52,381 B | 45,049 B | -17 B |

| Local profile | Code | Read-only data | Primary | Writable | Max stack |
|---|---:|---:|---:|---:|---:|
| Native | 42,493 B | 8,678 B | 51,171 B | 18,001 B | 8,056 B |
| AVX2-only | 39,762 B | 5,270 B | 45,032 B | 26,593 B | 4,512 B |

The complete per-comparator size outputs are in the [c8 size matrix](../2026-08-22-goal-size-c8/README.md), and the machine-readable aggregate is
[`size-summary.tsv`](size-summary.tsv). All 20 individual size gates pass.

## Library Scope and Dependencies

| Library | Role | Revision or provenance | Runtime dependency of baby-mlkem |
|---|---|---|---|
| baby-mlkem | Candidate independent core | `400dbe4` | No |
| Kyber upstream | AVX2 reference | `3edd5af` | No |
| PQClean | C AVX2 comparator | `0586a82` | No |
| mlkem-native | Native C comparator | `0457037` | No |
| liboqs | Library comparator | `4e1183a` | No |
| BoringSSL | Library comparator | `a204be2` | No |
| libcrux | Rust comparator | crate `0.0.10`, lock hash recorded | No |
| libjade | AVX2 comparator | assembly hash recorded | No |
| Botan | C++ comparator | `7ffae68` | No |
| OpenSSL | Library comparator | `1a3455e` | No |

The comparator sources are built separately for measurement. Botan and
OpenSSL use normalized internal-core adapters, and BoringSSL/liboqs/libcrux/
libjade use normalized three-operation harnesses. These adapters are part of
the comparison methodology, not baby-mlkem runtime dependencies. The local
product links its own repository-local C/intrinsics/assembly implementation.

The machine-readable dependency list is [`library-scope.tsv`](library-scope.tsv).

## Interpretation

The closest speed comparisons are Kyber, fair-flags Kyber, mlkem-native,
PQClean, and libjade. The local product is ahead of each in the formal matrix,
but the AVX2 margin over libjade keygen is only `1.1062x`; this is the most
important speed margin to protect in future changes.

The large Botan, BoringSSL, and OpenSSL ratios should not be interpreted as a
single primitive being intrinsically that much slower. Their normalized calls
include adapter, wire-key parsing, operation rebuild, or selected-object
boundaries required by the no-cache comparison contract. The report therefore
supports the claim "faster than these pinned normalized paths", not an
unqualified claim about every high-level API configuration.

## Reproduction

The local benchmark set can be rebuilt from the repository root in an isolated
checkout:

```bash
make -B CC=clang AVX2_BACKEND=core ARCH_CFLAGS=-march=native \
  bench bench-product bench-ntt bench-keccak bench-keccak-vendor bench-stages product-size
taskset -c 0 ./benchc 100000
taskset -c 0 ./bench_productc 100000
taskset -c 0 ./bench_nttc 20000
taskset -c 0 ./bench_keccakc 50000
taskset -c 0 ./bench_keccak_vendorc 50000
taskset -c 0 ./bench_core_stagesc 1000
```

For AVX2-only, replace `ARCH_CFLAGS` with:

```bash
ARCH_CFLAGS="-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f"
```

The formal comparator reports can be rechecked without rerunning them with
`scripts/verify_goal_speed_report.py`; their exact commands and raw outputs
are recorded in the linked c8 speed and size reports.
