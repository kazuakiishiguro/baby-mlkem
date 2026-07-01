# baby-mlkem

A toy implementation of ML-KEM (formaly knows as kyber), a Module-Lattice-Based Key-Encapsulation Mechanism Standard ([FIPS203](https://doi.org/10.6028/NIST.FIPS.203)). This implementation is written in pure C and is inspired by the blog post [Enough Polynomials and Linear Algebra to Implement Kyber](https://words.filippo.io/dispatches/kyber-math/).

## Implementation Status

The repository contains a toy ML-KEM implementation. The default benchmark and
test build now uses the independent baby-mlkem core (`AVX2_BACKEND=core`) rather
than delegating KEM operations to vendored upstream Kyber or PQClean AVX2 code.

The default build does not link against external crypto libraries such as
OpenSSL, BoringSSL, or liboqs. It also does not compile the vendored Kyber/PQClean
AVX2 KEM backends or the vendored PQClean FIPS202 object into the local binary.
This default is the baseline for true core optimization work.

The repository still keeps in-tree comparator backends. Set
`AVX2_BACKEND=upstream` to use the vendored upstream Kyber AVX2 sources under
`include/kyber_upstream/avx2`, or `AVX2_BACKEND=pqclean` to use the vendored
PQClean AVX2 sources. Results from those opt-in backends measure integration with
external-origin vendored code, not an independent baby-mlkem core.

## Test

To run tests for the implementation, execute the following command:

```bash
make test
```

## Benchmark

Compile and run the local benchmark harness:

```bash
make bench-run
```

Use a custom iteration count when needed:

```bash
make bench-run BENCH_ITERS=1000
```

Benchmark ciphertext buffer stride defaults to `1088` (ML-KEM-768 ciphertext
size). Override when needed:

```bash
make bench-run BENCH_CT_STRIDE=4096
```

By default, `Makefile` prefers `clang` when available and otherwise falls back
to `gcc`. Override explicitly when needed:

```bash
make bench-run CC=gcc
```

The default build uses the independent baby-mlkem core. On x86 hosts with AVX2,
that core may use self-contained AVX2 intrinsics from `baby-mlkem.c`, but it does
not delegate KEM operations to the vendored Kyber/PQClean AVX2 backends.

Switch backend explicitly when needed:

```bash
make bench AVX2_BACKEND=core       # default, independent baby-mlkem core
make bench AVX2_BACKEND=upstream   # vendored upstream Kyber AVX2
make bench AVX2_BACKEND=pqclean    # vendored PQClean AVX2
```

## External Comparison

External comparison results now default to the independent core local build.
For example, this compares `AVX2_BACKEND=core` baby-mlkem against a separately
checked out upstream Kyber AVX2 build:

```bash
PIN_CPU=0 ./scripts/bench_compare_kyber_upstream.sh 400
```

If you explicitly set `AVX2_BACKEND=upstream` or `AVX2_BACKEND=pqclean`, the
local binary delegates KEM operations to vendored external-origin AVX2 code.
Speedups from those opt-in modes are integration/build/harness comparisons, not
claims that an independent baby-mlkem arithmetic core is faster.

Run a local comparison against PQClean ML-KEM-768 clean/avx2 on the same host:

```bash
./scripts/bench_compare_pqclean.sh 400
```

Each comparison script defaults to `2000` iterations when not specified.
If `C_COMPILER` is unset, comparator scripts also prefer `clang` when available
and otherwise fall back to `gcc`.
Comparator scripts also use a shared `flock` lock on
`$ROOT_DIR/.bench-compare.lock` to prevent concurrent local rebuild/run races.
Override lock path if needed:

```bash
BENCH_LOCK_FILE=/tmp/my-bench.lock ./scripts/bench_compare_kyber_upstream.sh 400
```

Comparator scripts also clean local build artifacts on exit by default to
avoid cross-compiler object contamination between runs. Disable only if needed:

```bash
CLEAN_LOCAL_BUILD_ARTIFACTS=0 ./scripts/bench_compare_kyber_upstream.sh 400
```

All comparator scripts support reusing a prebuilt local benchmark binary:

```bash
SKIP_LOCAL_BUILD=1 LOCAL_BENCH_BIN=./benchc ./scripts/bench_compare_liboqs.sh 400
```

This is useful when you want to pin local build flags once and compare many
competitors without rebuilding `benchc` in every script.

By default comparator checkouts are reused if already present in `/tmp`.
Set `UPDATE_REPOS=1` to fast-forward git-based comparator directories before
building:

```bash
UPDATE_REPOS=1 ./scripts/bench_compare_all_stats.sh 400 3
```

If a comparator checkout cannot be fast-forwarded, scripts can fall back to a
fresh temporary shallow clone for that run (default enabled):
- `KYBER_FALLBACK_CLONE_ON_UPDATE_FAIL=1`
- `PQCLEAN_FALLBACK_CLONE_ON_UPDATE_FAIL=1`
- `LIBOQS_FALLBACK_CLONE_ON_UPDATE_FAIL=1`
- `BORINGSSL_FALLBACK_CLONE_ON_UPDATE_FAIL=1`
- `OPENSSL_FALLBACK_CLONE_ON_UPDATE_FAIL=1`
- `MLKEM_NATIVE_FALLBACK_CLONE_ON_UPDATE_FAIL=1`
- `BOTAN_FALLBACK_CLONE_ON_UPDATE_FAIL=1`

The script clones PQClean into `/tmp/PQClean` by default. Override with:

```bash
PQCLEAN_DIR=/path/to/PQClean ./scripts/bench_compare_pqclean.sh 400
```

Pin benchmark execution to one CPU core (reduces scheduler noise):

```bash
PIN_CPU=0 ./scripts/bench_compare_pqclean.sh 400
```

Compare against `liboqs` ML-KEM-768 on the same host:

```bash
./scripts/bench_compare_liboqs.sh 400
```

Override liboqs source location if needed:

```bash
LIBOQS_DIR=/path/to/liboqs ./scripts/bench_compare_liboqs.sh 400
```

With CPU pinning:

```bash
PIN_CPU=0 ./scripts/bench_compare_liboqs.sh 400
```

When liboqs exposes derandomized APIs for ML-KEM, the comparator uses
`OQS_KEM_keypair_derand` and `OQS_KEM_encaps_derand` with deterministic seeds
to reduce RNG noise and align with deterministic local benchmarking.

Compare against upstream `pq-crystals/kyber` AVX2 (`KYBER_K=3`):

```bash
./scripts/bench_compare_kyber_upstream.sh 400
```

Override upstream checkout location if needed:

```bash
KYBER_DIR=/path/to/kyber ./scripts/bench_compare_kyber_upstream.sh 400
```

With CPU pinning:

```bash
PIN_CPU=0 ./scripts/bench_compare_kyber_upstream.sh 400
```

Use a different compiler (for both local and competitor harness builds):

```bash
C_COMPILER=clang ./scripts/bench_compare_kyber_upstream.sh 400
```

When `C_COMPILER` is set, comparator scripts now rebuild the local benchmark
with `CC=$C_COMPILER` as well (not only the competitor harness).

Tune upstream compile flags for fairness checks:

```bash
UPSTREAM_CFLAGS="-O2 -flto -fno-semantic-interposition -march=native -mavx2 -mbmi2 -mpopcnt -funroll-loops -fomit-frame-pointer -fno-stack-protector -falign-loops=32 -std=c99" \
  ./scripts/bench_compare_kyber_upstream.sh 400
```

Reuse a prebuilt local benchmark binary (e.g., PGO build):

```bash
SKIP_LOCAL_BUILD=1 LOCAL_BENCH_BIN=./benchc ./scripts/bench_compare_kyber_upstream.sh 400
```

When reusing a prebuilt local binary, you can preheat the local run before the
timed measurement to reduce cold-start governor noise:

```bash
SKIP_LOCAL_BUILD=1 LOCAL_BENCH_BIN=./benchc LOCAL_PREHEAT_ITERS=64 ./scripts/bench_compare_kyber_upstream.sh 400
```

Compare against local `mlkem-native` (`libmlkem768.a`) on the same host:

```bash
./scripts/bench_compare_mlkem_native.sh 400
```

Override `mlkem-native` location if needed:

```bash
MLKEM_NATIVE_DIR=/path/to/mlkem-native ./scripts/bench_compare_mlkem_native.sh 400
```

With CPU pinning:

```bash
PIN_CPU=0 ./scripts/bench_compare_mlkem_native.sh 400
```

The `mlkem-native` comparator uses deterministic `*_derand` KEM paths and
stores prepared ciphertexts at exact `CRYPTO_CIPHERTEXTBYTES` stride for fair
decapsulation measurements.

The comparator defaults to `MLKEM_NATIVE_AUTO=1` (enables host-aware optimized
build mode in newer `mlkem-native` trees). Override if needed:

```bash
MLKEM_NATIVE_AUTO=0 ./scripts/bench_compare_mlkem_native.sh 400
```

Compare against BoringSSL ML-KEM-768 on the same host:

```bash
./scripts/bench_compare_boringssl.sh 400
```

Override BoringSSL checkout location if needed:

```bash
BORINGSSL_DIR=/path/to/boringssl ./scripts/bench_compare_boringssl.sh 400
```

With CPU pinning:

```bash
PIN_CPU=0 ./scripts/bench_compare_boringssl.sh 400
```

The BoringSSL comparator uses internal deterministic ML-KEM hooks from
`crypto/fipsmodule/bcm_interface.h` for repeatable benchmark inputs.

Compare against Rust `libcrux-ml-kem` ML-KEM-768 on the same host:

```bash
./scripts/bench_compare_libcrux.sh 400
```

Override `libcrux-ml-kem` crate version if needed:

```bash
LIBCRUX_CRATE_VERSION=0.0.8 ./scripts/bench_compare_libcrux.sh 400
```

With CPU pinning:

```bash
PIN_CPU=0 ./scripts/bench_compare_libcrux.sh 400
```

The libcrux comparator builds a pinned release Rust harness with
`target-cpu=native`, `lto=fat`, and `codegen-units=1`.

Compare against OpenSSL (>= 3.5) ML-KEM-768 on the same host:

```bash
./scripts/bench_compare_openssl_mlkem.sh 400
```

Override OpenSSL checkout path if needed:

```bash
OPENSSL_DIR=/path/to/openssl ./scripts/bench_compare_openssl_mlkem.sh 400
```

With CPU pinning:

```bash
PIN_CPU=0 ./scripts/bench_compare_openssl_mlkem.sh 400
```

The OpenSSL comparator builds OpenSSL from source with deterministic keygen
seed (`OSSL_PKEY_PARAM_ML_KEM_SEED`) and deterministic encapsulation entropy
(`OSSL_KEM_PARAM_IKME`) for repeatable measurements.

Compare against Libjade `kyber_kyber768_avx2` on the same host:

```bash
./scripts/bench_compare_libjade.sh 400
```

Override Libjade distribution location if needed:

```bash
LIBJADE_DIST_ROOT=/path/to/libjade-dist-src-amd64 ./scripts/bench_compare_libjade.sh 400
```

With CPU pinning:

```bash
PIN_CPU=0 ./scripts/bench_compare_libjade.sh 400
```

The Libjade comparator uses the official release distribution
`libjade-dist-src-amd64` (prebuilt assembly) and deterministic
`*_derand` KEM entrypoints for repeatable inputs.

Compare against Botan ML-KEM-768 on the same host:

```bash
./scripts/bench_compare_botan_mlkem.sh 400
```

Override Botan checkout/build locations if needed:

```bash
BOTAN_DIR=/path/to/botan BOTAN_BUILD_DIR=/tmp/botan-build ./scripts/bench_compare_botan_mlkem.sh 400
```

With CPU pinning:

```bash
PIN_CPU=0 ./scripts/bench_compare_botan_mlkem.sh 400
```

The Botan comparator uses Botan FFI in a minimized static build
(`ffi,ml_kem,...` modules) and deterministic seed/RNG inputs for repeatable
measurements. By default it prefers `BOTAN_CXX=clang++` when `C_COMPILER` is
clang, otherwise `g++`. If the clang++ toolchain cannot build Botan on the
host, the script automatically falls back to `g++` unless `BOTAN_CXX` or
`BOTAN_CC_FAMILY` is explicitly pinned. The script caches this failure in
`$BOTAN_DIR/.botan_clangpp_broken`; set `BOTAN_RESET_AUTO_FALLBACK=1` to retry
clang++ auto-selection.

When `UPDATE_REPOS=1` is set and the configured `MLKEM_NATIVE_DIR` cannot be
fast-forwarded, the script keeps that checkout untouched and falls back to a
fresh temporary shallow clone for the run.

Likewise for Botan, when `UPDATE_REPOS=1` is set and `BOTAN_DIR` cannot be
fast-forwarded, the script can use a fresh temporary shallow clone for that run
(`BOTAN_FALLBACK_CLONE_ON_UPDATE_FAIL=1`, default).

Run repeated mean/sd comparison across upstream Kyber AVX2, `mlkem-native`,
PQClean AVX2, liboqs, BoringSSL, libcrux, Libjade, Botan, and OpenSSL ML-KEM:

```bash
./scripts/bench_compare_all_stats.sh 400 3
```

By default (`LOCAL_BENCH_REUSE=1`), the repeated suite builds local `benchc`
once and reuses it across all comparator scripts for faster iteration and
consistent local-binary reuse. Disable if needed:

```bash
LOCAL_BENCH_REUSE=0 ./scripts/bench_compare_all_stats.sh 400 3
```

Run the repeated suite with a different compiler:

```bash
C_COMPILER=clang ./scripts/bench_compare_all_stats.sh 400 3
```

By default, repeated-suite speedups are computed from run means. You can switch
the aggregation mode:

```bash
STATS_MODE=median ./scripts/bench_compare_all_stats.sh 400 5
```

or use trimmed means (drop `TRIM_COUNT` lowest and highest values per side):

```bash
STATS_MODE=trimmed TRIM_COUNT=1 ./scripts/bench_compare_all_stats.sh 400 5
```

Supported modes are `mean` (default), `median`, and `trimmed`.

By default, comparator speedups use `mlkem_roundtrip_ns_per_op`, which preserves
local cross-operation caches inside a fresh roundtrip. For core-only comparison,
select the cache-free local metric:

```bash
LOCAL_ROUNDTRIP_METRIC=mlkem_roundtrip_core_ns_per_op \
  STATS_MODE=median PIN_CPU=0 C_COMPILER=clang \
  ./scripts/bench_compare_all_stats.sh 600 2
```

`mlkem_roundtrip_core` clears baby-mlkem's public-key, secret-key, and public-key
hash caches between keygen, encapsulation, and decapsulation. This is the more
conservative metric for deciding whether the implementation core itself is
competitive without relying on repeated-key cache effects.

The repeated suite also runs a fair Kyber AVX2 variant where the upstream
competitor is rebuilt with local-style optimization flags.
Override those flags if needed:

```bash
FAIR_UPSTREAM_CFLAGS="-O2 -flto -fno-semantic-interposition -march=native -mavx2 -mbmi2 -mpopcnt -funroll-loops -fomit-frame-pointer -fno-stack-protector -falign-loops=32 -std=c99" \
  ./scripts/bench_compare_all_stats.sh 400 3
```

You can override local compiler flags for the repeated suite:

```bash
OPT_CFLAGS="-Ofast -flto" EXTRA_CFLAGS="-funroll-loops -fomit-frame-pointer" \
  ./scripts/bench_compare_all_stats.sh 400 3
```

If `CC` resolves to `clang` and no explicit `OPT_CFLAGS`/`EXTRA_CFLAGS` are
provided, `Makefile` applies clang-tuned defaults:
- `OPT_CFLAGS=-O3 -fno-semantic-interposition -fvisibility=hidden`
- `EXTRA_CFLAGS=-fomit-frame-pointer -fno-stack-protector -falign-loops=64 -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-strict-aliasing`

If `CC` resolves to `gcc` and no explicit `EXTRA_CFLAGS` is provided, the
default extra flags are:
- `EXTRA_CFLAGS=-funroll-loops -fomit-frame-pointer -fno-stack-protector -falign-loops=32 -finline-functions`

## Flag Tuning

Run automatic local-vs-upstream fair-flag exploration:

```bash
PIN_CPU=0 ./scripts/tune_flags_against_kyber.sh 2000 3
```

Arguments are `[iterations] [runs]`.
Set `WARMUP_RUNS` (default `1`) to discard initial transient runs:

```bash
PIN_CPU=0 WARMUP_RUNS=1 ./scripts/tune_flags_against_kyber.sh 2000 3
```

For thermally constrained hosts, add cooldown sleeps (seconds, fractional
allowed):

```bash
PIN_CPU=0 WARMUP_RUNS=1 SLEEP_BETWEEN_RUNS=0.2 SLEEP_BETWEEN_COMBOS=1 \
  ./scripts/tune_flags_against_kyber.sh 2000 3
```

For file-local backend tuning, the Makefile also exposes these per-file knobs.
`KYBER_FIPS202_CFLAGS` defaults to `-O2` for the upstream Kyber scalar
FIPS202 path; the x4 and Keccak4x knobs default to empty. All three can be
overridden from the command line for A/B experiments:

```bash
KYBER_FIPS202_CFLAGS= make bench
KYBER_FIPS202_CFLAGS="-fno-slp-vectorize" make bench
KYBER_FIPS202X4_CFLAGS="-Ofast" make bench
KYBER_KECCAK4X_CFLAGS="-falign-functions=64" make bench
```

Keep non-default overrides only when repeated comparison runs show a stable win.

## Profiling

When `perf` is unavailable (restricted `perf_event_paranoid`), use the
`gprof`-based profiler to identify hot symbols in the current local backend:

```bash
PIN_CPU=0 C_COMPILER=clang AVX2_BACKEND=upstream \
  KEEP_PROFILE_ARTIFACTS=1 PROFILE_BENCH_ITERS=6000 \
  ./scripts/profile_kyber_gprof.sh 6000
```

The script prints a flat profile excerpt and call graph excerpt, and writes
`full_gprof_report=<path>` for deeper inspection.

Current independent-core profile snapshot, pinned to CPU 0, `clang`,
`AVX2_BACKEND=core`, `PROFILE_BENCH_ITERS=8000`, after `d6f357b`:

| Symbol | Flat self time |
|---|---:|
| `keccakf4` | 33.33% |
| `ntt` | 22.22% |
| `sample_ntt_parse_stream` | 14.81% |
| `keccakf` | 11.11% |
| `bench_decaps` | 7.41% |
| `mlkem_prf_cbd_eta2x4_32` | 3.70% |
| `kpke_encrypt` | 3.70% |

This profile explains why the next core-only work should be biased toward
public matrix sampling (`keccakf4` plus `sample_ntt_parse_stream`) and forward
NTT. Small cache-copy or post-processing changes are now likely to be lost in
noise unless the target stage metric also improves.

## Compiler Matrix

Compare performance across multiple compilers with one command:

```bash
PIN_CPU=0 COMPILERS="gcc clang" ./scripts/bench_compiler_matrix.sh 2000 3
```

Arguments are `[iterations] [runs]`.
The output includes `vs_boringssl`, `vs_libcrux`, `vs_libjade`, `vs_botan`,
and `vs_openssl` in addition to existing competitor columns.

### Latest Comparison Table (2026-05-09)

Snapshot command:

```bash
PIN_CPU=0 WARMUP_RUNS=1 COMPILERS="gcc clang" ./scripts/bench_compiler_matrix.sh 500 1
```

Roundtrip comparison snapshot (`x` means local is faster):

This is a historical upstream-backed snapshot from before the Makefile default
was changed to `AVX2_BACKEND=core`. The `vs kyber default` and `vs kyber fair`
columns compare the local in-tree upstream-AVX2-backed build against separately
built upstream Kyber AVX2 checkouts. They should not be interpreted as an
independent implementation beating upstream Kyber AVX2.

| Compiler | Local mean ns/op | vs kyber default | vs kyber fair | vs mlkem-native | vs PQClean AVX2 | vs liboqs | vs BoringSSL | vs libcrux | vs Libjade | vs Botan | vs OpenSSL |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| gcc | 17890.38 | 1.070x | 1.048x | 1.551x | 1.172x | 1.204x | 3.302x | 1.284x | 1.148x | 7.383x | 3.028x |
| clang | 16029.25 | 1.002x | 1.004x | 1.631x | 1.251x | 1.332x | 3.345x | 1.338x | 1.318x | 8.391x | 3.014x |

For lower-noise comparisons, prefer larger runs such as:

```bash
PIN_CPU=0 WARMUP_RUNS=1 COMPILERS="gcc clang" ./scripts/bench_compiler_matrix.sh 2000 3
```

### Current Independent Core vs Opt-in Upstream Backend (2026-06-30)

Current `baby-mlkem` defaults to the independent core. The table below compares
that default core path with the opt-in vendored upstream Kyber AVX2 backend built
from this same repository. This is a local backend comparison, not a claim that
the independent core is faster than upstream Kyber AVX2.

Snapshot commands, pinned to CPU 0, `clang`, `5000` iterations:

```bash
make clean CC=clang AVX2_BACKEND=core && make bench CC=clang AVX2_BACKEND=core
taskset -c 0 ./benchc 5000
make clean CC=clang AVX2_BACKEND=upstream && make bench CC=clang AVX2_BACKEND=upstream
taskset -c 0 ./benchc 5000
```

| Backend | keygen ns/op | encaps ns/op | decaps ns/op | roundtrip ns/op | Interpretation |
|---|---:|---:|---:|---:|---|
| `core` | 9120.48 | 2480.06 | 3478.97 | 15172.46 | Independent baby-mlkem core, default build |
| `upstream` | 5123.74 | 1250.48 | 3146.91 | 11821.75 | Opt-in vendored upstream Kyber AVX2 backend |

At this snapshot, the independent core is `1.28x` slower on roundtrip than the
opt-in vendored upstream Kyber AVX2 backend. Per operation, the core is `1.78x`
slower for keygen, `1.98x` slower for encaps, and `1.11x` slower for decaps.
This is the current baseline for judging whether future vendor-free core changes
are closing the gap.

### Historical Independent Core Baseline (2026-06-29)

This snapshot is a historical baseline from before the later core optimization
series. Use the latest `Independent Core Optimization A/B` sections for current
core throughput, and use this table only as an early before/after reference.

Snapshot commands:

```bash
make clean CC=clang AVX2_BACKEND=core && make bench CC=clang AVX2_BACKEND=core
taskset -c 0 ./benchc 1000
make clean CC=clang AVX2_BACKEND=upstream && make bench CC=clang AVX2_BACKEND=upstream
taskset -c 0 ./benchc 1000
```

Local benchmark snapshot, pinned to CPU 0, `clang`, `1000` iterations:

| Backend | keygen ns/op | encaps ns/op | decaps ns/op | roundtrip ns/op | Interpretation |
|---|---:|---:|---:|---:|---|
| `core` | 43795.84 | 14681.88 | 18064.43 | 110320.24 | Independent baby-mlkem scalar core |
| `upstream` | 5145.68 | 1276.05 | 3052.52 | 11621.58 | Vendored upstream Kyber AVX2 backend |

At this historical baseline, the independent core roundtrip was about `9.49x`
slower than local upstream AVX2. Current core optimization work should still be
measured against the default `AVX2_BACKEND=core` path, not the opt-in
upstream-backed path.

### Independent Core NTT Microbench (2026-06-29)

Use the NTT microbench when changing the vendor-free core NTT arithmetic. This
benchmark includes `baby-mlkem.c` directly and does not link the vendored
upstream Kyber or PQClean AVX2 KEM sources, so it is intended for true
independent-core before/after measurements.

```bash
make clean CC=clang AVX2_BACKEND=core && make bench-ntt CC=clang AVX2_BACKEND=core
taskset -c 0 ./bench_nttc 200000
```

The binary validates the core helper relationships before timing, including
`ntt_inv(ntt(x))`, the fused inverse-NTT add/sub helpers, and the fused
three-term NTT-domain multiplication helpers. Reported metrics isolate these
helpers:

| Metric | Core helper measured |
|---|---|
| `mlkem_ntt_copy` | `ntt(in, out)` including the out-of-place copy |
| `mlkem_ntt_inplace` | `ntt(in, in)` without the initial copy |
| `mlkem_ntt_head_l7_l4` | AVX2 build only: current forward-NTT upper stages before `ntt_tail_avx2()` |
| `mlkem_ntt_tail_avx2` | AVX2 build only: current forward-NTT lower stages `l3`..`l1` |
| `mlkem_ntt_tail_avx2_l3` .. `mlkem_ntt_tail_avx2_l1` | AVX2 build only: one prepared lower-stage helper from the actual tail path |
| `mlkem_ntt_level_l7` .. `mlkem_ntt_level_l1` | one prepared scalar forward-NTT level, from length 128 down to length 2 |
| `mlkem_ntt_inv` | `ntt_inv()` |
| `mlkem_ntt_inv_level_l1` .. `mlkem_ntt_inv_level_l7` | one prepared inverse-NTT level, from length 2 up to length 128 |
| `mlkem_ntt_inv_add` | `ntt_inv_add()` |
| `mlkem_ntt_inv_add2` | `ntt_inv_add2()` |
| `mlkem_ntt_inv_sub_from` | `ntt_inv_sub_from()` |
| `mlkem_ntt_mul_acc3` | `ntt_mul_acc3()` |
| `mlkem_ntt_mul_acc3_factored` | `ntt_mul_acc3_factored_gamma()` |

For optimization work, compare the same command before and after each small
NTT change, preferably pinned to one CPU. These numbers are microbenchmarks for
core arithmetic direction-finding, not ML-KEM KEM throughput results. The
forward- and inverse-level metrics mutate a prepared input state for a single
level; use them to rank implementation targets, not as additive replacements for
full `ntt()` or `ntt_inv()`. The AVX2 forward split rows measure the actual
current full-NTT split: scalar/vectorized C upper stages followed by the
self-contained AVX2 tail. The scalar forward-level `l2`/`l1` rows are kept only
for direction finding and are not the implementation used by full AVX2 `ntt()`.
The inverse-level rows also time scalar level kernels for direction finding;
the current full inverse NTT already uses a self-contained AVX2 head for
`l1`..`l3`.

Current AVX2 forward split snapshot, pinned to CPU 0, `clang`,
`AVX2_BACKEND=core`, `200000` iterations:

| Metric | ns/op |
|---|---:|
| `mlkem_ntt_copy` | 197.12 |
| `mlkem_ntt_inplace` | 194.85 |
| `mlkem_ntt_head_l7_l4` | 96.92 |
| `mlkem_ntt_tail_avx2` | 97.37 |
| `mlkem_ntt_tail_avx2_l3` | 26.79 |
| `mlkem_ntt_tail_avx2_l2` | 29.18 |
| `mlkem_ntt_tail_avx2_l1` | 41.76 |

This shows the current forward NTT is roughly balanced between the upper stages
and the AVX2 lower tail. Within the tail, `l1` is the largest single prepared
stage, but the earlier isolated `l4` replacement regressed KEM throughput; the
next implementation attempt should therefore fuse multiple stages or change data
layout instead of swapping one stage in isolation.

A narrow experiment replacing the `l1` tail helper's four 2-coefficient
gather/scatter pairs with one 16-coefficient block load, dword permutes, and one
block store was also rejected. It improved the NTT microbench
(`mlkem_ntt_tail_avx2_l1` `41.76` -> `31.92` ns/op, `mlkem_ntt_tail_avx2`
`97.37` -> `87.82` ns/op, `mlkem_ntt_inplace` `194.85` -> `185.27` ns/op), and
stage A/B showed `decrypt_u_ntt` median speedup `1.0439x` and
`encrypt_noise_ntt` median speedup `1.0400x`. Longer KEM A/B rejected it because
`mlkem_keygen_core` regressed reproducibly (`0.8927x` and `0.8906x` median
speedup in two KEM-only confirmations) and `mlkem_roundtrip` also regressed.
This suggests future tail work must be validated through keygen/roundtrip, not
accepted on NTT microbench or stage splits alone.

A follow-up attempt kept default `ntt()` unchanged for keygen and routed only the
encryption `rhat` and decryption `u` transforms through the block-load `l1` tail.
This preserved the stage-level wins (`decrypt_u_ntt` median speedup `1.0426x`,
`decrypt_u_ntt_tail` `1.0573x`, `encrypt_noise_ntt` `1.0244x`), but was also
rejected after longer KEM confirmation: `mlkem_encaps_core` median speedup
`0.9545x`, `mlkem_decaps_core` `0.9676x`, and `mlkem_roundtrip_core` `0.9512x`.
The result reinforces that the block-load `l1` shape is not currently a safe
production path even when keygen is excluded.

A separate K=3 batching attempt was also rejected. The candidate kept the normal
per-polynomial tail, but replaced the three independent encryption/decryption
forward-NTT calls with `ntt3_inplace()`, advancing the same upper-stage
`zeta/start` across all three polynomials before moving on. Even with the same
clang vectorization hint as `ntt()`, pinned stage A/B regressed the target rows:
`decrypt_u_ntt` median speedup `0.9948x` and `encrypt_noise_ntt` median speedup
`0.9895x`. Simple loop interleaving therefore is not enough; any future K=3 NTT
work needs real cross-polynomial vector packing or a different data layout.

Current scalar forward-level snapshot, pinned to CPU 0, `clang`,
`AVX2_BACKEND=core`, `200000` iterations:

| Metric | ns/op |
|---|---:|
| `mlkem_ntt_level_l7` | 24.20 |
| `mlkem_ntt_level_l6` | 24.36 |
| `mlkem_ntt_level_l5` | 24.93 |
| `mlkem_ntt_level_l4` | 26.20 |
| `mlkem_ntt_level_l3` | 29.92 |
| `mlkem_ntt_level_l2` | 231.52 |
| `mlkem_ntt_level_l1` | 246.47 |

Current inverse-level snapshot, pinned to CPU 0, `clang`, `AVX2_BACKEND=core`,
`200000` iterations:

| Metric | ns/op |
|---|---:|
| `mlkem_ntt_inv_level_l1` | 247.20 |
| `mlkem_ntt_inv_level_l2` | 233.35 |
| `mlkem_ntt_inv_level_l3` | 28.03 |
| `mlkem_ntt_inv_level_l4` | 23.60 |
| `mlkem_ntt_inv_level_l5` | 22.49 |
| `mlkem_ntt_inv_level_l6` | 22.01 |
| `mlkem_ntt_inv_level_l7` | 21.63 |

The inverse snapshot still argues against broad work on the already-small upper
inverse stages (`l4`..`l7`). For decrypt, the larger remaining targets are the
forward NTT split above and the fused accumulation/inverse path rather than
message recovery or isolated scalar inverse-tail levels.

### Independent Core Keccak/Sampling Microbench (2026-06-29)

Use the Keccak/sampling microbench when changing the vendor-free scalar Keccak,
CBD, PRF, or SHAKE128 rejection-sampling code. Like the NTT microbench, this
benchmark includes `baby-mlkem.c` directly and does not link vendored upstream
Kyber or PQClean AVX2 KEM sources.

```bash
make clean CC=clang AVX2_BACKEND=core && make bench-keccak CC=clang AVX2_BACKEND=core
taskset -c 0 ./bench_keccakc 200000
```

The binary validates deterministic helper behavior before timing. Reported
metrics isolate these helpers:

| Metric | Core helper measured |
|---|---|
| `mlkem_keccakf` | one scalar `keccakf()` permutation |
| `mlkem_keccakf4` | one AVX2 `keccakf4()` permutation over four parallel states |
| `mlkem_sha3_256_32` | `sha3_256()` over a 32-byte input |
| `mlkem_sha3_256_public_key` | `sha3_256()` over a 1184-byte encoded ML-KEM-768 public key |
| `mlkem_sha3_512_32` | `sha3_512()` over a 32-byte input |
| `mlkem_sha3_512_64` | `sha3_512()` over a 64-byte input |
| `mlkem_prf_eta2` | `mlkem_prf(ETA2, seed[32], nonce)` |
| `mlkem_cbd_eta2` | `sample_poly_cbd(ETA2)` over prepared PRF bytes |
| `mlkem_sample_ntt_parse` | one `sample_ntt_parse_stream()` pass over 504 bytes |
| `mlkem_sample_ntt_full` | full `sample_ntt()` including SHAKE128 squeezing and parsing |

Current snapshot, pinned to CPU 0, `clang`, `AVX2_BACKEND=core`, `200000`
iterations:

| Metric | ns/op |
|---|---:|
| `mlkem_keccakf` | 193.67 |
| `mlkem_keccakf4` | 172.64 |
| `mlkem_sha3_256_32` | 205.87 |
| `mlkem_sha3_256_public_key` | 1796.43 |
| `mlkem_sha3_512_32` | 200.44 |
| `mlkem_sha3_512_64` | 198.49 |
| `mlkem_prf_eta2` | 200.28 |
| `mlkem_cbd_eta2` | 22.60 |
| `mlkem_sample_ntt_parse` | 98.88 |
| `mlkem_sample_ntt_full` | 691.40 |

A later experiment forcing full unrolling of the AVX2/AVX512 vector Keccak round
loops was rejected. Keccak A/B against `704354b` with AVX2-only flags showed
`mlkem_keccakf4` median speedup `0.9082x`, while `mlkem_prf_eta2` median speedup
also regressed to `0.9921x`. Keep the vector Keccak round loops rolled; the
code-size/register-pressure cost outweighed loop overhead.

These numbers show that further sampling work should target Keccak/SHAKE128 and
full `sample_ntt()` first; standalone CBD is already much smaller.

### Independent Core Stage Microbench (2026-06-29)

Use the stage microbench to decide where vendor-free core work should go next.
This benchmark includes `baby-mlkem.c` directly, validates its derived stage
state against the real K-PKE keygen/encrypt/decrypt path, and does not link the
vendored upstream Kyber or PQClean AVX2 KEM sources.

```bash
make clean CC=clang AVX2_BACKEND=core && make bench-stages CC=clang AVX2_BACKEND=core
taskset -c 0 ./bench_core_stagesc 20000
```

Reported full K-PKE metrics are useful for context. Reported stage metrics are
not intended to add up exactly to full K-PKE time because cache state, temporary
outputs, and validation scope differ; use them to rank optimization targets.
The PRF/CBD, NTT, and sample-matrix split metrics are isolated
direction-finding measurements, not additive replacements for the combined
stage metrics.

| Metric | Core work measured |
|---|---|
| `mlkem_core_stage_kpke_keygen_full` | full `kpke_keygen()` |
| `mlkem_core_stage_kpke_encrypt_uncached` | full `kpke_encrypt()` with internal caches disabled |
| `mlkem_core_stage_kpke_decrypt_uncached` | full `kpke_decrypt()` with internal caches disabled |
| `mlkem_core_stage_kpke_encrypt_cached` | full `kpke_encrypt()` with a cached public key, for repeated-key context only |
| `mlkem_core_stage_kpke_decrypt_cached` | full `kpke_decrypt()` with a cached secret key, for repeated-key context only |
| `mlkem_core_stage_sample_matrix` | the 3x3 `sample_ntt()` public matrix generation |
| `mlkem_core_stage_sample_matrix_x4_batch0` | first four-entry x4 public-matrix sampler batch |
| `mlkem_core_stage_sample_matrix_x4_batch1` | second four-entry x4 public-matrix sampler batch |
| `mlkem_core_stage_sample_matrix_tail` | final `(2,2)` public-matrix sampler tail |
| `mlkem_core_stage_sample_ntt4_full_raw` | AVX2-only x4 sampler call with a lightweight sink, excluding full-polynomial checksum overhead |
| `mlkem_core_stage_sample_ntt4_store_rate` | AVX2-only x4 sampler 168-byte-rate state transpose/store cost |
| `mlkem_core_stage_sample_ntt4_keccak_store3` | AVX2-only x4 sampler initial three Keccak-f4 blocks plus stream stores |
| `mlkem_core_stage_sample_ntt4_parse_504` | AVX2-only x4 sampler parse of four 504-byte rejection streams |
| `mlkem_core_stage_sample_ntt4_initial_extra_groups` | AVX2-only x4 sampler groups that need a refill after the first 504 bytes per lane |
| `mlkem_core_stage_sample_ntt4_initial_extra_group_pct` | percent of x4 sampler groups that need a refill after the first 504 bytes per lane |
| `mlkem_core_stage_sample_ntt4_initial_extra_lanes` | AVX2-only x4 sampler lanes that need a refill after the first 504 bytes |
| `mlkem_core_stage_sample_ntt4_initial_extra_lane_pct` | percent of x4 sampler lanes that need a refill after the first 504 bytes |
| `mlkem_core_stage_sample_ntt4_initial_avg_accepts` | average accepted coefficients after the first 504-byte parse |
| `mlkem_core_stage_sample_ntt4_initial_min_accepts` | minimum accepted coefficients observed after the first 504-byte parse |
| `mlkem_core_stage_keygen_noise_ntt` | keygen secret/error PRF, CBD, NTT, and secret-key encode |
| `mlkem_core_stage_keygen_noise_prf_cbd` | isolated keygen secret/error PRF and CBD only |
| `mlkem_core_stage_keygen_noise_ntt_encode` | isolated keygen secret/error NTT plus secret-key encode |
| `mlkem_core_stage_keygen_accum_encode` | keygen NTT-domain multiply-add, add error, and public-key encode |
| `mlkem_core_stage_encrypt_noise` | encryption PRF, CBD, and NTT for `r`, `e1`, and `e2` |
| `mlkem_core_stage_encrypt_noise_prf_cbd` | isolated encryption PRF and CBD for `r`, `e1`, and `e2` |
| `mlkem_core_stage_encrypt_noise_ntt` | isolated encryption forward NTT for `r` |
| `mlkem_core_stage_encrypt_accum_inv` | encryption NTT-domain accumulation and inverse NTT for `u` and `v` |
| `mlkem_core_stage_encrypt_accum_inv_u` | the three `u`-polynomial accumulation plus inverse-NTT-add paths |
| `mlkem_core_stage_encrypt_accum_inv_v` | the single `v`-polynomial accumulation plus inverse-NTT-add2 path |
| `mlkem_core_stage_ciphertext_compress_encode` | ciphertext compression and DU/DV bit-packing |
| `mlkem_core_stage_ciphertext_decode_decompress` | ciphertext DU/DV decode and decompression |
| `mlkem_core_stage_decrypt_u_ntt` | decrypt-side forward NTT for the three decoded `u` polynomials |
| `mlkem_core_stage_decrypt_u_ntt_head` | AVX2-only decrypt-side forward NTT upper stages before `ntt_tail_avx2()` |
| `mlkem_core_stage_decrypt_u_ntt_tail` | AVX2-only decrypt-side `ntt_tail_avx2()` lower stages, using precomputed head output |
| `mlkem_core_stage_decrypt_accum_only` | decrypt-side `ntt_mul_acc3()` secret accumulation only, using precomputed `ntt(u)` |
| `mlkem_core_stage_decrypt_inv_sub_from` | decrypt-side inverse NTT subtraction only, using a precomputed NTT-domain accumulation |
| `mlkem_core_stage_decrypt_inv_butterflies` | decrypt-side inverse NTT butterflies only, before final scale/subtraction |
| `mlkem_core_stage_decrypt_inv_head` | AVX2-only decrypt-side inverse NTT head stages `l1`..`l3`, using precomputed NTT-domain accumulation |
| `mlkem_core_stage_decrypt_inv_tail` | AVX2-only decrypt-side inverse NTT tail stages `l4`..`l7`, using precomputed inverse-head output |
| `mlkem_core_stage_decrypt_inv_scale_sub_from` | decrypt-side final inverse-NTT scale and subtraction only, using precomputed inverse-butterfly output |
| `mlkem_core_stage_decrypt_accum_inv` | decrypt-side secret accumulation plus inverse NTT subtraction, using precomputed `ntt(u)` |
| `mlkem_core_stage_decrypt_recover_message` | decrypt-side message recovery from the already reconstructed `w` polynomial |
| `mlkem_core_stage_decrypt_ntt_accum_recover` | decrypt-side NTT, accumulation, inverse NTT subtraction, and message recovery |

The decrypt split metrics are diagnostic and intentionally reuse precomputed
intermediates where noted. On one pinned AVX2 run with 20,000 iterations,
`decrypt_u_ntt` measured 773.17 ns/op, `decrypt_accum_inv` measured 471.97
ns/op, and `decrypt_recover_message` measured 6.25 ns/op. This points future
decrypt work at forward NTT or accumulation/inverse-NTT structure rather than
message recovery. A later pinned AVX2 diagnostic split measured
`decrypt_u_ntt_head` at 489.59 ns/op and `decrypt_u_ntt_tail` at 494.93 ns/op;
these standalone head/tail probes include their own copy and sink overhead, so
they should rank the two halves rather than be added back to full NTT time. A
newer pinned AVX2 20,000-iteration split measured `decrypt_accum_only` at
272.64 ns/op and `decrypt_inv_sub_from` at 390.02 ns/op while the combined
`decrypt_accum_inv` row measured 479.44 ns/op. The split rows have independent
copy/sink overhead, but they show the remaining decrypt-side accumulation work
is more constrained by inverse-NTT subtraction than by the already-fused K=3
`ntt_mul_acc3()` accumulation. A further pinned AVX2 split measured
`decrypt_inv_butterflies` at 365.76 ns/op and `decrypt_inv_scale_sub_from` at
221.04 ns/op, so the next inverse-subtraction target should be the inverse
butterfly schedule rather than the final scale/sub loop alone. Splitting those
inverse butterflies again measured `decrypt_inv_head` at 274.08 ns/op and
`decrypt_inv_tail` at 269.45 ns/op. The head/tail standalone probes have their
own copy/sink overhead, but the near tie means a single isolated inverse stage
is unlikely to carry the full win; future work should fuse or reschedule across
both inverse-head and inverse-tail boundaries. A narrow AVX2 experiment
replacing only the inverse-tail `log2len = 4` / length-16 stage with
`ntt_inv_butterfly8_avx2()` was also rejected: stage A/B against the split
baseline showed `decrypt_inv_tail` average speedup `0.9967x`,
`decrypt_inv_sub_from` average speedup `0.9963x`, and
`decrypt_accum_inv` average speedup `0.9965x`.

A narrow experiment replacing only the forward-NTT `log2len = 4` / length-16
stage with two `ntt_butterfly8_avx2()` calls per block was rejected: AVX2
stage/KEM A/B showed `decrypt_u_ntt` median speedup `0.991x`,
`encrypt_noise_ntt` median speedup `0.990x`, and `roundtrip_core` median
speedup `0.947x`. Future forward-NTT work should therefore redesign scheduling
across multiple stages instead of swapping one scalar/vectorized head level in
isolation.

A branchless modular add/sub experiment was rejected. Replacing
`mod_q_add_i16()` and `mod_q_sub_i16()` with shift-and-mask corrections kept
correctness, but AVX2 NTT microbench A/B against `a403d5f` with `RUNS=11` and
`NTT_ITERS=300000` regressed `mlkem_ntt_head_l7_l4` median speedup to
`0.9600x`, `mlkem_ntt_copy` to `0.9743x`, `mlkem_ntt_inplace` to `0.9804x`,
and `mlkem_ntt_inv` to `0.9871x`. Keep the existing simple conditional form;
clang's generated code is better for the scalar upper NTT stages on this target.

The `sample_ntt4_*` breakdown metrics are diagnostic only and are not emitted on
non-AVX2 builds. `sample_ntt4_full_raw` measures the x4 sampler with a
lightweight sink, while the other breakdown metrics separate state
transpose/store, Keccak+store, and rejection-parse portions so future sampler
redesign work can target the dominant part instead of repeatedly tuning parser
bookkeeping in isolation.

A later AVX2 parser experiment that added a 256-byte accepted-lane popcount
lookup table beside the existing shuffle-index table was rejected. Stage A/B
against `f3e4b81` regressed `sample_ntt4_parse_504` median speedup to `0.9666x`
and `sample_ntt4_full_raw` median speedup to `0.9974x`; keep the in-loop
`POPCNT` operations instead of adding more table loads to the hot parser path.

A follow-up experiment that parsed each 168-byte Keccak rate immediately instead
of first storing the common three-rate 504-byte stream was also rejected. Stage
A/B against `a47d649` showed `sample_ntt4_full_raw` median speedup `0.9625x`,
`sample_matrix_x4_batch0` median speedup `0.9689x`, and `sample_matrix` median
speedup `0.9617x`. Keep the three-rate store-then-parse schedule; interleaving
Keccak output storage and parser work hurts the full x4 sampler even if isolated
store/parse probes look neutral.

The refill counters quantify how often the first three Keccak rates are
insufficient. On one pinned AVX2 diagnostic run with 20,000 iterations, only
3.245% of x4 groups and 0.815% of individual lanes needed a refill after the
first 504 bytes. That keeps the refill path below the primary optimization
target; direct Keccak-state-to-parser work should focus first on the common
three-rate path.

Historical snapshot, pinned to CPU 0, `clang`, `AVX2_BACKEND=core`, `20000`
iterations, before the later core AVX2 and cache optimization series:

| Metric | ns/op |
|---|---:|
| `mlkem_core_stage_kpke_keygen_full` | 5670.29 |
| `mlkem_core_stage_kpke_encrypt_cached` | 2870.28 |
| `mlkem_core_stage_kpke_decrypt_cached` | 1279.13 |
| `mlkem_core_stage_sample_matrix` | 3069.87 |
| `mlkem_core_stage_sample_matrix_x4_batch0` | 1122.83 |
| `mlkem_core_stage_sample_matrix_x4_batch1` | 1353.84 |
| `mlkem_core_stage_sample_matrix_tail` | 825.86 |
| `mlkem_core_stage_keygen_noise_ntt` | 2342.69 |
| `mlkem_core_stage_keygen_noise_prf_cbd` | 898.19 |
| `mlkem_core_stage_keygen_noise_ntt_encode` | 1980.42 |
| `mlkem_core_stage_keygen_accum_encode` | 468.17 |
| `mlkem_core_stage_encrypt_noise` | 1551.44 |
| `mlkem_core_stage_encrypt_noise_prf_cbd` | 1075.85 |
| `mlkem_core_stage_encrypt_noise_ntt` | 1016.90 |
| `mlkem_core_stage_encrypt_accum_inv` | 1510.71 |
| `mlkem_core_stage_ciphertext_compress_encode` | 102.61 |
| `mlkem_core_stage_ciphertext_decode_decompress` | 246.43 |
| `mlkem_core_stage_decrypt_ntt_accum_recover` | 1220.76 |

Current snapshot, pinned to CPU 0, `clang`, default `AVX2_BACKEND=core`,
`20000` iterations, after the current optimization series through `e762218`:

| Metric | ns/op |
|---|---:|
| `mlkem_core_stage_kpke_keygen_full` | 4925.44 |
| `mlkem_core_stage_kpke_encrypt_cached` | 2267.21 |
| `mlkem_core_stage_kpke_decrypt_cached` | 1007.14 |
| `mlkem_core_stage_sample_matrix` | 2945.93 |
| `mlkem_core_stage_sample_matrix_x4_batch0` | 1126.15 |
| `mlkem_core_stage_sample_matrix_x4_batch1` | 1358.90 |
| `mlkem_core_stage_sample_matrix_tail` | 827.42 |
| `mlkem_core_stage_keygen_noise_ntt` | 1896.56 |
| `mlkem_core_stage_keygen_noise_prf_cbd` | 779.87 |
| `mlkem_core_stage_keygen_noise_ntt_encode` | 1676.42 |
| `mlkem_core_stage_keygen_accum_encode` | 454.63 |
| `mlkem_core_stage_encrypt_noise` | 1245.92 |
| `mlkem_core_stage_encrypt_noise_prf_cbd` | 964.22 |
| `mlkem_core_stage_encrypt_noise_ntt` | 830.96 |
| `mlkem_core_stage_encrypt_accum_inv` | 1235.86 |
| `mlkem_core_stage_encrypt_accum_inv_u` | 958.22 |
| `mlkem_core_stage_encrypt_accum_inv_v` | 448.76 |
| `mlkem_core_stage_ciphertext_compress_encode` | 101.66 |
| `mlkem_core_stage_ciphertext_decode_decompress` | 246.68 |
| `mlkem_core_stage_decrypt_ntt_accum_recover` | 920.44 |

The current remaining hotspots are public matrix generation, keygen
noise/NTT/encode, encryption noise generation, and encryption accumulation plus
inverse NTT. Within encryption accumulation, the three `u` paths dominate the
single `v` path, so the next arithmetic work should prioritize reducing repeated
`u`-side accumulation/inverse-NTT-add overhead before targeting `v`.
Compression, bit-packing, and ciphertext decode/decompress remain smaller
contributors.

### Independent Core Local A/B Runner

Use the local A/B runner when testing candidate changes to the independent
`AVX2_BACKEND=core` path. The script builds the baseline ref in a temporary git
worktree, builds the current working tree as the candidate, pins execution when
`PIN_CPU` is set, and reports average and median speedups.

```bash
PIN_CPU=0 RUNS=5 KEM_ITERS=3000 STAGE_ITERS=10000 \
  ./scripts/bench_core_ab.sh dd30d94
```

Limit the run to a specific suite when iterating quickly:

```bash
SUITES=kem RUNS=3 KEM_ITERS=1000 ./scripts/bench_core_ab.sh HEAD
SUITES=stage RUNS=3 STAGE_ITERS=5000 ./scripts/bench_core_ab.sh HEAD
SUITES=ntt,keccak RUNS=3 ./scripts/bench_core_ab.sh HEAD
```

Supported suites are `kem`, `stage`, `ntt`, and `keccak`. Environment variables
`C_COMPILER`, `ARCH_CFLAGS`, `PIN_CPU`, `RUNS`, `WARMUP_RUNS`, `KEM_ITERS`,
`STAGE_ITERS`, `NTT_ITERS`, and `KECCAK_ITERS` control the run. `ARCH_CFLAGS`
is forwarded to both the baseline and candidate builds when set; leave it unset
to use the Makefile default `-march=native`. Use this local A/B output as the
first filter before documenting an optimization as an independent-core speedup.

For example, force an AVX2-only comparison without AVX512 by overriding the
architecture flags for both sides:

```bash
ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" SUITES=stage RUNS=3 \
  STAGE_ITERS=5000 ./scripts/bench_core_ab.sh HEAD
```

### Core-Only No-Cache Comparison Snapshot (2026-06-30)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`,
`LOCAL_ROUNDTRIP_METRIC=mlkem_roundtrip_core_ns_per_op`, `600` iterations and
two repeated runs, median aggregation. This intentionally disables baby-mlkem's
cross-operation caches between keygen, encapsulation, and decapsulation, so it
is a better signal for whether the core implementation itself is competitive.

| Comparator | Local core ns/op | Comparator ns/op | Local speedup |
|---|---:|---:|---:|
| upstream Kyber AVX2 | 21790.18 | 16051.60 | 0.737x |
| upstream Kyber AVX2 fair flags | 21811.80 | 16064.89 | 0.737x |
| mlkem-native | 21921.44 | 25981.47 | 1.185x |
| PQClean AVX2 | 23066.81 | 20182.96 | 0.875x |
| liboqs | 24009.59 | 20633.35 | 0.859x |
| BoringSSL | 23426.60 | 52819.90 | 2.255x |
| libcrux Rust | 24126.27 | 21438.25 | 0.889x |
| libjade Kyber768 AVX2 | 24044.38 | 20959.99 | 0.872x |
| Botan ML-KEM | 24120.10 | 135345.27 | 5.611x |
| OpenSSL ML-KEM | 23525.71 | 47624.24 | 2.024x |

The current honest core-only target is therefore upstream Kyber AVX2/PQClean
AVX2/libjade/libcrux/liboqs, not the cache-assisted `mlkem_roundtrip` result.
The main gap comes from cold encapsulation/decapsulation needing to regenerate or
decode public matrix state rather than reusing `kpke_public_cache_*` across
operations.

### Core-Only No-Cache Verification Snapshot (2026-07-01)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`,
`LOCAL_ROUNDTRIP_METRIC=mlkem_roundtrip_core_ns_per_op`, `STATS_MODE=median`,
`2000` iterations and three repeated runs. This uses the cache-free local
roundtrip metric, so the local result does not rely on repeated-key or
cross-operation caches.

```bash
LOCAL_ROUNDTRIP_METRIC=mlkem_roundtrip_core_ns_per_op STATS_MODE=median \
  WARMUP_RUNS=1 C_COMPILER=clang PIN_CPU=0 \
  ./scripts/verify_world_fastest.sh 2000 3
```

| Comparator | Local speedup | Status |
|---|---:|---|
| upstream Kyber AVX2 | 1.097x | pass |
| upstream Kyber AVX2 fair flags | 1.096x | pass |
| mlkem-native | 1.783x | pass |
| PQClean AVX2 | 1.390x | pass |
| liboqs | 1.405x | pass |
| BoringSSL | 3.576x | pass |
| libcrux Rust | 1.388x | pass |
| libjade Kyber768 AVX2 | 1.436x | pass |
| Botan ML-KEM | 9.145x | pass |
| OpenSSL ML-KEM | 3.239x | pass |

The verifier reported `verify_world_fastest=PASS`; the local mean for the
reference upstream Kyber AVX2 comparison was `14689.88` ns/op. This supersedes
the older 2026-06-30 core-only snapshot above, where the cache-free local path
was still slower than the strongest AVX2 comparators.

### Core-Only No-Cache Strict Verification Snapshot (2026-07-01)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`,
`LOCAL_ROUNDTRIP_METRIC=mlkem_roundtrip_core_ns_per_op`, `STATS_MODE=median`,
`600` iterations and two repeated runs. The strict script first verifies current
comparator checkouts with `UPDATE_REPOS=0`, then verifies latest comparator
updates with `UPDATE_REPOS=1`.

```bash
LOCAL_ROUNDTRIP_METRIC=mlkem_roundtrip_core_ns_per_op STATS_MODE=median \
  WARMUP_RUNS=1 C_COMPILER=clang PIN_CPU=0 SHOW_FULL_OUTPUT_ON_FAIL=0 \
  ./scripts/verify_world_fastest_strict.sh 600 2
```

Current-checkout stage:

| Comparator | Local speedup | Status |
|---|---:|---|
| upstream Kyber AVX2 | 1.094x | pass |
| upstream Kyber AVX2 fair flags | 1.089x | pass |
| mlkem-native | 1.688x | pass |
| PQClean AVX2 | 1.291x | pass |
| liboqs | 1.337x | pass |
| BoringSSL | 3.345x | pass |
| libcrux Rust | 1.427x | pass |
| libjade Kyber768 AVX2 | 1.440x | pass |
| Botan ML-KEM | 8.281x | pass |
| OpenSSL ML-KEM | 3.142x | pass |

Latest-update stage:

| Comparator | Local speedup | Status |
|---|---:|---|
| upstream Kyber AVX2 | 1.088x | pass |
| upstream Kyber AVX2 fair flags | 1.099x | pass |
| mlkem-native | 1.660x | pass |
| PQClean AVX2 | 1.345x | pass |
| liboqs | 1.329x | pass |
| BoringSSL | 3.469x | pass |
| libcrux Rust | 1.327x | pass |
| libjade Kyber768 AVX2 | 1.351x | pass |
| Botan ML-KEM | 9.123x | pass |
| OpenSSL ML-KEM | 3.043x | pass |

The strict verifier reported `verify_world_fastest_strict=PASS`. During the
latest-update stage, several diverged comparator checkouts could not be
fast-forwarded, so the scripts used fallback fresh clones for those comparators
before measuring them.

### Independent Core Optimization A/B (2026-07-01, no-cache encaps public work co-scheduling)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`. Baseline is
commit `3ff66d0` before co-scheduling no-cache encapsulation public-key work;
candidate is the working tree after the change. This is a core-vs-core
comparison and does not use the vendored Kyber/PQClean AVX2 backends for the
candidate path.

Native KEM A/B, `14000` iterations, seventeen repeated runs:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_keygen_core` | 5333.11 | 5338.78 | 0.999x | 0.998x |
| `mlkem_encaps_core` | 5437.64 | 4893.75 | 1.111x | 1.111x |
| `mlkem_decaps_core` | 4616.40 | 4635.70 | 0.996x | 0.998x |
| `mlkem_roundtrip_core` | 15462.58 | 14935.00 | 1.035x | 1.036x |

AVX2-only KEM A/B, `10000` iterations, thirteen repeated runs, with
`ARCH_CFLAGS='-mavx2 -mbmi2 -mpopcnt'`:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_encaps_core` | 10040.30 | 8993.11 | 1.116x | 1.075x |
| `mlkem_decaps_core` | 8674.56 | 8651.89 | 1.003x | 1.008x |
| `mlkem_roundtrip_core` | 28362.29 | 27305.01 | 1.039x | 1.061x |

The change keeps the core path vendor-free and does not add any cross-operation
cache. When internal caches are disabled, `mlkem_encaps()` now prepares the
public key once, then calls the K-PKE arithmetic body directly. The final public
matrix entry `(2,2)` is sampled with `keccakf4()` while lane 0 simultaneously
runs the first three SHA3-256 public-key-hash permutations for `H(ek)`. The
remaining public-key hash blocks continue through the scalar SHA3-256 state.
This removes three scalar Keccak permutations from cold/no-cache encapsulation
without reusing data across benchmark iterations or across KEM operations.

The stage microbench remained median-flat (`mlkem_core_stage_kpke_encrypt_uncached`
median speedup `0.999x`, `mlkem_core_stage_sample_matrix` median speedup
`1.002x`), which is expected: the optimization targets the full KEM no-cache
encapsulation sequence, not standalone `kpke_encrypt()`.

### Independent Core Optimization A/B (2026-07-01, no-cache decaps public work co-scheduling)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`. Baseline is
commit `053f37d` before co-scheduling no-cache decapsulation re-encryption public
work; candidate is the working tree after the change. This is a core-vs-core
comparison and does not use the vendored Kyber/PQClean AVX2 backends for the
candidate path.

Native KEM A/B, `14000` iterations, seventeen repeated runs:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_encaps_core` | 4888.77 | 4907.48 | 0.996x | 1.001x |
| `mlkem_decaps_core` | 4609.12 | 4431.97 | 1.040x | 1.039x |
| `mlkem_roundtrip_core` | 14950.21 | 14789.43 | 1.011x | 1.012x |

AVX2-only KEM A/B, `14000` iterations, seventeen repeated runs, with
`ARCH_CFLAGS='-mavx2 -mbmi2 -mpopcnt'`:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_encaps_core` | 9070.99 | 8904.15 | 1.019x | 0.998x |
| `mlkem_decaps_core` | 8924.69 | 8422.83 | 1.060x | 1.027x |
| `mlkem_roundtrip_core` | 27525.70 | 26590.89 | 1.035x | 1.043x |

The change keeps the core path vendor-free and does not add any cross-operation
cache. When internal caches are disabled, `mlkem_decaps()` now prepares the
public key for the re-encryption check before calling the K-PKE arithmetic body.
The final public matrix entry `(2,2)` is sampled with `keccakf4()` while lane 0
simultaneously computes the fixed `sha3_512(mdash || h)` permutation used to
produce `kdash || rdash`. This removes one scalar Keccak permutation from
cold/no-cache decapsulation and avoids a second public-key preparation pass
inside `kpke_encrypt()`.

### Independent Core Optimization A/B (2026-07-01, AVX512 message recovery)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`. Baseline is
commit `4bd110b` before the AVX512 message recovery path; candidate is commit
`8d8c888` after the change. This is a core-vs-core comparison and does not use
the vendored Kyber/PQClean AVX2 backends for the candidate path.

The implementation keeps the core path vendor-free and does not add any
cross-operation cache. On native AVX512BW-capable builds,
`mlkem_recover_message()` now compares 32 coefficients at a time and writes the
resulting AVX512 mask directly as four message bytes. This replaces the native
path's previous AVX2 `movemask + pext` sequence over 16 coefficients at a time.
AVX2-only and non-AVX2 builds keep the previous code path.

Native focused stage A/B command:

```bash
RUNS=17 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=180000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh 4bd110b
```

Stage A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_decrypt_ntt_accum_recover` | 758.86 | 757.71 | 1.002x | 1.002x |
| `mlkem_core_stage_kpke_decrypt_cached` | 829.35 | 827.98 | 1.002x | 1.001x |
| `mlkem_core_stage_kpke_decrypt_uncached` | 836.28 | 834.22 | 1.002x | 1.002x |

Native stage/KEM A/B command:

```bash
RUNS=15 WARMUP_RUNS=2 SUITES=stage,kem STAGE_ITERS=90000 KEM_ITERS=18000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh 4bd110b
```

KEM A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_decaps` | 2951.24 | 2944.41 | 1.002x | 1.002x |
| `mlkem_decaps_core` | 4443.15 | 4442.35 | 1.000x | 1.000x |
| `mlkem_roundtrip` | 10354.85 | 10354.44 | 1.000x | 1.001x |
| `mlkem_roundtrip_core` | 14709.91 | 14707.68 | 1.000x | 0.999x |

The effect is intentionally described as small and local: message recovery is
only the tail of K-PKE decrypt, so full KEM movement is near benchmark noise.
The focused decrypt stage is the defensible signal for this change.

### Independent Core Optimization A/B (2026-07-01, AVX2 message recovery without BMI2 pext)

Baseline is commit `021c6f7` before replacing the AVX2 message recovery bit
packing; candidate is the working tree after changing `mlkem_recover_message()`
from BMI2 `_pext_u32(movemask, 0x55555555)` to `packs_epi16 + movemask` bit
collection. This is a core implementation change and does not call vendored
Kyber/PQClean code.

The AVX2 path still compares sixteen 16-bit coefficients at a time. Instead of
extracting one bit from each 16-bit comparison result with BMI2 `pext`, it packs
the sixteen comparison words to one byte per coefficient, takes a byte movemask,
and combines the low and high 128-bit halves. This removes the BMI2 dependency
from the AVX2 message recovery path and avoids `pext` on CPUs where it is not a
cheap operation. AVX512BW builds keep the existing 32-coefficient mask path.

Correctness checks:

```bash
make clean CC=clang AVX2_BACKEND=core && \
make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"

make clean CC=clang AVX2_BACKEND=core && \
make test CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-mavx2 -mno-bmi2 -mno-avx512f -mno-avx512bw"
```

A temporary checker also compared `mlkem_recover_message()` against the scalar
reference on 10,000 random polynomials.

AVX2-only stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=60000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

Stage A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_decrypt_recover_message` | 6.03 | 5.86 | 1.028x | 1.029x |
| `mlkem_core_stage_decrypt_ntt_accum_recover` | 895.96 | 889.17 | 1.008x | 1.008x |
| `mlkem_core_stage_kpke_decrypt_cached` | 927.00 | 927.53 | 0.999x | 0.999x |
| `mlkem_core_stage_kpke_decrypt_uncached` | 941.23 | 941.15 | 1.000x | 1.000x |

AVX2-only KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=kem KEM_ITERS=50000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

KEM A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_decaps` | 4140.10 | 3968.62 | 1.043x | 1.001x |
| `mlkem_decaps_core` | 8221.44 | 7918.79 | 1.038x | 1.106x |
| `mlkem_roundtrip_core` | 26458.26 | 26546.22 | 0.997x | 0.952x |

Treat the focused decrypt stage as the acceptance signal. The KEM run was noisy:
keygen and encaps rows, which do not execute message recovery, moved
substantially, so the roundtrip rows are not a clean signal for this narrow
decrypt-tail change.

### Independent Core Optimization A/B (2026-07-01, AVX2 message recovery 32-lane pack)

A follow-up AVX2 message recovery experiment packing two 16-coefficient compare
vectors at once was rejected. The candidate used `_mm256_packs_epi16(m0, m1)`
to produce a 32-bit movemask for 32 coefficients, then swapped the middle two
bytes because AVX2 packs operate independently in each 128-bit lane. It passed
AVX2 `make test`, AVX2 no-BMI2 `make test`, and a temporary 10,000-random-input
scalar reference checker, but it was slower than the accepted 16-coefficient
`packs_epi16 + movemask` path.

AVX2-only stage A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage STAGE_ITERS=100000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

Stage A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_decrypt_recover_message` | 5.97 | 6.04 | 0.989x | 0.980x |
| `mlkem_core_stage_decrypt_ntt_accum_recover` | 890.31 | 894.10 | 0.996x | 0.996x |
| `mlkem_core_stage_kpke_decrypt_cached` | 928.53 | 928.62 | 1.000x | 0.999x |
| `mlkem_core_stage_kpke_decrypt_uncached` | 943.39 | 941.95 | 1.002x | 1.001x |

Keep the accepted 16-coefficient AVX2 message recovery packer. The 32-coefficient
shape halves the loop count, but the AVX2 lane-local pack ordering forces extra
byte rearrangement work and loses in the direct recover-message stage.

### Independent Core Optimization A/B (2026-07-01, AVX512 PRF/CBD lane extraction)

An AVX512 PRF/CBD decode experiment replacing the local `uint64_t words[8]`
store/reload in `sample_poly_cbd_eta2x6_state_avx512()` and
`sample_poly_cbd_eta2x7_state_avx512()` with direct `_mm512_castsi512_si128()` /
`_mm512_extracti32x4_epi32()` lane-pair extraction was rejected. The intent was
to remove a stack round-trip in the native AVX512 keygen/encryption PRF/CBD
path, matching the data-movement reductions that helped earlier x4 PRF/CBD and
sample-matrix work.

The candidate passed native `make test`, AVX2-only `make test`, and
`git diff --check`, but the direct PRF/CBD stage movement was noise-sized.

Native stage A/B command:

```bash
RUNS=11 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

Stage A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_noise_prf_cbd` | 699.28 | 696.24 | 1.004x | 1.000x |
| `mlkem_core_stage_encrypt_noise_prf_cbd` | 878.59 | 878.09 | 1.001x | 1.000x |
| `mlkem_core_stage_keygen_noise_ntt` | 1569.68 | 1566.93 | 1.002x | 1.000x |
| `mlkem_core_stage_encrypt_noise` | 1026.32 | 1025.62 | 1.001x | 1.002x |

Keep the current store/reload shape in the AVX512 x6/x7 PRF/CBD decoders. The
compiler and memory pipeline already handle this small local temporary well
enough that explicit extraction does not produce a defensible integrated win.

### Independent Core Optimization A/B (2026-07-01, keygen add/encode fusion)

Two keygen `that = A^T*s + e` fusion experiments were rejected. Both were aimed
at removing or combining the separate `ntt_add()` pass before d12 public-key
encoding, without changing the independent core arithmetic or using a vendored
backend.

The first variant added `ehat` inside the scalar `ntt_mul_acc3_factored_gamma()`
loop. It passed native and AVX2-only `make test`, but it moved the modular add
onto the scalar multiply/reduction critical path and lost clearly. The existing
separate `ntt_add()` pass is cheap because it uses AVX2 16-bit vector add/sub.

AVX2-only stage A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage STAGE_ITERS=90000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected scalar-add highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_accum_encode` | 488.51 | 510.17 | 0.958x | 0.957x |
| `mlkem_core_stage_kpke_keygen_full` | 6817.79 | 6827.96 | 0.999x | 0.997x |

The second variant kept the add vectorized and fused `ntt_add()` with the d12
AVX2 encoder pass, storing the canonical `that` coefficients and emitting the
encoded public-key bytes from the same loaded vectors. This avoided the scalar
critical-path problem and showed a very small direct stage win, but the effect
was too small and the KEM confirmation did not give a clean no-regression signal.

AVX2-only stage confirmation command:

```bash
RUNS=11 WARMUP_RUNS=3 SUITES=stage STAGE_ITERS=160000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

Vector add/encode stage highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_accum_encode` | 487.90 | 486.43 | 1.003x | 1.005x |
| `mlkem_core_stage_keygen_noise_ntt_encode` | 1604.23 | 1604.42 | 1.000x | 1.001x |

KEM no-regression command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=kem KEM_ITERS=30000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

KEM highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_keygen` | 8757.35 | 8995.55 | 0.974x | 0.995x |
| `mlkem_keygen_core` | 8737.80 | 8994.42 | 0.972x | 0.979x |
| `mlkem_encaps` | 3018.11 | 3035.37 | 0.994x | 0.999x |
| `mlkem_roundtrip_core` | 26072.20 | 26745.64 | 0.975x | 1.011x |

Keep the existing `ntt_mul_acc3_factored_gamma()` plus separate `ntt_add()` and
`byte_encode_d12_avx2()` sequence. The scalar-add fusion is directly slower, and
the vector add/encode fusion is only a sub-percent local stage improvement with
weak KEM evidence, so the extra code path is not worth carrying.

### Independent Core Optimization A/B (2026-07-01, ciphertext compress/pack fusion)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`. Baseline is
commit `4adb1f0` before ciphertext compress/pack fusion; candidate is the
working tree after the change. This is a core-vs-core comparison and does not
use the vendored Kyber/PQClean AVX2 backends for the candidate path.

The implementation follows the same broad idea used by the public
PQ-Crystals Kyber AVX2 code: compress the ciphertext coefficients and bit-pack
those small residues in one vectorized pass instead of materializing a
`uint16_t` intermediate and then calling a scalar byte encoder. Reference:
`https://github.com/pq-crystals/kyber/tree/main/avx2`.

Native stage/KEM A/B command:

```bash
RUNS=9 WARMUP_RUNS=1 SUITES=stage,kem STAGE_ITERS=50000 KEM_ITERS=12000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

Stage A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_ciphertext_compress_encode` | 67.37 | 53.51 | 1.259x | 1.258x |
| `mlkem_core_stage_kpke_encrypt_cached` | 1921.09 | 1921.71 | 1.000x | 1.003x |
| `mlkem_core_stage_kpke_encrypt_uncached` | 3656.03 | 3658.24 | 0.999x | 1.003x |

KEM A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_encaps` | 2128.61 | 2124.09 | 1.002x | 1.002x |
| `mlkem_encaps_core` | 4912.82 | 4937.08 | 0.995x | 1.001x |
| `mlkem_roundtrip` | 10443.00 | 10383.41 | 1.006x | 1.003x |
| `mlkem_roundtrip_core` | 14760.44 | 14739.01 | 1.001x | 1.000x |

The original effect was intentionally described as local: ciphertext
compress/encode was about 25% faster on the native AVX512-capable core build,
while full KEM impact was small because this stage is a small fraction of
encapsulation.

Additional AVX2-only A/B after fixing `ARCH_CFLAGS` forwarding showed that the
same fused compress/pack path is also useful without AVX512. Baseline is commit
`ab346f1` before enabling the fused packer for AVX2-only builds; candidate is
the working tree after the change.

AVX2-only stage/KEM A/B command:

```bash
RUNS=11 WARMUP_RUNS=2 SUITES=stage,kem STAGE_ITERS=50000 KEM_ITERS=10000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

AVX2-only highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_ciphertext_compress_encode` | 208.52 | 56.27 | 3.706x | 3.701x |
| `mlkem_encaps` | 3206.78 | 3108.28 | 1.032x | 1.053x |
| `mlkem_encaps_core` | 9021.32 | 8659.20 | 1.042x | 1.017x |
| `mlkem_roundtrip` | 17121.61 | 16673.88 | 1.027x | 1.034x |
| `mlkem_roundtrip_core` | 27085.22 | 26406.50 | 1.026x | 1.037x |

The implementation now enables `compress_encode_poly_d10_avx2()` and
`compress_encode_poly_d4_avx2()` for all AVX2 core builds. Non-AVX2 builds keep
the scalar `compress_poly()` plus `byte_encode_u16()` path.

### Independent Core Optimization A/B (2026-07-01, AVX2 d4 decode/decompress)

Baseline is commit `6cabe0a` before adding the AVX2 `d = 4` ciphertext
decode/decompress path; candidate is the working tree after the change. This is
a core implementation change and does not call an external backend.

The implementation adds `decompress_decode_poly_d4_avx2()`, which unpacks the
128-byte `DV = 4` ciphertext component as 16 bytes to 32 coefficients per loop
and applies `((v * Q + 8) >> 4)` with AVX2 16-bit operations. The `DU = 10`
path still kept the existing scalar code at that point; non-AVX2 builds
keep the scalar code.

AVX2-only stage command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage STAGE_ITERS=100000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

Stage A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_ciphertext_decode_decompress` | 374.46 | 366.31 | 1.022x | 1.021x |
| `mlkem_core_stage_kpke_decrypt_cached` | 1081.60 | 1074.92 | 1.006x | 1.006x |
| `mlkem_core_stage_kpke_decrypt_uncached` | 1096.96 | 1094.17 | 1.003x | 1.006x |

KEM-only confirmation command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=kem KEM_ITERS=30000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

KEM A/B was noisier, as expected for an 8 ns local stage win inside full
decapsulation. The run showed `mlkem_roundtrip_core` median speedup `1.011x`
and `mlkem_decaps` median speedup `0.998x`; treat the local
`ciphertext_decode_decompress` row as the defensible signal for this change.

### Independent Core Optimization A/B (2026-07-01, AVX2 d10 decode/decompress)

Baseline is commit `727824c` after the AVX2 `d = 4` ciphertext
decode/decompress path; candidate is the working tree after adding the AVX2
`d = 10` path. This is a core implementation change and does not call an
external backend.

The implementation adds `decompress_decode_poly_d10_avx2()`. It unpacks the
320-byte `DU = 10` ciphertext component as two independent 10-byte groups per
AVX2 register, forms sixteen 10-bit coefficients per loop, and widens to
32-bit lanes for the exact `((v * Q + 512) >> 10)` decompression. The
initial version kept the final 16 coefficients in the scalar decode shape to
avoid an out-of-bounds vector load; the follow-up section below removes that
tail. A temporary checker compared 10,000 random 320-byte inputs against the
scalar reference and matched exactly.

AVX2-only stage command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage STAGE_ITERS=100000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

Stage A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_ciphertext_decode_decompress` | 366.89 | 272.43 | 1.347x | 1.347x |
| `mlkem_core_stage_kpke_decrypt_cached` | 1078.45 | 982.06 | 1.098x | 1.097x |
| `mlkem_core_stage_kpke_decrypt_uncached` | 1093.26 | 994.98 | 1.099x | 1.097x |

KEM-only confirmation command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=kem KEM_ITERS=30000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

KEM A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_decaps` | 4174.98 | 4076.31 | 1.024x | 1.023x |
| `mlkem_decaps_core` | 8515.75 | 8394.79 | 1.014x | 1.013x |
| `mlkem_roundtrip_core` | 26923.66 | 26845.55 | 1.003x | 1.015x |

This is a real decrypt-side win because ciphertext decode/decompress is on the
`kpke_decrypt()` path. Encapsulation rows from the same KEM run moved with
benchmark noise and are not attributed to this change.

### Independent Core Optimization A/B (2026-07-01, AVX2 d10 tail decode/decompress)

Baseline is commit `2dc49be` with the AVX2 `d = 10` decode/decompress path and
a scalar final 16-coefficient tail; candidate is the working tree after building
that final 20-byte input segment as one AVX2 block without reading past the
ciphertext buffer. This is a core implementation change and does not call an
external backend.

The tail path loads the first final 10-byte group with a normal 128-bit load,
builds the second final 10-byte group from an 8-byte load plus the last two
bytes, and then reuses the same shuffle/blend/widen/decompress sequence as the
main AVX2 loop. A temporary checker again compared 10,000 random 320-byte
inputs against the scalar reference and matched exactly.

AVX2-only stage command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage STAGE_ITERS=120000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

Stage A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_ciphertext_decode_decompress` | 272.46 | 256.67 | 1.062x | 1.066x |
| `mlkem_core_stage_kpke_decrypt_cached` | 983.33 | 962.79 | 1.021x | 1.021x |
| `mlkem_core_stage_kpke_decrypt_uncached` | 995.83 | 979.92 | 1.016x | 1.017x |

Longer KEM-only confirmation command:

```bash
RUNS=17 WARMUP_RUNS=4 SUITES=kem KEM_ITERS=40000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

KEM A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_decaps` | 4101.43 | 4075.27 | 1.006x | 1.003x |
| `mlkem_decaps_core` | 8519.68 | 8149.94 | 1.045x | 1.057x |
| `mlkem_roundtrip_core` | 26417.05 | 26045.13 | 1.014x | 1.023x |

The defensible effect is still the local decode/decompress stage. Full KEM
rows are noisier, but the longer confirmation did not show a decrypt-side
regression and the roundtrip core row moved in the same direction.

A follow-up experiment that collapsed the two 8-lane decompression helper calls
into one 16-lane helper and one 256-bit store while keeping the widened 32-bit
multiply was rejected. AVX2 stage A/B
against `233bac2` with `RUNS=13` and `STAGE_ITERS=120000` regressed
`mlkem_core_stage_ciphertext_decode_decompress` median speedup to `0.9853x` and
`mlkem_core_stage_kpke_decrypt_cached` to `0.9998x`. Keep the two 8-lane helper
calls; the compiler schedules that shape better than the wider packed helper on
this target.

### Independent Core Optimization A/B (2026-07-01, AVX2 d10 mulhrs decompress)

Baseline is commit `3dc14d6` with the accepted AVX2 `d = 10` tail path and the
rejected widened-helper experiment reverted; candidate is the working tree after
rewriting the `DU = 10` decompression arithmetic to stay in 16-bit lanes. This
is a core implementation change and does not call an external backend.

The implementation uses the exact identity
`((3329 * v + 512) >> 10) = 3*v + ((257*v + 512) >> 10)` for each 10-bit
coefficient. The second term is computed as `_mm256_mulhrs_epi16(v, 8224)`,
because `(v * 8224 + 16384) >> 15` equals `((257*v + 512) >> 10)` for
`0 <= v < 1024`. This removes the previous 16-bit-to-32-bit widening and
32-bit multiply from the d10 decode/decompress path. A temporary checker
compared 10,000 random 320-byte inputs against the scalar reference and also
checked the identity for all `v = 0..1023`.

AVX2-only stage command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage STAGE_ITERS=120000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

Stage A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_ciphertext_decode_decompress` | 255.71 | 220.75 | 1.158x | 1.157x |
| `mlkem_core_stage_kpke_decrypt_cached` | 964.59 | 926.53 | 1.041x | 1.040x |
| `mlkem_core_stage_kpke_decrypt_uncached` | 979.10 | 942.03 | 1.039x | 1.038x |

KEM-only confirmation command:

```bash
RUNS=13 WARMUP_RUNS=4 SUITES=kem KEM_ITERS=50000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

KEM A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_decaps` | 4099.62 | 4047.34 | 1.013x | 1.008x |
| `mlkem_decaps_core` | 8555.93 | 8186.83 | 1.045x | 1.055x |
| `mlkem_roundtrip_core` | 27003.70 | 25812.84 | 1.046x | 1.031x |

Unlike the rejected widened 16-lane helper above, this change is useful because
it removes the expensive 32-bit arithmetic rather than merely repacking it.

A follow-up decrypt scheduling experiment that ran `ntt(u[i], u[i])` immediately
after each `DU = 10` decode/decompress was rejected. The intent was to consume
freshly written `u` coefficients while they were still hot, but AVX2 stage A/B
against `c2acb8a` with `RUNS=13` and `STAGE_ITERS=100000` regressed
`mlkem_core_stage_kpke_decrypt_cached` median speedup to `0.9957x` and
`mlkem_core_stage_kpke_decrypt_uncached` to `0.9963x`. Keep the existing decrypt
schedule: decode the full ciphertext, parse/cache the secret key, then transform
the three `u` polynomials in place before accumulation.

A `DV = 4` decompression rewrite using the exact identity
`((3329*v + 8) >> 4) = 208*v + (v >> 3)` for `v = 0..15` was also rejected.
Replacing the AVX2 `mullo/add/shift` helper with shift/add arithmetic kept
correctness, but stage A/B against `6dffcfd` with `RUNS=13` and
`STAGE_ITERS=120000` showed `mlkem_core_stage_ciphertext_decode_decompress`
median speedup only `1.0005x`, `kpke_decrypt_cached` `0.9997x`, and
`kpke_decrypt_uncached` `0.9991x`. Keep the compact 16-bit multiply for d4;
removing that multiply adds enough shift/add work to cancel the benefit.

A stronger `DV = 4` fusion experiment that skipped materializing `v` and
decoded the compressed c2 bytes inside the AVX2 inverse final subtraction was
rejected. It kept correctness, but stage A/B against `f8bc443` with `RUNS=13`
and `STAGE_ITERS=100000` regressed `mlkem_core_stage_kpke_decrypt_cached`
median speedup to `0.9820x`, `kpke_decrypt_uncached` to `0.9875x`, and
`decrypt_inv_sub_from` to `0.9855x`. The extra nibble decode and decompression
uops in the already-hot inverse final loop cost more than the separate `v`
materialization pass saves.

A 12-bit key byte-encoding experiment that packed four coefficients into a
48-bit word and stored six bytes with `memcpy()` was rejected. It matched the
old scalar byte encoder on 10,000 random inputs, but stage A/B against
`c5494c7` with `RUNS=13` and `STAGE_ITERS=100000` regressed
`mlkem_core_stage_keygen_accum_encode` median speedup to `0.9113x`,
`mlkem_core_stage_keygen_noise_ntt_encode` to `0.9703x`, and
`kpke_keygen_full` to `0.9782x`. Keep the current simple 12-bit pair encoder;
the compiler emits a better store sequence than the 48-bit helper here.

### Independent Core Optimization A/B (2026-07-01, AVX2 d12 key encode)

Baseline is commit `3a884e4` with the rejected d12 decode-tail experiment only
documented; candidate is the working tree after adding a core AVX2
`byte_encode_d12_avx2()` path for `byte_encode(12)`. This is an independent
core implementation change: it does not call the vendored Kyber or PQClean AVX2
backend.

The implementation packs sixteen 12-bit coefficients at a time. `_mm256_madd_epi16`
forms each adjacent coefficient pair as a 24-bit little-endian word
`v0 + 4096*v1`, then `_mm256_shuffle_epi8` drops the unused fourth byte from
each 32-bit lane. Each 128-bit half is stored as twelve bytes. This differs from
the rejected scalar 48-bit helper above: the useful work is done by vector pair
packing and byte shuffle, not by constructing wider scalar words.

Correctness checks:

```bash
make clean CC=clang AVX2_BACKEND=core && \
make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"

make clean CC=clang AVX2_BACKEND=core && \
make test CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-mno-avx2 -mno-avx512f -mno-avx512bw -mno-bmi2"
```

A temporary checker also compared the AVX2 encoder against the old scalar
encoder on 10,000 random input polynomials.

AVX2-only stage command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage STAGE_ITERS=100000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

Stage A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_accum_encode` | 514.65 | 488.03 | 1.055x | 1.055x |
| `mlkem_core_stage_keygen_noise_ntt_encode` | 1621.14 | 1605.98 | 1.009x | 1.010x |
| `mlkem_core_stage_kpke_decrypt_cached` | 927.04 | 926.43 | 1.001x | 1.001x |
| `mlkem_core_stage_kpke_decrypt_uncached` | 942.97 | 940.69 | 1.002x | 1.003x |

KEM confirmation command:

```bash
RUNS=17 WARMUP_RUNS=4 SUITES=kem KEM_ITERS=40000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

KEM A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_keygen` | 8996.19 | 9123.83 | 0.986x | 1.008x |
| `mlkem_keygen_core` | 8969.77 | 9079.55 | 0.988x | 1.003x |
| `mlkem_roundtrip_core` | 26276.45 | 26849.39 | 0.979x | 0.962x |

Treat this as a narrow key-encoding win, not as an end-to-end KEM speedup claim:
the full KEM rows are dominated by unrelated sampling/encapsulation/decapsulation
noise, and the roundtrip core row moved opposite to the isolated keygen encode
rows.

### Independent Core Optimization A/B (2026-07-01, NTT accumulation reciprocal reduction)

A follow-up attempt to replace the remaining 32-bit `% Q` operations in
`ntt_mul_acc3()` and `ntt_mul_acc3_factored_gamma()` was rejected. The first
variant tried to reuse `mod_q_reduce_ntt_u32()` on three-product accumulator
ranges and failed correctness because that reducer relies on the `x * 315u`
product not overflowing 32 bits; it is safe for single `Q^2` products, not for
three-product sums.

The safe variant used a 64-bit reciprocal reducer with
`mu = floor(2^32 / 3329) = 1290167`, verified by a temporary C checker against
`x % 3329` for all `x <= 100000000`. It passed AVX2 `make test` and the
`bench_ntt` correctness smoke test, but it was slower than clang's existing
constant-modulo lowering for this hot loop.

AVX2-only NTT A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=ntt NTT_ITERS=200000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

NTT A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_ntt_mul_acc3` | 87.98 | 91.64 | 0.960x | 0.959x |
| `mlkem_ntt_mul_acc3_factored` | 88.33 | 92.07 | 0.959x | 0.960x |
| `mlkem_ntt_copy` | 198.86 | 199.44 | 0.997x | 0.999x |
| `mlkem_ntt_inplace` | 196.33 | 197.00 | 0.997x | 0.999x |

Keep the compiler-generated 32-bit `% Q` in the K=3 NTT accumulation helpers.
The reciprocal-reduction idea is useful for ranges where it avoids actual
division or 64-bit modulo, but here it adds a 64-bit multiply on the critical
path and loses about four percent in the direct helper microbench.

### Independent Core Optimization A/B (2026-07-01, Keccak theta ternary XOR)

A Keccak vector-permutation experiment replacing the five-input Theta column
parity XOR trees in `keccakf4()` and `keccakf8()` with two AVX512
`vpternlog` three-input XOR operations was rejected. This follows a common
SIMD/zkp-style idea of collapsing boolean networks into ternary logic, but on
this implementation the added ternary operations did not schedule better than
the existing XOR tree.

The combined `keccakf4()`/`keccakf8()` variant passed native and AVX2-only
`make test`, but native Keccak A/B showed the direct x4 permutation regressed:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=keccak KECCAK_ITERS=200000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_keccakf4` | 163.03 | 165.54 | 0.985x | 0.985x |
| `mlkem_prf_eta2` | 187.57 | 187.70 | 0.999x | 1.001x |
| `mlkem_sample_ntt_full` | 590.41 | 589.36 | 1.002x | 1.000x |

A narrower `keccakf8()`-only variant also passed native `make test`, but native
stage A/B did not show a useful AVX512 x8 sampler/PRF win:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=60000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_noise_prf_cbd` | 696.02 | 700.23 | 0.994x | 0.994x |
| `mlkem_core_stage_encrypt_noise_prf_cbd` | 886.16 | 884.35 | 1.002x | 0.993x |
| `mlkem_core_stage_sample_matrix` | 1887.22 | 1889.45 | 0.999x | 0.997x |
| `mlkem_core_stage_sample_ntt4_full_raw` | 607.50 | 603.81 | 1.006x | 1.001x |

Keep the explicit XOR trees in the Keccak Theta step. `vpternlog` remains useful
for Chi (`x ^ (~y & z)`), where the implementation already uses it when
available, but replacing parity XORs with ternary logic loses on this target.

### Independent Core Optimization A/B (2026-07-01, sample_ntt4_one lane extraction)

A narrow AVX2 `sample_ntt4_one()` experiment replacing the per-state-word
`uint64_t words[4]` store with direct `keccak_lane0_u64()` extraction was
rejected. The idea was to avoid a 256-bit store plus scalar reload when building
the `(2,2)` public-matrix tail stream, similar to lane-extraction cleanups used
in other SIMD crypto code. It passed native and AVX2-only `make test`, but the
focused stage A/B did not show a useful integrated win.

AVX2-only stage A/B command:

```bash
RUNS=17 WARMUP_RUNS=3 SUITES=stage STAGE_ITERS=90000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

Stage A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_matrix_tail` | 1648.34 | 1561.51 | 1.056x | 1.001x |
| `mlkem_core_stage_sample_matrix` | 4854.93 | 4700.32 | 1.033x | 1.000x |
| `mlkem_core_stage_sample_ntt4_full_raw` | 1546.02 | 1512.57 | 1.022x | 1.002x |
| `mlkem_core_stage_kpke_keygen_full` | 6830.99 | 6930.13 | 0.986x | 0.981x |

Keep the current local `words[4]` extraction in `sample_ntt4_one()`. The direct
extract form is cleaner, but the measured tail improvement is only noise-sized
and the full keygen stage moved the wrong way.

### Independent Core Optimization A/B (2026-07-01, AVX2 NTT accumulation helper)

An AVX2 `ntt_mul_acc3_avx2()` experiment processing four base-pairs at a time
was rejected. The design reduced each single 16-bit product with the existing
vector `mod_q_reduce_ntt_u32x8()` before adding terms, so it avoided the unsafe
wide-accumulator range that broke the earlier reciprocal-reduction attempt. It
passed AVX2 `make test` and the `bench_ntt` correctness smoke test against the
three-pass `ntt_mul_add()` reference.

The problem was instruction count: reducing each single product separately adds
far more vector multiplies, reductions, shuffles, and packs than the current
scalar helper's clang-lowered constant modulo.

AVX2-only NTT A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=ntt NTT_ITERS=200000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

NTT A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_ntt_mul_acc3` | 105.57 | 212.62 | 0.497x | 0.424x |
| `mlkem_ntt_mul_acc3_factored` | 105.73 | 212.35 | 0.498x | 0.426x |
| `mlkem_ntt_copy` | 198.89 | 198.96 | 1.000x | 1.001x |
| `mlkem_ntt_inplace` | 196.32 | 196.58 | 0.999x | 0.999x |

Keep the scalar K=3 NTT accumulation helper. A useful AVX2 rewrite would need a
Harvey/Montgomery-style layout that reduces the number of modular reductions,
not merely vectorizes every individual product.

A narrow AVX2 `byte_decode_d12_avx2()` tail experiment replacing the existing
`_mm256_maskload_epi32()` with explicit 16-byte plus 8-byte loads was rejected.
It matched the scalar decoder on 10,000 random inputs, but stage A/B against
`22cc78d` with `RUNS=13` and `STAGE_ITERS=100000` showed no reliable integrated
win: `kpke_decrypt_uncached` median speedup was `0.9996x`,
`kpke_decrypt_cached` was `1.0003x`, and the large `kpke_encrypt_uncached`
movement was dominated by sample-matrix noise. Keep the existing maskload tail
until a direct d12-decode microbench proves otherwise.

### Independent Core Optimization A/B (2026-07-01, AVX2 sample_ntt4 static stream scratch)

Baseline is commit `6c63b52` before moving the AVX2 x4 sampler stream scratch;
candidate keeps the same sampler logic but stores the 4x504-byte temporary
stream in static scratch instead of per-call stack storage. This is a core
implementation change, not a cache or external-backend optimization.

AVX2-only stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=2 SUITES=stage,kem STAGE_ITERS=50000 KEM_ITERS=12000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

| Metric | Baseline median ns/op | Candidate median ns/op | Median speedup |
|---|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_full_raw` | 1352.73 | 1350.67 | 1.002x |
| `mlkem_core_stage_sample_matrix` | 4675.75 | 4258.40 | 1.098x |
| `mlkem_core_stage_kpke_keygen_full` | 6747.60 | 6732.75 | 1.002x |
| `mlkem_keygen_core` | 9671.07 | 9396.98 | 1.029x |
| `mlkem_roundtrip_core` | 26367.66 | 26161.21 | 1.008x |

KEM-only confirmation command:

```bash
RUNS=17 WARMUP_RUNS=2 SUITES=kem KEM_ITERS=16000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

| Metric | Baseline median ns/op | Candidate median ns/op | Median speedup |
|---|---:|---:|---:|
| `mlkem_keygen_core` | 9419.45 | 8854.80 | 1.064x |
| `mlkem_decaps_core` | 8393.26 | 7858.29 | 1.068x |
| `mlkem_roundtrip_core` | 27283.58 | 26046.08 | 1.048x |

The direct x4 sampler body only moves slightly, but removing the large per-call
stack scratch stabilizes the surrounding keygen/roundtrip core path on AVX2-only
builds.

A later narrow experiment that reused `sample_ntt4_store_last()` for the final
8-byte word of each x4 lane was rejected. Stage A/B against `6660169` showed the
direct `sample_ntt4_store_rate` median speedup regressed to `0.9948x` and
`sample_ntt4_keccak_store3` median speedup regressed to `0.9985x`; keep the
existing local `last[4]` store in `sample_ntt4_store_rate()`.

### Independent Core Optimization A/B (2026-07-01, AVX512 forward NTT tail l2)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`. Baseline is
commit `e5df22b` before widening the forward NTT tail l2 butterfly; candidate is
the working tree after the AVX512 l2 change. This is a core-vs-core comparison
and does not use the vendored Kyber/PQClean AVX2 backends for the candidate
path.

The implementation keeps the core path vendor-free and does not add any
cross-operation cache. On native AVX512BW-capable builds, `ntt_tail_avx2()` now
processes two adjacent l2 16-coefficient blocks at once with a 512-bit helper.
AVX2-only and non-AVX512 builds keep the previous 256-bit l2 helper. The NTT
bench harness was also aligned so `mlkem_ntt_tail_avx2_l2` measures the same
AVX512/AVX2 split used by the real tail path.

Correctness checks:

```bash
git diff --check
make clean CC=clang AVX2_BACKEND=core && \
make test CC=clang AVX2_BACKEND=core
make clean CC=clang AVX2_BACKEND=core && \
make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
make bench-ntt-run CC=clang AVX2_BACKEND=core BENCH_NTT_ITERS=1000
make bench-ntt-run CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" BENCH_NTT_ITERS=1000
```

Native NTT/stage A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=ntt,stage NTT_ITERS=200000 STAGE_ITERS=90000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

NTT A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_ntt_tail_avx2_l2` | 31.38 | 30.76 | 1.020x | 1.017x |
| `mlkem_ntt_tail_avx2` | 94.27 | 93.54 | 1.008x | 1.008x |
| `mlkem_ntt_inplace` | 170.56 | 171.15 | 0.997x | 1.003x |
| `mlkem_ntt_copy` | 172.55 | 172.18 | 1.002x | 1.000x |

Stage A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_decrypt_ntt_accum_recover` | 763.93 | 762.28 | 1.002x | 1.002x |
| `mlkem_core_stage_decrypt_u_ntt_tail` | 466.73 | 466.93 | 1.000x | 1.001x |
| `mlkem_core_stage_encrypt_noise_ntt` | 693.47 | 695.29 | 0.997x | 1.002x |
| `mlkem_core_stage_keygen_noise_ntt` | 1560.39 | 1564.92 | 0.997x | 1.001x |
| `mlkem_core_stage_kpke_keygen_full` | 3409.59 | 3400.41 | 1.003x | 1.002x |

Native KEM A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=kem KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

KEM A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_keygen` | 5303.94 | 5277.10 | 1.005x | 1.002x |
| `mlkem_encaps` | 2115.66 | 2116.96 | 0.999x | 1.001x |
| `mlkem_decaps` | 2947.85 | 2939.03 | 1.003x | 1.003x |
| `mlkem_roundtrip` | 10358.23 | 10335.99 | 1.002x | 1.002x |
| `mlkem_keygen_core` | 5262.73 | 5259.29 | 1.001x | 1.000x |
| `mlkem_roundtrip_core` | 14752.80 | 14722.10 | 1.002x | 1.003x |

The direct acceptance signal is the l2/tail NTT improvement. Full KEM movement
is intentionally described as small because this changes only one forward NTT
tail stage; the useful outcome is a local 512-bit butterfly without relying on
vendored external arithmetic code.

A follow-up AVX512 l1 two-block experiment was rejected. The candidate added an
`ntt_butterfly2x8_avx512()` helper for the final length-2 forward NTT tail
stage, passed native `make test` plus short `bench-ntt-run` validation, but the
direct NTT A/B regressed badly:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=ntt NTT_ITERS=200000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_ntt_tail_avx2_l1` | 38.50 | 47.84 | 0.805x | 0.804x |
| `mlkem_ntt_tail_avx2` | 93.76 | 102.10 | 0.918x | 0.918x |
| `mlkem_ntt_inplace` | 170.09 | 177.22 | 0.960x | 0.959x |
| `mlkem_ntt_copy` | 172.33 | 178.93 | 0.963x | 0.963x |

Keep l1 on the existing AVX2 helper. At length 2, the extra gather/pack/scatter
work needed to fill 16 AVX512 lanes costs more than the wider multiply/reduce
saves.

### Independent Core Optimization A/B (2026-07-01, AVX512 sample_ntt8 static stream scratch)

A native AVX512 follow-up that moved `sample_ntt8_matrix()`'s `uint8_t
stream[8][504]` scratch from the stack to static storage was rejected. This was
modeled after the accepted AVX2 x4 sampler scratch change above, but the x8 path
behaved differently: the direct public-matrix sampler row regressed clearly.

The candidate changed only the storage duration of the 8x504-byte stream buffer
inside `sample_ntt8_matrix()`. It passed native `make test`, AVX2-only
`make test`, and `git diff --check`.

Native stage A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage STAGE_ITERS=90000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

Stage A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_matrix` | 1901.04 | 1961.43 | 0.969x | 0.965x |
| `mlkem_core_stage_sample_matrix_x4_batch0` | 787.48 | 794.88 | 0.991x | 1.001x |
| `mlkem_core_stage_sample_matrix_x4_batch1` | 830.79 | 839.95 | 0.989x | 0.998x |
| `mlkem_core_stage_kpke_keygen_full` | 3402.47 | 3396.43 | 1.002x | 1.002x |

Keep `sample_ntt8_matrix()`'s stream buffer on the stack. Unlike the AVX2 x4
sampler, moving the larger AVX512 x8 stream to static storage hurts the direct
sample-matrix stage enough that any surrounding keygen noise is not a defensible
acceptance signal.

A separate producer/consumer fusion experiment for `sample_ntt8_matrix()` was
also rejected. The candidate stored only one 168-byte SHAKE128 rate block per
lane, parsed it immediately, and reused that scratch for the next block instead
of first writing all three blocks to `stream[8][504]` and parsing each lane once.
This reduced scratch size and write/read traffic, but increased parser call
overhead and hurt the integrated public-matrix path.

Native stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=60000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

Stage A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_matrix` | 1897.64 | 1994.55 | 0.951x | 0.949x |
| `mlkem_core_stage_kpke_keygen_full` | 3394.63 | 3537.57 | 0.960x | 0.971x |
| `mlkem_core_stage_kpke_encrypt_uncached` | 3650.38 | 3754.45 | 0.972x | 0.974x |

Keep the existing three-block store followed by one 504-byte parse per lane. For
this parser, larger contiguous chunks beat tighter producer/consumer fusion.

An AVX512VBMI2 parser compaction experiment was also rejected. The candidate
kept the existing 48-byte decode shape but replaced the AVX2 table-shuffle
packing of accepted 12-bit values with `_mm512_mask_compressstoreu_epi16()` over
32 candidate coefficients. This is a common SIMD compaction pattern, but on this
target the 16-bit compress-store path was much slower than the AVX2 shuffle
table.

Native stage A/B command:

```bash
RUNS=5 WARMUP_RUNS=1 SUITES=stage STAGE_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

Stage A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_parse_504` | 126.17 | 868.02 | 0.145x | 0.146x |
| `mlkem_core_stage_sample_ntt4_full_raw` | 601.88 | 1335.55 | 0.451x | 0.451x |
| `mlkem_core_stage_sample_matrix` | 1887.40 | 3543.12 | 0.533x | 0.532x |
| `mlkem_core_stage_kpke_keygen_full` | 3394.15 | 5014.73 | 0.677x | 0.677x |

Keep the AVX2 table-shuffle parser. For 16-bit rejection compaction,
`VPCOMPRESSW`/VBMI2 is not a useful replacement here despite reducing code
complexity.

A narrower AVX512 `sample_ntt8_store_rate()` experiment replacing the two
`sample_ntt4_store_last()` calls for `st[20]` with one `_mm512_storeu_si512()` to
`uint64_t last[8]` plus eight 8-byte copies was also rejected. This was the
opposite direction of the rejected x4 helper reuse above: x4 should keep the
local `last[4]` store, so the question was whether x8 should also avoid the
extract helper for the final 8-byte word. The candidate passed native
`make test`, AVX2-only `make test`, and `git diff --check`, but the full
sample-matrix path did not improve.

Native stage A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage STAGE_ITERS=90000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

Stage A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_store_rate` | 1.67 | 1.66 | 1.005x | 1.006x |
| `mlkem_core_stage_sample_matrix` | 1899.82 | 1901.54 | 0.999x | 0.999x |
| `mlkem_core_stage_sample_matrix_tail` | 702.70 | 708.47 | 0.992x | 0.998x |
| `mlkem_core_stage_kpke_keygen_full` | 3409.37 | 3407.35 | 1.001x | 0.997x |

Keep the existing `sample_ntt4_store_last()` calls in `sample_ntt8_store_rate()`.
The isolated store-rate probe moves by about half a percent, but the direct
public-matrix stage is flat-to-slower, so this is not a production win.

### Independent Core Optimization A/B (2026-07-01, u inverse-NTT add batching)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`. Baseline is
commit `0262389` before batching the `u` inverse-NTT add path; candidate is the
working tree after the change. This is a core-vs-core comparison and does not
use the vendored Kyber/PQClean AVX2 backends for the candidate path.

The implementation computes all three `u` NTT-domain accumulations first, then
uses a native AVX512-capable `ntt_inv_add3_inplace()` helper to process the
three inverse-NTT tail schedules and final scale/add loop together. This reuses
the same twiddle schedule and scale constant across the three `u` polynomials.
The AVX2-only and non-AVX2 paths keep the previous per-polynomial order.

Native stage/KEM A/B command:

```bash
RUNS=9 WARMUP_RUNS=1 SUITES=stage,kem STAGE_ITERS=50000 KEM_ITERS=12000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

Stage A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_encrypt_accum_inv_u` | 895.70 | 891.25 | 1.005x | 1.006x |
| `mlkem_core_stage_encrypt_accum_inv` | 1137.04 | 1128.32 | 1.008x | 1.007x |
| `mlkem_core_stage_kpke_encrypt_cached` | 1913.61 | 1896.69 | 1.009x | 1.011x |
| `mlkem_core_stage_kpke_encrypt_uncached` | 3648.65 | 3650.19 | 1.000x | 1.007x |

KEM A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_encaps` | 2116.26 | 2107.08 | 1.004x | 1.003x |
| `mlkem_encaps_core` | 4905.66 | 4892.53 | 1.003x | 1.004x |
| `mlkem_roundtrip` | 10375.32 | 10383.70 | 0.999x | 1.000x |
| `mlkem_roundtrip_core` | 14692.87 | 14695.44 | 1.000x | 1.000x |

A more aggressive variant that also batched the AVX2 inverse-NTT head stages was
rejected: it made `mlkem_core_stage_encrypt_accum_inv_u` slower in A/B. The
accepted version therefore limits batching to the AVX512 tail and scale/add
part, where it measured consistently useful without changing AVX2-only behavior.

### Independent Core Optimization A/B (2026-07-01, e2/message fusion)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`. Baseline is
commit `719fc50` before the `e2`/message fusion; candidate is the working tree
after the change. This is a core-vs-core comparison and does not use the
vendored Kyber/PQClean AVX2 backends for the candidate path.

The implementation stops materializing `mu` as a separate polynomial in the
K-PKE encryption path. Instead, it folds the message polynomial directly into
`e2`, which is no longer needed separately after `v` is formed, then uses the
single-add inverse NTT path. On AVX2 builds, message expansion follows the same
coefficient layout as the Kyber AVX2 `poly_frommsg()` style expansion, but adds
those coefficients directly into `e2` instead of storing an intermediate `mu`.
This is a data-flow reduction, not a cache or repeated-key optimization.

Native stage/KEM A/B command:

```bash
RUNS=9 WARMUP_RUNS=1 SUITES=stage,kem STAGE_ITERS=50000 KEM_ITERS=12000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

Stage A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_encrypt_accum_inv_v` | 419.71 | 410.01 | 1.024x | 1.024x |
| `mlkem_core_stage_encrypt_accum_inv` | 1147.17 | 1137.30 | 1.009x | 1.008x |
| `mlkem_core_stage_kpke_encrypt_cached` | 1926.14 | 1917.16 | 1.005x | 1.004x |
| `mlkem_core_stage_kpke_encrypt_uncached` | 3699.26 | 3714.14 | 0.996x | 0.998x |

KEM A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_encaps` | 2120.61 | 2113.17 | 1.004x | 1.002x |
| `mlkem_encaps_core` | 4906.13 | 4903.58 | 1.001x | 1.000x |
| `mlkem_roundtrip_core` | 14710.18 | 14669.08 | 1.003x | 1.004x |

AVX2-only KEM no-regression check, built with
`ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"`, `16000` iterations, nine repeated runs:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_encaps` | 3332.24 | 3251.42 | 1.025x | 1.006x |
| `mlkem_roundtrip` | 17662.25 | 17060.50 | 1.035x | 1.026x |
| `mlkem_roundtrip_core` | 28899.41 | 27158.74 | 1.064x | 1.052x |

The main defensible effect is the local `v` accumulation/inverse-NTT stage. Full
KEM impact is intentionally described as small because message folding is a
minor fraction of encapsulation.

### Independent Core Optimization A/B (2026-07-01, AVX2 sample parser init hoist)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`. Baseline is
commit `beac787` before the AVX2 sample parser init hoist; candidate is the
working tree after the change. This is a core-vs-core comparison and does not
use the vendored Kyber/PQClean AVX2 backends for the candidate path.

The implementation hoists `sample_ntt_parse_init_avx2()` out of the per-lane
`sample_ntt4()` parse calls and calls `sample_ntt_parse_stream_avx2_ready()`
directly. This removes repeated wrapper/init checks in the AVX2-only matrix
sampling path. It does not add caching, reuse sampled data across operations, or
call an external backend.

AVX2-only focused KEM A/B: both baseline and candidate were built with
`ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"`, then run with `20000` iterations,
fifteen repeated runs, two warmups, pinned to CPU 0.

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_keygen` | 10152.88 | 9578.06 | 1.060x | 1.047x |
| `mlkem_keygen_core` | 10126.98 | 9554.08 | 1.060x | 1.047x |
| `mlkem_roundtrip` | 17891.43 | 17331.09 | 1.032x | 1.035x |

Native stage/KEM A/B command:

```bash
RUNS=9 WARMUP_RUNS=1 SUITES=stage,kem STAGE_ITERS=50000 KEM_ITERS=12000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

Native highlights, treated as a no-regression check rather than the target of
this optimization:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_matrix` | 1896.56 | 1923.79 | 0.986x | 1.000x |
| `mlkem_core_stage_sample_matrix_x4_batch0` | 796.44 | 785.13 | 1.014x | 1.005x |
| `mlkem_keygen` | 5287.65 | 5265.34 | 1.004x | 1.004x |
| `mlkem_keygen_core` | 5261.66 | 5241.18 | 1.004x | 1.003x |

The useful effect is AVX2-only. The native AVX512-capable KEM path already uses
the `sample_ntt8_matrix()` path for most matrix generation, so this change is
expected to be approximately neutral there.

A narrower follow-up that wrapped the ready check with
`__builtin_expect(sample_ntt_parse_idx_ready, 1)` was rejected. AVX2 stage A/B
against `704354b` with `RUNS=11`, `STAGE_ITERS=80000`, and
`ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"` showed `sample_ntt4_parse_504` median
speedup `1.0027x`, but `sample_ntt4_full_raw` `0.9970x`,
`sample_matrix_x4_batch0` `0.9994x`, `sample_matrix_x4_batch1` `0.9981x`, and
`sample_matrix` `0.9971x`. The compiler branch hint is too small and noisy for
the full sampler path, so keep the plain ready check.

### Independent Core Optimization A/B (2026-07-01, keygen tail/noise co-scheduling)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`. Baseline is
commit `8595479` before keygen tail/noise co-scheduling; candidate is commit
`581554d`. This is a core-vs-core comparison and does not use the vendored
Kyber/PQClean AVX2 backends for the candidate path.

Native stage/KEM A/B command:

```bash
RUNS=7 WARMUP_RUNS=1 SUITES=stage,kem STAGE_ITERS=40000 KEM_ITERS=10000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh 8595479
```

Stage A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_kpke_keygen_full` | 3547.61 | 3387.02 | 1.047x | 1.047x |
| `mlkem_core_stage_sample_matrix_tail` | 705.59 | 704.51 | 1.002x | 1.000x |
| `mlkem_core_stage_keygen_noise_prf_cbd` | 693.33 | 693.40 | 1.000x | 1.000x |

KEM A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_keygen` | 5356.58 | 5257.33 | 1.019x | 1.019x |
| `mlkem_keygen_core` | 5327.58 | 5227.47 | 1.019x | 1.020x |
| `mlkem_roundtrip_core` | 14779.48 | 14655.82 | 1.008x | 1.008x |

The change keeps the core path vendor-free and does not add any cross-operation
cache. On AVX512 builds, keygen still samples the first eight public-matrix
entries with `sample_ntt8_matrix()`, but the final `(2,2)` SHAKE128 matrix tail
uses lane 6 of the existing six-lane SHAKE256 PRF `keccakf8()` call for the
first tail block. Remaining tail blocks continue through the local `keccakf4()`
state. At that point, AVX2-only builds kept the previous path; the later AVX2
section below adds the analogous x4 keygen-only co-schedule.

### Independent Core Optimization A/B (2026-07-01, AVX2 keygen tail/noise co-scheduling)

Baseline is commit `7049074` before the AVX2 keygen co-schedule; candidate is
the working tree after moving the final `(2,2)` public-matrix tail into the same
first `keccakf4()` call that generates keygen PRF nonces 4 and 5. This is a
core implementation change, not a cache or external-backend optimization. The
change removes one typical AVX2 x4 Keccak permutation from `kpke_keygen()` by
sharing independent vector lanes; the remaining tail blocks continue in the same
local Keccak state.

AVX2-only stage command:

```bash
RUNS=17 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=80000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

| Metric | Baseline median ns/op | Candidate median ns/op | Median speedup |
|---|---:|---:|---:|
| `mlkem_core_stage_kpke_keygen_full` | 6726.96 | 6331.42 | 1.063x |
| `mlkem_core_stage_kpke_encrypt_cached` | 2719.70 | 2720.04 | 1.000x |
| `mlkem_core_stage_kpke_decrypt_cached` | 1088.29 | 1087.35 | 1.001x |

KEM-only confirmation command:

```bash
RUNS=13 WARMUP_RUNS=2 SUITES=kem KEM_ITERS=40000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

| Metric | Baseline median ns/op | Candidate median ns/op | Median speedup |
|---|---:|---:|---:|
| `mlkem_keygen_core` | 9103.04 | 8471.98 | 1.075x |
| `mlkem_roundtrip_core` | 26414.71 | 25612.89 | 1.031x |

### Independent Core Optimization A/B (2026-07-01, AVX2 inverse-add final fusion)

Baseline is commit `8a1308a` before extending the final-stage fusion to inverse
NTT add paths; candidate is the working tree after applying the same AVX2 final
`log2len = 7` butterfly plus `3303` scale folding to `ntt_inv_add_inplace()`
and `ntt_inv_add2_inplace()`. This is a core implementation change and does
not use caches or vendored AVX2 backends. The already-fused decrypt
`ntt_inv_sub_from_inplace()` path is unchanged except that it now shares the
common pre-final helper.

AVX2-only NTT/stage command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=ntt,stage NTT_ITERS=200000 STAGE_ITERS=50000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_ntt_inv_add` | 213.25 | 200.80 | 1.062x | 1.059x |
| `mlkem_ntt_inv_add2` | 227.28 | 211.54 | 1.074x | 1.075x |
| `mlkem_core_stage_encrypt_accum_inv` | 1374.54 | 1324.32 | 1.038x | 1.038x |
| `mlkem_core_stage_encrypt_accum_inv_u` | 1073.85 | 1037.85 | 1.035x | 1.037x |
| `mlkem_core_stage_encrypt_accum_inv_v` | 481.64 | 475.81 | 1.012x | 1.024x |
| `mlkem_core_stage_kpke_encrypt_uncached` | 7254.38 | 7196.57 | 1.008x | 1.010x |

AVX2-only KEM confirmation command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=kem KEM_ITERS=40000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_encaps` | 3170.43 | 3048.43 | 1.040x | 1.020x |
| `mlkem_encaps_core` | 9023.93 | 8940.77 | 1.009x | 1.052x |
| `mlkem_roundtrip_core` | 26992.24 | 26713.25 | 1.010x | 1.024x |

The main effect is the local inverse-add post-processing scan: the fused final
stage removes one full scale/add pass for each AVX2 inverse-add call. The KEM
rows still include higher-noise sampling and hashing work, so use the NTT/stage
rows as the primary attribution for why this change is faster.

A follow-up AVX2 experiment that changed the `u` side to compute all three
`ntt_mul_acc3()` accumulations first and then call an AVX2-only
`ntt_inv_add3_inplace()` final-fusion helper was rejected. Stage A/B against
`c45445c` showed `encrypt_accum_inv_u` average speedup `0.9974x`,
`encrypt_accum_inv` average speedup `0.9985x`, and `kpke_encrypt_uncached`
median speedup `0.9602x`. This confirms that the AVX2-only path should keep the
per-row accumulation/inverse-add order, even though the AVX512 path can still
benefit from its wider batched helper.

A narrower experiment replacing the final fused AVX2 32-bit modular add/sub
operations with packed 16-bit modular add/sub was also rejected. NTT micro A/B
showed only small wins for `ntt_inv_add` (`1.0037x`) and `ntt_inv_add2`
(`1.0043x`), while stage/KEM confirmation regressed `decrypt_inv_sub_from`
median speedup to `0.9988x`, `encaps_core` average speedup to `0.9866x`, and
`roundtrip_core` average speedup to `0.9941x`. Keep the final fused arithmetic in
32-bit lanes after the reduction.

### Independent Core Optimization A/B (2026-07-01, AVX2 decrypt inverse final fusion)

Baseline is commit `8402ce5` before fusing the decrypt inverse-NTT final stage;
candidate is the working tree after folding the final `log2len = 7` inverse
butterfly, the mandatory `3303` inverse-NTT scale, and `v - scaled(w)` into one
AVX2 pass for `ntt_inv_sub_from_inplace()`. This is a core implementation
change: it removes a full post-inverse polynomial scan from the decrypt path and
does not add a cache or use an external backend.

AVX2-only stage command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=50000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_decrypt_inv_sub_from` | 391.89 | 381.50 | 1.027x | 1.027x |
| `mlkem_core_stage_decrypt_accum_inv` | 472.65 | 461.98 | 1.023x | 1.022x |
| `mlkem_core_stage_decrypt_ntt_accum_recover` | 897.67 | 886.97 | 1.012x | 1.012x |
| `mlkem_core_stage_kpke_decrypt_uncached` | 1102.25 | 1094.76 | 1.007x | 1.007x |

KEM-only confirmation command:

```bash
RUNS=17 WARMUP_RUNS=3 SUITES=kem KEM_ITERS=24000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_decaps` | 4174.74 | 4343.32 | 0.961x | 0.999x |
| `mlkem_decaps_core` | 8313.88 | 8025.69 | 1.036x | 1.001x |
| `mlkem_roundtrip_core` | 26935.84 | 26106.89 | 1.032x | 1.031x |

The public `mlkem_decaps` row is noisy and should not be read as a broad KEM
win. The defensible effect is the local decrypt inverse-sub stage: the fused
final stage removes one scale/sub scan and improves the decrypt-focused stage
rows without relying on caches or vendored code.

### Independent Core Optimization A/B (2026-06-30, sample-matrix x4 transpose store)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`. Baseline
is commit `eb72685` before replacing the x4 sample-matrix state transpose;
candidate is the working tree after the change. This is a core-vs-core
comparison and does not use the vendored Kyber/PQClean AVX2 backends for the
candidate path.

Stage A/B, `50000` iterations, fifteen repeated runs:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_matrix` | 2762.73 | 2724.86 | 1.014x | 1.011x |
| `mlkem_core_stage_sample_matrix_x4_batch0` | 1126.87 | 1113.80 | 1.012x | 1.012x |
| `mlkem_core_stage_sample_matrix_x4_batch1` | 1171.56 | 1156.53 | 1.013x | 1.013x |
| `mlkem_core_stage_sample_matrix_tail` | 823.40 | 820.44 | 1.004x | 1.000x |
| `mlkem_core_stage_kpke_keygen_full` | 4709.70 | 4692.95 | 1.004x | 1.006x |
| `mlkem_core_stage_kpke_encrypt_cached` | 2249.08 | 2238.47 | 1.005x | 1.002x |

KEM A/B, `16000` iterations, twenty-one repeated runs:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| keygen | 9008.30 | 9018.80 | 0.999x | 1.002x |
| encaps | 2462.82 | 2466.68 | 0.998x | 0.999x |
| decaps | 3458.00 | 3452.55 | 1.002x | 0.998x |
| roundtrip | 15011.10 | 14992.71 | 1.001x | 1.000x |

External comparison smoke gate, `600` iterations and two runs, passed with
`verify_world_fastest=PASS`; the local implementation remained at least
`1.098x` faster than the upstream AVX2 label in that short gate.

The change keeps the core path vendor-free. `sample_ntt4_store_rate()` now
transposes four consecutive Keccak x4 state words with AVX2 unpack/permute
operations and stores each stream in 32-byte chunks, instead of storing every
state word to a temporary `uint64_t[4]` and copying four 8-byte lanes with
`memcpy()`. The candidate deliberately keeps the existing byte-stream parser and
three-block buffering, because a direct state parser was correct but made
`sample_matrix` and end-to-end KEM slower in A/B tests.

### Independent Core Optimization A/B (2026-06-30, PRF/CBD x4 state decode)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`. Baseline
is commit `e45c9d8` before decoding the x4 PRF/CBD output directly from the
Keccak state; candidate is the working tree after the change. This is a
core-vs-core comparison and does not use the vendored Kyber/PQClean AVX2
backends for the candidate path.

Stage A/B, `20000` iterations, nine repeated runs:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_noise_prf_cbd` | 777.56 | 758.32 | 1.025x | 1.025x |
| `mlkem_core_stage_keygen_noise_ntt` | 1841.30 | 1818.38 | 1.013x | 1.013x |
| `mlkem_core_stage_encrypt_noise_prf_cbd` | 969.70 | 943.45 | 1.028x | 1.025x |
| `mlkem_core_stage_encrypt_noise` | 1213.02 | 1192.29 | 1.017x | 1.019x |
| `mlkem_core_stage_kpke_keygen_full` | 4755.99 | 4741.59 | 1.003x | 1.003x |
| `mlkem_core_stage_kpke_encrypt_cached` | 2286.67 | 2240.60 | 1.021x | 1.010x |

KEM A/B, `9000` iterations, fifteen repeated runs:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| keygen | 9022.23 | 9012.35 | 1.001x | 1.001x |
| encaps | 2473.24 | 2467.54 | 1.002x | 1.001x |
| decaps | 3444.98 | 3439.78 | 1.002x | 1.001x |
| roundtrip | 15000.58 | 14967.41 | 1.002x | 1.002x |

The change keeps the core path vendor-free. `mlkem_prf_cbd_eta2x4_32()` now
decodes the four live SHAKE256 streams directly from the `keccakf4()` state in
16-byte pairs instead of first transposing state words into four temporary
`stream[4][128]` buffers and then calling the byte-oriented CBD decoder. The
x2/x3 helpers intentionally keep their previous stream path because applying
the same direct-state decoder there made end-to-end KEM noisier. The direct
acceptance signal is the PRF/CBD noise-stage improvement; KEM-level movement is
small because the x4 helper is only one component of keygen and encaps.

### Independent Core Optimization A/B (2026-06-30, sample-matrix fallback squeeze)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`. Baseline
is commit `40bf80d` before continuing x4 sampler fallback squeezes; candidate
is the working tree after the change. This is a core-vs-core comparison and
does not use the vendored Kyber/PQClean AVX2 backends for the candidate path.

Stage A/B, `20000` iterations, fifteen repeated runs:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_matrix` | 2973.00 | 2755.70 | 1.079x | 1.071x |
| `mlkem_core_stage_sample_matrix_x4_batch0` | 1123.55 | 1130.71 | 0.994x | 0.993x |
| `mlkem_core_stage_sample_matrix_x4_batch1` | 1361.62 | 1170.11 | 1.164x | 1.162x |
| `mlkem_core_stage_sample_matrix_tail` | 853.55 | 816.41 | 1.046x | 1.018x |
| `mlkem_core_stage_kpke_keygen_full` | 4912.18 | 4741.26 | 1.036x | 1.041x |

KEM A/B, `9000` iterations, fifteen repeated runs:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| keygen | 9082.72 | 9031.91 | 1.006x | 1.006x |
| encaps | 2468.03 | 2483.94 | 0.994x | 0.997x |
| decaps | 3446.39 | 3454.32 | 0.998x | 0.998x |
| roundtrip | 15087.31 | 15041.65 | 1.003x | 1.004x |

The change keeps the core path vendor-free. `sample_ntt4()` and
`sample_ntt4_one()` used to fall back to scalar `sample_ntt()` from the
beginning when the first three SHAKE128 blocks did not produce all 256
coefficients. They now continue squeezing the existing x4 Keccak state and
parse only the extra block(s) needed by incomplete lanes. This removes wasted
Keccak work in the public matrix sampler. The direct acceptance signal is the
`sample_matrix` / `kpke_keygen_full` improvement; cached encaps/decaps do not
exercise public matrix generation and remain layout-noise sensitive.

### Independent Core Optimization A/B (2026-06-30, forward NTT zeta vectors)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`. Baseline
is commit `d6f357b` before precomputing forward-tail AVX2 zeta vectors;
candidate is the working tree after the change. This is a core-vs-core
comparison and does not use the vendored Kyber/PQClean AVX2 backends for the
candidate path.

NTT A/B, `200000` iterations, nine repeated runs:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_ntt_copy` | 217.48 | 208.15 | 1.045x | 1.046x |
| `mlkem_ntt_inplace` | 214.49 | 205.11 | 1.046x | 1.046x |

Stage A/B, `15000` iterations, nine repeated runs:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_noise_ntt_encode` | 1683.98 | 1626.19 | 1.035x | 1.035x |
| `mlkem_core_stage_encrypt_noise_ntt` | 829.46 | 809.06 | 1.025x | 1.036x |
| `mlkem_core_stage_decrypt_ntt_accum_recover` | 930.72 | 908.34 | 1.025x | 1.033x |

KEM A/B, `8000` iterations, fifteen repeated runs:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| keygen | 9161.49 | 9080.96 | 1.009x | 1.007x |
| encaps | 2501.16 | 2477.27 | 1.010x | 1.012x |
| decaps | 3498.54 | 3464.05 | 1.010x | 1.013x |
| roundtrip | 15234.07 | 15084.15 | 1.010x | 1.009x |

The change keeps the core path vendor-free. `init_ntt_roots()` now also builds
AVX2 zeta vectors for the forward NTT tail levels (`l3`..`l1`), so
`ntt_tail_avx2()` loads pre-shaped vectors instead of constructing
`_mm256_set1_epi32()` / `_mm256_setr_epi32()` values on every transform. The
inverse NTT path is unchanged.

### Independent Core Optimization A/B (2026-06-30, keygen cache direct fill)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`. Baseline
is commit `a0ceba1` before filling the public-key cache directly during
`kpke_keygen()`; candidate is the working tree after the change. This is a
core-vs-core comparison and does not use the vendored Kyber/PQClean AVX2
backends for the candidate path.

Stage A/B, `15000` iterations, nine repeated runs:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_kpke_keygen_full` | 5011.67 | 4966.83 | 1.009x | 1.007x |

KEM A/B, `8000` iterations, fifteen repeated runs:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| keygen | 9175.25 | 9173.88 | 1.000x | 1.005x |
| encaps | 2502.52 | 2498.03 | 1.002x | 0.999x |
| decaps | 3488.25 | 3494.83 | 0.998x | 0.998x |
| roundtrip | 15245.14 | 15241.45 | 1.000x | 1.002x |

The direct effect is in K-PKE key generation: `kpke_keygen()` now samples
`A^T` into the existing public-key cache storage and writes `t-hat` into the
cached `that` array as it encodes the public key. This removes the follow-up
copy of the generated matrix and public-key polynomials into the cache. The
end-to-end KEM result is intentionally documented as near-neutral on averages,
with the stage keygen row as the primary acceptance signal.

### Independent Core Optimization A/B (2026-06-30, decrypt in-place NTT)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`. Baseline
is commit `3f77114` before making decrypt-side `u` transforms in-place;
candidate is the working tree after the change. This is a core-vs-core
comparison and does not use the vendored Kyber/PQClean AVX2 backends for the
candidate path.

Stage A/B, `15000` iterations, nine repeated runs:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_kpke_decrypt_cached` | 1010.10 | 1000.64 | 1.009x | 1.007x |
| `mlkem_core_stage_decrypt_ntt_accum_recover` | 924.69 | 926.36 | 0.998x | 0.997x |

KEM A/B, `8000` iterations, thirteen repeated runs:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| keygen | 9199.03 | 9198.16 | 1.000x | 0.998x |
| encaps | 2490.73 | 2494.09 | 0.999x | 0.999x |
| decaps | 3508.13 | 3493.03 | 1.004x | 1.005x |
| roundtrip | 15277.98 | 15265.03 | 1.001x | 0.999x |

The change keeps the core path vendor-free. `kpke_decrypt()` now transforms the
freshly decoded `u` polynomials in-place before the fixed K=3 NTT accumulation,
removing the separate `u_ntt` scratch copy in the real decrypt path. The stage
split metric still copies precomputed inputs before the in-place NTT so it can
preserve reusable benchmark fixtures; the full `kpke_decrypt_cached` and KEM
`decaps` rows are the direct acceptance signal.

### Independent Core Optimization A/B (2026-06-30, PRF/CBD dummy-lane skip)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`. Baseline
is commit `0c32149` before avoiding dummy PRF/CBD output lanes; candidate is
the working tree after the change. This is a core-vs-core comparison and does
not use the vendored Kyber/PQClean AVX2 backends for the candidate path.

Stage A/B, `15000` iterations, nine repeated runs:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_noise_prf_cbd` | 793.83 | 779.52 | 1.018x | 1.018x |
| `mlkem_core_stage_keygen_noise_ntt` | 1923.76 | 1903.70 | 1.010x | 1.010x |
| `mlkem_core_stage_encrypt_noise_prf_cbd` | 973.12 | 964.55 | 1.009x | 1.008x |
| `mlkem_core_stage_encrypt_noise` | 1251.48 | 1241.78 | 1.008x | 1.008x |
| `mlkem_core_stage_kpke_keygen_full` | 5017.53 | 5005.47 | 1.002x | 1.003x |
| `mlkem_core_stage_kpke_encrypt_cached` | 2291.77 | 2289.74 | 1.001x | 1.003x |

KEM A/B, `5000` iterations, nine repeated runs:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| keygen | 9232.44 | 9198.62 | 1.004x | 1.004x |
| encaps | 2516.08 | 2495.17 | 1.008x | 1.004x |
| decaps | 3539.18 | 3510.14 | 1.008x | 1.007x |
| roundtrip | 15357.59 | 15272.68 | 1.006x | 1.004x |

The change keeps the core path vendor-free. The existing x4 PRF/CBD helper is
still used when all four lanes are real. For the second keygen batch only two
outputs are needed, and for the second encryption batch only three outputs are
needed. New local x2/x3 helpers keep the same `keccakf4()` permutation but skip
stream extraction and CBD decode for dummy lanes, avoiding unnecessary work
without calling or modifying vendored Kyber/PQClean code.

A later AVX2 experiment moving the smaller x2/x3 PRF/CBD stream scratch arrays
from stack to static storage was rejected. Stage A/B against `2bb59a9` showed
`keygen_noise_prf_cbd` median speedup `0.9904x` and
`encrypt_noise_prf_cbd` median speedup `0.9898x`, so the accepted static-scratch
idea should remain limited to the larger x4 `sample_ntt4()` stream buffer.

### Independent Core Optimization A/B (2026-06-30, ETA2 CBD AVX2 decode)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`. Baseline
is commit `a11bd74` before adding the self-contained AVX2 decoder for ETA2
CBD; candidate is the working tree after the change. This is a core-vs-core
comparison and does not use the vendored Kyber/PQClean AVX2 backends for the
candidate path.

Keccak/sampling A/B, `200000` iterations, seven repeated runs:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_cbd_eta2` | 22.53 | 7.63 | 2.954x | 2.953x |
| `mlkem_prf_eta2` | 200.79 | 199.93 | 1.004x | 1.002x |

Stage A/B, `15000` iterations, nine repeated runs:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_noise_prf_cbd` | 901.10 | 793.96 | 1.135x | 1.136x |
| `mlkem_core_stage_keygen_noise_ntt` | 2038.96 | 1924.48 | 1.059x | 1.060x |
| `mlkem_core_stage_encrypt_noise_prf_cbd` | 1079.03 | 973.08 | 1.109x | 1.108x |
| `mlkem_core_stage_encrypt_noise` | 1365.04 | 1252.30 | 1.090x | 1.090x |
| `mlkem_core_stage_kpke_keygen_full` | 5117.52 | 5014.01 | 1.021x | 1.021x |
| `mlkem_core_stage_kpke_encrypt_cached` | 2401.46 | 2291.99 | 1.048x | 1.047x |

KEM A/B, `5000` iterations, nine repeated runs:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| keygen | 9319.28 | 9281.84 | 1.004x | 1.013x |
| encaps | 2635.35 | 2540.66 | 1.037x | 1.040x |
| decaps | 3653.01 | 3545.30 | 1.030x | 1.028x |
| roundtrip | 15684.14 | 15444.70 | 1.016x | 1.021x |

The change keeps the core path vendor-free. `sample_poly_cbd_eta2_bytes()` now
uses a local AVX2 nibble lookup for the common ETA2 case, mapping each 4-bit
CBD group to the signed `{-2..2}` coefficient and adding `Q` only for negative
lanes to preserve the existing canonical representation. This reduces the
standalone CBD cost and flows into the PRF/CBD noise stages without calling or
modifying vendored Kyber/PQClean code.

### Independent Core Optimization A/B (2026-06-30, inverse NTT AVX2 head)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`. Baseline
is commit `c9f7051` before adding the self-contained AVX2 head for inverse
NTT; candidate is the working tree after the change. This is a core-vs-core
comparison and does not use the vendored Kyber/PQClean AVX2 backends for the
candidate path.

NTT A/B, `200000` iterations, seven repeated runs:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_ntt_inv` | 249.66 | 183.85 | 1.358x | 1.358x |
| `mlkem_ntt_inv_add` | 259.86 | 195.87 | 1.327x | 1.331x |
| `mlkem_ntt_inv_add2` | 272.79 | 207.73 | 1.313x | 1.314x |
| `mlkem_ntt_inv_sub_from` | 260.61 | 195.96 | 1.330x | 1.335x |

Stage A/B, `15000` iterations, nine repeated runs:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_encrypt_accum_inv` | 1503.21 | 1244.26 | 1.208x | 1.208x |
| `mlkem_core_stage_decrypt_ntt_accum_recover` | 1003.51 | 925.88 | 1.084x | 1.091x |
| `mlkem_core_stage_kpke_encrypt_cached` | 2652.73 | 2406.77 | 1.102x | 1.102x |
| `mlkem_core_stage_kpke_decrypt_cached` | 1071.45 | 1005.70 | 1.065x | 1.067x |

KEM A/B, `5000` iterations, nine repeated runs:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| keygen | 9317.33 | 9312.34 | 1.001x | 1.001x |
| encaps | 2915.98 | 2633.78 | 1.107x | 1.104x |
| decaps | 4001.17 | 3653.41 | 1.095x | 1.095x |
| roundtrip | 16308.55 | 15668.49 | 1.041x | 1.040x |

The change keeps the core path vendor-free. The inverse NTT family now uses a
local AVX2 helper for the first three short-butterfly stages (`log2len = 1, 2,
3`) and leaves the remaining stages plus final scaling/add/sub fusion on the
existing scalar code. This improves `ntt_inv()`, `ntt_inv_add()`,
`ntt_inv_add2()`, and `ntt_inv_sub_from()` without calling or modifying
vendored Kyber/PQClean assembly.

### Independent Core Optimization A/B (2026-06-30, forward NTT AVX2 tail)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`. Baseline
is commit `f596d47` before adding the self-contained AVX2 tail for forward
NTT; candidate is the working tree after the change. This is a core-vs-core
comparison and does not use the vendored Kyber/PQClean AVX2 backends for the
candidate path.

NTT A/B, `200000` iterations, seven repeated runs:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_ntt_copy` | 282.43 | 218.08 | 1.295x | 1.299x |
| `mlkem_ntt_inplace` | 281.23 | 214.88 | 1.309x | 1.309x |

Stage A/B, `15000` iterations, nine repeated runs:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_noise_ntt` | 2338.51 | 2036.96 | 1.148x | 1.148x |
| `mlkem_core_stage_keygen_noise_ntt_encode` | 1978.44 | 1685.35 | 1.174x | 1.175x |
| `mlkem_core_stage_encrypt_noise_ntt` | 1017.34 | 829.42 | 1.227x | 1.226x |
| `mlkem_core_stage_encrypt_noise` | 1562.90 | 1365.65 | 1.144x | 1.145x |
| `mlkem_core_stage_decrypt_ntt_accum_recover` | 1216.85 | 1001.24 | 1.215x | 1.212x |
| `mlkem_core_stage_kpke_keygen_full` | 5577.64 | 5114.29 | 1.091x | 1.082x |
| `mlkem_core_stage_kpke_encrypt_cached` | 2878.11 | 2660.15 | 1.082x | 1.080x |
| `mlkem_core_stage_kpke_decrypt_cached` | 1286.62 | 1069.82 | 1.203x | 1.202x |

KEM A/B, `5000` iterations, nine repeated runs:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| keygen | 9721.46 | 9297.79 | 1.046x | 1.044x |
| encaps | 3119.01 | 2907.26 | 1.073x | 1.070x |
| decaps | 4422.83 | 4012.12 | 1.102x | 1.104x |
| roundtrip | 17321.16 | 16281.61 | 1.064x | 1.065x |

The change keeps the core path vendor-free. `ntt()` still uses the existing
scalar code for the first four forward stages, where the compiler already
handles the long contiguous butterflies well. It then switches to a local AVX2
tail helper for `log2len = 3, 2, 1`, batching the short butterflies into eight
32-bit lanes and using the existing NTT modular reduction formula in vector
form. This targets the previously expensive short-butterfly tail without
calling or modifying vendored Kyber/PQClean assembly.

### Independent Core Optimization A/B (2026-06-30, verified public-cache reuse)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`. Baseline
is commit `82f1b71` before reusing the public-key verification already done by
the `H(ek)` cache; candidate is the working tree after the change. This is a
core-vs-core comparison and does not use the vendored Kyber/PQClean AVX2
backends for the candidate path.

KEM A/B, `8000` iterations, thirteen repeated runs:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| keygen | 9732.78 | 9720.66 | 1.001x | 1.001x |
| encaps | 3138.86 | 3114.86 | 1.008x | 1.008x |
| decaps | 4422.47 | 4439.96 | 0.996x | 0.994x |
| roundtrip | 17363.69 | 17343.66 | 1.001x | 1.003x |

The change keeps the core path vendor-free. `mlkem_encaps()` already validates
the public-key bytes while checking or refreshing the `H(ek)` cache. The K-PKE
public cache now carries a generation number tied to that verified hash-cache
entry, so `kpke_encrypt()` can skip its second full public-key `memcmp()` only
when `mlkem_encaps()` passes a verified generation. Direct K-PKE calls and the
decapsulation re-encryption path still use the existing content comparison.

### Independent Core Optimization A/B (2026-06-30, sample-matrix x4 tail)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`. Baseline
is commit `9f8b1bb` before using the one-lane x4 sampler for the final public
matrix entry; candidate is the working tree after the change. This is a
core-vs-core comparison and does not use the vendored Kyber/PQClean AVX2
backends for the candidate path.

Stage A/B, `15000` iterations, nine repeated runs:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_matrix` | 2999.00 | 2935.08 | 1.022x | 1.022x |
| `mlkem_core_stage_kpke_keygen_full` | 5617.74 | 5532.68 | 1.015x | 1.015x |

KEM A/B, `5000` iterations, nine repeated runs:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| keygen | 9815.41 | 9737.01 | 1.008x | 1.005x |
| encaps | 3118.08 | 3151.27 | 0.990x | 1.008x |
| decaps | 4460.07 | 4437.65 | 1.005x | 0.992x |
| roundtrip | 17501.35 | 17384.44 | 1.007x | 1.004x |

The change keeps the core path vendor-free. `sample_matrix()` already used two
`sample_ntt4()` calls for eight of the nine public matrix polynomials, then fell
back to scalar `sample_ntt()` for `(2,2)`. The new `sample_ntt4_one()` path uses
`keccakf4()` with one live lane for that final polynomial and discards the other
three lanes. That replaces three scalar Keccak permutations in the tail with
three x4 permutations while preserving the scalar fallback if 504 squeezed bytes
do not produce enough rejection-sampling coefficients.

### Independent Core Optimization A/B (2026-06-30, fixed-length SHA3-512)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`. Baseline
is commit `202306b` before specializing SHA3-512 fixed input lengths; candidate
is the working tree after the change. This is a core-vs-core comparison and
does not use the vendored Kyber/PQClean AVX2 backends for the candidate path.

Keccak A/B, `200000` iterations, five repeated runs:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_sha3_512_32` | 205.80 | 200.33 | 1.027x | 1.028x |
| `mlkem_sha3_512_64` | 206.53 | 199.84 | 1.034x | 1.036x |

KEM A/B, `5000` iterations, seven repeated runs:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| keygen | 9813.09 | 9815.85 | 1.000x | 1.003x |
| encaps | 3126.36 | 3116.82 | 1.003x | 1.003x |
| decaps | 4440.51 | 4433.69 | 1.002x | 1.003x |
| roundtrip | 17439.53 | 17412.60 | 1.002x | 1.001x |

The change keeps the core path vendor-free. `sha3_512()` now has direct
fixed-length paths for the ML-KEM `32`-byte keygen seed hash and `64`-byte
`m || H(pk)` / `m' || H(pk)` hashes. Other input lengths still use the generic
`keccak_ctx` path. The stage suite was noisier than the direct Keccak and KEM
measurements, so the KEM rows above are the acceptance signal for this change.

### Independent Core Optimization A/B (2026-06-30, fixed-input PRF SHAKE256)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`. Baseline
is commit `accbc15` before adding the fixed-input PRF path; candidate is the
working tree after the change. This is a core-vs-core comparison and does not
use the vendored Kyber/PQClean AVX2 backends for the candidate path.

Keccak/sampling A/B, `200000` iterations, five repeated runs:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_prf_eta2` | 201.20 | 200.78 | 1.002x | 0.998x |
| `mlkem_sample_ntt_full` | 691.37 | 694.30 | 0.996x | 0.996x |

Stage A/B, `10000` iterations, five repeated runs:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_noise_prf_cbd` | 900.27 | 899.55 | 1.001x | 1.000x |
| `mlkem_core_stage_encrypt_noise_prf_cbd` | 1061.13 | 1060.04 | 1.001x | 1.001x |
| `mlkem_core_stage_encrypt_noise` | 1558.31 | 1550.16 | 1.005x | 1.005x |
| `mlkem_core_stage_kpke_keygen_full` | 5758.38 | 5633.06 | 1.022x | 1.002x |

KEM A/B, `5000` iterations, five repeated runs:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| keygen | 9832.26 | 9805.85 | 1.003x | 1.004x |
| encaps | 3163.56 | 3128.98 | 1.011x | 1.020x |
| decaps | 4444.91 | 4450.60 | 0.999x | 0.998x |
| roundtrip | 17658.89 | 17447.64 | 1.012x | 1.006x |

The change keeps the core path vendor-free. `mlkem_prf()` now routes the common
`dlen == 32` case through `shake256_32_suffix1()`, a fixed-input SHAKE256
one-shot for `seed[32] || nonce`. This avoids the generic `keccak_ctx` absorb
and squeeze bookkeeping for ML-KEM PRF calls while preserving the existing
generic path for other input lengths. Decapsulation is included for whole-KEM
context; this change does not add a decapsulation-specific fast path.

### Independent Core Optimization A/B (2026-06-30, sample NTT parse unroll)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`. Baseline
is commit `d3fdb3d` before widening the rejection-sampling parser; candidate is
the working tree after the change.

Keccak/sampling A/B, `200000` iterations, three repeated runs:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_sample_ntt_parse` | 106.11 | 98.92 | 1.073x | 1.062x |
| `mlkem_sample_ntt_full` | 696.66 | 691.16 | 1.008x | 1.006x |

Stage A/B, `10000` iterations, three repeated runs:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_matrix` | 3066.30 | 3000.57 | 1.022x | 1.023x |
| `mlkem_core_stage_kpke_keygen_full` | 5671.53 | 5608.24 | 1.011x | 1.012x |

KEM A/B, `5000` iterations, five repeated runs:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| keygen | 9897.53 | 9779.06 | 1.012x | 1.010x |
| encaps | 3128.94 | 3122.09 | 1.002x | 1.012x |
| decaps | 4433.31 | 4454.05 | 0.995x | 0.997x |
| roundtrip | 17519.52 | 17442.13 | 1.004x | 1.003x |

This change keeps `AVX2_BACKEND=core` independent from vendored Kyber/PQClean
sources. The direct implementation change is in `sample_ntt_parse_stream()`: it
adds a 12-byte fast path that handles eight 12-bit rejection candidates before
falling back to the existing 6-byte and 3-byte tails. The intended direct effect
is faster SHAKE128 rejection parsing, which flows into public matrix generation
and key generation. The decapsulation row is included for whole-binary context;
this change does not add a decapsulation-specific fast path.

### Independent Core Optimization A/B (2026-06-29, decaps scratch sizing)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`, `4000`
iterations, three repeated runs. Baseline is commit `41fb7f2` before reducing
the decapsulation re-encryption scratch buffer; candidate is the working tree
after the change.

KEM A/B:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| keygen | 10225.57 | 9837.99 | 1.039x | 1.017x |
| encaps | 3246.73 | 3113.91 | 1.043x | 1.022x |
| decaps | 4460.41 | 4433.80 | 1.006x | 1.008x |
| roundtrip | 17940.94 | 17433.89 | 1.029x | 1.039x |

This change keeps `AVX2_BACKEND=core` independent from vendored Kyber/PQClean
sources. The direct implementation change is in `mlkem_decaps()`: the
re-encryption comparison buffer now uses the exact ML-KEM-768 ciphertext size
instead of a 4096-byte scratch array, and the fallback `z||c` stack buffer
reuses the same bound. The intended direct effect is on decapsulation stack
pressure; keygen and encaps shifts are included for whole-binary context and may
include code-layout noise rather than a semantic fast path.

### Independent Core Optimization A/B (2026-06-29, self AVX2 matrix 3-block squeeze)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`, `10000`
iterations. Baseline is commit `cf77e89` before reducing the self-AVX2
`sample_ntt4()` squeeze depth; candidate is the working tree after the change.

Stage A/B:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_matrix` | 3197.34 | 3085.18 | 1.037x | 1.045x |
| `mlkem_core_stage_kpke_keygen_full` | 5818.30 | 5756.45 | 1.012x | 1.026x |
| `mlkem_core_stage_kpke_encrypt_cached` | 2883.96 | 2883.71 | 1.000x | 1.001x |
| `mlkem_core_stage_kpke_decrypt_cached` | 1281.15 | 1283.75 | 0.998x | 1.000x |

KEM A/B:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| keygen | 10278.16 | 9852.42 | 1.043x | 1.044x |
| encaps | 3136.65 | 3121.44 | 1.005x | 1.007x |
| decaps | 4451.23 | 4467.32 | 0.997x | 0.994x |
| roundtrip | 17914.36 | 17496.49 | 1.024x | 1.026x |

This change keeps `AVX2_BACKEND=core` independent from vendored Kyber/PQClean
sources. The self-AVX2 `sample_ntt4()` path now squeezes three SHAKE128 blocks
per lane, matching the scalar fast path, and falls back to scalar `sample_ntt()`
for any lane that does not collect 256 accepted coefficients. The existing
`bench_core_stages` validation still checks `sample_matrix()` against scalar
`sample_ntt()` for all 3x3 public-matrix entries.

### Independent Core Optimization A/B (2026-06-29, self AVX2 matrix scalar tail)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`, `10000`
iterations. Baseline is commit `9f38b65` before replacing the final dummy
4-way matrix-sampling group; candidate is the working tree after the change.

Stage A/B:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_matrix` | 3669.88 | 3199.08 | 1.147x | 1.147x |
| `mlkem_core_stage_kpke_keygen_full` | 6271.91 | 5815.60 | 1.079x | 1.078x |
| `mlkem_core_stage_kpke_encrypt_cached` | 2878.40 | 2879.97 | 1.000x | 0.999x |
| `mlkem_core_stage_kpke_decrypt_cached` | 1278.83 | 1281.96 | 0.998x | 0.996x |

KEM A/B:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| keygen | 10783.15 | 10293.47 | 1.048x | 1.048x |
| encaps | 3124.38 | 3134.52 | 0.997x | 0.990x |
| decaps | 4471.38 | 4458.72 | 1.003x | 1.007x |
| roundtrip | 18463.36 | 17937.85 | 1.029x | 1.030x |

This change keeps `AVX2_BACKEND=core` independent from vendored Kyber/PQClean
sources. The previous self-AVX2 `sample_matrix()` implementation used three
4-way groups for nine public-matrix entries, so the final group computed three
dummy lanes. The new path uses two 4-way groups for the first eight entries and
the existing scalar `sample_ntt()` for the final `(2,2)` entry.

### Independent Core Optimization A/B (2026-06-29, self AVX2 PRF/CBD batching)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`, `10000`
iterations. Baseline is commit `d727e29` before the self-contained AVX2
PRF/CBD batching path; candidate is the working tree after the change.

Stage A/B:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_noise_ntt` | 3332.24 | 2343.49 | 1.422x | 1.407x |
| `mlkem_core_stage_encrypt_noise` | 2666.39 | 1557.42 | 1.712x | 1.694x |
| `mlkem_core_stage_kpke_keygen_full` | 6990.11 | 6286.27 | 1.112x | 1.112x |
| `mlkem_core_stage_kpke_encrypt_cached` | 3934.03 | 2883.88 | 1.364x | 1.364x |
| `mlkem_core_stage_kpke_decrypt_cached` | 1283.36 | 1283.18 | 1.000x | 1.001x |

KEM A/B:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| keygen | 11509.01 | 10795.24 | 1.066x | 1.067x |
| encaps | 4181.44 | 3122.91 | 1.339x | 1.335x |
| decaps | 5511.92 | 4466.50 | 1.234x | 1.234x |
| roundtrip | 21317.48 | 18452.40 | 1.155x | 1.156x |

This change keeps `AVX2_BACKEND=core` independent from vendored Kyber/PQClean
sources. It reuses the local Keccak-f[1600]x4 helper for SHAKE256
`seed||nonce` PRF calls, then feeds each lane through the existing eta2 CBD
conversion. The stage benchmark validates the x4 PRF/CBD output against the
existing scalar `mlkem_prf()` + `sample_poly_cbd()` path. Decapsulation also
improves because ML-KEM decapsulation performs a re-encryption check, so faster
core `kpke_encrypt()` reduces part of decapsulation time.

### Independent Core Optimization A/B (2026-06-29, self AVX2 matrix sampling)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`, `10000`
iterations. Baseline is commit `c0724d0` before the self-contained AVX2
`sample_matrix()` path; candidate is the working tree after the change.

Stage A/B:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_matrix` | 6513.23 | 3527.90 | 1.846x | 1.848x |
| `mlkem_core_stage_kpke_keygen_full` | 9953.54 | 6971.59 | 1.428x | 1.432x |
| `mlkem_core_stage_kpke_encrypt_cached` | 3928.43 | 3957.67 | 0.993x | 0.993x |
| `mlkem_core_stage_kpke_decrypt_cached` | 1280.98 | 1285.86 | 0.996x | 0.996x |

KEM A/B:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| keygen | 14254.92 | 11482.58 | 1.241x | 1.242x |
| encaps | 4185.75 | 4209.25 | 0.995x | 1.001x |
| decaps | 5517.25 | 5521.59 | 0.999x | 1.000x |
| roundtrip | 24091.62 | 21260.86 | 1.133x | 1.133x |

This change keeps `AVX2_BACKEND=core` independent from vendored Kyber/PQClean
sources. It adds a local AVX2 Keccak-f[1600]x4 helper and uses it only for
public matrix sampling, with the scalar `sample_ntt()` path retained as the
fallback and as the correctness reference. A direct matrix check confirmed that
the AVX2 `sample_matrix()` output matches the existing scalar `sample_ntt()`
output for all 3x3 public-matrix entries.

### Independent Core Optimization A/B (2026-06-29, public cache seed)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`, `1000`
iterations. Baseline is commit `e4a2768` before keygen seeded the core public
cache; candidate is the working tree after the cache change.

| Metric | Baseline ns/op | Candidate ns/op | Speedup |
|---|---:|---:|---:|
| keygen | 43795.84 | 44668.08 | 0.980x |
| encaps | 14681.88 | 14697.27 | 0.999x |
| decaps | 18064.43 | 18031.20 | 1.002x |
| roundtrip | 110320.24 | 76410.00 | 1.444x |

This optimization stores only public-key-derived data produced during core
keygen: the expanded public matrix cache, decoded public key vector, and
`H(pk)`. It mainly improves keygen->encaps->decaps roundtrip workloads by
avoiding a second SHAKE128 matrix expansion and duplicate `H(pk)` after keygen.

Post-change profiling (`4000` iterations, `-pg`) still shows `keccakf` as the
largest core hotspot, followed by `kpke_encrypt` arithmetic/packing work.

### Independent Core Optimization A/B (2026-06-29, Keccak and compression)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`, `2000`
iterations. Baseline is commit `e60405f` before the core Keccak/compression
changes; candidate is the working tree after the change.

| Metric | Baseline ns/op | Candidate ns/op | Speedup |
|---|---:|---:|---:|
| keygen | 45209.09 | 23544.19 | 1.920x |
| encaps | 14721.15 | 11684.66 | 1.260x |
| decaps | 18107.28 | 15175.22 | 1.193x |
| roundtrip | 78151.01 | 50586.39 | 1.545x |

This keeps the implementation vendor-free in `AVX2_BACKEND=core`. The change
unrolls the scalar Keccak-f theta/chi steps and replaces ML-KEM-768 compression
integer division for `d=10` and `d=4` with exact reciprocal multiplication.

Post-change profiling (`4000` iterations, `-pg`) shows `kpke_encrypt` as the
largest hotspot (`45.65%` self time), with `keccakf` reduced to `23.91%`.

### Independent Core Optimization A/B (2026-06-29, NTT arithmetic)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`, `3000`
iterations. Baseline is commit `b4525ba` before the core NTT/decode changes;
candidate is the working tree after the change.

| Metric | Baseline ns/op | Candidate ns/op | Speedup |
|---|---:|---:|---:|
| keygen | 23920.30 | 23673.88 | 1.010x |
| encaps | 11682.40 | 7654.28 | 1.526x |
| decaps | 15103.63 | 9994.34 | 1.511x |
| roundtrip | 50568.64 | 41112.24 | 1.230x |

The change keeps the core path vendor-free and relies on canonical coefficient
ranges (`0..Q-1`) to use unsigned modular arithmetic in `ntt()`, `ntt_inv()`,
and `ntt_mul()`. It also uses one-pass ciphertext decode/decompress for the
ML-KEM-768 `d=10` and `d=4` paths.

Post-change profiling (`6000` iterations, `-pg`) shows `keccakf` as the largest
hotspot again (`38.18%` self time), followed by `kpke_encrypt` (`27.27%`) and
`bench_keygen` (`23.64%`).

### Independent Core Optimization A/B (2026-06-29, matrix sampling)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`, `10000`
iterations. Baseline is commit `e79ab72` before the core matrix sampling change;
candidate is the working tree after the change.

| Metric | Baseline ns/op | Candidate ns/op | Speedup |
|---|---:|---:|---:|
| keygen | 22978.35 | 17805.09 | 1.291x |
| encaps | 7667.25 | 7616.26 | 1.007x |
| decaps | 10039.63 | 10022.49 | 1.002x |
| roundtrip | 40805.76 | 35575.62 | 1.147x |

The change keeps the core path vendor-free. `sample_ntt()` now squeezes `504`
bytes in the first SHAKE128 pass, which is the largest multiple of 3 that still
fits in three SHAKE128 rate blocks, and continues squeezing from the same XOF
state if rejection sampling needs more candidates instead of rehashing a large
fallback buffer.

Post-change profiling (`6000` iterations, `-pg`) shows `kpke_encrypt` as the
largest hotspot (`35.56%` self time), followed by `bench_keygen` (`24.44%`) and
`keccakf` (`20.00%`).

### Independent Core Optimization A/B (2026-06-29, NTT multiply-add)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`, `5000`
iterations. Baseline is commit `f593418` before the core NTT multiply-add
change; candidate is the working tree after the change.

| Metric | Baseline ns/op | Candidate ns/op | Speedup |
|---|---:|---:|---:|
| keygen | 17559.83 | 17592.06 | 0.998x |
| encaps | 7640.86 | 7617.97 | 1.003x |
| decaps | 9955.60 | 9813.80 | 1.014x |
| roundtrip | 35314.36 | 35111.03 | 1.006x |

The change keeps the core path vendor-free. It fuses NTT-domain base
multiplication and accumulation so the common `ntt_mul()` followed by
`ntt_add()` pattern no longer writes a temporary polynomial and then scans it
again for accumulation. The expected gain is small because Keccak, keygen
matrix sampling, and inverse NTT work remain larger costs.

### Independent Core Optimization A/B (2026-06-29, Keccak absorb lanes)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`, `10000`
iterations. Baseline is commit `169c485` before the core Keccak absorb
change; candidate is the working tree after the change.

| Metric | Baseline ns/op | Candidate ns/op | Speedup |
|---|---:|---:|---:|
| keygen | 17571.54 | 17191.94 | 1.022x |
| encaps | 7624.06 | 7569.86 | 1.007x |
| decaps | 9779.67 | 9782.07 | 1.000x |
| roundtrip | 35152.39 | 34728.53 | 1.012x |

The change keeps the core path vendor-free. `keccak_absorb()` now XORs aligned
input chunks into the Keccak state as explicit little-endian 64-bit lanes,
falling back to byte-wise absorption only for tail bytes. This reduces absorb
overhead for SHA3/SHAKE calls used by public-key hashing, PRF output, and
matrix sampling without changing the permutation count or using an external
Keccak implementation.

Post-change profiling (`6000` iterations, `-pg`) shows `kpke_encrypt` as the
largest hotspot (`36.17%` self time), followed by `keccakf` (`27.66%`),
`bench_keygen` (`17.02%`), and `ntt_inv` (`8.51%`).

### Independent Core Optimization A/B (2026-06-29, fixed Keccak seed absorb)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`, `10000`
iterations per run, `6` order-flipped baseline/candidate pairs. Baseline is
commit `1dff1c1` before the fixed-size Keccak seed absorb change; candidate is
the working tree after the change.

| Metric | Baseline mean ns/op | Candidate mean ns/op | Speedup |
|---|---:|---:|---:|
| keygen | 17631.49 | 17538.97 | 1.005x |
| encaps | 7636.27 | 7620.70 | 1.002x |
| decaps | 9840.08 | 9777.58 | 1.006x |
| roundtrip | 35191.61 | 34759.01 | 1.012x |

The change keeps the core path vendor-free. It adds fixed-size Keccak absorb
helpers for the ML-KEM `seed[32] || suffix` hot paths: PRF input
`data[32] || nonce` and matrix sampling input `rho[32] || i || j`. These
helpers absorb the four 64-bit seed lanes directly and write suffix bytes into
the state, avoiding temporary stack buffers and generic absorb loops for these
common cases.

Post-change profiling (`6000` iterations, `-pg`) shows `keccakf` as the largest
hotspot (`38.30%` self time), followed by `kpke_encrypt` (`27.66%`),
`bench_keygen` (`14.89%`), and `ntt_inv` (`6.38%`).

### Independent Core Optimization A/B (2026-06-29, Keccak Chi unroll)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`, `10000`
iterations per run, `6` order-flipped baseline/candidate pairs. Baseline is
commit `bae2cf6` before the Keccak Chi row unroll; candidate is the working
tree after the change.

| Metric | Baseline mean ns/op | Candidate mean ns/op | Speedup |
|---|---:|---:|---:|
| keygen | 17517.17 | 17500.41 | 1.001x |
| encaps | 7590.49 | 7563.94 | 1.004x |
| decaps | 9773.82 | 9763.25 | 1.001x |
| roundtrip | 34814.28 | 34692.20 | 1.004x |

The change keeps the core path vendor-free. It unrolls the five Keccak Chi
rows inside each Keccak-f round, removing the small row loop while keeping the
Rho/Pi loop unchanged because a prior Rho/Pi unroll trial did not produce a
stable speedup.

Post-change profiling (`6000` iterations, `-pg`) still shows `keccakf` as the
largest hotspot (`33.33%` self time), followed by `kpke_encrypt` (`26.67%`),
`bench_keygen` (`22.22%`), and `ntt_inv` (`6.67%`).

### Independent Core Optimization A/B (2026-06-29, Keccak Rho/Pi-Chi fusion)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`, `10000`
iterations per run, `6` order-flipped baseline/candidate pairs. Baseline is
commit `7a51a11` before fusing the Keccak Rho/Pi and Chi steps; candidate is
the working tree after the change.

| Metric | Baseline mean ns/op | Candidate mean ns/op | Speedup |
|---|---:|---:|---:|
| keygen | 17521.90 | 17521.01 | 1.000x |
| encaps | 7592.51 | 7571.39 | 1.003x |
| decaps | 9771.02 | 9768.95 | 1.000x |
| roundtrip | 34816.60 | 34700.54 | 1.003x |

The change keeps the core path vendor-free. It removes the Keccak Rho/Pi
lookup-table loop and computes the Rho/Pi lanes into temporaries that feed Chi
directly, avoiding a full intermediate store/load of the 25-lane state array.
The old `rho`/`pi` tables are no longer needed.

Post-change profiling (`6000` iterations, `-pg`) shows `kpke_encrypt` as the
largest hotspot (`43.18%` self time), followed by `keccakf` (`25.00%`),
`bench_keygen` (`13.64%`), and `ntt_inv` (`6.82%`).

### Independent Core Optimization A/B (2026-06-29, decrypt message packing)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`, `10000`
iterations per run, `6` order-flipped baseline/candidate pairs. Baseline is
commit `f1a3304` before byte-wise message packing in core decrypt; candidate is
the working tree after the change.

| Metric | Baseline mean ns/op | Candidate mean ns/op | Speedup |
|---|---:|---:|---:|
| keygen | 17559.73 | 17471.24 | 1.005x |
| encaps | 7624.15 | 7614.90 | 1.001x |
| decaps | 9771.52 | 9663.16 | 1.011x |
| roundtrip | 34742.23 | 34626.30 | 1.003x |

The change keeps the core path vendor-free. Core decrypt now builds each
recovered message byte in a local `uint8_t` and stores it once, instead of
zeroing `out_m` and updating it bit-by-bit with repeated read-modify-write
operations. The polynomial subtraction path remains unchanged.

Post-change profiling (`6000` iterations, `-pg`) shows `keccakf` and
`kpke_encrypt` tied as the largest hotspots (`36.96%` self time each), followed
by `bench_keygen` (`19.57%`) and `ntt_inv` (`6.52%`).

### Independent Core Optimization A/B (2026-06-29, keygen copy reduction)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`, `10000`
iterations per run, `6` order-flipped baseline/candidate pairs. Baseline is
commit `2cfe8d3` before reducing copies in core keygen; candidate is the
working tree after the change.

| Metric | Baseline mean ns/op | Candidate mean ns/op | Speedup |
|---|---:|---:|---:|
| keygen | 17465.92 | 17432.68 | 1.002x |
| encaps | 7607.48 | 7561.26 | 1.006x |
| decaps | 9674.95 | 9628.41 | 1.005x |
| roundtrip | 34691.89 | 34505.16 | 1.005x |

The change keeps the core path vendor-free. Core keygen now references the
`rho` and `sigma` halves directly from the SHA3-512 output, encodes `shat[i]`
while it is hot after NTT, and writes `sum + ehat[i]` directly to `that[i]`
instead of updating `accum` and copying a whole polynomial.

Post-change profiling (`6000` iterations, `-pg`) shows `keccakf` as the largest
hotspot (`34.69%` self time), followed by `kpke_encrypt` (`32.65%`),
`bench_keygen` (`18.37%`), and `ntt_inv` (`8.16%`).

### Independent Core Optimization A/B (2026-06-29, direct keygen output)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`, `10000`
iterations per run, `6` order-flipped baseline/candidate pairs. Baseline is
commit `038d095` before writing core keygen output directly into the final
`ek`/`dk` buffers; candidate is the working tree after the change.

| Metric | Baseline mean ns/op | Candidate mean ns/op | Speedup |
|---|---:|---:|---:|
| keygen | 17223.21 | 16656.63 | 1.034x |
| encaps | 7582.34 | 7593.90 | 0.998x |
| decaps | 9644.59 | 9642.77 | 1.000x |
| roundtrip | 34569.76 | 34038.84 | 1.016x |

The change keeps the core path vendor-free. Core `mlkem_keygen()` now passes the
final public-key and secret-key output regions directly to `kpke_keygen()`, and
uses input seed pointers directly when deterministic seeds are provided. This
removes the stack-local `ek_pke`/`dk_pke` staging buffers and the duplicate
copies into `ek` and the first `dk` segment.

Post-change profiling (`6000` iterations, `-pg`) shows `keccakf` and
`kpke_encrypt` tied as the largest hotspots (`30.43%` self time each), followed
by `bench_keygen` (`21.74%`), `bench_decaps` (`8.70%`), and `ntt_inv` (`6.52%`).

### Independent Core Optimization A/B (2026-06-29, encrypt mu initialization)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`, `10000`
iterations per run, `6` order-flipped baseline/candidate pairs. Baseline is
commit `b1b7d8c` before removing redundant core `mu` zeroing; candidate is the
working tree after the change.

| Metric | Baseline mean ns/op | Candidate mean ns/op | Speedup |
|---|---:|---:|---:|
| keygen | 16683.25 | 16652.77 | 1.002x |
| encaps | 7582.13 | 7565.66 | 1.002x |
| decaps | 9647.19 | 9640.53 | 1.001x |
| roundtrip | 34014.27 | 33973.02 | 1.001x |

The change keeps the core path vendor-free. Core `kpke_encrypt()` no longer
clears the full `mu` polynomial before the standard `mlen == 32` path, because
that path immediately writes all 256 coefficients from the message bits. The
zero-fill remains for non-standard message lengths.

Post-change profiling (`6000` iterations, `-pg`) shows `kpke_encrypt` as the
largest hotspot (`34.78%` self time), followed by `bench_keygen` (`26.09%`),
`keccakf` (`19.57%`), and `ntt_inv`/`bench_decaps` (`8.70%` each).

### Independent Core Optimization A/B (2026-06-29, fused NTT accumulation)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`, `10000`
iterations per run, `6` order-flipped baseline/candidate pairs. Baseline is
commit `9af3c4b` before fusing the fixed K=3 NTT-domain multiply accumulation;
candidate is the working tree after the change.

| Metric | Baseline mean ns/op | Candidate mean ns/op | Speedup |
|---|---:|---:|---:|
| keygen | 16693.45 | 16271.72 | 1.026x |
| encaps | 7585.22 | 6123.82 | 1.239x |
| decaps | 9685.53 | 8192.53 | 1.182x |
| roundtrip | 34101.29 | 30704.09 | 1.111x |

The change keeps the core path vendor-free. Core keygen and encryption now use a
K=3-specific `ntt_mul_acc3()` helper for fixed three-term products, replacing
three separate `ntt_mul_add()` passes plus an `accum` zero-fill. The helper
computes the three base multiplications in one loop and writes the accumulated
polynomial directly. Generic `ntt_mul_add()` remains for non-fused callers.

A longer confirmation run (`20000` iterations, `4` order-flipped pairs) showed
`1.023x` keygen, `1.250x` encaps, `1.186x` decaps, and `1.113x` roundtrip
speedups.

Post-change profiling (`6000` iterations, `-pg`) shows `bench_keygen` as the
largest hotspot (`37.50%` self time), followed by `kpke_encrypt` (`25.00%`),
`keccakf` (`20.00%`), and `ntt_inv` (`15.00%`).

### Independent Core Optimization A/B (2026-06-29, fused decrypt accumulation)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`, `10000`
iterations per run, `6` order-flipped baseline/candidate pairs. Baseline is
commit `f07a5af` before applying fused K=3 NTT accumulation to core decrypt;
candidate is the working tree after the change.

| Metric | Baseline mean ns/op | Candidate mean ns/op | Speedup |
|---|---:|---:|---:|
| keygen | 16335.04 | 16306.54 | 1.002x |
| encaps | 6104.78 | 6099.68 | 1.001x |
| decaps | 8224.53 | 7909.43 | 1.040x |
| roundtrip | 30788.12 | 30425.87 | 1.012x |

The change keeps the core path vendor-free. Core decrypt now transforms all
three `u[i]` polynomials to NTT form first, then uses the existing
`ntt_mul_acc3()` helper to accumulate `s-hat[i] * ntt(u[i])` in one loop instead
of three separate `ntt_mul_add()` passes plus an `accum` zero-fill.

A longer confirmation run (`20000` iterations, `4` order-flipped pairs) showed
`1.036x` decaps and `1.009x` roundtrip speedups.

Post-change profiling (`6000` iterations, `-pg`) shows `keccakf` as the largest
hotspot (`47.50%` self time), followed by `ntt_inv` (`17.50%`), `bench_keygen`
(`15.00%`), and `kpke_encrypt` (`10.00%`).

### Independent Core Optimization A/B (2026-06-29, keygen factored NTT accumulation)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`, `10000`
iterations per run, `6` order-flipped baseline/candidate pairs. Baseline is
commit `7a7be87` before factoring the fixed K=3 keygen NTT accumulation;
candidate is the working tree after the change.

| Metric | Baseline mean ns/op | Candidate mean ns/op | Speedup |
|---|---:|---:|---:|
| keygen | 16300.96 | 16057.68 | 1.015x |
| encaps | 6117.68 | 6099.43 | 1.003x |
| decaps | 7929.46 | 7984.63 | 0.993x |
| roundtrip | 30461.96 | 30262.68 | 1.007x |

The change keeps the core path vendor-free. Core keygen now uses
`ntt_mul_acc3_factored_gamma()` for the fixed K=3 `that[i]` accumulation, so the
three high-lane products are summed first and multiplied by `GAMMA[i]` once.
This reduces two `GAMMA` multiplications per base pair in the keygen hot path.

The factored helper is intentionally limited to keygen. Applying the same shape
globally to encryption/decryption was measured separately and regressed
roundtrip performance, so those paths continue to use the original
`ntt_mul_acc3()` helper.

A longer confirmation run (`20000` iterations, `4` order-flipped pairs) showed
`1.019x` keygen, `1.001x` encaps, `0.999x` decaps, and `1.005x` roundtrip
speedups.

Post-change profiling (`6000` iterations, `-pg`) shows `keccakf` as the largest
hotspot (`38.46%` self time), followed by `bench_keygen` (`28.21%`),
`kpke_encrypt` (`17.95%`), `ntt_inv` (`7.69%`), and `sample_poly_cbd`
(`5.13%`).

### Independent Core Optimization A/B (2026-06-29, in-place NTT copy elision)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`, `10000`
iterations per run, `6` order-flipped baseline/candidate pairs. Baseline is
commit `bcabe96` before skipping the in-place `ntt()` copy; candidate is the
working tree after the change.

| Metric | Baseline mean ns/op | Candidate mean ns/op | Speedup |
|---|---:|---:|---:|
| keygen | 16045.74 | 16054.53 | 0.999x |
| encaps | 6109.82 | 6117.85 | 0.999x |
| decaps | 7935.27 | 7918.81 | 1.002x |
| roundtrip | 30257.12 | 30210.44 | 1.002x |

The change keeps the core path vendor-free. Core `ntt()` now skips the initial
`memcpy()` when the input and output polynomial are the same object. This avoids
redundant 512-byte copies in the in-place keygen/encryption NTT calls while
leaving out-of-place decrypt NTT calls unchanged.

The standard run was mostly noise-sized, so the change was accepted only after a
longer confirmation run (`20000` iterations, `4` order-flipped pairs) showed
`1.007x` keygen, `1.001x` encaps, `1.001x` decaps, and `1.001x` roundtrip
speedups.

Post-change profiling (`6000` iterations, `-pg`) shows `keccakf` as the largest
hotspot (`55.00%` self time), followed by `kpke_encrypt` and `bench_keygen`
(`15.00%` each), `ntt_inv` (`10.00%`), and `sample_poly_cbd` (`5.00%`).

### Independent Core Optimization A/B (2026-06-29, fused inverse NTT post-processing)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`, `10000`
iterations per run, `6` order-flipped baseline/candidate pairs. Baseline is
commit `25ba3b4` before fusing inverse NTT post-processing; candidate is the
working tree after the change.

| Metric | Baseline mean ns/op | Candidate mean ns/op | Speedup |
|---|---:|---:|---:|
| keygen | 16045.72 | 16065.14 | 0.999x |
| encaps | 6122.87 | 6042.16 | 1.013x |
| decaps | 7918.21 | 7878.40 | 1.005x |
| roundtrip | 30225.15 | 30140.91 | 1.003x |

The change keeps the core path vendor-free. Core encryption and decryption now
use inverse-NTT variants that fuse the final `3303` scaling pass with the
immediately following polynomial add/subtract work: `+e1[i]` for `u[i]`,
`+e2+mu` for `v`, and `v - invntt(...)` in decrypt. This removes separate full
polynomial scans after inverse NTT without changing the transform itself or
calling any vendored AVX2 implementation.

A longer confirmation run (`20000` iterations, `4` order-flipped pairs) showed
`1.003x` keygen, `1.010x` encaps, `1.008x` decaps, and `1.003x` roundtrip
speedups.

Post-change profiling (`6000` iterations, `-pg`) shows `keccakf` as the largest
hotspot (`32.50%` self time), followed by `kpke_encrypt` and `bench_keygen`
(`25.00%` each), `bench_decaps` (`10.00%`), and `sample_poly_cbd` (`5.00%`).

### Independent Core Optimization A/B (2026-06-29, local-lane Keccak-f)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`, `10000`
iterations per run, `6` order-flipped baseline/candidate pairs. Baseline is
commit `b7f3187` before keeping Keccak-f lanes in local variables; candidate is
the working tree after the change.

| Metric | Baseline mean ns/op | Candidate mean ns/op | Speedup |
|---|---:|---:|---:|
| keygen | 16182.12 | 15899.05 | 1.018x |
| encaps | 6053.80 | 6023.31 | 1.005x |
| decaps | 7867.96 | 7856.80 | 1.001x |
| roundtrip | 30146.94 | 29949.42 | 1.007x |

The change keeps the core path vendor-free. `keccakf()` now loads the 25 state
lanes into local variables, runs all 24 rounds on those lanes, and stores them
back once at the end. The Rho/Pi/Chi mapping is unchanged; the goal is to avoid
round-by-round traffic through the state array in the independent scalar core.

A longer confirmation run (`20000` iterations, `6` order-flipped pairs) showed
average speedups of `1.012x` keygen, `1.002x` encaps, `1.004x` decaps, and
`1.008x` roundtrip. The same run's median speedups were `1.010x` keygen,
`1.005x` encaps, `1.004x` decaps, and `1.008x` roundtrip.

Post-change profiling (`6000` iterations, `-pg`) shows `keccakf` and
`kpke_encrypt` tied as the largest hotspots (`35.90%` self time each), followed
by `bench_keygen` (`17.95%`), `sample_poly_cbd` (`5.13%`), and `sha3_512` /
`bench_decaps` (`2.56%` each).

### Independent Core Optimization A/B (2026-06-29, pointer-based matrix parser)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`, `20000`
iterations per run, `6` order-flipped baseline/candidate pairs. Baseline is
commit `cb7b22d` before using a pointer-based `sample_ntt()` parser; candidate
is the working tree after the parser change.

| Metric | Baseline mean ns/op | Candidate mean ns/op | Speedup |
|---|---:|---:|---:|
| keygen | 15887.98 | 15761.82 | 1.008x |
| encaps | 6030.73 | 6017.40 | 1.002x |
| decaps | 7846.17 | 7845.09 | 1.000x |
| roundtrip | 29903.36 | 29774.31 | 1.004x |

The median speedups from the same run were `1.007x` keygen, `1.003x`
encaps, `1.000x` decaps, and `1.004x` roundtrip.

The change keeps the core path vendor-free. `sample_ntt_parse_stream()` now
tracks the output polynomial with a moving pointer and end pointer instead of
recomputing `out[count]` on every accepted rejection-sampling coefficient. This
targets the SHAKE128 matrix expansion used by core keygen; repeated encaps and
decaps runs mostly reuse the public-key cache, so the expected direct gain there
is small.

Post-change profiling (`6000` iterations, `-pg`) shows `kpke_encrypt` as the
largest hotspot (`35.90%` self time), followed by `keccakf` (`33.33%`),
`bench_keygen` (`25.64%`), and `bench_decaps` (`5.13%`).

### Independent Core Optimization A/B (2026-06-29, unrolled matrix parser)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`, `20000`
iterations per run, `6` order-flipped baseline/candidate pairs. Baseline is
commit `a31caba` before unrolling the `sample_ntt()` rejection parser; candidate
is the working tree after the parser unroll.

| Metric | Baseline mean ns/op | Candidate mean ns/op | Speedup |
|---|---:|---:|---:|
| keygen | 15747.90 | 15560.44 | 1.012x |
| encaps | 6006.29 | 5997.74 | 1.001x |
| decaps | 7834.60 | 7849.31 | 0.998x |
| roundtrip | 29716.41 | 29585.98 | 1.004x |

The median speedups from the same run were `1.011x` keygen, `1.003x`
encaps, `0.999x` decaps, and `1.007x` roundtrip.

The change keeps the core path vendor-free. `sample_ntt_parse_stream()` now
walks the input stream with a pointer and handles two 3-byte rejection-sampling
groups per loop before falling back to the final single group. This reduces loop
branch and index overhead in the SHAKE128 matrix expansion used by core keygen.
Repeated encaps and decaps mostly use cached public-key state, so the direct
benefit is expected to show primarily in keygen and full roundtrip timings.

Post-change profiling (`6000` iterations, `-pg`) shows `keccakf` as the largest
hotspot (`35.90%` self time), followed by `kpke_encrypt` (`23.08%`),
`sample_ntt` (`15.38%`), `bench_keygen` (`12.82%`), and `sample_poly_cbd` /
`bench_decaps` (`5.13%` each).

### Independent Core Optimization A/B (2026-06-29, inverse NTT reduction)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`, `20000`
iterations per run, `6` order-flipped baseline/candidate pairs. Baseline is
commit `a58ba15` before replacing inverse-NTT `% Q` reductions; candidate is
the working tree after the inverse reduction change.

| Metric | Baseline mean ns/op | Candidate mean ns/op | Speedup |
|---|---:|---:|---:|
| keygen | 15574.72 | 15546.48 | 1.002x |
| encaps | 6022.97 | 5839.23 | 1.032x |
| decaps | 7824.35 | 7667.85 | 1.020x |
| roundtrip | 29505.66 | 29175.24 | 1.011x |

The median speedups from the same run were `1.002x` keygen, `1.034x`
encaps, `1.019x` decaps, and `1.012x` roundtrip.

The change keeps the core path vendor-free. It adds a small scalar reduction
for inverse NTT product ranges: for `0 <= x <= 3328*3328`, `q=(x*315)>>20`
followed by one negative correction exactly matches `x % 3329`. This replaces
`% Q` only in `ntt_inv()` and the fused inverse-NTT helpers. The forward
`ntt()` path remains on the compiler-generated constant modulo because applying
the same reduction there was slower in microbenchmarks.

NTT microbench A/B (`200000` iterations per run, `6` order-flipped pairs)
showed the direct helper-level effect: average speedups were `1.147x` for
`ntt_inv`, `1.148x` for `ntt_inv_add`, `1.138x` for `ntt_inv_add2`, and
`1.138x` for `ntt_inv_sub_from`; `ntt_copy` and `ntt_inplace` stayed
effectively flat.

Post-change profiling (`6000` iterations, `-pg`) shows `keccakf` as the largest
hotspot (`37.84%` self time), followed by `kpke_encrypt` (`24.32%`),
`sample_ntt` (`16.22%`), `bench_keygen` (`13.51%`), and `sample_poly_cbd`
(`5.41%`).

### Independent Core Optimization A/B (2026-06-29, matrix parser fast path)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`, `20000`
iterations per run, `6` order-flipped baseline/candidate pairs. Baseline is
commit `00bcff9` before reducing `sample_ntt()` parser end checks; candidate is
the working tree after the parser fast path.

| Metric | Baseline mean ns/op | Candidate mean ns/op | Speedup |
|---|---:|---:|---:|
| keygen | 15577.97 | 15472.22 | 1.007x |
| encaps | 5861.56 | 5819.30 | 1.007x |
| decaps | 7697.83 | 7694.86 | 1.000x |
| roundtrip | 29204.80 | 29094.79 | 1.004x |

The median speedups from the same run were `1.008x` keygen, `1.008x`
encaps, `1.000x` decaps, and `1.003x` roundtrip.

The change keeps the core path vendor-free. `sample_ntt_parse_stream()` now
uses a fast path while at least four output coefficients remain, so the common
two-group parser loop no longer checks the output end after each accepted
coefficient. The existing checked parser tail still handles the final few
coefficients safely. The direct benefit is expected mostly in keygen and full
roundtrip workloads because keygen expands the public matrix with SHAKE128
rejection sampling.

Post-change profiling (`6000` iterations, `-pg`) shows `keccakf` as the largest
hotspot (`38.46%` self time), followed by `kpke_encrypt` (`33.33%`),
`sample_ntt` (`10.26%`), `bench_keygen` (`7.69%`), and `sample_poly_cbd` /
`bench_decaps` (`5.13%` each).

### Independent Core Optimization A/B (2026-06-29, 32-bit NTT accumulation)

Snapshot command shape: pinned CPU, `clang`, `AVX2_BACKEND=core`, `10000`
iterations per run, `6` order-flipped baseline/candidate pairs. Baseline is
commit `379e294` before reducing the core K=3 NTT accumulation range; candidate
is the working tree after the reduction change.

| Metric | Baseline mean ns/op | Candidate mean ns/op | Speedup |
|---|---:|---:|---:|
| keygen | 15501.88 | 14263.57 | 1.087x |
| encaps | 5886.14 | 4194.76 | 1.403x |
| decaps | 7649.31 | 5494.93 | 1.392x |
| roundtrip | 29208.74 | 24081.02 | 1.213x |

The median speedups from the same run were `1.085x` keygen, `1.397x`
encaps, `1.396x` decaps, and `1.211x` roundtrip.

The change keeps the core path vendor-free. `ntt_mul_acc3()` and
`ntt_mul_acc3_factored_gamma()` now split the `c0` term into low and high
coefficient products and reduce `c0_hi` before multiplying by `gamma`:
`c0 = c0_lo + (c0_hi % Q) * gamma`. This is exact because reducing `c0_hi`
modulo `Q` before the final modular reduction does not change the result, and
it keeps the intermediate range in 32-bit arithmetic instead of using a 64-bit
product plus 64-bit `% Q`.

NTT microbench A/B (`200000` iterations per run, `6` order-flipped pairs)
showed the direct helper-level effect: `ntt_mul_acc3` improved from `501.72`
ns/op to `63.79` ns/op (`7.866x`), and `ntt_mul_acc3_factored_gamma` improved
from `492.55` ns/op to `64.17` ns/op (`7.676x`). Forward NTT copy/in-place
metrics stayed effectively flat, so the KEM-level speedup comes from the
three-term NTT-domain multiplication helpers used by keygen, encaps, and
decaps.

Post-change profiling (`6000` iterations, `-pg`) shows `keccakf` as the largest
hotspot (`45.16%` self time), followed by `kpke_encrypt` (`35.48%`),
`sample_ntt` (`12.90%`), and `sample_poly_cbd` / `bench_keygen` (`3.23%`
each). `ntt_mul_acc3` no longer appears in the flat-profile top entries.

### Latest Local Optimization A/B (2026-06-26)

Snapshot command shape: pinned CPU, `clang`, upstream AVX2 backend, `8000`
iterations per run, `16` order-flipped runs. Baseline is commit `24e00c2`
(before repeated-public-key cache); candidate is the working tree after the
cache change.

| Metric | Baseline mean ns/op | Candidate mean ns/op | Speedup |
|---|---:|---:|---:|
| keygen | 5146.42 | 5150.37 | 0.999x |
| encaps | 5046.97 | 1311.22 | 3.849x |
| decaps | 5281.84 | 3197.67 | 1.652x |
| roundtrip | 15615.07 | 13638.48 | 1.145x |

This optimization targets repeated use of the same public key by caching only
public-key-derived data (`H(pk)`, unpacked `pk`, and generated `A^T`).

### Latest Local Optimization A/B (2026-06-26, fixed `hash_g`)

Snapshot command shape: pinned CPU, `clang`, upstream AVX2 backend, `8000`
iterations per run, `16` order-flipped runs. Baseline is commit `13c7e19`
(before fixed-length `hash_g`); candidate is the working tree after the
`sha3_512_64()` route.

| Metric | Baseline mean ns/op | Candidate mean ns/op | Speedup |
|---|---:|---:|---:|
| keygen | 5149.30 | 5139.78 | 1.002x |
| encaps | 1299.08 | 1275.29 | 1.019x |
| decaps | 3169.72 | 3147.78 | 1.007x |
| roundtrip | 13626.00 | 13573.37 | 1.004x |

The fixed-length path only specializes the 64-byte `hash_g` calls used by
encapsulation and decapsulation; the 33-byte keypair seed expansion keeps the
generic SHA3-512 path.


### Latest Local Optimization A/B (2026-06-26, public-key cache consolidation)

Snapshot command shape: pinned CPU, `clang`, upstream AVX2 backend, `20000`
iterations per run, `6` baseline runs followed by `6` candidate runs. Baseline
is commit `edaa300`; candidate is the working tree after consolidating repeated
public-key cache lookups into the `indcpa` cache.

| Metric | Baseline mean ns/op | Candidate mean ns/op | Speedup |
|---|---:|---:|---:|
| keygen | 5118.64 | 5126.85 | 0.998x |
| encaps | 1275.87 | 1263.53 | 1.010x |
| decaps | 3154.48 | 3149.10 | 1.002x |
| roundtrip | 13577.97 | 13482.23 | 1.007x |

This keeps the cached data public-only, but removes the duplicated same-public-key
lookup in encapsulation by sharing cached `H(pk)`, unpacked `pk`, and generated
`A^T` from the same cache entry.


### Latest Local Optimization A/B (2026-06-26, clang scalar FIPS202 flags)

Snapshot command shape: pinned CPU, `clang`, upstream AVX2 backend, `20000`
iterations per run, `6` baseline runs followed by `6` candidate runs. Baseline
uses `KYBER_FIPS202_CFLAGS=-O2`; candidate uses
`KYBER_FIPS202_CFLAGS=-O3 -fno-vectorize -fno-slp-vectorize` for scalar
Kyber `fips202.c`.

| Metric | Baseline mean ns/op | Candidate mean ns/op | Speedup |
|---|---:|---:|---:|
| keygen | 5151.78 | 5108.20 | 1.008x |
| encaps | 1264.34 | 1254.86 | 1.008x |
| decaps | 3155.95 | 3159.02 | 0.999x |
| roundtrip | 13551.25 | 13452.19 | 1.007x |

The Makefile applies these flags only for `clang`; GCC keeps the previous
`KYBER_FIPS202_CFLAGS=-O2` default.


### Latest Local Optimization A/B (2026-06-26, seed public `H(pk)` cache)

Snapshot command shape: pinned CPU, `clang`, upstream AVX2 backend, `20000`
iterations per run, `6` baseline runs followed by `6` candidate runs. Baseline
is commit `9d50768`; candidate seeds the public `H(pk)` cache from the hash
already computed during keypair generation.

| Metric | Baseline mean ns/op | Candidate mean ns/op | Speedup |
|---|---:|---:|---:|
| keygen | 5150.34 | 5104.86 | 1.009x |
| encaps | 1251.41 | 1253.79 | 0.998x |
| decaps | 3144.54 | 3153.46 | 0.997x |
| roundtrip | 13493.09 | 11735.49 | 1.150x |

This cache entry is public-key-derived only. It removes the duplicate `H(pk)`
work in keygen-then-encaps roundtrips without storing secret-key material.

## Fastest Verification

Run a one-shot pass/fail verifier that checks local speedup against all
comparators (default threshold: `>= 1.000x` for each label):

```bash
PIN_CPU=0 C_COMPILER=clang ./scripts/verify_world_fastest.sh 2000 3
```

Run a strict two-stage verifier (current checkouts + latest updates) in one
command:

```bash
PIN_CPU=0 C_COMPILER=clang ./scripts/verify_world_fastest_strict.sh 600 2
```

The strict script runs:
1. `UPDATE_REPOS=0` verification (current comparator checkouts)
2. `UPDATE_REPOS=1` verification (latest comparator updates)

and reports `verify_world_fastest_strict=PASS` only if both stages pass.

Tune robustness and acceptance thresholds via environment:

```bash
PIN_CPU=0 C_COMPILER=clang STATS_MODE=median WARMUP_RUNS=1 MIN_SPEEDUP=1.000 \
  ./scripts/verify_world_fastest.sh 2000 3
```

Per-label thresholds can be overridden with
`MIN_SPEEDUP_<LABEL>` where `<LABEL>` is uppercased and non-alphanumeric
characters are converted to `_` (for example:
`MIN_SPEEDUP_KYBER_UPSTREAM_AVX2_FAIR`).

For noisy comparators, enable controlled retries (defaults:
`MAX_RETRIES=1`, `RETRY_LABELS=kyber_upstream_avx2,kyber_upstream_avx2_fair`):

```bash
PIN_CPU=0 C_COMPILER=clang STATS_MODE=median WARMUP_RUNS=1 \
  MIN_SPEEDUP=1.000 MIN_SPEEDUP_KYBER_UPSTREAM_AVX2_FAIR=0.995 \
  MAX_RETRIES=1 RETRY_LABELS=kyber_upstream_avx2,kyber_upstream_avx2_fair SHOW_FULL_OUTPUT_ON_FAIL=0 \
  ./scripts/verify_world_fastest.sh 2000 3
```
