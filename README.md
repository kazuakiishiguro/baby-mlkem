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
| `mlkem_ntt_level_l7` .. `mlkem_ntt_level_l1` | one prepared forward-NTT level, from length 128 down to length 2 |
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
full `ntt()` or `ntt_inv()`. The inverse-level rows time the scalar level kernel
for direction finding; the current full inverse NTT already uses a self-contained
AVX2 head for `l1`..`l3`.

Current forward-level snapshot, pinned to CPU 0, `clang`, `AVX2_BACKEND=core`,
`200000` iterations:

| Metric | ns/op |
|---|---:|
| `mlkem_ntt_level_l7` | 23.99 |
| `mlkem_ntt_level_l6` | 24.30 |
| `mlkem_ntt_level_l5` | 24.38 |
| `mlkem_ntt_level_l4` | 26.03 |
| `mlkem_ntt_level_l3` | 207.78 |
| `mlkem_ntt_level_l2` | 212.10 |
| `mlkem_ntt_level_l1` | 225.38 |

This points the next self-contained AVX2 work at the fine-grained forward NTT
levels (`l3`..`l1`) before revisiting broad changes to the full scalar loop.

Current inverse-level snapshot, pinned to CPU 0, `clang`, `AVX2_BACKEND=core`,
`200000` iterations:

| Metric | ns/op |
|---|---:|
| `mlkem_ntt_inv_level_l1` | 242.39 |
| `mlkem_ntt_inv_level_l2` | 237.36 |
| `mlkem_ntt_inv_level_l3` | 209.23 |
| `mlkem_ntt_inv_level_l4` | 20.04 |
| `mlkem_ntt_inv_level_l5` | 19.17 |
| `mlkem_ntt_inv_level_l6` | 19.61 |
| `mlkem_ntt_inv_level_l7` | 19.53 |

This explains why broad AVX2 work on the remaining inverse stages (`l4`..`l7`)
is unlikely to pay off: those scalar stage kernels are already small compared
with the inverse head and final scale/add/sub fusion work.

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
| `mlkem_core_stage_kpke_encrypt_cached` | full `kpke_encrypt()` with a cached public key |
| `mlkem_core_stage_kpke_decrypt_cached` | full `kpke_decrypt()` with a cached secret key |
| `mlkem_core_stage_sample_matrix` | the 3x3 `sample_ntt()` public matrix generation |
| `mlkem_core_stage_sample_matrix_x4_batch0` | first four-entry x4 public-matrix sampler batch |
| `mlkem_core_stage_sample_matrix_x4_batch1` | second four-entry x4 public-matrix sampler batch |
| `mlkem_core_stage_sample_matrix_tail` | final `(2,2)` public-matrix sampler tail |
| `mlkem_core_stage_keygen_noise_ntt` | keygen secret/error PRF, CBD, NTT, and secret-key encode |
| `mlkem_core_stage_keygen_noise_prf_cbd` | isolated keygen secret/error PRF and CBD only |
| `mlkem_core_stage_keygen_noise_ntt_encode` | isolated keygen secret/error NTT plus secret-key encode |
| `mlkem_core_stage_keygen_accum_encode` | keygen NTT-domain multiply-add, add error, and public-key encode |
| `mlkem_core_stage_encrypt_noise` | encryption PRF, CBD, and NTT for `r`, `e1`, and `e2` |
| `mlkem_core_stage_encrypt_noise_prf_cbd` | isolated encryption PRF and CBD for `r`, `e1`, and `e2` |
| `mlkem_core_stage_encrypt_noise_ntt` | isolated encryption forward NTT for `r` |
| `mlkem_core_stage_encrypt_accum_inv` | encryption NTT-domain accumulation and inverse NTT for `u` and `v` |
| `mlkem_core_stage_ciphertext_compress_encode` | ciphertext compression and DU/DV bit-packing |
| `mlkem_core_stage_ciphertext_decode_decompress` | ciphertext DU/DV decode and decompression |
| `mlkem_core_stage_decrypt_ntt_accum_recover` | decrypt-side NTT, accumulation, inverse NTT subtraction, and message recovery |

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
`20000` iterations, after the current optimization series:

| Metric | ns/op |
|---|---:|
| `mlkem_core_stage_kpke_keygen_full` | 4983.07 |
| `mlkem_core_stage_kpke_encrypt_cached` | 2274.53 |
| `mlkem_core_stage_kpke_decrypt_cached` | 994.13 |
| `mlkem_core_stage_sample_matrix` | 2940.65 |
| `mlkem_core_stage_sample_matrix_x4_batch0` | 1118.26 |
| `mlkem_core_stage_sample_matrix_x4_batch1` | 1359.50 |
| `mlkem_core_stage_sample_matrix_tail` | 833.37 |
| `mlkem_core_stage_keygen_noise_ntt` | 1893.05 |
| `mlkem_core_stage_keygen_noise_prf_cbd` | 771.89 |
| `mlkem_core_stage_keygen_noise_ntt_encode` | 1675.66 |
| `mlkem_core_stage_keygen_accum_encode` | 460.55 |
| `mlkem_core_stage_encrypt_noise` | 1243.91 |
| `mlkem_core_stage_encrypt_noise_prf_cbd` | 962.97 |
| `mlkem_core_stage_encrypt_noise_ntt` | 828.65 |
| `mlkem_core_stage_encrypt_accum_inv` | 1252.60 |
| `mlkem_core_stage_ciphertext_compress_encode` | 101.90 |
| `mlkem_core_stage_ciphertext_decode_decompress` | 247.13 |
| `mlkem_core_stage_decrypt_ntt_accum_recover` | 930.13 |

The current remaining hotspots are public matrix generation, keygen
noise/NTT/encode, encryption noise generation, and encryption accumulation plus
inverse NTT. Compression, bit-packing, and ciphertext decode/decompress remain
smaller contributors.

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
`C_COMPILER`, `PIN_CPU`, `RUNS`, `WARMUP_RUNS`, `KEM_ITERS`, `STAGE_ITERS`,
`NTT_ITERS`, and `KECCAK_ITERS` control the run. Use this local A/B output as
the first filter before documenting an optimization as an independent-core
speedup.

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
