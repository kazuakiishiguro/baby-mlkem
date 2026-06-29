# baby-mlkem

A toy implementation of ML-KEM (formaly knows as kyber), a Module-Lattice-Based Key-Encapsulation Mechanism Standard ([FIPS203](https://doi.org/10.6028/NIST.FIPS.203)). This implementation is written in pure C and is inspired by the blog post [Enough Polynomials and Linear Algebra to Implement Kyber](https://words.filippo.io/dispatches/kyber-math/).

## Implementation Status

The repository contains a toy ML-KEM implementation, but the default optimized
build is not a from-scratch scalar implementation. By default, the benchmark and
test Makefile use an in-tree copy of upstream Kyber AVX2 sources under
`include/kyber_upstream/avx2`.

This means current high-performance numbers should be read as measurements of
the baby-mlkem integration that uses a vendored upstream Kyber AVX2 backend, not
as evidence that an independent baby-mlkem arithmetic core outperforms upstream
Kyber AVX2.

The default build does not link against external crypto libraries such as
OpenSSL, BoringSSL, or liboqs. It does, however, compile vendored external-origin
AVX2 sources into the local binary. `AVX2_BACKEND=pqclean` switches the local
backend to the vendored PQClean AVX2 sources instead.

Use `AVX2_BACKEND=core` to build and benchmark the independent baby-mlkem core
without vendored AVX2 KEM sources and without the vendored PQClean FIPS202
object. This mode is the baseline for true core optimization work.

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

The default build enables an in-tree upstream Kyber AVX2 backend for
ML-KEM-768-compatible KEM operations on supported x86 hosts
(`-mavx2 -mbmi2 -mpopcnt`).

With the default `AVX2_BACKEND=upstream`, the benchmark harness delegates KEM
operations to `pqcrystals_kyber768_avx2_*` functions.
`AVX2_BACKEND=pqclean` delegates to the vendored PQClean AVX2 KEM. Use
`AVX2_BACKEND=core` when measuring the independent baby-mlkem scalar core.

Switch backend explicitly when needed:

```bash
make bench AVX2_BACKEND=upstream   # default, vendored upstream Kyber AVX2
make bench AVX2_BACKEND=pqclean    # vendored PQClean AVX2
make bench AVX2_BACKEND=core       # independent baby-mlkem core
```

## External Comparison

External comparison results need a narrow interpretation. The local
`baby-mlkem` binary in these comparisons normally uses the vendored upstream
Kyber AVX2 backend. Therefore, speedups against an independently checked out
upstream Kyber AVX2 build are integration/build/harness comparisons, not a claim
that a separate baby-mlkem core is faster than upstream Kyber AVX2.

For true independent-core comparisons, pass `AVX2_BACKEND=core` to the local
build, for example:

```bash
AVX2_BACKEND=core PIN_CPU=0 ./scripts/bench_compare_kyber_upstream.sh 400
```

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

The `vs kyber default` and `vs kyber fair` columns compare the local in-tree
upstream-AVX2-backed build against separately built upstream Kyber AVX2
checkouts. They should not be interpreted as an independent implementation
beating upstream Kyber AVX2.

| Compiler | Local mean ns/op | vs kyber default | vs kyber fair | vs mlkem-native | vs PQClean AVX2 | vs liboqs | vs BoringSSL | vs libcrux | vs Libjade | vs Botan | vs OpenSSL |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| gcc | 17890.38 | 1.070x | 1.048x | 1.551x | 1.172x | 1.204x | 3.302x | 1.284x | 1.148x | 7.383x | 3.028x |
| clang | 16029.25 | 1.002x | 1.004x | 1.631x | 1.251x | 1.332x | 3.345x | 1.338x | 1.318x | 8.391x | 3.014x |

For lower-noise comparisons, prefer larger runs such as:

```bash
PIN_CPU=0 WARMUP_RUNS=1 COMPILERS="gcc clang" ./scripts/bench_compiler_matrix.sh 2000 3
```

### Independent Core Baseline (2026-06-29)

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

At this baseline, the independent core roundtrip is about `9.49x` slower than
local upstream AVX2. Core optimization work should be measured against the
`AVX2_BACKEND=core` row, not the default upstream-backed row.

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
