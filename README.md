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

## Current Core Optimization Frontier (2026-07-03)

The active optimization goal is to keep improving the independent baby-mlkem
core itself, not to claim wins from benchmark caches or vendored AVX2 backends.
The current short-term filter is therefore: only pursue changes that reduce real
core work in SHAKE/sample_ntt, forward/inverse NTT, K=3 accumulation, or range
normalization across encode/compress boundaries.

Current AVX2-only frontier snapshot, pinned to CPU 0, `clang`,
`AVX2_BACKEND=core`, seven runs of `./bench_core_stagesc 30000`:

Regenerate this table with:

```bash
RUNS=7 STAGE_ITERS=30000 PIN_CPU=0 C_COMPILER=clang ./scripts/bench_core_frontier.sh
```

| Metric | Avg ns/op | Median ns/op | Readout |
|---|---:|---:|---|
| `mlkem_core_stage_kpke_encrypt_uncached` | 4932.84 | 4886.79 | largest integrated cache-miss encryption row |
| `mlkem_core_stage_kpke_keygen_full` | 4830.38 | 4762.78 | keygen still dominated by matrix sampling plus six NTTs |
| `mlkem_core_stage_kpke_prepare_public_no_cache` | 4372.95 | 4276.23 | public-key d12 decode + matrix sampling + H(pk) |
| `mlkem_core_stage_sample_matrix` | 2837.65 | 2821.11 | largest standalone public-work target |
| `mlkem_core_stage_kpke_encrypt_cached` | 2439.32 | 2402.78 | cached encapsulation arithmetic/noise target |
| `mlkem_core_stage_keygen_noise_ntt` | 1977.44 | 1976.18 | keygen PRF/CBD plus six forward NTTs |
| `mlkem_core_stage_keygen_noise_ntt_encode` | 1582.56 | 1581.39 | six forward NTTs plus secret d12 encode |
| `mlkem_core_stage_encrypt_noise` | 1395.11 | 1394.77 | encrypt PRF/CBD plus lazy r NTT |
| `mlkem_core_stage_encrypt_accum_inv` | 1292.18 | 1290.76 | K=3 accumulation plus inverse-add |
| `mlkem_core_stage_sample_ntt4_keccak_store3` | 872.12 | 871.99 | common x4 sampler Keccak/state/store cost |
| `mlkem_core_stage_sample_ntt4_parse_504` | 118.48 | 117.58 | parser bookkeeping is not the main sampler cost |
| `mlkem_core_stage_keygen_accum_only` | 439.36 | 438.14 | A^T*s scalar accumulation is still meaningful but local rewrites failed |
| `mlkem_core_stage_keygen_add_only` | 203.08 | 203.17 | vector add is smaller than accumulation and NTT work |
| `mlkem_core_stage_ciphertext_compress_encode` | 51.57 | 50.58 | d10/d4 packing is too small for the next target |

Near-term target selection:

| Candidate family | Status | Reason |
|---|---|---|
| Common `sample_ntt4()` Keccak/state layout | Open | `keccak_store3` is far larger than `parse_504`; a useful change must remove state movement or fill lanes with useful work, not just tweak parser bookkeeping. |
| Broad lazy/signed range contract | Open | NAF-like signed/lazy ideas only make sense if the range is carried through CBD or sampler output, forward NTT, K=3 multiplication, inverse add/sub, and encode/compress. Narrow signed ETA2/rhat changes already lost. |
| Local K=3 scalar accumulation rewrites | Mostly closed | Karatsuba, reciprocal, wide-c0, Montgomery, restrict, unroll, noinline, AVX2 product-vectorization, and multi-output coalescing all failed direct or integrated gates. |
| d10/d12 packing, d12 decode, fixed nonce setup, tail rotation | Closed for now | These rows are small or have explicit rejection records. Reopening them needs new evidence, not another local schedule variant. |

The next implementation should therefore be either a real `sample_ntt4` state to
accepted-coefficient path that avoids the current store/reload boundary, or a
range-contract prototype broad enough to avoid paying normalization back at the
next consumer. Anything narrower is likely to reproduce the recent pattern:
small direct wins, then neutral or negative KEM medians.

### Range Contract Diagnostic

`bench_core_stagesc` now prints non-timing `mlkem_core_range_*` lines before the
stage timings. These rows are intended to gate broad lazy/signed representation
work without relying on comments or one-off reasoning.

Short AVX2-only diagnostic run:

```bash
make bench-stages CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
taskset -c 0 ./bench_core_stagesc 1000 | sed -n '1,48p'
```

Observed fixture bounds:

| Boundary | Stored range | Centered range | `>= Q` lanes | Readout |
|---|---:|---:|---:|---|
| ETA2 CBD outputs | `0..3328` | `-2..2` | `0` | current producer canonicalizes negative noise immediately. |
| Keygen NTT outputs | `0..3328` | `-1664..1664` | `0` | public key path is fully canonical after NTT. |
| Encrypt canonical NTT outputs | `0..3324` | `-1663..1662` | `0` | stage fixture canonical row remains exact. |
| K=3 accumulation outputs | `0..3328` | `-1664..1664` | `0` | current `ntt_mul_acc3()` normalizes before inverse NTT. |
| Inverse/add outputs | `0..3328` | `-1664..1664` | `0` | compress still receives canonical coefficients. |
| Message-folded `e2` | `0..3328` | `-1664..1664` | `0` | message add already crosses the full centered range. |
| Lazy multiply-input NTT | `20..6624` | `-1663..1663` | `3059` | modulo-checked against canonical NTT and still `< 2Q`. |

Implication: the only currently proved lazy production contract on AVX2 is the
`[0, 2Q)` output of `ntt_lazy_mul_input_avx2()` consumed by `ntt_mul_acc3()`.
A useful next range optimization must either make K=3 accumulation/inverse work
natively with that wider range, or carry a signed CBD representation into an NTT
head that does not reintroduce equivalent per-lane canonicalization. Repeating a
local final-add or CBD lookup rewrite is already covered by prior rejection rows.

### Production Lazy K=3 Accumulation Alignment

The stage harness now also keeps `stage_rhat_lazy`, validates it modulo `Q`
against canonical `stage_rhat`, and reports AVX2-only accumulation rows that feed
`ntt_mul_acc3()` with the same `[0, 2Q)` lazy multiply-input range used by
production encryption.

Short AVX2-only diagnostic command:

```bash
make bench-stages CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
for i in $(seq 1 5); do
  taskset -c 0 ./bench_core_stagesc 10000 | \
    awk -F= -v run="$i" '/mlkem_core_stage_encrypt_accum_inv(_lazy_input)?_ns_per_op=|mlkem_core_stage_encrypt_accum_u_only(_lazy_input)?_ns_per_op=/{print run, $1, $2}'
done
```

Short-run AVX2-only results:

| Metric | Avg ns/op | Median ns/op | Readout |
|---|---:|---:|---|
| `mlkem_core_stage_encrypt_accum_inv` | 1288.67 | 1288.98 | historical canonical fixture row. |
| `mlkem_core_stage_encrypt_accum_inv_lazy_input` | 1297.71 | 1293.95 | production-aligned lazy `rhat` input row. |
| `mlkem_core_stage_encrypt_accum_u_only` | 440.34 | 440.52 | canonical K=3 `u` accumulations only. |
| `mlkem_core_stage_encrypt_accum_u_only_lazy_input` | 442.53 | 439.85 | lazy-input K=3 `u` accumulations only. |

Decision: keep these as alignment diagnostics, not production changes. The lazy
forward NTT remains useful, but feeding `[0, 2Q)` values into the existing scalar
K=3 accumulator does not reveal extra downstream speed; the full accumulation
plus inverse row is slightly slower in this short run. The next K=3 attempt still
needs a real accumulation/reduction redesign, not just relying on the lazy input
range to make the current scalar loop faster.

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
| `mlkem_ntt_copy_lazy_mul_input` | AVX2-only: production `ntt_lazy_mul_input_avx2(in, out)` including its initial copy, matching the out-of-place stage diagnostic shape |
| `mlkem_ntt_inplace_lazy_mul_input` | AVX2-only: production lazy multiply-input NTT in-place body; scratch inputs are restored outside the timed window so each transform starts from canonical input |
| `mlkem_ntt_copy_fused_tail` | AVX2-only diagnostic full forward NTT using a fused `l3 -> l2 -> lazy l1` tail block order plus canonicalization |
| `mlkem_ntt_inplace_fused_tail` | AVX2-only diagnostic in-place full forward NTT using the fused tail block order |
| `mlkem_ntt_copy_lazy_mul_input_fused_tail` | AVX2-only diagnostic lazy multiply-input NTT using the fused tail block order, including the input copy |
| `mlkem_ntt_inplace_lazy_mul_input_fused_tail` | AVX2-only diagnostic in-place lazy multiply-input NTT using the fused tail block order |
| `mlkem_ntt3_inplace` | three consecutive in-place forward NTTs, matching the K=3 batch shape in keygen/encrypt/decrypt |
| `mlkem_ntt3_inplace_fused_tail` | AVX2-only diagnostic K=3 forward NTT batch using the fused tail block order |
| `mlkem_ntt3_pack_aos4` | diagnostic pack of three polynomials into `[coefficient][poly0, poly1, poly2, pad]` layout |
| `mlkem_ntt3_unpack_aos4` | diagnostic unpack from the padded K=3 AoS4 layout back to three polynomials |
| `mlkem_ntt3_pack_unpack_aos4` | diagnostic round-trip pack plus unpack cost for a future packed K=3 NTT representation |
| `mlkem_ntt3_aos4_inplace` | bench-only K=3 forward NTT directly over the padded AoS4 layout, excluding pack/unpack |
| `mlkem_ntt3_pack_ntt_aos4` | diagnostic pack plus bench-only AoS4 K=3 forward NTT |
| `mlkem_ntt3_pack_ntt_unpack_aos4` | diagnostic standalone AoS4 K=3 forward NTT including pack and unpack |
| `mlkem_ntt3_2coeff_inplace` | bench-only K=3 forward NTT that processes two coefficients across three polynomials per AVX2 vector, without changing storage layout |
| `mlkem_ntt3_pack_tile2x3` | diagnostic pack into `[coeff pair][poly0 c0, poly1 c0, poly2 c0, poly0 c1, poly1 c1, poly2 c1, pad, pad]` |
| `mlkem_ntt3_unpack_tile2x3` | diagnostic unpack from the K=3 x 2-coefficient tiled layout |
| `mlkem_ntt3_tile2x3_inplace` | bench-only K=3 forward NTT over the contiguous K=3 x 2-coefficient tiled layout |
| `mlkem_ntt3_pack_ntt_tile2x3` | diagnostic pack plus tiled K=3 x 2-coefficient forward NTT |
| `mlkem_ntt3_pack_ntt_unpack_tile2x3` | diagnostic standalone tiled K=3 x 2-coefficient forward NTT including pack and unpack |
| `mlkem_ntt4_inplace` | four consecutive in-place forward NTTs, used as the K=4 baseline for fully occupied AVX2 tile experiments |
| `mlkem_ntt4_pack_tile2x4` | diagnostic pack into `[coeff pair][poly0 c0, poly1 c0, poly2 c0, poly3 c0, poly0 c1, poly1 c1, poly2 c1, poly3 c1]` |
| `mlkem_ntt4_unpack_tile2x4` | diagnostic unpack from the K=4 x 2-coefficient tiled layout |
| `mlkem_ntt4_tile2x4_inplace` | bench-only K=4 forward NTT over the contiguous K=4 x 2-coefficient tiled layout |
| `mlkem_ntt4_pack_ntt_unpack_tile2x4` | diagnostic standalone tiled K=4 x 2-coefficient forward NTT including pack and unpack |
| `mlkem_ntt6_inplace` | six consecutive in-place forward NTTs, matching the keygen secret/error NTT count |
| `mlkem_ntt6_inplace_fused_tail` | AVX2-only diagnostic six-polynomial forward NTT batch using the fused tail block order |
| `mlkem_ntt6_tile2x4_plus2_inplace` | diagnostic lower bound: first four polynomials already in tile2x4 layout plus two normal in-place NTTs, excluding tile pack/unpack |
| `mlkem_ntt6_pack_ntt_unpack_tile2x4_plus2` | diagnostic K=6 composition with tile2x4 pack/NTT/unpack for four polynomials plus two normal in-place NTTs |
| `mlkem_ntt_head_l7_l4` | AVX2 build only: current forward-NTT upper stages before `ntt_tail_avx2()` |
| `mlkem_ntt_tail_avx2` | AVX2 build only: current forward-NTT lower stages `l3`..`l1` |
| `mlkem_ntt_tail_avx2_fused_l3_l1` | AVX2-only diagnostic lower tail using one loop that completes `l3`, `l2`, and lazy `l1` per 16-coefficient block |
| `mlkem_ntt_tail_avx2_l3` .. `mlkem_ntt_tail_avx2_l1` | AVX2 build only: one prepared lower-stage helper from the actual tail path |
| `mlkem_ntt_tail_avx2_l2_block` | AVX2-only diagnostic: forward NTT tail `l2` using two contiguous 128-bit block loads/stores instead of the production pair-load helper |
| `mlkem_ntt_tail_avx2_l2_block_lazy_l1_canon` | AVX2-only diagnostic: forward NTT tail `l3`, block-load `l2`, lazy `l1`, then canonicalization |
| `mlkem_ntt_level_l7` .. `mlkem_ntt_level_l1` | one prepared scalar forward-NTT level, from length 128 down to length 2 |
| `mlkem_ntt_inv` | `ntt_inv()` |
| `mlkem_ntt_inv_level_l1` .. `mlkem_ntt_inv_level_l7` | one prepared inverse-NTT level, from length 2 up to length 128 |
| `mlkem_ntt_inv_add` | `ntt_inv_add()` |
| `mlkem_ntt_inv_add2` | `ntt_inv_add2()` |
| `mlkem_ntt_inv_sub_from` | `ntt_inv_sub_from()` |
| `mlkem_ntt_mul_acc3` | `ntt_mul_acc3()` |
| `mlkem_ntt_mul_acc3_tile2x3` | bench-only `ntt_mul_acc3()` equivalent that consumes already-packed K=3 x 2-coefficient tile2x3 inputs |
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

A follow-up tested the direct multi-stage fusion idea by changing only the AVX2
lower-tail schedule in the bench harness: instead of three full-array passes for
`l3`, `l2`, and lazy `l1`, the diagnostic completes `l3 -> l2 -> lazy l1` inside
each 16-coefficient block and then runs the same canonicalization pass as the
current tail. Pinned CPU 0, `clang`, `AVX2_BACKEND=core`, `-mavx2 -mbmi2
-mpopcnt`, median of seven `200000`-iteration runs measured:

| Metric pair | Current median ns/op | Fused-tail median ns/op | Fused/current speed |
|---|---:|---:|---:|
| `mlkem_ntt_tail_avx2` | 94.36 | 147.60 | 0.6393x |
| `mlkem_ntt_inplace` | 191.84 | 246.41 | 0.7785x |
| `mlkem_ntt_copy_lazy_mul_input` | 191.58 | 243.89 | 0.7855x |
| `mlkem_ntt_inplace_lazy_mul_input` | 188.45 | 242.25 | 0.7779x |
| `mlkem_ntt3_inplace` | 575.32 | 740.39 | 0.7770x |
| `mlkem_ntt6_inplace` | 1152.56 | 1482.61 | 0.7774x |

This rejects per-block `l3/l2/l1` tail fusion. The transform has less array
sweeping, but it also serializes three dependent stages inside a larger loop body
and loses the simple stage-by-stage instruction stream that clang handles well.
Future forward-NTT work should not fuse only the existing tail loops; it needs a
different representation or a producer/consumer fusion that removes work outside
this tail body.

Current AVX2 lazy multiply-input snapshot, pinned to CPU 0, `clang`,
`AVX2_BACKEND=core`, `-mavx2 -mbmi2 -mpopcnt`, median of seven
`200000`-iteration runs:

| Metric | Median ns/op | Interpretation |
|---|---:|---|
| `mlkem_ntt_copy` | 196.24 | canonical out-of-place baseline |
| `mlkem_ntt_inplace` | 191.84 | canonical in-place baseline |
| `mlkem_ntt_copy_lazy_mul_input` | 191.42 | production lazy helper with out-of-place copy |
| `mlkem_ntt_inplace_lazy_mul_input` | 188.40 | production lazy helper body used by encrypt/decrypt `rhat` and `u` |

The lazy multiply-input representation is a real but small NTT-local win: about
`1.025x` over canonical out-of-place NTT and about `1.018x` over canonical
in-place NTT in this microbench. This also fixes a measurement blind spot: the
stage rows use the out-of-place helper shape, while production encryption and
decryption call the helper in-place. Future NTT work should not chase another
copy-boundary tweak here; it needs to change the K=3 NTT/accumulation layout or
a broader representation boundary to move integrated KEM rows.

A new `mlkem_ntt3_inplace` metric was added as the baseline for that next design
step. It measures three consecutive in-place forward NTTs as one operation, which
matches the K=3 shape used by keygen secret/error transforms, encapsulation
`rhat`, and decapsulation `u`. It intentionally does not implement a new packed
algorithm yet; it makes future real cross-polynomial packing measurable against
`HEAD` instead of relying on indirect stage rows.

Current `mlkem_ntt3_inplace` snapshot, pinned to CPU 0, `clang`, `200000`
iterations:

| Build | `mlkem_ntt_inplace` ns/op | `mlkem_ntt3_inplace` ns/op | Per-poly ns/op |
|---|---:|---:|---:|
| native `AVX2_BACKEND=core` | 169.93 | 509.86 | 169.95 |
| AVX2-only `-mavx2 -mbmi2 -mpopcnt` | 197.87 | 580.20 | 193.40 |

A later K=3 packed-layout diagnostic added an AoS4 representation,
`[coefficient][poly0, poly1, poly2, pad]`, to estimate the pack/unpack overhead
that any real cross-polynomial NTT layout has to overcome. Pinned CPU 0,
`clang`, `200000`-iteration snapshots measured:

| Build | Metric | ns/op |
|---|---|---:|
| native | `mlkem_ntt3_inplace` | 507.54 |
| native | `mlkem_ntt3_pack_aos4` | 15.29 |
| native | `mlkem_ntt3_unpack_aos4` | 18.67 |
| native | `mlkem_ntt3_pack_unpack_aos4` | 37.03 |
| AVX2-only | `mlkem_ntt3_inplace` | 583.22 |
| AVX2-only | `mlkem_ntt3_pack_aos4` | 26.51 |
| AVX2-only | `mlkem_ntt3_unpack_aos4` | 71.23 |
| AVX2-only | `mlkem_ntt3_pack_unpack_aos4` | 96.92 |

This diagnostic is not a packed NTT implementation. It shows the conversion
budget: a standalone packed K=3 NTT that packs inputs and unpacks outputs around
each transform must save more than about 37 ns on native and 97 ns on AVX2-only
just to break even. A more plausible design should either keep data in the
packed layout across neighboring stages or generate/consume CBD/decode data in
that layout directly.

A bench-only AoS4 packed-NTT prototype then tested whether that layout can pay
for itself inside the transform. It runs the full forward NTT over
`[coefficient][poly0, poly1, poly2, pad]`, using the fourth lane as padding and
checking the unpacked result against three independent `ntt()` calls. Pinned CPU
0, `clang`, `200000`-iteration snapshots measured:

| Build | Metric | ns/op | Speedup vs `mlkem_ntt3_inplace` |
|---|---|---:|---:|
| native | `mlkem_ntt3_inplace` | 510.54 | 1.000x |
| native | `mlkem_ntt3_aos4_inplace` | 1377.63 | 0.371x |
| native | `mlkem_ntt3_pack_ntt_aos4` | 1529.71 | 0.334x |
| native | `mlkem_ntt3_pack_ntt_unpack_aos4` | 1548.40 | 0.330x |
| AVX2-only | `mlkem_ntt3_inplace` | 584.02 | 1.000x |
| AVX2-only | `mlkem_ntt3_aos4_inplace` | 1319.51 | 0.443x |
| AVX2-only | `mlkem_ntt3_pack_ntt_aos4` | 1348.66 | 0.433x |
| AVX2-only | `mlkem_ntt3_pack_ntt_unpack_aos4` | 1419.90 | 0.411x |

Reject this coefficient-major AoS4 transform shape. It vectorizes only three
useful polynomial lanes per butterfly, so each 256-bit operation does too little
work and loses badly to the current single-polynomial NTT tail and compiler-
vectorized upper levels. A viable packed K=3 design needs a wider tile that also
uses coefficient parallelism, not just the three K columns plus one padding lane.

A follow-up bench-only `mlkem_ntt3_2coeff_inplace` prototype kept the normal
three-polynomial storage layout but processed two coefficients across the three
polynomials per AVX2 vector. That raises theoretical lane use from AoS4's three
useful lanes to six useful lanes, but requires scalar gathers and scalar lane
extraction stores for every butterfly. Pinned CPU 0, `clang`, `200000`-iteration
snapshots measured:

| Build | Metric | ns/op | Speedup vs `mlkem_ntt3_inplace` |
|---|---|---:|---:|
| native | `mlkem_ntt3_inplace` | 523.29 | 1.000x |
| native | `mlkem_ntt3_2coeff_inplace` | 2156.40 | 0.243x |
| AVX2-only | `mlkem_ntt3_inplace` | 584.30 | 1.000x |
| AVX2-only | `mlkem_ntt3_2coeff_inplace` | 2073.41 | 0.282x |

Reject this normal-layout K=3 x 2-coefficient vectorization as well. Lane
occupancy alone is not enough; the memory-access pattern must also remain
contiguous. The next packed NTT design should use a real tiled in-memory layout
that provides contiguous loads/stores for both coefficient and polynomial
parallelism, or avoid cross-polynomial NTT packing and move to a different
bottleneck.

A contiguous tile follow-up implemented that real tiled-memory version as
`mlkem_ntt3_tile2x3_inplace`. The tile layout stores two adjacent coefficients
for the three K polynomials in one 8-lane vector, leaving only two padding lanes,
so every non-final butterfly can use contiguous loads and stores instead of
scalar gathers. Pinned CPU 0, `clang`, `200000`-iteration snapshots measured:

| Build | Metric | ns/op | Speedup vs `mlkem_ntt3_inplace` |
|---|---|---:|---:|
| native | `mlkem_ntt3_inplace` | 509.00 | 1.000x |
| native | `mlkem_ntt3_pack_tile2x3` | 21.51 | - |
| native | `mlkem_ntt3_unpack_tile2x3` | 20.35 | - |
| native | `mlkem_ntt3_tile2x3_inplace` | 783.80 | 0.649x |
| native | `mlkem_ntt3_pack_ntt_unpack_tile2x3` | 823.71 | 0.618x |
| AVX2-only | `mlkem_ntt3_inplace` | 582.04 | 1.000x |
| AVX2-only | `mlkem_ntt3_pack_tile2x3` | 51.19 | - |
| AVX2-only | `mlkem_ntt3_unpack_tile2x3` | 73.38 | - |
| AVX2-only | `mlkem_ntt3_tile2x3_inplace` | 770.10 | 0.756x |
| AVX2-only | `mlkem_ntt3_pack_ntt_unpack_tile2x3` | 893.68 | 0.651x |

This confirms the memory-layout part of the hypothesis: contiguous tiles reduce
the normal-layout K=3 x 2-coefficient prototype from about 2.1 us to about 0.77
us. It still loses to three existing NTTs because a K=3-only AVX2 tile has at
most six useful 16-bit lanes out of eight. The next packed NTT attempt should
not be another standalone K=3 layout; it would need to combine more independent
polynomials or fuse surrounding work enough to pay for the 6/8 lane ceiling and
conversion cost.

A K=4 tile follow-up tested whether fully occupying the eight AVX2 16-bit lanes
changes that conclusion. The bench-only `mlkem_ntt4_tile2x4_inplace` layout
stores two adjacent coefficients from four polynomials in each vector, so every
tile lane is useful. It validates against four independent `ntt()` calls and is
still only a direction-finding diagnostic, not a production layout.

Pinned CPU 0, `clang`, `200000`-iteration snapshots measured:

| Build | Metric | ns/op | Speedup vs `mlkem_ntt4_inplace` |
|---|---|---:|---:|
| native | `mlkem_ntt4_inplace` | 693.21 | 1.000x |
| native | `mlkem_ntt4_pack_tile2x4` | 15.23 | - |
| native | `mlkem_ntt4_unpack_tile2x4` | 21.68 | - |
| native | `mlkem_ntt4_tile2x4_inplace` | 777.15 | 0.892x |
| native | `mlkem_ntt4_pack_ntt_unpack_tile2x4` | 798.02 | 0.869x |
| AVX2-only | `mlkem_ntt4_inplace` | 757.77 | 1.000x |
| AVX2-only | `mlkem_ntt4_pack_tile2x4` | 35.78 | - |
| AVX2-only | `mlkem_ntt4_unpack_tile2x4` | 95.76 | - |
| AVX2-only | `mlkem_ntt4_tile2x4_inplace` | 753.49 | 1.006x |
| AVX2-only | `mlkem_ntt4_pack_ntt_unpack_tile2x4` | 882.54 | 0.859x |

This rejects a standalone pack/NTT/unpack K=4 tiled implementation. The
AVX2-only in-place row is close enough to four independent NTTs to show that
full lane occupancy fixes the K=3 tile ceiling, but the conversion cost erases
the win. The native row also loses before conversion. A production K=4 tile
should only be reconsidered if neighboring producers and consumers can stay in
this layout, for example by generating PRF/CBD output directly as tile2x4 and
consuming the transformed values without an immediate unpack.

After the keygen split identified the six secret/error forward NTTs as the
remaining keygen-local target, a K=6 composition diagnostic checked whether the
K=4 tile could help when paired with two ordinary NTTs. Pinned CPU 0, `clang`,
`AVX2_BACKEND=core`, `-mavx2 -mbmi2 -mpopcnt`, median of seven
`200000`-iteration runs measured:

| Metric | Avg ns/op | Median ns/op | Relative to `mlkem_ntt6_inplace` median |
|---|---:|---:|---:|
| `mlkem_ntt6_inplace` | 1152.93 | 1152.66 | 1.0000x |
| `mlkem_ntt6_tile2x4_plus2_inplace` | 1160.64 | 1160.32 | 0.9934x |
| `mlkem_ntt6_pack_ntt_unpack_tile2x4_plus2` | 1297.96 | 1297.95 | 0.8881x |

This rejects K=4-tile-plus-two as a keygen K=6 direction. Even the lower-bound
row that assumes the first four inputs are already tiled loses slightly, and the
normal-layout round trip is much worse. Keygen forward-NTT work should therefore
not split six polynomials into a K=4 tile plus two scalar transforms; it needs a
different schedule or representation that covers all six outputs without a
normal-layout conversion boundary.

A direct K=4 input-generation follow-up tested that condition from the PRF/CBD
side. The bench-only tile2x4 decoders validate against the current four normal
ETA2 CBD outputs packed into the same layout. Pinned CPU 0, `clang`,
`AVX2_BACKEND=core`, `200000`-iteration snapshots measured:

| Build | Metric | ns/op | Comparison |
|---|---|---:|---:|
| native | `mlkem_cbd_eta2x4` | 30.49 | baseline |
| native | `mlkem_cbd_eta2x4_pack_tile2x4` | 48.41 | +17.92 ns |
| native | `mlkem_cbd_eta2x4_direct_tile2x4` | 45.57 | +15.08 ns |
| native | `mlkem_prf_cbd_eta2x4_current` | 197.11 | baseline |
| native | `mlkem_prf_cbd_eta2x4_direct_tile2x4` | 211.78 | 0.931x |
| AVX2-only | `mlkem_cbd_eta2x4` | 38.87 | baseline |
| AVX2-only | `mlkem_cbd_eta2x4_pack_tile2x4` | 79.69 | +40.82 ns |
| AVX2-only | `mlkem_cbd_eta2x4_direct_tile2x4` | 54.15 | +15.28 ns |
| AVX2-only | `mlkem_prf_cbd_eta2x4_current` | 314.56 | baseline |
| AVX2-only | `mlkem_prf_cbd_eta2x4_direct_tile2x4` | 330.41 | 0.952x |

This rejects direct tile2x4 PRF/CBD as a standalone production change. Direct
tile output removes much of the explicit pack cost, especially on AVX2-only, but
it is still about 15 ns slower than producing four normal CBD polynomials. The
full PRF/CBD x4 path also loses on both native and AVX2-only builds. Combined
with the NTT result above, the AVX2-only tile2x4 NTT parity is not enough to pay
for the input-generation cost, and native loses on both sides of the boundary.

A follow-up CBD-side diagnostic checks the input-generation part of the K=3
layout question. `mlkem_cbd_eta2x3` measures three prepared ETA2 CBD decodes,
while `mlkem_cbd_eta2x3_pack_aos4` adds the diagnostic AoS4 pack step after the
three normal polynomial outputs have already been produced. Pinned CPU 0,
`clang`, `AVX2_BACKEND=core`, `200000`-iteration snapshots measured:

| Build | Metric | ns/op | Extra vs CBD x3 |
|---|---|---:|---:|
| native | `mlkem_cbd_eta2` | 7.32 | - |
| native | `mlkem_cbd_eta2x3` | 22.80 | - |
| native | `mlkem_cbd_eta2x3_pack_aos4` | 40.36 | +17.56 |
| native | `mlkem_cbd_eta2x3_direct_aos4` | 38.77 | +15.97 |
| AVX2-only | `mlkem_cbd_eta2` | 9.59 | - |
| AVX2-only | `mlkem_cbd_eta2x3` | 29.66 | - |
| AVX2-only | `mlkem_cbd_eta2x3_pack_aos4` | 59.99 | +30.33 |
| AVX2-only | `mlkem_cbd_eta2x3_direct_aos4` | 46.24 | +16.58 |

This makes the packed-layout target more specific: converting three already
decoded CBD polynomials into AoS4 costs about 18 ns on native and 30 ns on
AVX2-only. Direct CBD-to-AoS4 generation cuts the AVX2-only overhead roughly in
half, but still costs about 16 ns more than producing three normal polynomial
outputs because the padded/interleaved AoS4 stores are heavier. A serious packed
K=3 NTT therefore has to consume this representation directly and recover that
input-side cost inside the transform; direct packed CBD alone is not a complete
optimization.

The useful target for a packed K=3 forward NTT is therefore not another call-site
shuffle. It must make `mlkem_ntt3_inplace` materially lower than three independent
`ntt(in, in)` calls while preserving the existing single-polynomial path.

A K=3 forward-NTT head+tail interleave experiment was rejected. The candidate
added `ntt3_inplace(f0, f1, f2)`, interleaving the upper forward-NTT stages across
three polynomials and also interleaving the existing AVX2/AVX512 tail helpers
across the same three polynomials. Production AVX2 paths routed keygen `shat`,
keygen `ehat`, encapsulation `rhat`, and decapsulation `u` through this helper;
`bench_ntt` also validated `ntt3_inplace()` against three independent `ntt()`
results.

Correctness passed native `make test`, AVX2-only `make test`, and short
native/AVX2-only `bench-ntt-run` validation. The direct `mlkem_ntt3_inplace` A/B
rejected it: reusing the same zeta/load schedule across three polynomials without
changing the in-memory representation increased instruction pressure and lost on
both native and AVX2-only builds.

A/B command shape:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=ntt NTT_ITERS=200000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
RUNS=9 WARMUP_RUNS=2 SUITES=ntt NTT_ITERS=200000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected K=3 head+tail interleave highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_ntt3_inplace` native | 510.09 | 531.75 | 0.9593x | 0.9635x |
| `mlkem_ntt3_inplace` AVX2-only | 587.74 | 674.69 | 0.8711x | 0.8715x |

Keep the baseline three independent `ntt()` calls. The next viable K=3 attempt
must actually change representation, for example by packing same-index
coefficients from multiple polynomials into SIMD lanes before butterfly work, not
just by interleaving existing per-polynomial butterflies.

A hand-written AVX2 forward-head experiment was also rejected. The candidate
added precomputed `ZETA_NTT_HEAD_L7_L4` vectors and replaced the AVX2-only
compiler-vectorized upper forward-NTT stages (`log2len = 7..4`) with an explicit
`ntt_head_avx2()` built from repeated `ntt_butterfly8_avx2()` calls. The native
AVX512 head path was left unchanged; the goal was to reduce the three-polynomial
forward-NTT baseline by making the single-polynomial AVX2 head cheaper.

Correctness passed native `make test`, AVX2-only `make test`, and AVX2-only
`bench-ntt-run` validation. Direct AVX2-only NTT A/B rejected it because the
manual helper was slower than clang's existing vectorized scalar loop in the full
forward transform.

AVX2-only A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=ntt NTT_ITERS=200000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected AVX2 forward-head highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_ntt_copy` | 199.10 | 209.18 | 0.9518x | 0.9546x |
| `mlkem_ntt_inplace` | 196.64 | 205.31 | 0.9578x | 0.9578x |
| `mlkem_ntt3_inplace` | 587.87 | 616.46 | 0.9536x | 0.9547x |

Keep the compiler-vectorized AVX2 upper forward-NTT loop. The next useful
forward-NTT attempt should avoid manually re-expressing the same per-polynomial
butterflies and instead change either the multi-polynomial representation or a
larger fused operation around NTT.

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

A forward-NTT in-place wrapper split was also rejected. The candidate split the
body of `ntt()` into `ntt_inplace(poly256 f)`, left `ntt(in, out)` as a copy plus
`ntt_inplace(out)`, and routed the production hot-path `ntt(x, x)` calls plus the
in-place NTT/stage benchmark rows through the explicit helper. The intended
effect was to remove the alias check and copy-shape ambiguity from keygen,
encapsulation, and decapsulation forward transforms without changing any
butterfly arithmetic.

Correctness passed for native `make test`, AVX2-only `make test`, and short
native/AVX2-only `bench-ntt-run` validation, but A/B did not justify adoption.
Native NTT/stage was effectively flat and AVX2-only regressed the direct
encryption NTT stage. Because this is only a call-shape refactor, not a real
multi-stage/data-layout improvement, the source change was reverted.

A/B command shape:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=ntt,stage NTT_ITERS=200000 STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
RUNS=13 WARMUP_RUNS=3 SUITES=ntt,stage NTT_ITERS=200000 STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected in-place wrapper split highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_ntt_inplace` native | 171.08 | 172.19 | 0.9936x | 1.0004x |
| `mlkem_core_stage_encrypt_noise_ntt` native | 695.31 | 689.31 | 1.0087x | 1.0051x |
| `mlkem_core_stage_decrypt_u_ntt` native | 689.96 | 688.54 | 1.0021x | 1.0010x |
| `mlkem_ntt_inplace` AVX2-only | 196.55 | 196.51 | 1.0002x | 1.0005x |
| `mlkem_core_stage_encrypt_noise_ntt` AVX2-only | 776.84 | 789.50 | 0.9840x | 0.9824x |
| `mlkem_core_stage_decrypt_u_ntt` AVX2-only | 789.13 | 789.20 | 0.9999x | 1.0006x |

Keep the existing `ntt()` wrapper. Future forward-NTT work should change the data
movement inside the transform, not merely expose the current in-place shape.

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
| `mlkem_prf_cbd_eta2x2_current` | current AVX2 two-output PRF/CBD helper used by the second keygen noise batch |
| `mlkem_prf_cbd_eta2x2_direct` | bench-only two-output PRF/CBD helper that decodes CBD directly from the Keccak-f4 state |
| `mlkem_prf_cbd_eta2x3_current` | current AVX2 three-output PRF/CBD helper used by the second encryption noise batch |
| `mlkem_prf_cbd_eta2x3_direct` | bench-only three-output PRF/CBD helper that decodes CBD directly from the Keccak-f4 state |
| `mlkem_prf_cbd_eta2x4_current` | current AVX2 four-output PRF/CBD helper used by the first keygen/encrypt noise batch |
| `mlkem_prf_cbd_eta2x4_direct_tile2x4` | bench-only four-output PRF/CBD helper that decodes directly from the Keccak-f4 state into the diagnostic K=4 tile2x4 layout |
| `mlkem_cbd_eta2` | `sample_poly_cbd(ETA2)` over prepared PRF bytes |
| `mlkem_cbd_eta2x3` | three prepared ETA2 CBD decodes, matching one K=3 NTT input vector |
| `mlkem_cbd_eta2x3_pack_aos4` | three ETA2 CBD decodes followed by pack into the diagnostic K=3 AoS4 layout |
| `mlkem_cbd_eta2x3_direct_aos4` | direct ETA2 CBD decode of three prepared inputs into the diagnostic K=3 AoS4 layout |
| `mlkem_cbd_eta2x4` | four prepared ETA2 CBD decodes, matching the K=4 tile2x4 input-generation diagnostic |
| `mlkem_cbd_eta2x4_pack_tile2x4` | four ETA2 CBD decodes followed by pack into the diagnostic K=4 tile2x4 layout |
| `mlkem_cbd_eta2x4_direct_tile2x4` | direct ETA2 CBD decode of four prepared inputs into the diagnostic K=4 tile2x4 layout |
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

A narrower AVX2-only follow-up using `#pragma clang loop unroll_count(2)` on
`keccakf4()` was also rejected. This kept correctness but did not produce a
stable direct Keccak win, and the integrated PRF/SHAKE rows were neutral.

AVX2-only Keccak A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=keccak KECCAK_ITERS=200000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Keccak highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_keccakf4` | 451.43 | 441.32 | 1.0229x | 0.9734x |
| `mlkem_prf_eta2` | 221.19 | 221.63 | 0.9980x | 0.9994x |
| `mlkem_sample_ntt_full` | 690.25 | 692.83 | 0.9963x | 1.0019x |

Keep the `keccakf4()` round loop in its current rolled form. Small fixed-factor
unroll hints are not a reliable alternative to the already rejected full unroll.

A later AVX2-only function-boundary experiment was accepted. The change marks
`keccakf4()` as `always_inline` so hot callers can embed the permutation body,
while keeping the internal 24-round loop rolled. This is different from the
rejected round-loop unrolls: it targets the call boundary and repeated 25-lane
state load/store traffic around x4 Keccak users, not the round schedule itself.
The change remains vendor-free and does not call an external backend.

AVX2-only direct Keccak A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=keccak KECCAK_ITERS=200000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Direct Keccak highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_keccakf4` | 502.18 | 287.59 | 1.7462x | 1.4142x |
| `mlkem_prf_cbd_eta2x2_current` | 459.60 | 498.83 | 0.9214x | 0.9933x |
| `mlkem_prf_cbd_eta2x3_current` | 464.14 | 489.02 | 0.9491x | 1.0466x |
| `mlkem_sample_ntt_full` | 692.39 | 690.78 | 1.0023x | 0.9996x |

The direct `keccakf4` row shows that the call boundary matters, but direct
`sample_ntt_full` is too broad and scalar-heavy to prove the integrated effect.
The deciding evidence is the AVX2-only stage/KEM run:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage,kem STAGE_ITERS=50000 KEM_ITERS=20000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

AVX2-only stage/KEM highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_full_raw` | 1654.92 | 1584.03 | 1.0447x | 1.1445x |
| `mlkem_core_stage_sample_matrix_x4_batch0` | 1851.26 | 1777.01 | 1.0418x | 1.1237x |
| `mlkem_core_stage_sample_matrix_x4_batch1` | 1977.98 | 1897.22 | 1.0426x | 1.1297x |
| `mlkem_core_stage_sample_matrix` | 4315.83 | 4174.71 | 1.0338x | 1.0938x |
| `mlkem_core_stage_kpke_keygen_full` | 6529.50 | 5947.58 | 1.0978x | 1.1514x |
| `mlkem_keygen_core` | 8840.33 | 7795.06 | 1.1341x | 1.1086x |
| `mlkem_encaps_core` | 9154.57 | 7508.75 | 1.2192x | 1.2380x |
| `mlkem_roundtrip_core` | 26093.83 | 22234.18 | 1.1736x | 1.1926x |

A longer AVX2-only KEM confirmation with `RUNS=17`, `KEM_ITERS=50000` kept the
signal: `mlkem_keygen_core` median `1.1105x`, `mlkem_encaps_core` `1.1174x`,
`mlkem_decaps_core` `1.2342x`, and `mlkem_roundtrip_core` `1.1876x`. Native
KEM-only confirmation with the default `-march=native` build stayed neutral to
slightly positive (`mlkem_roundtrip_core` median `1.0013x`), although some
native AVX2-tail diagnostics such as `sample_ntt4_one_full_raw` moved slightly
negative. Treat this as an AVX2-only core win with native KEM no-regression, not
as a native sampler-tail optimization.

A native AVX512 follow-up applying the same `always_inline` boundary removal to
`keccakf8()` was rejected. The candidate changed only the `keccakf8()` function
attribute and kept the 24-round loop rolled. It passed native `make test`, but
native stage/KEM A/B showed only a weak local signal and the longer KEM
confirmation was neutral-to-negative.

Native stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage,kem STAGE_ITERS=50000 KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

Rejected `keccakf8()` inline highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_matrix` | 1898.67 | 1893.47 | 1.0027x | 1.0018x |
| `mlkem_core_stage_keygen_noise_prf_cbd` | 691.77 | 692.72 | 0.9986x | 0.9988x |
| `mlkem_core_stage_kpke_keygen_full` | 3420.80 | 3419.39 | 1.0004x | 0.9994x |
| `mlkem_keygen_core` | 5256.00 | 5253.30 | 1.0005x | 1.0008x |
| `mlkem_roundtrip_core` | 14587.56 | 14525.46 | 1.0043x | 1.0033x |

The longer native KEM confirmation with `RUNS=17`, `KEM_ITERS=50000` did not
hold the full-path signal: `mlkem_keygen_core` median `1.0005x` and
`mlkem_encaps_core` `1.0014x` were neutral, while `mlkem_roundtrip_core` median
regressed to `0.9997x`. Keep only the AVX2 `keccakf4()` inline boundary change;
`keccakf8()` should remain a normal helper unless a future rewrite improves the
x8 sampler or PRF path directly.

These numbers show that further sampling work should target Keccak/SHAKE128 and
full `sample_ntt()` first; standalone CBD is already much smaller.

### Independent Core Optimization A/B (2026-07-03, AVX2 eta2x2 direct PRF/CBD)

An AVX2-only PRF/CBD cleanup was accepted. The second keygen noise batch uses
`mlkem_prf_cbd_eta2x2_32()` for nonces `4,5`; the old helper permuted the low two
Keccak-f4 lanes through a stack `uint8_t stream[2][128]` and then called
`sample_poly_cbd_eta2_bytes()` twice. The new helper decodes directly from each
Keccak state word with `sample_poly_cbd_eta2_store2_avx2()`, matching the already
used x3/x4 direct-state shape. The helper is marked `MLKEM_NOINLINE`: the inline
variant made the x2 microbench fast, but regressed the integrated keygen noise
rows, so the call boundary is kept to contain code-size/register-pressure effects.

Correctness passed the AVX2 gate:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

The rejected inline diagnostic used `RUNS=13`, `WARMUP_RUNS=3`,
`SUITES=keccak,stage`; it improved `mlkem_prf_cbd_eta2x2_current` to median
`1.4663x`, but regressed `mlkem_core_stage_keygen_noise_prf_cbd` to `0.9875x`,
`mlkem_core_stage_keygen_noise_ntt` to `0.9935x`, and KEM `mlkem_keygen` to
`0.9989x`. Keep the direct decode, but not as an inline expansion into the
keygen-noise wrapper.

Accepted noinline AVX2-only keccak/stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=keccak,stage KECCAK_ITERS=200000 \
  STAGE_ITERS=70000 C_COMPILER=clang PIN_CPU=0 \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" ./scripts/bench_core_ab.sh HEAD
```

Accepted noinline keccak/stage highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_prf_cbd_eta2x2_current` | 511.92 | 293.82 | 1.7423x | 1.4654x |
| `mlkem_prf_cbd_eta2x2_direct` | 294.61 | 295.50 | 0.9970x | 0.9979x |
| `mlkem_core_stage_keygen_noise_prf_cbd` | 974.43 | 965.72 | 1.0090x | 1.0093x |
| `mlkem_core_stage_keygen_noise_ntt` | 1994.16 | 1985.15 | 1.0045x | 1.0044x |
| `mlkem_core_stage_kpke_keygen_full` | 4809.44 | 4809.26 | 1.0000x | 0.9989x |
| `mlkem_core_stage_kpke_encrypt_cached` | 2434.83 | 2422.20 | 1.0052x | 1.0050x |

Accepted noinline AVX2-only KEM confirmation command:

```bash
RUNS=17 WARMUP_RUNS=4 SUITES=kem KEM_ITERS=40000 C_COMPILER=clang \
  PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" ./scripts/bench_core_ab.sh HEAD
```

KEM confirmation highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_keygen` | 6944.58 | 6936.66 | 1.0011x | 1.0010x |
| `mlkem_keygen_core` | 6919.44 | 6916.95 | 1.0004x | 1.0002x |
| `mlkem_decaps_core` | 6084.53 | 6045.60 | 1.0064x | 1.0019x |
| `mlkem_encaps_core` | 6995.59 | 7011.75 | 0.9977x | 1.0109x |
| `mlkem_roundtrip` | 13379.63 | 13363.60 | 1.0012x | 1.0006x |
| `mlkem_roundtrip_core` | 20123.65 | 20096.68 | 1.0013x | 1.0035x |

This is a small vendor-free core win. It does not change the CBD math or wire
format; it removes the avoidable stream materialization in the two-output ETA2
path and keeps the optimized helper behind a call boundary so the larger keygen
and KEM code layout remains stable.

A follow-up AVX2 keygen PRF/CBD composition experiment was rejected. The
candidate replaced the current keygen `x4(0,1,2,3) + x2(4,5)` split with
`x3(0,1,2) + x3(3,4,5)`, reusing the already direct-state x3 helper for both
batches. The goal was to remove the remaining two-output helper call and use a
more uniform three-output decode/store shape without changing Keccak count,
nonce order, CBD math, or output polynomials.

Correctness passed the AVX2 gate:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage STAGE_ITERS=70000 C_COMPILER=clang \
  PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" ./scripts/bench_core_ab.sh HEAD
```

Rejected x3+x3 composition highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_noise_prf_cbd` | 965.88 | 966.37 | 0.9995x | 0.9992x |
| `mlkem_core_stage_keygen_noise_ntt` | 1985.39 | 1988.06 | 0.9987x | 0.9987x |
| `mlkem_core_stage_keygen_noise_ntt_encode` | 1588.93 | 1590.98 | 0.9987x | 0.9975x |
| `mlkem_core_stage_keygen_noise_ntt_only` | 1544.19 | 1555.48 | 0.9927x | 0.9968x |
| `mlkem_core_stage_kpke_keygen_full` | 4812.81 | 4824.78 | 0.9975x | 1.0003x |
| `mlkem_core_stage_kpke_prepare_public_no_cache` | 4154.61 | 4180.03 | 0.9939x | 0.9953x |
| `mlkem_core_stage_encrypt_noise_prf_cbd` | 1174.40 | 1151.40 | 1.0200x | 1.0200x |
| `mlkem_core_stage_kpke_encrypt_cached` | 2431.29 | 2419.58 | 1.0048x | 1.0054x |

Keep keygen on the accepted `x4 + noinline x2` composition. The apparent
positive movement in unrelated encryption rows is code-layout noise; the direct
keygen noise rows are neutral-to-negative, so KEM confirmation was skipped.

A follow-up AVX2 encrypt PRF/CBD composition experiment was rejected. The
candidate changed the encryption noise split from `x4(0,1,2,3) + x3(4,5,6)` to
`x3(0,1,2) + x4(3,4,5,6)`. This keeps two Keccak-f4 permutations and the same
nonce/output mapping, but groups all `rhat[0..2]` outputs in the first helper and
all `e1[0..2]` plus `e2` outputs in the second helper. The intent was to align
the PRF/CBD boundary with the later NTT-only `rhat` consumer and the later
non-NTT error consumers.

Correctness passed the AVX2-only gate:

```bash
make test CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected encrypt composition stage highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_encrypt_noise_prf_cbd` | 1178.72 | 1168.46 | 1.0088x | 1.0031x |
| `mlkem_core_stage_encrypt_noise` | 1403.41 | 1400.45 | 1.0021x | 1.0018x |
| `mlkem_core_stage_kpke_encrypt_cached` | 2425.57 | 2423.50 | 1.0009x | 1.0025x |
| `mlkem_core_stage_kpke_encrypt_uncached` | 4887.14 | 4893.61 | 0.9987x | 0.9996x |

AVX2-only KEM confirmation command:

```bash
RUNS=11 WARMUP_RUNS=3 SUITES=kem KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected encrypt composition KEM highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_encaps` | 2691.65 | 2688.48 | 1.0012x | 1.0007x |
| `mlkem_encaps_core` | 7069.39 | 6946.90 | 1.0176x | 0.9949x |
| `mlkem_decaps_core` | 6064.34 | 6079.20 | 0.9976x | 0.9992x |
| `mlkem_roundtrip` | 13364.09 | 13351.13 | 1.0010x | 1.0012x |
| `mlkem_roundtrip_core` | 20191.67 | 20075.75 | 1.0058x | 0.9971x |

Decision: keep the current encryption `x4(0,1,2,3) + x3(4,5,6)` composition.
The local PRF/CBD row improves slightly, but the no-cache encrypt row is not
positive and the KEM core medians for encapsulation and roundtrip move negative.
The top-level positive movement is too small to justify a core code-shape change.
Future PRF/CBD work should fill otherwise unused lanes with independent useful
work, as in the accepted tail co-schedules, not merely repartition the same seven
noise outputs.

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
| `mlkem_core_stage_kpke_encrypt_uncached_rowwise` | AVX2-only diagnostic: cache-disabled encryption that generates noise/tail first, NTTs `r`, then samples public-matrix x4 batches and consumes complete rows immediately |
| `mlkem_core_stage_kpke_encrypt_uncached_tail21` | AVX2-only diagnostic: cache-disabled encryption that rotates the co-scheduled scalar public-matrix tail from `(2,2)` to `(2,1)` and samples `(2,2)` in the second x4 batch |
| `mlkem_core_stage_kpke_prepare_public_no_cache` | no-cache `mlkem_encaps()` public preparation: public-key d12 decode, public-matrix sampling, and `H(ek)` with the AVX2 hash/tail co-schedule |
| `mlkem_core_stage_kpke_prepare_public_no_cache_tail21` | AVX2-only diagnostic: no-cache public preparation that rotates the hash/co-scheduled scalar public-matrix tail from `(2,2)` to `(2,1)` and samples `(2,2)` in the second x4 batch |
| `mlkem_core_stage_public_key_decode_d12` | public-key d12 decode only for the three encoded public-key polynomials |
| `mlkem_core_stage_kpke_decrypt_uncached` | full `kpke_decrypt()` with internal caches disabled |
| `mlkem_core_stage_kpke_encrypt_cached` | full `kpke_encrypt()` with a cached public key, for repeated-key context only |
| `mlkem_core_stage_kpke_decrypt_cached` | full `kpke_decrypt()` with a cached secret key, for repeated-key context only |
| `mlkem_core_stage_sample_matrix` | the 3x3 `sample_ntt()` public matrix generation |
| `mlkem_core_stage_sample_matrix_x4_batch0` | first four-entry x4 public-matrix sampler batch |
| `mlkem_core_stage_sample_matrix_x4_batch1` | second four-entry x4 public-matrix sampler batch |
| `mlkem_core_stage_sample_matrix_tail` | final `(2,2)` public-matrix sampler tail |
| `mlkem_core_stage_sample_matrix_tail_scalar` | final `(2,2)` public-matrix sampler tail forced through scalar `sample_ntt()` with full checksum |
| `mlkem_core_stage_sample_matrix_tail_scalar_raw` | final `(2,2)` scalar `sample_ntt()` tail with a lightweight sink, excluding full-polynomial checksum overhead |
| `mlkem_core_stage_sample_matrix_tail_choice_XX` | AVX2-only diagnostic: choose matrix entry `XX` as the scalar tail and place the other eight entries into two row-major x4 sampler batches |
| `mlkem_core_stage_sample_matrix_x3x3x3` | AVX2-only diagnostic: generate the full 3x3 public matrix as three row-major three-lane sampler groups |
| `mlkem_core_stage_sample_matrix_x4x3x2` | AVX2-only diagnostic: generate the full 3x3 public matrix as one x4 group, one x3 group, and one x2 group |
| `mlkem_core_stage_keygen_matrix_noise_current` | AVX2-only bench of the production keygen matrix/noise order: x4 batch0, co-scheduled PRF/CBD plus `(2,2)` tail, x4 batch1 |
| `mlkem_core_stage_keygen_matrix_noise_tail_first` | AVX2-only diagnostic order: co-scheduled PRF/CBD plus `(2,2)` tail before both public-matrix x4 batches |
| `mlkem_core_stage_keygen_matrix_noise_tail_last` | AVX2-only diagnostic order: both public-matrix x4 batches before co-scheduled PRF/CBD plus `(2,2)` tail |
| `mlkem_core_stage_keygen_matrix_noise_tail21` | AVX2-only diagnostic: keygen matrix/noise co-schedule using `(2,1)` as the PRF/CBD tail lane and placing `(2,2)` in the second x4 matrix batch |
| `mlkem_core_stage_sample_ntt4_full_raw` | AVX2-only x4 sampler call with a lightweight sink, excluding full-polynomial checksum overhead |
| `mlkem_core_stage_sample_ntt4_full_raw_batch1` | AVX2-only x4 sampler call for the second public-matrix batch tuple, with the same lightweight sink as `sample_ntt4_full_raw` |
| `mlkem_core_stage_sample_ntt4_block_parse_full_raw` | AVX2-only diagnostic: x4 sampler variant that parses each 168-byte SHAKE block immediately instead of materializing and parsing the initial 504-byte streams |
| `mlkem_core_stage_sample_ntt4_state_parse_full_raw` | AVX2-only diagnostic: x4 sampler variant that parses Keccak state words directly with a scalar streaming parser instead of materializing 504-byte streams |
| `mlkem_core_stage_sample_ntt4_state_mask3` | AVX2-only diagnostic lower bound: initial three `keccakf4_mem()` blocks plus direct SIMD validity masks from state words, without output compaction |
| `mlkem_core_stage_sample_ntt4_init_only` | AVX2-only diagnostic: x4 sampler Keccak-state initialization for the same lane tuple as `sample_ntt4_full_raw` |
| `mlkem_core_stage_sample_ntt4_scalar4_raw` | AVX2-only diagnostic: four scalar `sample_ntt()` calls for the same entries as `sample_ntt4_full_raw`, with the same lightweight sink |
| `mlkem_core_stage_sample_ntt2_full_raw` | AVX2-only diagnostic: two-lane SHAKE128 matrix sampler for `(2,0)` and `(2,1)`, using the existing parser and a lightweight sink |
| `mlkem_core_stage_sample_ntt3_full_raw` | AVX2-only diagnostic: three-lane SHAKE128 matrix sampler for `(1,2)`, `(2,0)`, and `(2,1)`, using the existing parser and a lightweight sink |
| `mlkem_core_stage_sample_ntt4_store_rate` | AVX2-only x4 sampler 168-byte-rate state transpose/store cost |
| `mlkem_core_stage_sample_ntt4_keccak3_only` | AVX2-only x4 sampler initial three production `keccakf4_mem()` blocks, excluding stream stores |
| `mlkem_core_stage_sample_ntt4_keccak_store3` | AVX2-only x4 sampler initial three production `keccakf4_mem()` blocks plus stream stores |
| `mlkem_core_stage_sample_ntt4_parse_504` | AVX2-only x4 sampler parse of four 504-byte rejection streams |
| `mlkem_core_stage_sample_ntt4_common3_step` | AVX2-only x4 sampler common first three-rate step, including Keccak state init, three production Keccak/store blocks, four 504-byte parses, and refill-decision bookkeeping |
| `mlkem_core_stage_sample_ntt4_refill_keccak_store1` | AVX2-only x4 sampler one additional production register `keccakf4()` refill block plus stream stores, conditioned on groups that need refill |
| `mlkem_core_stage_sample_ntt4_refill_step_once` | AVX2-only x4 sampler one additional refill step including Keccak/store and parsing only lanes still below 256 coefficients |
| `mlkem_core_stage_sample_ntt4_one_full_raw` | AVX2-only one-lane x4 tail sampler call with a lightweight sink, excluding full-polynomial checksum overhead |
| `mlkem_core_stage_sample_ntt4_one_keccak_store3` | AVX2-only one-lane x4 tail sampler initial three Keccak-f4 blocks plus lane-0 stream stores |
| `mlkem_core_stage_sample_ntt4_one_parse_504` | AVX2-only one-lane x4 tail sampler parse of one 504-byte rejection stream |
| `mlkem_core_stage_sample_ntt4_initial_extra_groups` | AVX2-only x4 sampler groups that need a refill after the first 504 bytes per lane |
| `mlkem_core_stage_sample_ntt4_initial_extra_group_pct` | percent of x4 sampler groups that need a refill after the first 504 bytes per lane |
| `mlkem_core_stage_sample_ntt4_initial_extra_lanes` | AVX2-only x4 sampler lanes that need a refill after the first 504 bytes |
| `mlkem_core_stage_sample_ntt4_initial_extra_lane_pct` | percent of x4 sampler lanes that need a refill after the first 504 bytes |
| `mlkem_core_stage_sample_ntt4_initial_avg_accepts` | average accepted coefficients after the first 504-byte parse |
| `mlkem_core_stage_sample_ntt4_initial_min_accepts` | minimum accepted coefficients observed after the first 504-byte parse |
| `mlkem_core_stage_sample_ntt4_batch1_initial_*` | same initial refill/acceptance counters for the second AVX2 public-matrix x4 batch tuple |
| `mlkem_core_stage_sample_ntt4_one_initial_extra_lanes` | AVX2-only one-lane x4 tail sampler lanes that need a refill after the first 504 bytes |
| `mlkem_core_stage_sample_ntt4_one_initial_extra_lane_pct` | percent of one-lane x4 tail sampler lanes that need a refill after the first 504 bytes |
| `mlkem_core_stage_sample_ntt4_one_initial_avg_accepts` | average accepted coefficients after the one-lane x4 tail sampler first 504-byte parse |
| `mlkem_core_stage_sample_ntt4_one_initial_min_accepts` | minimum accepted coefficients observed in the one-lane x4 tail sampler after the first 504-byte parse |
| `mlkem_core_stage_keygen_noise_ntt` | keygen secret/error PRF, CBD, NTT, and secret-key encode |
| `mlkem_core_stage_keygen_noise_prf_cbd` | isolated keygen secret/error PRF and CBD only |
| `mlkem_core_stage_keygen_noise_ntt_encode` | isolated keygen secret/error NTT plus secret-key encode |
| `mlkem_core_stage_keygen_noise_ntt_only` | isolated keygen six-polynomial secret/error forward NTT, excluding secret-key encode |
| `mlkem_core_stage_keygen_noise_ntt_headtail_batch` | AVX2-only diagnostic: run the upper forward-NTT levels for all six keygen secret/error polynomials before running all six AVX2 tails |
| `mlkem_core_stage_keygen_noise_ntt_encode_headtail_batch` | AVX2-only diagnostic: the same six-polynomial head/tail batch schedule plus d12 secret-key encode for `shat[0..2]` |
| `mlkem_core_stage_keygen_secret_ntt_encode_only` | isolated keygen secret-vector forward NTT plus secret-key d12 encode for `shat[0..2]` |
| `mlkem_core_stage_keygen_secret_ntt_only` | isolated keygen secret-vector three-polynomial forward NTT for `shat[0..2]`, excluding d12 encode |
| `mlkem_core_stage_keygen_error_ntt_only` | isolated keygen error-vector three-polynomial forward NTT for `ehat[0..2]` |
| `mlkem_core_stage_keygen_noise_ntt_head_only` | AVX2-only keygen six-polynomial forward NTT upper stages before `ntt_tail_avx2()` |
| `mlkem_core_stage_keygen_noise_ntt_tail_only` | AVX2-only keygen six-polynomial `ntt_tail_avx2()` lower stages, using precomputed head output |
| `mlkem_core_stage_keygen_secret_encode_only` | isolated keygen secret-key d12 encode for the already transformed `shat` vector |
| `mlkem_core_stage_keygen_secret_decode_only` | isolated d12 decode for the three secret-key polynomials, with lightweight sink |
| `mlkem_core_stage_keygen_accum_encode` | keygen NTT-domain multiply-add, add error, and public-key encode |
| `mlkem_core_stage_keygen_accum_add_only` | isolated keygen public-vector NTT-domain multiply-add plus error add, excluding public-key encode |
| `mlkem_core_stage_keygen_accum_only` | isolated keygen public-vector `A^T*s` NTT-domain multiply-add, excluding error add and public-key encode |
| `mlkem_core_stage_keygen_add_only` | isolated keygen public-vector error add, using precomputed `A^T*s` and `ehat` |
| `mlkem_core_stage_keygen_error_ntt_add_canonical_ehat` | AVX2-only diagnostic: canonical forward NTT for the three keygen error polynomials followed by add into precomputed `A^T*s` |
| `mlkem_core_stage_keygen_error_ntt_add_lazy_ehat` | AVX2-only diagnostic: lazy multiply-input forward NTT for the three keygen error polynomials followed by an add that reduces only the lazy `ehat` input |
| `mlkem_core_stage_keygen_public_encode_only` | isolated keygen public-key d12 encode for the already accumulated `that` vector |
| `mlkem_core_stage_keygen_public_decode_only` | isolated d12 decode for the three public-key polynomials, with lightweight sink |
| `mlkem_core_stage_encrypt_noise` | encryption PRF, CBD, and canonical NTT for `r`, using the historical stage shape |
| `mlkem_core_stage_encrypt_noise_lazy` | AVX2-only production-aligned encryption PRF, CBD, and lazy multiply-input NTT for `r` |
| `mlkem_core_stage_encrypt_noise_prf_cbd` | isolated encryption PRF and CBD for `r`, `e1`, and `e2` |
| `mlkem_core_stage_encrypt_noise_prf_cbd_tail_separate` | AVX2-only diagnostic: scalar `(2,2)` public-matrix tail plus encryption PRF/CBD, using a lightweight sink |
| `mlkem_core_stage_encrypt_noise_prf_cbd_tail_cosched` | AVX2-only diagnostic: encryption PRF/CBD with the first `(2,2)` public-matrix tail block co-scheduled into the nonce 4/5/6 `keccakf4()` call |
| `mlkem_core_stage_encrypt_noise_prf_cbd_tail_cosched_accum3` | AVX2-only diagnostic: co-scheduled encryption PRF/CBD tail using the keygen-style three-rate tail parse schedule |
| `mlkem_core_stage_encrypt_noise_prf_cbd_tail_separate_lazy` | AVX2-only diagnostic: scalar `(2,2)` public-matrix tail plus encryption PRF/CBD and production lazy multiply-input NTT for `r` |
| `mlkem_core_stage_encrypt_noise_prf_cbd_tail_cosched_lazy` | AVX2-only diagnostic: co-scheduled `(2,2)` public-matrix tail plus encryption PRF/CBD and production lazy multiply-input NTT for `r` |
| `mlkem_core_stage_encrypt_noise_prf_cbd_tail_cosched_accum3_lazy` | AVX2-only diagnostic: co-scheduled three-rate tail parse plus encryption PRF/CBD and production lazy multiply-input NTT for `r` |
| `mlkem_core_stage_encrypt_noise_ntt` | isolated encryption forward NTT for `r` |
| `mlkem_core_stage_encrypt_noise_ntt_lazy` | AVX2-only diagnostic: encryption forward NTT for `r` using the production lazy multiply-input range |
| `mlkem_core_stage_encrypt_accum_inv` | encryption NTT-domain accumulation and inverse NTT for `u` and `v` using the historical canonical fixture |
| `mlkem_core_stage_encrypt_accum_inv_lazy_input` | AVX2-only diagnostic: same accumulation/inverse work but feeding `ntt_mul_acc3()` with production lazy `rhat` in `[0, 2Q)` |
| `mlkem_core_stage_encrypt_accum_inv_u` | the three `u`-polynomial accumulation plus inverse-NTT-add paths |
| `mlkem_core_stage_encrypt_accum_u_only` | isolated three-`u` NTT-domain accumulations, excluding inverse-NTT-add, using the canonical fixture |
| `mlkem_core_stage_encrypt_accum_u_only_lazy_input` | AVX2-only diagnostic: isolated three-`u` accumulations with production lazy `rhat` input |
| `mlkem_core_stage_encrypt_accum4_separate_only` | diagnostic: three `u` accumulations plus the `v` accumulation as four separate `ntt_mul_acc3()` calls, excluding inverse NTT |
| `mlkem_core_stage_encrypt_accum4_combined_only` | diagnostic: one scalar loop computes the same four encryption accumulations while reusing `rhat[0..2]` and `GAMMA` loads |
| `mlkem_core_stage_ntt_mul_acc3_canonical_scalar` | AVX2-only diagnostic: one scalar `ntt_mul_acc3()` over canonical NTT-domain inputs, using the same fixture as the AVX2 canonical diagnostic |
| `mlkem_core_stage_ntt_mul_acc3_canonical_avx2` | AVX2-only diagnostic: one manual 8-pair AVX2 `ntt_mul_acc3()` over canonical inputs, excluding lazy-input canonicalization cost |
| `mlkem_core_stage_encrypt_inv_add_u_only` | isolated three-`u` inverse-NTT-add from precomputed accumulations, including scratch copies to preserve inputs |
| `mlkem_core_stage_encrypt_inv_add_u_head_only` | AVX2 builds only: inverse-NTT head stages for the three precomputed `u` accumulations, including scratch copies |
| `mlkem_core_stage_encrypt_inv_add_u_head_l1` | AVX2 builds only: isolated inverse-head l1 stage for the three `u` accumulations, using precomputed inputs and scratch copies |
| `mlkem_core_stage_encrypt_inv_add_u_head_l2` | AVX2 builds only: isolated inverse-head l2 stage for the three `u` accumulations, using precomputed l1 outputs and scratch copies |
| `mlkem_core_stage_encrypt_inv_add_u_head_l3` | AVX2 builds only: isolated inverse-head l3 stage for the three `u` accumulations, using precomputed l2 outputs and scratch copies |
| `mlkem_core_stage_encrypt_inv_add_u_tail_l4` | AVX2 builds only: isolated inverse-tail l4 stage after precomputed inverse heads for the three `u` accumulations |
| `mlkem_core_stage_encrypt_inv_add_u_tail_l5` | AVX2 builds only: isolated inverse-tail l5 stage after precomputed l4 outputs for the three `u` accumulations |
| `mlkem_core_stage_encrypt_inv_add_u_tail_l6` | AVX2 builds only: isolated inverse-tail l6 stage after precomputed l5 outputs for the three `u` accumulations |
| `mlkem_core_stage_encrypt_inv_add_u_final_only` | AVX2 builds only: final inverse butterfly plus scale/add after precomputed l6 outputs for the three `u` accumulations |
| `mlkem_core_stage_encrypt_inv_add_u_final3_only` | AVX2-only diagnostic: the same final inverse butterfly plus scale/add for the three `u` accumulations, but grouped into one shared `j` loop |
| `mlkem_core_stage_encrypt_inv_add_u_final_d10_encode` | AVX2-only diagnostic: existing final inverse butterfly plus scale/add followed by DU=10 compression/encoding for the three `u` polynomials, from precomputed l6 outputs |
| `mlkem_core_stage_encrypt_inv_add_u_final_d10_encode_fused` | AVX2-only diagnostic: fused final inverse butterfly plus scale/add directly into DU=10 compression/encoding, byte-validated against the existing split path |
| `mlkem_core_stage_encrypt_inv_add_u_final_scale_only` | AVX2 builds only: final inverse butterfly plus inverse-NTT scale after precomputed l6 outputs, excluding the `e1` add |
| `mlkem_core_stage_encrypt_inv_add_u_final_scale_low_only` | AVX2 builds only: low-half `sum * 3303` scale/reduction portion of the final inverse pass |
| `mlkem_core_stage_encrypt_inv_add_u_final_scale_high_only` | AVX2 builds only: high-half `diff * zeta_scale` scale/reduction portion of the final inverse pass |
| `mlkem_core_stage_encrypt_inv_add_u_final_noise_add_only` | AVX2 builds only: final `e1` add against precomputed final-scaled `u` outputs |
| `mlkem_core_stage_encrypt_inv_add_u_tail_final_only` | AVX2 builds only: inverse-NTT tail plus scale/add after precomputed inverse heads for the three `u` accumulations |
| `mlkem_core_stage_encrypt_accum_inv_v` | the single `v`-polynomial accumulation plus inverse-NTT-add2 path |
| `mlkem_core_stage_ciphertext_compress_encode` | ciphertext compression and DU/DV bit-packing |
| `mlkem_core_stage_ciphertext_compress_encode_d10` | isolated ciphertext DU=10 compression/encoding for the three `u` polynomials, with lightweight sink |
| `mlkem_core_stage_ciphertext_compress_encode_d10_compress_only` | isolated DU=10 coefficient compression for the three `u` polynomials, excluding bit-packing |
| `mlkem_core_stage_ciphertext_compress_encode_d10_pack_only` | isolated DU=10 bit-packing for precompressed `u` polynomials, excluding coefficient compression |
| `mlkem_core_stage_ciphertext_compress_encode_d4` | isolated ciphertext DV=4 compression/encoding for the `v` polynomial, with lightweight sink |
| `mlkem_core_stage_ciphertext_decode_decompress` | ciphertext DU/DV decode and decompression |
| `mlkem_core_stage_ciphertext_decode_decompress_d10` | isolated ciphertext DU=10 decode/decompression for the three `u` polynomials, with lightweight sink |
| `mlkem_core_stage_ciphertext_decode_decompress_d4` | isolated ciphertext DV=4 decode/decompression for the `v` polynomial, with lightweight sink |
| `mlkem_core_stage_decrypt_u_ntt` | decrypt-side forward NTT for the three decoded `u` polynomials |
| `mlkem_core_stage_decrypt_u_ntt_lazy` | AVX2-only diagnostic: decrypt-side forward NTT for decoded `u` using the production lazy multiply-input range |
| `mlkem_core_stage_decrypt_u_ntt_head` | AVX2-only decrypt-side forward NTT upper stages before `ntt_tail_avx2()` |
| `mlkem_core_stage_decrypt_u_ntt_tail` | AVX2-only decrypt-side `ntt_tail_avx2()` lower stages, using precomputed head output |
| `mlkem_core_stage_decrypt_accum_only` | decrypt-side `ntt_mul_acc3()` secret accumulation only, using precomputed `ntt(u)` |
| `mlkem_core_stage_decrypt_ntt_accum_only` | decrypt-side canonical forward NTT for three decoded `u` polynomials plus `ntt_mul_acc3()` secret accumulation |
| `mlkem_core_stage_decrypt_lazy_ntt_accum_only` | AVX2-only diagnostic: production lazy multiply-input NTT for three decoded `u` polynomials plus `ntt_mul_acc3()` secret accumulation |
| `mlkem_core_stage_decrypt_inv_sub_from` | decrypt-side inverse NTT subtraction only, using a precomputed NTT-domain accumulation |
| `mlkem_core_stage_decrypt_inv_butterflies` | decrypt-side inverse NTT butterflies only, before final scale/subtraction |
| `mlkem_core_stage_decrypt_inv_copy_only` | AVX2-only diagnostic: decrypt inverse split copy plus checksum baseline for interpreting per-level rows |
| `mlkem_core_stage_decrypt_inv_head` | AVX2-only decrypt-side inverse NTT head stages `l1`..`l3`, using precomputed NTT-domain accumulation |
| `mlkem_core_stage_decrypt_inv_tail` | AVX2-only decrypt-side inverse NTT tail stages `l4`..`l7`, using precomputed inverse-head output |
| `mlkem_core_stage_decrypt_inv_tail_vec8` | AVX2-only diagnostic: explicit 8-lane AVX2 rewrite of decrypt inverse tail `l4`..`l7`, rejected versus the compiler-vectorized scalar tail |
| `mlkem_core_stage_decrypt_inv_head_l1` | AVX2-only diagnostic: decrypt inverse head `l1` stage from precomputed NTT-domain accumulation, using the previous scatter/gather helper shape |
| `mlkem_core_stage_decrypt_inv_head_l1_block` | AVX2-only diagnostic: decrypt inverse head `l1` stage using the production block-load/shuffle helper |
| `mlkem_core_stage_decrypt_inv_head_l2` | AVX2-only diagnostic: decrypt inverse head `l2` stage from precomputed `l1` output, using the previous pair-load helper shape |
| `mlkem_core_stage_decrypt_inv_head_l2_block` | AVX2-only diagnostic: decrypt inverse head `l2` stage using the production block-load helper |
| `mlkem_core_stage_decrypt_inv_head_l3` | AVX2-only diagnostic: decrypt inverse head `l3` stage from precomputed `l2` output |
| `mlkem_core_stage_decrypt_inv_tail_l4` | AVX2-only diagnostic: decrypt inverse tail `l4` stage from precomputed head output |
| `mlkem_core_stage_decrypt_inv_tail_l4_vec8` | AVX2-only diagnostic: explicit 8-lane AVX2 rewrite of decrypt inverse tail `l4`, rejected versus the compiler-vectorized scalar tail |
| `mlkem_core_stage_decrypt_inv_tail_l5` | AVX2-only diagnostic: decrypt inverse tail `l5` stage from precomputed `l4` output |
| `mlkem_core_stage_decrypt_inv_tail_l5_vec8` | AVX2-only diagnostic: explicit 8-lane AVX2 rewrite of decrypt inverse tail `l5`, rejected versus the compiler-vectorized scalar tail |
| `mlkem_core_stage_decrypt_inv_tail_l6` | AVX2-only diagnostic: decrypt inverse tail `l6` stage from precomputed `l5` output |
| `mlkem_core_stage_decrypt_inv_tail_l6_vec8` | AVX2-only diagnostic: explicit 8-lane AVX2 rewrite of decrypt inverse tail `l6`, rejected versus the compiler-vectorized scalar tail |
| `mlkem_core_stage_decrypt_inv_final_sub_from` | AVX2-only diagnostic: production-style final inverse butterfly plus scale/subtraction from precomputed `l6` output |
| `mlkem_core_stage_decrypt_inv_final_sub_recover_split` | AVX2-only diagnostic: final inverse butterfly plus scale/subtraction from precomputed `l6` output, then the existing message recovery pass |
| `mlkem_core_stage_decrypt_inv_final_sub_recover_fused` | AVX2-only diagnostic: final inverse butterfly plus scale/subtraction from precomputed `l6` output, directly producing recovered message bytes |
| `mlkem_core_stage_decrypt_inv_scale_sub_from` | decrypt-side final inverse-NTT scale and subtraction only, using precomputed inverse-butterfly output |
| `mlkem_core_stage_decrypt_accum_inv` | decrypt-side secret accumulation plus inverse NTT subtraction, using precomputed `ntt(u)` |
| `mlkem_core_stage_decrypt_recover_message` | decrypt-side message recovery from the already reconstructed `w` polynomial |
| `mlkem_core_stage_decrypt_ntt_accum_recover` | decrypt-side canonical NTT, accumulation, inverse NTT subtraction, and message recovery |
| `mlkem_core_stage_decrypt_lazy_ntt_accum_recover` | AVX2-only diagnostic: production lazy multiply-input NTT, accumulation, inverse NTT subtraction, and message recovery |

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

A direct boundary metric, `decrypt_ntt_accum_only`, now measures the decrypt-side
three-`u` forward NTTs plus the following `ntt_mul_acc3()` accumulation without
the inverse NTT subtraction or message recovery. On one pinned CPU 0, `clang`,
20,000-iteration snapshot, it measured 747.08 ns/op with the native build and
859.35 ns/op with the AVX2-only build. These rows should not be reconstructed by
adding standalone `decrypt_u_ntt` and `decrypt_accum_only` rows, because those
probes each include independent copy and sink overhead. This metric is the next
reference point for any attempt to fuse the final forward-NTT schedule with the
secret accumulation path.

A decrypt-only secret-cache experiment precomputing `GAMMA[i] * s_hat[2*i+1]`
for the odd secret coefficients was rejected. The candidate replaced the
`c0_hi % Q` plus gamma multiply inside decrypt accumulation with three extra
precomputed secret-side loads per base pair and routed the matching stage
metrics through the same helper. Native and AVX2-only correctness passed, but
stage A/B against `823d48e` with `RUNS=13` and `STAGE_ITERS=40000` regressed the
hot decrypt rows. Native median speedups were `decrypt_accum_only` `0.7020x`,
`decrypt_ntt_accum_only` `0.8806x`, and `kpke_decrypt_cached` `0.8961x`.
AVX2-only median speedups were `decrypt_accum_only` `0.8392x`,
`decrypt_ntt_accum_only` `0.9480x`, and `kpke_decrypt_cached` `0.9633x`. Keep
the current compact accumulation; on this target the extra loads are more
expensive than the scalar reduction and gamma multiply they replace.

An AVX512-capable decrypt boundary fusion was accepted. The implementation runs
the three decoded `u` polynomials through the existing AVX512 forward NTT head
and lower `l3`/`l2` tail stages, then computes the final `l1` butterflies as
base-pair values and feeds them directly into the K=3 secret accumulation. This
avoids writing the final `ntt(u)` arrays only to reload them immediately for
`ntt_mul_acc3()`. Native CPU 0 stage A/B against `725d515` with `RUNS=13` and
`STAGE_ITERS=40000` showed median speedups of `decrypt_ntt_accum_only`
`1.0420x`, `decrypt_ntt_accum_recover` `1.0423x`, and `kpke_decrypt_cached`
`1.0462x`. Native KEM A/B with `RUNS=17` and `KEM_ITERS=50000` showed
`mlkem_decaps` median `1.0086x` and `mlkem_decaps_core` median `1.0048x`, with
roundtrip effectively neutral. The same fused-final shape was rejected for
AVX2-only builds because scalarizing the final `l1` stage outweighed the saved
stores/loads (`decrypt_ntt_accum_only` median `0.9246x`, `kpke_decrypt_cached`
median `0.9396x`), so the production change is guarded to AVX512-capable
builds and AVX2-only keeps the original vector tail plus scalar accumulation.

A narrower AVX512 encryption-side `v` inverse-add final fusion was accepted. The
previous generic `ntt_inv_add()` / `ntt_inv_add2()` AVX512 final-fusion variant
was rejected because the local wins came with decrypt/code-layout regressions,
so this change introduces a separate `ntt_inv_add_v_inplace()` wrapper and uses
it only for `v = invntt(sum_i(that[i] * rhat[i])) + e2 + message`. Native CPU 0
stage A/B against `79c1b2d` with `RUNS=13` and `STAGE_ITERS=40000` showed
median speedups of `encrypt_accum_inv_v` `1.0252x`, `encrypt_accum_inv`
`1.0082x`, and `kpke_encrypt_cached` `1.0037x`. Native KEM A/B with `RUNS=17`
and `KEM_ITERS=50000` showed `mlkem_encaps` median `1.0042x`,
`mlkem_encaps_core` median `1.0021x`, and `mlkem_roundtrip` median `1.0010x`;
`mlkem_roundtrip_core` remained effectively flat at `0.9995x`. AVX2-only stage
A/B kept the target rows neutral because the wrapper falls back to the existing
AVX2 helper (`encrypt_accum_inv_v` median `1.0003x`, `kpke_encrypt_cached`
median `0.9996x`).

An AVX512 encryption-side `rhat` boundary fusion was accepted. The implementation
keeps `rhat[0..2]` in the pre-final-l1 NTT form, computes the final l1 pair
values once, and feeds those values into the three public-matrix `u`
accumulations plus the `that`/`v` accumulation. This avoids materializing final
`rhat` coefficients only to reload each one across four subsequent K=3
accumulations. Native CPU 0 stage A/B against `85659a0` with `RUNS=13` and
`STAGE_ITERS=40000` showed full encrypt median speedups of
`kpke_encrypt_cached` `1.0095x` and `kpke_encrypt_uncached` `1.0078x`. Native
KEM A/B with `RUNS=17` and `KEM_ITERS=50000` showed `mlkem_encaps` median
`1.0045x`, `mlkem_encaps_core` median `1.0005x`, `mlkem_roundtrip` median
`1.0031x`, and `mlkem_roundtrip_core` median `1.0021x`. AVX2-only builds keep
the original final-vector tail plus accumulation schedule; AVX2-only stage A/B
kept the target split rows neutral (`encrypt_accum_inv_v` median `1.0004x`,
`encrypt_accum_inv` median `1.0004x`) and `kpke_encrypt_cached` median was
`1.0048x`.

A branchless modular add/sub experiment was rejected. Replacing
`mod_q_add_i16()` and `mod_q_sub_i16()` with shift-and-mask corrections kept
correctness, but AVX2 NTT microbench A/B against `a403d5f` with `RUNS=11` and
`NTT_ITERS=300000` regressed `mlkem_ntt_head_l7_l4` median speedup to
`0.9600x`, `mlkem_ntt_copy` to `0.9743x`, `mlkem_ntt_inplace` to `0.9804x`,
and `mlkem_ntt_inv` to `0.9871x`. Keep the existing simple conditional form;
clang's generated code is better for the scalar upper NTT stages on this target.

A separate AVX2 vector NTT reduction correction-shape experiment was rejected.
The candidate changed only `mod_q_reduce_ntt_u32x8()`'s final negative correction
from `cmpgt_epi32(zero, r)` to `srai_epi32(r, 31)`, keeping the same Barrett-style
`x - (((x * 315) >> 20) * Q)` estimate and the same value range. This tested a
classic sign-mask idiom on the AVX2 butterfly reduction helper, not the scalar
upper NTT add/sub path above.

Correctness passed both gates:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
make clean CC=clang AVX2_BACKEND=core && make test CC=clang AVX2_BACKEND=core
```

AVX2-only NTT/stage/KEM A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=ntt,stage,kem NTT_ITERS=200000 \
  STAGE_ITERS=60000 KEM_ITERS=20000 C_COMPILER=clang PIN_CPU=0 \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" ./scripts/bench_core_ab.sh HEAD
```

Rejected AVX2 vector-reduction correction highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_ntt_copy` | 197.15 | 197.02 | 1.0007x | 1.0001x |
| `mlkem_ntt_inplace` | 191.81 | 191.75 | 1.0003x | 1.0002x |
| `mlkem_ntt_inv_add` | 200.40 | 200.27 | 1.0006x | 1.0005x |
| `mlkem_ntt_tail_avx2` | 94.17 | 94.11 | 1.0006x | 0.9999x |
| `mlkem_core_stage_encrypt_accum_inv` | 1326.71 | 1333.50 | 0.9949x | 0.9994x |
| `mlkem_core_stage_keygen_noise_ntt` | 1991.96 | 2000.13 | 0.9959x | 0.9993x |
| `mlkem_core_stage_kpke_encrypt_cached` | 2427.09 | 2438.11 | 0.9955x | 0.9994x |
| `mlkem_encaps_core` | 6986.98 | 7197.67 | 0.9707x | 1.0000x |
| `mlkem_roundtrip_core` | 20065.33 | 20272.32 | 0.9898x | 1.0006x |

Reject the sign-mask replacement. It is at best neutral in direct NTT medians
and does not improve the integrated rows; several stage averages move negative.
Keep the explicit compare correction in the AVX2 vector reducer. Future
reduction work needs to remove broader correction/reduction passes, not swap the
final mask instruction in the existing helper.

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

A later Keccak/store split added `sample_ntt4_keccak3_only` to separate the
common three Keccak-f4 permutations from the stream transpose/store work. Pinned
CPU 0, `clang`, 50,000-iteration snapshots:

| Build | Metric | ns/op |
|---|---|---:|
| native | `mlkem_core_stage_sample_ntt4_full_raw` | 603.49 |
| native | `mlkem_core_stage_sample_ntt4_store_rate` | 1.83 |
| native | `mlkem_core_stage_sample_ntt4_keccak3_only` | 501.43 |
| native | `mlkem_core_stage_sample_ntt4_keccak_store3` | 500.49 |
| native | `mlkem_core_stage_sample_ntt4_parse_504` | 153.80 |
| AVX2-only | `mlkem_core_stage_sample_ntt4_full_raw` | 1312.92 |
| AVX2-only | `mlkem_core_stage_sample_ntt4_store_rate` | 7.54 |
| AVX2-only | `mlkem_core_stage_sample_ntt4_keccak3_only` | 828.43 |
| AVX2-only | `mlkem_core_stage_sample_ntt4_keccak_store3` | 852.47 |
| AVX2-only | `mlkem_core_stage_sample_ntt4_parse_504` | 112.39 |

The split is diagnostic and not additive, but it is clear enough: the common
three-block path is dominated by `keccakf4()`, not the state transpose/store.
The native store delta is within noise, and AVX2-only store overhead is roughly
24 ns over three rates. Future x4 sampler work should not focus on another
`sample_ntt4_store_rate()` rewrite unless paired with a larger Keccak/state
layout change.

A later refill-cost split measured the conditional cost of one extra refill
step, using only x4 sampler groups that actually needed at least one lane refill
after the first 504 bytes. Pinned CPU 0, `clang`, 50,000-iteration snapshots:

| Build | Metric | ns/op |
|---|---|---:|
| native | `mlkem_core_stage_sample_ntt4_full_raw` | 601.51 |
| native | `mlkem_core_stage_sample_ntt4_keccak_store3` | 500.42 |
| native | `mlkem_core_stage_sample_ntt4_parse_504` | 148.57 |
| native | `mlkem_core_stage_sample_ntt4_refill_keccak_store1` | 169.47 |
| native | `mlkem_core_stage_sample_ntt4_refill_step_once` | 179.97 |
| AVX2-only | `mlkem_core_stage_sample_ntt4_full_raw` | 1313.50 |
| AVX2-only | `mlkem_core_stage_sample_ntt4_keccak_store3` | 797.39 |
| AVX2-only | `mlkem_core_stage_sample_ntt4_parse_504` | 115.51 |
| AVX2-only | `mlkem_core_stage_sample_ntt4_refill_keccak_store1` | 403.87 |
| AVX2-only | `mlkem_core_stage_sample_ntt4_refill_step_once` | 406.97 |

The same 50,000-iteration run found 3.384% of x4 groups and 0.856% of lanes
needed a refill, with average first-pass accepts `255.974000` and minimum `238`.
That makes the amortized refill-step cost about 6 ns/op on native and 14 ns/op
on AVX2-only, far below the common three-block Keccak/store path. Do not spend
the next sampler work on refill handling unless the main three-rate path has
already been redesigned.

A later common three-rate step diagnostic measured the first `sample_ntt4()`
phase as one unit: Keccak state init, the first three Keccak/store blocks,
four 504-byte parses, and the refill-decision bookkeeping. Pinned CPU 0, `clang`,
50,000-iteration snapshots:

| Build | Metric | ns/op |
|---|---|---:|
| native | `mlkem_core_stage_sample_ntt4_full_raw` | 603.61 |
| native | `mlkem_core_stage_sample_ntt4_keccak_store3` | 501.78 |
| native | `mlkem_core_stage_sample_ntt4_parse_504` | 151.56 |
| native | `mlkem_core_stage_sample_ntt4_common3_step` | 657.08 |
| native | `mlkem_core_stage_sample_ntt4_refill_step_once` | 180.82 |
| AVX2-only | `mlkem_core_stage_sample_ntt4_full_raw` | 1350.62 |
| AVX2-only | `mlkem_core_stage_sample_ntt4_keccak_store3` | 891.76 |
| AVX2-only | `mlkem_core_stage_sample_ntt4_parse_504` | 117.01 |
| AVX2-only | `mlkem_core_stage_sample_ntt4_common3_step` | 998.15 |
| AVX2-only | `mlkem_core_stage_sample_ntt4_refill_step_once` | 420.25 |

This split is also diagnostic and should not be added back to `full_raw`, but
the AVX2-only row is useful: `common3_step` is within about 11 ns of
`keccak_store3 + parse_504`, so there is no large hidden bookkeeping gap before
the refill loop. The remaining sampler target is still the Keccak/state
representation or a larger common-path redesign, not NAF-style sparse
bookkeeping or another narrow refill-control tweak. The native `common3_step`
row overmeasures `full_raw`, so use it only as a reminder that these probes are
layout-sensitive.

A later one-lane tail diagnostic split measured the `sample_ntt4_one()` path
used for the final public-matrix entry `(2,2)`. These rows are diagnostic and
exclude the full-polynomial checksum overhead used by `sample_matrix_tail`. A
`clang`, `BENCH_STAGES_ITERS=50000` snapshot measured:

| Build | Metric | ns/op |
|---|---|---:|
| native | `mlkem_core_stage_sample_matrix` | 1919.71 |
| native | `mlkem_core_stage_sample_matrix_tail` | 725.74 |
| native | `mlkem_core_stage_sample_ntt4_full_raw` | 598.43 |
| native | `mlkem_core_stage_sample_ntt4_keccak_store3` | 499.45 |
| native | `mlkem_core_stage_sample_ntt4_parse_504` | 226.61 |
| native | `mlkem_core_stage_sample_ntt4_one_full_raw` | 539.95 |
| native | `mlkem_core_stage_sample_ntt4_one_keccak_store3` | 490.67 |
| native | `mlkem_core_stage_sample_ntt4_one_parse_504` | 27.80 |
| AVX2-only | `mlkem_core_stage_sample_matrix` | 4138.92 |
| AVX2-only | `mlkem_core_stage_sample_matrix_tail` | 1410.66 |
| AVX2-only | `mlkem_core_stage_sample_ntt4_full_raw` | 1313.20 |
| AVX2-only | `mlkem_core_stage_sample_ntt4_keccak_store3` | 793.40 |
| AVX2-only | `mlkem_core_stage_sample_ntt4_parse_504` | 112.94 |
| AVX2-only | `mlkem_core_stage_sample_ntt4_one_full_raw` | 1221.02 |
| AVX2-only | `mlkem_core_stage_sample_ntt4_one_keccak_store3` | 809.37 |
| AVX2-only | `mlkem_core_stage_sample_ntt4_one_parse_504` | 29.54 |

The tail parser itself is small: one 504-byte tail stream parses in roughly
28-30 ns, while the initial three Keccak-f4 permutations plus lane-0 stream
stores dominate. The one-lane tail also has the same refill probability as an
individual x4 sampler lane: in this snapshot 0.835% of tail lanes needed an
extra squeeze, with average first-pass accepts `255.974600` and minimum `247`.
Future tail work should therefore target the lane-0 Keccak-state extraction or
stream scratch layout, not parser bookkeeping or refill handling.

A later scalar-tail comparison checked whether `sample_ntt4_one()` is still the
right final-entry path on AVX2-only builds. It measures the current tail row, a
forced scalar `sample_ntt()` tail with the same checksum cost, and a lightweight
scalar raw row comparable to `sample_ntt4_one_full_raw`. Pinned CPU 0, `clang`,
`20000`-iteration snapshots measured:

| Build | Metric | ns/op |
|---|---|---:|
| native | `mlkem_core_stage_sample_matrix_tail` | 702.22 |
| native | `mlkem_core_stage_sample_matrix_tail_scalar` | 783.61 |
| native | `mlkem_core_stage_sample_ntt4_one_full_raw` | 518.39 |
| native | `mlkem_core_stage_sample_matrix_tail_scalar_raw` | 597.46 |
| AVX2-only | `mlkem_core_stage_sample_matrix_tail` | 2003.02 |
| AVX2-only | `mlkem_core_stage_sample_matrix_tail_scalar` | 873.87 |
| AVX2-only | `mlkem_core_stage_sample_ntt4_one_full_raw` | 1810.73 |
| AVX2-only | `mlkem_core_stage_sample_matrix_tail_scalar_raw` | 682.71 |

This changes the tail decision by target. Native still prefers the one-lane x4
tail, but AVX2-only wastes too much work running four identical Keccak lanes and
then extracting only lane 0. The next implementation attempt should route the
final `(2,2)` sample-matrix entry through scalar `sample_ntt()` for AVX2-only
builds while preserving the current native/AVX512 path.

That target-specific switch was accepted for AVX2-only builds. The production
`sample_matrix()` path now keeps `sample_ntt4_one()` when AVX512 is available,
but uses scalar `sample_ntt()` for the final `(2,2)` entry on AVX2-only builds.
AVX2-only stage/KEM A/B against commit `310843d`, pinned CPU 0, `clang`,
`RUNS=9`, `STAGE_ITERS=50000`, `KEM_ITERS=20000` measured:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_matrix_tail` | 1555.55 | 883.11 | 1.7614x | 1.6426x |
| `mlkem_core_stage_sample_ntt4_one_full_raw` | 1371.44 | 916.17 | 1.4969x | 1.3783x |
| `mlkem_core_stage_sample_matrix` | 4593.97 | 3895.66 | 1.1793x | 1.1537x |
| `mlkem_core_stage_kpke_keygen_full` | 6775.44 | 6609.77 | 1.0251x | 1.0211x |
| `mlkem_encaps_core` | 9504.86 | 9106.19 | 1.0438x | 1.0607x |
| `mlkem_roundtrip_core` | 27022.28 | 26574.09 | 1.0169x | 1.0308x |

The acceptance signal is the public-matrix stage and keygen path. Non-core KEM
wrapper rows were noisy, but the local target and keygen core movement are large
enough to keep the AVX2-only scalar tail switch.

A direct follow-up moving the smaller `sample_ntt4_one()` `stream[63]` and refill
`extra[21]` scratch arrays from the stack to static storage was rejected. Native
and AVX2-only core `make test` passed, but AVX2-only stage A/B did not show a
clear target win: `sample_ntt4_one_full_raw` was only marginally positive,
`sample_matrix_tail` was neutral, and full `sample_matrix` was slightly negative
on median. Keep the static scratch optimization limited to the larger x4
`sample_ntt4()` stream buffer; the one-lane tail scratch is not large enough to
justify the global storage and code-layout perturbation.

AVX2-only stage A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_one_full_raw` | 1416.82 | 1348.55 | 1.0506x | 1.0015x |
| `mlkem_core_stage_sample_ntt4_one_keccak_store3` | 855.52 | 849.91 | 1.0066x | 0.9997x |
| `mlkem_core_stage_sample_ntt4_one_parse_504` | 31.28 | 31.67 | 0.9875x | 0.9877x |
| `mlkem_core_stage_sample_matrix_tail` | 1601.35 | 1531.93 | 1.0453x | 1.0002x |
| `mlkem_core_stage_sample_matrix` | 4730.63 | 4671.60 | 1.0126x | 0.9984x |
| `mlkem_core_stage_kpke_keygen_full` | 7260.29 | 6871.01 | 1.0567x | 1.0801x |

KEM confirmation was skipped because the direct sampler target rows were neutral
or negative on median; the large `kpke_keygen_full` stage movement is treated as
layout noise without matching `sample_matrix` evidence.

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

A later keygen secret-noise split added `keygen_noise_ntt_only` and
`keygen_secret_encode_only` rows to separate the six forward NTTs from the
secret-key d12 encode. Pinned CPU 0, `clang`, 50,000-iteration snapshots measured:

| Build | Metric | ns/op |
|---|---|---:|
| native | `mlkem_core_stage_keygen_noise_ntt_encode` | 1426.20 |
| native | `mlkem_core_stage_keygen_noise_ntt_only` | 1391.78 |
| native | `mlkem_core_stage_keygen_secret_encode_only` | 36.53 |
| AVX2-only | `mlkem_core_stage_keygen_noise_ntt_encode` | 1593.04 |
| AVX2-only | `mlkem_core_stage_keygen_noise_ntt_only` | 1546.29 |
| AVX2-only | `mlkem_core_stage_keygen_secret_encode_only` | 36.28 |

The split confirms that the remaining `keygen_noise_ntt_encode` cost is the six
forward NTTs. Another d12 secret-key encode rewrite is unlikely to move keygen;
future work should target forward-NTT scheduling or reusable NTT-side arithmetic
instead.

A later keygen NTT split diagnostic added separate rows for the three secret
polynomial NTTs, the three error polynomial NTTs, and the secret NTT+encode
boundary. Pinned CPU 0, `clang`, `AVX2_BACKEND=core`, `-mavx2 -mbmi2 -mpopcnt`,
median of seven `50000`-iteration runs measured:

| Metric | Median ns/op |
|---|---:|
| `mlkem_core_stage_keygen_noise_ntt_encode` | 1593.16 |
| `mlkem_core_stage_keygen_noise_ntt_only` | 1548.56 |
| `mlkem_core_stage_keygen_secret_ntt_encode_only` | 816.04 |
| `mlkem_core_stage_keygen_secret_ntt_only` | 784.59 |
| `mlkem_core_stage_keygen_error_ntt_only` | 772.64 |
| `mlkem_core_stage_keygen_secret_encode_only` | 36.45 |

This rules out another secret-encode-adjacent tweak as a primary target. The
secret and error halves are symmetric within measurement noise; the useful
keygen target remains the full forward-NTT schedule or a broader representation
that changes both halves, not `shat`-only or `ehat`-only handling.

A follow-up AVX2-only ETA2 first-level NTT specialization was rejected. The
candidate added an `ntt_eta2()` path for CBD-derived polynomials and replaced the
first forward-NTT `l7` multiply/reduce with constant-time selection over the only
possible ETA2 canonical inputs `{0, 1, 2, Q-2, Q-1}`. The remaining `l6..l1`
stages reused the existing forward NTT implementation. Correctness passed
AVX2-only `make test`, but the source was reverted after KEM confirmation showed
large whole-program regressions.

AVX2-only stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Stage highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_noise_ntt_only` | 1549.29 | 1532.13 | 1.0112x | 1.0168x |
| `mlkem_core_stage_keygen_noise_ntt_encode` | 1596.76 | 1585.78 | 1.0069x | 1.0178x |
| `mlkem_core_stage_encrypt_noise_ntt` | 772.97 | 766.48 | 1.0085x | 1.0145x |

AVX2-only KEM A/B command:

```bash
RUNS=17 WARMUP_RUNS=4 SUITES=kem KEM_ITERS=40000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

KEM rejection highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_keygen_core` | 8626.56 | 9085.99 | 0.9494x | 0.9033x |
| `mlkem_encaps_core` | 8445.28 | 9051.66 | 0.9330x | 0.9103x |
| `mlkem_roundtrip_core` | 25604.21 | 26423.14 | 0.9690x | 0.9809x |

Do not reintroduce this first-level ETA2 selection shape. Although it improves
isolated NTT stage rows, the extra code shape and instruction mix hurt the
production KEM binaries too much. Future CBD-derived NTT work needs a broader
layout/schedule change, not just replacing the first level's modular multiply.

Encryption `u` accumulation split metrics were added later to separate the three
`ntt_mul_acc3()` accumulations from the following three inverse-NTT-add paths.
The inverse-add-only row copies precomputed NTT-domain accumulations into scratch
buffers before calling the mutating inverse-add helpers, so it is diagnostic and
should not be added back exactly to the fused `encrypt_accum_inv_u` row. The
head/tail rows split that diagnostic path further; on AVX2-only builds the
tail/final row preserves the production final-fusion shape after a precomputed
inverse head, while native AVX512 numbers are only a reference split and do not
exactly match the accepted three-polynomial fused final helper. A `clang`,
`BENCH_STAGES_ITERS=50000` snapshot measured:

| Build | Metric | ns/op |
|---|---|---:|
| native | `mlkem_core_stage_encrypt_accum_inv` | 1096.96 |
| native | `mlkem_core_stage_encrypt_accum_inv_u` | 864.19 |
| native | `mlkem_core_stage_encrypt_accum_u_only` | 373.79 |
| native | `mlkem_core_stage_encrypt_inv_add_u_only` | 692.89 |
| native | `mlkem_core_stage_encrypt_inv_add_u_head_only` | 431.26 |
| native | `mlkem_core_stage_encrypt_inv_add_u_head_l1` | 299.23 |
| native | `mlkem_core_stage_encrypt_inv_add_u_head_l2` | 268.96 |
| native | `mlkem_core_stage_encrypt_inv_add_u_head_l3` | 262.41 |
| native | `mlkem_core_stage_encrypt_inv_add_u_tail_l4` | 233.01 |
| native | `mlkem_core_stage_encrypt_inv_add_u_tail_l5` | 231.04 |
| native | `mlkem_core_stage_encrypt_inv_add_u_tail_l6` | 231.34 |
| native | `mlkem_core_stage_encrypt_inv_add_u_final_only` | 278.55 |
| native | `mlkem_core_stage_encrypt_inv_add_u_tail_final_only` | 458.30 |
| native | `mlkem_core_stage_encrypt_accum_inv_v` | 405.14 |
| AVX2-only | `mlkem_core_stage_encrypt_accum_inv` | 1326.98 |
| AVX2-only | `mlkem_core_stage_encrypt_accum_inv_u` | 1029.32 |
| AVX2-only | `mlkem_core_stage_encrypt_accum_u_only` | 439.52 |
| AVX2-only | `mlkem_core_stage_encrypt_inv_add_u_only` | 795.43 |
| AVX2-only | `mlkem_core_stage_encrypt_inv_add_u_head_only` | 467.71 |
| AVX2-only | `mlkem_core_stage_encrypt_inv_add_u_head_l1` | 316.57 |
| AVX2-only | `mlkem_core_stage_encrypt_inv_add_u_head_l2` | 284.28 |
| AVX2-only | `mlkem_core_stage_encrypt_inv_add_u_head_l3` | 268.45 |
| AVX2-only | `mlkem_core_stage_encrypt_inv_add_u_tail_l4` | 266.08 |
| AVX2-only | `mlkem_core_stage_encrypt_inv_add_u_tail_l5` | 261.09 |
| AVX2-only | `mlkem_core_stage_encrypt_inv_add_u_tail_l6` | 262.13 |
| AVX2-only | `mlkem_core_stage_encrypt_inv_add_u_final_only` | 340.39 |
| AVX2-only | `mlkem_core_stage_encrypt_inv_add_u_tail_final_only` | 520.29 |
| AVX2-only | `mlkem_core_stage_encrypt_accum_inv_v` | 470.78 |

The split points the next encryption-accumulation work at the `u` inverse-add
side rather than another `ntt_mul_acc3()` rewrite. Prior Karatsuba, reciprocal
reduction, AVX2 vector-helper, and generic batching attempts already showed that
the multiplication helper is hard to improve robustly. Within AVX2-only
inverse-add, the head and tail/final diagnostics are both large. The finer
head-level rows show l1, l2, and l3 are all material after scratch-copy overhead,
with no single stage dominating. The tail split shows l4, l5, and l6 are similar
and smaller than the final butterfly plus scale/add row. The next useful
implementation work should therefore target the final pass or a structural
inverse-head cleanup with KEM confirmation, not another whole-`ntt_mul_acc3()`
experiment. The already rejected packed 16-bit final-add rewrite should not be
repeated.

A follow-up diagnostic split separates the final pass itself into final
butterfly plus inverse-NTT scale, and the final `e1` add against precomputed
scaled outputs. These rows include their own scratch copies and are diagnostic,
so they should not be added to reconstruct `final_only`. A `clang`,
`BENCH_STAGES_ITERS=50000` snapshot measured:

| Build | Metric | ns/op |
|---|---|---:|
| native | `mlkem_core_stage_encrypt_accum_inv_u` | 880.19 |
| native | `mlkem_core_stage_encrypt_inv_add_u_final_only` | 280.28 |
| native | `mlkem_core_stage_encrypt_inv_add_u_final_scale_only` | 249.52 |
| native | `mlkem_core_stage_encrypt_inv_add_u_final_noise_add_only` | 212.45 |
| native | `mlkem_core_stage_encrypt_inv_add_u_tail_final_only` | 459.04 |
| AVX2-only | `mlkem_core_stage_encrypt_accum_inv_u` | 1023.31 |
| AVX2-only | `mlkem_core_stage_encrypt_inv_add_u_final_only` | 321.10 |
| AVX2-only | `mlkem_core_stage_encrypt_inv_add_u_final_scale_only` | 288.08 |
| AVX2-only | `mlkem_core_stage_encrypt_inv_add_u_final_noise_add_only` | 239.14 |
| AVX2-only | `mlkem_core_stage_encrypt_inv_add_u_tail_final_only` | 510.99 |

This narrows the next production target inside the final pass: optimize the
final butterfly plus scale/reduction path first. The isolated add path is still
visible, but the prior packed 16-bit final-add experiment already showed that
changing that add form is not robust at KEM level.

A later low/high diagnostic split separates that final scale row into the
low-half `sum * 3303` output and the high-half `diff * zeta_scale` output. These
rows also include their own scratch copies and are diagnostic. A `clang`,
`BENCH_STAGES_ITERS=50000` snapshot measured:

| Build | Metric | ns/op |
|---|---|---:|
| native | `mlkem_core_stage_encrypt_accum_inv_u` | 866.41 |
| native | `mlkem_core_stage_encrypt_inv_add_u_final_only` | 279.85 |
| native | `mlkem_core_stage_encrypt_inv_add_u_final_scale_only` | 250.07 |
| native | `mlkem_core_stage_encrypt_inv_add_u_final_scale_low_only` | 225.91 |
| native | `mlkem_core_stage_encrypt_inv_add_u_final_scale_high_only` | 224.40 |
| native | `mlkem_core_stage_encrypt_inv_add_u_final_noise_add_only` | 212.44 |
| native | `mlkem_core_stage_encrypt_inv_add_u_tail_final_only` | 456.92 |
| AVX2-only | `mlkem_core_stage_encrypt_accum_inv_u` | 1023.93 |
| AVX2-only | `mlkem_core_stage_encrypt_inv_add_u_final_only` | 322.56 |
| AVX2-only | `mlkem_core_stage_encrypt_inv_add_u_final_scale_only` | 289.58 |
| AVX2-only | `mlkem_core_stage_encrypt_inv_add_u_final_scale_low_only` | 250.48 |
| AVX2-only | `mlkem_core_stage_encrypt_inv_add_u_final_scale_high_only` | 247.31 |
| AVX2-only | `mlkem_core_stage_encrypt_inv_add_u_final_noise_add_only` | 239.52 |
| AVX2-only | `mlkem_core_stage_encrypt_inv_add_u_tail_final_only` | 512.29 |

The low and high scale halves are effectively balanced. After the negative-scale
experiment below, this makes a one-sided rewrite less attractive: the next
production attempt should remove shared load/extend/reduction work or change the
final-pass structure as a whole, not only rewrite the low or high multiply.

An AVX2 hand-written inverse-tail helper experiment was rejected. The candidate
replaced the AVX2-only scalar/vectorizer-driven inverse-tail loops (`l4` through
`l7`, and `l4` through `l6` before the fused final pass) with a 16-coefficient
intrinsic helper: low/high halves were loaded as 16-bit vectors, modular sum and
difference were computed in 16-bit lanes, and only the zeta multiply/reduction
was widened to 32-bit lanes. It passed native and AVX2-only core `make test` and
produced strong local NTT/stage wins, but KEM confirmation was not stable enough
for a production change. The inline form regressed `encaps_core` badly in two
KEM runs; the `MLKEM_NOINLINE` form preserved the local wins and improved some
KEM medians, but `roundtrip_core` and unrelated `keygen_core` rows still moved
against the candidate in repeat runs. Keep the current scalar/vectorizer-driven
AVX2 tail loops until a layout-stable version proves whole-KEM robustness.

Inline AVX2-only NTT/stage A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=ntt,stage NTT_ITERS=200000 STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_ntt_inv` | 198.69 | 186.19 | 1.0672x | 1.0744x |
| `mlkem_ntt_inv_add` | 201.60 | 191.53 | 1.0526x | 1.0518x |
| `mlkem_ntt_inv_add2` | 211.73 | 201.73 | 1.0496x | 1.0491x |
| `mlkem_ntt_inv_sub_from` | 201.26 | 191.14 | 1.0530x | 1.0524x |
| `mlkem_core_stage_encrypt_accum_inv_u` | 1041.17 | 1007.06 | 1.0339x | 1.0323x |
| `mlkem_core_stage_encrypt_inv_add_u_only` | 801.90 | 765.22 | 1.0479x | 1.0404x |
| `mlkem_core_stage_decrypt_inv_sub_from` | 381.91 | 371.57 | 1.0278x | 1.0268x |

Inline AVX2-only KEM confirmations rejected the form despite those local wins:

| Metric | Run | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---|---:|---:|---:|---:|
| `mlkem_encaps_core` | 1 | 8499.32 | 9017.83 | 0.9425x | 0.9200x |
| `mlkem_roundtrip_core` | 1 | 25487.15 | 26478.48 | 0.9626x | 0.9637x |
| `mlkem_encaps_core` | 2 | 8960.49 | 9079.02 | 0.9869x | 0.9481x |
| `mlkem_roundtrip_core` | 2 | 26228.71 | 26512.69 | 0.9893x | 1.0188x |

`MLKEM_NOINLINE` helper A/B kept the local stage win:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_ntt_inv_add` | 201.00 | 192.64 | 1.0434x | 1.0435x |
| `mlkem_ntt_inv_add2` | 211.74 | 203.75 | 1.0392x | 1.0394x |
| `mlkem_ntt_inv_sub_from` | 201.21 | 192.65 | 1.0444x | 1.0444x |
| `mlkem_core_stage_encrypt_accum_inv_u` | 1037.31 | 1014.49 | 1.0225x | 1.0240x |
| `mlkem_core_stage_encrypt_inv_add_u_only` | 795.81 | 763.06 | 1.0429x | 1.0437x |
| `mlkem_core_stage_decrypt_inv_sub_from` | 381.99 | 373.74 | 1.0221x | 1.0213x |

But repeated noinline KEM confirmation was still unstable:

| Metric | Run | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---|---:|---:|---:|---:|
| `mlkem_encaps_core` | 1 | 8831.23 | 8967.42 | 0.9848x | 1.0722x |
| `mlkem_roundtrip_core` | 1 | 26385.78 | 26388.12 | 0.9999x | 1.0350x |
| `mlkem_keygen_core` | 1 | 9105.15 | 9149.67 | 0.9951x | 0.9829x |
| `mlkem_encaps_core` | 2 | 8854.20 | 8714.76 | 1.0160x | 1.0592x |
| `mlkem_roundtrip_core` | 2 | 26044.34 | 26109.63 | 0.9975x | 0.9826x |
| `mlkem_keygen_core` | 2 | 9039.72 | 9217.44 | 0.9807x | 0.9441x |

An AVX2 final zeta-scale constant experiment was rejected. The candidate changed
`ntt_inv_before_final_avx2()` to stop returning the final zeta and replaced the
per-call `mod_q_reduce_ntt_u32(ZETA[1] * 3303)` setup in the AVX2 final fused
helpers with the fixed value `1652`. It passed native and AVX2-only core
`make test`, and local NTT rows improved slightly, but KEM confirmation regressed
the encryption core path enough to reject the change. Keep the computed local
zeta-scale setup in the production AVX2 final helpers unless a later rewrite
proves a whole-core win.

AVX2-only NTT/stage A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=ntt,stage NTT_ITERS=200000 STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_ntt_inv_add` | 202.67 | 200.31 | 1.0118x | 1.0052x |
| `mlkem_ntt_inv_add2` | 213.16 | 210.92 | 1.0106x | 1.0053x |
| `mlkem_ntt_inv_sub_from` | 201.47 | 200.36 | 1.0055x | 1.0050x |
| `mlkem_core_stage_encrypt_inv_add_u_final_only` | 321.13 | 321.54 | 0.9987x | 0.9997x |
| `mlkem_core_stage_encrypt_inv_add_u_only` | 796.06 | 792.99 | 1.0039x | 1.0044x |
| `mlkem_core_stage_encrypt_accum_inv_u` | 1038.64 | 1038.51 | 1.0001x | 1.0019x |

AVX2-only KEM confirmation command:

```bash
RUNS=17 WARMUP_RUNS=4 SUITES=kem KEM_ITERS=40000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_encaps_core` | 8966.14 | 9146.18 | 0.9803x | 0.9720x |
| `mlkem_roundtrip_core` | 26518.12 | 26586.20 | 0.9974x | 1.0035x |
| `mlkem_decaps_core` | 8278.30 | 8279.06 | 0.9999x | 0.9876x |

A follow-up AVX2 final zeta-scale global-vector precompute experiment was also
rejected. The candidate initialized a global `__m256i` holding
`mod_q_reduce_ntt_u32(ZETA[1] * 3303)` during `init_ntt_roots()`, changed
`ntt_inv_before_final_avx2()` to return `void`, and loaded that vector in the
three AVX2 final fused inverse-NTT helpers. This avoided the scalar per-call
zeta-scale computation, but replaced it with a hot-loop-adjacent global YMM load.
AVX2-only `make test` passed.

AVX2-only stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=70000 C_COMPILER=clang \
  PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" ./scripts/bench_core_ab.sh HEAD
```

Global-vector precompute rejection highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_encrypt_inv_add_u_final_scale_only` | 291.62 | 298.29 | 0.9776x | 0.9744x |
| `mlkem_core_stage_encrypt_inv_add_u_final_scale_low_only` | 254.04 | 260.81 | 0.9740x | 0.9728x |
| `mlkem_core_stage_encrypt_inv_add_u_final_scale_high_only` | 248.43 | 263.29 | 0.9436x | 0.9433x |
| `mlkem_core_stage_encrypt_inv_add_u_only` | 792.82 | 791.22 | 1.0020x | 1.0027x |
| `mlkem_core_stage_encrypt_accum_inv_u` | 1058.02 | 1041.35 | 1.0160x | 1.0030x |
| `mlkem_core_stage_decrypt_inv_sub_from` | 382.60 | 381.73 | 1.0023x | 1.0025x |
| `mlkem_core_stage_decrypt_ntt_accum_recover` | 889.40 | 896.72 | 0.9918x | 0.9983x |
| `mlkem_core_stage_kpke_encrypt_cached` | 2437.53 | 2437.47 | 1.0000x | 0.9993x |

Skip KEM confirmation for this shape. The full inverse-add rows show only small
noise-level positives, while the direct final-scale split regresses sharply and
cached encryption is not positive by median. Keep the current local zeta-scale
setup until a representation-level inverse-NTT rewrite removes more work than a
single scalar constant computation.

A narrower AVX2 final zeta fixed-index experiment was also rejected. The
candidate kept the scalar per-call zeta-scale computation, but changed
`ntt_inv_before_final_avx2()` to return `void` and used `ZETA[1]` directly in
`ntt_inv_add_fused_final_avx2()`, `ntt_inv_add2_fused_final_avx2()`, and
`ntt_inv_sub_from_fused_final_avx2()`. This is algebraically valid because the
pre-final inverse helper always reaches the final `log2len = 7` zeta, but the
extra information did not become a stable whole-core win. AVX2-only core
`make test` passed.

AVX2-only stage/KEM A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage,kem STAGE_ITERS=50000 KEM_ITERS=25000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Fixed-index zeta rejection highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_encrypt_inv_add_u_only` | 788.99 | 788.11 | 1.0011x | 1.0016x |
| `mlkem_core_stage_encrypt_inv_add_u_final_scale_only` | 291.06 | 290.21 | 1.0029x | 1.0022x |
| `mlkem_core_stage_decrypt_inv_sub_from` | 381.53 | 381.26 | 1.0007x | 1.0008x |
| `mlkem_core_stage_decrypt_ntt_accum_recover` | 894.76 | 894.30 | 1.0005x | 0.9993x |
| `mlkem_encaps_core` | 7063.75 | 6975.74 | 1.0126x | 0.9991x |
| `mlkem_decaps_core` | 6254.09 | 6038.71 | 1.0357x | 1.0013x |
| `mlkem_roundtrip_core` | 20215.28 | 20116.48 | 1.0049x | 0.9993x |

Reject the fixed-index rewrite. The direct target rows moved only around
0.1-0.3%, and KEM medians were neutral or mixed. Keep returning the local zeta
from `ntt_inv_before_final_avx2()`; the remaining opportunity is not the scalar
`ZETA[1]` selection, but a larger representation-level inverse-final rewrite.

An AVX2 negative-scale final reduction experiment was also rejected. The
candidate used `3303 == -26 mod q` and replaced the `sum * 3303` product in the
AVX2 final fused helpers with `(q - sum) * 26`, implemented as shifts and
subtractions before the existing reduction. It passed native and AVX2-only core
`make test`, but the extra vector shifts/subtracts cost more than the removed
`vpmulld`; the isolated final scale row and integrated inverse-add rows
regressed. KEM confirmation was skipped because the target stage rows were
already clearly negative. Keep the current 32-bit multiply/reduce form for this
half of the final pass.

A narrower AVX2 code-layout experiment marking only
`ntt_inv_add_fused_final_avx2()` as `MLKEM_NOINLINE` was also rejected. This was
intended to reduce inlined code pressure in the encapsulation `u` inverse-add
path without changing arithmetic. AVX2-only `make test` passed, but the direct
stage rows regressed, so KEM confirmation was skipped and the source was
reverted.

AVX2-only stage A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

No-inline final helper rejection highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_encrypt_inv_add_u_only` | 781.70 | 792.59 | 0.9863x | 0.9862x |
| `mlkem_core_stage_encrypt_accum_inv_u` | 1031.89 | 1033.07 | 0.9989x | 0.9976x |
| `mlkem_core_stage_encrypt_inv_add_u_final_only` | 318.55 | 319.07 | 0.9984x | 0.9994x |
| `mlkem_core_stage_kpke_encrypt_cached` | 2802.13 | 2752.05 | 1.0182x | 0.9922x |

Keep the AVX2 fused final add helper inline. The call boundary costs more than
any code-layout benefit in the direct inverse-add rows.

AVX2-only NTT/stage A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=ntt,stage NTT_ITERS=200000 STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_ntt_inv_add` | 201.49 | 202.55 | 0.9948x | 0.9965x |
| `mlkem_ntt_inv_add2` | 212.32 | 214.53 | 0.9897x | 0.9896x |
| `mlkem_ntt_inv_sub_from` | 201.69 | 202.29 | 0.9970x | 0.9973x |
| `mlkem_core_stage_encrypt_inv_add_u_final_scale_only` | 288.62 | 292.80 | 0.9857x | 0.9862x |
| `mlkem_core_stage_encrypt_inv_add_u_final_only` | 321.28 | 325.26 | 0.9878x | 0.9885x |
| `mlkem_core_stage_encrypt_inv_add_u_only` | 796.30 | 799.46 | 0.9960x | 0.9959x |
| `mlkem_core_stage_encrypt_accum_inv_u` | 1041.38 | 1045.69 | 0.9959x | 0.9967x |

An AVX2 inverse-add final loop unroll hint experiment was also rejected. The
candidate added `#pragma clang loop unroll_count(2)` to the final AVX2 fused
loops in `ntt_inv_add_fused_final_avx2()`, `ntt_inv_add2_fused_final_avx2()`,
and `ntt_inv_sub_from_fused_final_avx2()`. It changed only clang code generation
hints, not arithmetic or data representation. AVX2-only `make test` passed, but
stage A/B did not show a consistent direct win, so KEM confirmation was skipped
and the source was reverted.

AVX2-only stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Final-loop unroll rejection highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_encrypt_inv_add_u_final_scale_only` | 290.91 | 291.10 | 0.9993x | 0.9990x |
| `mlkem_core_stage_encrypt_inv_add_u_final_only` | 323.64 | 323.63 | 1.0000x | 0.9994x |
| `mlkem_core_stage_encrypt_inv_add_u_only` | 791.17 | 795.88 | 0.9941x | 0.9997x |
| `mlkem_core_stage_encrypt_accum_inv_u` | 1045.25 | 1043.82 | 1.0014x | 1.0003x |
| `mlkem_core_stage_decrypt_inv_sub_from` | 381.50 | 381.62 | 0.9997x | 0.9998x |
| `mlkem_core_stage_kpke_encrypt_cached` | 2438.48 | 2446.03 | 0.9969x | 1.0010x |

Keep the final AVX2 loops in their current compact form. The final pass is still
worth targeting, but simple loop-control reshaping is not enough; future work
needs to remove shared load/extend/reduction work or change the representation
boundary feeding compression.

A narrower AVX2 final-pass grouping diagnostic was also rejected. The candidate
left the arithmetic and reductions unchanged, but processed the three `u`
polynomial final butterfly/scale/add passes inside one shared `j` loop
(`mlkem_core_stage_encrypt_inv_add_u_final3_only`) instead of calling the
one-polynomial final helper three times. The helper is benchmark-only and is
validated against the existing separate final pass for all stage lanes.

AVX2-only diagnostic command:

```bash
make bench-stages CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
for i in 1 2 3 4 5 6 7; do
  taskset -c 0 ./bench_core_stagesc 10000 | \
    awk -F= -v run="$i" '
      /mlkem_core_stage_encrypt_inv_add_u_(final_only|final3_only|final_scale_only|final_noise_add_only|tail_final_only)_ns_per_op=|mlkem_core_stage_encrypt_accum_inv_u_ns_per_op=/ {
        print run "\t" $1 "\t" $2
      }'
done
```

Final3 grouping diagnostic highlights:

| Metric | Current avg ns/op | Candidate avg ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_encrypt_inv_add_u_final_only` vs `mlkem_core_stage_encrypt_inv_add_u_final3_only` | 330.97 | 339.89 | 0.9738x | 0.9645x |

The grouped loop loses despite removing the outer three-row loop. This points to
register pressure and reduced scheduling freedom dominating any loop-control
savings: each `u` still needs independent load/extend, butterfly, multiply,
reduction, add, and store work. Do not productionize this shape. A useful next
final-pass optimization needs to reduce data movement/reductions or change the
representation boundary, not merely group the three polynomials.

An AVX2 inverse-head block-local ordering experiment was rejected. The candidate
changed `ntt_inv_head_avx2()` from three level-wise passes (`l1` over all
16-coefficient blocks, then `l2`, then `l3`) to one block-local pass that ran
`l1 -> l2 -> l3` for each 16-coefficient block before advancing. The transform
remained correct and native plus AVX2-only `make test` passed, but the integrated
AVX2-only stage paths regressed badly.

The likely cause is scheduling rather than arithmetic: each individual head
level stayed essentially flat, but the combined head path lost the level-wise
instruction locality / out-of-order overlap that the original three-pass shape
gets from running the same butterfly helper repeatedly. Keep the existing
level-wise `ntt_inv_head_avx2()` ordering. Future inverse-head work should avoid
serializing all three helper shapes inside one small block unless it also keeps
intermediate values in registers, which would be a different and much larger
rewrite.

AVX2-only stage A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage STAGE_ITERS=90000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected inverse-head block-local ordering highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_encrypt_inv_add_u_head_only` | 465.05 | 598.45 | 0.7771x | 0.7774x |
| `mlkem_core_stage_encrypt_inv_add_u_only` | 788.31 | 933.13 | 0.8448x | 0.8452x |
| `mlkem_core_stage_encrypt_accum_inv_u` | 1042.19 | 1181.12 | 0.8824x | 0.8811x |
| `mlkem_core_stage_decrypt_inv_head` | 276.08 | 316.56 | 0.8721x | 0.8721x |
| `mlkem_core_stage_decrypt_inv_sub_from` | 381.80 | 430.51 | 0.8869x | 0.8865x |
| `mlkem_core_stage_kpke_encrypt_cached` | 2782.73 | 3120.62 | 0.8917x | 0.9188x |

### Independent Core Optimization Diagnostic (2026-07-02, AVX2 inverse-sub final i16 subtract)

An AVX2 inverse-sub final subtract experiment was rejected. The candidate packed
the final scaled inverse outputs to 16-bit first, then computed the final
`minuend - scaled` step with a 16-bit modular subtract helper inside
`ntt_inv_sub_from_fused_final_avx2()`. The intended win was to avoid widening the
`minuend` vectors to 32-bit for the final subtract. Native and AVX2-only
correctness gates passed, but the direct target and nearby stage/KEM-path
proxies were flat to slightly slower.

Keep the existing 32-bit final subtract. The saved `vpmovzxwd` work did not pay
for the added pack-before-sub plus 16-bit compare/correction sequence, and the
direct `mlkem_ntt_inv_sub_from` target regressed. KEM confirmation was skipped
because the local target did not clear the adoption threshold.

AVX2-only NTT/stage A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=ntt,stage NTT_ITERS=200000 STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected inverse-sub final i16 subtract highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_ntt_inv_sub_from` | 200.14 | 200.43 | 0.9985x | 0.9987x |
| `mlkem_core_stage_decrypt_inv_sub_from` | 381.90 | 385.26 | 0.9913x | 0.9996x |
| `mlkem_core_stage_decrypt_inv_scale_sub_from` | 217.27 | 217.36 | 0.9996x | 1.0000x |
| `mlkem_core_stage_decrypt_accum_inv` | 463.44 | 462.99 | 1.0010x | 0.9992x |
| `mlkem_core_stage_kpke_decrypt_cached` | 905.98 | 906.18 | 0.9998x | 0.9997x |

Ciphertext compression/decode split metrics were added later to separate the
three `DU = 10` `u` polynomials from the single `DV = 4` `v` polynomial. These
split rows use lightweight sinks, so they are diagnostic and should not be added
back to the historical combined rows, which keep their existing sink shapes.
A pinned AVX2-only, `clang`, `BENCH_STAGES_ITERS=50000` snapshot after
the `DU = 10` compression/packing split measured:

| Metric | ns/op |
|---|---:|
| `mlkem_core_stage_ciphertext_compress_encode` | 55.90 |
| `mlkem_core_stage_ciphertext_compress_encode_d10` | 50.47 |
| `mlkem_core_stage_ciphertext_compress_encode_d10_compress_only` | 29.66 |
| `mlkem_core_stage_ciphertext_compress_encode_d10_pack_only` | 19.26 |
| `mlkem_core_stage_ciphertext_compress_encode_d4` | 6.04 |
| `mlkem_core_stage_ciphertext_decode_decompress` | 220.59 |
| `mlkem_core_stage_ciphertext_decode_decompress_d10` | 28.85 |
| `mlkem_core_stage_ciphertext_decode_decompress_d4` | 6.67 |

The split confirms that future ciphertext compression/decode work should target
the three `DU = 10` `u` paths first. The additional `compress_only` and
`pack_only` rows are diagnostic and are not expected to add exactly to the fused
`d10` row, because the fused helper keeps intermediate values in registers and
uses a different sink shape. The current split shows coefficient compression is
larger than 10-bit packing, so the next ciphertext-compression target should be
`compress_poly_d10_avx2` arithmetic first, with the d10 packing schedule as the
secondary target. The `DV = 4` components are already small, and previous d4
shift/add and inverse-subtraction fusion experiments did not survive stage/KEM
confirmation.

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

A follow-up public-prepare scheduling experiment was rejected. The candidate
kept the accepted no-cache encapsulation co-schedule, but reordered
`kpke_prepare_public_no_cache()` from
`byte_decode(pk) -> sample_matrix(rho) -> H(pk)+tail` to
`byte_decode(pk) -> H(pk)+tail -> sample_matrix(rho)`. The intent was to keep
the second read of the public-key bytes for `H(pk)` close to the d12 decode,
instead of separating them with the expensive public-matrix sampler. This is a
reasonable cache-locality/dataflow idea, but the native KEM confirmation was
flat and did not justify changing the established public-prepare order.

The candidate passed native `make test`, AVX2-only `make test`, and
`git diff --check`. Because the native `encaps_core` row was effectively flat
and `roundtrip_core` moved slightly negative, no AVX2-only A/B was run.

Native KEM A/B command:

```bash
RUNS=17 WARMUP_RUNS=4 SUITES=kem KEM_ITERS=50000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

Rejected public-prepare reorder highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_encaps_core` | 4910.31 | 4906.60 | 1.0008x | 1.0001x |
| `mlkem_roundtrip_core` | 14645.42 | 14680.65 | 0.9976x | 0.9993x |
| `mlkem_decaps_core` | 4394.02 | 4425.76 | 0.9928x | 0.9991x |
| `mlkem_encaps` | 2090.94 | 2088.58 | 1.0011x | 1.0008x |
| `mlkem_decaps` | 2910.19 | 2912.77 | 0.9991x | 0.9998x |

Keep `kpke_prepare_public_no_cache()` in decode, matrix-sample, then hash-tail
order. The extra locality from adjacent decode/hash public-key reads is too
small next to the sampler and K-PKE arithmetic costs.


A native AVX512 d10 ciphertext decode/decompress experiment was also rejected.
The candidate added a `decompress_decode_poly_d10_avx512()` path that unpacked
four 10-byte ciphertext groups into one zmm register and decompressed 32
coefficients at a time. This follows the same wide-lane batching idea used in
high-throughput finite-field code, but here the direct stage win did not carry
through to KEM decapsulation.

The candidate passed native `make test` and AVX2-only `make test`. AVX2-only
kept the existing AVX2 d10 decoder because the new path was guarded by
`__AVX512F__ && __AVX512BW__`.

Native stage A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage STAGE_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

Native KEM A/B command:

```bash
RUNS=17 WARMUP_RUNS=4 SUITES=kem KEM_ITERS=50000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

Rejected AVX512 d10 decode/decompress highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_ciphertext_decode_decompress` | 215.79 | 213.42 | 1.0111x | 1.0104x |
| `mlkem_core_stage_kpke_decrypt_cached` | 786.54 | 789.47 | 0.9963x | 0.9999x |
| `mlkem_decaps` | 2911.89 | 2909.72 | 1.0007x | 0.9999x |
| `mlkem_decaps_core` | 4392.35 | 4400.78 | 0.9981x | 0.9997x |
| `mlkem_roundtrip_core` | 14640.25 | 14621.85 | 1.0013x | 1.0006x |

Keep the narrower AVX2 d10 decoder. The zmm path makes the isolated decode
stage about 1% faster, but the full decapsulation path is neutral to slightly
negative, likely because the wider instructions add front-end/downclock cost
around much larger NTT and multiply-accumulate work.


A decrypt-side decode-to-NTT scheduling experiment was rejected. The candidate
changed `kpke_decrypt()` to run `ntt(u[i], u[i])` immediately after each d10
ciphertext `u[i]` decode, instead of decoding all `u[0..2]` and `v` first and
then transforming the three `u` polynomials. The intent was producer/consumer
locality: use each freshly decoded `u[i]` while it is still warm.

The candidate passed native `make test` and AVX2-only `make test`, but the
stage confirmation moved the full decrypt rows slightly negative, so no KEM A/B
was run.

Native stage A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage STAGE_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

Rejected decode-to-NTT scheduling highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_kpke_decrypt_cached` | 786.99 | 792.35 | 0.9932x | 0.9987x |
| `mlkem_core_stage_kpke_decrypt_uncached` | 791.42 | 795.15 | 0.9953x | 0.9988x |
| `mlkem_core_stage_ciphertext_decode_decompress` | 215.77 | 215.74 | 1.0001x | 1.0005x |
| `mlkem_core_stage_decrypt_u_ntt` | 689.67 | 691.85 | 0.9968x | 1.0006x |
| `mlkem_core_stage_decrypt_ntt_accum_recover` | 748.72 | 751.35 | 0.9965x | 0.9996x |

Keep `kpke_decrypt()` in the existing decode-all, secret-cache, then NTT order.
The attempted locality gain is smaller than the cost of moving large NTT work
before the rest of ciphertext preparation and secret-key cache handling.


A small ciphertext d10 compress/encode store cleanup was accepted. The change
replaces the final 4-byte `memcpy()` in `compress_encode_poly_d10_avx2()` with
an explicit `_mm_storeu_si32()` after computing the 20-byte packed ciphertext
chunk pointer once. This is a code-generation cleanup rather than an algorithmic
change; it keeps the core path vendor-free and leaves the packed output format
unchanged.

The candidate passed native `make test`, AVX2-only `make test`, native KEM A/B,
and AVX2-only KEM A/B. The direct stage effect is intentionally recorded as
small: this is not a new bottleneck breakthrough, only a low-risk store-path
cleanup that did not regress KEM.

Native stage A/B command:

```bash
RUNS=17 WARMUP_RUNS=4 SUITES=stage STAGE_ITERS=40000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

Native KEM A/B command:

```bash
RUNS=17 WARMUP_RUNS=4 SUITES=kem KEM_ITERS=50000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

AVX2-only KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=kem KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Accepted d10 compress/encode store cleanup highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_ciphertext_compress_encode` | 53.65 | 53.62 | 1.0004x | 1.0006x |
| `mlkem_encaps_core` native | 4953.34 | 4878.09 | 1.0154x | 1.0001x |
| `mlkem_roundtrip_core` native | 14788.28 | 14649.85 | 1.0094x | 1.0017x |
| `mlkem_encaps_core` AVX2-only | 9189.34 | 8548.82 | 1.0749x | 1.0514x |
| `mlkem_roundtrip_core` AVX2-only | 26880.25 | 25646.55 | 1.0481x | 1.0648x |

Treat this as a minor accepted cleanup. The reliable claim is removal of a
scalar-looking 4-byte copy in the d10 compress/encode hot path; the larger KEM
speedups in the AVX2-only run are too noisy to attribute solely to this change.

A helper-boundary follow-up was rejected. The candidate changed only
`compress_encode_poly_d10_avx2()` from a plain `static` helper to
`static MLKEM_ALWAYS_INLINE`, keeping the d10 compression identity, bit-packing
schedule, and ciphertext format unchanged. The goal was to see whether forcing
this fused d10 helper into the two encryption call sites would preserve the
accepted small store cleanup and reduce call-boundary/layout overhead.

Correctness passed the AVX2-only gate:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=90000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected d10 always-inline highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_ciphertext_compress_encode` | 51.14 | 51.27 | 0.9973x | 0.9990x |
| `mlkem_core_stage_ciphertext_compress_encode_d10` | 47.11 | 47.12 | 0.9998x | 1.0000x |
| `mlkem_core_stage_ciphertext_compress_encode_d10_compress_only` | 23.60 | 23.64 | 0.9986x | 0.9983x |
| `mlkem_core_stage_ciphertext_compress_encode_d10_pack_only` | 20.54 | 20.48 | 1.0027x | 1.0020x |
| `mlkem_core_stage_kpke_encrypt_cached` | 2440.46 | 2432.22 | 1.0034x | 1.0008x |
| `mlkem_core_stage_kpke_encrypt_uncached` | 4917.16 | 4916.54 | 1.0001x | 0.9996x |

Do not force-inline `compress_encode_poly_d10_avx2()`. The direct d10 fused row
is neutral and the small pack-only movement does not translate into the full
ciphertext compression row. Future d10 work should change compression or packing
arithmetic, not only the helper boundary.

A d10 pack-shift scheduling experiment was rejected. The current packer uses
`_mm256_sllv_epi32()` with the count vector created by
`_mm256_set1_epi64x(12)`. That is intentionally not a uniform 12-bit shift: it
creates the per-dword pattern `{12, 0, 12, 0, ...}` so each 64-bit lane becomes
`pair0 | (pair1 << 20)` after the following `_mm256_srli_epi64(..., 12)`. A
plain `_mm256_slli_epi32(..., 12)` would be incorrect.

The tested equivalent replaced the variable shift and count vector with an
immediate 32-bit shift plus a dword blend:

```c
__m256i shifted = _mm256_slli_epi32(f, 12);
f = _mm256_blend_epi32(shifted, f, 0xaa);
f = _mm256_srli_epi64(f, 12);
```

The same change was applied to the pack-only stage helper so the split benchmark
matched the production fused d10 packer.

Correctness passed the AVX2-only gate:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=90000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected shift/blend highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_ciphertext_compress_encode` | 51.18 | 51.46 | 0.9945x | 1.0006x |
| `mlkem_core_stage_ciphertext_compress_encode_d10` | 47.10 | 47.05 | 1.0010x | 1.0004x |
| `mlkem_core_stage_ciphertext_compress_encode_d10_compress_only` | 23.63 | 23.60 | 1.0012x | 1.0004x |
| `mlkem_core_stage_ciphertext_compress_encode_d10_pack_only` | 20.52 | 20.55 | 0.9987x | 1.0005x |
| `mlkem_core_stage_kpke_encrypt_cached` | 2433.27 | 2444.21 | 0.9955x | 1.0008x |
| `mlkem_core_stage_kpke_encrypt_uncached` | 4921.43 | 4913.08 | 1.0017x | 0.9979x |

Keep the existing `vpsllvd`-style variable dword shift. The equivalent
shift-plus-blend shape removes the count vector but adds a blend, and the target
pack/fused d10 rows are effectively neutral. This is not enough to justify a new
packing schedule or KEM confirmation.


A narrower d10 compression constant-construction experiment was rejected. The
candidate changed the AVX2 d10 compression helpers from computing
`v8 = _mm256_slli_epi16(v, 3)` to loading the equivalent 16-bit constant
`30200` directly. The arithmetic and bit packing were unchanged; the intent was
to remove one constant-construction operation from `compress_poly_d10_avx2()`
and the fused `compress_encode_poly_d10_avx2()` path. Native and AVX2-only
`make test` passed, but the targeted split metric did not move.

AVX2-only stage A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage STAGE_ITERS=120000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected d10 `v8` constant highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_ciphertext_compress_encode` | 57.32 | 57.05 | 1.0046x | 1.0025x |
| `mlkem_core_stage_ciphertext_compress_encode_d10` | 53.38 | 53.31 | 1.0015x | 1.0000x |
| `mlkem_core_stage_ciphertext_compress_encode_d4` | 5.08 | 5.07 | 1.0018x | 1.0020x |
| `mlkem_core_stage_kpke_encrypt_cached` | 2798.97 | 2855.51 | 0.9802x | 1.0006x |
| `mlkem_core_stage_kpke_keygen_full` | 7161.08 | 6989.93 | 1.0245x | 0.9744x |

Keep the existing `v << 3` expression. Clang already treats this constant shape
well enough, and the new d10 split metric shows no median improvement in the
actual fused ciphertext encoder. Future d10 compress work needs to change the
compression or packing schedule itself, not only constant construction.

A d10 two-vector compression scheduling experiment was rejected. The candidate
changed the AVX2 d10 compression path to process two independent 16-coefficient
vectors per loop body and reused that helper in the fused
`compress_encode_poly_d10_avx2()` path. The goal was to expose more instruction
level parallelism around the d10 multiply-high and `mulhrs` sequence without
changing the compression identity or ciphertext format. Native and AVX2-only
`make test` passed.

The targeted AVX2-only stage A/B looked promising for the fused d10 row, but the
full KEM confirmation regressed core roundtrip and did not produce a robust
encapsulation win. Keep the current single-vector d10 compression schedule; the
compiler and out-of-order core already overlap enough work, and the extra helper
shape/register pressure is not justified by the KEM result.

AVX2-only stage A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage STAGE_ITERS=120000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

AVX2-only KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=kem KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected d10 two-vector scheduling highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_ciphertext_compress_encode` | 57.08 | 54.57 | 1.0461x | 1.0374x |
| `mlkem_core_stage_ciphertext_compress_encode_d10` | 52.22 | 49.62 | 1.0523x | 1.0421x |
| `mlkem_core_stage_ciphertext_compress_encode_d10_compress_only` | 30.10 | 30.02 | 1.0025x | 0.9977x |
| `mlkem_encaps_core` | 8680.81 | 8714.61 | 0.9961x | 0.9989x |
| `mlkem_roundtrip_core` | 25822.96 | 26309.63 | 0.9815x | 0.9780x |

An AVX512BW d4 ciphertext compress/encode path was rejected. The candidate
processed 32 coefficients per zmm register, combined adjacent 4-bit compressed
coefficients with 32-bit shifts, and stored two 16-byte chunks for each 64 input
coefficients. The idea was to replace the AVX2 pack/madd/permute sequence used
for the `v` ciphertext component with a direct wide-lane nibble pack.

The candidate passed native `make test` and AVX2-only `make test`; AVX2-only
kept the existing AVX2 d4 encoder because the new path was guarded by
`__AVX512F__ && __AVX512BW__`. The native stage result did not justify keeping
the zmm path: the direct `ciphertext_compress_encode` median was effectively
flat, the average was slower, and full encrypt stage rows moved slightly
negative. No KEM A/B was run.

Native stage A/B command:

```bash
RUNS=17 WARMUP_RUNS=4 SUITES=stage STAGE_ITERS=40000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

Rejected AVX512BW d4 compress/encode highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_ciphertext_compress_encode` | 53.60 | 53.99 | 0.9927x | 1.0002x |
| `mlkem_core_stage_kpke_encrypt_cached` | 1869.57 | 1876.28 | 0.9964x | 0.9995x |
| `mlkem_core_stage_kpke_encrypt_uncached` | 3614.71 | 3628.94 | 0.9961x | 0.9989x |
| `mlkem_core_stage_encrypt_accum_inv` | 1111.90 | 1113.99 | 0.9981x | 1.0000x |

Keep the AVX2 d4 encoder. The d4 component is too small for the extra AVX512
width to pay for itself, and the wider path risks front-end/downclock cost
without reducing the larger K-PKE arithmetic bottleneck.


A d10 compress/encode pointer-loop cleanup was rejected. The candidate kept the
accepted explicit 4-byte tail store, but changed `compress_encode_poly_d10_avx2()`
from recomputing `out + (i / 16) * 20` inside the loop to advancing input and
output pointers by 16 coefficients and 20 bytes. This is a standard
address-generation cleanup, but modern clang already strength-reduces the
original loop well enough.

The candidate passed native `make test`, AVX2-only `make test`, native stage
A/B, and native KEM A/B. The direct stage row was weakly positive, but full KEM
core rows moved slightly negative, so the source change was not kept.

Native stage A/B command:

```bash
RUNS=17 WARMUP_RUNS=4 SUITES=stage STAGE_ITERS=40000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

Native KEM A/B command:

```bash
RUNS=17 WARMUP_RUNS=4 SUITES=kem KEM_ITERS=50000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

Rejected d10 pointer-loop highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_ciphertext_compress_encode` | 53.63 | 53.64 | 0.9999x | 1.0007x |
| `mlkem_core_stage_kpke_encrypt_uncached` | 3637.96 | 3612.51 | 1.0070x | 1.0014x |
| `mlkem_encaps_core` | 4876.26 | 4902.27 | 0.9947x | 0.9987x |
| `mlkem_roundtrip_core` | 14608.02 | 14647.33 | 0.9973x | 0.9994x |
| `mlkem_decaps_core` | 4397.36 | 4407.93 | 0.9976x | 0.9990x |

Keep the existing d10 encode loop after the explicit tail-store cleanup. The
pointer form is clearer in isolation, but it does not produce a robust KEM win.


A d10 compression correction-compare rewrite was accepted. The change keeps the
same exact `DU = 10` compression identity, but replaces the correction-bit
bit-hack in `compress_poly_d10_avx2()` and the fused
`compress_poly_d10_vec_avx2()` helper with an explicit unsigned 16-bit compare:
flip the sign bit on both operands and use the AVX2 signed compare. This removes
the dependent `sub` plus `andnot` sequence from the d10 coefficient compressor.

The equivalence condition was checked exhaustively for all canonical ML-KEM
coefficients `0..3328`: the old correction bit is exactly
`(x * 30200 & 0xffff) < x + 15`, which is the unsigned comparison implemented by
the new AVX2 sequence. The change is a vendor-free core arithmetic optimization;
it does not rely on cache effects or external library code.

Correctness commands:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core
```

AVX2-only stage A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage STAGE_ITERS=120000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

AVX2-only KEM A/B command:

```bash
RUNS=17 WARMUP_RUNS=3 SUITES=kem KEM_ITERS=50000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Native stage+KEM A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage,kem STAGE_ITERS=50000 KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

Accepted d10 correction-compare highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_ciphertext_compress_encode_d10_compress_only` AVX2-only | 27.33 | 23.51 | 1.1624x | 1.1638x |
| `mlkem_core_stage_ciphertext_compress_encode_d10` AVX2-only | 51.88 | 46.75 | 1.1097x | 1.1101x |
| `mlkem_core_stage_ciphertext_compress_encode` AVX2-only | 56.64 | 51.83 | 1.0927x | 1.0945x |
| `mlkem_encaps` AVX2-only | 2700.54 | 2690.26 | 1.0038x | 1.0025x |
| `mlkem_encaps_core` AVX2-only | 7508.10 | 7446.27 | 1.0083x | 1.0012x |
| `mlkem_roundtrip_core` AVX2-only | 22300.60 | 22172.49 | 1.0058x | 1.0010x |
| `mlkem_core_stage_ciphertext_compress_encode_d10_compress_only` native | 26.74 | 23.19 | 1.1529x | 1.1407x |
| `mlkem_core_stage_ciphertext_compress_encode_d10` native | 48.94 | 44.29 | 1.1050x | 1.0919x |
| `mlkem_core_stage_ciphertext_compress_encode` native | 53.58 | 48.76 | 1.0988x | 1.0869x |
| `mlkem_encaps` native | 2074.17 | 2064.41 | 1.0047x | 1.0051x |
| `mlkem_roundtrip_core` native | 14667.93 | 14630.12 | 1.0026x | 1.0025x |

Accept this as a real d10 arithmetic win. The local compressor row moves by
roughly 14-16%, the fused ciphertext compression row moves by roughly 9-10%, and
full encapsulation stays neutral to slightly positive on both AVX2-only and
native builds.


A narrow keygen public-key hash/copy cleanup was accepted. The change updates
`sha3_256_copy_1184()`, used by top-level ML-KEM keygen for copying `ek_pke`
into the secret key while computing `H(ek_pke)`, so each full 136-byte SHA3-256
rate block loads the final 8-byte lane once and reuses that word for both the
copy and the Keccak state absorb. This does not reduce the nine SHA3-256
permutations required for `H(ek_pke)`; it only removes a duplicated tail-lane
load in the combined copy/hash helper.

The candidate passed native `make test`, AVX2-only `make test`, native KEM A/B,
and a longer AVX2-only KEM A/B. Treat this as a small keygen-local cleanup, not
an end-to-end roundtrip breakthrough.

Native KEM A/B command:

```bash
RUNS=17 WARMUP_RUNS=4 SUITES=kem KEM_ITERS=50000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

AVX2-only KEM A/B command:

```bash
RUNS=17 WARMUP_RUNS=4 SUITES=kem KEM_ITERS=50000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Accepted public-key hash/copy tail-load highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_keygen` native | 5311.17 | 5298.16 | 1.0025x | 1.0017x |
| `mlkem_keygen_core` native | 5273.34 | 5267.67 | 1.0011x | 1.0023x |
| `mlkem_roundtrip_core` native | 14644.40 | 14672.44 | 0.9981x | 1.0015x |
| `mlkem_keygen` AVX2-only | 8747.27 | 9060.67 | 0.9654x | 1.0038x |
| `mlkem_keygen_core` AVX2-only | 8713.19 | 9046.56 | 0.9631x | 1.0004x |

The AVX2-only averages were noisy, including unrelated encaps/decaps movement;
the acceptance signal is the non-negative keygen median plus the simpler single
load feeding both the copy and absorb paths.


A follow-up top-level keygen hash-output copy cleanup was accepted. The
candidate writes `sha3_256_copy_1184()` output directly into the `H(ek_pke)`
field inside `dk` instead of first writing to a local `h[32]` buffer and then
copying those 32 bytes into the secret key. The cache store now reads the hash
from the same `dk` field. This preserves the secret-key layout and does not
change the public-key hash computation.

The candidate passed native `make test`, AVX2-only `make test`, native KEM A/B,
and AVX2-only KEM A/B. The effect is intentionally scoped to top-level keygen;
no claim is made for encaps/decaps rows.

Native KEM A/B command:

```bash
RUNS=17 WARMUP_RUNS=4 SUITES=kem KEM_ITERS=50000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

AVX2-only KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=kem KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Accepted direct hash-output write highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_keygen` native | 5286.99 | 5287.06 | 1.0000x | 1.0002x |
| `mlkem_keygen_core` native | 5264.64 | 5264.71 | 1.0000x | 1.0002x |
| `mlkem_keygen` AVX2-only | 8945.20 | 8910.67 | 1.0039x | 1.0021x |
| `mlkem_keygen_core` AVX2-only | 8931.12 | 8889.45 | 1.0047x | 1.0032x |

This is a small copy-elision cleanup: it removes one local 32-byte hash buffer
and one 32-byte copy in keygen, while keeping all Keccak work and output bytes
unchanged.


An encapsulation SHA3-512 split-output experiment was rejected. The candidate
kept the existing `m || H(ek)` 64-byte input buffer, but added a local
`sha3_512_64_split_output()` helper that wrote the first 32 output bytes
directly to the shared secret `k` and the second 32 bytes to the local `r`
buffer, instead of writing `ghash[64]` and then copying `ghash[0..31]` to `k`.
This is an output-copy elision only; it does not change the SHA3-512 input or
permutation count.

The candidate passed native `make test` and AVX2-only `make test`, but the
native encapsulation core row was flat-to-negative and the AVX2-only KEM run
moved sharply negative. The source change was reverted.

Native KEM A/B command:

```bash
RUNS=17 WARMUP_RUNS=4 SUITES=kem KEM_ITERS=50000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

AVX2-only KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=kem KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected SHA3-512 split-output highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_encaps` native | 2085.26 | 2084.42 | 1.0004x | 1.0001x |
| `mlkem_encaps_core` native | 4930.13 | 4902.98 | 1.0055x | 0.9994x |
| `mlkem_roundtrip_core` native | 14712.19 | 14626.89 | 1.0058x | 1.0019x |
| `mlkem_encaps` AVX2-only | 3010.63 | 3045.25 | 0.9886x | 0.9994x |
| `mlkem_encaps_core` AVX2-only | 8970.65 | 9546.21 | 0.9397x | 0.8380x |

Keep the existing `ghash[64]` path in `mlkem_encaps()`. Avoiding the final
32-byte copy is not enough to offset the extra helper/codegen shape, and the
AVX2-only run does not support adoption.


A deterministic encapsulation message-copy cleanup was accepted. The candidate
keeps the existing `ghash[64]` SHA3-512 path, but changes `mlkem_encaps()` so a
non-null encapsulation seed is used directly as `m` instead of first copying it
into a local `m[32]` buffer. Random encapsulation still fills a local 32-byte
buffer and then uses that buffer as `m`. This removes one 32-byte copy from the
common `mlkem_encaps_derand()` / benchmark path without changing `m`, `k`, `r`,
or ciphertext generation.

The candidate passed native `make test`, AVX2-only `make test`, native KEM A/B,
and AVX2-only KEM A/B. The effect is intentionally scoped to deterministic
encapsulation; keygen and decapsulation movement is unrelated noise.

Native KEM A/B command:

```bash
RUNS=17 WARMUP_RUNS=4 SUITES=kem KEM_ITERS=50000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

AVX2-only KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=kem KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Accepted deterministic encaps message-copy highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_encaps` native | 2087.23 | 2086.62 | 1.0003x | 1.0005x |
| `mlkem_encaps_core` native | 4876.32 | 4874.79 | 1.0003x | 1.0006x |
| `mlkem_roundtrip_core` native | 14657.31 | 14636.82 | 1.0014x | 1.0000x |
| `mlkem_encaps` AVX2-only | 3045.73 | 3139.98 | 0.9700x | 1.0003x |
| `mlkem_encaps_core` AVX2-only | 8926.92 | 8832.19 | 1.0107x | 1.0091x |

This is a small copy-elision cleanup. The reliable claim is removal of the local
seed-to-message copy for deterministic encapsulation; the KEM rows are kept only
to show non-regression of the exercised path.


A keygen hash-cache input-copy elision experiment was rejected. The candidate
avoided copying the freshly generated 1184-byte public key into
`mlkem_ek_hash_cache_input` during top-level keygen. Instead, the hash cache
kept only `H(ek)` and a generation number, and `mlkem_encaps()` could validate
that hash cache entry by matching the same generation against the already-filled
public cache `ek`. The goal was to reuse the public cache's `ek` copy instead of
keeping a duplicate hash-cache input copy.

The candidate passed native `make test` and AVX2-only `make test`, but the
runtime signal was not robust. Native keygen improved slightly, but native
encapsulation core moved negative and AVX2-only keygen median regressed. The
extra cache-matching state and branch complexity are not justified.

Native KEM A/B command:

```bash
RUNS=17 WARMUP_RUNS=4 SUITES=kem KEM_ITERS=50000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

AVX2-only KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=kem KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected hash-cache input-copy elision highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_keygen` native | 5317.07 | 5281.58 | 1.0067x | 1.0019x |
| `mlkem_encaps_core` native | 4873.84 | 4906.39 | 0.9934x | 0.9989x |
| `mlkem_keygen` AVX2-only | 9077.84 | 9054.78 | 1.0025x | 0.9885x |
| `mlkem_keygen_core` AVX2-only | 9078.04 | 9025.52 | 1.0058x | 1.0103x |
| `mlkem_encaps_core` AVX2-only | 9270.52 | 8881.16 | 1.0438x | 1.0107x |

Keep the simpler hash cache that owns its input copy. The duplicate 1184-byte
copy in keygen is measurable in isolation, but avoiding it makes cache-hit
validation more complex and does not produce stable KEM wins.


A decapsulation re-encryption compare-folding experiment was rejected. The
candidate added AVX2-only `compress_encode_poly_d10_cmp_avx2()` and
`compress_encode_poly_d4_cmp_avx2()` helpers, refactored
`kpke_encrypt_prepared_public()` behind an internal compare-capable helper, and
used that path in `mlkem_decaps()` only for the fixed-size no-cache
`public_prepared && clen == CT_BYTES` case. The intended direct effect was to
avoid writing `cdash[1088]` and then calling `memcmp(c, cdash, clen)` during the
Fujisaki-Okamoto re-encryption check; the encode path instead accumulated XOR
differences against the input ciphertext.

The candidate passed native `make test` and AVX2-only `make test`, but the KEM
signal was not stable enough to justify the extra code and the write-path
refactor. Native `mlkem_decaps_core` was only a `1.0007x` median speedup while
`mlkem_roundtrip_core` regressed. AVX2-only confirmation was contradictory: one
run showed a large decapsulation-core win, but the repeat regressed decapsulation
and roundtrip core. The source change was reverted.

Native KEM A/B command:

```bash
RUNS=17 WARMUP_RUNS=4 SUITES=kem KEM_ITERS=50000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

AVX2-only KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=kem KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected decaps compare-folding highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_decaps_core` native | 4422.66 | 4418.69 | 1.0009x | 1.0007x |
| `mlkem_roundtrip_core` native | 14686.13 | 14673.36 | 1.0009x | 0.9985x |
| `mlkem_decaps_core` AVX2-only run 1 | 8687.19 | 8224.53 | 1.0563x | 1.0852x |
| `mlkem_roundtrip_core` AVX2-only run 1 | 26980.03 | 26570.11 | 1.0154x | 1.0174x |
| `mlkem_decaps_core` AVX2-only run 2 | 8360.58 | 8570.16 | 0.9755x | 0.9843x |
| `mlkem_roundtrip_core` AVX2-only run 2 | 26463.55 | 26788.76 | 0.9879x | 0.9621x |

Keep the current `cdash[CT_BYTES]` plus `memcmp()` path. Avoiding the 1088-byte
store does not produce a reproducible KEM win, and folding the comparison into
AVX2 final encode adds enough codegen/layout risk that it should not be treated
as a core optimization target unless a future design avoids perturbing the normal
write path and proves stable across repeated KEM runs.

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

A follow-up scratch-placement experiment for the accepted public work
co-scheduling was rejected. The candidate moved the 504-byte tail sampler
`stream[63]` scratch in both `sha3_256_sample_ntt_tail_avx2()` and
`sha3_512_sample_ntt_tail_avx2()` from the stack to static storage. This was
modeled after the accepted AVX2 x4 sampler scratch placement, but the longer
KEM confirmation did not show a robust core win for the public-prepare path.

The candidate passed native `make test`, AVX2-only `make test`, and
`git diff --check`. The first native stage/KEM A/B was flat-to-slightly-positive
in KEM core rows, but the longer native KEM confirmation regressed the direct
core encapsulation/decapsulation rows, so the source was reverted.

Initial native stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage,kem STAGE_ITERS=90000 KEM_ITERS=35000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

Initial highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_kpke_encrypt_uncached` | 3609.15 | 3615.77 | 0.9982x | 0.9996x |
| `mlkem_core_stage_kpke_decrypt_uncached` | 788.31 | 790.98 | 0.9966x | 0.9999x |
| `mlkem_encaps_core` | 4906.71 | 4903.82 | 1.0006x | 1.0002x |
| `mlkem_decaps_core` | 4455.22 | 4414.09 | 1.0093x | 1.0017x |
| `mlkem_roundtrip_core` | 14764.36 | 14721.90 | 1.0029x | 1.0087x |

Longer native KEM confirmation:

```bash
RUNS=17 WARMUP_RUNS=4 SUITES=kem KEM_ITERS=50000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

Rejected hash-tail static scratch highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_encaps_core` | 4873.94 | 4893.00 | 0.9961x | 0.9982x |
| `mlkem_decaps_core` | 4401.07 | 4402.17 | 0.9997x | 0.9986x |
| `mlkem_roundtrip_core` | 14622.33 | 14633.52 | 0.9992x | 0.9989x |
| `mlkem_encaps` | 2090.68 | 2087.78 | 1.0014x | 1.0015x |
| `mlkem_decaps` | 2916.06 | 2914.70 | 1.0005x | 0.9997x |

Keep the hash-tail co-scheduling stream scratch on the stack. The accepted x4
sampler static scratch result does not transfer cleanly to these public-prepare
helpers; the core KEM rows are too sensitive to code/layout effects.

### Latest Core Optimization A/B (2026-07-02, AVX2 decaps re-encrypt tail/noise co-scheduling)

The AVX2-only no-cache `mlkem_decaps()` path now moves the final public-matrix
`(2,2)` tail from the `sha3_512(mdash || h)` co-schedule into the re-encryption
noise schedule. The previous no-cache decapsulation path sampled the tail while
lane 0 computed `kdash || rdash`, then generated the re-encryption PRF/CBD noise
separately. The new path computes `ghash` first, prepares the first eight public
matrix entries with the existing two `sample_ntt4()` calls, and then uses the
same AVX2 tail/noise co-schedule as the uncached encapsulation path with
`rdash`. The first tail block rides with PRF nonces 4, 5, and 6; the remaining
single-lane tail continuation uses scalar `keccakf()`.

This is a core dataflow change inside one decapsulation. It does not add or rely
on a cross-operation cache, and it is guarded to AVX2-only builds because native
AVX512 keeps the existing public-work co-schedule.

Correctness checks:

```bash
make test CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
make test CC=clang AVX2_BACKEND=core
```

Initial AVX2-only KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=kem KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Initial highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_decaps` | 3632.06 | 3624.16 | 1.0022x | 1.0016x |
| `mlkem_decaps_core` | 6500.37 | 6145.00 | 1.0578x | 1.0498x |
| `mlkem_encaps_core` | 7156.63 | 7273.09 | 0.9840x | 0.9885x |
| `mlkem_roundtrip_core` | 20816.36 | 20529.65 | 1.0140x | 1.0077x |

The first run showed the intended decapsulation-core win but an unrelated-looking
`encaps_core` regression, so the change needed a longer confirmation before
acceptance.

Longer AVX2-only KEM confirmation:

```bash
RUNS=17 WARMUP_RUNS=4 SUITES=kem KEM_ITERS=50000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_decaps` | 3642.09 | 3643.10 | 0.9997x | 1.0013x |
| `mlkem_decaps_core` | 6549.03 | 6129.48 | 1.0684x | 1.0486x |
| `mlkem_encaps` | 2699.57 | 2688.71 | 1.0040x | 1.0014x |
| `mlkem_encaps_core` | 7077.99 | 7108.58 | 0.9957x | 0.9990x |
| `mlkem_roundtrip` | 13483.20 | 13473.71 | 1.0007x | 1.0009x |
| `mlkem_roundtrip_core` | 20772.83 | 20344.67 | 1.0210x | 1.0167x |

Decision: accept the AVX2-only decapsulation re-encrypt tail/noise co-schedule.
The direct no-cache decapsulation core path keeps about a 1.05x median win, and
the longer confirmation carries that into `roundtrip_core` without a meaningful
encapsulation median regression. This reinforces the current direction: use SIMD
lanes for independent real work inside the same KEM operation, but switch back to
scalar Keccak once only a single XOF stream remains.

A matching AVX2-only no-cache encapsulation tail/noise move was rejected. The
candidate tried to mirror the accepted decapsulation change: compute `H(ek)` with
scalar SHA3-256 first, compute `G(m || H(ek))`, then prepare the first eight
public-matrix entries with two `sample_ntt4()` calls and move the final `(2,2)`
tail into the encryption PRF/CBD noise schedule with `r`. This replaced the
existing no-cache encapsulation `H(ek)+tail` co-schedule in
`kpke_prepare_public_no_cache()`.

Correctness passed the AVX2-only gate:

```bash
make test CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=kem KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected encaps tail/noise highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_encaps` | 2688.25 | 2688.02 | 1.0001x | 1.0005x |
| `mlkem_encaps_core` | 7084.93 | 7246.60 | 0.9777x | 0.9791x |
| `mlkem_decaps_core` | 6148.82 | 6143.66 | 1.0008x | 0.9972x |
| `mlkem_roundtrip` | 13504.96 | 13462.77 | 1.0031x | 1.0022x |
| `mlkem_roundtrip_core` | 20388.65 | 20468.81 | 0.9961x | 0.9977x |

Keep no-cache encapsulation on the existing `H(ek)+tail` public-prepare
co-schedule. Unlike decapsulation's `sha3_512(mdash || h)` case, the first three
public-key hash permutations are real work that pair well with the three initial
SHAKE128 tail blocks. Moving the tail to the noise schedule saves an empty noise
lane but pays extra scalar tail/hash work and clearly regresses `encaps_core`.

A hash-tail Keccak shape experiment was rejected. The candidate changed only the
initial three `keccakf4()` calls in `sha3_256_sample_ntt_tail_avx2()` and
`sha3_512_sample_ntt_tail_avx2()` to `keccakf4_mem()`, leaving the rare refill
continuation register-resident. This tested whether the memory-resident shape
that helps the standalone `sample_ntt4()` public-matrix sampler also helps the
mixed public-hash/tail helpers.

Correctness passed the AVX2-only gate:

```bash
make test CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage/KEM A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage,kem STAGE_ITERS=70000 KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected hash-tail memory Keccak highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_kpke_prepare_public_no_cache` | 4234.57 | 4435.24 | 0.9548x | 0.9571x |
| `mlkem_core_stage_kpke_encrypt_uncached` | 4977.84 | 4984.73 | 0.9986x | 1.0011x |
| `mlkem_encaps_core` | 7023.49 | 6999.93 | 1.0034x | 1.0053x |
| `mlkem_decaps_core` | 6134.91 | 6109.61 | 1.0041x | 1.0003x |
| `mlkem_roundtrip_core` | 20279.34 | 20209.39 | 1.0035x | 1.0028x |

Keep the hash-tail helpers on register-resident `keccakf4()`. The small positive
KEM movement is not an acceptance signal because the direct public-prepare stage
regresses by about 4.3% on median. The `sample_ntt4()` memory-resident win does
not transfer to these mixed helpers: public-key hash absorb, lane extraction, and
hash continuation change the register-pressure/layout tradeoff.


### Independent Core Optimization Diagnostic (2026-07-03, AVX2 hash-tail lane1 extraction)

A narrower AVX2 hash-tail state-extraction experiment was rejected. The
candidate kept the accepted hash/tail co-schedule and register-resident
`keccakf4()` permutations, but replaced the scalar `keccak_lane1_u64()` loop used
for the `(2,2)` tail stream with a four-word vector helper:
`unpackhi_epi64` extracts lane 1 from four Keccak state vectors, then one
`storeu_si256` writes four stream words. This changed only the lane-1 extraction
used by `sha3_256_sample_ntt_tail_avx2()` and
`sha3_512_sample_ntt_tail_avx2()` for the initial three tail blocks and rare
refill block; Keccak counts, parser, hash continuation, and outputs were
unchanged.

Correctness passed the AVX2-only gate:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected hash-tail lane1 extraction highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_kpke_prepare_public_no_cache` | 4178.76 | 4183.56 | 0.9989x | 0.9989x |
| `mlkem_core_stage_kpke_encrypt_uncached` | 4920.11 | 4889.37 | 1.0063x | 1.0057x |
| `mlkem_core_stage_kpke_encrypt_cached` | 2422.70 | 2428.68 | 0.9975x | 0.9999x |
| `mlkem_core_stage_sample_matrix_tail` | 870.19 | 865.75 | 1.0051x | 1.0077x |
| `mlkem_core_stage_sample_matrix` | 2809.82 | 2803.00 | 1.0024x | 1.0005x |

Decision: keep the simple scalar `keccak_lane1_u64()` extraction in the
hash-tail helpers. The vector extract form is mechanically tidy, but it adds
shuffles and does not improve the direct public-prepare row that uses these
helpers. No KEM confirmation was run because the stage gate failed. Future
state-extraction work needs to remove an extraction boundary entirely or fill
more Keccak lanes with real work; batching the same lane extract is too small.

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

A narrower native AVX512 encryption PRF/CBD fixed-nonce experiment was also
rejected. The candidate specialized the x7 PRF helper for the fixed encryption
nonce sequence `{0, 1, 2, 3, 4, 5, 6}` so the wrapper no longer built a local
nonce array or passed it into `mlkem_prf_cbd_eta2x7_32()`. It passed native and
AVX2-only `make test`, but the direct stage did not improve and the integrated
encryption rows were not robust enough to justify the extra helper. The likely
reason is that clang already folds the fixed nonce setup cheaply, while the
remaining cost is dominated by Keccak and CBD decode work.

Native stage A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage KEM_ITERS=3000 STAGE_ITERS=100000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

Rejected AVX512 fixed-nonce PRF/CBD highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_encrypt_noise_prf_cbd` | 878.75 | 878.71 | 1.0000x | 0.9993x |
| `mlkem_core_stage_encrypt_noise` | n/a | n/a | 1.0020x | 1.0012x |
| `mlkem_core_stage_kpke_encrypt_cached` | n/a | n/a | 0.9957x | 1.0001x |
| `mlkem_core_stage_kpke_encrypt_uncached` | n/a | n/a | 0.9962x | 0.9988x |
| `mlkem_core_stage_keygen_noise_prf_cbd` | n/a | n/a | 0.9996x | 0.9988x |

Keep the generic AVX512 x7 PRF/CBD helper for encryption. Fixed-nonce
specialization does not currently buy real core speed, so the simpler shared
helper is preferable.

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

A native AVX512 follow-up that widened the generic `poly256_add()` helper from
16-lane AVX2 vectors to 32-lane AVX512 vectors was also rejected. The candidate
passed native and AVX2-only core `make test`, but the direct keygen
accumulate/add/encode stage regressed. The wider helper adds AVX512 mask and zmm
overhead to a small 16-bit modular add where the existing AVX2 path is already
cheap.

Native stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage,kem STAGE_ITERS=120000 KEM_ITERS=40000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

AVX512 `poly256_add()` widening highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_accum_encode` | 425.44 | 432.20 | 0.9844x | 0.9848x |
| `mlkem_core_stage_kpke_keygen_full` | 3396.03 | 3412.16 | 0.9953x | 0.9982x |
| `mlkem_keygen_core` | n/a | n/a | 0.9947x | 1.0002x |
| `mlkem_roundtrip_core` | n/a | n/a | n/a | 1.0017x |

Keep `poly256_add()` on the AVX2 implementation even for native AVX512 builds.
The target stage is worse, while the full KEM rows are at best noise-level.

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

### Independent Core Optimization A/B (2026-07-02, AVX2-only d10 ciphertext tail load)

A narrow follow-up specializes the `DU = 10` decode/decompress tail only for the
internal `kpke_decrypt()` ciphertext path on AVX2-only builds. The generic
`decompress_decode_poly_d10_avx2()` remains exact-buffer-safe. The new internal
`decompress_decode_poly_d10_ct_avx2()` is used only after `kpke_decrypt()` has
checked the full ciphertext length, so the final d10 vector load may legally read
into the following `DV = 4` ciphertext bytes. This removes the special final
8-byte-plus-2-byte construction from the decrypt ciphertext path without changing
non-AVX2 or native AVX512 paths.

Native AVX512 was deliberately left on the existing safe decoder: an unguarded
variant slightly weakened native decapsulation/roundtrip rows, while the
AVX2-only gate kept native KEM neutral.

AVX2-only stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage,kem STAGE_ITERS=70000 KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Accepted AVX2-only stage highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_ciphertext_decode_decompress_d10` | 27.76 | 27.60 | 1.0060x | 1.0065x |
| `mlkem_core_stage_ciphertext_decode_decompress` | 221.13 | 221.47 | 0.9985x | 0.9994x |
| `mlkem_core_stage_kpke_decrypt_cached` | 925.84 | 925.07 | 1.0008x | 1.0001x |
| `mlkem_core_stage_decrypt_ntt_accum_recover` | 882.35 | 882.83 | 0.9995x | 0.9996x |

Longer AVX2-only KEM confirmation command:

```bash
RUNS=17 WARMUP_RUNS=2 SUITES=kem KEM_ITERS=50000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

KEM confirmation highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_decaps` | 3678.16 | 3665.17 | 1.0035x | 1.0008x |
| `mlkem_decaps_core` | 6906.96 | 6730.08 | 1.0263x | 1.0726x |
| `mlkem_roundtrip` | 14453.69 | 14487.00 | 0.9977x | 1.0023x |
| `mlkem_roundtrip_core` | 22545.07 | 22155.21 | 1.0176x | 1.0011x |

Native guarded no-regression with `RUNS=9`, `KEM_ITERS=30000` stayed neutral:
`mlkem_decaps` median `1.0022x`, `mlkem_decaps_core` median `0.9995x`, and
`mlkem_roundtrip_core` median `1.0013x`. Treat the direct d10 decode row as the
primary attribution; the full KEM movement is small and layout-sensitive.

A helper-boundary follow-up for the internal ciphertext decoder was rejected.
The candidate changed only `decompress_decode_poly_d10_ct_avx2()` from a plain
`static` helper to `static MLKEM_ALWAYS_INLINE`, leaving the generic exact-buffer
safe decoder untouched. The unpack schedule, 16-bit `mulhrs` decompression
identity, and ciphertext format were unchanged.

Correctness passed the AVX2-only gate:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=90000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Stage highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_ciphertext_decode_decompress_d10` | 31.15 | 30.92 | 1.0072x | 1.0052x |
| `mlkem_core_stage_ciphertext_decode_decompress` | 222.63 | 222.63 | 1.0000x | 1.0000x |
| `mlkem_core_stage_kpke_decrypt_cached` | 908.92 | 905.46 | 1.0038x | 1.0003x |
| `mlkem_core_stage_kpke_decrypt_uncached` | 916.73 | 916.31 | 1.0005x | 1.0006x |

AVX2-only KEM confirmation with `RUNS=13`, `KEM_ITERS=30000` rejected keeping the
source change:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_decaps` | 3680.67 | 3642.85 | 1.0104x | 0.9994x |
| `mlkem_decaps_core` | 6089.11 | 6095.53 | 0.9989x | 0.9962x |
| `mlkem_roundtrip` | 13386.00 | 13382.67 | 1.0002x | 0.9986x |
| `mlkem_roundtrip_core` | 20259.90 | 20264.40 | 0.9998x | 0.9996x |

Keep `decompress_decode_poly_d10_ct_avx2()` on the compiler-selected call
boundary. The direct d10 decode row improves, but the KEM decapsulation and
roundtrip core medians do not retain the benefit. Future d10 decode work should
remove data movement or fuse with later decrypt work rather than only changing
helper placement.

A symmetric helper-boundary follow-up that forced
`decompress_decode_poly_d10_ct_avx2()` to `static MLKEM_NOINLINE` was also
rejected. Correctness passed the same AVX2-only gate, but the direct target row
regressed enough that no KEM confirmation was warranted.

AVX2-only stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=90000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Stage highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_ciphertext_decode_decompress_d10` | 30.99 | 31.56 | 0.9820x | 0.9828x |
| `mlkem_core_stage_ciphertext_decode_decompress` | 222.68 | 223.98 | 0.9942x | 0.9937x |
| `mlkem_core_stage_kpke_decrypt_cached` | 907.04 | 907.02 | 1.0000x | 0.9991x |
| `mlkem_core_stage_kpke_decrypt_uncached` | 918.49 | 918.17 | 1.0003x | 1.0006x |

Keep the compiler-selected call boundary: forcing either inline or noinline is
not a stable core optimization. The next useful d10 decode work should attack
unpack/decompress data movement or fusion with decrypt instead of function
placement.

A follow-up d10 unpack scheduling experiment was rejected. The candidate kept
the accepted 16-bit `mulhrs` decompression identity, but changed the 10-bit
byte unpack from three constant right shifts plus three `_mm256_blend_epi16()`
operations to one `_mm256_mulhi_epu16()` with per-lane shift multipliers plus a
single blend. This reduced the number of shuffle-side operations in the local
unpack schedule, but moved work onto the multiply pipeline and changed code
layout. Native and AVX2-only `make test` passed, and the direct decode stage
improved slightly, but KEM-level no-regression failed.

AVX2-only stage A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage STAGE_ITERS=120000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

Stage highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_ciphertext_decode_decompress` | 220.47 | 219.61 | 1.0039x | 1.0039x |
| `mlkem_core_stage_kpke_decrypt_cached` | 929.00 | 927.05 | 1.0021x | 1.0001x |
| `mlkem_core_stage_kpke_decrypt_uncached` | 937.91 | 938.51 | 0.9994x | 0.9999x |
| `mlkem_core_stage_kpke_keygen_full` | 6524.69 | 6941.14 | 0.9400x | 0.9655x |

AVX2-only KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=kem KEM_ITERS=30000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected d10 unpack `mulhi` schedule KEM highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_decaps_core` | 8061.24 | 8210.73 | 0.9818x | 1.0474x |
| `mlkem_encaps_core` | 8847.74 | 9317.61 | 0.9496x | 0.9493x |
| `mlkem_keygen_core` | 8827.81 | 9067.86 | 0.9735x | 0.9355x |
| `mlkem_roundtrip_core` | 25869.68 | 26741.96 | 0.9674x | 0.9832x |

Keep the existing shift/blend unpack schedule in `decompress_decode_poly_d10_avx2()`.
The local decode row is only about `0.4%` faster with `mulhi`, while the broader
KEM rows show unacceptable code-layout / pipeline side effects. Future d10 work
should remove larger data movement or fuse with later decrypt work, not trade
cheap shifts for another vector multiply in this helper.

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

A native AVX512 follow-up was rejected. The candidate widened the d12 key
encoder to pack 32 coefficients at a time with `_mm512_madd_epi16`,
`_mm512_shuffle_epi8`, and four 12-byte stores. Native stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage,kem STAGE_ITERS=90000 KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

AVX512 d12 encode A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_accum_encode` | 424.52 | 426.46 | 0.9955x | 0.9953x |
| `mlkem_core_stage_keygen_noise_ntt` | 1560.60 | 1561.12 | 0.9997x | 0.9995x |
| `mlkem_core_stage_keygen_noise_ntt_encode` | 1423.16 | 1430.66 | 0.9948x | 0.9937x |
| `mlkem_core_stage_kpke_keygen_full` | 3407.63 | 3421.55 | 0.9959x | 0.9940x |
| `mlkem_keygen` | 5303.66 | 5322.51 | 0.9965x | 0.9956x |
| `mlkem_keygen_core` | 5278.34 | 5299.28 | 0.9960x | 0.9967x |
| `mlkem_roundtrip` | 20132.26 | 20189.13 | 0.9972x | 0.9985x |
| `mlkem_roundtrip_core` | 19237.71 | 19264.76 | 0.9986x | 1.0003x |

Halving the loop count did not pay for the wider shuffle and lane extraction:
the zmm shuffle still works in 128-bit lanes, the static shuffle mask adds a
load, and the result still has to be split into four 12-byte chunks. Keep the
AVX2 16-coefficient packer on native AVX512 builds too.

A forward-NTT/d12 secret-key encode fusion experiment was also rejected. The
candidate duplicated the AVX2 forward-NTT tail and, in the final `length = 2`
stage, packed the freshly computed 16 coefficients directly into the d12
secret-key encoding while still storing the NTT-domain `shat` polynomial for the
public-key multiply. This was intended to remove the immediate reload by
`byte_encode_d12_avx2()` after `ntt(shat)`. It passed native `make test`,
AVX2-only `make test`, and `git diff --check`, but the direct NTT+encode row
regressed clearly. The extra final-stage unpacking, duplicated tail body, and
code-layout pressure cost more than the eliminated encode reload.

A later diagnostic split added `keygen_accum_add_only` and
`keygen_public_encode_only` stage metrics for the public-key output side. On one
pinned CPU 0, `clang`, 20,000-iteration snapshot, native measured
`keygen_accum_encode` 425.74 ns/op, `keygen_accum_add_only` 402.60 ns/op, and
`keygen_public_encode_only` 36.19 ns/op. AVX2-only measured 486.32 ns/op, 460.45
ns/op, and 36.57 ns/op respectively. The split rows have independent sink
overhead, but the direction is clear: public-key d12 encode is now a small
component, so future keygen work should target the K=3 accumulation/add
schedule rather than another d12 encode rewrite. The `keygen_accum_only` and
`keygen_add_only` rows further split the accumulation/add boundary so future
attempts can separate arithmetic wins from the already vectorized error-add
pass. A pinned CPU 0, `clang`, 40,000-iteration snapshot measured native
`keygen_accum_only` at 372.87 ns/op and `keygen_add_only` at 200.65 ns/op;
AVX2-only measured 441.12 ns/op and 204.39 ns/op respectively. These rows have
separate checksum overhead and are not additive, but they confirm that the next
core target is still the `A^T*s` accumulation arithmetic rather than the
existing vectorized error-add pass.

A follow-up K=3 three-output accumulation experiment was rejected. The candidate
computed all three public-key columns in one `ntt_mul_acc3_cols3_factored_gamma()`
loop, reusing `shat[0..2]` and `GAMMA[i]` loads before keeping the existing
separate vectorized `ntt_add()` and d12 encode passes. This is the right class
of core experiment, but the larger scalar loop increased instruction/register
pressure enough to lose despite the operand reuse. The candidate passed native
and AVX2-only `make test`; AVX2-only A/B was not pursued after the native stage
regression was already clear.

K=3 columns native stage A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage STAGE_ITERS=40000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

Rejected K=3 columns highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_accum_add_only` | 403.42 | 427.99 | 0.9426x | 0.9461x |
| `mlkem_core_stage_keygen_accum_encode` | 429.30 | 457.26 | 0.9388x | 0.9381x |
| `mlkem_core_stage_kpke_keygen_full` | 3419.93 | 3465.87 | 0.9867x | 0.9849x |

Keep the three separate `ntt_mul_acc3_factored_gamma()` calls for keygen public
accumulation. The next keygen attempt should either reduce the per-column scalar
critical path itself or add a vectorized accumulation path, not only coalesce the
three output columns into one larger scalar loop.

A narrow NTT accumulation `restrict` qualifier experiment was rejected. The
candidate changed `ntt_mul_add()`, `ntt_mul_acc3()`,
`ntt_mul_acc3_pair_values()`, and `ntt_mul_acc3_factored_gamma()` signatures from
`poly256` parameters to `int16_t [restrict N]` parameters, reflecting the actual
non-overlap between accumulation inputs and outputs. It passed native and
AVX2-only `make test`, but the direct helper rows were essentially neutral and
KEM keygen did not show a clean win.

Restrict AVX2-only NTT A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=ntt NTT_ITERS=200000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

Restrict native stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage,kem STAGE_ITERS=40000 KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

Rejected restrict highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_ntt_mul_acc3` | 96.40 | 97.19 | 0.9920x | 0.9985x |
| `mlkem_ntt_mul_acc3_factored` | 96.74 | 97.52 | 0.9920x | 0.9998x |
| `mlkem_core_stage_keygen_accum_only` | 372.25 | 373.00 | 0.9980x | 0.9997x |
| `mlkem_core_stage_keygen_accum_encode` | 422.65 | 422.23 | 1.0010x | 1.0019x |
| `mlkem_keygen` | 5310.35 | 5319.38 | 0.9983x | 1.0003x |
| `mlkem_keygen_core` | 5286.01 | 5295.13 | 0.9983x | 1.0007x |

Do not carry the restrict-only source change. Clang's current lowering for the
hot scalar accumulation loop is already effectively alias-insensitive here, and
the direct `A^T*s` metric did not move. Future work needs to change the
arithmetic schedule or representation, not just pointer qualifiers.

### Independent Core Optimization Diagnostic (2026-07-03, AVX2 keygen accumulation noinline boundary)

A call-boundary experiment for the keygen public accumulation helper was
rejected. The candidate changed only `ntt_mul_acc3_factored_gamma()` from a
plain `static` helper to `static MLKEM_NOINLINE`, keeping the arithmetic,
reductions, stores, and public-key encode schedule unchanged. The goal was to
see whether isolating the scalar accumulation loop reduced code-layout or
register-pressure interference around `kpke_keygen()`.

Correctness check:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected noinline highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_accum_only` | 440.89 | 444.37 | 0.9922x | 0.9929x |
| `mlkem_core_stage_keygen_accum_add_only` | 457.62 | 462.88 | 0.9886x | 0.9887x |
| `mlkem_core_stage_keygen_accum_encode` | 490.30 | 496.99 | 0.9866x | 0.9873x |
| `mlkem_core_stage_kpke_keygen_full` | 4814.89 | 4817.13 | 0.9995x | 0.9993x |

Do not force a call boundary on `ntt_mul_acc3_factored_gamma()`. The local
accumulation rows get slower and the full keygen row is neutral, so the current
compiler-selected boundary is better. The next useful keygen accumulation work
still needs to change the scalar arithmetic schedule or introduce a vectorized
path, not only adjust helper placement.

### Independent Core Optimization Diagnostic (2026-07-03, AVX2 keygen accumulation loop unroll)

A loop-scheduling experiment for `ntt_mul_acc3_factored_gamma()` was rejected.
The candidate added a clang-only `#pragma clang loop unroll_count(2)` immediately
before the 128-pair scalar accumulation loop. This was intended to expose more
independent products per iteration without changing arithmetic, reductions,
stores, or any public API.

Correctness check:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only NTT A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=ntt NTT_ITERS=250000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected unroll highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_ntt_mul_acc3_factored` | 98.59 | 211.80 | 0.4655x | 0.4215x |
| `mlkem_ntt_mul_acc3` | 98.31 | 101.29 | 0.9706x | 0.9992x |
| `mlkem_ntt_copy` | 197.51 | 197.37 | 1.0007x | 1.0010x |
| `mlkem_ntt_inplace` | 191.89 | 192.04 | 0.9992x | 1.0001x |

Do not manually unroll the factored K=3 accumulation loop. The forced unroll
bloats the hot scalar helper enough to more than double the direct factored
median, while unrelated NTT rows stay neutral. Clang's current rolled loop is
the right local shape unless the representation or reduction schedule changes.


Native stage A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage STAGE_ITERS=90000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

Rejected forward-NTT/d12 encode fusion highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_noise_ntt_encode` | 1423.71 | 1468.73 | 0.9693x | 0.9702x |
| `mlkem_core_stage_keygen_noise_ntt` | 1561.10 | 1612.97 | 0.9678x | 0.9660x |
| `mlkem_core_stage_kpke_keygen_full` | 3402.51 | 3496.20 | 0.9732x | 0.9779x |
| `mlkem_core_stage_kpke_encrypt_cached` | 1870.25 | 1881.55 | 0.9940x | 0.9947x |
| `mlkem_core_stage_decrypt_ntt_accum_recover` | 747.58 | 754.98 | 0.9902x | 0.9900x |

Keep `ntt(shat)` and `byte_encode_d12_avx2()` as separate passes. The existing
byte encoder's contiguous reload is cheap enough that fusing it into the NTT
final stage is not a useful core optimization on the native build.

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

### Independent Core Optimization A/B (2026-07-02, NTT accumulation 32-bit GAMMA table)

A narrow `GAMMA` representation experiment was rejected. The candidate changed
`GAMMA[128]` from `uint16_t` to `uint32_t` so the K=3 accumulation helpers could
load a native 32-bit multiplier for `(c0_hi % Q) * GAMMA[i]` instead of loading
16 bits and zero-extending. Native and AVX2-only `make test` passed, but the
larger table and changed load shape regressed the direct NTT accumulation
helpers.

AVX2-only NTT A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=ntt NTT_ITERS=200000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected 32-bit `GAMMA` table highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_ntt_mul_acc3` | 95.91 | 96.43 | 0.9946x | 0.9194x |
| `mlkem_ntt_mul_acc3_factored` | 96.26 | 96.45 | 0.9980x | 0.9226x |
| `mlkem_ntt_copy` | 198.93 | 198.86 | 1.0003x | 1.0005x |
| `mlkem_ntt_inplace` | 196.62 | 196.80 | 0.9991x | 1.0000x |

Keep `GAMMA` as `uint16_t`. The hot scalar loop already handles the narrow load
well, and the wider table does not reduce the critical arithmetic path. Future
accumulation work should change scheduling or representation more substantially
than table element width.

### Independent Core Optimization A/B (2026-07-02, NTT accumulation Karatsuba cross term)

A classic Karatsuba-style base-multiplication rewrite for `ntt_mul_acc3()` and
`ntt_mul_acc3_factored_gamma()` was rejected. The candidate reused the already
needed `x0*y0` and `x1*y1` products and computed each cross term as
`(x0 + x1) * (y0 + y1) - x0*y0 - x1*y1`, reducing the apparent per-pair
multiply count from twelve to nine. This follows the right family of classical
finite-field multiplication optimizations, and native plus AVX2-only `make test`
passed.

AVX2-only NTT A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=ntt NTT_ITERS=200000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected Karatsuba cross-term highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_ntt_mul_acc3` | 90.57 | 94.09 | 0.9626x | 0.9601x |
| `mlkem_ntt_mul_acc3_factored` | 90.86 | 96.66 | 0.9400x | 0.9393x |
| `mlkem_ntt_copy` | 199.01 | 199.01 | 1.0000x | 1.0006x |
| `mlkem_ntt_inplace` | 196.56 | 196.52 | 1.0002x | 1.0003x |

Keep the direct schoolbook cross products in the K=3 NTT accumulation helpers.
Here the saved integer multiplies are cheaper than the extra dependent
add/subtract chain introduced by Karatsuba, and clang's constant-modulo lowering
already schedules the current scalar loop well. A useful accumulation rewrite
still needs a different representation or reduction schedule, not this local
cross-term transform.

### Independent Core Optimization A/B (2026-07-02, NTT accumulation wide c0 reduction)

A reduction-scheduling follow-up for AVX2-only `ntt_mul_acc3()` and
`ntt_mul_acc3_factored_gamma()` was rejected. The candidate replaced the current
`c0_lo + (c0_hi % Q) * gamma` followed by a 32-bit `% Q` with a single wide
`uint64_t c0 = c0_lo + c0_hi * gamma` and one final `% Q`. This is algebraically
equivalent and passed native plus AVX2-only `make test`, but it puts a 64-bit
constant modulo directly on the scalar accumulation critical path.

AVX2-only NTT A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=ntt NTT_ITERS=200000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected wide-c0 highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_ntt_mul_acc3` | 88.42 | 500.19 | 0.1768x | 0.1754x |
| `mlkem_ntt_mul_acc3_factored` | 88.71 | 497.79 | 0.1782x | 0.1766x |
| `mlkem_ntt_copy` | 202.37 | 201.09 | 1.0064x | 1.0066x |
| `mlkem_ntt_inplace` | 194.78 | 194.19 | 1.0030x | 1.0018x |

Keep the existing two-step 32-bit reduction schedule. Reducing the apparent
modulo count is not useful if it promotes the hot `c0` path to a 64-bit modulo;
future accumulation work needs a representation change, not a wider scalar
reduction.

### Independent Core Optimization A/B (2026-07-02, NTT accumulation AVX2 product-vectorization)

An AVX2 product-vectorization experiment for K=3 NTT accumulation was rejected.
The first candidate replaced both `ntt_mul_acc3()` and
`ntt_mul_acc3_factored_gamma()` with an 8-base-pair AVX2 helper that loaded each
coefficient pair as one 32-bit lane, split low/high 16-bit coefficients, reduced
each individual product with the existing `Q^2`-range NTT reducer, then combined
terms with vector modular adds. This failed AVX2-only correctness because the
regular `ntt_mul_acc3()` path can consume lazy forward-NTT outputs during
encryption, while the per-product vector reducer is only safe when each input
coefficient is canonical.

The narrower correctness-safe candidate kept regular `ntt_mul_acc3()` scalar and
used the AVX2 helper only for `ntt_mul_acc3_factored_gamma()`, which is used by
keygen public accumulation after canonical forward NTTs. AVX2-only `make test`
passed, but direct NTT A/B showed the helper was much slower: SIMD parallelism
did not offset doing many more modular reductions than the scalar schedule.

AVX2-only correctness command for the narrowed candidate:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only NTT A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=ntt NTT_ITERS=200000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected AVX2 product-vectorization highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_ntt_mul_acc3_factored` | 91.09 | 175.20 | 0.5199x | 0.4975x |
| `mlkem_ntt_mul_acc3` | 90.87 | 94.71 | 0.9595x | 0.9708x |
| `mlkem_ntt_inplace` | 191.70 | 191.64 | 1.0003x | 1.0003x |
| `mlkem_ntt_inv` | 197.41 | 197.26 | 1.0008x | 1.0002x |

Keep the scalar K=3 accumulation schedule. The current scalar code wins because
it postpones reduction of product sums and lets clang lower constant `% Q`
efficiently. A future vector accumulation attempt must either operate in a
representation with cheap lane-wise reduction, or preserve a lazy/reduced range
that avoids per-product modular reduction.


### Independent Core Optimization Diagnostic (2026-07-02, Montgomery-domain NTT accumulation)

A bench-only Montgomery-domain feasibility check for the K=3 NTT accumulation
helper was rejected. The candidate preconverted the six input polynomials and
`GAMMA` table to `R = 2^16 mod Q` Montgomery form, then measured only the core
base multiplication/accumulation loop. This is the best-case version for a
future full Montgomery/Harvey redesign because the timed path does not include
input conversion. A second metric also converted the result back to the current
canonical representation to bound the compatibility cost.

The helper uses `qinv = -Q^-1 mod 2^16 = 3327` and `R^2 mod Q = 1353`, and the
`bench_ntt` validation checks the converted result against the current
`ntt_mul_acc3()` output before timing.

AVX2-only direct diagnostic command:

```bash
make bench-ntt CC=clang AVX2_BACKEND=core   ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
for i in $(seq 1 13); do
  taskset -c 0 ./bench_nttc 200000 |     rg "mlkem_ntt_mul_acc3(_factored|_mont_pre|_mont_pre_to_canon)?_ns_per_op"
done
```

Rejected Montgomery-domain accumulation highlights:

| Metric | Avg ns/op | Median ns/op | Avg speed vs current | Median speed vs current |
|---|---:|---:|---:|---:|
| `mlkem_ntt_mul_acc3` | 87.85 | 87.21 | 1.0000x | 1.0000x |
| `mlkem_ntt_mul_acc3_factored` | 88.14 | 87.35 | 0.9967x | 0.9984x |
| `mlkem_ntt_mul_acc3_mont_pre` | 109.67 | 109.49 | 0.8010x | 0.7965x |
| `mlkem_ntt_mul_acc3_mont_pre_to_canon` | 131.52 | 131.15 | 0.6680x | 0.6650x |

Do not productionize this local Montgomery accumulation shape. Even with
preconverted inputs and Montgomery output left in place, it needs too many
Montgomery reductions on the hot pair loop and loses about 20% against clang's
current constant-modulo lowering. A future Montgomery/Harvey attempt would need
to redesign the surrounding NTT representation and butterfly schedule, not only
swap the final K=3 base multiplication helper.

### Latest Core Optimization A/B (2026-07-02, AVX2 forward NTT lazy final l1)

The AVX2-only forward NTT tail now uses a Harvey-style lazy final l1 butterfly:
for the final length-2 stage it stores `a + t` and `a + Q - t` in `[0, 2Q)` and
then canonicalizes the full polynomial once at the end. The public `ntt()`
contract stays unchanged because the output is still reduced to `[0, Q)` before
returning. Native AVX512BW builds are guarded back to the previous exact l1
butterfly after no-regression testing showed the AVX2-only path was the useful
target.

Correctness checks:

```bash
make clean CC=clang AVX2_BACKEND=core && make test CC=clang AVX2_BACKEND=core
make clean CC=clang AVX2_BACKEND=core && make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only NTT A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=ntt NTT_ITERS=200000   C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"   ./scripts/bench_core_ab.sh HEAD
```

Direct NTT highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_ntt_tail_avx2` | 97.70 | 93.85 | 1.0410x | 1.0405x |
| `mlkem_ntt_copy` | 201.94 | 196.68 | 1.0267x | 1.0291x |
| `mlkem_ntt_inplace` | 194.86 | 191.15 | 1.0194x | 1.0196x |
| `mlkem_ntt3_inplace` | 584.76 | 574.47 | 1.0179x | 1.0184x |

AVX2-only stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage,kem STAGE_ITERS=70000 KEM_ITERS=30000   C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"   ./scripts/bench_core_ab.sh HEAD
```

Stage/KEM highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_noise_ntt` | 1996.19 | 1981.42 | 1.0075x | 1.0095x |
| `mlkem_core_stage_encrypt_noise_ntt` | 785.54 | 777.49 | 1.0104x | 1.0074x |
| `mlkem_core_stage_decrypt_u_ntt` | 787.32 | 778.23 | 1.0117x | 1.0127x |
| `mlkem_core_stage_decrypt_ntt_accum_recover` | 881.85 | 873.55 | 1.0095x | 1.0090x |
| `mlkem_core_stage_kpke_decrypt_cached` | 922.73 | 914.30 | 1.0092x | 1.0093x |
| `mlkem_keygen_core` | 7713.48 | 7732.95 | 0.9975x | 1.0014x |
| `mlkem_roundtrip_core` | 22163.79 | 22397.41 | 0.9896x | 1.0028x |

Longer AVX2-only KEM confirmation with `RUNS=17`, `KEM_ITERS=50000` kept the
full-path median signal: `mlkem_keygen_core` `1.0034x`, `mlkem_encaps_core`
`1.0090x`, `mlkem_decaps_core` `0.9988x`, and `mlkem_roundtrip_core` `1.0115x`.
After guarding native AVX512BW back to the previous l1 butterfly, native KEM
no-regression with `RUNS=9`, `KEM_ITERS=30000` was positive on all core medians:
`mlkem_keygen_core` `1.0027x`, `mlkem_encaps_core` `1.0024x`,
`mlkem_decaps_core` `1.0034x`, and `mlkem_roundtrip_core` `1.0027x`.

This is a small but real classical NTT optimization: it removes per-vector
conditional add/sub reductions from the final butterfly, pays one contiguous
canonicalization pass, and keeps all external encoders and NTT-domain consumers
on the existing canonical representation.


### Independent Core Optimization Diagnostic (2026-07-03, AVX2 forward tail-l2 block load)

A bench-only diagnostic tested the same block-load idea that helped inverse-head
`l2`, but on the AVX2 forward NTT tail `l2` level. The candidate loads each
16-coefficient block as two contiguous 128-bit halves, forms
`a=[0..3,8..11]` and `b=[4..7,12..15]` with 64-bit unpacks, then writes the
`sum,diff` output with two contiguous 128-bit stores. The diagnostic validates
the block-load sequence against the existing tail before timing.

Direct AVX2-only bench command:

```bash
make bench-ntt CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
for i in $(seq 1 9); do
  taskset -c 0 ./bench_nttc 200000 | \
    awk -F= -v run="$i" '/mlkem_ntt_(copy|inplace|tail_avx2|tail_avx2_l2|tail_avx2_l2_block|tail_avx2_l2_block_lazy_l1_canon|tail_avx2_lazy_l1_canon)_ns_per_op=/{print run, $1, $2}'
done
```

Direct diagnostic results:

| Metric | Existing avg ns/op | Existing median ns/op | Block avg ns/op | Block median ns/op |
|---|---:|---:|---:|---:|
| Tail `l2` only | 29.00 | 29.00 | 28.65 | 28.64 |
| Tail `l3 + l2 + lazy l1 + canon` | 94.68 | 94.66 | 94.27 | 94.25 |

The direct `l2` row is about `1.0126x` faster by median, and the full-tail-like
bench-only row is about `1.0044x` faster by median.

Production A/B was still rejected. Temporarily routing production
`ntt_tail_avx2()` and `ntt_tail_lazy_mul_input_avx2()` through the block-load
`l2` helper produced only a tiny direct NTT improvement, and KEM confirmation did
not hold.

Production A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=ntt,stage,kem NTT_ITERS=200000 \
  STAGE_ITERS=60000 KEM_ITERS=24000 C_COMPILER=clang PIN_CPU=0 \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" ./scripts/bench_core_ab.sh HEAD
```

Production A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_ntt_tail_avx2` | 93.67 | 93.40 | 1.0029x | 1.0020x |
| `mlkem_ntt_copy` | 195.48 | 194.94 | 1.0028x | 1.0028x |
| `mlkem_ntt_inplace` | 190.99 | 190.68 | 1.0016x | 1.0018x |
| `mlkem_core_stage_keygen_noise_ntt_only` | 1557.00 | 1552.45 | 1.0029x | 1.0015x |
| `mlkem_core_stage_encrypt_noise_ntt` | 787.62 | 787.68 | 0.9999x | 0.9999x |
| `mlkem_core_stage_decrypt_u_ntt_tail` | 491.29 | 492.11 | 0.9983x | 0.9984x |
| `mlkem_keygen_core` | 6882.25 | 6903.47 | 0.9969x | 1.0006x |
| `mlkem_encaps_core` | 6977.26 | 7243.56 | 0.9632x | 0.9984x |
| `mlkem_decaps_core` | 5967.96 | 6004.25 | 0.9940x | 0.9953x |
| `mlkem_roundtrip_core` | 19995.61 | 20348.06 | 0.9827x | 0.9817x |

Decision: reject the production forward-tail `l2` block-load helper. The direct
NTT win is real but too small, and it does not survive integrated KEM
confirmation. Keep the diagnostic rows only. Future forward-tail work should not
mirror the inverse-head local load/store rewrites blindly; it needs a
representation or scheduling change that remains positive in keygen, decrypt, and
roundtrip core rows.

### Independent Core Optimization Diagnostic (2026-07-02, AVX2 NTT tail inline boundary)

A small AVX2-only function-boundary experiment was rejected. The candidate changed
only `ntt_tail_avx2()` and `ntt_tail_lazy_mul_input_avx2()` from plain `static`
functions to `MLKEM_ALWAYS_INLINE`. This mirrors the successful keygen
matrix/noise boundary experiment, but here it expands the already-large forward
NTT tail into more call sites and risks I-cache pressure.

Correctness passed before benchmarking:

```bash
make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=ntt,stage,kem NTT_ITERS=200000 STAGE_ITERS=70000 KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Direct NTT highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_ntt_tail_avx2` | 94.12 | 93.79 | 1.0035x | 1.0035x |
| `mlkem_ntt_inplace` | 191.87 | 191.99 | 0.9994x | 0.9995x |
| `mlkem_ntt3_inplace` | 576.01 | 575.62 | 1.0007x | 1.0008x |
| `mlkem_ntt_copy_lazy_l1_canon` | 199.95 | 197.16 | 1.0141x | 1.0143x |

Integrated stage/KEM highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_noise_ntt` | 1993.87 | 1993.17 | 1.0004x | 1.0004x |
| `mlkem_core_stage_decrypt_u_ntt` | 787.10 | 792.48 | 0.9932x | 1.0004x |
| `mlkem_core_stage_kpke_encrypt_cached` | 2439.66 | 2424.71 | 1.0062x | 1.0054x |
| `mlkem_keygen_core` | 6931.99 | 6934.96 | 0.9996x | 0.9998x |
| `mlkem_encaps_core` | 6959.81 | 7047.07 | 0.9876x | 0.9886x |
| `mlkem_roundtrip_core` | 20135.87 | 20181.52 | 0.9977x | 0.9997x |

Decision: keep the AVX2 forward NTT tail out-of-line. The direct tail row gains
only about 0.35%, while full encapsulation loses about 1.1% median. This suggests
that the next useful NTT work needs a real arithmetic or layout change, not only
forcing inline expansion of the current tail loops.

### Independent Core Optimization Diagnostic (2026-07-02, AVX2 inverse NTT lazy final add)

A follow-up inverse-NTT lazy-final experiment was rejected. The bench-only
candidate kept the existing inverse final butterfly and scale arithmetic, but
stored the final `scaled + add` values in `[0, 2Q)` for `ntt_inv_add()` and in
`[0, 3Q)` for `ntt_inv_add2()`, then canonicalized the full polynomial once or
twice at the end. A matching `ntt_inv_sub_from()` diagnostic was also measured,
but it was neutral.

The direct NTT microbench looked attractive and `bench_ntt` validation checked
all lazy-final outputs against the existing exact helpers:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=ntt NTT_ITERS=200000   C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"   ./scripts/bench_core_ab.sh HEAD
```

Direct inverse NTT highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_ntt_inv_add` | 199.80 | 197.43 | 1.0120x | 1.0115x |
| `mlkem_ntt_inv_add2` | 210.96 | 205.26 | 1.0277x | 1.0273x |
| `mlkem_ntt_inv_sub_from` | 200.02 | 199.92 | 1.0005x | 1.0008x |

However, productionizing `ntt_inv_add()` and `ntt_inv_add2()` did not survive the
full-path gate:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage,kem STAGE_ITERS=70000 KEM_ITERS=30000   C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"   ./scripts/bench_core_ab.sh HEAD
```

Rejected stage/KEM highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_encrypt_inv_add_u_only` | 794.64 | 780.26 | 1.0184x | 1.0185x |
| `mlkem_core_stage_encrypt_accum_inv_v` | 467.11 | 474.15 | 0.9852x | 0.9856x |
| `mlkem_core_stage_kpke_encrypt_cached` | 2447.92 | 2444.21 | 1.0015x | 1.0016x |
| `mlkem_keygen_core` | 7585.66 | 8004.18 | 0.9477x | 0.9995x |
| `mlkem_roundtrip_core` | 22826.71 | 22735.35 | 1.0040x | 0.9818x |

Keep inverse final add/sub paths exact for now. Unlike the accepted forward NTT
final-l1 change, this inverse add rewrite perturbs integrated encryption and
roundtrip behavior enough that the direct helper win is not a reliable core
optimization.

### Latest Core Optimization A/B (2026-07-02, AVX2 internal lazy NTT multiply inputs)

The AVX2-only encryption and decryption paths now use an internal forward NTT
variant for values that immediately feed `ntt_mul_acc3()`: encryption `rhat[]`
and decryption `u[]`. The helper leaves the final l1 butterfly in `[0, 2Q)` and
skips the public `ntt()` canonicalization pass. This is safe only for these
NTT-domain multiplication inputs because `ntt_mul_acc3()` reduces products
modulo `Q`; public `ntt()` output, secret-key encoding, public-key encoding, and
add-then-encode paths still use canonical `[0, Q)` coefficients.

Correctness checks:

```bash
make clean CC=clang AVX2_BACKEND=core && make test CC=clang AVX2_BACKEND=core
make clean CC=clang AVX2_BACKEND=core && make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage,kem STAGE_ITERS=70000 KEM_ITERS=30000   C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"   ./scripts/bench_core_ab.sh HEAD
```

Stage/KEM highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_kpke_encrypt_cached` | 2448.57 | 2417.18 | 1.0130x | 1.0091x |
| `mlkem_core_stage_kpke_decrypt_cached` | 917.03 | 902.49 | 1.0161x | 1.0150x |
| `mlkem_core_stage_decrypt_ntt_accum_recover` | 878.39 | 873.50 | 1.0056x | 1.0019x |
| `mlkem_encaps` | 2716.10 | 2683.13 | 1.0123x | 1.0091x |
| `mlkem_decaps` | 3663.61 | 3631.23 | 1.0089x | 1.0070x |
| `mlkem_roundtrip_core` | 22369.07 | 22345.19 | 1.0011x | 1.0041x |

Longer AVX2-only KEM confirmation with `RUNS=17`, `KEM_ITERS=50000` kept the
full-path signal: `mlkem_encaps` median `1.0082x`, `mlkem_decaps` `1.0088x`,
`mlkem_encaps_core` `1.0008x`, `mlkem_decaps_core` `1.0007x`, and
`mlkem_roundtrip_core` `1.0387x`. Native `-march=native` KEM no-regression with
`RUNS=9`, `KEM_ITERS=30000` was also positive on all core medians:
`mlkem_keygen_core` `1.0009x`, `mlkem_encaps_core` `1.0006x`,
`mlkem_decaps_core` `1.0010x`, and `mlkem_roundtrip_core` `1.0034x`.

This extends the accepted forward-l1 lazy reduction in a restricted way: keep
external NTT results canonical, but skip the final canonicalization pass when
the next operation is a modular NTT-domain multiplication that already tolerates
representatives congruent modulo `Q`.

### Independent Core Optimization Diagnostic (2026-07-03, AVX2 rhat NTT noise-helper schedule)

An AVX2-only schedule follow-up to the accepted internal lazy NTT multiply-input
path was rejected. The candidate moved the three `rhat[]`
`ntt_lazy_mul_input_avx2()` calls out of
`kpke_encrypt_prepared_public_with_noise_avx2()` and into
`mlkem_encrypt_prf_cbd_eta2_32_sample_tail_avx2()` after the tail continuation
was parsed. Both production call sites of the prepared-noise encrypt path use
that helper, so correctness was preserved; the intended gain was to keep the
noise-generation boundary more self-contained and remove the later rhat NTT loop
from the prepared encrypt body.

Correctness passed both gates:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
make clean CC=clang AVX2_BACKEND=core && make test CC=clang AVX2_BACKEND=core
```

AVX2-only stage/KEM A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage,kem STAGE_ITERS=70000 KEM_ITERS=24000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected rhat-schedule highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_kpke_encrypt_cached` | 2434.96 | 2437.19 | 0.9991x | 1.0007x |
| `mlkem_core_stage_kpke_encrypt_uncached` | 4907.65 | 4926.88 | 0.9961x | 0.9969x |
| `mlkem_core_stage_encrypt_noise` | 1402.25 | 1401.23 | 1.0007x | 1.0001x |
| `mlkem_core_stage_encrypt_noise_prf_cbd_tail_cosched` | 1119.34 | 1123.55 | 0.9962x | 0.9991x |
| `mlkem_decaps` | 3620.21 | 3641.32 | 0.9942x | 0.9943x |
| `mlkem_decaps_core` | 6032.77 | 6083.19 | 0.9917x | 0.9935x |
| `mlkem_encaps_core` | 7256.80 | 6957.85 | 1.0430x | 1.0002x |
| `mlkem_roundtrip_core` | 20322.68 | 20037.11 | 1.0143x | 1.0011x |

Reject this schedule move. The candidate did not improve the direct no-cache
encrypt row, regressed decapsulation core, and the positive `encaps_core` /
`roundtrip_core` averages were not supported by meaningful medians. Keep the
accepted lazy rhat NTT inside the prepared encrypt body; moving it into the
noise/tail helper changes code layout and benchmark semantics without a robust
full-path win.

### Independent Core Optimization Diagnostic (2026-07-02, AVX2 lazy keygen shat encode)

A keygen-only follow-up to the accepted internal lazy NTT multiply-input work was
rejected. The candidate left `shat[]` in the AVX2 lazy forward-NTT output range
for the subsequent `ntt_mul_acc3()` keygen accumulation, while a dedicated
`byte_encode_d12_reduce_avx2()` canonicalized only the secret-key d12 encoding.
`ehat[]` stayed canonical because it is added into `that[]` before public-key
encoding.

This differs from the earlier rejected forward-NTT/d12 pack fusion: it did not
pack inside the NTT tail and instead tried to reuse lazy `shat[]` for the core
multiply path. Correctness passed both gates:

```bash
make clean CC=clang AVX2_BACKEND=core && make test CC=clang AVX2_BACKEND=core
make clean CC=clang AVX2_BACKEND=core && make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage,kem STAGE_ITERS=70000 KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Stage/KEM highlights after removing the unnecessary d12 post-reduce mask:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_noise_ntt` | 1981.50 | 1973.19 | 1.0042x | 1.0042x |
| `mlkem_core_stage_keygen_noise_ntt_encode` | 1571.08 | 1563.61 | 1.0048x | 1.0048x |
| `mlkem_core_stage_keygen_noise_ntt_only` | 1528.69 | 1514.64 | 1.0093x | 1.0094x |
| `mlkem_core_stage_kpke_keygen_full` | 5508.69 | 5724.87 | 0.9622x | 1.0003x |
| `mlkem_keygen_core` | 7772.27 | 8054.87 | 0.9649x | 0.9987x |

Longer AVX2-only KEM confirmation made the rejection clearer:

```bash
RUNS=17 WARMUP_RUNS=2 SUITES=kem KEM_ITERS=50000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_keygen` | 8053.02 | 8379.29 | 0.9611x | 0.9934x |
| `mlkem_keygen_core` | 8041.51 | 8341.33 | 0.9641x | 0.9955x |
| `mlkem_roundtrip` | 14474.74 | 14811.83 | 0.9772x | 0.9921x |

The local NTT work was measurably faster, but the secret-key encode-time
conditional subtract and integrated keygen/code-layout effects erased the win.
Keep keygen `shat[]` canonical unless a future design removes the d12
canonicalization cost entirely or reworks the keygen accumulation/encoding order
more broadly.

A narrower keygen `ehat[]` lazy-NTT follow-up was rejected. The candidate kept
`shat[]` canonical for secret-key d12 encoding and keygen accumulation, but ran
AVX2-only `ehat[]` through `ntt_lazy_mul_input_avx2()`. The public output add
then used a two-subtract AVX2 add helper to canonicalize
`that_accum + lazy_ehat` before d12 public-key encoding. This targeted only the
error-vector NTT canonicalization pass, avoiding the rejected `shat[]` lazy encode
shape.

The idea is another Harvey-style lazy-reduction variant: defer the final
canonicalization until the next modular add that already has to scan the output.
Correctness passed both AVX2-only and native builds, but the full-path A/B did
not show a keygen win and introduced severe code-layout side effects in decaps
core rows. The direct keygen median was neutral, so the source change was not
kept.

Correctness commands:

```bash
git diff --check
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core
```

AVX2-only stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage,kem STAGE_ITERS=70000 KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected keygen `ehat` lazy-NTT highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_kpke_keygen_full` | 5390.13 | 5490.09 | 0.9818x | 0.9997x |
| `mlkem_core_stage_keygen_noise_ntt_only` | 1530.54 | 1530.69 | 0.9999x | 1.0000x |
| `mlkem_core_stage_keygen_accum_encode` | 485.75 | 486.43 | 0.9986x | 0.9996x |
| `mlkem_keygen_core` | 7576.80 | 7436.08 | 1.0189x | 0.9995x |
| `mlkem_decaps_core` | 6473.44 | 7054.74 | 0.9176x | 0.9289x |
| `mlkem_roundtrip` | 13980.55 | 13914.34 | 1.0048x | 0.9970x |

Keep keygen `ehat[]` canonical. Deferring this single canonicalization pass
moves work into the public-output add and changes code layout without producing a
robust keygen median. Future keygen lazy-reduction work needs a broader
accumulation/encoding redesign, not only moving `ehat`'s final reduction.

A signed-ETA2 input NTT experiment was also rejected. This was the ML-KEM analogue
of using a signed sparse representation: the candidate decoded AVX2-only keygen
ETA2 PRF/CBD outputs as small signed coefficients in `{-2..2}`, then used a
special `ntt_eta2_signed_avx2()` first forward-NTT stage that canonicalized back
to `[0, Q)` before the existing later NTT stages. The goal was to avoid the CBD
negative-lane canonicalization and make the first NTT multiplication consume tiny
signed inputs instead of `Q-1`/`Q-2` encodings.

Correctness passed, but the integrated keygen path regressed. The stage rows that
use precomputed canonical inputs cannot show this representation-boundary change,
so the acceptance signal was `kpke_keygen_full` plus KEM keygen medians.

Correctness command:

```bash
make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage/KEM A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage,kem STAGE_ITERS=60000 KEM_ITERS=20000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected signed-ETA2 input NTT highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_kpke_keygen_full` | 5336.62 | 5374.08 | 0.9930x | 0.9982x |
| `mlkem_core_stage_keygen_noise_prf_cbd` | 976.15 | 972.47 | 1.0038x | 1.0006x |
| `mlkem_core_stage_keygen_noise_ntt` | 1986.64 | 1986.63 | 1.0000x | 1.0000x |
| `mlkem_keygen_core` | 7627.55 | 7636.31 | 0.9989x | 0.9964x |
| `mlkem_encaps_core` | 7523.47 | 7490.17 | 1.0044x | 0.9985x |
| `mlkem_roundtrip_core` | 22536.77 | 21904.65 | 1.0289x | 1.0432x |

Do not pursue NAF-like signed ETA2 decoding as a narrow keygen-only change. The
canonicalization saved in CBD/first-stage arithmetic is too small, and the extra
helper/code-shape cost hurts the keygen rows that the change is supposed to
improve. A future signed-representation design would need to carry the form
through accumulation/encoding more broadly, not stop after the first NTT stage.

A narrower encrypt-side signed-`rhat` follow-up was also rejected. The candidate
kept the shared canonical PRF/CBD helper unchanged for stage setup, added a
production-only AVX2 helper that decoded only `rhat[0..2]` as signed ETA2
coefficients while keeping `e1[0]` canonical, and ran those three polynomials
through a signed first-stage `ntt_lazy_eta2_signed_avx2()` before the existing
lazy-tail multiply-input path. This targeted encapsulation only, where `rhat` is
consumed immediately by NTT-domain multiplication and does not need d12 encoding.

Correctness and stage validation passed, but the KEM gate rejected the change:
the mixed signed/canonical decode and extra branch/code shape did not improve
`kpke_encrypt_cached`, and `mlkem_encaps_core` regressed clearly.

Correctness commands:

```bash
make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
make bench-stages CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" && \
  taskset -c 0 ./bench_core_stagesc 1000
```

AVX2-only stage/KEM A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage,kem STAGE_ITERS=60000 KEM_ITERS=20000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected encrypt signed-`rhat` highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_encrypt_noise_prf_cbd` | 1172.29 | 1149.77 | 1.0196x | 1.0191x |
| `mlkem_core_stage_kpke_encrypt_cached` | 2421.17 | 2427.34 | 0.9975x | 1.0001x |
| `mlkem_core_stage_kpke_encrypt_uncached` | 6339.12 | 6067.90 | 1.0447x | 0.9961x |
| `mlkem_encaps_core` | 7491.60 | 7769.63 | 0.9642x | 0.9538x |
| `mlkem_encaps` | 2684.39 | 2688.60 | 0.9984x | 0.9983x |
| `mlkem_roundtrip_core` | 21728.41 | 21913.47 | 0.9916x | 1.0084x |

Keep the existing canonical PRF/CBD output plus `ntt_lazy_mul_input_avx2()` for
encapsulation. The local signed-representation idea does not survive the full
KEM path unless a broader redesign removes the mixed decode and branch overhead.

Design note on secp256k1-style endomorphism/NAF applicability: GLV-style
endomorphism speedups do not translate directly to ML-KEM. They split elliptic
curve scalar multiplication by exploiting a cheap group endomorphism, while the
hot ML-KEM work is SHAKE-based dense public-matrix generation, NTT/inverse-NTT,
and dense polynomial products. The seed-derived `A` matrix gives no fixed
low-cost symmetry that can halve the core polynomial work without changing the
specified distribution or wire format.

NAF is more relevant only as a representation lesson. The useful analogue is
not sparse scalar multiplication, but keeping coefficients in a signed or lazy
centered range so reduction/canonicalization can be delayed. The rejected
signed-ETA2 and signed-`rhat` experiments show that applying this only at the
PRF/CBD-to-NTT boundary is too narrow: the saved canonicalization is smaller
than the mixed-representation and code-shape cost. A serious NAF-inspired
redesign must carry the representation through NTT, K=3 accumulation, inverse
NTT, and only canonicalize at encode/compress boundaries.

Practical next target from this decision: do not add another local signed-input
helper. The next representation experiment should define exact value ranges at
each boundary and prove that `ntt_mul_acc3()`, `ntt_inv_add*_inplace()`, and
compress/encode can consume those ranges without reintroducing the same
normalization work one stage later.

Follow-up target triage after the endomorphism/NAF review: the useful ideas from
secp256k1-style GLV/NAF and lattice papers such as H-NTT (arXiv:2109.02893) or
polyphase decomposition (KyberMat, arXiv:2310.04618) are representation-level
ideas, not local helper substitutions. On the current AVX2-only core, the
largest measured stage costs still come from SHAKE-based public-matrix
generation and whole forward/inverse NTT pipelines. This makes another local
signed-digit, gamma-table, or parser-bookkeeping change the wrong abstraction
level.

AVX2-only current-stage snapshot command:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make bench-stages CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
taskset -c 0 ./bench_core_stagesc 30000 | rg "ns_per_op" | \
  sort -t= -k2 -nr | head -n 50
```

Current largest AVX2-only stage rows after the later sampler/NTT/Keccak
micro-experiments and rejections:

| Metric | ns/op |
|---|---:|
| `mlkem_core_stage_kpke_encrypt_uncached` | 4896.52 |
| `mlkem_core_stage_kpke_keygen_full` | 4798.01 |
| `mlkem_core_stage_kpke_prepare_public_no_cache` | 4154.39 |
| `mlkem_core_stage_sample_matrix` | 2797.19 |
| `mlkem_core_stage_sample_ntt4_scalar4_raw` | 2737.59 |
| `mlkem_core_stage_kpke_encrypt_cached` | 2431.79 |
| `mlkem_core_stage_keygen_noise_ntt` | 1994.89 |
| `mlkem_core_stage_keygen_noise_ntt_encode` | 1585.88 |
| `mlkem_core_stage_keygen_noise_ntt_only` | 1543.86 |
| `mlkem_core_stage_encrypt_noise` | 1401.14 |
| `mlkem_core_stage_encrypt_noise_prf_cbd_tail_separate` | 1330.60 |
| `mlkem_core_stage_encrypt_accum_inv` | 1322.89 |
| `mlkem_core_stage_sample_matrix_x4_batch1` | 1180.13 |
| `mlkem_core_stage_encrypt_noise_prf_cbd` | 1174.51 |
| `mlkem_core_stage_encrypt_noise_prf_cbd_tail_cosched` | 1116.76 |
| `mlkem_core_stage_sample_matrix_x4_batch0` | 1113.14 |
| `mlkem_core_stage_encrypt_accum_inv_u` | 1039.39 |
| `mlkem_core_stage_sample_ntt4_common3_step` | 991.95 |
| `mlkem_core_stage_keygen_noise_prf_cbd` | 974.44 |
| `mlkem_core_stage_keygen_noise_ntt_head_only` | 962.16 |
| `mlkem_core_stage_keygen_noise_ntt_tail_only` | 957.27 |
| `mlkem_core_stage_sample_ntt4_full_raw` | 930.44 |
| `mlkem_core_stage_sample_ntt4_keccak_store3` | 874.28 |
| `mlkem_core_stage_sample_ntt4_parse_504` | 117.55 |

Current AVX2-only forward-NTT micro split from the same HEAD:

| Metric | ns/op |
|---|---:|
| `mlkem_ntt_copy` | 196.69 |
| `mlkem_ntt_inplace` | 190.31 |
| `mlkem_ntt_head_l7_l4` | 97.61 |
| `mlkem_ntt_tail_avx2` | 94.10 |
| `mlkem_ntt_tail_avx2_l3` | 26.94 |
| `mlkem_ntt_tail_avx2_l2` | 29.28 |
| `mlkem_ntt_tail_avx2_l1` | 41.99 |
| `mlkem_ntt_tail_avx2_l1_lazy` | 34.77 |

Use this as the next design filter. H-NTT/polyphase-style work would need a
full NTT and multiplication representation redesign before it can fairly
compete with the current scalar K=3 accumulation and AVX2 tail schedule. A
NAF-inspired signed/lazy representation should likewise span CBD, forward NTT,
K=3 accumulation, inverse NTT, and encode/compress boundaries at once. The
shorter-term implementation target remains the common `sample_ntt4()` three-rate
Keccak/state layout: the latest snapshot puts `sample_ntt4_keccak_store3` at
about 874 ns while `sample_ntt4_parse_504` is about 118 ns, so parser
bookkeeping and narrow signed/lazy coefficient rewrites are not the next likely
source of a robust KEM-level win. On the NTT side, head and tail are almost
balanced; another local `l1`, inline-boundary, or table-width tweak is unlikely
to move full KEM unless it is part of a representation change that carries
through the multiply and encode/compress boundaries.

Research-source mapping update (2026-07-03): libsecp256k1 documents the ECC-side
patterns that motivated the review--wNAF point multiplicands, a larger window
and precomputed multiples for the generator, Shamir's trick, and secp256k1's
endomorphism to split one public-key multiplicand
(`https://github.com/bitcoin-core/secp256k1`). These are scalar-multiplication
and group-addition optimizations, so they do not directly map onto ML-KEM's
SHAKE/NTT/matrix-vector pipeline. The useful translation remains: fill SIMD
lanes with independent work, avoid data-dependent secret control flow, and move
normalization only when the next consumer's range contract proves it safe.

For lattice-specific redesigns, OSKR/OKAI's H-NTT work
(`https://arxiv.org/abs/2109.02893`) and KyberMat's NTT/polyphase decomposition
(`https://arxiv.org/abs/2310.04618`) point at representation-level NTT and
matrix-vector changes, not small local helper rewrites. Newer NTT accelerator
work such as @NTT (`https://arxiv.org/abs/2601.17806`) is mainly a hardware
constant/dataflow lesson: fixed parameters can justify design-time specialization,
but in this C/AVX2 core the comparable software specialization has already been
measured mostly around Keccak/store layout, NTT tail/head balance, and final
range contracts. A latest-source check also found redundant-arithmetic NTT
accelerator work (`https://arxiv.org/abs/2607.00621`) and ZKP NTT/MSM layout
work such as MORPH (`https://arxiv.org/abs/2604.17808`); both reinforce the same
software rule here: lazy/redundant representations must remove work across a
whole dataflow and must not pay the win back as layout or boundary conversion.
The next valid implementation experiment should therefore prototype a full
boundary contract--for example CBD/sampler output range -> NTT range -> K=3
multiply range -> inverse/add range -> encode/compress range--or else stay in
the measured Keccak lane-filling/co-scheduling space.

### Independent Core Optimization A/B (2026-07-03, AVX2 keygen tail 3-rate parse)

The AVX2 keygen matrix/noise co-schedule now accumulates the `(2,2)` public-matrix
tail stream's first three SHAKE128 rates and calls the 504-byte rejection parser
once, instead of parsing the first co-scheduled rate and then parsing each scalar
continuation rate separately. Keccak work and outputs are unchanged; the change only
removes hot parser entry/bookkeeping from the keygen-only tail/noise helper.

The same parser-schedule idea was not applied to the encryption tail/noise helper.
A full 3-rate accumulation variant improved the direct `tail_cosched` diagnostic but
regressed `kpke_encrypt_uncached`, while a smaller 1+2-rate variant regressed the
direct `tail_cosched` row. Keeping the change keygen-only preserved the keygen win
without perturbing uncached encryption.

Correctness passed the AVX2-only gate:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Stage highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_matrix_noise_current` | 3030.57 | 3027.48 | 1.0010x | 1.0042x |
| `mlkem_core_stage_keygen_matrix_noise_tail_first` | 3041.25 | 3026.01 | 1.0050x | 1.0046x |
| `mlkem_core_stage_keygen_matrix_noise_tail_last` | 3040.07 | 3024.20 | 1.0052x | 1.0053x |
| `mlkem_core_stage_kpke_keygen_full` | 4786.72 | 4763.50 | 1.0049x | 1.0025x |
| `mlkem_core_stage_kpke_encrypt_uncached` | 4845.19 | 4831.00 | 1.0029x | 1.0008x |

AVX2-only KEM confirmation:

```bash
RUNS=17 WARMUP_RUNS=4 SUITES=kem KEM_ITERS=50000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

KEM highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_keygen` | 6914.18 | 6875.29 | 1.0057x | 1.0042x |
| `mlkem_keygen_core` | 6903.68 | 6850.36 | 1.0078x | 1.0038x |
| `mlkem_encaps_core` | 6925.61 | 7030.15 | 0.9851x | 1.0052x |
| `mlkem_decaps_core` | 6018.07 | 5969.93 | 1.0081x | 1.0026x |
| `mlkem_roundtrip_core` | 19984.05 | 20021.69 | 0.9981x | 1.0015x |

Decision: accept the keygen-only parser schedule. The direct keygen matrix/noise
rows and KEM keygen medians move in the same direction, while the broader KEM
median rows do not show a meaningful regression. This is a narrow dataflow win:
use 3-rate parsing where keygen already owns the single tail continuation, but keep
encryption on the existing rolling parse because its caller is more code-shape
sensitive.

### Independent Core Optimization Diagnostic (2026-07-03, native AVX512 keygen tail 3-rate parse)

A native AVX512 follow-up tried to generalize the accepted AVX2 keygen tail parser
schedule to `mlkem_keygen_prf_cbd_eta2_32_sample_tail_avx512()`. The candidate
extracted the lane-6 matrix-tail state after the `keccakf8()` PRF/CBD block into a
scalar `uint64_t tail_state[25]`, accumulated the next two SHAKE128 rates with
scalar `keccakf()`, and parsed one 504-byte stream instead of parsing the initial
168-byte block and continuing through a one-live-lane `keccakf4()` state.

Correctness passed both native and AVX2-only gates before benchmarking:

```bash
make clean CC=clang AVX2_BACKEND=core && make test CC=clang AVX2_BACKEND=core
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

Native stage A/B command, using `2dc014f` as the baseline after the benchmark
harness compile fix:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

Stage highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_kpke_keygen_full` | 3401.38 | 3475.46 | 0.9787x | 0.9980x |
| `mlkem_core_stage_kpke_prepare_public_no_cache` | 2827.20 | 2855.39 | 0.9901x | 0.9851x |
| `mlkem_core_stage_sample_matrix` | 1895.74 | 1900.43 | 0.9975x | 0.9967x |
| `mlkem_core_stage_keygen_noise_ntt` | 1563.67 | 1564.90 | 0.9992x | 0.9991x |
| `mlkem_core_stage_keygen_noise_prf_cbd` | 696.37 | 695.65 | 1.0010x | 1.0028x |
| `mlkem_core_stage_kpke_encrypt_uncached` | 3600.65 | 3602.29 | 0.9995x | 1.0007x |

Decision: reject the AVX512 generalization. The local PRF/CBD-side movement is
small, while native `kpke_keygen_full`, public preparation, and full
`sample_matrix` medians move negative. Keep the AVX2-only 3-rate parse where it
has direct keygen and KEM evidence, but do not assume the same parser schedule is
profitable in the AVX512 `keccakf8()` shape without a stronger native integrated
win.

Current HEAD spot-check after the tile2x3 accumulator diagnostic, AVX2-only,
`./bench_core_stagesc 12000`, keeps the same priority order: `sample_matrix`
about 2.7 us, `keygen_noise_ntt` about 1.94 us, `encrypt_noise` about 1.37 us,
`encrypt_accum_inv` about 1.31 us, and ciphertext compression about 51 ns. That
rules out d10/d4 packing and parser bookkeeping as primary next targets.

Current HEAD refresh after the inverse fixed-zeta rejection, AVX2-only,
`taskset -c 0 ./bench_core_stagesc 30000`, keeps the same design direction but
updates the local priority order:

| Metric | ns/op | Readout |
|---|---:|---|
| `mlkem_core_stage_sample_matrix` | 2787.58 | largest vendor-free public-work target |
| `mlkem_core_stage_kpke_encrypt_cached` | 2403.52 | integrated encryption target after public-key cache |
| `mlkem_core_stage_keygen_noise_ntt` | 1996.16 | six CBD-derived forward NTTs still dominate keygen noise |
| `mlkem_core_stage_encrypt_noise` | 1404.98 | PRF/CBD plus `r` forward NTT |
| `mlkem_core_stage_encrypt_accum_inv` | 1324.06 | K=3 accumulation plus inverse-add, mostly already fused |
| `mlkem_core_stage_sample_ntt4_full_raw` | 934.32 | x4 sampler raw lower-level row |
| `mlkem_core_stage_sample_ntt4_keccak_store3` | 869.42 | three common sampler Keccak/store blocks dominate parser work |
| `mlkem_core_stage_decrypt_ntt_accum_recover` | 893.85 | decrypt NTT/accum/inverse/recover bundle |
| `mlkem_core_stage_encrypt_inv_add_u_only` | 788.11 | inverse-add target after many final-loop rejections |
| `mlkem_core_stage_sample_ntt4_parse_504` | 118.31 | parser bookkeeping is not the primary sampler target |
| `mlkem_core_stage_ciphertext_compress_encode` | 50.58 | d10/d4 packing is too small for the next target |

This refresh closes several tempting short loops. Do not reopen scalar final-zeta
selection, `keccakf4_mem()` scratch/call-boundary/source-shape tweaks,
`sample_ntt4_store_rate()` reshaping, PRF/CBD x2/x3 composition, scalar-tail
rotation, or drop-in AVX2 `ntt_mul_acc3()` vectorization without new evidence;
those have direct rejection records. The follow-up direct `sample_ntt4()`
Keccak-state-to-parser lower bound, final-inverse-to-d10 boundary fusion, keygen
lazy-`ehat` add boundary, partial-lane full-matrix regroupings (`x3x3x3` and
`x4x3x2`), and direct state-lane validity-mask extraction were also measured and
rejected for production. The next implementation should therefore be either a
true vector compaction path from Keccak state lanes that avoids per-candidate
mask/control overhead, not scalar state parsing, or a broader representation
prototype that carries lazy/signed ranges across CBD or sampler output, forward
NTT, K=3 multiplication, inverse add/sub, and encode/compress boundaries
together. Anything narrower is likely to reproduce the recent noise-level wins
and KEM regressions.

### Independent Core Optimization Diagnostic (2026-07-03, AVX2 lazy NTT boundary)

A bench-only diagnostic now measures the existing production AVX2 lazy
multiply-input forward NTT against the canonical `ntt()` path on the same
three-polynomial encryption/decryption inputs. This does not change production
code; it makes the NAF/signed-lazy design rule measurable: delaying the final
forward-NTT reduction is useful when the next consumer is `ntt_mul_acc3()`, while
prior experiments showed that moving the same normalization to encode/compress
boundaries tends to pay the cost back immediately.

AVX2-only command:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make bench-stages CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
taskset -c 0 ./bench_core_stagesc 30000 | \
  rg "mlkem_core_stage_(encrypt_noise_ntt|decrypt_u_ntt)(_lazy)?_ns_per_op"
```

| Metric | Canonical ns/op | Lazy ns/op | Speedup |
|---|---:|---:|---:|
| `mlkem_core_stage_encrypt_noise_ntt` | 792.93 | 775.06 | 1.0231x |
| `mlkem_core_stage_decrypt_u_ntt` | 788.37 | 775.22 | 1.0170x |

Decision: keep the current production lazy multiply-input NTT for values that
flow directly into `ntt_mul_acc3()`. Do not generalize this into another local
signed/lazy helper at encode or compress boundaries; those boundaries still need
a broader representation redesign to avoid reintroducing the same
canonicalization work one stage later.

### Independent Core Optimization Diagnostic (2026-07-03, AVX2 decrypt lazy combined rows)

A bench-only follow-up added decrypt-side combined rows that use the same lazy
`u` forward NTT boundary as AVX2 production decrypt before `ntt_mul_acc3()`. The
older combined diagnostics remain useful as canonical-reference rows, but they
call `ntt()` and therefore slightly overstate the production NTT/accum/recover
bundle. The new rows are validated by comparing lazy-NTT accumulation output
against the existing canonical `stage_w_ntt` fixture before timing.

AVX2-only command:

```bash
make bench-stages CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
for i in $(seq 1 7); do
  taskset -c 0 ./bench_core_stagesc 30000 | \
    awk -F= -v run="$i" '/mlkem_core_stage_decrypt_(u_ntt|u_ntt_lazy|accum_only|ntt_accum_only|lazy_ntt_accum_only|ntt_accum_recover|lazy_ntt_accum_recover|recover_message)_ns_per_op=|mlkem_core_stage_kpke_decrypt_cached_ns_per_op=/{print run, $1, $2}'
done
```

AVX2-only results:

| Metric pair | Canonical avg ns/op | Lazy avg ns/op | Canonical median ns/op | Lazy median ns/op | Median speedup |
|---|---:|---:|---:|---:|---:|
| `decrypt_u_ntt` vs `decrypt_u_ntt_lazy` | 787.15 | 773.00 | 786.56 | 772.78 | 1.0178x |
| `decrypt_ntt_accum_only` vs `decrypt_lazy_ntt_accum_only` | 860.84 | 860.45 | 860.35 | 859.56 | 1.0009x |
| `decrypt_ntt_accum_recover` vs `decrypt_lazy_ntt_accum_recover` | 889.02 | 873.73 | 888.05 | 872.50 | 1.0178x |

Decision: keep the new lazy combined rows as production-aligned diagnostics.
This is not a new production optimization; production already used the lazy
`u` NTT. It fixes target selection: future decrypt work should compare against
`decrypt_lazy_ntt_accum_recover`, not only the older canonical
`decrypt_ntt_accum_recover`. The remaining decrypt-side headroom is now mostly
the K=3 accumulation plus inverse/sub boundary, because the lazy NTT win is
already present in production and disappears inside the accumulation-only row.

### Independent Core Optimization Diagnostic (2026-07-03, AVX2 decrypt inverse stage split)

A bench-only diagnostic split the AVX2 decrypt inverse/sub path into production
inverse-head levels, tail levels through `l6`, and the production-style final
`l7` butterfly plus inverse scale/subtraction from precomputed `l6` output. A
`decrypt_inv_copy_only` row is included because these per-stage probes all copy a
polynomial into scratch and checksum it; the adjusted column below subtracts the
copy/checksum median to show the approximate per-stage work. The final helper is
validated against `ntt_inv_sub_from_inplace()` before timing.

AVX2-only command:

```bash
make bench-stages CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
for i in $(seq 1 7); do
  taskset -c 0 ./bench_core_stagesc 30000 | \
    awk -F= -v run="$i" '/mlkem_core_stage_decrypt_inv_(copy_only|sub_from|butterflies|head|head_l1|head_l2|head_l3|tail|tail_l4|tail_l5|tail_l6|final_sub_from|scale_sub_from)_ns_per_op=|mlkem_core_stage_decrypt_(accum_inv|lazy_ntt_accum_recover)_ns_per_op=|mlkem_core_stage_kpke_decrypt_cached_ns_per_op=/{print run, $1, $2}'
done
```

AVX2-only results:

| Metric | Avg ns/op | Median ns/op | Median minus copy-only |
|---|---:|---:|---:|
| `mlkem_core_stage_decrypt_inv_copy_only` | 184.04 | 183.63 | 0.00 |
| `mlkem_core_stage_decrypt_inv_sub_from` | 381.66 | 381.76 | 198.13 |
| `mlkem_core_stage_decrypt_inv_butterflies` | 359.88 | 359.97 | 176.34 |
| `mlkem_core_stage_decrypt_inv_head` | 274.88 | 275.17 | 91.54 |
| `mlkem_core_stage_decrypt_inv_tail` | 268.60 | 268.46 | 84.83 |
| `mlkem_core_stage_decrypt_inv_head_l1` | 223.98 | 224.04 | 40.41 |
| `mlkem_core_stage_decrypt_inv_head_l2` | 213.25 | 213.26 | 29.63 |
| `mlkem_core_stage_decrypt_inv_head_l3` | 208.04 | 208.02 | 24.39 |
| `mlkem_core_stage_decrypt_inv_tail_l4` | 205.98 | 205.85 | 22.22 |
| `mlkem_core_stage_decrypt_inv_tail_l5` | 205.62 | 205.41 | 21.78 |
| `mlkem_core_stage_decrypt_inv_tail_l6` | 204.79 | 204.81 | 21.18 |
| `mlkem_core_stage_decrypt_inv_final_sub_from` | 226.73 | 226.80 | 43.17 |
| `mlkem_core_stage_decrypt_accum_inv` | 460.34 | 460.36 | 276.73 |
| `mlkem_core_stage_decrypt_lazy_ntt_accum_recover` | 874.06 | 873.50 | 689.87 |

Decision: keep these rows as diagnostics and do not try another isolated tail
level rewrite. After removing copy/sink overhead, no single inverse tail stage
dominates; `l4`, `l5`, and `l6` are all about `21-22 ns`. The largest local
items are the production final butterfly/scale/subtraction boundary
(`~43 ns` adjusted) and head `l1` (`~40 ns` adjusted). A useful decrypt-side
optimization should therefore either change the final boundary together with
message recovery or redesign the whole inverse schedule/range contract, not only
replace one tail level.

### Independent Core Optimization A/B (2026-07-03, AVX2 final recover fusion)

The final-boundary follow-up is accepted for AVX2-only production decrypt. The
new `ntt_inv_sub_recover_from_inplace_avx2()` keeps the existing inverse-head and
`l4..l6` schedule, but replaces the final `l7` butterfly + inverse scale +
subtraction + `mlkem_recover_message()` sequence with a single final pass that
turns the 32-bit final-sub lanes directly into message bits. This avoids storing
the final `w` polynomial only to reload it in the recovery pass. AVX512 and
scalar builds keep their existing paths.

The bench-only lower-bound rows compare the old split boundary against the fused
final boundary with the same scratch-copy shape. The fused helper is validated
against the split `ntt_inv_sub_from_inplace()` plus `mlkem_recover_message()`
path before timing.

Direct AVX2-only command:

```bash
make bench-stages CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
for i in $(seq 1 7); do
  taskset -c 0 ./bench_core_stagesc 50000 | \
    awk -F= -v run="$i" '/mlkem_core_stage_decrypt_inv_final_sub_(from|recover_split|recover_fused)_ns_per_op=|mlkem_core_stage_decrypt_recover_message_ns_per_op=|mlkem_core_stage_decrypt_lazy_ntt_accum_recover_ns_per_op=|mlkem_core_stage_kpke_decrypt_cached_ns_per_op=/{print run, $1, $2}'
done
```

Direct final-boundary results:

| Metric | Avg ns/op | Median ns/op |
|---|---:|---:|
| `mlkem_core_stage_decrypt_inv_final_sub_recover_split` | 52.64 | 52.15 |
| `mlkem_core_stage_decrypt_inv_final_sub_recover_fused` | 48.11 | 48.10 |

Fused final-recover is `1.0941x` faster by average and `1.0842x` faster by
median, saving about `4.05 ns` at this local boundary.

Production A/B command against the previous HEAD:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage,kem STAGE_ITERS=60000 KEM_ITERS=24000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Production A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_decrypt_lazy_ntt_accum_recover` | 874.91 | 871.49 | 1.0039x | 1.0034x |
| `mlkem_core_stage_decrypt_ntt_accum_recover` | 892.75 | 885.55 | 1.0081x | 1.0072x |
| `mlkem_core_stage_kpke_decrypt_cached` | 911.81 | 905.33 | 1.0072x | 1.0075x |
| `mlkem_core_stage_kpke_decrypt_uncached` | 923.58 | 917.59 | 1.0065x | 1.0070x |
| `mlkem_decaps` | 3611.26 | 3600.75 | 1.0029x | 1.0016x |
| `mlkem_decaps_core` | 6055.96 | 6061.73 | 0.9990x | 1.0022x |

Decision: keep the production fusion. The direct boundary win is small but real,
and the decrypt stage rows move in the expected direction. Broad KEM rows are
near noise, but decapsulation median does not regress. The older
`decrypt_inv_final_sub_from` row includes a full-polynomial checksum and is no
longer the acceptance signal for this boundary; use the split/fused final-recover
rows and `kpke_decrypt_*` rows instead. The next decrypt-side target is no longer
message recovery itself, but either head `l1` or a wider inverse schedule/range
redesign that can also preserve the final-recover fusion.

### Independent Core Optimization A/B (2026-07-03, AVX2 inverse head-l1 block load)

The AVX2-only inverse head now uses a block-load/shuffle helper for the `l1`
level. The previous helper gathered four 2-coefficient `a` chunks and four
2-coefficient `b` chunks with 32-bit loads, then scattered four 32-bit stores for
each result half. The new helper loads each 16-coefficient block with two
contiguous 128-bit loads, uses byte shuffles to form the `a` and `b` vectors, and
uses two contiguous 128-bit stores for the interleaved `sum,t` output. Levels
`l2` and `l3` remain unchanged. AVX512BW builds are guarded back to the previous
helper shape.

This is deliberately narrower than the rejected inverse-head block-local
ordering experiment. It does not run `l1 -> l2 -> l3` inside each block; it keeps
the existing level-wise order and only changes the `l1` load/store shape.

The bench-only diagnostic validates the block-load output against the previous
`stage_ntt_inv_head_l1_avx2()` helper before timing.

Direct AVX2-only command:

```bash
make bench-stages CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
for i in $(seq 1 7); do
  taskset -c 0 ./bench_core_stagesc 50000 | \
    awk -F= -v run="$i" '/mlkem_core_stage_decrypt_inv_(copy_only|head|head_l1|head_l1_block|sub_from)_ns_per_op=|mlkem_core_stage_kpke_decrypt_cached_ns_per_op=/{print run, $1, $2}'
done
```

Direct diagnostic results:

| Metric | Avg ns/op | Median ns/op |
|---|---:|---:|
| `mlkem_core_stage_decrypt_inv_head_l1` | 223.97 | 223.80 |
| `mlkem_core_stage_decrypt_inv_head_l1_block` | 218.62 | 218.61 |

The block-load helper is `1.0245x` faster by average and `1.0237x` faster by
median, saving about `5.19 ns` at this local `l1` boundary.

Production A/B command against the previous HEAD:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage,kem STAGE_ITERS=60000 KEM_ITERS=24000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Production A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_decrypt_inv_head` | 274.56 | 268.24 | 1.0235x | 1.0236x |
| `mlkem_core_stage_decrypt_inv_butterflies` | 359.80 | 352.77 | 1.0199x | 1.0198x |
| `mlkem_core_stage_decrypt_inv_sub_from` | 381.29 | 374.70 | 1.0176x | 1.0176x |
| `mlkem_core_stage_decrypt_lazy_ntt_accum_recover` | 872.29 | 868.53 | 1.0043x | 1.0063x |
| `mlkem_core_stage_kpke_decrypt_cached` | 905.66 | 901.94 | 1.0041x | 1.0045x |
| `mlkem_core_stage_kpke_decrypt_uncached` | 917.34 | 911.41 | 1.0065x | 1.0063x |
| `mlkem_core_stage_encrypt_inv_add_u_head_only` | 463.97 | 445.96 | 1.0404x | 1.0396x |
| `mlkem_core_stage_encrypt_inv_add_u_only` | 786.99 | 771.16 | 1.0205x | 1.0199x |
| `mlkem_core_stage_encrypt_accum_inv` | 1348.28 | 1304.95 | 1.0332x | 1.0174x |
| `mlkem_decaps` | 3602.77 | 3593.18 | 1.0027x | 1.0062x |
| `mlkem_roundtrip` | 13281.63 | 13266.07 | 1.0012x | 1.0027x |

Decision: keep the production `l1` block-load helper. It improves the direct
`l1` row, the full inverse-head/decrypt rows, and the encryption inverse-add
rows that share `ntt_inv_head_avx2()`. The broad KEM rows are small but positive
on median. Future inverse work should not revisit the rejected block-local
`l1->l2->l3` ordering; the useful pattern here is reducing the `l1` memory
scatter/gather overhead while preserving the level-wise schedule. The next
remaining inverse target is a wider l2/l3/tail representation or schedule change,
not another local l1 load/store variant.




### Independent Core Optimization A/B (2026-07-03, AVX2 inverse head-l2 block load)

The AVX2-only inverse head now also uses a block-load helper for `l2`. The
previous `l2` helper loaded `a0/a1` and `b0/b1` as four 64-bit chunks inside
each 16-coefficient block. The new helper loads the low and high 8-coefficient
halves with two contiguous 128-bit loads, forms `a=[0..3,8..11]` and
`b=[4..7,12..15]` with 64-bit unpacks, and stores the two contiguous output
halves with 128-bit stores. `l1` keeps the earlier block-load/shuffle helper and
`l3` was already naturally contiguous. AVX512BW builds remain on the previous
helper shape.

The bench-only diagnostic validates the block-load output against the previous
`stage_ntt_inv_head_l2_avx2()` helper before timing.

Direct AVX2-only command:

```bash
make bench-stages CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
for i in $(seq 1 7); do
  taskset -c 0 ./bench_core_stagesc 50000 | \
    awk -F= -v run="$i" '/mlkem_core_stage_decrypt_inv_(copy_only|head|head_l2|head_l2_block|sub_from)_ns_per_op=|mlkem_core_stage_kpke_decrypt_cached_ns_per_op=/{print run, $1, $2}'
done
```

Direct diagnostic results:

| Metric | Avg ns/op | Median ns/op |
|---|---:|---:|
| `mlkem_core_stage_decrypt_inv_head_l2` | 213.00 | 213.00 |
| `mlkem_core_stage_decrypt_inv_head_l2_block` | 210.87 | 210.86 |

The block-load helper is `1.0101x` faster by average and median, saving about
`2.14 ns` at this local `l2` boundary.

Production A/B command against the previous HEAD:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage,kem STAGE_ITERS=60000 KEM_ITERS=24000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Production A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_decrypt_inv_head` | 268.50 | 267.37 | 1.0042x | 1.0041x |
| `mlkem_core_stage_decrypt_inv_butterflies` | 353.55 | 352.21 | 1.0038x | 1.0031x |
| `mlkem_core_stage_decrypt_inv_sub_from` | 374.84 | 374.41 | 1.0012x | 1.0016x |
| `mlkem_core_stage_decrypt_lazy_ntt_accum_recover` | 863.02 | 861.47 | 1.0018x | 1.0008x |
| `mlkem_core_stage_encrypt_inv_add_u_head_only` | 448.41 | 445.93 | 1.0056x | 1.0055x |
| `mlkem_core_stage_encrypt_inv_add_u_only` | 770.99 | 769.14 | 1.0024x | 1.0027x |
| `mlkem_core_stage_encrypt_accum_inv` | 1304.16 | 1299.42 | 1.0036x | 1.0017x |
| `mlkem_decaps` | 3578.38 | 3568.70 | 1.0027x | 1.0008x |
| `mlkem_roundtrip` | 13305.95 | 13240.20 | 1.0050x | 1.0002x |

Decision: keep the production `l2` block-load helper. The direct `l2` row and
the shared inverse-head rows are consistently positive. Broad KEM rows are small
and near noise, so this should be treated as a local core improvement rather than
a headline end-to-end win. The useful pattern remains reducing inverse-head
scatter/gather while preserving the level-wise schedule; `l3` is already
contiguous, so the next inverse-head work should move beyond local load/store
rewrites.

### Independent Core Optimization Diagnostic (2026-07-03, AVX2 inverse tail explicit vec8)

A bench-only diagnostic tested replacing the AVX2-only inverse tail scalar loops
with explicit 8-lane AVX2 butterflies. The candidate loads each 8-coefficient
`a`/`b` half, applies the same inverse butterfly as the AVX2 head `l3`, and uses
a pre-expanded bench-local zeta table. Output is validated byte-for-byte against
the existing tail before timing.

This is a useful negative result: the current scalar tail loops are already
vectorized well by clang, and the manual 8-lane form loses to that code shape.

Command:

```bash
make bench-stages CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
for i in $(seq 1 7); do
  taskset -c 0 ./bench_core_stagesc 30000 | \
    awk -F= -v run="$i" '/mlkem_core_stage_decrypt_inv_(copy_only|tail|tail_vec8|tail_l4|tail_l4_vec8|tail_l5|tail_l5_vec8|tail_l6|tail_l6_vec8)_ns_per_op=/{print run, $1, $2}'
done
```

Results:

| Metric | Existing avg ns/op | Existing median ns/op | Vec8 avg ns/op | Vec8 median ns/op |
|---|---:|---:|---:|---:|
| Full tail `l4`..`l7` | 268.68 | 268.72 | 277.63 | 277.06 |
| Tail `l4` | 205.72 | 205.72 | 207.95 | 207.92 |
| Tail `l5` | 205.62 | 205.65 | 207.06 | 207.05 |
| Tail `l6` | 204.79 | 204.80 | 207.26 | 207.22 |

Decision: reject the explicit vec8 tail rewrite. It is about `0.968x` as fast
as the existing full-tail path by average, and every individual measured level is
slower. Do not spend more time on a direct 8-lane rewrite of `l4`..`l6`; any
future tail work needs a broader schedule/range change that beats clang's current
vectorized scalar loop, not a one-to-one manual AVX2 transcription.

### Independent Core Optimization Diagnostic (2026-07-03, AVX2 lazy ehat add boundary)

A bench-only keygen diagnostic tested the `ehat` side of the lazy/signed range
contract. The candidate computes the three keygen error-polynomial NTTs with
`ntt_lazy_mul_input_avx2()` and then adds them into precomputed `A^T*s` using an
add helper that reduces only the lazy `ehat` input before the normal add. This
keeps the public-key output canonical and validates byte-for-byte against the
existing `ntt(ehat) -> ntt_add()` path.

AVX2-only command:

```bash
make bench-stages CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
for i in $(seq 1 7); do
  taskset -c 0 ./bench_core_stagesc 30000 | \
    awk -F= -v run="$i" '
      /mlkem_core_stage_keygen_(error_ntt_add_canonical_ehat|error_ntt_add_lazy_ehat|error_ntt_only|add_only|noise_ntt_only|noise_ntt|accum_encode)_ns_per_op=/ {
        print run, $1, $2
      }'
done
```

Boundary highlights, relative to the canonical `ehat` NTT plus add path:

| Metric | Avg ns/op | Median ns/op | Avg speedup vs canonical | Median speedup vs canonical |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_error_ntt_add_canonical_ehat` | 805.74 | 805.76 | 1.0000x | 1.0000x |
| `mlkem_core_stage_keygen_error_ntt_add_lazy_ehat` | 802.32 | 802.32 | 1.0043x | 1.0043x |
| `mlkem_core_stage_keygen_error_ntt_only` | 783.66 | 783.78 | n/a | n/a |
| `mlkem_core_stage_keygen_add_only` | 204.31 | 204.40 | n/a | n/a |
| `mlkem_core_stage_keygen_noise_ntt_only` | 1561.34 | 1561.54 | n/a | n/a |
| `mlkem_core_stage_keygen_noise_ntt` | 1997.25 | 1998.06 | n/a | n/a |

The direct boundary row was positive, so a temporary production candidate routed
only AVX2 keygen `ehat[]` through `ntt_lazy_mul_input_avx2()` and used the lazy
`ehat` add for `that = A^T*s + ehat`. Correctness passed, but integrated A/B
rejected the change.

Production A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage,kem STAGE_ITERS=70000 KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Production A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_noise_ntt_only` | 1560.91 | 1557.18 | 1.0024x | 1.0028x |
| `mlkem_core_stage_keygen_accum_encode` | 491.31 | 488.72 | 1.0053x | 1.0066x |
| `mlkem_core_stage_keygen_noise_ntt` | 1991.10 | 1989.98 | 1.0006x | 1.0004x |
| `mlkem_core_stage_kpke_keygen_full` | 4803.14 | 4800.04 | 1.0006x | 1.0001x |
| `mlkem_keygen` | 6939.22 | 6933.14 | 1.0009x | 0.9971x |
| `mlkem_keygen_core` | 6901.94 | 6914.37 | 0.9982x | 0.9969x |
| `mlkem_roundtrip_core` | 20190.04 | 20210.51 | 0.9990x | 0.9963x |

Decision: reject the production lazy-`ehat` add boundary. The isolated boundary
saves only about 3.4 ns, and that does not survive the full keygen/KEM medians.
Keep canonical `ehat` in production. A future `ehat` range change would need to
span `ehat` generation, accumulation, public-key encoding, and cache effects
together rather than only moving the final NTT reduction into the add helper.


### Independent Core Optimization Diagnostic (2026-07-03, AVX2 inverse-final d10 fusion)

A bench-only boundary diagnostic tested the NAF/signed-lazy analogue at the
encryption output boundary: carry the pre-final inverse-NTT representation from
`stage_u_inv_l6` directly into DU=10 compression/encoding instead of materializing
the canonical `u` polynomial and then reading it again. The fused candidate keeps
the same final inverse butterfly, scale, `e1` add, and DU=10 packing semantics,
and validates its ciphertext bytes against the existing split
`stage_ntt_inv_add_final_after_l6_avx2() -> compress_encode_poly_d10_avx2()`
path. Production code is unchanged.

AVX2-only command:

```bash
make bench-stages CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
for i in $(seq 1 7); do
  taskset -c 0 ./bench_core_stagesc 30000 | \
    awk -F= -v run="$i" '
      /mlkem_core_stage_encrypt_inv_add_u_final(_only|3_only|_d10_encode|_d10_encode_fused)_ns_per_op=|mlkem_core_stage_ciphertext_compress_encode_d10_ns_per_op=|mlkem_core_stage_encrypt_inv_add_u_only_ns_per_op=/ {
        print run, $1, $2
      }'
done
```

Final-inverse-to-d10 highlights, relative to the existing split final+compress
boundary:

| Metric | Avg ns/op | Median ns/op | Avg speedup vs split | Median speedup vs split |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_encrypt_inv_add_u_final_d10_encode` | 193.94 | 193.08 | 1.0000x | 1.0000x |
| `mlkem_core_stage_encrypt_inv_add_u_final_d10_encode_fused` | 206.71 | 205.63 | 0.9382x | 0.9390x |
| `mlkem_core_stage_encrypt_inv_add_u_final_only` | 322.58 | 322.06 | n/a | n/a |
| `mlkem_core_stage_encrypt_inv_add_u_final3_only` | 334.44 | 334.31 | n/a | n/a |
| `mlkem_core_stage_ciphertext_compress_encode_d10` | 46.71 | 46.73 | n/a | n/a |
| `mlkem_core_stage_encrypt_inv_add_u_only` | 789.65 | 789.48 | n/a | n/a |

Decision: reject this final-only DU=10 fusion for production. Avoiding the
canonical `u` store/load boundary does not pay for the fused loop's extra
register pressure and less favorable packing shape; the median fused row is
about `1.0649x` slower than the existing split final+compress row. Future
range-contract work must span a larger boundary, or change the representation
earlier than the final inverse pass, rather than only fusing the last inverse
step into d10 packing.


### Independent Core Optimization Diagnostic (2026-07-03, AVX2 sample_ntt4 batch1 raw split)

A bench-only sampler diagnostic now measures the second AVX2 public-matrix x4
batch with the same lightweight sink as `sample_ntt4_full_raw`. The previous
`sample_matrix_x4_batch1` row includes full-polynomial checksums and different
output positions, so it could not isolate whether batch1 was slower in the x4
sampler itself or only in the diagnostic sink.

AVX2-only command:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make bench-stages CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
taskset -c 0 ./bench_core_stagesc 30000 | \
  rg "mlkem_core_stage_sample_(matrix_x4_batch[01]|ntt4_full_raw(_batch1)?)_ns_per_op|mlkem_core_stage_sample_matrix_ns_per_op"
```

| Metric | ns/op |
|---|---:|
| `mlkem_core_stage_sample_matrix` | 2796.33 |
| `mlkem_core_stage_sample_matrix_x4_batch0` | 1111.11 |
| `mlkem_core_stage_sample_matrix_x4_batch1` | 1180.18 |
| `mlkem_core_stage_sample_ntt4_full_raw` | 926.47 |
| `mlkem_core_stage_sample_ntt4_full_raw_batch1` | 1000.50 |

A follow-up distribution check used the same generated-seed sequence for the
first and second x4 batch tuples and compared how often the initial three-rate
504-byte parse needed a refill:

```bash
taskset -c 0 ./bench_core_stagesc 30000 | \
  rg "mlkem_core_stage_sample_ntt4(_batch1)?_initial_(extra_group_pct|extra_lane_pct|avg_accepts|min_accepts)"
```

| Metric | Batch0 | Batch1 |
|---|---:|---:|
| extra group pct | 3.296667 | 3.420000 |
| extra lane pct | 0.833333 | 0.863333 |
| average accepts | 255.974792 | 255.974333 |
| minimum accepts | 238 | 239 |

Decision: use this only as a target-selection diagnostic. The batch1 raw gap is
real in the fixed four-lane stage harness, but the refill/acceptance distribution
is effectively the same across generated seeds. Production `rho` is seed-derived,
so the rejection distribution should not be optimized around one fixed benchmark
input set. Do not change x4 batch order or grouping solely from this row; a real
sampler change still needs to improve full `sample_matrix()`, public-prepare,
keygen, and KEM medians.


### Independent Core Optimization Diagnostic (2026-07-03, AVX2 sampler restrict qualifiers)

A narrow alias-information experiment was rejected. The candidate changed only
AVX2 sampler/parser/store signatures around `sample_ntt_parse_stream_avx2_ready()`,
`sample_ntt4_store*()`, and `sample_ntt4()` to use C99 `restrict`-qualified
stream and output pointers. The goal was to tell clang that the four output
polynomials and stream rows are independent, without changing Keccak, rejection
parsing, stream layout, or produced samples.

Correctness passed the AVX2-only gate:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected restrict highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_matrix` | 2808.13 | 2805.64 | 1.0009x | 0.9993x |
| `mlkem_core_stage_sample_ntt4_full_raw` | 932.82 | 931.89 | 1.0010x | 0.9995x |
| `mlkem_core_stage_sample_ntt4_common3_step` | 992.16 | 993.84 | 0.9983x | 0.9985x |
| `mlkem_core_stage_sample_ntt4_keccak_store3` | 876.22 | 876.95 | 0.9992x | 0.9995x |
| `mlkem_core_stage_kpke_prepare_public_no_cache` | 4159.92 | 4154.12 | 1.0014x | 1.0006x |
| `mlkem_core_stage_kpke_keygen_full` | 4820.14 | 4801.71 | 1.0038x | 1.0018x |

Decision: keep the sampler signatures unchanged. The restrict-only source change
does not move the direct sampler rows robustly, and the full `sample_matrix()`
median is slightly negative. The small public-prepare/keygen movement is not a
defensible production signal without a sampler median win. Future sampler work
needs to change real state/dataflow, not only pointer alias annotations.


### Latest Core Optimization A/B (2026-07-03, AVX2 keygen matrix/noise scheduling)

The AVX2-only keygen matrix/noise helper now schedules the co-scheduled PRF/CBD
plus `(2,2)` public-matrix tail between the two `sample_ntt4()` public-matrix
batches. The previous order was `x4 batch0 -> x4 batch1 -> PRF/CBD+tail`; the
new order is `x4 batch0 -> PRF/CBD+tail -> x4 batch1`. This does not change
Keccak inputs, rejection sampling, CBD decoding, NTT inputs, wire-visible keys,
or any cache behavior. It only changes the local keygen production order inside
`mlkem_keygen_matrix_noise_avx2()`.

Correctness checks:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core
```

AVX2-only stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Stage highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_kpke_keygen_full` | 4832.39 | 4816.52 | 1.0033x | 1.0005x |
| `mlkem_core_stage_kpke_prepare_public_no_cache` | 4176.92 | 4153.38 | 1.0057x | 1.0019x |
| `mlkem_core_stage_keygen_noise_prf_cbd` | 970.02 | 965.81 | 1.0044x | 1.0010x |
| `mlkem_core_stage_keygen_noise_ntt` | 1991.06 | 1984.15 | 1.0035x | 1.0004x |
| `mlkem_core_stage_sample_matrix` | 2809.24 | 2800.23 | 1.0032x | 1.0007x |

Longer AVX2-only KEM confirmation:

```bash
RUNS=17 WARMUP_RUNS=4 SUITES=kem KEM_ITERS=50000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_keygen` | 6953.69 | 6931.56 | 1.0032x | 1.0008x |
| `mlkem_keygen_core` | 6931.62 | 6906.02 | 1.0037x | 1.0008x |
| `mlkem_encaps` | 2689.10 | 2687.01 | 1.0008x | 1.0000x |
| `mlkem_decaps_core` | 6101.85 | 6072.95 | 1.0048x | 1.0001x |
| `mlkem_roundtrip` | 13378.83 | 13364.93 | 1.0010x | 0.9996x |
| `mlkem_roundtrip_core` | 20145.06 | 20128.71 | 1.0008x | 1.0022x |

Decision: accept the keygen-only schedule change with a deliberately narrow
claim. The direct keygen rows and longer KEM keygen rows are consistently
positive, while top-level roundtrip median is effectively neutral. This is not a
new sampler primitive and should not be generalized to `sample_matrix()` or
encryption paths; earlier standalone tail/order experiments did not produce a
robust public-matrix win. The useful effect here is limited to the combined
keygen matrix/noise function's local code/data schedule.

A bench-only follow-up compared the accepted middle placement against the two
remaining orders that preserve the same co-scheduled PRF/CBD plus `(2,2)` tail
primitive. The three helpers validate identical `ahat`, `shat`, and `ehat`
outputs; the timed rows use the same lightweight coefficient sink. Pinned CPU 0,
`clang`, `AVX2_BACKEND=core`, `-mavx2 -mbmi2 -mpopcnt`, median of seven
`10000`-iteration full stage-bench runs measured:

| Metric | Avg ns/op | Median ns/op | Speed vs current median |
|---|---:|---:|---:|
| `mlkem_core_stage_keygen_matrix_noise_current` | 3038.75 | 3038.54 | 1.0000x |
| `mlkem_core_stage_keygen_matrix_noise_tail_first` | 3059.16 | 3057.78 | 0.9937x |
| `mlkem_core_stage_keygen_matrix_noise_tail_last` | 3054.65 | 3054.52 | 0.9948x |

This rejects both untested edge placements. Running the PRF/CBD+tail block first
or last loses about 0.5-0.6% in the direct matrix/noise diagnostic, so keep the
current `sample_ntt4` batch0 -> PRF/CBD+tail -> `sample_ntt4` batch1 order and
do not reopen this schedule unless the surrounding sampler or PRF/CBD primitive
changes.


### Independent Core Optimization Diagnostic (2026-07-03, AVX2 prepared-noise encrypt helper noinline)

A prepared-noise encrypt boundary follow-up was rejected. The candidate changed
only `kpke_encrypt_prepared_public_with_noise_avx2()` from `static inline` to
`static MLKEM_NOINLINE`. The intent was to reduce caller code pressure for the
prepared-noise paths used by uncached encrypt and decaps re-encrypt. It did not
change arithmetic, dataflow, Keccak inputs, NTT inputs, or cache behavior.

Correctness passed the AVX2-only gate:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage+KEM A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage,kem STAGE_ITERS=70000 KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected stage highlights:

| Metric | Baseline median ns/op | Candidate median ns/op | Median speedup |
|---|---:|---:|---:|
| `mlkem_core_stage_kpke_encrypt_cached` | 2418.59 | 2421.94 | 0.9986x |
| `mlkem_core_stage_kpke_encrypt_uncached` | 4889.47 | 4891.36 | 0.9996x |
| `mlkem_core_stage_kpke_decrypt_cached` | 905.24 | 905.20 | 1.0000x |
| `mlkem_core_stage_kpke_decrypt_uncached` | 916.92 | 916.87 | 1.0001x |
| `mlkem_core_stage_encrypt_noise_prf_cbd_tail_cosched` | 1115.99 | 1118.14 | 0.9981x |
| `mlkem_core_stage_decrypt_ntt_accum_recover` | 887.70 | 886.17 | 1.0017x |

Rejected KEM highlights:

| Metric | Baseline median ns/op | Candidate median ns/op | Median speedup |
|---|---:|---:|---:|
| `mlkem_decaps` | 3625.67 | 3610.33 | 1.0042x |
| `mlkem_decaps_core` | 6033.33 | 6043.99 | 0.9982x |
| `mlkem_encaps` | 2687.31 | 2685.16 | 1.0008x |
| `mlkem_encaps_core` | 6984.97 | 6988.17 | 0.9995x |
| `mlkem_keygen` | 6924.26 | 6925.49 | 0.9998x |
| `mlkem_keygen_core` | 6904.56 | 6905.98 | 0.9998x |
| `mlkem_roundtrip` | 13351.28 | 13356.79 | 0.9996x |
| `mlkem_roundtrip_core` | 20064.75 | 20086.30 | 0.9989x |

Decision: keep the compiler-selected inline boundary. The top-level
`mlkem_decaps` median moved positive, but the targeted core rows and
roundtrip-core regressed. The helper is dense enough that adding a call boundary
is not a reliable full-path improvement for the current prepared-noise encrypt
shape.


### Independent Core Optimization Diagnostic (2026-07-03, AVX2 manual `ntt_mul_acc3()` lane vectorization)

A manual AVX2 rewrite of `ntt_mul_acc3()` was rejected. The candidate processed
8 base-multiplication pairs at a time by loading each adjacent coefficient pair
as one 32-bit lane, splitting low/high 16-bit halves, multiplying in 32-bit
lanes, and interleaving the final `c0,c1` outputs. Because production encrypt
and decrypt feed lazy NTT multiply inputs in the `[0, 2Q)` range, the candidate
first canonicalized each lane with a single subtract. It also had to reduce each
individual 16-bit product before summing: the existing reciprocal reducer uses a
32-bit `x * 315` product and is only safe for single-product ranges, not for
three-product or six-product accumulated sums.

Correctness checks:

```bash
# Temporary scalar-reference diagnostic over random [0, 2Q) inputs.
clang -I. -D_GNU_SOURCE -O2 -Wall -Wextra -Wno-unused-function -std=c99 \
  -mavx2 -mbmi2 -mpopcnt /tmp/check_acc3.c -o /tmp/check_acc3 && \
  /tmp/check_acc3

make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage+KEM A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage,kem STAGE_ITERS=70000 KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected highlights:

| Metric | Baseline median ns/op | Candidate median ns/op | Median speedup |
|---|---:|---:|---:|
| `mlkem_core_stage_encrypt_accum_u_only` | 442.36 | 794.88 | 0.5565x |
| `mlkem_core_stage_encrypt_accum_inv` | 1323.63 | 1802.24 | 0.7344x |
| `mlkem_core_stage_decrypt_accum_only` | 267.77 | 393.87 | 0.6798x |
| `mlkem_core_stage_decrypt_ntt_accum_only` | 860.24 | 991.14 | 0.8679x |
| `mlkem_core_stage_kpke_encrypt_cached` | 2419.90 | 2917.36 | 0.8295x |
| `mlkem_core_stage_kpke_decrypt_cached` | 905.52 | 1025.25 | 0.8832x |
| `mlkem_encaps` | 2685.15 | 3185.62 | 0.8429x |
| `mlkem_decaps` | 3634.82 | 4218.68 | 0.8616x |
| `mlkem_roundtrip_core` | 20092.34 | 21191.32 | 0.9481x |

Decision: keep the compact scalar `ntt_mul_acc3()` source shape for AVX2. A
local SIMD rewrite loses because correctness with lazy multiply inputs requires
extra canonicalization and per-product modular reductions; those costs dominate
the lane parallelism. A future SIMD accumulation attempt needs a broader packed
representation where multiply inputs are already canonical and arranged for the
accumulator, not a drop-in replacement around the current scalar helper.


### Independent Core Optimization Diagnostic (2026-07-03, AVX2 canonical `ntt_mul_acc3()` lane vectorization)

A narrower follow-up measured the best plausible drop-in AVX2 accumulator shape
when all inputs are already canonical NTT-domain coefficients. The diagnostic
added two stage rows: `mlkem_core_stage_ntt_mul_acc3_canonical_scalar` calls the
current scalar `ntt_mul_acc3()`, while
`mlkem_core_stage_ntt_mul_acc3_canonical_avx2` calls a manual 8-pair AVX2 helper
on the same canonical fixture. This removes the lazy-input canonicalization cost
from the previous production replacement attempt, but still keeps the required
per-product modular reductions because the existing 32-bit reciprocal reducer is
not valid for accumulated three-product or six-product sums.

Correctness and benchmark checks:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make bench-stages CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
./bench_core_stagesc 1000 | \
  rg 'ntt_mul_acc3_canonical|bench_iterations|bench_sink'
make test CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

Pinned AVX2-only direct benchmark command:

```bash
for i in $(seq 1 9); do \
  taskset -c 0 ./bench_core_stagesc 70000 | \
    rg 'mlkem_core_stage_ntt_mul_acc3_canonical_(scalar|avx2)_ns_per_op'; \
done
```

Canonical accumulator highlights:

| Metric | Avg ns/op | Median ns/op | Relative to scalar median |
|---|---:|---:|---:|
| `mlkem_core_stage_ntt_mul_acc3_canonical_scalar` | 272.35 | 272.02 | 1.0000x |
| `mlkem_core_stage_ntt_mul_acc3_canonical_avx2` | 355.65 | 354.79 | 0.7667x |

Decision: reject the drop-in AVX2 accumulator direction even under canonical
input assumptions. Removing lazy-input canonicalization is not enough; the AVX2
version still spends too much work reducing individual products before summing.
A future accumulation redesign needs to avoid this reduction shape entirely, for
example by changing the multiply-input representation or using a different packed
accumulation/reduction strategy, rather than vectorizing the current scalar
helper one-for-one.


### Independent Core Optimization Diagnostic (2026-07-03, scalar `ntt_mul_acc3()` explicit reciprocal reduction)

An explicit scalar reduction follow-up was rejected. The temporary candidate kept
`ntt_mul_acc3()` scalar, but replaced the three `% Q` reductions with a helper
for accumulated 32-bit sums:

```c
qhat = ((uint64_t)x * 1290167) >> 32;
r = x - qhat * Q;
if (r >= Q) r -= Q;
if (r >= Q) r -= Q;
```

The helper was validated against the existing `% Q` implementation on both
canonical NTT inputs and AVX2 lazy multiply inputs. This tested whether the
compiler's constant-modulo lowering was leaving an easy scalar reduction win in
the hot accumulator.

Correctness and benchmark commands:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make bench-stages CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
./bench_core_stagesc 1000 | \
  rg 'ntt_mul_acc3_(reduce32|canonical_scalar)|bench_iterations|bench_sink'
make test CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"

for i in $(seq 1 9); do \
  taskset -c 0 ./bench_core_stagesc 70000 | \
    rg 'mlkem_core_stage_ntt_mul_acc3_(reduce32|canonical_scalar)_ns_per_op'; \
done
```

Rejected highlights:

| Metric | Avg ns/op | Median ns/op | Relative to scalar median |
|---|---:|---:|---:|
| `mlkem_core_stage_ntt_mul_acc3_canonical_scalar` | 272.07 | 271.26 | 1.0000x |
| temporary `mlkem_core_stage_ntt_mul_acc3_reduce32` | 286.13 | 285.74 | 0.9493x |

Decision: keep the existing `% Q` source shape in `ntt_mul_acc3()`. Clang's
constant-modulo lowering is already better than the explicit reciprocal helper
for this accumulator. The remaining accumulation problem is not a missed scalar
modulo idiom; it requires a representation or algorithm change that reduces the
number of modular reductions or changes where they occur.


### Independent Core Optimization Diagnostic (2026-07-03, AVX2 keygen `s`/`e` NTT split scheduling)

A keygen-only NTT/encode scheduling follow-up was rejected. The candidate changed
only the AVX2 branch of `kpke_keygen()` after `mlkem_keygen_matrix_noise_avx2()`:
instead of running `ntt(shat[i]) -> encode(shat[i]) -> ntt(ehat[i])` for each
`i`, it first transformed and encoded all three `shat` polynomials, then ran the
three `ehat` NTTs. This did not change PRF/CBD output, public-matrix generation,
NTT inputs, encodings, public keys, or secret keys; it only changed the local
order of six independent keygen NTT/encode operations.

Correctness passed the AVX2-only gate:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

Initial AVX2-only stage+KEM A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage,kem STAGE_ITERS=70000 KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Initial highlights:

| Metric | Baseline median ns/op | Candidate median ns/op | Median speedup |
|---|---:|---:|---:|
| `mlkem_core_stage_kpke_keygen_full` | 4802.05 | 4795.77 | 1.0013x |
| `mlkem_core_stage_keygen_noise_ntt_encode` | 1589.62 | 1589.20 | 1.0003x |
| `mlkem_keygen` | 6934.37 | 6922.32 | 1.0017x |
| `mlkem_keygen_core` | 6909.09 | 6905.35 | 1.0005x |
| `mlkem_roundtrip_core` | 20072.50 | 19979.69 | 1.0046x |

Longer AVX2-only KEM confirmation command:

```bash
RUNS=17 WARMUP_RUNS=4 SUITES=kem KEM_ITERS=50000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Longer confirmation rejected the candidate:

| Metric | Baseline median ns/op | Candidate median ns/op | Median speedup |
|---|---:|---:|---:|
| `mlkem_keygen` | 6922.09 | 6928.45 | 0.9991x |
| `mlkem_keygen_core` | 6904.21 | 6909.57 | 0.9992x |
| `mlkem_encaps` | 2684.48 | 2691.32 | 0.9975x |
| `mlkem_decaps_core` | 6032.55 | 6046.56 | 0.9977x |
| `mlkem_roundtrip` | 13335.78 | 13344.42 | 0.9994x |
| `mlkem_roundtrip_core` | 20084.86 | 20055.02 | 1.0015x |

Decision: keep the existing per-index `s_i` NTT/encode followed by `e_i` NTT
order. The first A/B showed small positive medians, but the longer KEM
confirmation moved the targeted keygen rows negative. This scheduling change is
not a robust keygen improvement; future keygen NTT work needs to change the NTT
representation or arithmetic, not only reorder independent `s` and `e` calls.


### Independent Core Optimization Diagnostic (2026-07-03, scalar `ntt_mul_acc3()` deferred `c0` reduction)

A deferred-`c0` reduction follow-up was rejected. The temporary benchmark-only
candidate kept `ntt_mul_acc3()` scalar, but changed the `c0` half from two
32-bit constant-modulo reductions:

```c
c0 = c0_lo + (c0_hi % Q) * gamma;
out0 = c0 % Q;
```

to one final 64-bit constant-modulo reduction:

```c
c0 = (uint64_t)c0_lo + (uint64_t)c0_hi * gamma;
out0 = c0 % Q;
```

The intent was to test whether removing one reduction from the `c0` path could
beat the cost of a wider modulo. The diagnostic validated the helper against the
existing implementation on both canonical NTT inputs and AVX2 lazy multiply
inputs.

Correctness and benchmark checks:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make bench-stages CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
./bench_core_stagesc 1000 | \
  rg 'ntt_mul_acc3_(defer_c0|canonical_scalar|canonical_avx2)|bench_iterations|bench_sink'
make test CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"

for i in $(seq 1 5); do \
  taskset -c 0 ./bench_core_stagesc 70000 | \
    rg 'mlkem_core_stage_ntt_mul_acc3_(defer_c0|canonical_scalar)_ns_per_op'; \
done
```

Rejected highlights:

| Metric | Avg ns/op | Median ns/op | Relative to scalar median |
|---|---:|---:|---:|
| `mlkem_core_stage_ntt_mul_acc3_canonical_scalar` | 271.88 | 271.15 | 1.0000x |
| temporary `mlkem_core_stage_ntt_mul_acc3_defer_c0` | 682.08 | 682.16 | 0.3975x |

Decision: keep the existing two-step 32-bit reduction shape for `c0`. A single
64-bit `% Q` is much slower than the extra 32-bit constant-modulo operation.
This rules out deferred scalar `c0` reduction as a viable way to reduce
`ntt_mul_acc3()` cost; future work needs a different representation or vector
reduction strategy, not wider scalar modulo.


### Independent Core Optimization Diagnostic (2026-07-03, K=3 tile2x3 packed acc3 input)

A packed-input follow-up for `ntt_mul_acc3()` was rejected. The diagnostic added
a benchmark-only helper that consumes already-packed K=3 x 2-coefficient
`tile2x3` inputs:

```c
[poly0 c0, poly1 c0, poly2 c0, poly0 c1, poly1 c1, poly2 c1, pad, pad]
```

Both A and B inputs are packed before the timed loop, so the measurement excludes
pack cost and isolates whether this memory layout helps the accumulator itself.
The helper is validated against the scalar `ntt_mul_acc3()` output.

Correctness and benchmark checks:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make bench-ntt CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
./bench_nttc 1000 | \
  rg 'mlkem_ntt_mul_acc3(_tile2x3)?_ns_per_op|mlkem_ntt_bench_iterations|mlkem_ntt_bench_sink'

for i in $(seq 1 5); do \
  taskset -c 0 ./bench_nttc 200000 | \
    rg 'mlkem_ntt_mul_acc3(_tile2x3)?_ns_per_op'; \
done
```

Rejected highlights:

| Metric | Avg ns/op | Median ns/op | Relative to scalar median |
|---|---:|---:|---:|
| `mlkem_ntt_mul_acc3` | 89.35 | 88.10 | 1.0000x |
| `mlkem_ntt_mul_acc3_tile2x3` | 263.33 | 263.84 | 0.3339x |

Decision: reject this packed-input `acc3` shape. Simply moving scalar
`ntt_mul_acc3()` to a K=3 x 2-coefficient tile layout is much slower even when
pack cost is excluded. The array-of-tiles indexing prevents the compiler from
keeping the compact scalar reduction shape. Future packed-representation work
must keep the multiply/reduction in registers or change the arithmetic/vector
reduction strategy, not merely consume `tile2x3` memory.


### Independent Core Optimization Diagnostic (2026-07-03, AVX2 `keccakf4_mem()` two-round noinline hybrid)

A hybrid follow-up to the earlier two-round and noinline `keccakf4_mem()`
experiments was rejected. The candidate kept the common `sample_ntt4()` path on a
memory-resident Keccak permutation, but split one round into an always-inline
`keccakf4_mem_round()` helper and changed `keccakf4_mem()` itself into a
`MLKEM_NOINLINE` loop over `round += 2`:
`st -> scratch` for one round, then `scratch -> st` for the next. The intent was
to keep the isolated two-round scheduling win while avoiding the large inlined
code-layout perturbation seen in the earlier manual two-round attempt.

Correctness passed the AVX2-only gate:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected two-round-noinline highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_keccak3_only` | 826.77 | 805.80 | 1.0260x | 1.0261x |
| `mlkem_core_stage_sample_ntt4_keccak_store3` | 876.64 | 825.58 | 1.0618x | 1.0618x |
| `mlkem_core_stage_sample_ntt4_common3_step` | 992.88 | 943.90 | 1.0519x | 1.0543x |
| `mlkem_core_stage_sample_ntt4_full_raw` | 936.50 | 938.60 | 0.9978x | 0.9961x |
| `mlkem_core_stage_sample_matrix_x4_batch0` | 1114.36 | 1125.25 | 0.9903x | 0.9923x |
| `mlkem_core_stage_sample_matrix_x4_batch1` | 1182.58 | 1195.07 | 0.9895x | 0.9896x |
| `mlkem_core_stage_sample_matrix` | 2805.24 | 2825.39 | 0.9929x | 0.9942x |
| `mlkem_core_stage_kpke_prepare_public_no_cache` | 4161.05 | 4176.91 | 0.9962x | 0.9963x |
| `mlkem_core_stage_kpke_keygen_full` | 4819.55 | 4909.18 | 0.9817x | 0.9999x |

Decision: keep the compact inlined pointer-swap `keccakf4_mem()` loop. The
hybrid preserves part of the split-row Keccak/store improvement, but it still
does not survive the full `sample_ntt4()` and public-matrix rows. This closes the
obvious combinations of two-round scheduling, unroll hints, and noinline
boundaries for the current memory-resident sampler shape. Future sampler work
needs to remove state movement or change the stream/parser representation, not
just reschedule the same Keccak round body.


### Independent Core Optimization Diagnostic (2026-07-03, AVX2 final-L1 fused multiply)

A production AVX2-only final-NTT fusion experiment was rejected. The candidate
ported the AVX512-style idea of stopping the three multiply inputs before the
final forward-NTT L1 stage, then computing those final L1 pair values inside a
fused K=3 multiply loop. Encryption used a K=4 fused loop for `u[0..2]` and `v`;
decryption used a K=3 fused loop for `w`. The goal was to avoid materializing
fully transformed `rhat`/`u` values and reading them repeatedly across the
matrix-vector multiply rows.

Correctness passed the AVX2-only gate:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected AVX2 final-L1 fusion highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_kpke_encrypt_cached` | 2423.07 | 2692.53 | 0.8999x | 0.8989x |
| `mlkem_core_stage_kpke_encrypt_uncached` | 4910.92 | 5187.25 | 0.9467x | 0.9477x |
| `mlkem_core_stage_kpke_decrypt_cached` | 906.57 | 967.27 | 0.9372x | 0.9438x |
| `mlkem_core_stage_kpke_decrypt_uncached` | 918.03 | 971.84 | 0.9446x | 0.9452x |
| `mlkem_core_stage_encrypt_accum_inv` | 1328.59 | 1332.54 | 0.9970x | 1.0004x |
| `mlkem_core_stage_decrypt_ntt_accum_recover` | 895.21 | 888.38 | 1.0077x | 1.0019x |

Decision: keep the existing AVX2 production structure: lazy multiply-input NTT
followed by the separate `ntt_mul_acc3()` loops. On AVX2, this final-L1 fusion
adds scalar pair bookkeeping and loses the current tail/multiply scheduling
advantages; the small isolated accumulator rows do not represent the full
production encrypt/decrypt path. Future multiply/NTT redesign should not just
port the AVX512 final-stage fusion shape to AVX2. It needs a genuinely AVX2-wide
packed multiply representation or a broader dataflow change that preserves lane
occupancy across the whole matrix-vector multiply.


### Independent Core Optimization Diagnostic (2026-07-03, AVX2 sample_matrix tail interleave)

A production-order experiment was rejected. The candidate kept the same generated
public matrix entries but changed the AVX2-only `sample_matrix()` call order from
`x4 batch0 -> x4 batch1 -> scalar tail` to
`x4 batch0 -> scalar tail -> x4 batch1`. The goal was to see whether placing the
single-lane `(2,2)` tail between the two four-lane batches reduced front-end or
state-pressure effects in the full public matrix sampler without changing
Keccak output, rejection sampling, or wire-visible values.

Correctness passed the AVX2-only gate:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected tail-interleave highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_matrix` | 2804.50 | 2802.09 | 1.0009x | 1.0002x |
| `mlkem_core_stage_sample_matrix_x4_batch0` | 1123.82 | 1113.26 | 1.0095x | 1.0009x |
| `mlkem_core_stage_sample_matrix_x4_batch1` | 1183.85 | 1180.74 | 1.0026x | 1.0006x |
| `mlkem_core_stage_sample_matrix_tail` | 865.00 | 864.57 | 1.0005x | 1.0000x |
| `mlkem_core_stage_kpke_prepare_public_no_cache` | 4208.58 | 4153.61 | 1.0132x | 0.9999x |
| `mlkem_core_stage_kpke_keygen_full` | 4835.34 | 4810.75 | 1.0051x | 1.0004x |
| `mlkem_core_stage_kpke_encrypt_uncached` | 4893.71 | 4906.89 | 0.9973x | 1.0001x |

Decision: keep the original production order. The direct `sample_matrix()` median
movement is only 1.0002x, the scalar tail row is neutral, and public-prepare does
not improve at the median. This confirms that local call ordering around the
single-lane tail is not a robust sampler optimization; future work should change
the sampler state/dataflow itself, not only the order of existing calls.


### Independent Core Optimization Diagnostic (2026-07-03, AVX2 sample_matrix tail choice)

A bench-only public-matrix grouping diagnostic compares which of the nine
`A[row][col]` entries should be left as the scalar tail while the other eight
entries are packed into two row-major `sample_ntt4()` batches. This does not
change production `sample_matrix()`; it only validates that each tail choice
produces the same matrix and measures the choices under one common generic
helper.

AVX2-only command:

```bash
make bench-stages CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
for i in 1 2 3 4 5 6 7; do
  taskset -c 0 ./bench_core_stagesc 10000 | \
    awk -F= -v run="$i" '
      /mlkem_core_stage_sample_matrix(_tail_choice_[0-2][0-2])?_ns_per_op=|mlkem_core_stage_kpke_keygen_full_ns_per_op=/ {
        print run "\t" $1 "\t" $2
      }'
done
```

Tail-choice highlights, relative to the current `(2,2)` tail under the same
generic diagnostic helper:

| Tail choice | Avg ns/op | Median ns/op | Avg speedup vs `22` | Median speedup vs `22` |
|---|---:|---:|---:|---:|
| `00` | 2811.53 | 2809.67 | 1.0020x | 1.0034x |
| `01` | 2811.26 | 2810.72 | 1.0021x | 1.0030x |
| `02` | 2812.00 | 2810.59 | 1.0018x | 1.0030x |
| `10` | 2816.11 | 2815.99 | 1.0003x | 1.0011x |
| `11` | 2816.26 | 2814.87 | 1.0003x | 1.0015x |
| `12` | 2816.10 | 2817.26 | 1.0003x | 1.0007x |
| `20` | 2815.19 | 2812.82 | 1.0007x | 1.0023x |
| `21` | 2799.10 | 2796.06 | 1.0064x | 1.0083x |
| `22` | 2817.05 | 2819.15 | 1.0000x | 1.0000x |

The fixed stage fixture makes `(2,1)` look best, but this is not a production
change. The difference comes from which fixed SHAKE128 suffixes happen to need
refills together; there is no ML-KEM structural reason to expect `(2,1)` to be
better than `(2,2)` over random `rho`. More importantly, current production
co-schedules the `(2,2)` tail with keygen PRF/CBD and public-hash preparation in
hardcoded tail helpers. Rotating the scalar tail would require redesigning those
co-scheduled helpers too, and the existing logs already show that simple
sampler grouping/order changes do not survive integrated matrix/keygen checks.
Keep `(2,2)` as the production tail. Future sampler work should change the
state/dataflow itself, not only rotate which matrix entry is scalar.


### Independent Core Optimization Diagnostic (2026-07-03, AVX2 sample_ntt2 lower bound)

A bench-only two-lane SHAKE128 sampler diagnostic was rejected as a building block
for public-matrix/hash co-scheduling. The motivation was to test whether the
unused lanes in hash/tail or keygen PRF/tail helpers could carry two additional
public-matrix XOFs, leaving the remaining two entries to a dedicated x2 sampler.
If that lower bound were competitive, a larger production rewrite could replace
`2 * sample_ntt4()` with `sample_ntt4() + sample_ntt2()` plus two co-scheduled
entries.

The diagnostic only adds `mlkem_core_stage_sample_ntt2_full_raw`; production
`sample_matrix()` and all co-scheduled helpers are unchanged. The x2 helper uses
the same AVX2 `keccakf4()` state shape and existing rejection parser, validates
against scalar `sample_ntt()` for `(2,0)` and `(2,1)`, and uses a lightweight
sink like the existing x4 raw rows.

AVX2-only command:

```bash
make bench-stages CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
for i in 1 2 3 4 5 6 7; do
  taskset -c 0 ./bench_core_stagesc 10000 | \
    awk -F= -v run="$i" '
      /mlkem_core_stage_sample_ntt(2_full_raw|4_full_raw|4_scalar4_raw|4_one_full_raw|4_keccak_store3|4_parse_504)_ns_per_op=|mlkem_core_stage_sample_matrix_ns_per_op=/ {
        print run "\t" $1 "\t" $2
      }'
done
```

Two-lane sampler highlights, relative to the existing x4 raw sampler:

| Metric | Avg ns/op | Median ns/op | Avg speedup vs x4 | Median speedup vs x4 |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_full_raw` | 938.15 | 939.04 | 1.0000x | 1.0000x |
| `mlkem_core_stage_sample_ntt2_full_raw` | 1693.13 | 1472.07 | 0.5541x | 0.6379x |
| `mlkem_core_stage_sample_ntt4_one_full_raw` | 893.62 | 892.37 | 1.0498x | 1.0523x |
| `mlkem_core_stage_sample_ntt4_scalar4_raw` | 2769.61 | 2760.44 | 0.3387x | 0.3402x |

This rejects the x2 complement idea. Even if two public-matrix entries were
co-scheduled into otherwise unused hash/PRF lanes, the remaining `sample_ntt4() +
sample_ntt2()` lower bound would be about `939.04 + 1472.07 = 2411.11 ns`, well
above two existing x4 sampler calls at about `1878.08 ns`. The likely cause is
that x2 keeps the full four-lane Keccak cost while losing the efficient x4
transpose/store and four-stream parser amortization. Do not build a production
public-matrix regrouping around a standalone x2 sampler; future co-scheduling
needs to fill all available lanes with useful work or avoid the byte-stream
boundary entirely.


### Independent Core Optimization Diagnostic (2026-07-03, AVX2 sample_ntt3 lower bound)

A follow-up bench-only three-lane SHAKE128 sampler diagnostic was also rejected.
This checks the remaining one-empty-lane case: keygen PRF/tail co-scheduling has
one unused AVX2 lane, so a hypothetical regrouping could put one extra matrix
XOF into that lane and leave three matrix entries for a dedicated x3 sampler.
That would only be useful if `sample_ntt4() + sample_ntt3()` beat the current
`2 * sample_ntt4()` shape.

The diagnostic adds `mlkem_core_stage_sample_ntt3_full_raw`; production
`sample_matrix()` and the keygen PRF/tail helper are unchanged. The helper uses a
three-live-lane `keccakf4()` state, stores three 504-byte streams, reuses the
existing parser, validates `(1,2)`, `(2,0)`, and `(2,1)` against scalar
`sample_ntt()`, and uses the same lightweight sink style as the x4 raw row.

AVX2-only command:

```bash
make bench-stages CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
for i in 1 2 3 4 5 6 7; do
  taskset -c 0 ./bench_core_stagesc 10000 | \
    awk -F= -v run="$i" '
      /mlkem_core_stage_sample_ntt(2_full_raw|3_full_raw|4_full_raw|4_scalar4_raw|4_one_full_raw|4_keccak_store3|4_parse_504)_ns_per_op=|mlkem_core_stage_sample_matrix_ns_per_op=/ {
        print run "\t" $1 "\t" $2
      }'
done
```

Three-lane sampler highlights, relative to the existing x4 raw sampler:

| Metric | Avg ns/op | Median ns/op | Avg speedup vs x4 | Median speedup vs x4 |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_full_raw` | 941.40 | 940.71 | 1.0000x | 1.0000x |
| `mlkem_core_stage_sample_ntt3_full_raw` | 1016.82 | 1015.36 | 0.9258x | 0.9265x |
| `mlkem_core_stage_sample_ntt2_full_raw` | 1612.96 | 1481.86 | 0.5836x | 0.6348x |
| `mlkem_core_stage_sample_ntt4_one_full_raw` | 892.58 | 893.76 | 1.0547x | 1.0525x |

This rejects the one-empty-lane regrouping. The median lower bound for
`sample_ntt4() + sample_ntt3()` is `940.71 + 1015.36 = 1956.07 ns`, while two
existing x4 sampler calls are about `1881.42 ns`; the regrouping is only
`0.9618x` as fast before paying any production integration cost. Keep the two
full x4 public-matrix batches. Future co-scheduling work should require either
full lane occupancy, reuse of already-needed permutations, or a larger redesign
that avoids stream materialization and parser amortization loss.


### Independent Core Optimization Diagnostic (2026-07-03, AVX2 partial-lane matrix grouping)

A matrix-level follow-up tested the same partial-lane idea end to end across all
nine public-matrix polynomials. The new bench-only rows compare the production
`x4 + x4 + scalar` shape against `x3 + x3 + x3` and `x4 + x3 + x2`. This keeps
production code unchanged and validates both regroupings against the scalar
`sample_ntt()` matrix before timing.

AVX2-only command:

```bash
make bench-stages CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
for i in $(seq 1 7); do
  taskset -c 0 ./bench_core_stagesc 40000 | \
    awk -F= -v run="$i" '
      /mlkem_core_stage_sample_matrix(_x3x3x3|_x4x3x2|_tail_choice_(21|22))?_ns_per_op=|mlkem_core_stage_keygen_matrix_noise_(current|tail21)_ns_per_op=|mlkem_core_stage_kpke_keygen_full_ns_per_op=/ {
        print run, $1, $2
      }'
done
```

Matrix grouping highlights, relative to the current `sample_matrix` row:

| Metric | Avg ns/op | Median ns/op | Avg speedup vs current | Median speedup vs current |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_matrix` | 2796.57 | 2796.45 | 1.0000x | 1.0000x |
| `mlkem_core_stage_sample_matrix_tail_choice_21` | 2783.77 | 2786.08 | 1.0046x | 1.0037x |
| `mlkem_core_stage_sample_matrix_tail_choice_22` | 2800.72 | 2800.94 | 0.9985x | 0.9984x |
| `mlkem_core_stage_sample_matrix_x3x3x3` | 3073.62 | 3072.52 | 0.9099x | 0.9101x |
| `mlkem_core_stage_sample_matrix_x4x3x2` | 3660.43 | 3520.77 | 0.7640x | 0.7943x |

Decision: reject partial-lane full-matrix regrouping. `x3x3x3` avoids the scalar
tail but loses the accepted memory-resident `sample_ntt4()` store/dataflow and is
about 9% slower at the median. `x4x3x2` is worse because the x2 helper keeps the
four-lane Keccak cost while losing x4 parser/store amortization. The persistent
`tail_choice_21` signal remains too small and suffix-fixture-dependent to justify
rotating production co-scheduled tail helpers. The next sampler candidate must
preserve the optimized x4 common path or remove the byte-stream parser boundary;
changing lane counts alone is the wrong abstraction.


### Independent Core Optimization Diagnostic (2026-07-03, AVX2 sample_ntt4 block parse)

A bench-only sampler diagnostic tested whether the x4 public-matrix sampler should
parse each 168-byte SHAKE128 rate block immediately instead of first
materializing the current three-block 504-byte streams. This is the remaining
local `sample_ntt4()` dataflow question after the store-order, inline/noinline,
refill scratch, and partial-lane x2/x3 experiments: it keeps the same four
Keccak lanes, same parser, same refill path, and same outputs, but changes the
initial common path from `keccak/store * 3 -> parse 504` to
`(keccak/store -> parse 168) * 3`.

The diagnostic adds `mlkem_core_stage_sample_ntt4_block_parse_full_raw` and
validates both production x4 public-matrix batch tuples against scalar
`sample_ntt()`. Production `sample_ntt4()` is unchanged.

AVX2-only command:

```bash
make bench-stages CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
for i in $(seq 1 7); do
  taskset -c 0 ./bench_core_stagesc 30000 | \
    awk -F= -v run="$i" '
      /mlkem_core_stage_sample_ntt4_(full_raw|block_parse_full_raw|common3_step|parse_504|keccak_store3)_ns_per_op=|mlkem_core_stage_sample_matrix_x4_batch0_ns_per_op=|mlkem_core_stage_sample_matrix_ns_per_op=/ {
        print run, $1, $2
      }'
done
```

Block-parse highlights, relative to the current x4 raw sampler:

| Metric | Avg ns/op | Median ns/op | Avg speedup vs current | Median speedup vs current |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_full_raw` | 938.25 | 935.97 | 1.0000x | 1.0000x |
| `mlkem_core_stage_sample_ntt4_block_parse_full_raw` | 996.73 | 997.42 | 0.9413x | 0.9384x |
| `mlkem_core_stage_sample_ntt4_common3_step` | 988.69 | 988.76 | 0.9490x | 0.9466x |
| `mlkem_core_stage_sample_matrix_x4_batch0` | 1112.17 | 1110.36 | n/a | n/a |
| `mlkem_core_stage_sample_matrix` | 2808.54 | 2800.57 | n/a | n/a |

Decision: reject block-by-block parsing for production. The current 504-byte
stream materialization lets the parser amortize setup and vector compaction over
a larger contiguous stream; parsing three smaller 168-byte chunks pays the parser
front-end and scalar tail costs repeatedly. The median block-parse row is about
`1.0657x` slower than the current x4 raw row, so future sampler work must remove
or reorganize Keccak/store/parse work rather than only moving the parse boundary.


### Independent Core Optimization Diagnostic (2026-07-03, AVX2 sample_ntt4 state parse)

A second bench-only sampler diagnostic tested whether `sample_ntt4()` should
avoid the four 504-byte stream buffers entirely and parse the AVX2 Keccak state
words directly. The candidate keeps the same production x4 lane tuple, same
initial three `keccakf4_mem()` blocks, same refill `keccakf4()` path, and same
scalar rejection predicate, but replaces `store state -> parse contiguous stream`
with a direct scalar 24-bit parser over the 21 SHAKE128 rate words in each state.

The diagnostic adds `mlkem_core_stage_sample_ntt4_state_parse_full_raw` and
validates both production x4 public-matrix batch tuples against scalar
`sample_ntt()`. Production `sample_ntt4()` is unchanged.

AVX2-only command:

```bash
make bench-stages CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
for i in $(seq 1 7); do
  taskset -c 0 ./bench_core_stagesc 30000 | \
    awk -F= -v run="$i" '
      /mlkem_core_stage_sample_ntt4_(full_raw|block_parse_full_raw|state_parse_full_raw|keccak_store3|parse_504)_ns_per_op=|mlkem_core_stage_sample_matrix_ns_per_op=/ {
        print run, $1, $2
      }'
done
```

State-parse highlights, relative to the current x4 raw sampler:

| Metric | Avg ns/op | Median ns/op | Avg speedup vs current | Median speedup vs current |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_full_raw` | 934.46 | 934.44 | 1.0000x | 1.0000x |
| `mlkem_core_stage_sample_ntt4_block_parse_full_raw` | 996.48 | 996.99 | 0.9378x | 0.9373x |
| `mlkem_core_stage_sample_ntt4_state_parse_full_raw` | 1517.74 | 1461.60 | 0.6157x | 0.6393x |
| `mlkem_core_stage_sample_ntt4_keccak_store3` | 870.81 | 870.64 | n/a | n/a |
| `mlkem_core_stage_sample_ntt4_parse_504` | 116.79 | 116.57 | n/a | n/a |
| `mlkem_core_stage_sample_matrix` | 2797.73 | 2797.86 | n/a | n/a |

Decision: reject direct scalar state parsing for production. Removing the
`stream[4][504]` materialization boundary is not enough by itself; the direct
state parser loses the existing parser's contiguous-stream vector compaction and
becomes about `1.56x` slower by median than the current x4 raw sampler. A future
direct-state design would need to compact accepted candidates from state lanes in
vector form, or make a larger Keccak/parser representation change, rather than
only scalarizing the stream extraction.


### Independent Core Optimization Diagnostic (2026-07-03, AVX2 sample_ntt4 state-mask lower bound)

A follow-up bench-only lower bound tested whether direct state-lane SIMD work is
cheap enough before implementing a full accepted-coefficient compactor. The new
row runs the same initial three `keccakf4_mem()` blocks as `sample_ntt4()`, then
extracts the SHAKE128 24-bit candidates directly from the four-lane Keccak state
and counts `d0 < q` / `d1 < q` with AVX2 masks. It deliberately does not write
coefficients, so it is a lower bound for any direct-state parser that would still
need to compact accepted values into four output polynomials.

The validation checks that the capped per-lane accept counts match the existing
`store 504-byte streams -> sample_ntt_parse_stream_avx2_ready()` path for both
production x4 public-matrix tuples. Production code is unchanged.

AVX2-only command:

```bash
make bench-stages CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
for i in $(seq 1 7); do
  taskset -c 0 ./bench_core_stagesc 30000 | \
    awk -F= -v run="$i" '
      /mlkem_core_stage_sample_ntt4_(full_raw|state_mask3|state_parse_full_raw|keccak3_only|keccak_store3|parse_504|common3_step)_ns_per_op=|mlkem_core_stage_sample_matrix_ns_per_op=/ {
        print run, $1, $2
      }'
done
```

State-mask highlights, relative to the current x4 raw sampler:

| Metric | Avg ns/op | Median ns/op | Avg speedup vs current | Median speedup vs current |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_full_raw` | 937.61 | 937.12 | 1.0000x | 1.0000x |
| `mlkem_core_stage_sample_ntt4_state_mask3` | 1240.31 | 1239.87 | 0.7559x | 0.7558x |
| `mlkem_core_stage_sample_ntt4_state_parse_full_raw` | 1463.52 | 1463.11 | 0.6407x | 0.6405x |
| `mlkem_core_stage_sample_ntt4_keccak3_only` | 823.35 | 822.42 | 1.1388x | 1.1395x |
| `mlkem_core_stage_sample_ntt4_keccak_store3` | 870.68 | 870.98 | 1.0769x | 1.0759x |
| `mlkem_core_stage_sample_ntt4_parse_504` | 116.71 | 116.70 | 8.0337x | 8.0302x |
| `mlkem_core_stage_sample_ntt4_common3_step` | 992.15 | 992.17 | 0.9450x | 0.9445x |
| `mlkem_core_stage_sample_matrix` | 2805.71 | 2807.19 | n/a | n/a |

Decision: reject this direct state-mask path. Even before writing accepted
coefficients, the state-lane extraction and per-candidate mask/control work is
about `1.323x` slower than the complete current x4 sampler. This means a viable
state-parser redesign cannot simply bolt SIMD validity masks onto the current
24-bit candidate schedule. It would need a substantially different representation
that produces compacted coefficients without per-candidate scalar control, or it
should leave the byte-stream parser boundary in place and target a different
bottleneck.


### Independent Core Optimization Diagnostic (2026-07-02, AVX2 sample_ntt4 scalar lower bound)

A bench-only AVX2 sampler diagnostic now measures the cost of replacing one
four-lane `sample_ntt4()` public-matrix batch with four scalar `sample_ntt()`
calls for the same `(row, col)` entries. The metric uses the same lightweight
sink as `sample_ntt4_full_raw`, so it is meant to compare only these two rows.
It does not change production code.

Command:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make bench-stages CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
for i in $(seq 1 7); do
  taskset -c 0 ./bench_core_stagesc 30000 | \
    rg "mlkem_core_stage_sample_ntt4_(full_raw|scalar4_raw|keccak_store3|parse_504)_ns_per_op|mlkem_core_stage_sample_matrix_ns_per_op"
done
```

Median AVX2-only results from the seven repeated runs:

| Metric | Median ns/op |
|---|---:|
| `mlkem_core_stage_sample_ntt4_full_raw` | 1174.66 |
| `mlkem_core_stage_sample_ntt4_scalar4_raw` | 2742.65 |
| `mlkem_core_stage_sample_ntt4_keccak_store3` | 892.08 |
| `mlkem_core_stage_sample_ntt4_parse_504` | 118.59 |
| `mlkem_core_stage_sample_matrix` | 3329.12 |

Decision: do not replace the common x4 public-matrix sampler batches with scalar
`sample_ntt()` calls. Even though the current `keccakf4()` path dominates the x4
sampler, four scalar streams are about 2.33x slower than one `sample_ntt4()`
batch. The next sampler work must preserve x4 lane occupancy and reduce the
Keccak/state work inside that layout; scalar fallback is only appropriate for
single-lane tails or co-scheduled tail continuation, where the accepted keygen
and encrypt changes already use it.


### Independent Core Optimization Diagnostic (2026-07-02, AVX2 sample_ntt4 state init cost)

A bench-only AVX2 sampler split now measures only the `sample_ntt4()` Keccak
state initialization for the common first public-matrix batch tuple. This
quantifies the maximum possible benefit of another fixed row/column prebuild or
state-initialization rewrite, independent of the already rejected fixed-batch
wrapper experiment.

Command:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make bench-stages CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
for i in $(seq 1 7); do
  taskset -c 0 ./bench_core_stagesc 30000 | \
    rg "mlkem_core_stage_sample_ntt4_(full_raw|init_only|keccak_store3|parse_504|common3_step)_ns_per_op|mlkem_core_stage_sample_matrix_ns_per_op"
done
```

Median AVX2-only results from the seven repeated runs:

| Metric | Median ns/op |
|---|---:|
| `mlkem_core_stage_sample_ntt4_init_only` | 6.53 |
| `mlkem_core_stage_sample_ntt4_keccak_store3` | 892.25 |
| `mlkem_core_stage_sample_ntt4_parse_504` | 118.35 |
| `mlkem_core_stage_sample_ntt4_common3_step` | 1000.06 |
| `mlkem_core_stage_sample_ntt4_full_raw` | 1173.69 |
| `mlkem_core_stage_sample_matrix` | 3328.36 |

Decision: do not spend more work on row/column state prebuilds or x4 sampler
initialization cleanup. The whole initialization is roughly 0.7% of the initial
Keccak/store path and below 0.2% of full `sample_matrix()`. This explains why
the earlier fixed-batch wrapper lost despite removing the visible lane
construction code: the removed work is too small, while the wrapper perturbs code
layout around the much larger three-`keccakf4()` path. The remaining sampler
optimization target is still the permutation/state dataflow itself.

A follow-up source-level initialization rewrite was rejected. The candidate
changed only the common AVX2 `sample_ntt4()` state zeroing, plus the matching
stage split helper, from a 25-lane `_mm256_setzero_si256()` loop to `memset()`.
This tested whether letting clang lower the zeroing as a bulk memory operation
could keep the tiny `init_only` win without perturbing the larger sampler path.

Correctness passed the AVX2-only gate:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Stage highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_init_only` | 6.60 | 6.53 | 1.0099x | 1.0154x |
| `mlkem_core_stage_sample_ntt4_full_raw` | 931.07 | 940.69 | 0.9898x | 0.9997x |
| `mlkem_core_stage_sample_matrix` | 2807.86 | 2816.86 | 0.9968x | 1.0027x |
| `mlkem_core_stage_kpke_prepare_public_no_cache` | 4155.66 | 4176.36 | 0.9950x | 0.9997x |
| `mlkem_core_stage_kpke_keygen_full` | 4814.99 | 4839.26 | 0.9950x | 1.0043x |

AVX2-only KEM confirmation with `RUNS=13`, `KEM_ITERS=30000` did not provide a
clean full-path win:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_keygen_core` | 6905.56 | 6902.67 | 1.0004x | 1.0010x |
| `mlkem_encaps_core` | 7316.00 | 7043.29 | 1.0387x | 1.0040x |
| `mlkem_decaps_core` | 6053.65 | 6099.05 | 0.9926x | 0.9996x |
| `mlkem_roundtrip_core` | 20373.04 | 20177.10 | 1.0097x | 0.9976x |

Keep the explicit vector zeroing loop in `sample_ntt4()`. The isolated init row
improves, but the full sampler is neutral-to-negative and the KEM roundtrip core
median regresses. This confirms the earlier triage: state initialization is too
small to be worth source-level reshaping unless it is part of a broader sampler
state/dataflow redesign.


### Independent Core Optimization A/B (2026-07-02, AVX2 sample_ntt4 memory-resident Keccak)

The accepted follow-up to the sampler state-init triage keeps the existing
register-resident `keccakf4()` for direct Keccak, PRF/CBD, and one-lane tail
users, but adds a memory-resident ping-pong variant for the common
`sample_ntt4()` public-matrix path. The goal is not a different Keccak round
function: it is to lower AVX2 register pressure around `sample_ntt4()`'s three
permutations plus stream-store/parser work.

A temporary assembly probe of the existing register-resident AVX2 permutation
showed a 24-round dynamic shape of about 6357 instructions and 2408 `rsp`
loads/stores per permutation. The memory-resident shape reduces the loop's stack
traffic, but a full replacement regressed direct `mlkem_keccakf4` and PRF/CBD
users. Therefore the production change is deliberately limited to the common
x4 public-matrix sampler.

Correctness passed the AVX2-only gate:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage,kem STAGE_ITERS=70000 \
  KEM_ITERS=30000 C_COMPILER=clang PIN_CPU=0 \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" ./scripts/bench_core_ab.sh HEAD
```

Accepted highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_full_raw` | 1245.00 | 971.68 | 1.2813x | 1.2110x |
| `mlkem_core_stage_sample_ntt4_keccak_store3` | 897.26 | 894.57 | 1.0030x | 1.0011x |
| `mlkem_core_stage_sample_matrix_x4_batch0` | 1435.68 | 1158.70 | 1.2390x | 1.1803x |
| `mlkem_core_stage_sample_matrix_x4_batch1` | 1533.04 | 1231.71 | 1.2446x | 1.1827x |
| `mlkem_core_stage_sample_matrix` | 3469.58 | 2894.10 | 1.1988x | 1.1488x |
| `mlkem_core_stage_kpke_prepare_public_no_cache` | 4811.42 | 4242.71 | 1.1340x | 1.1010x |
| `mlkem_core_stage_kpke_keygen_full` | 6029.14 | 4914.25 | 1.2269x | 1.0852x |
| `mlkem_core_stage_encrypt_noise_prf_cbd` | 1172.10 | 1172.32 | 0.9998x | 1.0001x |
| `mlkem_core_stage_keygen_noise_prf_cbd` | 975.00 | 977.58 | 0.9974x | 0.9971x |
| `mlkem_keygen_core` | 7439.84 | 7026.09 | 1.0589x | 1.0568x |
| `mlkem_encaps_core` | 7401.89 | 7060.27 | 1.0484x | 1.0431x |
| `mlkem_decaps_core` | 6867.27 | 6624.92 | 1.0366x | 1.0632x |
| `mlkem_roundtrip_core` | 21821.98 | 20840.77 | 1.0471x | 1.0513x |

Decision: accept the `sample_ntt4()`-only memory-resident Keccak path. Do not
replace every `keccakf4()` call with this shape: the all-use diagnostic regressed
`mlkem_keccakf4` from 288.51 ns to 294.88 ns median and made the PRF/CBD noise
stages worse. The useful part is the reduced register pressure at the public
matrix sampler boundary, where stream storage and rejection parsing are adjacent
to three x4 Keccak permutations.


### Latest Core Optimization A/B (2026-07-02, AVX2 `keccakf4_mem()` ping-pong copy elision)

The AVX2-only memory-resident Keccak path used by the common `sample_ntt4()`
public-matrix sampler now uses the caller's `st[25]` array as one side of the
ping-pong state. `keccakf4_mem()` previously copied `st` into a local 25-lane
array before the 24 Keccak rounds, ping-ponged between two local arrays, then
copied the final 25 lanes back to `st`. Because Keccak-f[1600] has exactly 24
rounds here, the ping-pong count is even: starting with `src = st` and
`dst = scratch` leaves the final state in `st` after the last swap. This removes
the copy-in/copy-out around each common sampler permutation without changing the
Keccak round function, rejection parser, stream layout, or refill path.

Correctness checks:

```bash
make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
make clean CC=clang AVX2_BACKEND=core && make test CC=clang AVX2_BACKEND=core
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage,kem STAGE_ITERS=70000 KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Stage highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_keccak3_only` | 1060.04 | 826.47 | 1.2826x | 1.2801x |
| `mlkem_core_stage_sample_ntt4_keccak_store3` | 1063.43 | 876.23 | 1.2136x | 1.2128x |
| `mlkem_core_stage_sample_ntt4_common3_step` | 1177.03 | 995.66 | 1.1822x | 1.1816x |
| `mlkem_core_stage_sample_ntt4_full_raw` | 935.87 | 931.70 | 1.0045x | 1.0040x |
| `mlkem_core_stage_sample_matrix_x4_batch0` | 1124.12 | 1113.65 | 1.0094x | 1.0086x |
| `mlkem_core_stage_sample_matrix_x4_batch1` | 1206.27 | 1186.12 | 1.0170x | 1.0187x |
| `mlkem_core_stage_sample_matrix` | 2836.56 | 2805.59 | 1.0110x | 1.0105x |
| `mlkem_core_stage_kpke_prepare_public_no_cache` | 4188.76 | 4157.02 | 1.0076x | 1.0065x |
| `mlkem_core_stage_kpke_keygen_full` | 4827.51 | 4804.53 | 1.0048x | 1.0046x |

Initial KEM highlights from the same run:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_keygen_core` | 6950.57 | 6919.36 | 1.0045x | 1.0032x |
| `mlkem_encaps_core` | 7107.59 | 6968.46 | 1.0200x | 1.0052x |
| `mlkem_decaps_core` | 6148.63 | 6043.03 | 1.0175x | 1.0088x |
| `mlkem_roundtrip_core` | 20306.18 | 20060.77 | 1.0122x | 1.0060x |

Longer AVX2-only KEM confirmation:

```bash
RUNS=17 WARMUP_RUNS=4 SUITES=kem KEM_ITERS=50000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_keygen` | 6968.04 | 6928.81 | 1.0057x | 1.0034x |
| `mlkem_keygen_core` | 6932.57 | 6923.66 | 1.0013x | 1.0023x |
| `mlkem_encaps` | 2690.87 | 2687.81 | 1.0011x | 1.0006x |
| `mlkem_encaps_core` | 7112.77 | 7024.34 | 1.0126x | 0.9911x |
| `mlkem_decaps_core` | 6106.02 | 6076.01 | 1.0049x | 1.0034x |
| `mlkem_roundtrip` | 13393.93 | 13363.14 | 1.0023x | 1.0010x |
| `mlkem_roundtrip_core` | 20270.22 | 20138.35 | 1.0065x | 1.0020x |

Decision: accept the copy elision. The target rows are the production sampler
rows, and they move consistently: the common Keccak/store split improves by about
21% median, both x4 matrix batches improve, full `sample_matrix()` improves by
about 1%, and no-cache public preparation plus keygen move in the same direction.
The longer KEM confirmation has a split `encaps_core` median, but top-level
encapsulation, keygen, decapsulation, and roundtrip medians stay positive. This
is a core dataflow optimization rather than benchmark caching: every operation
still computes fresh Keccak states and rejection samples; it only avoids copying
the 25-lane in-memory state around an even-round ping-pong permutation.

### Independent Core Optimization Diagnostic (2026-07-02, AVX2 `keccakf4_mem()` static scratch)

A follow-up scratch-placement experiment after the accepted ping-pong copy
elision was rejected. The candidate changed only the remaining `keccakf4_mem()`
ping-pong scratch from a local `__m256i e[25]` array to a static array. The
hypothesis was that, because the AVX2 `sample_ntt4()` path already uses static
stream scratch, moving the 25-lane Keccak scratch out of the stack frame might
reduce stack pressure around the common public-matrix sampler.

Correctness passed the AVX2-only gate:

```bash
make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected static-scratch highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_keccak3_only` | 826.87 | 827.82 | 0.9989x | 0.9997x |
| `mlkem_core_stage_sample_ntt4_keccak_store3` | 876.96 | 877.31 | 0.9996x | 1.0002x |
| `mlkem_core_stage_sample_ntt4_common3_step` | 995.60 | 997.76 | 0.9978x | 0.9983x |
| `mlkem_core_stage_sample_ntt4_full_raw` | 932.56 | 937.08 | 0.9952x | 0.9971x |
| `mlkem_core_stage_sample_matrix_x4_batch0` | 1114.81 | 1117.13 | 0.9979x | 0.9975x |
| `mlkem_core_stage_sample_matrix_x4_batch1` | 1183.54 | 1193.48 | 0.9917x | 0.9957x |
| `mlkem_core_stage_sample_matrix` | 2812.02 | 2822.45 | 0.9963x | 0.9966x |
| `mlkem_core_stage_sample_ntt4_store_rate` | 7.78 | 10.91 | 0.7129x | 0.7076x |

Decision: keep the ping-pong scratch local. The isolated Keccak/store split is
flat, but the full sampler and both x4 matrix batches regress. The direct
`sample_ntt4_store_rate` regression indicates the static object perturbs nearby
code layout or memory scheduling enough to erase any stack-frame benefit. Do not
move this scratch to static storage unless a future broader `sample_ntt4()` layout
change changes the surrounding store path.

### Independent Core Optimization Diagnostic (2026-07-03, AVX2 `keccakf4_mem()` local scratch alignment)

A narrower scratch-placement experiment was rejected. The candidate kept the
accepted stack-local ping-pong scratch in `keccakf4_mem()`, but changed the local
`__m256i e[25]` array to `__attribute__((aligned(32)))`. This tested whether
explicit stack alignment could improve the memory-resident Keccak path without
introducing a static object, changing the permutation schedule, or altering the
stream/parser layout.

Correctness passed the AVX2-only gate:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected local-alignment highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_keccak3_only` | 825.63 | 826.01 | 0.9995x | 0.9999x |
| `mlkem_core_stage_sample_ntt4_keccak_store3` | 875.19 | 875.03 | 1.0002x | 1.0007x |
| `mlkem_core_stage_sample_ntt4_common3_step` | 995.27 | 993.48 | 1.0018x | 1.0022x |
| `mlkem_core_stage_sample_ntt4_full_raw` | 930.59 | 931.87 | 0.9986x | 0.9995x |
| `mlkem_core_stage_sample_matrix_x4_batch0` | 1112.52 | 1113.76 | 0.9989x | 0.9999x |
| `mlkem_core_stage_sample_matrix_x4_batch1` | 1182.82 | 1186.78 | 0.9967x | 1.0002x |
| `mlkem_core_stage_sample_matrix` | 2807.25 | 2803.83 | 1.0012x | 1.0016x |
| `mlkem_core_stage_kpke_prepare_public_no_cache` | 4150.94 | 4170.55 | 0.9953x | 0.9992x |
| `mlkem_core_stage_kpke_keygen_full` | 4798.52 | 4807.93 | 0.9980x | 0.9989x |

Decision: keep the plain local `__m256i e[25]` scratch in `keccakf4_mem()`. The
explicit alignment hint does not improve the direct Keccak split and slightly
weakens the full sampler/public-prepare/keygen rows. This confirms that the
remaining sampler work must change the state dataflow itself; local scratch
placement hints are too small after the accepted ping-pong copy elision.

### Independent Core Optimization Diagnostic (2026-07-02, AVX2 `keccakf4_mem()` two-round schedule)

A second follow-up after the accepted ping-pong copy elision was rejected. The
candidate factored one memory-resident Keccak round into an always-inline helper
and changed `keccakf4_mem()` from a 24-iteration `src`/`dst` pointer-swap loop to
an explicit 12-iteration `st -> scratch` then `scratch -> st` schedule. This kept
the same round function and the same local scratch, but removed the runtime
pointer swap and made the even-round final-state placement explicit.

Correctness passed the AVX2-only gate:

```bash
make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Direct sampler highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_keccak3_only` | 827.00 | 774.95 | 1.0672x | 1.0671x |
| `mlkem_core_stage_sample_ntt4_keccak_store3` | 876.97 | 797.72 | 1.0993x | 1.1000x |
| `mlkem_core_stage_sample_ntt4_common3_step` | 995.97 | 900.91 | 1.1055x | 1.1056x |
| `mlkem_core_stage_sample_ntt4_full_raw` | 932.80 | 904.03 | 1.0318x | 1.0320x |
| `mlkem_core_stage_sample_matrix_x4_batch0` | 1114.03 | 1088.40 | 1.0235x | 1.0233x |
| `mlkem_core_stage_sample_matrix_x4_batch1` | 1185.39 | 1204.17 | 0.9844x | 0.9817x |
| `mlkem_core_stage_sample_matrix` | 2809.68 | 2795.53 | 1.0051x | 1.0049x |
| `mlkem_core_stage_kpke_keygen_full` | 4814.74 | 4815.18 | 0.9999x | 0.9988x |

AVX2-only KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=kem KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected KEM highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_keygen_core` | 6926.39 | 7076.71 | 0.9788x | 1.0046x |
| `mlkem_encaps_core` | 7062.66 | 7003.34 | 1.0085x | 1.0107x |
| `mlkem_decaps_core` | 6047.58 | 6371.91 | 0.9491x | 0.9519x |
| `mlkem_roundtrip` | 13377.03 | 13502.26 | 0.9907x | 1.0018x |
| `mlkem_roundtrip_core` | 20182.83 | 20637.53 | 0.9780x | 0.9695x |

Decision: keep the compact pointer-swap loop. The explicit two-round schedule is
attractive in the isolated `sample_ntt4()` split rows, but it duplicates the large
round body in the loop and perturbs integrated KEM code layout enough to regress
`decaps_core` and `roundtrip_core` substantially. Future `keccakf4_mem()` work
must preserve the direct sampler win without increasing the surrounding KEM code
footprint this much.

### Independent Core Optimization Diagnostic (2026-07-03, AVX2 `keccakf4_mem()` loop unroll hint)

A narrower follow-up to the rejected explicit two-round schedule was also
rejected. The candidate kept the current pointer-swap `keccakf4_mem()` loop,
local scratch, round body, stream layout, parser, and refill path unchanged, but
added a clang-only `#pragma clang loop unroll_count(2)` before the 24-round loop.
This tested whether a compiler-guided two-round shape could keep the local
sampler benefit without the larger code-layout cost of manually factoring and
expanding the round body.

Correctness passed the AVX2-only gate:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected unroll-hint highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_keccak3_only` | 825.59 | 761.77 | 1.0838x | 1.0841x |
| `mlkem_core_stage_sample_ntt4_keccak_store3` | 874.82 | 777.17 | 1.1256x | 1.1265x |
| `mlkem_core_stage_sample_ntt4_common3_step` | 994.06 | 905.22 | 1.0981x | 1.0975x |
| `mlkem_core_stage_sample_ntt4_full_raw` | 931.06 | 918.14 | 1.0141x | 1.0261x |
| `mlkem_core_stage_sample_matrix_x4_batch0` | 1113.12 | 1103.14 | 1.0090x | 1.0197x |
| `mlkem_core_stage_sample_matrix_x4_batch1` | 1183.94 | 1235.98 | 0.9579x | 0.9737x |
| `mlkem_core_stage_sample_matrix` | 2814.08 | 2841.20 | 0.9905x | 0.9991x |
| `mlkem_core_stage_kpke_prepare_public_no_cache` | 4156.61 | 4189.89 | 0.9921x | 0.9977x |
| `mlkem_core_stage_kpke_keygen_full` | 4815.91 | 4939.88 | 0.9749x | 0.9866x |

Do not add a loop-unroll hint to `keccakf4_mem()`. The isolated sampler rows show
that exposing two rounds can make the memory-resident permutation itself faster,
but the full public-matrix and keygen rows do not keep the win. This is the same
acceptance lesson as the manual two-round schedule: future sampler work must
reduce the common Keccak/state dataflow without perturbing the larger keygen code
layout, not just make the split Keccak rows faster.

### Independent Core Optimization Diagnostic (2026-07-02, AVX2 `keccakf4_mem()` round-constant vector table)

A third follow-up after the accepted ping-pong copy elision was rejected. The
candidate changed only the memory-resident Keccak iota step from a per-round
`_mm256_set1_epi64x((long long)rc[round])` broadcast to a 32-byte-aligned
`keccak_rc_x4[24][4]` table load. The hypothesis was that pre-vectorizing the
round constants could remove a broadcast from each of the 24 rounds without
changing the Keccak dataflow, stream layout, parser, or refill path.

Correctness passed the AVX2-only gate:

```bash
make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Stage highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_keccak3_only` | 826.40 | 832.69 | 0.9924x | 0.9924x |
| `mlkem_core_stage_sample_ntt4_keccak_store3` | 877.30 | 898.67 | 0.9762x | 0.9740x |
| `mlkem_core_stage_sample_ntt4_common3_step` | 996.54 | 1015.46 | 0.9814x | 0.9795x |
| `mlkem_core_stage_sample_ntt4_full_raw` | 931.56 | 922.81 | 1.0095x | 1.0097x |
| `mlkem_core_stage_sample_matrix_x4_batch0` | 1113.21 | 1105.69 | 1.0068x | 1.0070x |
| `mlkem_core_stage_sample_matrix_x4_batch1` | 1183.73 | 1173.03 | 1.0091x | 1.0073x |
| `mlkem_core_stage_sample_matrix` | 2808.84 | 2785.27 | 1.0085x | 1.0079x |
| `mlkem_core_stage_kpke_prepare_public_no_cache` | 4166.23 | 4138.33 | 1.0067x | 1.0041x |
| `mlkem_core_stage_kpke_keygen_full` | 4822.27 | 4794.72 | 1.0057x | 1.0025x |

AVX2-only KEM A/B command:

```bash
RUNS=17 WARMUP_RUNS=3 SUITES=kem KEM_ITERS=50000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected KEM highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_keygen_core` | 6917.41 | 6915.39 | 1.0003x | 0.9997x |
| `mlkem_encaps_core` | 7020.63 | 7144.38 | 0.9827x | 0.9927x |
| `mlkem_decaps_core` | 6063.97 | 6086.37 | 0.9963x | 1.0028x |
| `mlkem_roundtrip` | 13371.95 | 13359.83 | 1.0009x | 1.0002x |
| `mlkem_roundtrip_core` | 20103.86 | 20241.09 | 0.9932x | 0.9982x |

Decision: keep the scalar `rc[round]` broadcast in `keccakf4_mem()`. The full
public-matrix sampler rows moved positive, but the direct Keccak split rows
covering the modified iota path regressed sharply, and the integrated KEM
confirmation did not preserve the apparent sampler win: `encaps_core` regressed
and `roundtrip_core` was below baseline. A 768-byte vector table also adds a
read-only data dependency and layout perturbation to avoid a broadcast that the
compiler already handles well. Do not pre-vectorize these round constants unless
a future broader Keccak layout change removes the split-row regression and keeps
the KEM core rows positive.

A memory-resident theta source-shape follow-up was also rejected. The candidate
changed only the five `keccakf4_mem()` theta column parity expressions from the
nested XOR tree shape into sequential `_mm256_xor_si256()` assignments. This is
narrower than the earlier register-resident `keccakf4()` source-shape experiment:
all direct Keccak and PRF/CBD users stayed on the existing code, while the common
`sample_ntt4()` public-matrix path tested whether the memory-resident loop would
schedule better with shorter visible XOR trees.

Correctness passed the AVX2-only gate:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Stage highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_keccak3_only` | 827.64 | 827.33 | 1.0004x | 1.0008x |
| `mlkem_core_stage_sample_ntt4_keccak_store3` | 878.08 | 877.18 | 1.0010x | 1.0006x |
| `mlkem_core_stage_sample_ntt4_common3_step` | 997.08 | 996.03 | 1.0011x | 1.0006x |
| `mlkem_core_stage_sample_ntt4_full_raw` | 933.29 | 932.45 | 1.0009x | 1.0003x |
| `mlkem_core_stage_sample_matrix` | 2811.73 | 2809.08 | 1.0009x | 1.0019x |
| `mlkem_core_stage_kpke_prepare_public_no_cache` | 4166.43 | 4165.76 | 1.0002x | 0.9999x |
| `mlkem_core_stage_kpke_keygen_full` | 4836.56 | 4824.59 | 1.0025x | 1.0024x |

AVX2-only KEM confirmation rejected keeping the source change:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=kem KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_keygen_core` | 6925.77 | 6925.76 | 1.0000x | 1.0004x |
| `mlkem_encaps_core` | 6958.10 | 7059.54 | 0.9856x | 1.0091x |
| `mlkem_decaps_core` | 6073.07 | 6061.84 | 1.0019x | 1.0014x |
| `mlkem_roundtrip` | 13368.14 | 13392.30 | 0.9982x | 0.9991x |
| `mlkem_roundtrip_core` | 20071.88 | 20206.27 | 0.9933x | 0.9991x |

Decision: keep the nested XOR tree in `keccakf4_mem()`. The sampler split rows
show only sub-0.2% median movement, and KEM roundtrip medians do not retain even
that small signal. Future memory-resident Keccak work should remove real state
movement or stores rather than alter equivalent theta source spelling.

### Independent Core Optimization Diagnostic (2026-07-02, AVX2 NTT acc3 helper consolidation)

An NTT accumulation cleanup experiment was rejected. The candidate removed the
historical keygen-only `ntt_mul_acc3_factored_gamma()` helper and retargeted the
keygen path plus the matching stage harness rows to `ntt_mul_acc3()`. The two
helpers now have the same 32-bit factored-`GAMMA` arithmetic shape, so this was a
code-layout and call-target consolidation only; it did not change the NTT-domain
multiplication formula or any modular reductions.

Correctness passed the AVX2-only gate:

```bash
make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected stage highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_accum_only` | 441.78 | 440.79 | 1.0023x | 0.9992x |
| `mlkem_core_stage_keygen_accum_add_only` | 460.12 | 457.22 | 1.0063x | 0.9998x |
| `mlkem_core_stage_keygen_accum_encode` | 494.10 | 490.53 | 1.0073x | 1.0004x |
| `mlkem_core_stage_keygen_noise_ntt` | 1995.42 | 1994.20 | 1.0006x | 1.0003x |
| `mlkem_core_stage_kpke_prepare_public_no_cache` | 4156.07 | 4157.95 | 0.9995x | 1.0000x |
| `mlkem_core_stage_kpke_keygen_full` | 4801.07 | 4829.37 | 0.9941x | 0.9991x |

Decision: keep the keygen-specific `ntt_mul_acc3_factored_gamma()` call target.
Although the helper body is currently equivalent to `ntt_mul_acc3()`, removing it
only produced noise-sized local accumulation medians and weakened full keygen.
This is not a core arithmetic improvement, and the broader keygen row did not
clear the stage gate, so no KEM confirmation was run. Future NTT accumulation
work should change the multiply/reduction schedule itself rather than just
consolidating identical helper bodies.

### Independent Core Optimization Diagnostic (2026-07-02, AVX2 `sample_ntt4_store_rate()` last-lane helper)

A narrow x4 sampler store-path cleanup was rejected. The candidate changed only
`sample_ntt4_store_rate()`'s final rate lane (`st[20]`) from a full
`_mm256_storeu_si256()` into a local `uint64_t last[4]` followed by four 8-byte
copies to the existing `sample_ntt4_store_last()` scalar-lane extraction helper.
The hypothesis was that avoiding the temporary 32-byte local store could trim the
168-byte rate transpose used by both the common three-block sampler path and
refill blocks.

Correctness passed the AVX2-only gate:

```bash
make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected stage highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_store_rate` | 7.74 | 7.72 | 1.0020x | 1.0026x |
| `mlkem_core_stage_sample_ntt4_keccak_store3` | 877.22 | 875.44 | 1.0020x | 1.0010x |
| `mlkem_core_stage_sample_ntt4_common3_step` | 996.58 | 994.26 | 1.0023x | 1.0015x |
| `mlkem_core_stage_sample_ntt4_full_raw` | 931.44 | 940.53 | 0.9903x | 1.0000x |
| `mlkem_core_stage_sample_ntt4_refill_keccak_store1` | 283.22 | 295.19 | 0.9595x | 0.9590x |
| `mlkem_core_stage_sample_ntt4_refill_step_once` | 309.14 | 312.04 | 0.9907x | 0.9905x |
| `mlkem_core_stage_sample_matrix_x4_batch0` | 1113.56 | 1122.56 | 0.9920x | 1.0001x |
| `mlkem_core_stage_sample_matrix_x4_batch1` | 1185.66 | 1193.70 | 0.9933x | 0.9989x |
| `mlkem_core_stage_sample_matrix` | 2807.30 | 2825.56 | 0.9935x | 0.9995x |
| `mlkem_core_stage_kpke_keygen_full` | 4801.11 | 4808.07 | 0.9986x | 0.9998x |

Decision: keep the full-vector temporary store for the `st[20]` tail in
`sample_ntt4_store_rate()`. The isolated store-rate row improved only by about
0.26% median, while the refill store row regressed sharply and the integrated
public-matrix rows did not keep a useful win. The scalar extraction helper is
still useful for AVX512 lane splitting, but on AVX2-only x4 sampling the current
single YMM store plus scalar copies is the more robust layout.

A helper-boundary follow-up was also rejected. The candidate changed only
`sample_ntt4_store_rate()` from a plain `static` helper to
`static MLKEM_ALWAYS_INLINE`, keeping the transpose/store sequence, scratch
layout, parser, and Keccak schedule unchanged. This tested whether forcing the
small rate-store helper into the common sampler and refill callers could preserve
the isolated store-rate movement without changing arithmetic or dataflow.

Correctness passed the AVX2-only gate:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected always-inline highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_store_rate` | 7.75 | 7.71 | 1.0049x | 1.0052x |
| `mlkem_core_stage_sample_ntt4_keccak_store3` | 875.11 | 875.57 | 0.9995x | 0.9992x |
| `mlkem_core_stage_sample_ntt4_common3_step` | 993.71 | 994.96 | 0.9987x | 0.9996x |
| `mlkem_core_stage_sample_ntt4_full_raw` | 930.70 | 933.05 | 0.9975x | 0.9997x |
| `mlkem_core_stage_sample_matrix_x4_batch0` | 1112.65 | 1115.39 | 0.9975x | 0.9993x |
| `mlkem_core_stage_sample_matrix_x4_batch1` | 1187.67 | 1185.12 | 1.0022x | 0.9987x |
| `mlkem_core_stage_sample_matrix` | 2806.37 | 2808.24 | 0.9993x | 0.9982x |
| `mlkem_core_stage_kpke_keygen_full` | 4793.65 | 4892.65 | 0.9798x | 0.9983x |

Do not force-inline `sample_ntt4_store_rate()`. The direct store-rate row improves
by about half a percent, but the full sampler and public-matrix rows move
negative and keygen weakens. The current compiler-selected helper boundary is
better for the larger sampler path.

A store-order follow-up for `sample_ntt4_store4x4()` was rejected. The candidate
kept the same transpose values, parser, stream layout, Keccak schedule, and helper
boundaries, but changed the four 32-byte stores from `s0, s2, s1, s3` to
`s0, s1, s2, s3` so the write order matches the later lane parse order. This only
tested store-buffer/cache ordering around the Keccak/store boundary; it did not
remove any stores or loads.

Correctness passed the AVX2-only gate:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected store-order highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_store_rate` | 7.73 | 7.74 | 0.9981x | 0.9961x |
| `mlkem_core_stage_sample_ntt4_keccak_store3` | 876.94 | 876.38 | 1.0006x | 1.0005x |
| `mlkem_core_stage_sample_ntt4_common3_step` | 995.91 | 998.76 | 0.9972x | 1.0001x |
| `mlkem_core_stage_sample_ntt4_full_raw` | 935.54 | 932.25 | 1.0035x | 0.9999x |
| `mlkem_core_stage_sample_matrix_x4_batch0` | 1117.40 | 1113.79 | 1.0032x | 1.0000x |
| `mlkem_core_stage_sample_matrix_x4_batch1` | 1189.12 | 1180.40 | 1.0074x | 1.0023x |
| `mlkem_core_stage_sample_matrix` | 2824.31 | 2817.49 | 1.0024x | 1.0029x |
| `mlkem_core_stage_kpke_prepare_public_no_cache` | 4172.22 | 4154.92 | 1.0042x | 0.9995x |
| `mlkem_core_stage_kpke_keygen_full` | 4805.65 | 4826.45 | 0.9957x | 1.0001x |

Decision: keep the existing `s0, s2, s1, s3` store order. The direct store-rate
row regressed and the full x4 sampler row stayed neutral, so the small
`sample_matrix` median movement is not a safe acceptance signal. Future work at
this boundary must actually remove a store/load or change the parser
representation, not only reorder equivalent stores.

### Independent Benchmark Alignment Diagnostic (2026-07-02, AVX2 sample_ntt4 split rows)

The AVX2-only `sample_ntt4()` stage split rows now use the same production
`keccakf4_mem()` path as `sample_ntt4()` itself. The earlier split helpers still
called the register-resident `keccakf4()` even after production moved the common
x4 public-matrix sampler to the memory-resident Keccak shape. This made
`sample_ntt4_keccak3_only`, `sample_ntt4_keccak_store3`, the common three-rate
step, and refill rows useful for old-register-shape diagnostics but not for the
current production bottleneck.

This is a benchmark-harness alignment change only; `baby-mlkem.c` and KEM runtime
code are unchanged.

Correctness/build checks:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
make bench-stages CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage A/B command comparing the old split-row shape against the aligned
benchmark harness:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Benchmark alignment highlights:

| Metric | Old row ns/op | Aligned row ns/op | Avg ratio | Median ratio |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_keccak3_only` | 888.92 | 1057.81 | 0.8403x | 0.8399x |
| `mlkem_core_stage_sample_ntt4_keccak_store3` | 897.60 | 1016.71 | 0.8828x | 0.8806x |
| `mlkem_core_stage_sample_ntt4_common3_step` | 1001.74 | 1177.74 | 0.8506x | 0.8505x |
| `mlkem_core_stage_sample_ntt4_refill_keccak_store1` | 283.55 | 298.42 | 0.9502x | 0.9518x |
| `mlkem_core_stage_sample_ntt4_refill_step_once` | 308.89 | 318.01 | 0.9713x | 0.9702x |
| `mlkem_core_stage_sample_ntt4_full_raw` | 971.67 | 974.04 | 0.9976x | 0.9985x |
| `mlkem_core_stage_sample_matrix` | 2895.73 | 2907.81 | 0.9958x | 0.9989x |

The aligned split rows are intentionally not additive with `sample_ntt4_full_raw`:
the standalone split harness gives `keccakf4_mem()` a different local stack and
inlining context than the full sampler. Use `sample_ntt4_full_raw`, x4 batch rows,
and `sample_matrix` as the production acceptance metrics; use the split rows only
to compare future changes against the current production Keccak shape. This
prevents future work from optimizing the old register-resident split rows while
missing the real `sample_ntt4()` path.


### Independent Core Optimization Diagnostic (2026-07-02, AVX2 keccakf4_mem noinline boundary)

A narrow `sample_ntt4()` Keccak boundary experiment was rejected. The candidate
changed only `keccakf4_mem()` from `MLKEM_ALWAYS_INLINE` to `MLKEM_NOINLINE`,
leaving the memory-resident round function, stream stores, parser, and all other
Keccak callers unchanged. The hypothesis was that keeping the large ping-pong
Keccak arrays inside a separate function might reduce `sample_ntt4()` caller
register/stack pressure.

Correctness passed the AVX2-only gate:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage/KEM A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage,kem STAGE_ITERS=60000 KEM_ITERS=20000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected noinline highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_keccak3_only` | 1056.54 | 850.54 | 1.2422x | 1.2430x |
| `mlkem_core_stage_sample_ntt4_keccak_store3` | 1016.35 | 872.62 | 1.1647x | 1.1654x |
| `mlkem_core_stage_sample_ntt4_common3_step` | 1176.93 | 987.73 | 1.1916x | 1.1923x |
| `mlkem_core_stage_sample_ntt4_refill_step_once` | 317.61 | 307.12 | 1.0342x | 1.0386x |
| `mlkem_core_stage_sample_ntt4_full_raw` | 971.39 | 979.64 | 0.9916x | 0.9915x |
| `mlkem_core_stage_sample_matrix_x4_batch0` | 1159.03 | 1168.83 | 0.9916x | 0.9914x |
| `mlkem_core_stage_sample_matrix_x4_batch1` | 1236.81 | 1244.48 | 0.9938x | 0.9967x |
| `mlkem_core_stage_sample_matrix` | 2896.44 | 2914.62 | 0.9938x | 0.9939x |
| `mlkem_core_stage_kpke_keygen_full` | 4921.46 | 4936.51 | 0.9970x | 0.9971x |
| `mlkem_encaps_core` | 7013.38 | 7163.67 | 0.9790x | 0.9848x |
| `mlkem_keygen_core` | 7032.88 | 7052.99 | 0.9971x | 0.9987x |
| `mlkem_roundtrip_core` | 20722.53 | 20821.04 | 0.9953x | 0.9957x |

Keep `keccakf4_mem()` inline in the production `sample_ntt4()` path. The
standalone split rows improve with `noinline`, but the full sampler, public
matrix generation, and KEM core rows regress. This confirms that future
`keccakf4_mem()` work must be accepted on `sample_ntt4_full_raw`, x4 batch,
`sample_matrix`, and KEM rows, not on isolated split rows that have a different
caller context.


### Latest Core Optimization A/B (2026-07-02, AVX2 sample_ntt4 refill register Keccak)

The AVX2-only `sample_ntt4()` common first three SHAKE128 blocks still use the
accepted memory-resident `keccakf4_mem()` path, but refill blocks now switch back
to the register-resident `keccakf4()` path. The common path benefits from the
memory-resident shape because three permutations sit next to stream storage and
parsing in the full sampler. The refill path is different: it runs only after the
initial 504-byte streams leave at least one lane short, so the smaller
register-resident permutation wins enough in the rare-path continuation without
changing PRF/CBD or direct Keccak users.

The stage harness was aligned so `sample_ntt4_refill_keccak_store1` and
`sample_ntt4_refill_step_once` now measure the same register-resident refill
Keccak used by production. Initial x4 sampler split rows still measure
`keccakf4_mem()` because the first three production blocks still use that shape.

Correctness checks:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core
make bench-stages CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Stage highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_refill_keccak_store1` | 297.58 | 282.95 | 1.0517x | 1.0509x |
| `mlkem_core_stage_sample_ntt4_refill_step_once` | 317.36 | 308.63 | 1.0283x | 1.0285x |
| `mlkem_core_stage_sample_ntt4_full_raw` | 971.67 | 966.83 | 1.0050x | 1.0060x |
| `mlkem_core_stage_sample_matrix_x4_batch0` | 1158.49 | 1154.95 | 1.0031x | 1.0037x |
| `mlkem_core_stage_sample_matrix_x4_batch1` | 1233.73 | 1225.01 | 1.0071x | 1.0069x |
| `mlkem_core_stage_sample_matrix` | 2906.54 | 2881.47 | 1.0087x | 1.0073x |
| `mlkem_core_stage_kpke_prepare_public_no_cache` | 4249.94 | 4231.64 | 1.0043x | 1.0031x |
| `mlkem_core_stage_kpke_keygen_full` | 4915.07 | 4927.61 | 0.9975x | 1.0041x |

AVX2-only KEM confirmation:

```bash
RUNS=17 WARMUP_RUNS=4 SUITES=kem KEM_ITERS=50000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_keygen` | 7081.03 | 7023.34 | 1.0082x | 1.0025x |
| `mlkem_keygen_core` | 7043.74 | 7002.41 | 1.0059x | 1.0019x |
| `mlkem_encaps` | 2694.37 | 2686.61 | 1.0029x | 1.0026x |
| `mlkem_encaps_core` | 7072.07 | 7117.90 | 0.9936x | 1.0015x |
| `mlkem_decaps_core` | 6426.20 | 6518.19 | 0.9859x | 1.0023x |
| `mlkem_roundtrip` | 13495.03 | 13445.29 | 1.0037x | 1.0023x |
| `mlkem_roundtrip_core` | 20669.01 | 20761.17 | 0.9956x | 1.0026x |

Decision: accept the refill-only register Keccak path. Do not revert the common
three-block `sample_ntt4()` path back to register-resident Keccak; that was the
pre-`keccakf4_mem()` shape and lost badly in the full sampler. The useful split
is asymmetric: memory-resident Keccak for the dense common three-block sampler,
register-resident Keccak for the occasional one-block refill continuation.


### Latest Core Optimization A/B (2026-07-02, AVX2 sample_ntt4 refill stream reuse)

The AVX2-only `sample_ntt4()` refill path now reuses the existing static
`stream[4][504]` scratch for refill blocks after the initial 504-byte parse has
finished. Previously the rare refill continuation allocated a separate local
`extra[4][168]` buffer, squeezed one more SHAKE128 rate into it, then parsed only
lanes still below 256 coefficients. The initial stream is dead once all four
lanes have completed the first parse, so the refill block can safely overwrite
the first 168 bytes of each `stream[lane]`.

This is not a cache or cross-operation reuse optimization: every public-matrix
sample still performs the same Keccak squeezes and rejection parsing. The change
only removes the separate refill scratch lifetime from the full sampler. It is
also narrower than the earlier rejected static-refill-scratch experiment: no new
static buffer is introduced, and the common initial stream storage remains the
same object already used by production.

Correctness checks:

```bash
make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
make clean CC=clang AVX2_BACKEND=core && make test CC=clang AVX2_BACKEND=core
```

AVX2-only stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage,kem STAGE_ITERS=70000 KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Stage highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_full_raw` | 967.39 | 935.20 | 1.0344x | 1.0346x |
| `mlkem_core_stage_sample_matrix_x4_batch0` | 1162.31 | 1123.41 | 1.0346x | 1.0278x |
| `mlkem_core_stage_sample_matrix_x4_batch1` | 1224.14 | 1203.97 | 1.0167x | 1.0169x |
| `mlkem_core_stage_sample_matrix` | 2881.97 | 2830.44 | 1.0182x | 1.0185x |
| `mlkem_core_stage_kpke_prepare_public_no_cache` | 4231.75 | 4179.73 | 1.0124x | 1.0119x |
| `mlkem_core_stage_kpke_keygen_full` | 4920.21 | 4842.27 | 1.0161x | 1.0118x |

Longer AVX2-only KEM confirmation:

```bash
RUNS=17 WARMUP_RUNS=4 SUITES=kem KEM_ITERS=50000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_keygen` | 7020.26 | 6972.45 | 1.0069x | 1.0083x |
| `mlkem_keygen_core` | 6996.51 | 6941.27 | 1.0080x | 1.0088x |
| `mlkem_encaps_core` | 7234.28 | 7026.75 | 1.0295x | 1.0081x |
| `mlkem_decaps_core` | 6129.31 | 6086.42 | 1.0070x | 1.0097x |
| `mlkem_roundtrip` | 13429.01 | 13401.07 | 1.0021x | 1.0031x |
| `mlkem_roundtrip_core` | 20467.27 | 20225.92 | 1.0119x | 1.0064x |

Decision: accept refill stream reuse. The direct sampler and public-matrix rows
move in the same direction, and the longer KEM confirmation keeps keygen and
roundtrip positive. Keep the asymmetry from the previous optimization:
`keccakf4_mem()` for the dense first three blocks, register-resident `keccakf4()`
for rare refill blocks, and now the existing static stream scratch for those
refill bytes.

A follow-up AVX2-only refill cold-path split was rejected. The candidate moved
only the rare `sample_ntt4()` refill loop into a separate `MLKEM_NOINLINE`
`sample_ntt4_refill_avx2()` helper. The common first three-block path, Keccak
choices, stream scratch, parser, and output values were unchanged; the hypothesis
was that keeping the rare refill continuation out of the hot sampler body would
reduce register pressure or improve code layout.

Correctness passed the AVX2-only gate:

```bash
make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=60000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected refill cold-path highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_refill_step_once` | 309.29 | 308.91 | 1.0012x | 1.0008x |
| `mlkem_core_stage_sample_ntt4_common3_step` | 996.34 | 994.04 | 1.0023x | 1.0017x |
| `mlkem_core_stage_sample_ntt4_full_raw` | 933.57 | 932.54 | 1.0011x | 0.9987x |
| `mlkem_core_stage_sample_matrix_x4_batch0` | 1116.23 | 1113.53 | 1.0024x | 1.0002x |
| `mlkem_core_stage_sample_matrix_x4_batch1` | 1184.22 | 1183.70 | 1.0004x | 0.9993x |
| `mlkem_core_stage_sample_matrix` | 2807.12 | 2807.69 | 0.9998x | 0.9994x |
| `mlkem_core_stage_kpke_keygen_full` | 4812.80 | 4819.01 | 0.9987x | 0.9965x |

Decision: keep the refill loop inside `sample_ntt4()`. The rare-path helper gives
only noise-sized refill/common-step movement, while the full sampler,
public-matrix, and keygen rows do not preserve a median win. No KEM confirmation
was run because the stage gate failed on the rows the change was meant to help.
Future sampler work should remove or restructure common three-rate Keccak/store
work rather than split the already-small refill control path.

### Independent Core Optimization Diagnostic (2026-07-03, AVX2 sample_ntt4 scalar refill)

A rare-path sampler follow-up was rejected. The candidate kept the common
`sample_ntt4()` first three SHAKE128 blocks on the accepted `keccakf4_mem()`
path and changed only the refill branch after the 504-byte parse: instead of
continuing all four lanes with one `keccakf4()` when any lane was short, it
extracted each incomplete lane's 25-word state and continued that lane with
scalar `keccakf()`. The intent was to avoid three unused refill lanes, since the
initial refill diagnostic shows only about 0.86% of lanes need an extra block.

Correctness passed the AVX2-only gate:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected scalar-refill highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_full_raw` | 931.98 | 940.09 | 0.9914x | 0.9904x |
| `mlkem_core_stage_sample_matrix_x4_batch0` | 1114.33 | 1128.12 | 0.9878x | 0.9931x |
| `mlkem_core_stage_sample_matrix_x4_batch1` | 1182.69 | 1184.48 | 0.9985x | 1.0029x |
| `mlkem_core_stage_sample_matrix` | 2808.38 | 2808.57 | 0.9999x | 1.0005x |
| `mlkem_core_stage_kpke_prepare_public_no_cache` | 4169.79 | 4170.50 | 0.9998x | 0.9999x |
| `mlkem_core_stage_kpke_keygen_full` | 4821.30 | 4794.02 | 1.0057x | 1.0006x |

Decision: keep the existing x4 refill continuation. The scalar-lane refill idea
reduces theoretical wasted Keccak work only on a rare path, but it adds lane
extraction and changes the full sampler code shape enough that
`sample_ntt4_full_raw` and the first x4 matrix batch regress. The positive
`kpke_keygen_full` movement is not a defensible acceptance signal because the
direct sampler rows do not support it. No KEM confirmation was run after the
stage gate failed. Future sampler work should target the common three-rate
Keccak/store path or a real parser/state representation change, not another
rare-refill specialization.


### Independent Core Optimization Diagnostic (2026-07-03, AVX2 sample_ntt4 rolling parse)

A common-path `sample_ntt4()` dataflow experiment was rejected. The candidate kept
`keccakf4_mem()`, `sample_ntt4_store_rate()`, the AVX2 rejection parser, and the
refill path arithmetic unchanged, but changed the initial three SHAKE128 rates
from a `stream[4][504]` accumulation followed by four 504-byte parses into a
rolling `stream[4][168]` window parsed after each rate. This reduced the scratch
lifetime and overwrote the same 168-byte window, but increased the number of
short parser calls on the hot common path.

Correctness passed the AVX2-only gate:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected rolling-parse highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_common3_step` | 996.49 | 1017.03 | 0.9798x | 0.9794x |
| `mlkem_core_stage_sample_ntt4_full_raw` | 932.41 | 1015.42 | 0.9182x | 0.9338x |
| `mlkem_core_stage_sample_matrix_x4_batch0` | 1113.39 | 1203.47 | 0.9252x | 0.9393x |
| `mlkem_core_stage_sample_matrix_x4_batch1` | 1183.31 | 1255.41 | 0.9426x | 0.9420x |
| `mlkem_core_stage_sample_matrix` | 2811.33 | 2982.23 | 0.9427x | 0.9514x |
| `mlkem_core_stage_kpke_prepare_public_no_cache` | 4159.44 | 4336.22 | 0.9592x | 0.9651x |
| `mlkem_core_stage_kpke_keygen_full` | 4816.01 | 4972.46 | 0.9685x | 0.9770x |

Decision: keep the current three-rate accumulation followed by one 504-byte parse
per lane. The larger scratch object is static and not the bottleneck; rolling the
window makes the hot path parser shorter and more frequent, which loses badly in
the full sampler and public-matrix rows. Future common-path sampler work should
reduce the Keccak/state transpose cost itself, not trade it for more parser entry
and short-stream overhead.

### Independent Core Optimization Diagnostic (2026-07-02, AVX2 ntt_add unsigned-min reduction)

An AVX2-only `ntt_add()` reduction-shape experiment was rejected. The final
candidate kept generic `poly256_add()` unchanged because that helper preserves the
older signed/negative test semantics, then specialized only the canonical
NTT-domain `ntt_add()` call site. The AVX2 body replaced the existing
`cmpgt + and + sub` correction with `sum = min_epu16(sum, sum - Q)`, which is
valid for canonical inputs in `[0, Q)`.

Correctness passed the AVX2-only gate:

```bash
make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=80000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected unsigned-min `ntt_add()` highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_add_only` | 202.93 | 200.89 | 1.0101x | 1.0097x |
| `mlkem_core_stage_keygen_accum_add_only` | 456.79 | 455.00 | 1.0039x | 1.0042x |
| `mlkem_core_stage_keygen_accum_encode` | 490.31 | 489.11 | 1.0025x | 1.0021x |
| `mlkem_core_stage_kpke_keygen_full` | 4798.90 | 4838.55 | 0.9918x | 0.9987x |
| `mlkem_core_stage_kpke_prepare_public_no_cache` | 4167.06 | 4172.98 | 0.9986x | 0.9986x |

Decision: keep `ntt_add()` on the existing shared `poly256_add()` implementation.
The unsigned-min form improves the isolated add rows, but the full keygen stage
does not preserve the win and the public-prepare row also moves slightly negative.
No KEM confirmation was run for the final narrowed candidate because the stage gate
failed. Future add-side work should be part of a larger accumulation/output layout
change, not another one-pass modular-add instruction substitution.

No-cache encapsulation public-prepare diagnostic:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make bench-stages CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
for i in $(seq 1 7); do
  taskset -c 0 ./bench_core_stagesc 30000 | \
    rg "mlkem_core_stage_kpke_encrypt_(uncached|cached)_ns_per_op|mlkem_core_stage_kpke_prepare_public_no_cache_ns_per_op|mlkem_core_stage_public_key_decode_d12_ns_per_op|mlkem_core_stage_sample_matrix_ns_per_op"
done
```

AVX2-only median rows from the seven repeated runs:

| Metric | ns/op |
|---|---:|
| `mlkem_core_stage_kpke_encrypt_uncached` | 5637.01 |
| `mlkem_core_stage_kpke_prepare_public_no_cache` | 4686.57 |
| `mlkem_core_stage_public_key_decode_d12` | 20.25 |
| `mlkem_core_stage_kpke_encrypt_cached` | 2436.02 |
| `mlkem_core_stage_sample_matrix` | 3325.69 |

`kpke_encrypt_uncached` and `kpke_prepare_public_no_cache` are deliberately not
nested measurements. The former is standalone K-PKE encryption with caches
disabled; it decodes the public key and samples the public matrix, but does not
compute `H(ek)`. The latter is the no-cache `mlkem_encaps()` preparation path;
it decodes the public key, samples the matrix, and computes `H(ek)` using the
accepted AVX2 public-key hash/tail co-schedule.

This rules out public-key d12 decode as a meaningful target: it is only about
20 ns. The direct K-PKE uncached-vs-cached gap is roughly 3.2 us, which matches
the standalone public-matrix sampler. The no-cache encapsulation preparation
still has about 1.36 us beyond standalone `sample_matrix`, but the one-live-lane
`keccakf4()` SHA3 continuation diagnostic was already rejected. The next useful
work should therefore reduce `sample_matrix()` itself or find a real multi-state
co-scheduling opportunity; cache-local public-key decode/hash ordering and
single-lane Keccak tricks are not large enough.

A follow-up AVX2-only keygen forward-NTT split diagnostic adds two bench-only
rows for the six keygen secret/error NTTs: `head_only` for the scalar/vectorized
upper levels before `ntt_tail_avx2()`, and `tail_only` for the lower AVX2 tail
levels using precomputed head outputs. These rows are not additive with
`keygen_noise_ntt_only`, because the split rows have their own copy/checksum
shapes, but they show where a broader forward-NTT rewrite should focus.

Command:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make bench-stages CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
for i in $(seq 1 7); do
  taskset -c 0 ./bench_core_stagesc 30000 | \
    rg "mlkem_core_stage_keygen_noise_ntt(_only|_head_only|_tail_only)?_ns_per_op|mlkem_core_stage_decrypt_u_ntt(_head|_tail)?_ns_per_op"
done
```

Median results from the 7-run AVX2-only diagnostic:

| Metric | Median ns/op |
|---|---:|
| `mlkem_core_stage_keygen_noise_ntt` | 1990.06 |
| `mlkem_core_stage_keygen_noise_ntt_only` | 1542.85 |
| `mlkem_core_stage_keygen_noise_ntt_head_only` | 951.05 |
| `mlkem_core_stage_keygen_noise_ntt_tail_only` | 951.27 |
| `mlkem_core_stage_decrypt_u_ntt` | 780.70 |
| `mlkem_core_stage_decrypt_u_ntt_head` | 492.98 |
| `mlkem_core_stage_decrypt_u_ntt_tail` | 487.26 |

Decision: do not spend the next forward-NTT work on only the head or only the
tail. Keygen's six-polynomial NTT cost is split almost evenly between the upper
levels and the AVX2 tail, and decrypt's three-polynomial split shows the same
shape. A useful next NTT optimization needs to change the full dataflow, for
example by carrying multiple polynomials through the whole transform schedule or
by redesigning the representation across NTT, K=3 accumulation, and encoding.
Another isolated l1/l2/tail tweak is unlikely to move the integrated keygen or
KEM rows robustly.


### Independent Core Optimization Diagnostic (2026-07-03, AVX2 keygen tail21 co-schedule)

A bench-only follow-up tested whether the earlier public-matrix tail-choice signal
survives the production-like keygen matrix/noise co-schedule. The current AVX2
keygen path leaves `(2,2)` as the single matrix tail and samples it in the unused
lane of the second keygen PRF/CBD `keccakf4()` call. The diagnostic instead uses
`(2,1)` as that co-scheduled tail and puts `(2,2)` into the second x4 matrix
batch, so the generated `A` matrix, `shat`, and `ehat` are identical but the XOF
suffixes assigned to the x4 batches and tail lane change.

The diagnostic adds `mlkem_core_stage_keygen_matrix_noise_tail21` and validates
it against the production `mlkem_keygen_matrix_noise_avx2()` output before
timing. Production code is unchanged.

AVX2-only command:

```bash
make bench-stages CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
for i in $(seq 1 7); do
  taskset -c 0 ./bench_core_stagesc 40000 | \
    awk -F= -v run="$i" '
      /mlkem_core_stage_keygen_matrix_noise_(current|tail_first|tail_last|tail21)_ns_per_op=|mlkem_core_stage_sample_matrix_tail_choice_(21|22)_ns_per_op=|mlkem_core_stage_kpke_keygen_full_ns_per_op=/ {
        print run, $1, $2
      }'
done
```

Tail21 co-schedule highlights:

| Metric | Avg ns/op | Median ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_matrix_tail_choice_22` | 2826.76 | 2805.94 | 1.0000x | 1.0000x |
| `mlkem_core_stage_sample_matrix_tail_choice_21` | 2792.91 | 2791.56 | 1.0121x | 1.0052x |
| `mlkem_core_stage_keygen_matrix_noise_current` | 3044.39 | 3041.21 | 1.0000x | 1.0000x |
| `mlkem_core_stage_keygen_matrix_noise_tail21` | 3053.51 | 3035.17 | 0.9970x | 1.0020x |
| `mlkem_core_stage_keygen_matrix_noise_tail_last` | 3051.17 | 3048.03 | 0.9978x | 0.9978x |

Decision: reject production tail21 co-scheduling. The generic `sample_matrix`
tail-choice row still shows a small `(2,1)` median advantage, but the keygen
co-scheduled row is not robust: median movement is only about `1.0020x`, while
average movement is negative due to layout/noise sensitivity. Keep the current
`(2,2)` keygen tail lane. Future sampler work should change the common
Keccak/store/parser work itself, not only reassign which matrix entry is the
single co-scheduled tail.


### Independent Core Optimization Diagnostic (2026-07-03, AVX2 keygen NTT head/tail batch schedule)

A bench-only follow-up tested the broader forward-NTT scheduling idea suggested by
the keygen head/tail split. Instead of transforming each CBD-derived polynomial
all the way through `ntt()` independently, the diagnostic copies all six keygen
secret/error polynomials, runs the upper forward-NTT levels for all six, and only
then runs `ntt_tail_avx2()` for all six. This is a level-schedule/dataflow test,
not a new arithmetic representation: the NTT butterflies, reductions, tail
helper, and d12 secret-key encoding are unchanged.

The diagnostic adds `mlkem_core_stage_keygen_noise_ntt_headtail_batch` and
`mlkem_core_stage_keygen_noise_ntt_encode_headtail_batch`. The helper is validated
against the existing `ntt()` outputs for both `shat[0..2]` and `ehat[0..2]` before
timing.

Initial AVX2-only diagnostic command:

```bash
make bench-stages CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
for i in $(seq 1 7); do
  taskset -c 0 ./bench_core_stagesc 40000 | \
    awk -F= -v run="$i" '
      /mlkem_core_stage_keygen_noise_ntt(_encode|_only|_headtail_batch|_encode_headtail_batch)_ns_per_op=|mlkem_core_stage_kpke_keygen_full_ns_per_op=/ {
        print run, $1, $2
      }'
done
```

Isolated batch-schedule highlights:

| Metric | Avg ns/op | Median ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_noise_ntt_only` | 1562.42 | 1561.66 | 1.0000x | 1.0000x |
| `mlkem_core_stage_keygen_noise_ntt_headtail_batch` | 1556.91 | 1556.51 | 1.0035x | 1.0033x |
| `mlkem_core_stage_keygen_noise_ntt_encode` | 1600.21 | 1599.45 | 1.0000x | 1.0000x |
| `mlkem_core_stage_keygen_noise_ntt_encode_headtail_batch` | 1596.29 | 1594.36 | 1.0025x | 1.0032x |

A production candidate then moved AVX2 keygen to the same head-then-tail batch
schedule after `mlkem_keygen_matrix_noise_avx2()`. Correctness passed, but the
KEM confirmation rejected the change.

Production-candidate A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage,kem STAGE_ITERS=50000 KEM_ITERS=25000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Production-candidate rejection highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_kpke_keygen_full` | 4819.87 | 4811.37 | 1.0018x | 0.9981x |
| `mlkem_core_stage_keygen_noise_ntt_encode` | 1600.97 | 1600.89 | 1.0001x | 0.9996x |
| `mlkem_keygen` | 6923.29 | 6994.59 | 0.9898x | 0.9960x |
| `mlkem_keygen_core` | 6901.88 | 6942.65 | 0.9941x | 0.9970x |
| `mlkem_roundtrip_core` | 20139.32 | 20119.21 | 1.0010x | 0.9979x |

Decision: reject production head/tail batching. The isolated rows show that the
coarse six-polynomial schedule can save a few ns, but the improvement is too
small to survive full keygen/KEM code-shape effects. Keep the existing per-index
`ntt(shat[i]) -> encode(shat[i]) -> ntt(ehat[i])` order. Future keygen NTT work
needs a larger representation or arithmetic change across the whole transform,
not only a head/tail phase reorder.


### Independent Core Optimization Diagnostic (2026-07-02, AVX2 keygen ehat lazy NTT add)

An AVX2-only keygen representation experiment was rejected. The candidate kept
`shat` on the public `ntt()` path because it is encoded into the secret key and
used by NTT-domain multiplication, but routed `ehat` through the internal lazy
forward-NTT variant and fused its final canonicalization into `that += ehat`.
The fused add used two conditional subtracts so the public-key `byte_encode(12)`
still received canonical coefficients.

This is the same representation idea that works for encryption `rhat[]` and
decryption `u[]` multiplication inputs, but keygen is different: `ehat[]` feeds a
public-key add-and-encode boundary immediately after the NTT, so the saved
canonicalization pass is mostly paid back by the wider add-side reduction.

Correctness passed the AVX2-only gate:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage,kem STAGE_ITERS=70000 \
  KEM_ITERS=30000 C_COMPILER=clang PIN_CPU=0 \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" ./scripts/bench_core_ab.sh HEAD
```

Rejected highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_noise_ntt` | 1992.53 | 1992.81 | 0.9999x | 0.9997x |
| `mlkem_core_stage_keygen_noise_ntt_only` | 1544.94 | 1544.70 | 1.0002x | 0.9993x |
| `mlkem_core_stage_kpke_keygen_full` | 4921.60 | 4951.49 | 0.9940x | 0.9967x |
| `mlkem_core_stage_encrypt_noise_ntt` | 789.58 | 790.63 | 0.9987x | 0.9988x |
| `mlkem_keygen_core` | 7022.91 | 7052.69 | 0.9958x | 0.9962x |
| `mlkem_roundtrip_core` | 20874.68 | 20771.12 | 1.0050x | 0.9979x |

Decision: keep keygen `ehat[]` on the canonical public `ntt()` path. The lazy
representation is still useful for values consumed directly by `ntt_mul_acc3()`,
but not for this add-and-encode boundary. Future keygen NTT work should avoid
this narrow ehat-only fusion and instead change a larger representation boundary
that covers NTT, accumulation, and public-key encoding together.


A bench-only one-lane `keccakf4()` diagnostic rejects another tempting Keccak
state-layout shortcut. The idea was to continue the public-key SHA3-256 hash in
lane 0 of the existing x4 state after the matrix-tail co-schedule, instead of
switching the remaining public-key hash blocks back to scalar `keccakf()`. The
new diagnostic hashes the fixed 1184-byte ML-KEM public key with only lane 0 of
`keccakf4()` and validates the output against the existing scalar `sha3_256()`.

Command:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make bench-keccak CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
for i in $(seq 1 7); do
  taskset -c 0 ./bench_keccakc 100000 | \
    rg "mlkem_keccakf4?_ns_per_op|mlkem_sha3_256_public_key(_lane0_keccakf4)?_ns_per_op"
done
```

Median results from the 7-run AVX2-only diagnostic:

| Metric | Median ns/op |
|---|---:|
| `mlkem_keccakf` | 217.49 |
| `mlkem_keccakf4` | 287.21 |
| `mlkem_sha3_256_public_key` | 1974.23 |
| `mlkem_sha3_256_public_key_lane0_keccakf4` | 3728.44 |

Decision: reject productionizing one-live-lane `keccakf4()` for the public-key
hash continuation. It is about 1.89x slower than the scalar public-key SHA3 path
for this fixed-length input, even though it reuses the same AVX2 permutation
primitive. The x4 Keccak path should only be used when it can carry independent
SHAKE/SHA3 work in multiple lanes; otherwise the current scalar continuation is
the right code shape.

A first attempt to move the representation boundary past inverse-add and into
ciphertext compression was rejected. The AVX2-only candidate added an
encryption-only lazy final inverse-add helper that stored `u[0..2]` and `v` in
the range `[0, 2Q)` after adding `e1`/`e2+message`, then used lazy d10/d4
compressors that canonicalized each 16-bit lane once immediately before the
existing compression formulas. The goal was to remove the final modular-add
conditional subtract from inverse-add and pay a cheaper canonicalization at the
compress boundary, where the polynomials are consumed and not reused.

Correctness passed both AVX2-only and native gates:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core
```

Short AVX2-only stage/KEM A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage,kem STAGE_ITERS=50000 KEM_ITERS=20000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Short-run highlights were mixed and not sufficient for acceptance:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_kpke_encrypt_cached` | 2415.67 | 2410.24 | 1.0023x | 1.0042x |
| `mlkem_core_stage_encrypt_accum_inv` | 1321.30 | 1318.85 | 1.0019x | 0.9996x |
| `mlkem_core_stage_ciphertext_compress_encode` | 51.21 | 51.18 | 1.0006x | 1.0006x |
| `mlkem_encaps_core` | 8390.96 | 7211.24 | 1.1636x | 1.1349x |
| `mlkem_roundtrip_core` | 23240.15 | 21519.81 | 1.0799x | 1.0427x |

Longer AVX2-only KEM confirmation rejected the change:

```bash
RUNS=17 WARMUP_RUNS=3 SUITES=kem KEM_ITERS=50000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected lazy inverse-add/compress highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_encaps` | 2687.27 | 2679.73 | 1.0028x | 1.0057x |
| `mlkem_encaps_core` | 7445.94 | 7652.98 | 0.9729x | 0.9645x |
| `mlkem_roundtrip` | 13943.30 | 13965.99 | 0.9984x | 1.0006x |
| `mlkem_roundtrip_core` | 21999.85 | 22416.34 | 0.9814x | 0.9736x |

Keep the current exact inverse-add output before ciphertext compression. Moving
the final modular-add correction into d10/d4 compression is algebraically valid,
but the extra compression-side canonicalization and changed code layout do not
survive full KEM confirmation. Future broad representation work needs to remove
or merge more than this final add correction; simply sliding the same
normalization one stage later is not enough.



### Latest Core Optimization A/B (2026-07-02, AVX2 fixed-input SHAKE128 sample_ntt)

The AVX2-only scalar `sample_ntt()` fallback now builds the fixed
`rho[32] || row || col || SHAKE128-domain` state directly instead of routing the
same input through the generic `keccak_ctx` absorb/finalize/squeeze machinery.
The first three SHAKE128 rate blocks are still parsed as one 504-byte stream, so
this keeps the earlier parser shape and only removes generic context bookkeeping
from the one-lane AVX2 path. Native AVX512 builds and non-AVX2 builds keep the
previous `keccak_ctx` path; a wider unguarded change showed weak native KEM
negative noise, while the AVX2-only target is the path that actually uses scalar
`sample_ntt()` for the final public-matrix tail.

Correctness checks:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core
```

AVX2-only Keccak/stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=keccak,stage KECCAK_ITERS=200000 \
  STAGE_ITERS=50000 C_COMPILER=clang PIN_CPU=0 \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" ./scripts/bench_core_ab.sh HEAD
```

Target highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_sample_ntt_full` | 696.92 | 693.36 | 1.0051x | 1.0020x |
| `mlkem_core_stage_sample_matrix_tail` | 884.92 | 871.57 | 1.0153x | 1.0138x |
| `mlkem_core_stage_sample_matrix_tail_scalar` | 881.61 | 870.13 | 1.0132x | 1.0162x |
| `mlkem_core_stage_sample_matrix` | 3547.80 | 3511.17 | 1.0104x | 1.0025x |
| `mlkem_core_stage_kpke_encrypt_uncached` | 5869.01 | 6052.68 | 0.9697x | 1.0061x |
| `mlkem_core_stage_kpke_keygen_full` | 5665.80 | 5878.28 | 0.9639x | 0.9975x |

AVX2-only KEM confirmation:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=kem KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_keygen` | 8144.75 | 7629.60 | 1.0675x | 1.0023x |
| `mlkem_keygen_core` | 8123.05 | 7589.08 | 1.0704x | 1.0019x |
| `mlkem_encaps_core` | 7282.83 | 7261.54 | 1.0029x | 0.9983x |
| `mlkem_roundtrip` | 14531.14 | 14009.18 | 1.0373x | 1.0002x |
| `mlkem_roundtrip_core` | 22184.56 | 22072.54 | 1.0051x | 1.0072x |

Native `-march=native` on this machine defines both `__AVX2__` and
`__AVX512F__`, so it keeps the previous `keccak_ctx` route. A guarded native KEM
no-regression check with `RUNS=7`, `KEM_ITERS=30000` was neutral: median
`mlkem_keygen_core` `1.0011x`, `mlkem_encaps_core` `1.0024x`,
`mlkem_decaps_core` `1.0002x`, and `mlkem_roundtrip_core` `1.0007x`.

This is a small but genuine core cleanup: it does not use the vendored backends
or a cross-operation cache, and it speeds the remaining one-lane SHAKE128 matrix
sampler by removing generic sponge bookkeeping. It is intentionally not applied
to native/AVX512 until that target shows an integrated win.


### Independent Core Optimization Diagnostic (2026-07-02, AVX2 fixed `(2,2)` sample_ntt tail)

A narrower AVX2-only scalar tail specialization was rejected. The candidate added
a dedicated `sample_ntt_tail_22_avx2()` helper for the final public-matrix
`(2,2)` entry and routed the AVX2-only `sample_matrix()` tail through it. The
helper only replaced the runtime `row/col/domain` suffix construction with the
constant `0x1f0202`; Keccak, the initial 504-byte stream, parser, and refill path
were unchanged. The stage harness `sample_matrix_tail` row was aligned to the
production helper, while `sample_matrix_tail_scalar` kept the generic
`sample_ntt()` route for comparison.

Correctness passed the AVX2-only gate:

```bash
make test CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only Keccak/stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=keccak,stage KECCAK_ITERS=200000 \
  STAGE_ITERS=70000 C_COMPILER=clang PIN_CPU=0 \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" ./scripts/bench_core_ab.sh HEAD
```

Rejected fixed-tail highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_sample_ntt_full` | 692.19 | 688.73 | 1.0050x | 1.0047x |
| `mlkem_core_stage_sample_matrix_tail` | 866.19 | 866.84 | 0.9993x | 1.0020x |
| `mlkem_core_stage_sample_matrix_tail_scalar` | 863.91 | 864.81 | 0.9990x | 1.0016x |
| `mlkem_core_stage_sample_matrix_tail_scalar_raw` | 685.99 | 684.44 | 1.0023x | 1.0039x |
| `mlkem_core_stage_sample_matrix` | 2880.26 | 2896.52 | 0.9944x | 0.9998x |
| `mlkem_core_stage_kpke_keygen_full` | 4927.15 | 4928.48 | 0.9997x | 0.9997x |

Keep the generic AVX2-only `sample_ntt()` call for the public-matrix scalar tail.
The accepted fixed-input cleanup removed meaningful sponge context overhead, but
specializing the already-fixed `(2,2)` suffix saves only a few integer operations
and does not survive the full `sample_matrix()` or keygen stage. KEM confirmation
was skipped because the production matrix/keygen rows did not improve.

### Independent Core Optimization Diagnostic (2026-07-02, AVX2 scalar sample_ntt static stream scratch)

An AVX2-only scalar sampler scratch-placement experiment was rejected. The
candidate moved the AVX2-only `sample_ntt()` initial 504-byte `uint64_t
stream[63]` buffer from stack storage to static storage, leaving Keccak, parser,
and matrix scheduling unchanged. The target was the final one-lane `(2,2)`
public-matrix tail used by AVX2-only `sample_matrix()` after the two x4 batches;
native AVX512 and non-AVX2 builds were unaffected.

Correctness passed the AVX2-only gate:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only Keccak/stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=keccak,stage KECCAK_ITERS=200000 \
  STAGE_ITERS=50000 C_COMPILER=clang PIN_CPU=0 \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" ./scripts/bench_core_ab.sh HEAD
```

Rejected static-scratch highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_sample_ntt_full` | 689.01 | 687.26 | 1.0025x | 1.0013x |
| `mlkem_core_stage_sample_matrix_tail` | 868.67 | 869.28 | 0.9993x | 0.9997x |
| `mlkem_core_stage_sample_matrix_tail_scalar` | 865.60 | 866.13 | 0.9994x | 1.0012x |
| `mlkem_core_stage_sample_matrix_tail_scalar_raw` | 687.44 | 683.04 | 1.0064x | 1.0055x |
| `mlkem_core_stage_sample_matrix` | 2902.14 | 2920.96 | 0.9936x | 0.9997x |
| `mlkem_core_stage_kpke_keygen_full` | 4926.44 | 4962.25 | 0.9928x | 0.9982x |

Keep the scalar `sample_ntt()` stream buffer on the stack. The raw one-lane tail
row shows a small scratch-placement win, but the full tail, full matrix, and
keygen stage rows do not preserve it. Moving this buffer to static storage would
also weaken function isolation/thread-safety for no integrated core win, so no
KEM confirmation was run.


### Independent Core Optimization Diagnostic (2026-07-02, AVX2 x4 PRF/CBD inline boundary)

An AVX2 x4 PRF/CBD function-boundary experiment was rejected. The candidate
marked `sample_poly_cbd_eta2x4_state_avx2()` and `mlkem_prf_cbd_eta2x4_32()` as
`MLKEM_ALWAYS_INLINE`, leaving x2/x3 helpers and all arithmetic unchanged. The
hypothesis was that, after the accepted `keccakf4()` inline-boundary win, the
thin x4 PRF/CBD wrapper might similarly avoid call/alias overhead in the keygen
and encryption noise batches.

Correctness passed both gates:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core
```

AVX2-only stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage,kem STAGE_ITERS=70000 KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_encrypt_noise_prf_cbd` | 1170.54 | 1159.09 | 1.0099x | 1.0139x |
| `mlkem_core_stage_encrypt_noise` | 1394.45 | 1379.52 | 1.0108x | 1.0109x |
| `mlkem_core_stage_keygen_noise_prf_cbd` | 981.61 | 985.29 | 0.9963x | 0.9869x |
| `mlkem_core_stage_keygen_noise_ntt` | 1993.95 | 1998.06 | 0.9979x | 0.9936x |
| `mlkem_keygen_core` | 7930.61 | 8160.08 | 0.9719x | 0.9965x |
| `mlkem_encaps_core` | 7511.51 | 7299.73 | 1.0290x | 1.0022x |
| `mlkem_roundtrip` | 14374.66 | 14590.94 | 0.9852x | 0.9973x |
| `mlkem_roundtrip_core` | 22687.98 | 22314.49 | 1.0167x | 1.0406x |

Keep the current x4 PRF/CBD helper boundaries. The inline attribute helps the
encryption noise stage, but it perturbs the keygen x4+x2 composition and top-level
roundtrip enough that the broader KEM path does not justify the code-size/layout
change. This is another instance where `keccakf4()` itself benefits from boundary
removal, but surrounding decode helpers should stay compiler-shaped unless the
keygen rows move with the local stage.

### Independent Core Optimization Diagnostic (2026-07-02, AVX2 fixed-nonce PRF/CBD state setup)

An AVX2-only fixed-nonce PRF/CBD setup experiment was rejected. The candidate
kept the existing generic `mlkem_prf_cbd_eta2x2_32()`, `x3`, and `x4` helpers for
bench diagnostics, but routed production fixed nonce groups through dedicated
helpers that built Keccak `st[4]` from immediate vectors instead of local
`uint8_t nonce[]` arrays. This targeted the keygen `{0,1,2,3}` plus `{4,5}`
noise groups, the encryption `{0,1,2,3}` plus `{4,5,6}` groups, and the existing
public-tail/noise co-scheduled paths.

Correctness passed the AVX2-only gate:

```bash
make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage,kem STAGE_ITERS=70000 KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected fixed-nonce highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_noise_prf_cbd` | 974.95 | 985.52 | 0.9893x | 0.9934x |
| `mlkem_core_stage_encrypt_noise_prf_cbd` | 1174.45 | 1180.08 | 0.9952x | 0.9952x |
| `mlkem_core_stage_encrypt_noise_prf_cbd_tail_cosched` | 1118.43 | 1116.59 | 1.0017x | 1.0014x |
| `mlkem_core_stage_kpke_keygen_full` | 4835.86 | 4876.11 | 0.9917x | 0.9974x |
| `mlkem_core_stage_kpke_encrypt_uncached` | 4935.68 | 4975.02 | 0.9921x | 0.9966x |
| `mlkem_keygen_core` | 6933.33 | 7082.15 | 0.9790x | 0.9980x |
| `mlkem_encaps_core` | 6980.42 | 7072.49 | 0.9870x | 1.0044x |
| `mlkem_roundtrip_core` | 20118.80 | 20343.88 | 0.9889x | 0.9998x |

Decision: keep the current nonce-array helper shape. Fixed immediates save only
a few setup instructions before a full Keccak permutation, while the extra helper
bodies and changed code layout make the main keygen/encryption PRF/CBD stages
slower. The tiny tail co-scheduled row improvement is not enough to accept a
change that regresses the common noise paths.

### Independent Core Optimization Diagnostic (2026-07-02, AVX2 sample_ntt4 fixed matrix batches)

An AVX2-only public-matrix sampler specialization was rejected. The candidate
split `sample_ntt4()` into an internal helper taking a prebuilt `st[4]` Keccak
lane and routed the two fixed public-matrix x4 batches through wrappers with
constant lane values. The generic `sample_ntt4(row[], col[])` wrapper remained
for diagnostics. The intent was to remove the fixed row/column loads and lane
construction from the hottest `sample_matrix` batches without changing the
parser, Keccak rounds, stream layout, or cached data.

Correctness passed both gates before the candidate was reverted:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core
```

AVX2-only stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage,kem STAGE_ITERS=70000 KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected fixed-batch highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_matrix_x4_batch0` | 1437.73 | 1635.21 | 0.8792x | 0.9174x |
| `mlkem_core_stage_sample_matrix_x4_batch1` | 1531.94 | 1744.62 | 0.8781x | 0.9162x |
| `mlkem_core_stage_sample_matrix` | 3466.53 | 3879.13 | 0.8936x | 0.9290x |
| `mlkem_core_stage_sample_ntt4_full_raw` | 1245.29 | 1444.09 | 0.8623x | 0.9049x |
| `mlkem_core_stage_kpke_keygen_full` | 5570.33 | 5615.33 | 0.9920x | 0.9521x |
| `mlkem_keygen_core` | 7593.00 | 8243.48 | 0.9211x | 0.9654x |
| `mlkem_encaps_core` | 7600.88 | 7632.88 | 0.9958x | 0.9750x |
| `mlkem_roundtrip_core` | 22115.38 | 23070.17 | 0.9586x | 0.9739x |

Keep the existing generic `sample_ntt4()` call shape for AVX2-only public matrix
batches. The fixed row/column lane construction is not a real bottleneck next to
three `keccakf4()` permutations, stream transpose, and rejection parsing. This
wrapper split also worsens code layout/inlining enough to regress the very rows
it targets. A future fixed-batch attempt would need to remove larger work inside
the sampler itself, not only precompute `st[4]`.

A related `sample_ntt4()` function-boundary experiment was also rejected. The
candidate marked the generic AVX2 x4 public-matrix sampler `MLKEM_NOINLINE` to
test whether keeping the large sampler body out of callers improves instruction
cache pressure or code layout after the fixed-batch split regressed badly. The
parser, Keccak rounds, stream layout, and call sites were otherwise unchanged.
Correctness passed both AVX2-only and native tests, but the target medians did
not move and KEM medians were neutral to slightly negative, so the source change
was reverted.

AVX2-only stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage,kem STAGE_ITERS=70000 KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected noinline highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_matrix_x4_batch0` | 1618.91 | 1509.43 | 1.0725x | 0.9988x |
| `mlkem_core_stage_sample_matrix_x4_batch1` | 1729.18 | 1608.32 | 1.0752x | 1.0023x |
| `mlkem_core_stage_sample_matrix` | 3843.10 | 3610.02 | 1.0646x | 1.0009x |
| `mlkem_core_stage_sample_ntt4_full_raw` | 1430.75 | 1321.59 | 1.0826x | 0.9998x |
| `mlkem_core_stage_kpke_keygen_full` | 5642.84 | 5320.46 | 1.0606x | 1.0002x |
| `mlkem_keygen_core` | 7554.70 | 7796.67 | 0.9690x | 0.9991x |
| `mlkem_encaps_core` | 7590.92 | 7246.47 | 1.0475x | 1.0379x |
| `mlkem_roundtrip_core` | 22389.62 | 21948.73 | 1.0201x | 0.9994x |

Keep `sample_ntt4()` compiler-shaped. The direct sampler and matrix medians are
flat, and the positive average/core side rows are not enough to accept a pure
code-layout boundary change. Future public-matrix sampler work should remove or
restructure actual Keccak/parse work rather than only changing inlining.

### Independent Core Optimization Diagnostic (2026-07-02, AVX2 sample_ntt4 refill scratch)

An AVX2 x4 public-matrix sampler scratch experiment was rejected. The candidate
moved the `sample_ntt4()` refill `extra[4][168]` buffer from the stack to static
storage, matching the already-static common `stream[4][504]` scratch. This did
not add a new reentrancy limitation because the function already uses static
stream scratch; the intent was only to reduce stack-frame pressure around the
rare refill path without changing Keccak rounds, parsing, or output data.

Correctness passed both gates before the candidate was reverted:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core
```

AVX2-only stage A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected refill-scratch highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_matrix_x4_batch0` | 1437.30 | 1641.58 | 0.8756x | 0.9169x |
| `mlkem_core_stage_sample_matrix_x4_batch1` | 1531.37 | 1757.61 | 0.8713x | 0.9077x |
| `mlkem_core_stage_sample_matrix` | 3462.86 | 3895.26 | 0.8890x | 0.9246x |
| `mlkem_core_stage_sample_ntt4_full_raw` | 1249.15 | 1449.88 | 0.8616x | 0.9050x |
| `mlkem_core_stage_kpke_prepare_public_no_cache` | 4816.79 | 5245.96 | 0.9182x | 0.9464x |
| `mlkem_core_stage_kpke_keygen_full` | 5620.38 | 5884.81 | 0.9551x | 0.9529x |
| `mlkem_core_stage_sample_ntt4_refill_keccak_store1` | 283.55 | 283.78 | 0.9992x | 1.0000x |
| `mlkem_core_stage_sample_ntt4_refill_step_once` | 308.87 | 309.38 | 0.9983x | 1.0008x |

Do not move the x4 refill scratch to static storage. The direct refill probes are
neutral because refills are rare, while the full x4 sampler and public-matrix
rows regress substantially. This reinforces the earlier sampler diagnosis: the
next useful work must reduce or restructure the common three-rate Keccak/state
path, not adjust rare-path scratch placement. No KEM confirmation was run because
the direct sampler target rows already failed.

### Latest Core Optimization A/B (2026-07-02, AVX2 encrypt public-tail/noise co-scheduling)

The AVX2-only `kpke_encrypt()` public-cache-miss path now co-schedules the final
public-matrix tail entry with encryption noise generation when `rlen == 32`. The
first two public-matrix x4 batches still use `sample_ntt4()`. The final `(2,2)`
tail uses lane 2 of the second encryption PRF/CBD `keccakf4()` call, while lanes
0, 1, and 3 carry nonces 4, 5, and 6 for `e1[1]`, `e1[2]`, and `e2`. The
remaining tail SHAKE128 blocks continue with scalar `keccakf()`, matching the
accepted keygen tail scalar-continuation design.

This change is intentionally narrow. It does not change the cached public-key
path, the existing `kpke_encrypt_prepared_public()` source shape, AVX512/native
paths, or the no-cache encapsulation `H(ek)` public-prepare co-schedule. It only
applies when `kpke_encrypt()` has to prepare the public matrix and generate
32-byte encryption noise in the same operation.

Correctness checks:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core
```

Bench-only tail/noise diagnostic, seven repeated `30000`-iteration runs,
pinned CPU 0, `clang`, AVX2-only:

| Metric | Median ns/op |
|---|---:|
| `mlkem_core_stage_encrypt_noise_prf_cbd_tail_separate` | 1331.97 |
| `mlkem_core_stage_encrypt_noise_prf_cbd_tail_cosched` | 1116.96 |

The diagnostic uses a lightweight sink and is only meant to compare those two
rows directly. It shows that putting the first tail block into the otherwise
underfilled nonce 4/5/6 PRF `keccakf4()` call removes about 215 ns from the
combined tail-plus-noise work before integrating it into `kpke_encrypt()`.

AVX2-only stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage,kem STAGE_ITERS=70000 KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Stage/KEM highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_kpke_encrypt_uncached` | 5995.94 | 5407.33 | 1.1089x | 1.0457x |
| `mlkem_core_stage_kpke_encrypt_cached` | 2441.67 | 2440.32 | 1.0006x | 0.9983x |
| `mlkem_core_stage_encrypt_noise_prf_cbd` | 1172.42 | 1174.38 | 0.9983x | 0.9993x |
| `mlkem_encaps` | 2703.40 | 2687.03 | 1.0061x | 1.0012x |
| `mlkem_encaps_core` | 7538.03 | 7313.11 | 1.0308x | 0.9995x |
| `mlkem_roundtrip_core` | 22521.54 | 21962.59 | 1.0254x | 1.0309x |

Longer AVX2-only KEM confirmation:

```bash
RUNS=17 WARMUP_RUNS=4 SUITES=kem KEM_ITERS=50000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_encaps` | 2693.98 | 2711.01 | 0.9937x | 1.0011x |
| `mlkem_encaps_core` | 7802.90 | 7581.30 | 1.0292x | 1.0011x |
| `mlkem_keygen_core` | 7655.38 | 7777.19 | 0.9843x | 1.0012x |
| `mlkem_roundtrip_core` | 22534.40 | 22289.25 | 1.0110x | 1.0122x |

Keep the co-schedule. The direct target, `kpke_encrypt_uncached`, keeps a clear
median win, while the longer KEM confirmation does not show a full-path median
regression. The result also reinforces the current sampler direction: useful
wins come from filling otherwise unused Keccak SIMD lanes with real independent
work, not from cache reuse, parser bookkeeping, or rare-path scratch placement.


### Independent Core Optimization Diagnostic (2026-07-03, AVX2 encrypt PRF/tail noinline)

A follow-up AVX2-only call-boundary experiment on the same encrypt PRF/tail
co-schedule was rejected. The candidate changed only
`mlkem_encrypt_prf_cbd_eta2_32_sample_tail_avx2()` from a normal `static` helper
to `MLKEM_NOINLINE`, leaving the Keccak lane filling, lane-2 tail extraction,
scalar tail continuation, parser, and output values unchanged. The hypothesis was
that keeping this large mixed PRF/tail helper out of the `kpke_encrypt()` cache
miss body might reduce caller code pressure, analogous to prior accepted and
rejected boundary cleanups.

Correctness passed the AVX2-only gate:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected encrypt PRF/tail noinline highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_encrypt_noise_prf_cbd_tail_cosched` | 1119.59 | 1121.28 | 0.9985x | 0.9998x |
| `mlkem_core_stage_encrypt_noise_prf_cbd` | 1172.57 | 1171.36 | 1.0010x | 1.0011x |
| `mlkem_core_stage_kpke_encrypt_uncached` | 4901.23 | 4889.08 | 1.0025x | 1.0002x |
| `mlkem_core_stage_kpke_encrypt_cached` | 2417.06 | 2424.25 | 0.9970x | 0.9976x |
| `mlkem_core_stage_kpke_prepare_public_no_cache` | 4167.18 | 4167.72 | 0.9999x | 1.0004x |
| `mlkem_core_stage_sample_matrix` | 2804.08 | 2802.15 | 1.0007x | 1.0003x |

Decision: keep the encrypt PRF/tail co-schedule helper inlineable. The direct
co-scheduled row does not improve, and the tiny uncached-encrypt median movement
is not supported by a clear target-row win. No KEM confirmation was run because
the stage gate failed. Future work at this boundary should add real lane-filled
work or remove a Keccak/state extraction, not only move the function boundary.

### Independent Core Optimization Diagnostic (2026-07-03, AVX2 rowwise uncached encrypt boundary)

A bench-only AVX2 diagnostic tested whether the uncached encryption path should
break the public-matrix materialization boundary. The diagnostic keeps the same
outputs as `kpke_encrypt()` with internal caches disabled, but changes the local
order: generate encryption noise plus the `(2,2)` matrix tail first, transform
`rhat[0..2]`, then sample the first x4 public-matrix batch and immediately
consume row 0, sample the second x4 batch and consume rows 1 and 2. This tests
whether a rowwise public-matrix use pattern can beat the current prepare-then-use
shape without relying on cache reuse.

The benchmark harness validates the rowwise ciphertext byte-for-byte against the
current cache-disabled `kpke_encrypt()` before timing.

AVX2-only command:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make bench-stages CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
for i in $(seq 1 9); do
  taskset -c 0 ./bench_core_stagesc 40000 | \
    awk -F= -v run="$i" '/mlkem_core_stage_kpke_encrypt_uncached(_rowwise)?_ns_per_op=|mlkem_core_stage_kpke_encrypt_cached_ns_per_op=|mlkem_core_stage_sample_matrix_ns_per_op=/{print run, $1, $2}'
done
```

AVX2-only results:

| Metric | Avg ns/op | Median ns/op |
|---|---:|---:|
| `mlkem_core_stage_kpke_encrypt_uncached` | 4872.76 | 4872.90 |
| `mlkem_core_stage_kpke_encrypt_uncached_rowwise` | 4869.08 | 4867.46 |
| `mlkem_core_stage_kpke_encrypt_cached` | 2392.09 | 2389.89 |
| `mlkem_core_stage_sample_matrix` | 2817.66 | 2812.90 |

Relative rowwise speedup was only `1.0008x` average and `1.0011x` median.
Decision: keep this as a diagnostic and do not change production. The rowwise
schedule removes no Keccak work, no rejection parsing, and no K=3 arithmetic; it
only changes when sampled rows are consumed. The result is effectively noise-sized
and does not justify adding a second uncached encryption implementation. Future
work at this boundary still needs a real multi-state co-schedule or a sampler /
accumulator representation change, not just rowwise consumption of the existing
public-matrix layout.

### Independent Core Optimization Diagnostic (2026-07-03, AVX2 uncached encrypt tail21)

A full cache-miss encryption diagnostic retested the persistent `(2,1)`
public-matrix tail-choice signal in the actual co-scheduled encryption dataflow.
The row keeps the first x4 batch unchanged, samples `(1,1)`, `(1,2)`, `(2,0)`,
and `(2,2)` in the second x4 batch, and co-schedules encryption PRF/CBD with
the scalar `(2,1)` tail. The diagnostic validates the ciphertext byte-for-byte
against the current cache-disabled `kpke_encrypt()` before timing. Production is
unchanged in this commit.

AVX2-only command:

```bash
make bench-stages CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
for i in $(seq 1 9); do
  taskset -c 0 ./bench_core_stagesc 40000 | \
    awk -F= -v run="$i" '/mlkem_core_stage_kpke_encrypt_uncached(_rowwise|_tail21)?_ns_per_op=|mlkem_core_stage_sample_matrix(_tail_choice_(21|22))?_ns_per_op=|mlkem_core_stage_encrypt_noise_prf_cbd_tail_cosched(_lazy)?_ns_per_op=/{print run, $1, $2}'
done
```

AVX2-only results:

| Metric | Avg ns/op | Median ns/op |
|---|---:|---:|
| `mlkem_core_stage_kpke_encrypt_uncached` | 4904.04 | 4875.94 |
| `mlkem_core_stage_kpke_encrypt_uncached_rowwise` | 4931.03 | 4878.38 |
| `mlkem_core_stage_kpke_encrypt_uncached_tail21` | 4876.41 | 4858.93 |
| `mlkem_core_stage_sample_matrix` | 2820.94 | 2809.88 |
| `mlkem_core_stage_sample_matrix_tail_choice_21` | 2805.72 | 2790.98 |
| `mlkem_core_stage_sample_matrix_tail_choice_22` | 2821.60 | 2808.40 |
| `mlkem_core_stage_encrypt_noise_prf_cbd_tail_cosched` | 1112.90 | 1111.69 |
| `mlkem_core_stage_encrypt_noise_prf_cbd_tail_cosched_lazy` | 1673.76 | 1672.80 |

The integrated tail21 row is `1.0057x` average and `1.0035x` median faster than
the current cache-disabled `kpke_encrypt()` row, and `1.0112x` average /
`1.0040x` median faster than the earlier rowwise diagnostic. This is still a
small signal, but it is stronger than the standalone tail-choice row because it
measures the full co-scheduled K-PKE encryption boundary.

A follow-up production candidate changed the AVX2 `kpke_encrypt()` cache-miss
path to use the `(2,1)` co-scheduled tail and put `(2,2)` in the second x4
public-matrix batch. Correctness passed the AVX2-only gate, and the direct stage
row improved, but cached KEM medians regressed enough to reject the production
change.

Correctness and A/B commands:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
RUNS=9 WARMUP_RUNS=2 SUITES=kem KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Production-candidate stage highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_kpke_encrypt_cached` | 2445.74 | 2393.38 | 1.0219x | 1.0020x |
| `mlkem_core_stage_kpke_encrypt_uncached` | 4930.34 | 4847.49 | 1.0171x | 1.0069x |
| `mlkem_core_stage_kpke_encrypt_uncached_tail21` | 4857.72 | 4860.32 | 0.9995x | 1.0014x |
| `mlkem_core_stage_kpke_prepare_public_no_cache` | 4156.18 | 4231.71 | 0.9821x | 0.9997x |

Production-candidate KEM highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_decaps` | 3596.32 | 3628.66 | 0.9911x | 0.9960x |
| `mlkem_decaps_core` | 5995.70 | 6051.82 | 0.9907x | 0.9974x |
| `mlkem_encaps` | 2657.98 | 2661.15 | 0.9988x | 0.9992x |
| `mlkem_encaps_core` | 7053.24 | 6908.83 | 1.0209x | 0.9890x |
| `mlkem_keygen_core` | 6872.80 | 6900.88 | 0.9959x | 0.9985x |
| `mlkem_roundtrip_core` | 20135.35 | 20027.95 | 1.0054x | 0.9993x |

Decision: keep `kpke_encrypt_uncached_tail21` as a diagnostic row only and leave
production on the existing `(2,2)` co-scheduled tail. The direct K-PKE row is
positive, but the helper duplication and changed hardcoded public-matrix grouping
do not survive KEM median confirmation. Future tail work needs to remove shared
work or redesign the helper so the direct K-PKE gain does not come with wider
code-layout cost.

A narrower follow-up tested that exact hypothesis by avoiding the duplicated
helper body: the existing encryption PRF/tail helper was split into a shared
`tail_suffix` implementation plus the original `(2,2)` wrapper, and only the
AVX2 `kpke_encrypt()` cache-miss path called the shared helper with `(2,1)`.
This preserved correctness but failed the stage gate, so KEM confirmation was not
run.

Shared-helper candidate command:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
RUNS=7 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=50000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Shared-helper stage highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_kpke_encrypt_cached` | 2397.62 | 2448.53 | 0.9792x | 1.0002x |
| `mlkem_core_stage_kpke_encrypt_uncached` | 4872.61 | 4913.62 | 0.9917x | 1.0029x |
| `mlkem_core_stage_kpke_encrypt_uncached_tail21` | 4862.61 | 4861.83 | 1.0002x | 0.9993x |
| `mlkem_core_stage_kpke_prepare_public_no_cache` | 4148.31 | 4147.20 | 1.0003x | 1.0008x |
| `mlkem_core_stage_sample_matrix` | 2800.96 | 2830.65 | 0.9895x | 0.9960x |
| `mlkem_core_stage_sample_matrix_x4_batch1` | 1180.67 | 1213.98 | 0.9726x | 0.9860x |
| `mlkem_core_stage_encrypt_noise_prf_cbd_tail_cosched_lazy` | 1671.08 | 1677.11 | 0.9964x | 0.9995x |

This closes the local tail21 route for now. Removing helper duplication did not
make the signal robust; the direct uncached median improved only `1.0029x` while
the average regressed, and the diagnostic tail21 row itself regressed by median.
The next candidate should avoid hardcoded tail rotation and instead remove work
from the public-matrix or NTT/accumulation dataflow.

### Independent Core Optimization Diagnostic (2026-07-03, AVX2 public prepare tail21)

A no-cache public-preparation diagnostic tested whether the earlier standalone
`(2,1)` tail-choice signal survives the actual `H(ek)` + public-matrix
co-schedule. The row keeps the first x4 batch unchanged, samples `(1,1)`,
`(1,2)`, `(2,0)`, and `(2,2)` in the second x4 batch, and co-schedules `H(ek)`
with the scalar `(2,1)` tail. The diagnostic validates `h`, decoded public-key
polynomials, and all generated `A^T` entries against the current
`kpke_prepare_public_no_cache()` path before timing. Production is unchanged.

AVX2-only command:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make bench-stages CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
for i in $(seq 1 9); do
  taskset -c 0 ./bench_core_stagesc 40000 | \
    awk -F= -v run="$i" '/mlkem_core_stage_kpke_prepare_public_no_cache(_tail21)?_ns_per_op=|mlkem_core_stage_sample_matrix(_tail_choice_(21|22))?_ns_per_op=|mlkem_core_stage_kpke_encrypt_uncached_tail21_ns_per_op=/{print run, $1, $2}'
done
```

AVX2-only results:

| Metric | Avg ns/op | Median ns/op |
|---|---:|---:|
| `mlkem_core_stage_kpke_prepare_public_no_cache` | 4497.18 | 4285.02 |
| `mlkem_core_stage_kpke_prepare_public_no_cache_tail21` | 4555.28 | 4298.70 |
| `mlkem_core_stage_sample_matrix` | 2811.59 | 2806.33 |
| `mlkem_core_stage_sample_matrix_tail_choice_21` | 2808.70 | 2798.69 |
| `mlkem_core_stage_sample_matrix_tail_choice_22` | 2832.51 | 2828.67 |
| `mlkem_core_stage_kpke_encrypt_uncached_tail21` | 4885.23 | 4863.84 |

The integrated public-prepare tail21 row is slower than the current row:
`0.9872x` average and `0.9968x` median. This rejects the public-prepare tail
rotation as a production candidate. The standalone sampler still shows
`tail_choice_21` faster than `tail_choice_22` in this run, but the advantage does
not survive the surrounding `H(ek)` co-schedule and full no-cache public
preparation boundary. Future work should not spend more effort on hardcoded
`(2,1)` tail routing unless a broader schedule removes Keccak or parser work.

### Independent Core Optimization Diagnostic (2026-07-03, AVX2 sample_ntt4_one lane0 extract)

A narrow production candidate tested the remaining one-lane x4 public-matrix
tail sampler. `sample_ntt4_one()` extracted lane 0 from each `keccakf4()` state
word by storing the full `__m256i` to a temporary `uint64_t words[4]` and reading
`words[0]`. The candidate replaced that with direct low-lane extraction via
`_mm256_castsi256_si128()` and `_mm_cvtsi128_si64()`, and applied the same shape
to the stage helper used by the `sample_ntt4_one_keccak_store3` split row.
Correctness passed the short AVX2 stage validation, but the full stage gate did
not support the change, so production was restored.

AVX2-only stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected candidate highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_one_full_raw` | 882.98 | 882.82 | 1.0002x | 0.9995x |
| `mlkem_core_stage_sample_ntt4_one_keccak_store3` | 851.55 | 849.39 | 1.0025x | 0.9994x |
| `mlkem_core_stage_sample_matrix_tail` | 868.07 | 868.87 | 0.9991x | 0.9950x |
| `mlkem_core_stage_sample_matrix` | 2797.43 | 2803.16 | 0.9980x | 0.9980x |
| `mlkem_core_stage_keygen_matrix_noise_current` | 3025.26 | 3033.92 | 0.9971x | 0.9966x |
| `mlkem_core_stage_kpke_keygen_full` | 4755.56 | 4764.93 | 0.9980x | 0.9994x |

Decision: reject the direct lane0 extraction. The apparent store split-row
average win does not hold on median, and the integrated `sample_matrix`,
keygen matrix/noise, and full K-PKE keygen rows regress. The compiler/codegen
for the existing full-vector store is good enough here, and the one-lane tail is
not currently a useful bottleneck. Future sampler work should target fewer
Keccak/parser passes rather than this extraction micro-shape.

### Independent Core Optimization Diagnostic (2026-07-03, AVX2 `H(ek)`/tail order)

A narrow public-preparation dataflow candidate reordered
`sha3_256_sample_ntt_tail_avx2()`. The current helper co-schedules the first
three `H(ek)` SHA3-256 blocks with the scalar public-matrix tail, then parses the
tail stream before finishing the remaining `H(ek)` blocks. The candidate copied
the lane-0 hash state after the first three co-scheduled blocks, finished
`H(ek)` immediately, and parsed the lane-1 tail stream afterward. The hypothesis
was that `hst[25]` would no longer stay live across the rejection parser and
refill loop. Correctness passed the AVX2-only core gate, but the stage gate
rejected it, so production was restored.

AVX2-only stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected candidate highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_kpke_prepare_public_no_cache` | 4267.81 | 4510.06 | 0.9463x | 0.9940x |
| `mlkem_core_stage_kpke_prepare_public_no_cache_tail21` | 4304.01 | 4312.84 | 0.9980x | 1.0011x |
| `mlkem_core_stage_sample_matrix_tail` | 866.22 | 875.64 | 0.9892x | 0.9903x |
| `mlkem_core_stage_sample_matrix` | 2811.64 | 2819.47 | 0.9972x | 0.9978x |
| `mlkem_core_stage_kpke_keygen_full` | 4761.92 | 4752.48 | 1.0020x | 1.0001x |
| `mlkem_core_stage_kpke_encrypt_uncached` | 4910.24 | 4883.93 | 1.0054x | 0.9993x |

Decision: reject the `H(ek)`-first ordering. The intended lifetime reduction does
not improve the direct no-cache public-preparation row, and the tail/sampler
rows regress. Keep parsing the co-scheduled tail stream before finishing the
remaining scalar hash blocks; future work at this boundary needs to remove
Keccak/parser work, not just reorder independent consumers of the same
co-scheduled state.

### Independent Core Optimization Diagnostic (2026-07-02, AVX2 decrypt final-l1 accumulation fusion)

A decrypt-only AVX2 final forward-NTT fusion experiment was rejected. The
candidate changed the ciphertext `u[0..2]` path to run each forward NTT only
through the `l2` tail stage, then computed the final `l1` pair values inside a
new K=3 accumulation helper instead of storing the final NTT output and reloading
it in `ntt_mul_acc3()`. The intended win was to remove the final-l1 store/reload
boundary for decrypt inputs that are consumed exactly once by the secret
accumulation.

Native and AVX2-only correctness gates passed:

```bash
make clean CC=clang AVX2_BACKEND=core && make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
make clean CC=clang AVX2_BACKEND=core && make test CC=clang AVX2_BACKEND=core
```

AVX2-only stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage,kem STAGE_ITERS=70000 KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected final-l1 accumulation fusion highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_decrypt_ntt_accum_only` | 859.89 | 896.99 | 0.9586x | 0.9475x |
| `mlkem_core_stage_decrypt_ntt_accum_recover` | 877.25 | 929.38 | 0.9439x | 0.9438x |
| `mlkem_core_stage_kpke_decrypt_cached` | 910.05 | 962.92 | 0.9451x | 0.9414x |
| `mlkem_core_stage_kpke_decrypt_uncached` | 930.86 | 977.51 | 0.9523x | 0.9439x |
| `mlkem_decaps` | 3642.98 | 3684.84 | 0.9886x | 0.9834x |
| `mlkem_decaps_core` | 6840.06 | 6608.68 | 1.0350x | 1.0665x |
| `mlkem_roundtrip_core` | 22381.27 | 21644.69 | 1.0340x | 1.0351x |

Keep the existing AVX2 decrypt sequence: lazy final-l1 NTT output stored in
`u[i]`, followed by the scalar K=3 accumulation. The contradictory positive KEM
core medians are not a reliable acceptance signal because the direct boundary and
K-PKE decrypt stage regressed by roughly 5-6%, and top-level decapsulation also
moved negative. This scalar final-l1 fusion loses the existing AVX2 vectorized
final-l1 helper; a future fusion attempt would need to carry the final-l1 values
into a SIMD accumulation design rather than scalarizing the boundary.

### Latest Core Optimization A/B (2026-07-02, AVX2 d12 encode mask elision)

The AVX2-only d12 byte encoder now skips the pack-time `& 0x0fff` when AVX512BW
is not enabled. Production d12 encodes in this implementation receive canonical
ML-KEM coefficients in `[0, Q)`, and the existing d12 test inputs are already
12-bit values, so the mask is redundant for the valid inputs this helper packs.
Native AVX512BW builds keep the previous masked sequence because an unguarded
mask removal regressed native KEM measurements.

Correctness checks:

```bash
make clean CC=clang AVX2_BACKEND=core && make test CC=clang AVX2_BACKEND=core
make clean CC=clang AVX2_BACKEND=core && make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage,kem STAGE_ITERS=70000 KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Stage/KEM highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_accum_encode` | 484.99 | 483.02 | 1.0041x | 1.0032x |
| `mlkem_core_stage_keygen_noise_ntt_encode` | 1567.16 | 1564.47 | 1.0017x | 1.0017x |
| `mlkem_core_stage_keygen_secret_encode_only` | 36.50 | 36.44 | 1.0017x | 1.0036x |
| `mlkem_core_stage_keygen_public_encode_only` | 36.28 | 36.27 | 1.0002x | 1.0006x |
| `mlkem_keygen_core` | 7889.42 | 7774.11 | 1.0148x | 1.0012x |

Longer AVX2-only KEM confirmation with `RUNS=17`, `KEM_ITERS=50000` kept the
full-path median signal:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_encaps` | 2691.84 | 2678.20 | 1.0051x | 1.0018x |
| `mlkem_keygen` | 7723.42 | 7707.67 | 1.0020x | 1.0016x |
| `mlkem_keygen_core` | 7698.86 | 7691.45 | 1.0010x | 1.0016x |
| `mlkem_roundtrip` | 14144.77 | 14103.08 | 1.0030x | 1.0021x |
| `mlkem_roundtrip_core` | 22404.09 | 22456.05 | 0.9977x | 1.0015x |

Native `-march=native` KEM no-regression with `RUNS=9`, `KEM_ITERS=30000` was
neutral after guarding AVX512BW back to the previous masked sequence:
`mlkem_keygen_core` median `0.9998x`, `mlkem_encaps_core` `0.9996x`,
`mlkem_decaps_core` `1.0006x`, and `mlkem_roundtrip_core` `1.0006x`.

This is a very small encode-side cleanup, but it fits the same core strategy as
the lazy NTT work: remove redundant normalization/masking only at sites where the
producer already proves the value range, and keep broader or native paths exact
when integrated measurements do not improve.

### Independent Core Optimization Diagnostic (2026-07-02, AVX2 direct d12 encode helper boundary)

A d12 encode call-boundary cleanup was rejected. The candidate added a thin
`byte_encode_d12()` helper and replaced the hot `byte_encode(12, ...)` calls in
keygen and the stage harness with direct d12 helper calls. The d12 packing
arithmetic, range assumptions, and AVX512BW guard from the accepted mask-elision
change were unchanged; this only tested whether making the constant `d == 12`
path explicit would improve keygen encode scheduling.

Correctness passed the AVX2-only gate:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage,kem STAGE_ITERS=70000 \
  KEM_ITERS=30000 C_COMPILER=clang PIN_CPU=0 \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" ./scripts/bench_core_ab.sh HEAD
```

Rejected direct-helper highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_accum_encode` | 492.34 | 490.38 | 1.0040x | 1.0006x |
| `mlkem_core_stage_keygen_noise_ntt_encode` | 1590.58 | 1589.97 | 1.0004x | 1.0004x |
| `mlkem_core_stage_keygen_secret_encode_only` | 36.54 | 36.50 | 1.0010x | 1.0014x |
| `mlkem_core_stage_keygen_public_encode_only` | 36.17 | 36.15 | 1.0006x | 1.0003x |
| `mlkem_core_stage_kpke_keygen_full` | 4909.36 | 4960.82 | 0.9896x | 0.9982x |
| `mlkem_keygen` | 7073.52 | 7050.41 | 1.0033x | 1.0000x |
| `mlkem_keygen_core` | 7052.92 | 7035.33 | 1.0025x | 0.9998x |
| `mlkem_roundtrip_core` | 20635.01 | 20831.50 | 0.9906x | 0.9998x |

Keep the existing `byte_encode(12, ...)` call sites. The isolated d12 encode rows
are only about 36 ns for three polynomials, and making the helper boundary
explicit does not survive the full keygen/KEM path. This confirms that d12 pack
call dispatch is no longer a meaningful bottleneck after mask elision; further
keygen wins need to come from NTT/dataflow or sampler work, not d12 wrapper
cleanup.


### Independent Core Optimization Diagnostic (2026-07-02, AVX2 keygen add+encode fusion)

A keygen public-output fusion experiment was rejected. The candidate added an
AVX2-only helper that combined `ntt_add(that_accum, ehat, that)` with the
following d12 public-key byte encode. It still stored canonical `that[]` for the
public cache, but packed the same vector values immediately to avoid reloading
`that[]` in `byte_encode(12)`.

Correctness passed both gates:

```bash
make clean CC=clang AVX2_BACKEND=core && make test CC=clang AVX2_BACKEND=core
make clean CC=clang AVX2_BACKEND=core && make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage,kem STAGE_ITERS=70000 KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Stage/KEM highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_accum_encode` | 484.01 | 481.53 | 1.0051x | 1.0057x |
| `mlkem_core_stage_kpke_keygen_full` | 5894.18 | 5637.68 | 1.0455x | 1.0023x |
| `mlkem_keygen` | 7777.30 | 8011.99 | 0.9707x | 1.0002x |
| `mlkem_keygen_core` | 7753.75 | 7989.93 | 0.9704x | 0.9998x |

Longer AVX2-only KEM confirmation with `RUNS=17`, `KEM_ITERS=50000` did not keep
the keygen signal:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_keygen` | 7810.75 | 7722.55 | 1.0114x | 0.9994x |
| `mlkem_keygen_core` | 7788.15 | 7700.91 | 1.0113x | 0.9988x |
| `mlkem_roundtrip` | 14212.98 | 14153.04 | 1.0042x | 1.0000x |
| `mlkem_roundtrip_core` | 22579.58 | 22397.66 | 1.0081x | 1.0031x |

Keep `ntt_add()` and public-key d12 encoding separate for now. The fused helper
wins the targeted stage by removing one read pass, but the larger integrated
keygen path does not retain the improvement. A future attempt would need a
broader keygen layout change, not only add+pack fusion.

### Latest Core Optimization A/B (2026-07-02, AVX2 keygen tail scalar continuation)

The AVX2-only keygen matrix/noise co-schedule now keeps the first `(2,2)` public
matrix tail block in the existing PRF/tail `keccakf4()` call, then extracts the
tail lane into a scalar Keccak state and continues the remaining SHAKE128 tail
blocks with scalar `keccakf()`. This avoids running a four-lane AVX2 Keccak
permutation for the typical remaining one-lane tail squeezes while preserving the
accepted PRF/tail co-schedule for the first block.

Correctness checks:

```bash
make clean CC=clang AVX2_BACKEND=core && make test CC=clang AVX2_BACKEND=core
make clean CC=clang AVX2_BACKEND=core && make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage,kem STAGE_ITERS=70000 KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Stage/KEM highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_kpke_keygen_full` | 5485.12 | 5482.06 | 1.0006x | 1.0331x |
| `mlkem_keygen` | 7597.16 | 7949.37 | 0.9557x | 1.0221x |
| `mlkem_keygen_core` | 7566.68 | 7906.35 | 0.9570x | 1.0228x |
| `mlkem_roundtrip_core` | 22000.92 | 21706.62 | 1.0136x | 1.0084x |

Longer AVX2-only KEM confirmation with `RUNS=17`, `KEM_ITERS=50000` kept the
keygen and roundtrip median signal:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_keygen` | 7878.49 | 7546.66 | 1.0440x | 1.0219x |
| `mlkem_keygen_core` | 7873.10 | 7526.46 | 1.0461x | 1.0230x |
| `mlkem_roundtrip` | 14283.37 | 13919.72 | 1.0261x | 1.0140x |
| `mlkem_roundtrip_core` | 22294.61 | 21654.57 | 1.0296x | 1.0120x |

A second AVX2-only KEM confirmation with `RUNS=13`, `KEM_ITERS=40000` also kept
the signal and showed no unrelated full-path regression: `mlkem_keygen_core`
median `1.0241x`, `mlkem_keygen` `1.0234x`, `mlkem_encaps_core` `1.0009x`,
`mlkem_decaps_core` `1.0545x`, and `mlkem_roundtrip_core` `1.0072x`.

Native `-march=native` KEM no-regression with `RUNS=9`, `KEM_ITERS=30000` was
neutral: `mlkem_keygen_core` median `1.0005x`, `mlkem_encaps_core` `1.0025x`,
`mlkem_decaps_core` `0.9980x`, and `mlkem_roundtrip_core` `0.9994x`.

This follows the same target-specific lesson as the earlier AVX2 scalar-tail
switch: wide SIMD is profitable while lanes are full, but a single remaining XOF
stream should fall back to scalar once the useful co-scheduled lanes are gone.

### Latest Core Optimization A/B (2026-07-02, AVX2 keygen matrix/noise inline boundary)

The AVX2-only `mlkem_keygen_matrix_noise_avx2()` helper is no longer forced
`MLKEM_NOINLINE`. This helper is used only by `kpke_keygen()` and wraps the two
public-matrix `sample_ntt4()` batches plus the accepted keygen PRF/tail
co-schedule. Removing the forced call boundary lets clang choose the local shape
for the whole keygen matrix/noise block after the recent `sample_ntt4()` refill
stream reuse change.

This is a code-layout/call-boundary cleanup, not a cache optimization and not an
external backend. It does not change the Keccak schedule, sampling, NTTs, or
encoded key format.

Correctness checks:

```bash
make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
make clean CC=clang AVX2_BACKEND=core && make test CC=clang AVX2_BACKEND=core
```

AVX2-only stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage,kem STAGE_ITERS=70000 KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Stage/KEM highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_kpke_keygen_full` | 4909.46 | 4840.52 | 1.0142x | 1.0113x |
| `mlkem_core_stage_sample_matrix` | 2830.52 | 2835.64 | 0.9982x | 0.9991x |
| `mlkem_core_stage_keygen_noise_prf_cbd` | 974.65 | 975.31 | 0.9993x | 0.9996x |
| `mlkem_core_stage_keygen_noise_ntt` | 1993.91 | 1993.73 | 1.0001x | 1.0000x |
| `mlkem_keygen` | 6999.39 | 6952.18 | 1.0068x | 1.0024x |
| `mlkem_keygen_core` | 6977.46 | 6929.68 | 1.0069x | 1.0022x |
| `mlkem_roundtrip_core` | 20209.39 | 20227.47 | 0.9991x | 1.0004x |

Longer AVX2-only KEM confirmation:

```bash
RUNS=17 WARMUP_RUNS=4 SUITES=kem KEM_ITERS=50000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_keygen` | 7018.53 | 6957.95 | 1.0087x | 1.0006x |
| `mlkem_keygen_core` | 7007.21 | 6931.50 | 1.0109x | 1.0010x |
| `mlkem_encaps_core` | 7120.51 | 7071.88 | 1.0069x | 1.0019x |
| `mlkem_decaps_core` | 6086.37 | 6068.30 | 1.0030x | 1.0002x |
| `mlkem_roundtrip` | 13463.14 | 13404.22 | 1.0044x | 1.0013x |
| `mlkem_roundtrip_core` | 20302.99 | 20194.42 | 1.0054x | 1.0012x |

Decision: accept the inline-boundary cleanup with a narrow keygen claim. The
full keygen stage keeps the clearest signal, while the longer KEM confirmation
is only small but non-negative on the core rows. Do not generalize this to other
large sampler helpers: `sample_ntt4()` and x4 PRF/CBD function-boundary changes
were already rejected when their integrated rows did not hold up.

### Independent Core Optimization Diagnostic (2026-07-02, AVX2 keygen tail lane2x4 extraction)

A follow-up to the accepted AVX2 keygen tail scalar continuation was rejected.
The candidate batched the extraction of the scalar tail Keccak state from AVX2
lane 2: instead of calling `keccak_lane2_u64()` for all 25 state words, it used
`unpacklo_epi64` plus `permute2x128` to store four lane-2 words at a time, with a
single scalar extraction for word 24.

Correctness passed both gates:

```bash
make clean CC=clang AVX2_BACKEND=core && make test CC=clang AVX2_BACKEND=core
make clean CC=clang AVX2_BACKEND=core && make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage,kem STAGE_ITERS=70000 KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_kpke_keygen_full` | 5526.95 | 6166.48 | 0.8963x | 1.0006x |
| `mlkem_core_stage_sample_matrix_tail` | 876.50 | 883.47 | 0.9921x | 0.9959x |
| `mlkem_keygen` | 7578.71 | 7419.30 | 1.0215x | 0.9993x |
| `mlkem_keygen_core` | 7541.61 | 7398.86 | 1.0193x | 0.9990x |
| `mlkem_roundtrip_core` | 21685.50 | 21971.24 | 0.9870x | 0.9993x |

Keep the simpler per-word `keccak_lane2_u64()` extraction. The 4-word vector
extract form is mechanically tidy, but the extra shuffles do not improve the
integrated keygen path.

### Independent Core Optimization Diagnostic (2026-07-02, AVX2 parser const shuffle table)

A parser-table cleanup experiment was rejected. The candidate replaced the
runtime-generated `uint8_t sample_ntt_parse_idx_avx2[256][8]` shuffle-index
matrix with a compile-time `uint64_t[256]` table and made
`sample_ntt_parse_init_avx2()` an empty inline. The parser compaction algorithm
and table contents were unchanged; the goal was to remove the remaining ready
branch and first-use table generation.

Correctness passed both gates:

```bash
make clean CC=clang AVX2_BACKEND=core && make test CC=clang AVX2_BACKEND=core
make clean CC=clang AVX2_BACKEND=core && make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage,kem STAGE_ITERS=70000 KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Stage/KEM highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_parse_504` | 116.56 | 124.53 | 0.9360x | 0.9991x |
| `mlkem_core_stage_sample_matrix_tail` | 877.12 | 873.01 | 1.0047x | 1.0049x |
| `mlkem_core_stage_kpke_keygen_full` | 5344.71 | 5682.63 | 0.9405x | 1.0033x |
| `mlkem_keygen_core` | 7389.04 | 7390.62 | 0.9998x | 1.0001x |

Longer AVX2-only KEM confirmation with `RUNS=17`, `KEM_ITERS=50000` rejected the
change:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_encaps_core` | 7478.25 | 7508.82 | 0.9959x | 0.9890x |
| `mlkem_keygen` | 7932.79 | 7531.36 | 1.0533x | 0.9982x |
| `mlkem_keygen_core` | 7908.64 | 7509.47 | 1.0532x | 0.9984x |
| `mlkem_roundtrip` | 14311.96 | 13915.51 | 1.0285x | 0.9984x |

Keep the runtime-generated shuffle-index table. After the earlier accepted init
hoist, the remaining ready branch/table setup is not a meaningful full-path
bottleneck, and moving the table to `.rodata` perturbs the integrated KEM path.

### Independent Core Optimization Diagnostic (2026-07-03, AVX2 parser idx8 static load)

A smaller parser shuffle cleanup was rejected. The candidate kept the runtime
`sample_ntt_parse_idx_avx2[256][8]` compaction table, but replaced the local
`_mm256_set_epi8()` construction of the fixed 32-byte `idx8` extraction mask in
`sample_ntt_parse_stream_avx2_ready()` with an aligned static
`sample_ntt_parse_shuf_avx2[32]` object and `_mm256_load_si256()`. The goal was
to reduce immediate construction pressure in the common 56-byte parser loop.

Correctness passed the AVX2 gate:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=70000 C_COMPILER=clang \
  PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" ./scripts/bench_core_ab.sh HEAD
```

Stage highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_parse_504` | 118.35 | 118.37 | 0.9998x | 1.0028x |
| `mlkem_core_stage_sample_ntt4_common3_step` | 996.11 | 994.71 | 1.0014x | 1.0022x |
| `mlkem_core_stage_sample_ntt4_full_raw` | 939.66 | 933.86 | 1.0062x | 1.0012x |
| `mlkem_core_stage_sample_matrix_x4_batch0` | 1114.50 | 1124.39 | 0.9912x | 0.9991x |
| `mlkem_core_stage_sample_matrix_x4_batch1` | 1183.28 | 1183.94 | 0.9994x | 0.9985x |
| `mlkem_core_stage_sample_matrix` | 2825.03 | 2814.79 | 1.0036x | 1.0020x |
| `mlkem_core_stage_kpke_prepare_public_no_cache` | 4175.30 | 4162.50 | 1.0031x | 0.9992x |
| `mlkem_core_stage_kpke_keygen_full` | 4810.50 | 4815.49 | 0.9990x | 0.9994x |

Keep the local `_mm256_set_epi8()` form. The direct parser rows are only
neutral-to-slightly positive, while both x4 matrix batches and integrated keygen
rows are neutral or slightly negative by median. The static load also adds a
`.rodata` dependency to a hot loop without a full-path win, so this is not a
core improvement.

### Independent Core Optimization Diagnostic (2026-07-02, AVX2 keygen tail parser init skip)

A follow-up parser-init cleanup was rejected. The candidate removed the
`sample_ntt_parse_init_avx2()` call from the AVX2 keygen tail helper because the
current caller runs two `sample_ntt4()` batches first, and those batches already
initialize the parser table. This made the helper rely on the current keygen call
graph instead of being self-initializing.

Correctness passed both gates:

```bash
make clean CC=clang AVX2_BACKEND=core && make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
make clean CC=clang AVX2_BACKEND=core && make test CC=clang AVX2_BACKEND=core
```

AVX2-only stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage,kem STAGE_ITERS=70000 KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_matrix_tail` | 879.15 | 881.80 | 0.9970x | 0.9984x |
| `mlkem_core_stage_sample_matrix_tail_scalar` | 881.00 | 879.22 | 1.0020x | 1.0002x |
| `mlkem_core_stage_kpke_keygen_full` | 5342.04 | 5602.88 | 0.9534x | 1.0000x |
| `mlkem_keygen` | 7594.28 | 7440.60 | 1.0207x | 0.9994x |
| `mlkem_keygen_core` | 7573.84 | 7429.04 | 1.0195x | 0.9999x |
| `mlkem_roundtrip_core` | 22035.16 | 22103.87 | 0.9969x | 0.9982x |

Keep the keygen tail helper self-initializing. The call-graph assumption is true
today, but the removed branch/table-ready check did not produce an integrated
keygen win, and it weakens the helper boundary for no measurable benefit.

### Independent Core Optimization Diagnostic (2026-07-02, AVX2 Keccak x4 byte-rotate shuffle)

A Keccak x4 rotate cleanup was rejected. The candidate special-cased
`rotl64x4(..., 8)` and `rotl64x4(..., 56)` to use byte shuffles instead of the
existing shift/or sequence. This follows a common SIMD Keccak optimization: when
a 64-bit rotate is byte-aligned, `vpshufb` can replace two shifts plus an OR.

Correctness passed both gates:

```bash
make clean CC=clang AVX2_BACKEND=core && make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
make clean CC=clang AVX2_BACKEND=core && make test CC=clang AVX2_BACKEND=core
```

AVX2-only Keccak/stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=keccak,stage,kem KECCAK_ITERS=200000 \
  STAGE_ITERS=70000 KEM_ITERS=30000 C_COMPILER=clang PIN_CPU=0 \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" ./scripts/bench_core_ab.sh HEAD
```

Rejected highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_keccakf4` | 287.63 | 287.40 | 1.0008x | 1.0008x |
| `mlkem_core_stage_sample_ntt4_keccak_store3` | 891.09 | 891.14 | 0.9999x | 1.0003x |
| `mlkem_core_stage_sample_ntt4_full_raw` | 1176.47 | 1243.55 | 0.9461x | 1.0006x |
| `mlkem_core_stage_sample_matrix` | 3331.91 | 3463.74 | 0.9619x | 1.0003x |
| `mlkem_encaps_core` | 7762.54 | 7944.25 | 0.9771x | 1.0008x |
| `mlkem_decaps_core` | 7056.96 | 7228.89 | 0.9762x | 0.9945x |
| `mlkem_roundtrip_core` | 22373.59 | 23320.43 | 0.9594x | 0.9365x |

Keep the shift/or rotate sequence in `rotl64x4()`. The byte-shuffle form is a
valid Keccak trick, but here the direct `keccakf4()` improvement is only
noise-sized and the extra shuffle constants/port pressure do not survive the
integrated KEM gate.

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

### Independent Core Optimization Diagnostic (2026-07-02, AVX2 Keccak theta XOR source shape)

An AVX2-only Keccak source-shape experiment was rejected. The candidate rewrote
only the five `keccakf4()` Theta column parity expressions from nested XOR trees
into sequential `_mm256_xor_si256()` assignments. This kept the same operation
count and avoided AVX512-only `vpternlog`; the intent was only to see whether
clang would choose a better AVX2 schedule or register allocation for the common
x4 permutation.

Correctness passed the AVX2-only gate:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only Keccak/stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=keccak,stage,kem KECCAK_ITERS=200000 \
  STAGE_ITERS=70000 KEM_ITERS=30000 C_COMPILER=clang PIN_CPU=0 \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" ./scripts/bench_core_ab.sh HEAD
```

Rejected highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_keccakf4` | 288.14 | 296.59 | 0.9715x | 0.9995x |
| `mlkem_prf_eta2` | 221.74 | 221.03 | 1.0032x | 1.0027x |
| `mlkem_sample_ntt_full` | 693.10 | 694.10 | 0.9986x | 0.9965x |
| `mlkem_core_stage_sample_ntt4_keccak_store3` | 894.40 | 893.94 | 1.0005x | 0.9998x |
| `mlkem_core_stage_sample_ntt4_full_raw` | 1313.89 | 1243.37 | 1.0567x | 0.9998x |
| `mlkem_core_stage_sample_matrix` | 3604.94 | 3463.48 | 1.0408x | 0.9980x |
| `mlkem_encaps_core` | 7712.63 | 7363.44 | 1.0474x | 1.0163x |
| `mlkem_decaps_core` | 6850.09 | 6563.91 | 1.0436x | 1.0688x |
| `mlkem_roundtrip_core` | 22349.29 | 21929.61 | 1.0191x | 0.9997x |

Decision: keep the existing nested XOR tree source in `keccakf4()`. The direct
permutation average regressed and the relevant sampler median rows were neutral
or slightly negative. The apparent KEM-core median wins are not accepted as
causal evidence because this source-shape change also moved unrelated decaps
rows and did not improve the direct sampler/roundtrip median gate. Future Theta
work should require an assembly-level reduction in dependency depth or register
spills, not just a different C expression spelling.


An AVX512 rotate-intrinsic follow-up was rejected as neutral. The candidate
changed `rotl64x4()` and `rotl64x8()` to use `_mm256_rol_epi64()` /
`_mm512_rol_epi64()` when AVX512 rotate instructions are available, leaving
AVX2-only builds on the existing shift/or sequence. It passed native and
AVX2-only `make test`, but direct Keccak A/B did not show a measurable win.

Native Keccak A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=keccak KECCAK_ITERS=200000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

AVX512 rotate-intrinsic A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_keccakf4` | 163.29 | 163.25 | 1.0002x | 0.9999x |
| `mlkem_prf_eta2` | 188.97 | 187.83 | 1.0061x | 1.0011x |
| `mlkem_sha3_256_public_key` | 1667.34 | 1668.21 | 0.9995x | 0.9991x |
| `mlkem_sha3_256_32` | 193.73 | 193.87 | 0.9993x | 0.9998x |
| `mlkem_sha3_512_32` | 188.13 | 187.93 | 1.0010x | 1.0005x |
| `mlkem_sample_ntt_full` | 588.77 | 589.16 | 0.9993x | 1.0001x |

Keep the shift/or rotate helper. Clang appears to already recognize the rotate
idiom well enough on the native AVX512 target, so making the intrinsic explicit
adds source complexity without a defensible speedup.

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

A later direct d12-decode split added `keygen_secret_decode_only` and
`keygen_public_decode_only` stage metrics so this path can be ranked without
using noisy full uncached encrypt/decrypt rows. The rows decode the three 384-byte
d12 polynomials from the prepared secret/public key fixtures and use lightweight
coefficient sinks, matching the existing encode-only diagnostics.

Pinned CPU 0 snapshots with `BENCH_STAGES_ITERS=80000` measured:

| Build | Metric | ns/op |
|---|---|---:|
| native | `mlkem_core_stage_keygen_secret_encode_only` | 36.38 |
| native | `mlkem_core_stage_keygen_secret_decode_only` | 9.55 |
| native | `mlkem_core_stage_keygen_public_encode_only` | 36.12 |
| native | `mlkem_core_stage_keygen_public_decode_only` | 9.61 |
| AVX2-only | `mlkem_core_stage_keygen_secret_encode_only` | 36.70 |
| AVX2-only | `mlkem_core_stage_keygen_secret_decode_only` | 18.24 |
| AVX2-only | `mlkem_core_stage_keygen_public_encode_only` | 36.09 |
| AVX2-only | `mlkem_core_stage_keygen_public_decode_only` | 18.22 |

This makes d12 decode a poor next optimization target. Even if the tail load were
free, the whole three-polynomial decode row is much smaller than public-matrix
sampling, forward NTT, inverse NTT, or K=3 accumulation. Future d12 work should
only be revisited if a broader cold-cache public/secret key preparation redesign
needs it; narrow `byte_decode_d12_avx2()` reshaping is unlikely to move KEM.

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

A fixed-loop unroll of `sample_ntt4_store_rate()` was also rejected. The
candidate replaced the `for (lane = 0; lane < 20; lane += 4)` loop with five
explicit `sample_ntt4_store4x4()` calls at offsets 0, 32, 64, 96, and 128,
leaving the final local `last[4]` store unchanged. Native and AVX2-only
`make test` passed, but the AVX2-only stage A/B did not show a direct store or
full-sampler win.

AVX2-only stage A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected store-rate unroll highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_store_rate` | 7.62 | 7.64 | 0.9971x | 1.0000x |
| `mlkem_core_stage_sample_ntt4_keccak_store3` | 825.93 | 826.26 | 0.9996x | 1.0002x |
| `mlkem_core_stage_sample_ntt4_parse_504` | 124.98 | 126.23 | 0.9902x | 0.9979x |
| `mlkem_core_stage_sample_ntt4_full_raw` | 1543.85 | 1520.01 | 1.0157x | 0.9936x |
| `mlkem_core_stage_sample_matrix` | 4819.57 | 4750.04 | 1.0146x | 1.0015x |

Keep the compact loop in `sample_ntt4_store_rate()`. The compiler already
handles the fixed five-iteration loop well enough, and source-level unrolling
adds code size/layout pressure without improving the integrated x4 sampler.

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

A native AVX512 inverse-head follow-up was also rejected. The first candidate
added 512-bit helpers for inverse NTT head l2 and l3, mirroring the accepted
forward-tail l2 shape. It passed native and AVX2-only `make test`, but the full
inverse paths regressed even though the isolated head stage looked faster.

Native NTT/stage A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=ntt,stage NTT_ITERS=200000 STAGE_ITERS=90000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

AVX512 inverse-head l2+l3 A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_ntt_inv` | 169.12 | 171.40 | 0.9867x | 0.9863x |
| `mlkem_ntt_inv_add` | 177.62 | 179.37 | 0.9903x | 0.9895x |
| `mlkem_ntt_inv_add2` | 187.44 | 189.11 | 0.9912x | 0.9914x |
| `mlkem_ntt_inv_sub_from` | 177.61 | 179.31 | 0.9905x | 0.9901x |
| `mlkem_core_stage_decrypt_inv_head` | 268.45 | 263.39 | 1.0192x | 1.0118x |
| `mlkem_core_stage_encrypt_accum_inv` | 1132.59 | 1153.07 | 0.9822x | 0.9872x |
| `mlkem_core_stage_encrypt_accum_inv_u` | 893.21 | 910.23 | 0.9813x | 0.9860x |
| `mlkem_core_stage_decrypt_ntt_accum_recover` | 762.35 | 766.01 | 0.9952x | 0.9982x |

A narrower l3-only variant was also tested with the AVX2 l2 helper restored:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=ntt,stage NTT_ITERS=200000 STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

AVX512 inverse-head l3-only A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_decrypt_inv_head` | 265.88 | 260.68 | 1.0200x | 1.0202x |
| `mlkem_ntt_inv` | 169.80 | 169.34 | 1.0027x | 0.9980x |
| `mlkem_ntt_inv_add` | 177.49 | 177.85 | 0.9980x | 0.9989x |
| `mlkem_core_stage_encrypt_accum_inv` | 1131.40 | 1137.83 | 0.9944x | 0.9947x |
| `mlkem_core_stage_encrypt_accum_inv_u` | 892.76 | 897.23 | 0.9950x | 0.9951x |
| `mlkem_core_stage_decrypt_ntt_accum_recover` | 762.04 | 762.10 | 0.9999x | 0.9972x |

Keep inverse-head l2 and l3 on the existing AVX2 helpers. The isolated inverse
head can improve, but introducing zmm butterflies into the full inverse path does
not pay for the lane packing/extraction and likely perturbs the surrounding
AVX512/AVX2 schedule.

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

A later stream row-padding experiment was also rejected. The candidate changed
the x4/x8 sampler scratch layout from tightly packed 504-byte rows to
32-byte-aligned 512-byte rows, with 192-byte rows for the rare extra squeeze
block, while still parsing only the original 504 or 168 produced bytes. The
bench harness was adjusted to the same stride so the diagnostic parser rows did
not pass a 504-byte row to a 512-stride helper. Native and AVX2-only core
`make test` passed, and `git diff --check` passed.

Native stage/KEM A/B command:

```bash
RUNS=11 WARMUP_RUNS=2 SUITES=stage,kem STAGE_ITERS=70000 KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

Native highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_matrix` | 1905.57 | 1891.65 | 1.0074x | 1.0032x |
| `mlkem_core_stage_kpke_keygen_full` | 3410.58 | 3390.65 | 1.0059x | 1.0025x |
| `mlkem_keygen_core` | 5261.55 | 5259.10 | 1.0005x | 1.0009x |
| `mlkem_roundtrip_core` | 14775.46 | 14703.03 | 1.0049x | 1.0019x |

AVX2-only stage/KEM A/B command:

```bash
RUNS=11 WARMUP_RUNS=2 SUITES=stage,kem STAGE_ITERS=70000 KEM_ITERS=24000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

AVX2-only rejection highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_store_rate` | 7.64 | 4.73 | 1.6156x | 1.6186x |
| `mlkem_core_stage_sample_matrix` | 4459.12 | 4425.88 | 1.0075x | 0.9997x |
| `mlkem_keygen_core` | 8937.21 | 9326.58 | 0.9583x | 0.8822x |
| `mlkem_encaps_core` | 8875.20 | 9129.67 | 0.9721x | 0.9072x |
| `mlkem_roundtrip_core` | 26462.49 | 26634.13 | 0.9936x | 0.9978x |

Keep the tightly packed 504-byte sampler streams. The padded layout improves an
isolated store-rate diagnostic and is harmless-to-slightly-positive on the
native AVX512 path, but it badly destabilizes AVX2-only end-to-end KEM rows.
This is another case where an address-layout microbench win does not survive the
full keygen/encapsulation dataflow.

A narrower AVX2-only stream-base alignment experiment was also rejected. The
candidate kept the accepted static `stream[4][504]` scratch and the tightly
packed 504-byte row layout, but added `__attribute__((aligned(32)))` to the
static object in `sample_ntt4()`. This differs from the rejected row-padding
experiment above: it does not change row stride, parser length, refill reuse, or
stream contents. It only tests whether giving row 0 a known 32-byte-aligned base
helps the current transpose/store and parser path.

Correctness passed the AVX2-only gate:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected stream-base alignment highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_store_rate` | 7.73 | 7.70 | 1.0032x | 1.0039x |
| `mlkem_core_stage_sample_ntt4_parse_504` | 118.20 | 117.95 | 1.0021x | 1.0048x |
| `mlkem_core_stage_sample_ntt4_full_raw` | 931.32 | 931.09 | 1.0002x | 1.0000x |
| `mlkem_core_stage_sample_matrix_x4_batch0` | 1113.02 | 1113.02 | 1.0000x | 0.9998x |
| `mlkem_core_stage_sample_matrix_x4_batch1` | 1187.54 | 1180.86 | 1.0057x | 0.9994x |
| `mlkem_core_stage_sample_matrix` | 2803.29 | 2812.50 | 0.9967x | 0.9992x |
| `mlkem_core_stage_kpke_prepare_public_no_cache` | 4154.44 | 4155.38 | 0.9998x | 1.0000x |
| `mlkem_core_stage_kpke_keygen_full` | 4809.41 | 4801.84 | 1.0016x | 1.0001x |

Decision: keep the unannotated static `stream[4][504]` object. Explicit base
alignment produces only a tiny isolated store/parser movement and does not improve
the full x4 sampler or sample-matrix rows. Because the 504-byte row stride still
misaligns later rows, this hint is not a useful substitute for a real stream
layout redesign, and the full row-padding redesign already failed the KEM gate.

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

A native AVX512 one-lane matrix-tail experiment was also rejected. The candidate
added `sample_ntt8_one()` and used it for the final `(2,2)` polynomial in
`sample_matrix()`, replacing the existing `sample_ntt4_one()` tail on AVX512
builds. The idea was to keep the public-matrix tail in the AVX512 Keccak family
and extract lane 0 directly from `keccakf8()`. It passed native `make test`,
AVX2-only `make test`, and `git diff --check`, but the full public-matrix path
regressed badly. The direct tail row moved slightly positive, yet paying for
three `keccakf8()` permutations for one live sampler lane was much more
expensive than the existing `keccakf4()` tail.

Native stage A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage STAGE_ITERS=100000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

Rejected AVX512 one-lane matrix-tail highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_matrix_tail` | 703.41 | 700.18 | 1.0046x | 1.0088x |
| `mlkem_core_stage_sample_matrix` | 1886.65 | 2287.07 | 0.8249x | 0.8259x |
| `mlkem_core_stage_kpke_encrypt_uncached` | 3630.34 | 3963.14 | 0.9160x | 0.9119x |
| `mlkem_core_stage_kpke_keygen_full` | 3393.47 | 3396.52 | 0.9991x | 0.9997x |
| `mlkem_core_stage_sample_ntt4_full_raw` | 604.80 | 606.26 | 0.9976x | 1.0012x |

Keep `sample_matrix()` using `sample_ntt4_one()` for the final matrix entry on
native AVX512 builds. AVX512 is useful for the eight-lane batch, but it is the
wrong granularity for a single live SHAKE128 sampler lane.

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

A follow-up native AVX512 output-fusion variant was rejected. The candidate kept
the accepted three-way `u` accumulation and inverse-tail batching, but changed
the final scale/add loop to feed each 16-coefficient vector directly into the
`DU = 10` compress/encode packer instead of storing the three `u` polynomials
and reading them back during ciphertext packing. AVX2-only builds kept the
existing path. It passed native and AVX2-only `make test`, but full encryption
and KEM rows regressed.

Native stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage,kem STAGE_ITERS=90000 KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

AVX512 inverse-add3-to-d10-encode fusion A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_ciphertext_compress_encode` | 53.74 | 53.69 | 1.0010x | 1.0007x |
| `mlkem_core_stage_encrypt_accum_inv_u` | 893.21 | 892.05 | 1.0013x | 1.0013x |
| `mlkem_core_stage_kpke_encrypt_cached` | 1894.99 | 1942.46 | 0.9756x | 0.9892x |
| `mlkem_core_stage_kpke_encrypt_uncached` | 3674.94 | 3690.89 | 0.9957x | 0.9935x |
| `mlkem_encaps` | 2115.86 | 2140.71 | 0.9884x | 0.9879x |
| `mlkem_encaps_core` | 4908.92 | 4928.75 | 0.9960x | 0.9947x |
| `mlkem_roundtrip_core` | 14715.50 | 14786.06 | 0.9952x | 0.9977x |

Keep materializing the three `u` polynomials before ciphertext packing. The
extra store/load pair is cheaper than coupling the final inverse-NTT scale/add
loop with the dense d10 packer; the fused version likely increases register and
port pressure in the already-heavy encryption path.

### Independent Core Optimization Diagnostic (2026-07-02, AVX2 early u compression)

An AVX2-only follow-up tried the same boundary idea at the existing
`ntt_inv_add_inplace()` granularity instead of inside the AVX512 final scale/add
loop. The candidate compressed and packed each `u[i]` into the ciphertext buffer
immediately after `ntt_mul_acc3(...)` and `ntt_inv_add_inplace(e1[i], u[i])`,
then computed `v` and packed the final d4 component. This removed the later
readback of the three materialized `u` polynomials on AVX2-only builds while
leaving the native AVX512 path on the existing materialized schedule.

Correctness passed both gates:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
make clean CC=clang AVX2_BACKEND=core && make test CC=clang AVX2_BACKEND=core
```

AVX2-only stage/KEM A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage,kem STAGE_ITERS=70000 KEM_ITERS=24000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected AVX2 early-`u` compression highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_kpke_encrypt_cached` | 2430.60 | 2446.94 | 0.9933x | 0.9931x |
| `mlkem_core_stage_kpke_encrypt_uncached` | 4910.79 | 4911.96 | 0.9998x | 0.9982x |
| `mlkem_core_stage_encrypt_accum_inv` | 1323.81 | 1329.85 | 0.9955x | 0.9987x |
| `mlkem_core_stage_encrypt_accum_inv_u` | 1038.65 | 1044.08 | 0.9948x | 0.9991x |
| `mlkem_core_stage_ciphertext_compress_encode` | 51.08 | 51.12 | 0.9991x | 1.0022x |
| `mlkem_encaps` | 2687.20 | 2689.77 | 0.9990x | 0.9980x |
| `mlkem_encaps_core` | 7096.11 | 7183.34 | 0.9879x | 0.9949x |
| `mlkem_roundtrip_core` | 20160.63 | 20271.88 | 0.9945x | 0.9970x |

Reject this AVX2-only early-pack schedule. The isolated ciphertext compression
row is neutral, while cached K-PKE encryption and KEM core rows regress. The
extra store/load pair for `u[0..2]` is cheaper than interleaving the dense d10
packer into the accumulation/inverse-add schedule. Keep materializing `u` until
a broader representation change can combine more than this final readback.

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

A native AVX512 follow-up specializes the message-add part of that folded path.
When AVX512F+BW is available, `mlkem_add_message_to_poly()` now loads each
32-bit message word as an AVX512 mask and materializes 32 coefficients of either
`0` or `(Q + 1) / 2` with `_mm512_maskz_mov_epi16()`. It then adds those
coefficients to `e2` and conditionally subtracts `Q` in the same 32-lane vector.
AVX2-only builds keep the accepted `poly_frommsg`-style 16-lane expansion. This
keeps the independent core vendor-free and removes the AVX2 shuffle/unpack
message expansion on native AVX512 builds.

Correctness checks:

```bash
make clean CC=clang AVX2_BACKEND=core && make test CC=clang AVX2_BACKEND=core
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

Native stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage,kem STAGE_ITERS=90000 KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

Native highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_kpke_encrypt_cached` | 1912.44 | 1896.52 | 1.0084x | 1.0036x |
| `mlkem_core_stage_encrypt_accum_inv` | 1132.12 | 1132.00 | 1.0001x | 1.0006x |
| `mlkem_encaps` | 2115.04 | 2117.46 | 0.9989x | 1.0034x |
| `mlkem_encaps_core` | 4908.42 | 4904.53 | 1.0008x | 1.0004x |
| `mlkem_decaps_core` | 4443.70 | 4420.86 | 1.0052x | 1.0052x |

Longer native KEM confirmation:

```bash
RUNS=17 WARMUP_RUNS=4 SUITES=kem KEM_ITERS=50000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_encaps` | 2124.80 | 2108.85 | 1.0076x | 1.0040x |
| `mlkem_encaps_core` | 4914.95 | 4911.85 | 1.0006x | 1.0018x |
| `mlkem_decaps` | 2941.28 | 2939.70 | 1.0005x | 1.0016x |
| `mlkem_decaps_core` | 4445.54 | 4466.41 | 0.9953x | 1.0015x |
| `mlkem_roundtrip_core` | 14715.08 | 14731.66 | 0.9989x | 0.9979x |

The accepted claim is intentionally narrow: this is a small native AVX512
encapsulation/re-encryption improvement. It is not a broad roundtrip win; the
longer confirmation kept encapsulation positive but roundtrip-core noise moved
slightly negative.

A follow-up attempt to replace `maskz_mov + add` with `_mm512_mask_add_epi16()`
was rejected. It passed native and AVX2-only core `make test`, but the native
KEM-only confirmation was only neutral and the focused stage rows did not improve
cleanly. KEM A/B against the accepted maskz version with `RUNS=15`,
`KEM_ITERS=50000` showed `mlkem_encaps` median speedup `1.0004x`,
`mlkem_encaps_core` `0.9992x`, and `mlkem_roundtrip_core` `1.0012x`. A native
stage A/B with `RUNS=11` and `STAGE_ITERS=120000` showed
`mlkem_core_stage_kpke_encrypt_cached` median speedup `0.9992x` and
`mlkem_core_stage_encrypt_accum_inv_v` `1.0001x`. Keep the explicit
`maskz_mov + add` shape; it is no slower in the integrated path and is easier to
read as materializing the message polynomial.

### Independent Core Optimization Diagnostic (2026-07-02, AVX2 message final-fold)

An AVX2-only follow-up to the accepted `e2`/message fusion was rejected. The
candidate skipped the separate `mlkem_add_message_to_poly(m, e2)` pass and
instead folded `message` directly into the AVX2 final inverse-NTT add for the
`v` polynomial. Two forms were tested: first adding `scaled + e2 + message` with
two 32-bit modular adds in the final pass, then a lower-pressure variant that
formed `e2 + message` with the existing 16-bit modular-add shape before the
final 32-bit add.

Correctness passed both gates for both forms:

```bash
make clean CC=clang AVX2_BACKEND=core && make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
make clean CC=clang AVX2_BACKEND=core && make test CC=clang AVX2_BACKEND=core
```

Initial AVX2-only stage/KEM A/B for the direct 32-bit-add form:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage,kem STAGE_ITERS=70000 KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Direct 32-bit-add highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_kpke_encrypt_cached` | 2421.37 | 2438.99 | 0.9928x | 0.9937x |
| `mlkem_core_stage_encrypt_accum_inv_v` | 466.55 | 466.77 | 0.9995x | 0.9996x |
| `mlkem_encaps` | 2681.46 | 2702.84 | 0.9921x | 0.9937x |
| `mlkem_encaps_core` | 7624.07 | 7294.97 | 1.0451x | 1.0416x |
| `mlkem_roundtrip_core` | 22256.21 | 21546.68 | 1.0329x | 1.0421x |

Longer AVX2-only KEM confirmation rejected the direct form:

```bash
RUNS=17 WARMUP_RUNS=2 SUITES=kem KEM_ITERS=50000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_encaps` | 2692.60 | 2702.69 | 0.9963x | 0.9930x |
| `mlkem_encaps_core` | 7614.12 | 7715.93 | 0.9868x | 0.9965x |
| `mlkem_roundtrip_core` | 22326.80 | 22445.59 | 0.9947x | 0.9972x |

The 16-bit `e2 + message` fold variant also failed the longer AVX2-only KEM
gate:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_decaps_core` | 6674.37 | 7032.19 | 0.9491x | 0.9343x |
| `mlkem_encaps` | 2692.16 | 2712.17 | 0.9926x | 0.9944x |
| `mlkem_encaps_core` | 7406.68 | 7612.26 | 0.9730x | 0.9957x |
| `mlkem_roundtrip_core` | 21836.20 | 22184.83 | 0.9843x | 0.9949x |

Keep the current AVX2 message pre-pass into `e2`. It costs an extra pass over
`e2`, but it keeps message expansion out of the already dense inverse-final loop
and gives better encapsulation behavior than either direct final-fold shape.

### Independent Core Optimization Diagnostic (2026-07-02, AVX2 early e2/message fold)

An AVX2-only follow-up tried moving the accepted `e2` message fold earlier in
K-PKE encryption. The candidate added `mlkem_add_message_to_poly(m, e2)`
immediately after PRF/CBD noise generation in `kpke_encrypt_prepared_public()`
and at entry to `kpke_encrypt_prepared_public_with_noise_avx2()`, then removed
the later fold before `ntt_inv_add_v_inplace(e2, v)`. Algebraically this is the
same ciphertext equation: `e2` is not consumed until the final `v` inverse-add.
The intended benefit was keeping `e2` hot instead of touching it again after the
`rhat` NTTs and public-key dot products.

Correctness passed both core gates:

```bash
make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
make clean CC=clang AVX2_BACKEND=core && make test CC=clang AVX2_BACKEND=core
```

AVX2-only stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage,kem STAGE_ITERS=70000 KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_encrypt_accum_inv_v` | 467.02 | 468.85 | 0.9961x | 0.9994x |
| `mlkem_core_stage_encrypt_accum_inv` | 1329.88 | 1329.77 | 1.0001x | 0.9998x |
| `mlkem_core_stage_kpke_encrypt_cached` | 2431.62 | 2440.67 | 0.9963x | 0.9965x |
| `mlkem_core_stage_kpke_encrypt_uncached` | 4989.69 | 4984.51 | 1.0010x | 0.9989x |
| `mlkem_encaps` | 2690.92 | 2698.61 | 0.9971x | 0.9949x |
| `mlkem_encaps_core` | 7026.37 | 7234.36 | 0.9712x | 1.0066x |
| `mlkem_roundtrip_core` | 20231.37 | 20486.35 | 0.9876x | 0.9982x |

Reject this move. The direct `v` target is neutral-to-negative, cached K-PKE
encryption and encapsulation regress, and the positive `mlkem_encaps_core`
median is not supported by the average or neighboring rows. The current later
`e2` message pre-pass is less cache-local in theory, but it keeps the write
closer to the final inverse-add/pack boundary and behaves better in the
integrated AVX2-only path.

### Independent Core Optimization Diagnostic (2026-07-02, AVX2 message-add unsigned-min reduction)

An AVX2-only follow-up tried replacing the correction step inside
`mlkem_add_message_to_poly_vec_avx2()`. The current helper computes
`x = e2 + message`, then conditionally subtracts `Q` with
`cmpgt_epi16 + and + sub`. The candidate used the unsigned-min idiom instead:
`x = min_epu16(x, x - Q)`.

This is safe for this helper only: `e2` comes from ETA2 CBD output in canonical
`[0, Q)`, and `message` contributes either `0` or `(Q + 1) / 2`, so one
subtraction is sufficient and the sum stays below the signed 16-bit overflow
boundary. The generic polynomial add helpers and NTT add path were intentionally
left unchanged because they have broader input-range contracts.

Correctness passed the AVX2-only core gate:

```bash
make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=90000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_encrypt_accum_inv_v` | 467.19 | 473.40 | 0.9869x | 0.9990x |
| `mlkem_core_stage_encrypt_accum_inv` | 1323.08 | 1325.63 | 0.9981x | 0.9984x |
| `mlkem_core_stage_encrypt_accum_inv_u` | 1041.34 | 1040.19 | 1.0011x | 0.9986x |
| `mlkem_core_stage_kpke_encrypt_cached` | 2434.79 | 2430.88 | 1.0016x | 1.0000x |
| `mlkem_core_stage_kpke_encrypt_uncached` | 4908.76 | 4906.58 | 1.0004x | 0.9992x |
| `mlkem_core_stage_kpke_keygen_full` | 4808.50 | 4837.13 | 0.9941x | 0.9962x |

Reject this substitution. The direct `v` target regressed on average, the full
encrypt rows were effectively neutral, and neighboring keygen rows were noisy
negative. No longer KEM confirmation was run because the focused stage gate did
not clear. Future message-fold work should not be another one-pass correction
idiom swap; it needs to change the inverse-add/compress boundary or surrounding
dataflow to matter.

### Independent Core Optimization Diagnostic (2026-07-03, AVX2 lazy multiply-input NTT rows)

A bench-only diagnostic added direct rows for the production AVX2
`ntt_lazy_mul_input_avx2()` helper. This closes a measurement mismatch: existing
stage diagnostics call the helper out-of-place, but production encryption and
decryption call it in-place for `rhat[0..2]` and decoded `u[0..2]`. The in-place
row restores a scratch batch outside the timed window so each measured transform
still starts from canonical input instead of repeatedly transforming lazy output.

Correctness is covered by the `bench_ntt` helper validation before timing; it now
checks both copy and in-place lazy multiply-input output modulo `Q` against
canonical `ntt()`.

Command:

```bash
make clean CC=clang AVX2_BACKEND=core
make bench-ntt CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
for i in $(seq 1 7); do
  taskset -c 0 ./bench_nttc 200000 | \
    awk -F= -v run="$i" '/mlkem_ntt_(copy|inplace|copy_lazy_mul_input|inplace_lazy_mul_input)_ns_per_op=/{print run, $1, $2}'
done
```

Median AVX2-only results:

| Metric | Median ns/op |
|---|---:|
| `mlkem_ntt_copy` | 196.24 |
| `mlkem_ntt_inplace` | 191.84 |
| `mlkem_ntt_copy_lazy_mul_input` | 191.42 |
| `mlkem_ntt_inplace_lazy_mul_input` | 188.40 |

Decision: keep these rows as diagnostics. The current lazy multiply-input path is
already the right local representation for values consumed by `ntt_mul_acc3()`,
but the remaining direct NTT-local headroom is only a few ns/op. The next
optimization should target a larger K=3 dataflow, such as SIMD accumulation fed
by the NTT layout, rather than another isolated lazy NTT helper tweak.

### Independent Benchmark Alignment Diagnostic (2026-07-03, AVX2 production lazy encrypt noise)

The stage harness now has a production-aligned AVX2-only `encrypt_noise_lazy` row.
The older `encrypt_noise` row is still useful as a canonical-reference row, but
it calls `ntt()` on the three `r` polynomials after PRF/CBD. Production AVX2
encryption instead uses `ntt_lazy_mul_input_avx2()` before `ntt_mul_acc3()`, so
`encrypt_noise_lazy` measures the same PRF/CBD plus lazy-NTT boundary used by
`kpke_encrypt_prepared_public()` and the cache-miss prepared-noise path.

AVX2-only command:

```bash
make bench-stages CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
for i in $(seq 1 7); do
  taskset -c 0 ./bench_core_stagesc 40000 | \
    awk -F= -v run="$i" '/mlkem_core_stage_encrypt_noise(_lazy|_ntt|_ntt_lazy)?_ns_per_op=|mlkem_core_stage_encrypt_noise_prf_cbd_ns_per_op=/{print run, $1, $2}'
done
```

AVX2-only results:

| Metric | Avg ns/op | Median ns/op |
|---|---:|---:|
| `mlkem_core_stage_encrypt_noise` | 1389.96 | 1389.22 |
| `mlkem_core_stage_encrypt_noise_lazy` | 1378.04 | 1377.01 |
| `mlkem_core_stage_encrypt_noise_prf_cbd` | 1166.89 | 1166.55 |
| `mlkem_core_stage_encrypt_noise_ntt` | 781.82 | 781.34 |
| `mlkem_core_stage_encrypt_noise_ntt_lazy` | 768.51 | 769.23 |

Decision: keep both rows, but use `encrypt_noise_lazy` when ranking the current
AVX2 production encryption path. The production-aligned combined row is `1.0087x`
average and `1.0089x` median faster than the canonical reference, matching the
isolated lazy-NTT advantage. The remaining encryption-noise bottleneck is mostly
PRF/CBD and Keccak lane filling, not another local forward-NTT tweak.

### Independent Benchmark Alignment Diagnostic (2026-07-03, AVX2 tail co-schedule with lazy NTT)

The stage harness now also has AVX2-only rows that include both the cache-miss
`(2,2)` public-matrix tail and the production lazy multiply-input NTT for `r`.
These rows make the cache-miss encryption front-end comparable under the same
post-PRF condition: scalar tail generation versus the existing nonce 4/5/6
`keccakf4()` lane-fill co-schedule, followed by lazy NTT on the three `r`
polynomials.

AVX2-only command:

```bash
make bench-stages CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
for i in $(seq 1 7); do
  taskset -c 0 ./bench_core_stagesc 40000 | \
    awk -F= -v run="$i" '/mlkem_core_stage_encrypt_noise_lazy_ns_per_op=|mlkem_core_stage_encrypt_noise_prf_cbd_ns_per_op=|mlkem_core_stage_encrypt_noise_prf_cbd_tail_(separate|cosched|separate_lazy|cosched_lazy)_ns_per_op=|mlkem_core_stage_encrypt_noise_ntt_lazy_ns_per_op=/{print run, $1, $2}'
done
```

AVX2-only results:

| Metric | Avg ns/op | Median ns/op |
|---|---:|---:|
| `mlkem_core_stage_encrypt_noise_lazy` | 1375.58 | 1375.60 |
| `mlkem_core_stage_encrypt_noise_prf_cbd` | 1165.35 | 1165.16 |
| `mlkem_core_stage_encrypt_noise_prf_cbd_tail_separate` | 1319.73 | 1316.60 |
| `mlkem_core_stage_encrypt_noise_prf_cbd_tail_cosched` | 1107.95 | 1108.35 |
| `mlkem_core_stage_encrypt_noise_prf_cbd_tail_separate_lazy` | 1881.39 | 1880.36 |
| `mlkem_core_stage_encrypt_noise_prf_cbd_tail_cosched_lazy` | 1674.28 | 1674.95 |
| `mlkem_core_stage_encrypt_noise_ntt_lazy` | 768.77 | 767.79 |

Decision: keep the lazy tail rows as diagnostic rows, not production changes.
The co-scheduled tail path remains faster than the scalar-tail baseline even
after including production lazy NTT: `1.1237x` average and `1.1226x` median.
However, the co-scheduled cache-miss front-end is still `1.2171x` average and
`1.2176x` median slower than `encrypt_noise_lazy`, which excludes public-matrix
tail generation. The remaining cache-miss cost is therefore the residual tail
generation/parse boundary, not another local lazy-NTT helper tweak.

### Independent Core Optimization Diagnostic (2026-07-03, AVX2 encrypt tail accum3 parse)

A bench-only follow-up re-tested the keygen-style three-rate tail parse schedule
against the encryption cache-miss tail path, including the production lazy NTT
post-condition. The candidate accumulates the first three SHAKE128 rate blocks
for the `(2,2)` tail and calls the 504-byte parser once, instead of parsing the
co-scheduled first rate and then parsing scalar continuation rates one at a time.

AVX2-only diagnostic command:

```bash
make bench-stages CC=clang AVX2_BACKEND=core \
  ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
for i in $(seq 1 7); do
  taskset -c 0 ./bench_core_stagesc 40000 | \
    awk -F= -v run="$i" '/mlkem_core_stage_encrypt_noise_prf_cbd_tail_(separate|cosched|cosched_accum3|separate_lazy|cosched_lazy|cosched_accum3_lazy)_ns_per_op=|mlkem_core_stage_kpke_encrypt_uncached_ns_per_op=|mlkem_core_stage_encrypt_noise_lazy_ns_per_op=/{print run, $1, $2}'
done
```

AVX2-only diagnostic results:

| Metric | Avg ns/op | Median ns/op |
|---|---:|---:|
| `mlkem_core_stage_kpke_encrypt_uncached` | 4879.31 | 4864.33 |
| `mlkem_core_stage_encrypt_noise_lazy` | 1381.21 | 1380.81 |
| `mlkem_core_stage_encrypt_noise_prf_cbd_tail_separate` | 1322.19 | 1322.61 |
| `mlkem_core_stage_encrypt_noise_prf_cbd_tail_cosched` | 1113.05 | 1111.59 |
| `mlkem_core_stage_encrypt_noise_prf_cbd_tail_cosched_accum3` | 1108.06 | 1109.92 |
| `mlkem_core_stage_encrypt_noise_prf_cbd_tail_separate_lazy` | 1888.76 | 1888.08 |
| `mlkem_core_stage_encrypt_noise_prf_cbd_tail_cosched_lazy` | 1672.29 | 1669.23 |
| `mlkem_core_stage_encrypt_noise_prf_cbd_tail_cosched_accum3_lazy` | 1667.43 | 1666.38 |

The direct diagnostic was only `1.0045x` average and `1.0015x` median faster
than the existing co-scheduled tail row. Including production lazy NTT kept only
`1.0029x` average and `1.0017x` median. A temporary production A/B that routed
`mlkem_encrypt_prf_cbd_eta2_32_sample_tail_avx2()` through the same accum3 parse
schedule passed correctness but did not produce an integrated median win:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
RUNS=7 WARMUP_RUNS=2 SUITES=stage STAGE_ITERS=50000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Production-candidate A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_encrypt_noise_lazy` | 1378.27 | 1379.88 | 0.9988x | 0.9990x |
| `mlkem_core_stage_encrypt_noise_prf_cbd_tail_cosched` | 1111.15 | 1110.98 | 1.0002x | 0.9999x |
| `mlkem_core_stage_encrypt_noise_prf_cbd_tail_cosched_lazy` | 1674.13 | 1670.15 | 1.0024x | 1.0021x |
| `mlkem_core_stage_kpke_encrypt_cached` | 2455.41 | 2423.27 | 1.0133x | 1.0010x |
| `mlkem_core_stage_kpke_encrypt_uncached` | 4928.83 | 4893.11 | 1.0073x | 1.0000x |

Decision: keep the accum3 encryption-tail rows as diagnostics only and leave the
production encryption helper on the existing one-rate parse/continuation schedule.
The keygen helper keeps the accepted three-rate parse because it had a keygen-stage
win, but the encryption path does not show enough integrated median improvement to
justify another production boundary change. The next useful work should target a
larger public-matrix tail/dataflow change, not this local parser schedule.

### Independent Core Optimization Diagnostic (2026-07-03, scalar encrypt accum4 coalescing)

A bench-only encryption accumulation diagnostic tested the natural follow-up to
the K=3 accumulation bottleneck: compute all four encryption NTT-domain outputs
`u[0]`, `u[1]`, `u[2]`, and `v` in one scalar loop. The candidate reuses each
`rhat[0..2]` base pair and `GAMMA[i]` value once, then emits four outputs, instead
of calling `ntt_mul_acc3()` separately for the three public-matrix rows and the
`that` row. This is the AVX2/core analogue of the AVX512 encryption-side boundary
idea, but without changing the arithmetic representation or adding SIMD.

The helper is validated by comparing all four outputs against four independent
`ntt_mul_acc3()` calls before timing.

Command:

```bash
make clean CC=clang AVX2_BACKEND=core && \
  make bench-stages CC=clang AVX2_BACKEND=core \
    ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
for i in $(seq 1 7); do
  taskset -c 0 ./bench_core_stagesc 70000 | \
    awk -F= -v run="$i" '/mlkem_core_stage_encrypt_accum_(u_only|inv)_ns_per_op=|mlkem_core_stage_encrypt_accum4_(separate|combined)_only_ns_per_op=/{print run, $1, $2}'
done
```

AVX2-only results:

| Metric | Avg ns/op | Median ns/op | Relative to separate median |
|---|---:|---:|---:|
| `mlkem_core_stage_encrypt_accum4_separate_only` | 723.62 | 708.51 | 1.0000x |
| `mlkem_core_stage_encrypt_accum4_combined_only` | 751.50 | 709.90 | 0.9980x |

Decision: reject scalar four-output coalescing for production. Reusing `rhat` and
`GAMMA` loads is not enough to offset the larger loop body and register pressure;
the median is neutral-to-negative and the average is clearly worse. This rules
out a simple scalar AVX2/core port of the AVX512 encryption boundary idea. A
future attempt needs a genuinely different SIMD/reduction representation, not
just coalescing four scalar `ntt_mul_acc3()` calls.

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

A narrow 504-byte AVX2 parser specialization was rejected. The candidate added a
`sample_ntt_parse_504_avx2_ready()` path for the common initial three-rate stream
used by `sample_ntt4()` and `sample_ntt8_matrix()`, keeping the existing generic
parser for 168-byte refill blocks. It changed only fixed-length loop bounds and
removed the `stream_len` / nonzero-`count` genericity from the initial parse;
the shuffle-index table, compaction shape, Keccak schedule, and stream layout
were unchanged. Native and AVX2-only `make test` passed, but direct AVX2 sampler
metrics regressed, so KEM confirmation was not pursued.

AVX2-only stage A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected 504-byte parser highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_parse_504` | 117.35 | 118.52 | 0.9901x | 0.9981x |
| `mlkem_core_stage_sample_ntt4_full_raw` | 1496.89 | 1596.05 | 0.9379x | 0.9960x |
| `mlkem_core_stage_sample_matrix_x4_batch0` | 1683.76 | 1803.31 | 0.9337x | 0.9963x |
| `mlkem_core_stage_sample_matrix_x4_batch1` | 1799.30 | 1909.11 | 0.9425x | 0.9989x |
| `mlkem_core_stage_sample_matrix` | 4703.32 | 4997.57 | 0.9411x | 0.9971x |

Keep the generic `sample_ntt_parse_stream_avx2_ready()` for the 504-byte initial
parse. The compiler already handles the hot fixed-size call well enough, and a
large duplicated fixed-length parser adds code-layout pressure without improving
the integrated x4 sampler rows.

A narrow `sample_ntt4()` parse/refill bookkeeping unroll was rejected. The
candidate removed the local `outs[4]` array and replaced the two four-lane loops
around `sample_ntt_parse_stream_avx2_ready()` with explicit `count0..count3`
calls. It did not change the parser, Keccak schedule, stream layout, or refill
semantics. Native and AVX2-only `make test` passed, but AVX2-only stage/KEM A/B
showed that the direct sampler movement did not translate to keygen.

AVX2-only stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage,kem STAGE_ITERS=50000 KEM_ITERS=24000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected `sample_ntt4()` unroll highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_full_raw` | 1725.19 | 1621.64 | 1.0639x | 1.0032x |
| `mlkem_core_stage_sample_matrix` | 5315.43 | 5086.09 | 1.0451x | 1.0091x |
| `mlkem_core_stage_kpke_keygen_full` | 7138.05 | 7422.66 | 0.9617x | 0.9664x |
| `mlkem_keygen` | 8975.41 | 8865.23 | 1.0124x | 0.9976x |
| `mlkem_keygen_core` | 8953.68 | 8831.76 | 1.0138x | 0.9994x |
| `mlkem_roundtrip_core` | 26451.36 | 26044.92 | 1.0156x | 1.0029x |

Keep the compact loop in `sample_ntt4()`. The unrolled bookkeeping can improve
some isolated sampler rows, but it perturbs the integrated AVX2-only keygen
layout enough that the no-regression signal is not clean. Future x4 sampler work
should target Keccak/store or the parser representation itself, not just the
small lane-loop scaffolding.

A narrow `sample_ntt4()` suffix-specialization experiment was rejected. The
candidate tried to remove the per-call `row[4]` / `col[4]` suffix construction
for the two fixed AVX2 x4 public-matrix batches. Two forms were tested: first
four scalar `uint64_t suffix0..3` arguments, then a lower-pressure `__m256i
suffix` argument using `SAMPLE_NTT4_BATCH{0,1}_SUFFIX` constants so the four
output pointers stay in integer argument registers. Native and AVX2-only
`make test` passed for the vector-argument form, but the optimization was too
small for the full sampler and did not satisfy KEM no-regression.

AVX2-only stage A/B command for the vector-argument form:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected suffix-specialization stage highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_full_raw` | 1528.21 | 1535.97 | 0.9949x | 0.9998x |
| `mlkem_core_stage_sample_matrix_x4_batch0` | 1718.32 | 1726.83 | 0.9951x | 0.9985x |
| `mlkem_core_stage_sample_matrix_x4_batch1` | 1835.10 | 1844.54 | 0.9949x | 0.9997x |
| `mlkem_core_stage_sample_matrix` | 4808.32 | 4811.12 | 0.9994x | 1.0005x |
| `mlkem_core_stage_kpke_keygen_full` | 6810.40 | 6687.16 | 1.0184x | 1.0016x |

AVX2-only KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=kem KEM_ITERS=30000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected suffix-specialization KEM highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_keygen_core` | 9093.68 | 8678.22 | 1.0479x | 1.0057x |
| `mlkem_encaps_core` | 8979.06 | 8758.75 | 1.0252x | 1.0009x |
| `mlkem_decaps_core` | 8119.98 | 8597.48 | 0.9445x | 0.8995x |
| `mlkem_roundtrip_core` | 26340.48 | 26147.80 | 1.0074x | 1.0324x |

Keep the current `row[4]` / `col[4]` interface. Eliminating a few suffix
integer operations is not the limiting work in `sample_ntt4()`; Keccak, stream
storage, and the rejection parser dominate. The scalar-suffix form also
increased integer argument pressure, while the vector-suffix form was only
neutral locally and failed the KEM no-regression gate because of the large
`mlkem_decaps_core` regression.

A BMI2 index-generation variant was rejected. This copied the classic
Kyber/PQClean `pdep`/`pext` idea into the independent core parser by replacing
the 256-entry shuffle-index table lookup with `_pdep_u64()` plus `_pext_u64()`
when `__BMI2__` is available. It passed native, AVX2+BMI2, and AVX2 no-BMI2
`make test`, but the sampler path regressed sharply on the native build.

Native stage A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage STAGE_ITERS=90000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

BMI2 sampler-index A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_sample_ntt4_parse_504` | 142.07 | 163.98 | 0.8664x | 0.7787x |
| `mlkem_core_stage_sample_ntt4_full_raw` | 606.44 | 658.43 | 0.9210x | 0.9188x |
| `mlkem_core_stage_sample_matrix_x4_batch0` | 788.26 | 842.70 | 0.9354x | 0.9326x |
| `mlkem_core_stage_sample_matrix_x4_batch1` | 845.03 | 925.49 | 0.9131x | 0.8948x |
| `mlkem_core_stage_sample_matrix` | 1895.59 | 2009.68 | 0.9432x | 0.9445x |
| `mlkem_core_stage_kpke_keygen_full` | 3411.47 | 3530.02 | 0.9664x | 0.9642x |
| `mlkem_core_stage_kpke_encrypt_uncached` | 3663.16 | 3762.65 | 0.9736x | 0.9705x |

Keep the current table-based shuffle-index generation. On this target, avoiding
four tiny table loads is not worth the latency and port pressure of repeated
BMI2 `pdep`/`pext` in the hot rejection parser.

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

A follow-up lazy tail-state experiment was rejected. The candidate delayed
building the AVX2 `tail_st[25]` continuation state for lane 6 until the rare
case where the first 168-byte tail block failed to produce all 256 coefficients.
It passed native and AVX2-only core `make test`, but it did not improve the
integrated keygen path. The saved work is too small and likely offset by branch,
stack, or code-layout effects around the already co-scheduled Keccak path.

Native stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage,kem STAGE_ITERS=100000 KEM_ITERS=35000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

Lazy AVX512 tail-state highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_kpke_keygen_full` | 3404.04 | 3416.08 | 0.9965x | 0.9974x |
| `mlkem_core_stage_sample_matrix_tail` | 707.29 | 709.19 | 0.9973x | 0.9991x |
| `mlkem_core_stage_keygen_noise_prf_cbd` | 697.09 | 697.37 | 0.9996x | 0.9996x |
| `mlkem_keygen` | 5290.52 | 5311.58 | 0.9960x | 0.9972x |
| `mlkem_keygen_core` | 5272.83 | 5267.73 | 1.0010x | 0.9985x |
| `mlkem_roundtrip_core` | 14783.49 | 14691.70 | 1.0062x | 1.0013x |

Keep the eager `tail_st` construction in the AVX512 keygen co-schedule. The
rare-case lazy branch does not help the direct keygen rows and is not worth the
extra control flow.

A narrower AVX512 state-initialization experiment for the same keygen
PRF/tail co-schedule was also rejected. The candidate replaced the mixed
`_mm512_set_epi64()` construction for `st[0..3]` with a broadcast of each sigma
word, a masked lane-6 rho overwrite, and a masked zero of lane 7. It also built
the padding words with masked moves from a shared broadcast. This made the
source express the intended lane shape more directly, but it did not produce a
real speedup; the compiler already handles the repeated `set_epi64()` inputs
well, and the masked moves add their own uops.

The candidate passed native `make test`, AVX2-only `make test`, and
`git diff --check`. Stage A/B was enough to reject it, so no KEM confirmation
was run.

Native stage A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage STAGE_ITERS=90000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

Rejected AVX512 keygen PRF/tail init highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_noise_prf_cbd` | 697.10 | 697.91 | 0.9988x | 0.9988x |
| `mlkem_core_stage_kpke_keygen_full` | 3390.75 | 3404.13 | 0.9961x | 0.9987x |
| `mlkem_core_stage_sample_matrix_tail` | 703.62 | 703.95 | 0.9995x | 1.0018x |
| `mlkem_core_stage_sample_matrix` | 1892.10 | 1887.99 | 1.0022x | 0.9997x |
| `mlkem_core_stage_keygen_noise_ntt_encode` | 1419.75 | 1423.65 | 0.9973x | 0.9969x |

Keep the existing explicit `set_epi64()` initialization in
`mlkem_keygen_prf_cbd_eta2_32_sample_tail_avx512()`. It is simpler and measured
slightly faster in the direct keygen rows.

A later keygen NTT/encode scheduling experiment was rejected. The candidate ran
all six `shat`/`ehat` forward NTTs first and then encoded the three `shat`
polynomials into the secret key, instead of keeping the existing
`ntt(shat[i]) -> encode(shat[i]) -> ntt(ehat[i])` order. The idea was to group
like NTT work, but it gave no defensible native full-keygen win and regressed
the AVX2-only full keygen stage.

Native stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage,kem STAGE_ITERS=90000 KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

Native highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_noise_ntt` | 1560.48 | 1557.43 | 1.002x | 1.002x |
| `mlkem_core_stage_keygen_noise_ntt_encode` | 1424.45 | 1423.22 | 1.001x | 1.004x |
| `mlkem_core_stage_kpke_keygen_full` | 3395.70 | 3400.68 | 0.999x | 1.000x |
| `mlkem_keygen_core` | 5276.92 | 5265.42 | 1.002x | 1.001x |

AVX2-only stage/KEM A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=stage,kem STAGE_ITERS=70000 KEM_ITERS=20000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

AVX2-only highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_noise_ntt_encode` | 1604.60 | 1594.09 | 1.007x | 1.006x |
| `mlkem_core_stage_kpke_keygen_full` | 6553.96 | 7040.20 | 0.931x | 0.916x |

Keep encoding `shat[i]` while it is hot immediately after its NTT. Grouping all
NTTs first is not robust enough for the full keygen path.

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

A narrower AVX2-only encryption schedule experiment was also rejected. The
candidate moved only the `v = sum_i(that[i] * rhat[i])` dot product before the
three `u[i]` accumulation/inverse-add pairs, while keeping the accepted per-row
`u` order and avoiding the previously rejected AVX2 `ntt_inv_add3()` batching.
The intent was to consume `rhat[0..2]` for all four public-key dot products
before the `u` inverse-add work evicts those inputs.

Correctness passed the AVX2-only core gate:

```bash
make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage,kem STAGE_ITERS=70000 KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected v-first schedule highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_encrypt_accum_inv` | 1327.23 | 1331.37 | 0.9969x | 1.0005x |
| `mlkem_core_stage_encrypt_accum_inv_u` | 1046.72 | 1045.56 | 1.0011x | 0.9981x |
| `mlkem_core_stage_encrypt_accum_inv_v` | 468.44 | 468.52 | 0.9998x | 1.0013x |
| `mlkem_core_stage_kpke_encrypt_cached` | 2438.31 | 2439.52 | 0.9995x | 1.0003x |
| `mlkem_core_stage_kpke_encrypt_uncached` | 4940.50 | 4943.53 | 0.9994x | 0.9972x |
| `mlkem_encaps` | 2693.52 | 2692.61 | 1.0003x | 0.9990x |
| `mlkem_encaps_core` | 7083.94 | 6951.51 | 1.0190x | 1.0121x |
| `mlkem_roundtrip_core` | 20235.53 | 20128.65 | 1.0053x | 1.0003x |

Reject the schedule change. The positive `encaps_core` median is not supported
by the direct encryption rows: cached K-PKE is neutral, uncached K-PKE regresses,
and the `u` accumulation/inverse-add target weakens on median. Keep computing
and inverse-adding each `u` row before the `v` dot product on AVX2-only builds;
this matches the earlier conclusion that the `u` side is sensitive to ordering
and does not benefit robustly from batching around `rhat`.

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

A native AVX512 follow-up applies the same final-fusion idea to the AVX512
`ntt_inv_sub_from_inplace()` path used by decrypt. The helper runs the AVX2
inverse head and AVX512 tail levels through `log2len = 6`, then folds the final
`log2len = 7` inverse butterfly, the `3303` inverse scale, and `v - scaled(w)`
into one 16-lane AVX512 pass. AVX2-only builds keep the existing AVX2 fused
helper. This remains a core implementation change and does not use a cache or a
vendored backend.

Correctness checks:

```bash
make clean CC=clang AVX2_BACKEND=core && make test CC=clang AVX2_BACKEND=core
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

Native NTT/stage A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=ntt,stage NTT_ITERS=220000 STAGE_ITERS=80000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

Native AVX512 decrypt final-fusion highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_ntt_inv_sub_from` | 177.56 | 169.08 | 1.0502x | 1.0499x |
| `mlkem_core_stage_decrypt_inv_sub_from` | 354.52 | 343.24 | 1.0329x | 1.0324x |
| `mlkem_core_stage_decrypt_accum_inv` | 412.41 | 402.68 | 1.0242x | 1.0260x |
| `mlkem_core_stage_decrypt_ntt_accum_recover` | 759.08 | 747.51 | 1.0155x | 1.0155x |
| `mlkem_core_stage_kpke_decrypt_cached` | 794.89 | 793.21 | 1.0021x | 1.0023x |

Longer native KEM confirmation:

```bash
RUNS=21 WARMUP_RUNS=5 SUITES=kem KEM_ITERS=60000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_decaps` | 2938.95 | 2933.08 | 1.0020x | 1.0016x |
| `mlkem_decaps_core` | 4459.93 | 4424.24 | 1.0081x | 1.0027x |
| `mlkem_roundtrip` | 10339.14 | 10325.96 | 1.0013x | 1.0006x |
| `mlkem_roundtrip_core` | 14726.99 | 14671.47 | 1.0038x | 1.0005x |

The accepted claim is local and decrypt-focused: the change reliably speeds the
AVX512 inverse-sub helper and decrypt stage, while full KEM movement is small but
confirmed no-regression in the longer run.

A second native AVX512 follow-up applies the final-fusion pattern to
`ntt_inv_add3_inplace()`, the three-polynomial inverse-add helper used for the
encapsulation `u` vector. The helper now runs the shared inverse head and AVX512
tail only through `log2len = 6`, then folds the final `log2len = 7` inverse
butterfly, `3303` inverse scale, and per-polynomial `+ e1[i]` addition into one
AVX512 pass across all three output polynomials. AVX2-only builds keep the
existing AVX2 fused helper. This is a core arithmetic/scheduling change, not a
cache or vendored-backend optimization.

Correctness checks:

```bash
make clean CC=clang AVX2_BACKEND=core && make test CC=clang AVX2_BACKEND=core
make clean CC=clang AVX2_BACKEND=core && \
  make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

Native NTT/stage A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=ntt,stage NTT_ITERS=220000 STAGE_ITERS=90000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

Native AVX512 `ntt_inv_add3` final-fusion highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_encrypt_accum_inv` | 1131.58 | 1111.25 | 1.0183x | 1.0185x |
| `mlkem_core_stage_encrypt_accum_inv_u` | 892.27 | 870.62 | 1.0249x | 1.0241x |
| `mlkem_core_stage_kpke_encrypt_cached` | 1897.01 | 1884.64 | 1.0066x | 1.0123x |
| `mlkem_core_stage_kpke_encrypt_uncached` | 3697.12 | 3627.05 | 1.0193x | 1.0080x |

Native KEM confirmation:

```bash
RUNS=17 WARMUP_RUNS=4 SUITES=kem KEM_ITERS=50000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_encaps` | 2109.08 | 2087.93 | 1.0101x | 1.0103x |
| `mlkem_encaps_core` | 4917.31 | 4885.40 | 1.0065x | 1.0061x |
| `mlkem_roundtrip` | 10321.28 | 10270.58 | 1.0049x | 1.0047x |
| `mlkem_roundtrip_core` | 14685.90 | 14647.94 | 1.0026x | 1.0038x |

The accepted claim is encapsulation-focused: the local `u` inverse-add stage
improves clearly, and the KEM confirmation keeps encapsulation and roundtrip
positive.

A narrower native AVX512 follow-up that applied the same final-fusion pattern to
`ntt_inv_add_inplace()` and `ntt_inv_add2_inplace()` was rejected. The candidate
passed native and AVX2-only core `make test`, and it did speed the direct
`ntt_inv_add`/`ntt_inv_add2` microbench rows plus the local encapsulation `v`
inverse-add stage. However, the same binary also weakened the already accepted
AVX512 decrypt inverse-sub path and did not produce clean core KEM evidence. The
likely cause is instruction/cache/code-layout pressure around several nearby
inverse-NTT helpers; the local add/add2 win is not enough to justify carrying the
extra path.

Native NTT/stage A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=ntt,stage NTT_ITERS=220000 STAGE_ITERS=90000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

Rejected AVX512 `ntt_inv_add`/`add2` final-fusion highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_ntt_inv_add` | 177.47 | 171.64 | 1.0339x | 1.0343x |
| `mlkem_ntt_inv_add2` | 187.19 | 183.10 | 1.0224x | 1.0261x |
| `mlkem_core_stage_encrypt_accum_inv_v` | 414.43 | 405.48 | 1.0221x | 1.0243x |
| `mlkem_core_stage_kpke_encrypt_cached` | 1881.43 | 1863.47 | 1.0096x | 1.0051x |
| `mlkem_ntt_inv_sub_from` | 169.10 | 171.08 | 0.9884x | 0.9884x |
| `mlkem_core_stage_decrypt_accum_inv` | 401.85 | 403.94 | 0.9948x | 0.9961x |

Native KEM confirmation:

```bash
RUNS=17 WARMUP_RUNS=4 SUITES=kem KEM_ITERS=50000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_encaps` | 2090.60 | 2092.87 | 0.9989x | 1.0035x |
| `mlkem_encaps_core` | 4881.90 | 4895.63 | 0.9972x | 0.9989x |
| `mlkem_decaps_core` | 4430.59 | 4418.14 | 1.0028x | 0.9970x |
| `mlkem_roundtrip_core` | 14717.62 | 14671.88 | 1.0031x | 1.0001x |

Keep native AVX512 final fusion limited to `ntt_inv_sub_from_inplace()` and
`ntt_inv_add3_inplace()`. Those two integrated cleanly; generic add/add2 fusion
shows useful local rows but insufficient whole-core robustness.

An AVX512 inverse-final constant-hoist follow-up was also rejected. The candidate
precomputed `3303` and `ZETA[1] * 3303` as global `__m512i` constants during
`init_ntt_roots()` and reused them from the accepted AVX512 inverse final-fusion
helpers. It passed native and AVX2-only core `make test`, but the A/B result was
weaker than keeping local `_mm512_set1_epi32()` construction. The likely reason
is that the compiler already handles these broadcasts cheaply, while global
vector loads and the changed code layout perturb nearby inverse-NTT helpers.

Native NTT/stage A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=ntt,stage NTT_ITERS=240000 STAGE_ITERS=90000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

Rejected AVX512 inverse constant-hoist highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_ntt_inv` | 169.02 | 169.73 | 0.9958x | 0.9963x |
| `mlkem_ntt_inv_add` | 177.41 | 178.67 | 0.9930x | 0.9928x |
| `mlkem_ntt_inv_add2` | 187.25 | 188.99 | 0.9908x | 0.9909x |
| `mlkem_ntt_inv_sub_from` | 169.05 | 169.31 | 0.9985x | 0.9988x |
| `mlkem_core_stage_encrypt_accum_inv` | 1111.35 | 1113.16 | 0.9984x | 0.9990x |
| `mlkem_core_stage_kpke_encrypt_cached` | 1863.84 | 1866.82 | 0.9984x | 0.9982x |
| `mlkem_core_stage_kpke_keygen_full` | 3401.21 | 3420.26 | 0.9944x | 0.9967x |

Keep the accepted AVX512 inverse helpers using local vector broadcasts for the
scale constants. This keeps the source simpler and measured faster.

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

A later bench-only direct-state diagnostic tested whether the remaining x2/x3
helpers should skip the temporary stream arrays entirely and decode CBD directly
from the `keccakf4()` state. The outputs matched the current helpers, but the
local timing did not justify a production change. Pinned CPU 0, `clang`,
`200000`-iteration snapshots measured:

| Build | Metric | ns/op | Speedup vs current |
|---|---|---:|---:|
| native | `mlkem_prf_cbd_eta2x2_current` | 180.74 | 1.000x |
| native | `mlkem_prf_cbd_eta2x2_direct` | 179.77 | 1.005x |
| native | `mlkem_prf_cbd_eta2x3_current` | 190.39 | 1.000x |
| native | `mlkem_prf_cbd_eta2x3_direct` | 191.87 | 0.992x |
| AVX2-only | `mlkem_prf_cbd_eta2x2_current` | 431.56 | 1.000x |
| AVX2-only | `mlkem_prf_cbd_eta2x2_direct` | 435.82 | 0.990x |
| AVX2-only | `mlkem_prf_cbd_eta2x3_current` | 443.16 | 1.000x |
| AVX2-only | `mlkem_prf_cbd_eta2x3_direct` | 449.66 | 0.986x |

At that point, keep the x2/x3 stream-based helpers. The direct-state form
avoided the small stream arrays but introduced a less favorable decode/store
schedule before reaching stage/KEM A/B.

After the later `keccakf4()` inline-boundary change, the direct-state cost model
changed. A fresh AVX2-only direct Keccak snapshot before productionizing the
change showed x2 and x3 direct decode both beating the old stream path locally:
`mlkem_prf_cbd_eta2x2_current` `427.40` ns/op vs direct `292.90` ns/op, and
`mlkem_prf_cbd_eta2x3_current` `417.98` ns/op vs direct `304.40` ns/op.
However, productionizing both x2 and x3 direct-state helpers together regressed
the keygen side and did not satisfy the full-path gate.

AVX2-only x2+x3 direct-state rejection highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_noise_prf_cbd` | 969.13 | 982.91 | 0.9860x | 0.9865x |
| `mlkem_core_stage_encrypt_noise_prf_cbd` | 1318.88 | 1167.72 | 1.1295x | 1.0852x |
| `mlkem_keygen_core` | 7734.20 | 7892.43 | 0.9800x | 0.9984x |
| `mlkem_roundtrip_core` | 22136.75 | 22196.27 | 0.9973x | 0.9981x |

The accepted production change at that point was narrower: keep x2 stream-based,
but decode the AVX2-only x3 helper directly from the `keccakf4()` state. This
targeted the second encryption noise batch and avoided changing the keygen x4+x2
composition. The later 2026-07-03 eta2x2 direct PRF/CBD change supersedes the x2
part of this older decision on the current AVX2-only baseline.
The x3 direct path is guarded away from AVX512 builds, where the main PRF/CBD
paths use x6/x7 helpers and a native KEM no-regression check is the relevant
criterion.

AVX2-only x3-only direct-state stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage,kem STAGE_ITERS=50000 KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Accepted x3-only highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_noise_prf_cbd` | 971.41 | 973.10 | 0.9983x | 1.0001x |
| `mlkem_core_stage_encrypt_noise_prf_cbd` | 1299.75 | 1170.32 | 1.1106x | 1.0858x |
| `mlkem_core_stage_kpke_encrypt_cached` | 2620.87 | 2440.66 | 1.0738x | 1.0505x |
| `mlkem_keygen_core` | 8054.26 | 7680.52 | 1.0487x | 1.0012x |
| `mlkem_encaps_core` | 7609.75 | 7742.79 | 0.9828x | 0.9980x |
| `mlkem_roundtrip_core` | 22709.08 | 22608.02 | 1.0045x | 1.0026x |

A longer AVX2-only KEM confirmation with `RUNS=17`, `KEM_ITERS=50000` kept the
full-path signal: `mlkem_keygen_core` median `1.0015x`, `mlkem_encaps_core`
`1.0363x`, `mlkem_decaps_core` `1.0676x`, and `mlkem_roundtrip_core` `1.1029x`.
A native `-march=native` KEM no-regression run with `RUNS=9`, `KEM_ITERS=30000`
stayed neutral-to-positive on the core rows (`mlkem_roundtrip_core` median
`1.0053x`).

A follow-up x2-only direct-state experiment was rejected on that older baseline.
The candidate kept AVX512/native on the original stream path, used direct state
decode only on AVX2-only builds, and marked `mlkem_prf_cbd_eta2x2_32()`
`MLKEM_NOINLINE` to avoid the keygen code-layout regression seen in the x2+x3
attempt. The local stage row improved, but full KEM averages moved the wrong way
and medians were only neutral. This historical rejection is superseded by the
2026-07-03 AVX2 eta2x2 direct PRF/CBD A/B above, which remeasured the same
noinline direct-state shape on the current baseline and accepted it after longer
KEM confirmation.

Rejected x2 direct/noinline highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_noise_prf_cbd` | 971.75 | 962.45 | 1.0097x | 1.0096x |
| `mlkem_core_stage_kpke_keygen_full` | 5823.79 | 5815.90 | 1.0014x | 0.9990x |
| `mlkem_keygen_core` | 7880.07 | 7927.45 | 0.9940x | 1.0001x |
| `mlkem_encaps_core` | 7216.63 | 7476.38 | 0.9653x | 1.0009x |
| `mlkem_roundtrip_core` | 21858.17 | 22257.79 | 0.9820x | 1.0006x |

At that point, x2 stayed stream-based because the keygen/KEM integration did not
give enough full-path signal to justify another code-shape variant. The current
production code now uses the later accepted noinline direct-state x2 helper; keep
this older table only as evidence that the x2 direct shape is baseline-sensitive
and must be checked at KEM level.

A smaller AVX2-only x2 stream-extraction cleanup was also rejected. The
candidate kept the then-accepted stream-based `mlkem_prf_cbd_eta2x2_32()` design, but
replaced the per-lane `uint64_t words[4]` store plus two 8-byte `memcpy()` calls
with two `_mm_storel_epi64()` stores from the low 128 bits of the `keccakf4()`
state. This preserved the byte-stream CBD decoder and only tried to remove the
extra stack round trip for the two live lanes.

Correctness passed the AVX2-only core gate:

```bash
make test CC=clang AVX2_BACKEND=core ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt"
```

AVX2-only stage/KEM A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage,kem STAGE_ITERS=70000 KEM_ITERS=30000 \
  C_COMPILER=clang PIN_CPU=0 ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected x2 stream-extract highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_noise_prf_cbd` | 980.88 | 975.24 | 1.0058x | 1.0006x |
| `mlkem_core_stage_keygen_noise_ntt` | 1997.36 | 1994.53 | 1.0014x | 0.9998x |
| `mlkem_core_stage_kpke_keygen_full` | 4918.28 | 4936.74 | 0.9963x | 0.9999x |
| `mlkem_keygen_core` | 7045.77 | 7097.91 | 0.9927x | 0.9979x |
| `mlkem_roundtrip` | 13513.88 | 13582.04 | 0.9950x | 0.9958x |
| `mlkem_roundtrip_core` | 20468.87 | 20546.99 | 0.9962x | 1.0019x |

Keep the current x2 stream extraction. The local PRF/CBD row improves only in
average, not meaningfully in median, and the integrated keygen/KEM rows do not
support carrying a separate extraction shape.

A follow-up marking the accepted x3 direct helper `MLKEM_NOINLINE` was rejected.
The short stage/KEM run showed a local encryption-noise improvement, but the
longer AVX2-only KEM confirmation regressed the full path.

Rejected x3 noinline highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_encrypt_noise_prf_cbd` | 1169.54 | 1146.37 | 1.0202x | 1.0192x |
| `mlkem_core_stage_kpke_encrypt_cached` | 2452.12 | 2425.39 | 1.0110x | 1.0082x |
| `mlkem_encaps_core` | 7596.27 | 7442.44 | 1.0207x | 1.0040x |
| `mlkem_roundtrip_core` | 22101.47 | 22196.47 | 0.9957x | 1.0038x |

The longer `RUNS=17`, `KEM_ITERS=50000` confirmation rejected the attribute:
`mlkem_decaps_core` median `0.9417x` and `mlkem_roundtrip_core` median
`0.9635x`. Keep the accepted x3 helper inlineable; forcing a call boundary
hurts the broader AVX2-only KEM layout.

A follow-up folding the accepted x3 direct-state loop from
`sample_poly_cbd_eta2_store2_avx2()` plus `sample_poly_cbd_eta2_store1_avx2()`
into a new `sample_poly_cbd_eta2_store3_avx2()` helper was rejected. The
candidate only changed the AVX2-only x3 direct-state path and tried to share the
ETA2 decode LUT/mask setup across the three live output streams for each
`keccakf4()` state word. Correctness passed in both native and AVX2-only test
builds, but the measured helper win was effectively neutral and did not hold in
the longer KEM gate.

Focused AVX2-only Keccak/PRF-CBD A/B (`RUNS=13`, `KECCAK_ITERS=200000`) showed
only a tiny local signal:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_prf_cbd_eta2x3_current` | 306.96 | 306.16 | 1.0026x | 1.0008x |
| `mlkem_cbd_eta2x3` | 29.96 | 29.74 | 1.0076x | 1.0037x |

Rejected x3 store3-helper highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_encrypt_noise_prf_cbd` | 1170.15 | 1170.53 | 0.9997x | 1.0003x |
| `mlkem_core_stage_kpke_encrypt_cached` | 2444.42 | 2445.34 | 0.9996x | 1.0010x |
| `mlkem_encaps_core` | 7480.93 | 7387.04 | 1.0127x | 1.0015x |
| `mlkem_roundtrip_core` | 22858.43 | 22333.67 | 1.0235x | 1.0072x |

The longer AVX2-only `RUNS=17`, `KEM_ITERS=50000` confirmation rejected the
change: `mlkem_encaps_core` median `0.9997x` and `mlkem_roundtrip_core` median
`0.9998x`. Keep the simpler `store2` plus `store1` composition; after the
accepted `keccakf4()` inline and x3 direct-state changes, this decode scheduling
is no longer a useful bottleneck.

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

A later unsigned-lookup variant was rejected. It replaced the signed
`{-2..2}` nibble LUT plus negative canonicalization with two byte LUTs that
materialized canonical 16-bit `{0,1,2,Q-2,Q-1}` values directly. This removed
the compare/add canonicalization but doubled the shuffle lookup work and was
slower in both the standalone CBD row and the integrated PRF/CBD stages.

Native Keccak/stage A/B command:

```bash
RUNS=9 WARMUP_RUNS=2 SUITES=keccak,stage KECCAK_ITERS=200000 STAGE_ITERS=70000 \
  C_COMPILER=clang PIN_CPU=0 ./scripts/bench_core_ab.sh HEAD
```

A/B highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_cbd_eta2` | 7.34 | 10.44 | 0.703x | 0.701x |
| `mlkem_core_stage_keygen_noise_prf_cbd` | 694.88 | 710.69 | 0.978x | 0.977x |
| `mlkem_core_stage_encrypt_noise_prf_cbd` | 878.37 | 899.45 | 0.977x | 0.977x |
| `mlkem_core_stage_encrypt_noise` | 1023.29 | 1062.58 | 0.963x | 0.963x |

Keep the signed nibble LUT and canonicalize with AVX2 compare/add.

A narrower AVX2 ETA2 CBD constant-hoist experiment was rejected. The candidate
changed `cbd_eta2_canonicalize_i8x16()` and the `sample_poly_cbd_eta2_store1/2`
helpers to pass prebuilt `lut`, `mask`, `zero`, and `Q` vectors from the outer
byte/state decode loops instead of constructing them in the small helpers. The
intent was to remove repeated constant setup in the x4/x6/x7 PRF/CBD state
paths. Native and AVX2-only `make test` passed, but AVX2-only stage A/B showed
that the extra helper arguments/code shape did not improve the integrated noise
paths and regressed full keygen.

AVX2-only stage A/B command:

```bash
RUNS=13 WARMUP_RUNS=3 SUITES=stage STAGE_ITERS=70000 \
  C_COMPILER=clang ARCH_CFLAGS="-mavx2 -mbmi2 -mpopcnt" PIN_CPU=0 \
  ./scripts/bench_core_ab.sh HEAD
```

Rejected CBD constant-hoist highlights:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_core_stage_keygen_noise_prf_cbd` | 1274.66 | 1330.59 | 0.9580x | 0.9999x |
| `mlkem_core_stage_encrypt_noise_prf_cbd` | 1462.65 | 1515.81 | 0.9649x | 0.9993x |
| `mlkem_core_stage_keygen_noise_ntt` | 2310.93 | 2361.11 | 0.9787x | 0.9999x |
| `mlkem_core_stage_kpke_keygen_full` | 7041.53 | 7097.35 | 0.9921x | 0.9923x |
| `mlkem_core_stage_kpke_encrypt_cached` | 2823.15 | 2824.23 | 0.9996x | 0.9992x |

Keep the current local constants inside the small CBD helpers. Clang already
handles the immediate vector constants well enough, and explicitly threading
those vectors through the helper interface increases register pressure/code
layout without a PRF/CBD win.

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

A later split-input variant was rejected. The candidate added a local
`sha3_512_32x2(in0, in1, out)` helper and replaced the `inbuf[64]` concatenation
in `mlkem_encaps()`, the cache-enabled `mlkem_decaps()` path, and the scalar
no-cache public-preparation fallback. It passed native and AVX2-only core
`make test`, but the KEM signal was neutral at best. Non-inline helper form
regressed `mlkem_encaps` median speedup to `0.9969x`; the `static inline` form
recovered that to effectively flat.

Split 32+32 SHA3-512 helper KEM A/B, `30000` iterations, thirteen repeated runs:

| Metric | Baseline ns/op | Candidate ns/op | Avg speedup | Median speedup |
|---|---:|---:|---:|---:|
| `mlkem_decaps` | 2938.08 | 2939.44 | 0.9995x | 0.9986x |
| `mlkem_decaps_core` | 4439.74 | 4456.46 | 0.9962x | 1.0011x |
| `mlkem_encaps` | 2115.51 | 2114.70 | 1.0004x | 1.0001x |
| `mlkem_encaps_core` | 4923.64 | 4918.93 | 1.0010x | 1.0006x |
| `mlkem_roundtrip` | 10381.00 | 10354.50 | 1.0026x | 1.0016x |
| `mlkem_roundtrip_core` | 14714.99 | 14715.27 | 1.0000x | 1.0007x |

Keep the existing contiguous 64-byte fixed-length `sha3_512()` path. The
64-byte stack concatenation is not a measurable bottleneck next to the Keccak
permutation, and direct split loading does not produce a defensible KEM win.

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
