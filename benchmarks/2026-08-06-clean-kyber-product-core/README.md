# Production/no-cache core versus clean Kyber AVX2

This native-profile milestone compares the finalized baby-mlkem production
artifact with a cache-free Kyber AVX2 snapshot. It also records and invalidates
a misleading result obtained from the repository's experimentally modified
vendored copy.

This is not the final speed-goal report. It covers one historical comparator
snapshot, not the complete current authoritative comparator set, and it does not
cover the AVX2-only profile.

## Environment and provenance

- measured baby-mlkem commit: `755c4a0`
- cache-audit follow-up: `e762e18`
- CPU: AMD Ryzen Threadripper 7980X 64-Cores, pinned to logical CPU 0
- OS: Linux 6.8.0-124-generic
- compiler: Ubuntu Clang 18.1.3
- local artifact: `bench_productc` linked with `baby_mlkem768_product.o`
- local metric: `mlkem_roundtrip_core_ns_per_op`
- comparator: `include/kyber_upstream` exported from repository commit
  `932013626cdf8853af8aadc00c1d9b84ab6066ca`
- measured pairs: 15 after 3 untimed warmup pairs
- iterations per binary and pair: 100,000
- order: local first for odd pairs, comparator first for even pairs
- interval: deterministic 20,000-sample paired bootstrap 95% CI

The imported comparator snapshot has no `pk_cache`, `public_key_cache`, or
`indcpa_enc_precomp` implementation. Its external pq-crystals commit was not
recorded when it was imported, so this result is explicitly a historical clean
snapshot milestone rather than evidence about current upstream HEAD.

## Valid no-cache result

Ratios are `comparator median time / baby-mlkem median time`; values above 1.0
favor baby-mlkem.

| Operation | baby-mlkem median (ns) | clean Kyber median (ns) | Ratio of medians | Paired gmean 95% CI | Wins |
|---|---:|---:|---:|---:|---:|
| keygen | 3,936.23 | 5,183.07 | 1.3168x | 1.3116x-1.3228x | 15/15 |
| encaps | 3,497.34 | 5,103.93 | 1.4594x | 1.4425x-1.4607x | 15/15 |
| decaps | 2,807.53 | 5,715.72 | 2.0359x | 2.0104x-2.0391x | 15/15 |
| roundtrip | 10,364.71 | 16,221.68 | 1.5651x | 1.5571x-1.5695x | 15/15 |

`verify_goal_speed_report.py` passes this single-comparator report at the goal's
15-run, 3-warmup, 20,000-bootstrap, per-operation non-regression, and 1.05x
aggregate thresholds. The full Goal remains open until the same gate passes all
required current comparators in both native and AVX2-only profiles.

## Rejected cached-vendor diagnostic

The first run accidentally used the current `include/kyber_upstream` tree. That
tree is not upstream-equivalent: commits `13c7e19`, `182f644`, and `24f0b10`
added persistent decoded-public-key, transposed-matrix, and public-key-hash
caches plus a precomputed encryption path. The fixed public key in the encaps
microbenchmark was therefore a warmed cache hit.

That invalid run reported Kyber encaps at 1,267.13 ns and baby-mlkem at 3,490.96
ns (`0.3630x`). It cannot support a no-cache claim and must not be used to select
a core bottleneck. The adjacent file is retained only as negative evidence and
is named `rejected` accordingly.

Commit `e762e18` makes `bench_compare_kyber_upstream.sh` scan the actual
comparator source and refuse known persistent-cache implementations before it
builds or times them. `ALLOW_CACHED_COMPARATOR=1` is available only for an
explicitly non-qualifying diagnostic; the strict Goal runner forces it to zero.

## Reproduction

```bash
snapshot_root="$(mktemp -d /tmp/baby-mlkem-clean-kyber.XXXXXX)"
git archive 932013626cdf8853af8aadc00c1d9b84ab6066ca \
  include/kyber_upstream | tar -x -C "$snapshot_root"

make clean CC=clang
make bench-product CC=clang

KYBER_DIR="$snapshot_root/include/kyber_upstream" \
BENCH_SUITES=kyber_upstream_avx2 \
WARMUP_RUNS=3 STATS_MODE=median BOOTSTRAP_SAMPLES=20000 \
SKIP_LOCAL_BUILD=1 LOCAL_BENCH_BIN="$PWD/bench_productc" \
LOCAL_PREHEAT_ITERS=64 PIN_CPU=0 C_COMPILER=clang UPDATE_REPOS=0 \
CLEAN_LOCAL_BUILD_ARTIFACTS=0 \
./scripts/bench_compare_all_stats.sh 100000 15
```

Raw files:

- `clang-native-clean-import.txt`: qualifying single-comparator measurement
- `clang-native-rejected-cached-vendor.txt`: invalid cached-vendor diagnostic
