# Native all-comparator speed gate

This report records the formal native speed gate for the independent
baby-mlkem ML-KEM-768 production core. It closes the native speed portion of
the completion contract; it does not close the production size, maximum-stack,
or final correctness gates.

## Environment and method

- measured baby-mlkem commit: `513a2d2db512a3a81b18ddabbfa05a2bfa62b18f`
- report time: `2026-08-06T01:56:00Z`
- CPU: AMD Ryzen Threadripper 7980X 64-Cores, pinned to logical CPU 0
- OS: Linux 6.8.0-124-generic
- C/C++ compiler: Ubuntu Clang 18.1.3
- local artifact: `bench_productc` linked with `baby_mlkem768_product.o`
- local backend and metric: independent `AVX2_BACKEND=core` and
  `mlkem_roundtrip_core_ns_per_op`, with no persistent KEM-result cache
- ISA policy: `-march=native`; every comparator was allowed its fastest
  supported production path on this host
- measured pairs: 15 after 3 untimed warmup pairs
- iterations per binary and pair: 100,000
- order: local first for odd pairs, comparator first for even pairs
- interval: deterministic 20,000-sample paired bootstrap 95% CI
- repository policy: every Git comparator was updated from its authoritative
  remote, left clean, and recorded; compiler or repository fallback was fatal

Ratios are `comparator time / baby-mlkem time`, so values above 1.0 favor
baby-mlkem. Each cell contains the ratio of medians followed by the paired
geometric-mean 95% CI. The aggregate gate requires a roundtrip ratio of at
least 1.05 and CI lower bound above 1.0. Each operation additionally requires a
ratio of at least 1.0 and CI lower bound at least 1.0.

## Results

| Comparator | Keygen ratio (95% CI) | Encaps ratio (95% CI) | Decaps ratio (95% CI) | Roundtrip ratio (95% CI) |
|---|---:|---:|---:|---:|
| pq-crystals Kyber AVX2 | 1.3115x (1.2961x-1.3134x) | 1.4560x (1.4360x-1.4550x) | 2.0325x (2.0163x-2.0383x) | 1.5620x (1.5497x-1.5636x) |
| pq-crystals Kyber AVX2, fair flags | 1.3147x (1.3093x-1.3241x) | 1.4560x (1.4339x-1.4591x) | 2.0381x (1.9672x-2.0412x) | 1.5607x (1.5441x-1.5637x) |
| mlkem-native | 1.6774x (1.6469x-1.6753x) | 2.0119x (1.9694x-2.0083x) | 3.3082x (3.2516x-3.3065x) | 2.2197x (2.1831x-2.2184x) |
| PQClean AVX2 | 1.6746x (1.6637x-1.6973x) | 1.8427x (1.8108x-1.8462x) | 2.6454x (2.6207x-2.6881x) | 2.0104x (1.9845x-2.0139x) |
| liboqs | 1.5196x (1.5046x-1.5262x) | 1.8473x (1.8289x-1.8467x) | 3.0370x (2.9538x-3.0350x) | 2.0178x (1.9963x-2.0212x) |
| BoringSSL | 3.1020x (3.0500x-3.1209x) | 1.4052x (1.3952x-1.4110x) | 3.0007x (2.9330x-3.0060x) | 3.0201x (3.0010x-3.0317x) |
| libcrux 0.0.8 | 1.6092x (1.6019x-1.6161x) | 1.9463x (1.9233x-1.9576x) | 2.6358x (2.5975x-2.6438x) | 2.0028x (1.9889x-2.0088x) |
| libjade Kyber768 AVX2 | 1.9022x (1.8579x-1.9047x) | 2.3493x (2.3123x-2.3482x) | 2.3370x (2.3113x-2.3439x) | 2.0676x (2.0485x-2.0673x) |
| Botan ML-KEM | 7.4107x (7.4039x-7.6496x) | 1.6097x (1.5865x-1.6626x) | 3.7438x (3.6846x-3.7386x) | 7.5749x (7.5302x-7.6732x) |
| OpenSSL ML-KEM | 5.1665x (5.1216x-5.1863x) | 3.6121x (3.5751x-3.6158x) | 6.7392x (6.5657x-6.7574x) | 5.0181x (4.9748x-5.0234x) |

| Comparator | baby-mlkem roundtrip median (ns) | Comparator roundtrip median (ns) | Wins |
|---|---:|---:|---:|
| pq-crystals Kyber AVX2 | 10,367.73 | 16,194.60 | 15/15 |
| pq-crystals Kyber AVX2, fair flags | 10,370.31 | 16,185.14 | 15/15 |
| mlkem-native | 10,341.07 | 22,953.64 | 15/15 |
| PQClean AVX2 | 10,338.33 | 20,784.36 | 15/15 |
| liboqs | 10,361.47 | 20,906.95 | 15/15 |
| BoringSSL | 10,455.81 | 31,577.81 | 15/15 |
| libcrux 0.0.8 | 10,356.58 | 20,742.06 | 15/15 |
| libjade Kyber768 AVX2 | 10,364.92 | 21,430.45 | 15/15 |
| Botan ML-KEM | 10,363.02 | 78,498.63 | 15/15 |
| OpenSSL ML-KEM | 10,363.39 | 52,004.99 | 15/15 |

All 40 operation/comparator rows pass. The narrowest aggregate result is
1.5607x with a 1.5441x CI lower bound against pq-crystals Kyber AVX2 with fair
flags. The narrowest operation result is Kyber keygen at 1.3115x with a 1.2961x
CI lower bound. The formal verifier therefore reports `goal_speed_gate=PASS`.

## Comparator provenance

| Comparator | Recorded source identity |
|---|---|
| pq-crystals Kyber | `3edd5af5991927164edd4aacebfcbee00b8064e7` |
| PQClean | `0586a824fc0d49df0b6b6e9179d8d15d06d0974f` |
| mlkem-native | `852fc4b38057d18120aab32537fd361468d38e4f` |
| liboqs | `9d20051143544daa348bc0bbdcef5ef121e385d3` |
| BoringSSL | `5b0508f29ec17a6a2d4780b3d2715a7feaa99d40` |
| Botan | `a8f6c6a59e850016f77dd2a1d3d10991d2610eba` |
| OpenSSL | `9c4d2c7bff92e678b88a5964a11c7057925a0bbb` |
| libcrux | crate `libcrux-ml-kem` 0.0.8; Cargo.lock SHA-256 `3a8da26467c551b3965aabd706fc86137fbf18eef3ada704178851510a4599bc` |
| libjade | release `2023.05-2`; assembly SHA-256 `358736656400f28f75db858c1be703a3140c8f6fac17b99279abc857112cf5d1` |

The raw report records each Git remote, exact effective flags, every paired
measurement, and every statistic. Its SHA-256 is
`2f66e06d17f6fcb10ba7d517f8c9b346aa0caf198e307359d2dc14f0e78a2a01`.
The stderr capture has SHA-256
`953e20518142d1e6e13eeeefa7f3187bd9d3b620ebfbb03a9568bfb72acee363`;
it contains only build notices and GNU-stack/libunwind warnings, not update,
compiler-fallback, benchmark, or verifier failures.

The external projects above are build-time benchmark comparators only. They are
not linked into or required by the baby-mlkem production artifact.

## Reproduction

Populate the comparator directories accepted by `verify_goal_speed.sh` (or set
its documented directory variables), then run from a clean committed worktree:

```bash
RUNS=15 WARMUP_RUNS=3 BOOTSTRAP_SAMPLES=20000 \
PIN_CPU=0 C_COMPILER=clang \
REPORT_FILE=/tmp/baby-mlkem-goal-native-speed.txt \
./scripts/verify_goal_native_speed.sh 100000
```

The strict runner forces repository updates, the exact ten-suite set, cache
rejection, the production/no-cache metric, native flags, and fail-closed
compiler selection. Recheck the committed raw report with:

```bash
./scripts/verify_goal_speed_report.py \
  benchmarks/2026-08-06-goal-native-speed/clang-native.txt \
  --expected-suites kyber_upstream_avx2,kyber_upstream_avx2_fair,mlkem_native,pqclean_avx2,liboqs,boringssl,libcrux_rust,libjade_kyber768_avx2,botan_mlkem,openssl_mlkem \
  --expected-profile native --min-runs 15 --min-warmups 3 \
  --min-bootstrap-samples 20000 --min-aggregate-speedup 1.05 \
  --min-operation-speedup 1.0 --require-updated-repos
```

Raw files:

- `clang-native.txt`: complete metadata, paired measurements, and statistics
- `clang-native.txt.stderr`: build/update diagnostic stream
