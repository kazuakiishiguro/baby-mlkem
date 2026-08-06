# AVX2-only all-comparator speed gate

This report records the formal AVX2-only speed gate for the independent
baby-mlkem ML-KEM-768 production core. It closes the AVX2-only speed portion of
the completion contract; it does not close the native speed, production size,
maximum-stack, or final correctness gates.

## Environment and method

- measured baby-mlkem commit: `245823e9414984e46b1ee2675dd0e95855dcc6d8`
- report time: `2026-08-06T01:02:52Z`
- CPU: AMD Ryzen Threadripper 7980X 64-Cores, pinned to logical CPU 0
- OS: Linux 6.8.0-124-generic
- C/C++ compiler: Ubuntu Clang 18.1.3
- local artifact: `bench_productc` linked with `baby_mlkem768_product.o`
- local backend and metric: independent `AVX2_BACKEND=core` and
  `mlkem_roundtrip_core_ns_per_op`, with no persistent KEM-result cache
- ISA policy: `-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f`;
  runtime AVX512 paths were disabled and the local object passed an AVX512
  register/symbol audit
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
| pq-crystals Kyber AVX2 | 1.1412x (1.1401x-1.1713x) | 1.3869x (1.3720x-1.4146x) | 1.5794x (1.5798x-1.6235x) | 1.3505x (1.3409x-1.3569x) |
| pq-crystals Kyber AVX2, fair flags | 1.1599x (1.1569x-1.2101x) | 1.3964x (1.3870x-1.4092x) | 1.5857x (1.5823x-1.6033x) | 1.3525x (1.3503x-1.3731x) |
| mlkem-native | 1.1636x (1.1524x-1.1642x) | 1.5381x (1.5096x-1.5362x) | 2.0734x (2.0591x-2.0735x) | 1.5275x (1.5191x-1.5299x) |
| PQClean AVX2 | 1.1766x (1.1750x-1.1972x) | 1.4233x (1.4143x-1.4438x) | 1.6806x (1.6738x-1.7063x) | 1.3970x (1.3924x-1.4100x) |
| liboqs | 1.2538x (1.2496x-1.2619x) | 1.6519x (1.6353x-1.6691x) | 2.1479x (2.1465x-2.1685x) | 1.6282x (1.6222x-1.6325x) |
| BoringSSL | 2.4182x (2.3985x-2.4217x) | 1.3500x (1.3241x-1.3551x) | 2.2751x (2.2459x-2.2767x) | 2.4367x (2.4155x-2.4404x) |
| libcrux 0.0.8 | 1.3758x (1.3741x-1.3802x) | 1.7954x (1.7849x-1.7997x) | 1.9982x (1.9868x-2.0030x) | 1.6753x (1.6696x-1.6778x) |
| libjade Kyber768 AVX2 | 1.3241x (1.3201x-1.3257x) | 1.7987x (1.7887x-1.7999x) | 1.4697x (1.4631x-1.4720x) | 1.4272x (1.4211x-1.4280x) |
| Botan ML-KEM | 5.3361x (5.2859x-5.3382x) | 1.4450x (1.4425x-1.4528x) | 2.6510x (2.6399x-2.6603x) | 5.4596x (5.4398x-5.4630x) |
| OpenSSL ML-KEM | 3.5922x (3.5592x-3.6746x) | 2.7541x (2.7481x-2.7666x) | 4.2378x (4.2104x-4.2375x) | 3.4622x (3.4493x-3.4963x) |

| Comparator | baby-mlkem roundtrip median (ns) | Comparator roundtrip median (ns) | Wins |
|---|---:|---:|---:|
| pq-crystals Kyber AVX2 | 14,998.29 | 20,255.36 | 15/15 |
| pq-crystals Kyber AVX2, fair flags | 15,017.89 | 20,311.88 | 15/15 |
| mlkem-native | 15,036.85 | 22,968.62 | 15/15 |
| PQClean AVX2 | 15,007.80 | 20,965.16 | 15/15 |
| liboqs | 15,011.17 | 24,440.64 | 15/15 |
| BoringSSL | 15,036.65 | 36,640.12 | 15/15 |
| libcrux 0.0.8 | 15,005.08 | 25,137.99 | 15/15 |
| libjade Kyber768 AVX2 | 15,000.67 | 21,408.73 | 15/15 |
| Botan ML-KEM | 14,995.50 | 81,868.87 | 15/15 |
| OpenSSL ML-KEM | 15,012.58 | 51,975.91 | 15/15 |

All 40 operation/comparator rows pass. The narrowest aggregate result is
1.3505x with a 1.3409x CI lower bound against pq-crystals Kyber AVX2. The
narrowest operation result is Kyber keygen at 1.1412x with a 1.1401x CI lower
bound. The formal verifier therefore reports `goal_speed_gate=PASS`.

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
`a28034dfe5fa317a3faffaa0e92fe3aa42f3404118ae1329933014200839c1e2`.
The stderr capture has SHA-256
`c94ff23caaca1a6bbb5b6245689fdaf0a59443a8e7958d8580782444dd899620`;
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
REPORT_FILE=/tmp/baby-mlkem-goal-avx2-speed.txt \
./scripts/verify_goal_avx2_speed.sh 100000
```

The strict runner forces repository updates, the exact ten-suite set, cache
rejection, the production/no-cache metric, AVX2-only flags, and fail-closed
compiler selection. Recheck the committed raw report with:

```bash
./scripts/verify_goal_speed_report.py \
  benchmarks/2026-08-06-goal-avx2-speed/clang-avx2-only.txt \
  --expected-suites kyber_upstream_avx2,kyber_upstream_avx2_fair,mlkem_native,pqclean_avx2,liboqs,boringssl,libcrux_rust,libjade_kyber768_avx2,botan_mlkem,openssl_mlkem \
  --expected-profile avx2 --min-runs 15 --min-warmups 3 \
  --min-bootstrap-samples 20000 --min-aggregate-speedup 1.05 \
  --min-operation-speedup 1.0 --require-updated-repos
```

Raw files:

- `clang-avx2-only.txt`: complete metadata, paired measurements, and statistics
- `clang-avx2-only.txt.stderr`: build/update diagnostic stream
