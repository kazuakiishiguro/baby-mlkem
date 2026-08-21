# AVX2-only all-comparator speed gate

This directory records the formal AVX2-only speed measurement for the current
baby-mlkem ML-KEM-768 production core at commit `d5e58a8`. The speed gate
passes all ten comparator suites and all forty operation rows, including the
local AVX512 instruction audit.

## Environment and method

- measured baby-mlkem commit: `d5e58a82e49d4853c7e66148e451740c708c2afe`
- report time: `2026-08-21T17:27:15Z`
- CPU: AMD Ryzen Threadripper 7980X 64-Cores, pinned to logical CPU 0
- OS: Linux 6.8.0-124-generic
- C/C++ compiler: Ubuntu Clang 18.1.3
- local artifact: `bench_productc` linked with the production-only object
- metric: `mlkem_roundtrip_core_ns_per_op`, with no persistent KEM cache
- ISA policy: `-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f`
- comparator policy: AVX512 dispatch paths disabled where applicable
- local artifact audit: no AVX512 registers or symbols
- samples: 15 measured pairs after 3 warmup pairs, 100,000 iterations each
- order: local first for odd pairs, comparator first for even pairs
- interval: deterministic 20,000-sample paired bootstrap 95% CI
- source policy: Git comparators were updated once before timing, then pinned
  for the complete run; repository and compiler fallback remained fatal

Ratios are `comparator time / baby-mlkem time`. Each table entry is
`ratio of medians / paired 95% CI lower bound`; values above 1 favor
baby-mlkem.

## Results

| Comparator | Keygen | Encaps | Decaps | Roundtrip |
|---|---:|---:|---:|---:|
| pq-crystals Kyber AVX2 | 1.1684x / 1.1604x | 1.4485x / 1.4433x | 1.6072x / 1.6101x | 1.3759x / 1.3747x |
| pq-crystals Kyber AVX2, fair flags | 1.1779x / 1.1632x | 1.4543x / 1.4518x | 1.6185x / 1.5966x | 1.3823x / 1.3740x |
| mlkem-native | 1.1295x / 1.1180x | 1.5054x / 1.4980x | 1.9479x / 1.9002x | 1.4727x / 1.4556x |
| PQClean AVX2 | 1.1872x / 1.1861x | 1.4586x / 1.4520x | 1.6866x / 1.6468x | 1.4030x / 1.4002x |
| liboqs | 1.2757x / 1.2737x | 1.7131x / 1.6999x | 2.1638x / 2.1230x | 1.6556x / 1.6413x |
| BoringSSL | 2.5229x / 2.4875x | 2.9156x / 2.8820x | 3.9242x / 3.7607x | 2.9939x / 2.9490x |
| libcrux 0.0.10 | 1.4194x / 1.4167x | 1.8744x / 1.8675x | 2.0652x / 2.0514x | 1.7288x / 1.7218x |
| libjade Kyber768 AVX2 | 1.1079x / 1.1015x | 1.8472x / 1.8194x | 1.4823x / 1.4672x | 1.4356x / 1.4242x |
| Botan ML-KEM | 5.6044x / 5.5595x | 5.4570x / 5.4336x | 6.9047x / 6.8990x | 5.9107x / 5.8875x |
| OpenSSL ML-KEM | 3.6818x / 3.6465x | 2.8496x / 2.8326x | 4.3280x / 4.2135x | 3.5477x / 3.5088x |

The narrowest aggregate ratio is 1.3759x against standard-flags Kyber. The
narrowest aggregate CI lower bound is 1.3740x against fair-flags Kyber. The
narrowest operation ratio and CI lower bound are 1.1079x and 1.1015x for
libjade keygen.

## Comparator provenance

| Comparator | Source identity |
|---|---|
| pq-crystals Kyber | `3edd5af5991927164edd4aacebfcbee00b8064e7` |
| PQClean | `0586a824fc0d49df0b6b6e9179d8d15d06d0974f` |
| mlkem-native | `69d24e37b8a04c6050ec55bc84a4228d7051bb4b` |
| liboqs | `8979276ad1eb008215aa78a3c56b3649f604bbb1` |
| BoringSSL | `a0689af29e8e460f1e5380e0fb74cef1b342e810` |
| Botan | `4fae673d77af6b1cd4a235951d25b14b51f7e753` |
| OpenSSL | `b64f68a94e61fa2363c598c75444482b48056697` |
| libcrux | crate 0.0.10; lock SHA-256 `f5ba14023113fc34c5ee11ea83c9633ecbccb2adc8bd18786f3096bfe67b972a` |
| libjade | release 2023.05-2; assembly SHA-256 `358736656400f28f75db858c1be703a3140c8f6fac17b99279abc857112cf5d1` |

The comparator projects are benchmark-time sources only. No comparator object,
vendor backend, runtime library, cache, API, algorithm, or wire-format change
is linked into the baby-mlkem production artifact.

## Files and hashes

| File | SHA-256 |
|---|---|
| `clang-avx2-only.txt` | `0e47860ed0e4c08f0f98aec9a9040efff041cd0bfdfc409a0b8a6461d1e06f38` |
| `clang-avx2-only.txt.raw` | `7b3a67194493a89a9bccde2883abf3109f16a8150f55ec0dd8a994fb250a4f55` |
| `clang-avx2-only.txt.stderr` | `76326b2c51ecc28978a491bf0455bf3b1d012f168e7f8415999cbb50f3e58e5c` |
| `clang-avx2-only.verifier.txt` | `66ee9816e5725cb646075fff2e37b4d5717340920a9365c03f3e6c0cd26f9c9e` |

## Reproduction

From a clean committed worktree with the comparator directories populated:

```bash
RUNS=15 WARMUP_RUNS=3 BOOTSTRAP_SAMPLES=20000 \
PIN_CPU=0 C_COMPILER=clang \
REPORT_FILE=/tmp/baby-mlkem-goal-avx2-speed.txt \
./scripts/verify_goal_avx2_speed.sh 100000
```

Recheck the committed report with:

```bash
./scripts/verify_goal_speed_report.py \
  benchmarks/2026-08-22-goal-avx2-speed/clang-avx2-only.txt \
  --expected-suites kyber_upstream_avx2,kyber_upstream_avx2_fair,mlkem_native,pqclean_avx2,liboqs,boringssl,libcrux_rust,libjade_kyber768_avx2,botan_mlkem,openssl_mlkem \
  --expected-profile avx2 --min-runs 15 --min-warmups 3 \
  --min-bootstrap-samples 20000 --min-aggregate-speedup 1.05 \
  --min-operation-speedup 1.0 --require-updated-repos
```
