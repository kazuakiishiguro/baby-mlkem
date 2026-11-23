# AVX2-only all-comparator speed gate

This directory records the current formal AVX2-only speed measurement for the
independent baby-mlkem ML-KEM-768 production core. The numerical AVX2-only
speed gate passes. This is a dated speed milestone, not completion of the
overall Goal: the simultaneous production-size gate still fails, and a final
accepted code revision must rerun every same-revision gate.

## Environment and method

- measured baby-mlkem commit: `0c0f16cddef4999b6e7d31399119ab076127cac2`
- report time: `2026-08-07T09:22:39Z`
- CPU: AMD Ryzen Threadripper 7980X 64-Cores, pinned to logical CPU 0
- OS: Linux 6.8.0-124-generic
- C/C++ compiler: Ubuntu Clang 18.1.3
- local artifact: `bench_productc` linked with the production-only object
- metric: `mlkem_roundtrip_core_ns_per_op`, with no persistent KEM cache
- ISA policy: `-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f`
- AVX512 policy: comparator dispatch exclusions were applied, and the local
  production object passed register and symbol audits
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
| pq-crystals Kyber AVX2 | 1.1532x / 1.1451x | 1.4235x / 1.4027x | 1.5816x / 1.5589x | 1.3560x / 1.3398x |
| pq-crystals Kyber AVX2, fair flags | 1.1591x / 1.1505x | 1.4264x / 1.4234x | 1.5811x / 1.5487x | 1.3553x / 1.3431x |
| mlkem-native | 1.1040x / 1.0935x | 1.4839x / 1.4721x | 1.9236x / 1.8879x | 1.4412x / 1.4322x |
| PQClean AVX2 | 1.1795x / 1.1698x | 1.4597x / 1.4457x | 1.6611x / 1.6192x | 1.3984x / 1.3792x |
| liboqs | 1.2569x / 1.2523x | 1.6650x / 1.6605x | 2.1231x / 2.1037x | 1.6218x / 1.6096x |
| BoringSSL | 2.4563x / 2.4318x | 2.8263x / 2.8221x | 3.8035x / 3.7901x | 2.9234x / 2.9060x |
| libcrux 0.0.10 | 1.3958x / 1.3918x | 1.8505x / 1.8414x | 2.0253x / 2.0069x | 1.6946x / 1.6888x |
| libjade Kyber768 AVX2 | 1.0905x / 1.0887x | 1.8202x / 1.7999x | 1.4469x / 1.4152x | 1.4080x / 1.3971x |
| Botan ML-KEM | 5.5562x / 5.5439x | 5.3749x / 5.2476x | 6.7922x / 6.7387x | 5.8433x / 5.7919x |
| OpenSSL ML-KEM | 3.6077x / 3.5549x | 2.7888x / 2.7724x | 4.1903x / 4.1387x | 3.4615x / 3.4306x |

All 40 operation/comparator rows pass. The narrowest aggregate ratio is
1.3553x against fair-flags Kyber; the narrowest aggregate CI lower bound is
1.3398x against standard-flags Kyber. The narrowest operation is libjade
keygen at a 1.0905x ratio and a 1.0887x CI lower bound.

## Comparator provenance

| Comparator | Source identity |
|---|---|
| pq-crystals Kyber | `3edd5af5991927164edd4aacebfcbee00b8064e7` |
| PQClean | `0586a824fc0d49df0b6b6e9179d8d15d06d0974f` |
| mlkem-native | `dc081dc596b53443acb70c8e66d9ff507b0857f4` |
| liboqs | `4e1183aaa34b0d0d52413c49f269f909b505e0cf` |
| BoringSSL | `a204be272595867e7069221050f19697a0cf66ad` |
| Botan | `7ffae689f89286ecddf5ffecb17803403ad96fde` |
| OpenSSL | `def638aa2d6895d36648cbccfb16444e24311683` |
| libcrux | crate 0.0.10; lock SHA-256 `fb8e17a643a60b25160aba36e0a28c5ff47f5fc73d38884420a98a923c940b3f` |
| libjade | release 2023.05-2; assembly SHA-256 `358736656400f28f75db858c1be703a3140c8f6fac17b99279abc857112cf5d1` |

## Files and hashes

| File | SHA-256 |
|---|---|
| `clang-avx2-only.txt` | `d9fd966976ec06155d2be477f743af6d91137fa16fd860a0c1f72ab1677c90d0` |
| `clang-avx2-only.txt.raw` | `6706fe2d5254ae353fa9c519c26bd63a58fe43e66fab6c25f4330ce559233675` |
| `clang-avx2-only.txt.stderr` | `76326b2c51ecc28978a491bf0455bf3b1d012f168e7f8415999cbb50f3e58e5c` |
| `clang-avx2-only.verifier.txt` | `314c04fbe96140261029726978c2190a0aec744e45b3ce753a06acec999d4206` |

The stderr capture contains only successful Cargo index/update notices. The
external projects are benchmark-time comparators only and are not linked into
the baby-mlkem production artifact.

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
  benchmarks/2026-08-07-goal-avx2-speed/clang-avx2-only.txt \
  --expected-suites kyber_upstream_avx2,kyber_upstream_avx2_fair,mlkem_native,pqclean_avx2,liboqs,boringssl,libcrux_rust,libjade_kyber768_avx2,botan_mlkem,openssl_mlkem \
  --expected-profile avx2 --min-runs 15 --min-warmups 3 \
  --min-bootstrap-samples 20000 --min-aggregate-speedup 1.05 \
  --min-operation-speedup 1.0 --require-updated-repos
```
