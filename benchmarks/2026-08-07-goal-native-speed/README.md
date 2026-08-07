# Native all-comparator speed gate

This directory records the current formal native speed measurement for the
independent baby-mlkem ML-KEM-768 production core. The numerical native speed
gate passes. This is a dated speed milestone, not completion of the overall
Goal: the simultaneous production-size gate still fails, and a final accepted
code revision must rerun every same-revision gate.

## Environment and method

- measured baby-mlkem commit: `f711965a0f21cdcda0e71bd9eedeeac49b8f2408`
- report time: `2026-08-07T08:18:28Z`
- CPU: AMD Ryzen Threadripper 7980X 64-Cores, pinned to logical CPU 0
- OS: Linux 6.8.0-124-generic
- C/C++ compiler: Ubuntu Clang 18.1.3
- local artifact: `bench_productc` linked with the production-only object
- metric: `mlkem_roundtrip_core_ns_per_op`, with no persistent KEM cache
- ISA policy: `-march=native`; every comparator could use its fastest path
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
| pq-crystals Kyber AVX2 | 1.3338x / 1.3132x | 1.4761x / 1.4460x | 2.0520x / 2.0169x | 1.5732x / 1.5528x |
| pq-crystals Kyber AVX2, fair flags | 1.3323x / 1.3254x | 1.4744x / 1.4598x | 2.0594x / 2.0328x | 1.5735x / 1.5628x |
| mlkem-native | 1.5924x / 1.5803x | 1.9004x / 1.8777x | 3.1018x / 3.0849x | 2.0849x / 2.0756x |
| PQClean AVX2 | 1.7670x / 1.7405x | 1.9651x / 1.9285x | 2.7971x / 2.7238x | 2.1060x / 2.0751x |
| liboqs | 1.5181x / 1.5093x | 1.8245x / 1.7974x | 3.0009x / 2.9040x | 2.0008x / 1.9856x |
| BoringSSL | 3.1546x / 3.1233x | 3.0281x / 2.9880x | 5.1799x / 5.0417x | 3.6352x / 3.5934x |
| libcrux 0.0.10 | 1.6280x / 1.6169x | 1.9712x / 1.9511x | 2.6976x / 2.6826x | 2.0175x / 2.0086x |
| libjade Kyber768 AVX2 | 1.5741x / 1.5699x | 2.3601x / 2.3467x | 2.3451x / 2.3221x | 2.0486x / 2.0408x |
| Botan ML-KEM | 7.7629x / 7.7117x | 6.6604x / 6.6221x | 10.3845x / 10.0276x | 8.1095x / 8.0506x |
| OpenSSL ML-KEM | 5.0672x / 5.0293x | 3.1597x / 3.1239x | 6.1226x / 6.1119x | 4.6469x / 4.6233x |

All 40 operation/comparator rows pass. The narrowest aggregate ratio and CI
lower bound are 1.5732x and 1.5528x against upstream Kyber. The narrowest
operation ratio is 1.3323x for fair-flags Kyber keygen; the narrowest operation
CI lower bound is 1.3132x for the standard-flags Kyber keygen measurement.

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

## Metadata repair

The complete 150-pair measurement finished, but the first verifier invocation
stopped because `bench_compare_all_stats.sh` did not print the already enforced
`BOTAN_ALLOW_COMPILER_FALLBACK=0` profile value. Commit `0c0f16c` fixes that
reporting omission. `clang-native.pre-metadata-fix.txt` is the original report;
`clang-native.txt` differs only by this inserted line:

```text
botan_allow_compiler_fallback=0
```

The measured pairs and raw report were not modified. Reverification of the
one-line-completed report produces `goal_speed_gate=PASS`.

## Files and hashes

| File | SHA-256 |
|---|---|
| `clang-native.txt` | `8df3ad296bcf86442c623f933dcf4e271c91b022d20380e7f63c60862ff0d32f` |
| `clang-native.pre-metadata-fix.txt` | `d261c3d26ca52afc225b6e3d9d4eb7179f1e5eb8dacbcbaa11d6b1bd9ed76b07` |
| `clang-native.txt.raw` | `54a7162940ef5c0c6b3fe13cdc7e79f9f54788ed2c43496e9a57f11385056f04` |
| `clang-native.txt.stderr` | `76326b2c51ecc28978a491bf0455bf3b1d012f168e7f8415999cbb50f3e58e5c` |
| `clang-native.verifier.txt` | `fc0dc1081f09e3bd2303a852ad2b11e40dc33568c2aa379ae50cf32027029511` |

The stderr capture contains only successful Cargo index/update notices. The
external projects are benchmark-time comparators only and are not linked into
the baby-mlkem production artifact.

## Reproduction

From a clean committed worktree with the comparator directories populated:

```bash
RUNS=15 WARMUP_RUNS=3 BOOTSTRAP_SAMPLES=20000 \
PIN_CPU=0 C_COMPILER=clang \
REPORT_FILE=/tmp/baby-mlkem-goal-native-speed.txt \
./scripts/verify_goal_native_speed.sh 100000
```

Recheck the committed completed report with:

```bash
./scripts/verify_goal_speed_report.py \
  benchmarks/2026-08-07-goal-native-speed/clang-native.txt \
  --expected-suites kyber_upstream_avx2,kyber_upstream_avx2_fair,mlkem_native,pqclean_avx2,liboqs,boringssl,libcrux_rust,libjade_kyber768_avx2,botan_mlkem,openssl_mlkem \
  --expected-profile native --min-runs 15 --min-warmups 3 \
  --min-bootstrap-samples 20000 --min-aggregate-speedup 1.05 \
  --min-operation-speedup 1.0 --require-updated-repos
```
