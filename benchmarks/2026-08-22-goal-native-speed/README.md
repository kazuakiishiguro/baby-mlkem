# Native all-comparator speed gate

This directory records the formal native speed measurement for the current
baby-mlkem ML-KEM-768 production core at commit `d5e58a8`. The speed gate
passes all ten comparator suites and all forty operation rows. This is a
same-revision speed result; production-size and the AVX2-only same-revision
speed result remain separate gates.

## Environment and method

- measured baby-mlkem commit: `d5e58a82e49d4853c7e66148e451740c708c2afe`
- report time: `2026-08-21T15:47:12Z`
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
| pq-crystals Kyber AVX2 | 1.3328x / 1.3273x | 1.4634x / 1.4579x | 2.0533x / 2.0397x | 1.5770x / 1.5692x |
| pq-crystals Kyber AVX2, fair flags | 1.3435x / 1.3196x | 1.4722x / 1.4461x | 2.0738x / 2.0520x | 1.5853x / 1.5708x |
| mlkem-native | 1.5959x / 1.5811x | 1.9026x / 1.8814x | 3.1128x / 3.0775x | 2.0897x / 2.0762x |
| PQClean AVX2 | 1.7816x / 1.7819x | 1.9545x / 1.9432x | 2.8106x / 2.8101x | 2.1384x / 2.1223x |
| liboqs | 1.5174x / 1.5042x | 1.8073x / 1.7937x | 3.0321x / 2.9690x | 1.9994x / 1.9978x |
| BoringSSL | 3.1305x / 3.1209x | 2.9920x / 2.9679x | 5.1321x / 5.0401x | 3.5970x / 3.5774x |
| libcrux 0.0.10 | 1.6258x / 1.6051x | 1.9626x / 1.9472x | 2.7028x / 2.6443x | 2.0104x / 1.9950x |
| libjade Kyber768 AVX2 | 1.5701x / 1.5522x | 2.3481x / 2.3070x | 2.3706x / 2.3319x | 2.0552x / 2.0328x |
| Botan ML-KEM | 7.7561x / 7.6674x | 6.6198x / 6.5334x | 10.4375x / 10.2820x | 8.0653x / 8.0185x |
| OpenSSL ML-KEM | 5.0787x / 5.0555x | 3.1650x / 3.1511x | 6.1896x / 6.1344x | 4.6932x / 4.6698x |

The narrowest aggregate ratio and CI lower bound are 1.5770x and 1.5692x
against standard-flags Kyber. The narrowest operation ratio is 1.3328x and
the narrowest operation CI lower bound is 1.3196x, both on Kyber keygen.

## Comparator provenance

| Comparator | Source identity |
|---|---|
| pq-crystals Kyber | `3edd5af5991927164edd4aacebfcbee00b8064e7` |
| PQClean | `0586a824fc0d49df0b6b6e9179d8d15d06d0974f` |
| mlkem-native | `69d24e37b8a04c6050ec55bc84a4228d7051bb4b` |
| liboqs | `8979276ad1eb008215aa78a3c56b3649f604bbb1` |
| BoringSSL | `aebe361280f2c4afd7426815002e354ff02a4ce1` |
| Botan | `010037a31527deb21dc8d3473368ed3d3b78d8cc` |
| OpenSSL | `b64f68a94e61fa2363c598c75444482b48056697` |
| libcrux | crate 0.0.10; lock SHA-256 `f5ba14023113fc34c5ee11ea83c9633ecbccb2adc8bd18786f3096bfe67b972a` |
| libjade | release 2023.05-2; assembly SHA-256 `358736656400f28f75db858c1be703a3140c8f6fac17b99279abc857112cf5d1` |

## Report handling

The complete 150-pair measurement finished and is preserved in
`clang-native.txt.raw`. The first verifier invocation then stopped at the
post-measurement libjade path check because the path was not passed to that
invocation. The saved raw measurements were not changed or rerun: the final
report was reconstructed with the exact clean comparator revisions and
libjade/libcrux hashes above, then passed `verify_goal_speed_report.py` with
the native profile, 15 runs, 3 warmups, 20,000 bootstrap samples, and the
updated-repository requirement.

The comparator projects are benchmark-time sources only. No comparator object,
vendor backend, runtime library, cache, API, algorithm, or wire-format change
is linked into the baby-mlkem production artifact.

## Files and hashes

| File | SHA-256 |
|---|---|
| `clang-native.txt` | `5bc90b72159f76fddfc299888405fa9adc9767990b35f2741759c803f8f21892` |
| `clang-native.txt.raw` | `a5d4994e202db4c7a77b19cf3bad06f43b95ac546ab3879add9ee0619477e9b0` |
| `clang-native.txt.stderr` | `6c0c550068449d083b2a619579ac3d6bf2e1eb47be73a16662553ad29049a00d` |
| `clang-native.verifier.txt` | `6fc6c9149e6c549e88426676e10c769f056e458c447124c59853f3322541f3dc` |

## Reproduction

From a clean committed worktree with the comparator directories populated:

```bash
PROFILE=native RUNS=15 WARMUP_RUNS=3 BOOTSTRAP_SAMPLES=20000 \
PIN_CPU=0 C_COMPILER=clang \
REPORT_FILE=/tmp/baby-mlkem-goal-native-speed.txt \
./scripts/verify_goal_native_speed.sh 100000
```

Recheck the committed report with:

```bash
./scripts/verify_goal_speed_report.py \
  benchmarks/2026-08-22-goal-native-speed/clang-native.txt \
  --expected-suites kyber_upstream_avx2,kyber_upstream_avx2_fair,mlkem_native,pqclean_avx2,liboqs,boringssl,libcrux_rust,libjade_kyber768_avx2,botan_mlkem,openssl_mlkem \
  --expected-profile native --min-runs 15 --min-warmups 3 \
  --min-bootstrap-samples 20000 --min-aggregate-speedup 1.05 \
  --min-operation-speedup 1.0 --require-updated-repos
```
