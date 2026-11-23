# c8 AVX2-Only Goal Speed

This is the completion-qualifying AVX2-only speed report for source commit
`400dbe4` (`c8b7823`). It uses Clang 18.1.3, CPU 0 on an AMD Ryzen
Threadripper 7980X, `-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f`,
100,000 iterations, three warmups, fifteen measured pairs, alternating order,
and 20,000 paired bootstrap samples. The local production artifact passed the
AVX512 register and symbol audit.

The comparator provenance is the same as the native report and is recorded in
`report.txt`: ten comparators, libcrux `0.0.10` lock SHA-256
`f5ba14023113fc34c5ee11ea83c9633ecbccb2adc8bd18786f3096bfe67b972a`, and
libjade assembly SHA-256
`358736656400f28f75db858c1be703a3140c8f6fac17b99279abc857112cf5d1`.

## Result

All 40 operation rows pass the goal verifier. Ratios are baby-mlkem time
divided by comparator time, so values above `1.0x` are faster.

| Comparator | Keygen | Encaps | Decaps | Roundtrip |
|---|---:|---:|---:|---:|
| Kyber AVX2 | 1.1762x | 1.4501x | 1.6062x | 1.3754x |
| Kyber fair flags | 1.1898x | 1.4548x | 1.6178x | 1.3912x |
| mlkem-native | 1.1271x | 1.5048x | 1.9677x | 1.4699x |
| PQClean AVX2 | 1.1894x | 1.4701x | 1.6941x | 1.4219x |
| liboqs | 1.2771x | 1.6885x | 2.1652x | 1.6495x |
| BoringSSL | 2.4907x | 2.8720x | 3.8676x | 2.9701x |
| libcrux Rust | 1.4184x | 1.8771x | 2.0690x | 1.7278x |
| libjade Kyber768 | 1.1062x | 1.8457x | 1.4823x | 1.4349x |
| Botan ML-KEM | 5.6477x | 5.4543x | 6.9456x | 5.9738x |
| OpenSSL ML-KEM | 3.6584x | 2.8317x | 4.2870x | 3.5207x |

The minimum operation ratio and CI lower bound are both set by libjade keygen:
`1.1062x` and `1.1002x`. The minimum roundtrip ratio is `1.3754x` against
standard-flags Kyber; the minimum roundtrip CI lower bound is `1.3388x` against
fair-flags Kyber.

## Evidence

- `report.txt` contains metadata, AVX2 flags, the AVX512 audit, comparator revisions, raw measurements, and paired statistics.
- `report.txt.raw` contains benchmark runner output before the final verifier.
- `report.txt.stderr` contains comparator update/build diagnostics.

Recheck the committed report without rerunning the benchmark:

```bash
python3 scripts/verify_goal_speed_report.py \
  benchmarks/2026-08-22-goal-avx2-speed-c8/report.txt \
  --expected-suites kyber_upstream_avx2,kyber_upstream_avx2_fair,mlkem_native,pqclean_avx2,liboqs,boringssl,libcrux_rust,libjade_kyber768_avx2,botan_mlkem,openssl_mlkem \
  --expected-profile avx2 --min-runs 15 --min-warmups 3 \
  --min-bootstrap-samples 20000 --min-aggregate-speedup 1.05 \
  --min-operation-speedup 1.0 --require-updated-repos
```

The formal source commit is `400dbe4`; later documentation-only commits do
not change the product inputs used by this report.
