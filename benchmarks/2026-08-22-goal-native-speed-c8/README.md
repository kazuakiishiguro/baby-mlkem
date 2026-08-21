# c8 Native Goal Speed

This is the completion-qualifying native speed report for source commit
`400dbe4` (`c8b7823`). It uses the independent baby-mlkem core, no persistent
KEM cache, Clang 18.1.3, CPU 0 on an AMD Ryzen Threadripper 7980X, 100,000
iterations, three warmups, fifteen measured pairs, alternating order, and
20,000 paired bootstrap samples.

The ten required comparators were updated or provenance-checked before the
run. Git comparator commits are recorded in `report.txt`; libcrux is crate
`0.0.10` with lock SHA-256
`f5ba14023113fc34c5ee11ea83c9633ecbccb2adc8bd18786f3096bfe67b972a`, and the
libjade assembly SHA-256 is
`358736656400f28f75db858c1be703a3140c8f6fac17b99279abc857112cf5d1`.

## Result

All 40 operation rows pass the goal verifier. Ratios are baby-mlkem time
divided by comparator time, so values above `1.0x` are faster.

| Comparator | Keygen | Encaps | Decaps | Roundtrip |
|---|---:|---:|---:|---:|
| Kyber AVX2 | 1.3282x | 1.4628x | 2.0377x | 1.5715x |
| Kyber fair flags | 1.3325x | 1.4579x | 2.0382x | 1.5709x |
| mlkem-native | 1.5864x | 1.8957x | 3.0822x | 2.0763x |
| PQClean AVX2 | 1.7595x | 1.9434x | 2.7721x | 2.1052x |
| liboqs | 1.5117x | 1.8106x | 2.9902x | 1.9990x |
| BoringSSL | 3.1285x | 2.9950x | 5.1334x | 3.5729x |
| libcrux Rust | 1.6156x | 1.9527x | 2.6739x | 2.0009x |
| libjade Kyber768 | 1.5632x | 2.3380x | 2.3383x | 2.0392x |
| Botan ML-KEM | 7.7280x | 6.5875x | 10.3313x | 8.0501x |
| OpenSSL ML-KEM | 5.0374x | 3.1260x | 6.0984x | 4.6173x |

The minimum operation ratio is `1.3282x` for Kyber keygen. The minimum
operation CI lower bound is `1.3209x` for fair-flags Kyber keygen. The minimum
roundtrip ratio and CI lower bound are `1.5709x` and `1.5563x`, respectively,
for fair-flags Kyber.

## Evidence

- `report.txt` contains metadata, comparator revisions, flags, raw measurements, and paired statistics.
- `report.txt.raw` contains benchmark runner output before the final verifier.
- `report.txt.stderr` contains comparator update/build diagnostics.

Recheck the committed report without rerunning the benchmark:

```bash
python3 scripts/verify_goal_speed_report.py \
  benchmarks/2026-08-22-goal-native-speed-c8/report.txt \
  --expected-suites kyber_upstream_avx2,kyber_upstream_avx2_fair,mlkem_native,pqclean_avx2,liboqs,boringssl,libcrux_rust,libjade_kyber768_avx2,botan_mlkem,openssl_mlkem \
  --expected-profile native --min-runs 15 --min-warmups 3 \
  --min-bootstrap-samples 20000 --min-aggregate-speedup 1.05 \
  --min-operation-speedup 1.0 --require-updated-repos
```

The formal source commit is `400dbe4`; later documentation-only commits do
not change the product inputs used by this report.
