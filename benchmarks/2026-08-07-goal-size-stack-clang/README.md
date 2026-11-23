# Current Clang Goal Size and Stack Matrix

This directory records the complete native and AVX2-only production footprint
and stack matrix at commit `9952e84` (algorithm commit `a03a486`). Each of the
20 per-comparator reports used Clang 18.1.3, required a clean baby-mlkem
worktree, enabled authoritative comparator updates, and reports
`comparator_update=pass`.

The local artifact is the exact no-cache speed-build product for each profile,
not a separate `-Os` build. Each report audits the local three-API surface and
persistent-cache exclusion. AVX2-only reports additionally audit that no AVX512
registers or symbols remain. Comparator builders apply their documented
production normalization, provenance, correctness, and stack checks.

These reports are current diagnostics assembled from the strict
per-comparator verifier. They do not establish Goal completion because ten size
gates fail and the same-revision formal speed matrix is still open.

## Primary Footprint

Positive deltas mean baby-mlkem is larger. Primary is executable plus read-only
allocatable data, including required unwind/exception metadata.

| Profile | Comparator | baby-mlkem | Comparator | Delta | Gate |
|---|---|---:|---:|---:|---|
| native | upstream Kyber | 103,485 B | 61,032 B | +42,453 B | FAIL |
| native | upstream Kyber, fair flags | 103,485 B | 62,075 B | +41,410 B | FAIL |
| native | PQClean | 103,485 B | 60,950 B | +42,535 B | FAIL |
| native | mlkem-native | 103,485 B | 51,186 B | +52,299 B | FAIL |
| native | liboqs | 103,485 B | 70,206 B | +33,279 B | FAIL |
| native | BoringSSL | 103,485 B | 208,709 B | -105,224 B | PASS |
| native | libcrux | 103,485 B | 137,086 B | -33,601 B | PASS |
| native | libjade | 103,485 B | 109,633 B | -6,148 B | PASS |
| native | Botan | 103,485 B | 183,712 B | -80,227 B | PASS |
| native | OpenSSL | 103,485 B | 103,552 B | -67 B | PASS |
| AVX2-only | upstream Kyber | 65,019 B | 62,970 B | +2,049 B | FAIL |
| AVX2-only | upstream Kyber, fair flags | 65,019 B | 64,269 B | +750 B | FAIL |
| AVX2-only | PQClean | 65,019 B | 61,827 B | +3,192 B | FAIL |
| AVX2-only | mlkem-native | 65,019 B | 51,267 B | +13,752 B | FAIL |
| AVX2-only | liboqs | 65,019 B | 81,316 B | -16,297 B | PASS |
| AVX2-only | BoringSSL | 65,019 B | 134,942 B | -69,923 B | PASS |
| AVX2-only | libcrux | 65,019 B | 142,302 B | -77,283 B | PASS |
| AVX2-only | libjade | 65,019 B | 109,633 B | -44,614 B | PASS |
| AVX2-only | Botan | 65,019 B | 146,600 B | -81,581 B | PASS |
| AVX2-only | OpenSSL | 65,019 B | 45,049 B | +19,970 B | FAIL |

baby-mlkem passes 5/10 gates in each profile. The limiting primary artifacts
are mlkem-native at 51,186 bytes for native and OpenSSL at 45,049 bytes for
AVX2-only. Closing only the nearest AVX2 gap to fair-flags Kyber would therefore
not satisfy the Goal.

## Maximum Stack

Stack is reported separately and is not part of the primary-size ordering.
Every value is the maximum over cold/warm keygen, encapsulation, valid
decapsulation, and invalid decapsulation in eight guarded alternate-stack runs.

| Profile | baby-mlkem | Comparators below local | Lowest comparator |
|---|---:|---|---:|
| native | 10,040 B | Botan, OpenSSL | Botan, 4,952 B |
| AVX2-only | 5,856 B | Botan | Botan, 4,952 B |

baby-mlkem uses less stack than 8/10 native comparators and 9/10 AVX2-only
comparators. Full values are in [`summary.tsv`](summary.tsv) and the individual
reports under [`native/`](native/) and [`avx2/`](avx2/).

## Reproduction

The matrix invokes the generic verifier once per comparator and profile:

```bash
export KYBER_DIR=/tmp/baby-mlkem-goal-comparators/kyber
export PQCLEAN_DIR=/tmp/baby-mlkem-goal-comparators/PQClean
export MLKEM_NATIVE_DIR=/tmp/baby-mlkem-goal-comparators/mlkem-native
export LIBOQS_DIR=/tmp/baby-mlkem-goal-comparators/liboqs
export BORINGSSL_DIR=/tmp/baby-mlkem-goal-comparators/boringssl
export LIBCRUX_BENCH_DIR=/tmp/baby-mlkem-goal-comparators/libcrux
export LIBJADE_DIST_ROOT=/tmp/baby-mlkem-goal-comparators/libjade-dist-src-amd64
export BOTAN_DIR=/tmp/baby-mlkem-goal-comparators/botan
export OPENSSL_DIR=/tmp/baby-mlkem-goal-comparators/openssl-native-current

for profile in native avx2; do
  for comparator in kyber kyber-fair pqclean mlkem-native liboqs boringssl \
      libcrux libjade botan openssl; do
    COMPARATOR="$comparator" PROFILE="$profile" C_COMPILER=clang \
      UPDATE_REPOS=1 SIZE_ENFORCE=0 \
      REPORT_FILE="/tmp/${profile}-${comparator}-size.txt" \
      ./scripts/verify_goal_comparator_size.sh
  done
done
```

Checkout-location environment variables used for this run are recorded in the
individual build reports where relevant. All source commits, release versions,
remotes, compiler flags, artifact hashes, API/cache audits, correctness smoke
results, footprint sections, and per-operation stack values are retained in
those reports.
