# c8 Production Size Matrix

This is the completion-qualifying production-size matrix for source commit
`400dbe4` (`c8b7823`). It measures the three exported product operations with
Clang 18.1.3 and compares the local primary footprint against ten required
implementations. Primary size is code plus read-only data plus unwind and
exception metadata; writable data and maximum stack are reported separately.

All 20 comparator rows pass. A smaller primary footprint is better.

## Native

Local primary size is `51,171 B`, writable size is `18,001 B`, and maximum
stack is `8,056 B`.

| Comparator | Comparator primary | Difference | Local writable | Local max stack | Gate |
|---|---:|---:|---:|---:|---|
| Kyber AVX2 | 61,032 B | -9,861 B | 18,001 B | 8,056 B | PASS |
| Kyber fair flags | 61,371 B | -10,200 B | 18,001 B | 8,056 B | PASS |
| mlkem-native | 51,200 B | -29 B | 18,001 B | 8,056 B | PASS |
| PQClean AVX2 | 60,950 B | -9,779 B | 18,001 B | 8,056 B | PASS |
| liboqs | 70,206 B | -19,035 B | 18,001 B | 8,056 B | PASS |
| BoringSSL | 208,736 B | -157,565 B | 18,001 B | 8,056 B | PASS |
| libcrux Rust | 137,086 B | -85,915 B | 18,001 B | 8,056 B | PASS |
| libjade Kyber768 | 109,633 B | -58,462 B | 18,001 B | 8,056 B | PASS |
| Botan ML-KEM | 183,712 B | -132,541 B | 18,001 B | 8,056 B | PASS |
| OpenSSL ML-KEM | 103,552 B | -52,381 B | 18,001 B | 8,056 B | PASS |

## AVX2-only

Local primary size is `45,032 B`, writable size is `26,593 B`, and maximum
stack is `4,512 B`.

| Comparator | Comparator primary | Difference | Local writable | Local max stack | Gate |
|---|---:|---:|---:|---:|---|
| Kyber AVX2 | 62,970 B | -17,938 B | 26,593 B | 4,512 B | PASS |
| Kyber fair flags | 63,373 B | -18,341 B | 26,593 B | 4,512 B | PASS |
| mlkem-native | 51,279 B | -6,247 B | 26,593 B | 4,512 B | PASS |
| PQClean AVX2 | 61,827 B | -16,795 B | 26,593 B | 4,512 B | PASS |
| liboqs | 81,316 B | -36,284 B | 26,593 B | 4,512 B | PASS |
| BoringSSL | 134,969 B | -89,937 B | 26,593 B | 4,512 B | PASS |
| libcrux Rust | 142,302 B | -97,270 B | 26,593 B | 4,512 B | PASS |
| libjade Kyber768 | 109,633 B | -64,601 B | 26,593 B | 4,512 B | PASS |
| Botan ML-KEM | 146,600 B | -101,568 B | 26,593 B | 4,512 B | PASS |
| OpenSSL ML-KEM | 45,049 B | -17 B | 26,593 B | 4,512 B | PASS |

## Evidence and Reproduction

The individual `native-*.txt` and `avx2-*.txt` files contain the complete
verifier output, comparator commit, compiler flags, footprint, cache audit,
and stack probe. The OpenSSL reports use the official remote
`https://github.com/openssl/openssl.git`; comparator update was intentionally
skipped there because provenance and the source commit were already checked
in the formal speed run.

To rerun the complete matrix from the repository root:

```bash
for profile in native avx2; do
  for comparator in kyber kyber-fair mlkem-native pqclean liboqs boringssl \
      libcrux libjade botan openssl; do
    PROFILE="$profile" COMPARATOR="$comparator" C_COMPILER=clang \
      UPDATE_REPOS=1 SIZE_ENFORCE=1 \
      REPORT_FILE="/tmp/baby-mlkem-${profile}-${comparator}-size.txt" \
      ./scripts/verify_goal_comparator_size.sh
  done
done
```

The aggregate conclusion is based on the same product commit and all 20
individual reports, not on a single closest comparator.
