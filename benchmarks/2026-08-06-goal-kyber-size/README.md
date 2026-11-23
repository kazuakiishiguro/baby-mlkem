# GCC Product Size and Stack vs. Kyber (2026-08-06)

This report applies the normalized production-artifact rules to baby-mlkem and
one comparator, upstream `pq-crystals/kyber` AVX2. It is a Kyber-only size gate,
not the ten-comparator Goal size gate.

## Scope

- baby-mlkem commit: `442f81b31f91d3a5f3a14bab8a0466cb2f9ca770`
- Kyber commit: `3edd5af5991927164edd4aacebfcbee00b8064e7`
- Compiler: GCC 13.3.0 with the normal speed flags for each profile
- APIs: deterministic ML-KEM-768 keygen, encapsulation, and decapsulation
- Cache policy: persistent key, matrix, transformed-key, and hash caches absent
- Footprint: allocatable executable plus read-only sections after section GC
- Stack: guarded alternate-stack touched high-water, eight input runs, two
  sentinel patterns, cold/warm keygen, and valid/invalid decapsulation

`UPDATE_REPOS=0` was used because these reports reuse the clean Kyber checkout
from the same day's strict speed run. The exact comparator commit and remote are
recorded, but these files do not claim a fresh authoritative update.

## Results

| Profile | Implementation | Code | Read-only data | Primary | Writable | Max stack | Result |
|---|---|---:|---:|---:|---:|---:|---|
| native | baby-mlkem | 60,234 B | 2,337 B | 62,571 B | 33,728 B | 11,072 B | FAIL by 2,670 B |
| native | Kyber AVX2 | 55,693 B | 4,208 B | 59,901 B | 0 B | 17,376 B | comparator |
| AVX2-only | baby-mlkem | 55,073 B | 2,353 B | 57,426 B | 34,920 B | 5,728 B | PASS by 12,637 B |
| AVX2-only | Kyber AVX2 | 65,903 B | 4,160 B | 70,063 B | 0 B | 18,400 B | comparator |

The primary ratios `baby-mlkem / Kyber` are `1.044574` native and `0.819634`
AVX2-only. The completion contract treats primary footprint as the size gate;
writable storage and stack are reported separately rather than folded into that
number.

## Stack Detail

| Profile | Implementation | Keygen | Encaps | Decaps valid | Decaps invalid |
|---|---|---:|---:|---:|---:|
| native | baby-mlkem | 6,464 B | 6,592 B | 11,072 B | 11,072 B |
| native | Kyber AVX2 | 13,088 B | 16,288 B | 17,376 B | 17,376 B |
| AVX2-only | baby-mlkem | 4,456 B | 4,584 B | 5,728 B | 5,728 B |
| AVX2-only | Kyber AVX2 | 14,112 B | 17,312 B | 18,400 B | 18,400 B |

The probe reports the deepest sentinel byte touched, including the direct API
call return address. It does not claim a static upper bound for an input corpus
that was not executed.

## Reproduction

```bash
PROFILE=native C_COMPILER=gcc \
  KYBER_DIR=/tmp/baby-mlkem-goal-20260806/kyber \
  UPDATE_REPOS=0 SIZE_ENFORCE=0 \
  REPORT_FILE=/tmp/goal-kyber-size-gcc-native.txt \
  ./scripts/verify_goal_kyber_size.sh

PROFILE=avx2 C_COMPILER=gcc \
  KYBER_DIR=/tmp/baby-mlkem-goal-20260806/kyber \
  UPDATE_REPOS=0 SIZE_ENFORCE=1 \
  REPORT_FILE=/tmp/goal-kyber-size-gcc-avx2.txt \
  ./scripts/verify_goal_kyber_size.sh
```

Raw report SHA-256:

- `gcc-native.txt`: `f886b1f5eeb9fe9fdd7bcec87dbc59206b9b35e030c7be8e3ec8d2eb9744bdce`
- `gcc-avx2-only.txt`: `d061be10a616ffb65ad3d1fb68dde482d435ccd78fd4c4ea13cf1da850a90717`

## Decision

The AVX2-only Kyber size gate is closed for GCC. Native remains open with a
2,670-byte primary deficit. The other nine required comparator artifacts are
still unmeasured, so baby-mlkem does not claim the full smallest or overall Goal
milestone.
