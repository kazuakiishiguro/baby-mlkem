# GCC Product Size and Stack vs. Kyber after Cold NTT Setup (2026-08-06)

This report supersedes the GCC/Kyber result at `442f81b` for the baby-mlkem
candidate at `ff7ca72`. It applies the normalized production-artifact rules to
baby-mlkem and upstream `pq-crystals/kyber` AVX2. This remains a Kyber-only
size gate, not the ten-comparator Goal size gate.

## Scope

- baby-mlkem commit: `ff7ca72dba2a0f15cd539aeb5fb4dc4635307560`
- parent baseline: `b587ca1`
- Kyber commit: `3edd5af5991927164edd4aacebfcbee00b8064e7`
- Compiler: GCC 13.3.0 with the normal speed flags for each profile
- APIs: deterministic ML-KEM-768 keygen, encapsulation, and decapsulation
- Cache policy: persistent key, matrix, transformed-key, and hash caches absent
- Footprint: allocatable executable plus read-only sections after section GC
- Stack: guarded alternate-stack touched high-water over eight input runs and
  two sentinel patterns, including cold/warm keygen and valid/invalid decaps

`UPDATE_REPOS=0` was used with the clean official Kyber checkout retained from
the same day's strict runs. The exact comparator commit and remote are recorded,
but these files do not claim a fresh authoritative update.

## Change

The GCC production flags include global `-funroll-loops`. GCC expanded the
one-time `init_ntt_roots()` setup to 5,629 bytes in the native product. Commit
`ff7ca72` marks only that cold initializer `noinline`, `cold`, and `optimize("Os")`
for GCC. Its native body becomes 1,057 bytes; the timed steady-state operations
still use the normal speed flags. Clang is deliberately excluded from the
attribute because it did not have this code-size problem.

Compared with the parent product, GCC primary footprint changes as follows:

| Profile | Parent primary | Candidate primary | Reduction |
|---|---:|---:|---:|
| native | 62,571 B | 58,151 B | 4,420 B (7.1%) |
| AVX2-only | 57,426 B | 51,396 B | 6,030 B (10.5%) |
| scalar | 22,610 B | 21,787 B | 823 B (3.6%) |

Clang native and AVX2-only products are byte-identical to the parent. Their
respective SHA-256 values are
`cc8e367d212d10962214e862066333c7cf9975eccfb50e46e4f7b66f8e5388de`
and `99e300022553579eccd98b10dbeafbe727299512220913384738e1eda27c5adc`.

## Size and Stack Results

| Profile | Implementation | Code | Read-only data | Primary | Writable | Max stack | Result |
|---|---|---:|---:|---:|---:|---:|---|
| native | baby-mlkem | 55,814 B | 2,337 B | 58,151 B | 33,728 B | 11,072 B | PASS by 1,750 B |
| native | Kyber AVX2 | 55,693 B | 4,208 B | 59,901 B | 0 B | 17,376 B | comparator |
| AVX2-only | baby-mlkem | 49,043 B | 2,353 B | 51,396 B | 34,920 B | 5,728 B | PASS by 18,667 B |
| AVX2-only | Kyber AVX2 | 65,903 B | 4,160 B | 70,063 B | 0 B | 18,400 B | comparator |

The primary ratios `baby-mlkem / Kyber` are `0.970785` native and `0.733568`
AVX2-only. Stack high-water is unchanged from the parent product.

## Internal Speed A/B

The direct three-API harness compared `b587ca1` with `ff7ca72` for 15 paired
50,000-iteration runs after three warmups, alternating execution order. Ratios
are `parent time / candidate time`; a value below one means the candidate is
slower. The repository's operation-level internal acceptance floor is `0.995x`.

| Profile | Keygen | Encaps | Decaps | Roundtrip | Lowest |
|---|---:|---:|---:|---:|---:|
| native | 1.0004x | 0.9992x | 0.9966x | 1.0003x | 0.9966x |
| AVX2-only | 0.9992x | 1.0020x | 0.9993x | 1.0009x | 0.9992x |

Both profiles pass. `native-ab/` and `avx2-only-ab/` contain the report and the
15 raw values for each baseline/candidate metric. Candidate artifact SHA-256 is
`4f55c40b1a0fff2bb3c82874a9870dae6f4dcf945a5c32f1d2e9673d761678c0`
native and
`59b3e8dad23704e8f1b5e1b4a1f3fb1acdc35446fc637f8de6324db8715cb564`
AVX2-only.

## Correctness

GCC and Clang native, AVX2-only, and scalar KEM/KAT plus product smoke tests
pass. GCC native UBSan and Clang native ASan+UBSan pass the KEM/KAT and complete
stage validator. Both sanitizer validators produced sink
`14843503313874379226`. The AVX2-only artifact audit found no AVX512 registers
or symbols.

## Reproduction

```bash
PROFILE=native C_COMPILER=gcc \
  KYBER_DIR=/tmp/baby-mlkem-goal-20260806/kyber \
  UPDATE_REPOS=0 SIZE_ENFORCE=1 \
  REPORT_FILE=/tmp/goal-kyber-size-gcc-native-ff7ca72.txt \
  ./scripts/verify_goal_kyber_size.sh

PROFILE=avx2 C_COMPILER=gcc \
  KYBER_DIR=/tmp/baby-mlkem-goal-20260806/kyber \
  UPDATE_REPOS=0 SIZE_ENFORCE=1 \
  REPORT_FILE=/tmp/goal-kyber-size-gcc-avx2-ff7ca72.txt \
  ./scripts/verify_goal_kyber_size.sh
```

Raw size report SHA-256:

- `gcc-native.txt`: `85c62a0f220daa83d2d6560ec236609f891d9385dcb87b9882274decb348ffb6`
- `gcc-avx2-only.txt`: `d7fef3a8be66325c6671088f2a39efb91865a4be73418175ad52b8864b6b3912`

## Decision

Both GCC Kyber size gates are closed at `ff7ca72`, and baby-mlkem also uses less
measured stack in both profiles. The other nine required comparator artifacts
remain unmeasured, and strict all-comparator speed evidence must be rerun for
this product revision. baby-mlkem therefore does not claim the full smallest or
overall Goal milestone.
