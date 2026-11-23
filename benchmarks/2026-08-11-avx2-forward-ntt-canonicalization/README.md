# AVX2 Forward-NTT Bounded Canonicalization

Date: 2026-08-11

Baseline: `1116c1d`

Candidate: `e8b4c22`

## Change

The AVX2-only seven-stage forward NTT keeps its signed Montgomery values in the
proved range `-7Q < v < 8Q`. The existing signed Barrett step maps every value
in `[-7Q+1, 8Q-1]` to `[0,Q]`; therefore the final canonicalization only needs
one masked subtraction for the possible redundant `Q` value. The candidate
removes the negative correction and the second generic correction from
`ntt_canonicalize_signed_avx2()`.

AVX512, scalar, API, key/ciphertext formats, and external-backend paths are
unchanged. The change uses the existing repository-local Q and Q-minus-one
constant definitions and adds no cache or external object.

## Build

The isolated Clang/GCC AVX2 builds used:

```text
-O3 (Clang) or -O2 -flto (GCC)
-mavx2 -mbmi2 -mpopcnt -mno-avx512f
-DMLKEM_AVX2_EXTERNAL_INV_MONT
-DMLKEM_AVX2_EXTERNAL_SHARED_CONSTANTS
-falign-loops=32
```

The product gate used separate baseline and candidate product objects with
`BABY_MLKEM_DISABLE_INTERNAL_CACHES`. Each product run used 60,000 iterations,
15 alternating pairs, and CPU 0. The isolated NTT run used 200,000 iterations,
15 alternating pairs, and CPU 0.

## Results

Ratios are baseline time divided by candidate time.

| Compiler | Isolated forward NTT gmean | Paired median | Wins |
|---|---:|---:|---:|
| Clang AVX2 | `1.053383x` | `1.042230x` | 14/15 |
| GCC AVX2 | `1.052394x` | `1.053080x` | 14/15 |

| Compiler | Keygen | Encaps | Decaps | Roundtrip |
|---|---:|---:|---:|---:|
| Clang AVX2 gmean | `0.999298x` | `1.000878x` | `1.011310x` | `1.003380x` |
| Clang AVX2 median | `1.001450x` | `1.000630x` | `1.008330x` | `1.001230x` |
| GCC AVX2 gmean | `1.001212x` | `1.002185x` | `1.005327x` | `1.004086x` |
| GCC AVX2 median | `1.001620x` | `1.002420x` | `1.002120x` | `1.003390x` |

| Artifact | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Clang AVX2 stage text | 904,410 | 904,186 | -224 |
| GCC AVX2 stage text | 565,502 | 565,182 | -320 |
| Clang AVX2 product text | 45,105 | 44,873 | -232 |
| GCC AVX2 product text | 51,527 | 51,207 | -320 |
| Clang/GCC product BSS | 26,593 / 34,912 | 26,593 / 34,912 | 0 |

## Correctness

Clang and GCC AVX2-only `test`, product KAT, and the full test suite passed.
Clang AVX2 ASan/UBSan passed with `LSAN_OPTIONS=detect_leaks=0`; the leak
checker itself cannot operate under the environment's CPU pinning wrapper.
The existing NTT scalar-reference and KEM validators cover the canonical output
contract. The range proof exhaustively covers all `49,934` values from
`-7Q+1` through `8Q-1` in the existing NTT evidence.

## Sampler Follow-up

The remaining `sample_ntt4()` state-layout target was screened before this
change. It was not retained because the AVX2 compiler schedule expanded instead
of reducing the common path:

| Candidate | Text delta | Isolated sampler gmean | Median | Wins |
|---|---:|---:|---:|---:|
| Final capacity-vector handoff | +2,144 B | `0.994266x` | `0.994043x` | 0/15 |
| Scalar three-permutation restart on refill | +2,080 B | `0.957941x` | `0.957994x` | 0/15 |

Both forms passed their local output checks but were discarded. The production
sampler keeps the current rolling lane-zero memory-resident Keccak path. A
future sampler improvement needs a larger spill-free Rho/Pi representation or
checked assembly, not another final-state store micro-variant.
