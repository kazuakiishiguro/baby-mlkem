# GCC AVX2 Inverse-NTT l4-l6 Fusion

Date: 2026-08-12

Baseline: `e8b4c22`

Candidate: `e65fc90`

## Change

The GCC AVX2-only inverse NTT path keeps each 128-coefficient block in eight
YMM values while applying inverse levels `l4`, `l5`, and `l6`. The values are
overwritten in the existing butterfly topology, removing two intermediate
store/load boundaries. The Montgomery products, signed Barrett reductions,
twiddle factors, final scale/add, and output representation are unchanged.

The candidate is guarded by `__GNUC__ && !__clang__`. Clang AVX2 keeps its
smaller level-wise schedule because the fused form is neutral-to-negative there.
AVX512 and scalar paths are unchanged.

## Build and Measurement

The AVX2 builds used:

```text
CC=gcc or clang
-mavx2 -mbmi2 -mpopcnt -mno-avx512f
GCC: -O2 -flto -falign-loops=32
Clang: -O3 -falign-loops=32
```

The isolated inverse-NTT run used 200,000 iterations, CPU 0, and seven
alternating pairs. Ratios are baseline time divided by candidate time.

## Isolated NTT

| Compiler | Operation | Gmean | Paired median | Wins |
|---|---|---:|---:|---:|
| GCC AVX2 | inverse NTT | `1.047106x` | `1.045160x` | 7/7 |
| GCC AVX2 | inverse NTT + add | `1.046881x` | `1.043930x` | 7/7 |
| GCC AVX2 | inverse NTT + add2 | `1.034722x` | `1.042500x` | 7/7 |
| GCC AVX2 | inverse NTT - from | `1.036968x` | `1.044330x` | 7/7 |
| Clang AVX2 | inverse NTT | `0.994233x` | `0.995281x` | 3/7 |
| Clang AVX2 | inverse NTT + add | `0.999012x` | `1.005430x` | 4/7 |
| Clang AVX2 | inverse NTT + add2 | `1.004365x` | `1.021460x` | 4/7 |
| Clang AVX2 | inverse NTT - from | `0.998278x` | `1.006700x` | 3/7 |

The Clang results do not support enabling the larger schedule, which is why the
implementation remains GCC-only.

## GCC Product

The product gate used separate cache-disabled product objects, 60,000
iterations, CPU 0, and seven alternating pairs.

| Operation | Gmean | Paired median | Wins |
|---|---:|---:|---:|
| Keygen | `1.008817x` | `1.001360x` | 7/7 |
| Encaps | `1.004107x` | `1.009340x` | 6/7 |
| Decaps | `1.012988x` | `1.009200x` | 7/7 |
| Roundtrip | `1.005359x` | `1.006680x` | 6/7 |

## Size

| Product | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| GCC relocatable text | 49,111 | 49,271 | +160 B |
| GCC product primary bytes | 51,415 | 51,575 | +160 B |
| GCC product file bytes | 65,200 | 65,408 | +208 B |
| GCC BSS | 34,912 | 34,912 | 0 B |
| Clang product text | 44,873 | 44,873 | 0 B |
| Clang product BSS | 26,593 | 26,593 | 0 B |

The GCC speed gain is accepted with the small code-size increase. Clang AVX2
`testc`, product KAT, and product object were byte-identical between baseline
and candidate. GCC and Clang AVX2 tests and product KATs passed. No cache,
external object, vendored backend, runtime library, API, algorithm, or
wire-format dependency is added.
