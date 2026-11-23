# Montgomery Dataflow Redesign

This document defines the next experimental boundary for baby-mlkem. It is
not a production change and does not claim a speedup.

## Current Evidence

The AVX2 stage benchmark measured the following representative costs:

| Path | ns/op |
| --- | ---: |
| Current `ntt_mul_acc3` | 85.0 |
| Montgomery precompute acc3 | 106.5 |
| Montgomery precompute plus canonicalize | 127.9 |
| 3-poly AoS/SoA pack, NTT, and unpack | 1400.7 |
| 3-poly individual NTT baseline | 197.4 |

The data rules out two simple changes: keeping only acc3 in a separate
Montgomery representation, and introducing an AoS/SoA transpose around NTT.
The conversion and reduction boundaries cost more than the arithmetic saved.

## Redesign Boundary

The next candidate must keep all of these values in one representation:

1. NTT output of the three vector inputs.
2. K=3 base multiplication and accumulation.
3. Inverse NTT butterflies through the final scale.
4. Addition of error or message terms at the first canonical boundary.

A candidate that converts only one stage is not an end-to-end Montgomery
pipeline and must not be promoted to production.

## Invariants

- Coefficients are stored as unsigned representatives in `[0, Q)` at every
  public API boundary.
- Montgomery products use `R = 2^16 mod Q` and are reduced before any value can
  exceed the signed 16-bit range.
- The candidate must match the existing path coefficient-for-coefficient,
  not only modulo `Q`, before benchmarking.
- Benchmarks include packing, conversion, and final canonicalization costs.
- Acceptance requires no operation in the whole KEM path to regress by more
  than 0.5% against the previous accepted commit.

## Promotion Plan

Implement the candidate in a diagnostic-only path first. Compare it against
`ntt_mul_acc3`, `ntt_inv_add`, and the complete KEM path. Keep the change only
if the end-to-end gate passes; otherwise retain the measurements and remove
the candidate.
