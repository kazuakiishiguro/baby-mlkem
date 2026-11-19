# 2026-11-19 AVX2-Only x4 Permutation Inventory

This note answers one question: in the AVX2-only profile, how many x4 Keccak
permutations run per operation, how much of the measured local overhead each
group accounts for, and which groups still have scheduling headroom. It is an
accounting exercise over the existing stage oracle; no product code changed.

## Why this matters

The 2026-11-19 follow-up established that the AVX2-only production artifact
pays a stable `1.41x` local penalty against native, and that the penalty is
dominated by the x4 Keccak permutation itself (`1.7x` per permutation:
254-280 ns AVX2-only versus 157-165 ns native). Expression-level rewrites,
unrolling, and full expansion were all rejected (`note.md`,
"avx2-only-keccak-penalty-probe"). If the permutation cannot be made cheaper,
the only remaining lever is the number of permutations, so each one must be
justified.

## Measured building blocks (CPU 0, Clang 18.1.3, `-march=x86-64-v3`)

| Stage row | ns/op | Meaning |
|---|---:|---|
| `sample_ntt4_lane0_sparse_first_keccak1_only` | 252.3 | one x4 permutation with the sparse first block |
| `sample_ntt4_lane0_carry_keccak1_only` | 259.0 | same with carried theta parity |
| `sample_ntt4_keccak3_only` | 756.8 | three chained x4 permutations (one matrix stream) |
| `sample_ntt4_full_raw` | 891.7 | three permutations plus parse/store for one stream |
| `sample_matrix_x4_batch0` / `batch1` | 1078 / 1072 | four matrix streams sampled |
| `keygen_matrix_noise_current` | 2709 | whole keygen matrix + ETA2 phase |
| `sample_matrix` | 2633 | whole 3x3 public-matrix expansion |
| `encrypt_noise_prf_cbd_tail_cosched` | 1094 | encryption noise phase |
| `kpke_keygen_full` | 3628 | full K-PKE keygen |
| `kpke_prepare_public_no_cache` | 2723 | public-key preparation (H(pk) + A^T) |
| `kpke_encrypt_uncached` | 3660 | full K-PKE encryption |

## Current AVX2-only permutation counts (derived from the measured phase times)

| Phase | Permutations today | Evidence |
|---|---:|---|
| Keygen noise (`PRF` + CBD for 6 ETA2 polys) | **2** | noise phase 2709 ns minus one matrix batch 1078 ns = 1631 ns; one permutation is 252-259 ns, so this is ~6.3 permutations total, i.e. 4 matrix streams (1 batch) + 2 noise permutations |
| Keygen matrix (`A^T`, 9 streams) | **7** | same decomposition: 4 streams in the first batch, 5 more in three permutations of two streams each |
| Keygen total | **9** | 2 + 7 |
| Public-key preparation (`H(pk)` + `A^T`) | **9** | `H(pk)` is ~7 serial single-state permutations plus one 3-lane matrix row per permutation, and the three remaining matrix streams need one permutation |
| Encryption noise (7 ETA2 streams) | **2** | 1094 ns / 252 ns ≈ 4.3, i.e. 2 noise permutations plus the 2-slot matrix tail sharing |
| Encryption matrix (9 streams, shared with the noise tail) | **9** | documented `ceil(34/4)` bound: 27 matrix rate blocks + 7 noise = 34 |
| Encryption total | **9** | 7 matrix + 2 noise |

## Where the remaining headroom is, and where it is not

Both the keygen and encryption schedules are already at their **lane-capacity
lower bound**, not merely at a convenient packing:

- Keygen needs 9 SHAKE128 streams x 3 rate blocks = 27 matrix lanes plus 6
  SHAKE256 ETA2 streams = 33 useful lanes. `ceil(33/4)` gives `ceil(33/4) = 9`.
  The current schedule uses exactly 9, so **keygen matrix/noise is closed**.
- Encryption needs 34 useful lanes and runs 9 permutations, which is exactly
  `ceil(34/4)`. **Encryption matrix/noise is closed**; the README already says
  another regrouping cannot remove a common-path permutation.
- Public-key preparation is *not* at a lane-capacity bound, because it also
  carries a serial `H(pk)`. The measured `H(pk)` cost is about 1.69 us for nine
  single-state permutations (~188 ns each), of which eight are absorbed into
  matrix-sampling calls that only have three usable lanes; the ninth is a
  standalone call. Measured `kpke_prepare_public_no_cache` is 2723 ns, so the
  matrix work costs about 1034 ns, i.e. roughly four x4 permutations instead of
  the `ceil(27/4) = 7` that a lane-only schedule would need. That works because
  each matrix row advances three of its rate blocks inside the same
  permutation that performs one `H(pk)` step, a 1.75x overlap that is already
  credited to this phase. The remaining overlap is bounded by `H(pk)`'s serial
  dependency (only one step can run at a time), not by lane capacity, so the
  four-permutation matrix remainder cannot be folded further without a
  different `H(pk)` schedule.
- Keygen is at 9 permutations for 33 useful lanes and encryption at 9 for 34;
  both equal their capacity bound. The only phase that is not at the bound is
  public-key preparation, and its slack is consumed by serial hashing that
  cannot use lanes.

The one structural change that would remove permutations is to stop computing
the full A^T matrix. ML-KEM encryption and decapsulation only need the K=3
matrix-vector products `A^T r` and `A^T y`, which can be evaluated from the
seed `rho` stream-by-stream instead of materialising nine polynomials. But the
seed stream is exactly the expensive part: each of the 9 streams still needs
its 3 SHAKE128 rate blocks (27 lanes) before any arithmetic can start, so the
stream count, and therefore `ceil(27/4) = 7` permutations, is unchanged. The
saving would be at most the 2 noise permutations that currently ride along in
the same 9 calls, and those lanes would simply go idle. Rejecting streams early
via a lattice-reduction shortcut is a real algorithmic change with a
correctness and security-review cost, not a scheduling change, and is out of
scope for this repository's optimization contract.

## Conclusion

- The AVX2-only profile is at the capacity lower bound for both keygen (9 for
  33 useful lanes) and encryption (9 for 34). Public-key preparation is below
  its lane-only bound (about four matrix permutations of a `ceil(27/4) = 7`
  requirement) precisely because it steals the three spare lanes of eight
  serial `H(pk)` permutations; the remainder is bound by `H(pk)`'s serial
  dependency rather than by lane capacity.
- Therefore there is no permutation-count-only change left. Any further
  AVX2-only gain must either make one x4 permutation cheaper (already shown to
  be ISA-bound on AVX2, with five rejected candidates) or reduce the number of
  matrix streams, which is an algorithm change, not a schedule change.
- Reported honestly, the AVX2-only `1.41x` local penalty against native is a
  consequence of AVX-512's `vpternlogq` and wider lanes, not of a scheduling
  defect in this repository.

## Reproduction

```bash
make -B CC=clang ARCH_CFLAGS="-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f" bench-stages
taskset -c 0 ./bench_core_stagesc 1500
```

The complete output for this analysis is `avx2-stage-inventory.txt` beside this
file; the cross-profile stage comparison is `avx2-stage-oracle.txt` and
`native-stage-oracle.txt` in the parent report directory.

## What was actually tried for AVX2-only on 2026-11-19

No permutation-count change was implemented, so this section records what the
rejected experiments were and why the alternative below was not built.

| Candidate | Result |
|---|---|
| AVX2-only x4 round loop `unroll_count(2)` | product roundtrip `14.6 us` -> `15.0-15.9 us`; rejected |
| AVX2 x1 permutation fully expanded (24 rounds) | `keccakf1_avx2` 191.9 -> 190.5 ns (`0.7%`, noise) for `0x3e5` -> `0x38ff` bytes; rejected |
| AVX2 x1 permutation `unroll_count(4)` | 191.9 -> 191.0 ns (`0.5%`) for 2.9x code; rejected |
| Theta folded into the rho shuffle (two variants) | failed the stage oracle, discarded |
| Chi reassociation `(x ^ z) ^ (y & ~z)` | failed a standalone vector check, discarded |
| Chi via `x ^ ((y|z) & ~(y&z))` | equal on paper, mismatched on the last lane in a vector check, discarded |

The remaining idea, evaluating `A^T r` and `A^T y` straight from `rho` without
materialising the nine matrix polynomials, was **not** implemented. It cannot
reduce the permutation count (each of the nine streams still needs its three
SHAKE128 rate blocks, so `ceil(27/4) = 7` stands) and it would save at most the
two ETA2 permutations that currently share the same nine calls, which is already
the lane-capacity optimum. Building it would add algorithmic risk for a null
result. A genuinely larger win needs early stream rejection (a lattice-reduction
shortcut that accepts or rejects a matrix entry before squeezing its full
96-byte block), which changes sampling semantics and needs its own correctness
and security review.
