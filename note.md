# baby-mlkem research log

## 2026-06-05: split baseline implementation

- Branch: `exp/baseline-impl`
- Hypothesis: Establish a correctness-first split C99 implementation from `plan.md` so later speed and size experiments have a stable baseline.
- Change: Added params, reduction, polynomial arithmetic, NTT, Keccak/SHA3/SHAKE, encoding/compression, sampling, randombytes, K-PKE, ML-KEM, unit/integration tests, and a simple benchmark harness.
- Baseline: `refactor` had only project instructions plus untracked plan/docs; `main` contained an older monolithic implementation and was used only as a reference for existing test vectors.
- Compiler/flags: `gcc (GCC) 16.1.1 20260430`, `-D_GNU_SOURCE -O3 -Wall -Wextra -std=c99 -march=native`.
- CPU/OS: AMD Ryzen AI 9 HX 370, Arch Linux `7.0.9-arch2-1`, x86_64.
- Correctness: `make test` passed.
- Benchmark: `make bench && ./bench 10` produced `keygen_ns_avg=105547`, `encaps_ns_avg=104125`, `decaps_ns_avg=125207`.
- Size: `make size` produced `testc text=44820 data=640 bss=840 dec=46300`; `bench text=23801 data=624 bss=840 dec=25265`; notable object sizes: `keccak.o dec=4701`, `kem.o dec=4485`, `ntt.o dec=5039`, `encode.o dec=3355`.
- Result: Accepted as the initial measurable baseline.
- Notes: `17^128 mod 3329 = 3328` and `17^256 mod 3329 = 1`, so the local test uses 17 as a primitive 256th root. Integer rounding in `Compress_d` gives max round-trip ring errors `{d=1:833, d=4:104, d=10:2}` for the implemented FIPS formula.
- Why it failed or was not accepted: Not applicable; this is the baseline.
- Next idea: Add independent ML-KEM-768 KAT vectors before performance work, then benchmark likely hot spots: Keccak permutation, NTT root tables, and byte encode/decode.

## 2026-06-05: byte pack specialization

- Branch: `exp/encode-pack`
- Hypothesis: Special-casing `ByteEncode/ByteDecode` for ML-KEM widths `d=1,4,10,12` would remove bit-loop overhead and improve KEM latency.
- Change: Replaced generic bitstream loops with byte-level packing/unpacking for the fixed widths.
- Baseline: `985772a` on `exp/baseline-impl`; `make test` passed; 5 runs of `./bench 100` had median `keygen_ns_avg=93953`, `encaps_ns_avg=94065`, `decaps_ns_avg=85559`; `bench dec=25265`; `encode.o dec=3355`.
- Result: Correctness still passed, but 5 runs of `./bench 100` had median `keygen_ns_avg=148924`, `encaps_ns_avg=122660`, `decaps_ns_avg=118038`; `bench dec=32097`; `encode.o dec=10187`.
- Why it failed or was not accepted: The specialized code bloated instruction text substantially and likely hurt I-cache/code layout. The benchmark is noisy, but the size regression is unambiguous and the median latency was worse.
- Next idea: Optimize NTT root storage by replacing runtime root generation and mutable tables with static const tables or a smaller constant-generation strategy, then measure both speed and `.bss`/text impact.

## 2026-06-05: static NTT root tables

- Branch: `exp/ntt-static-roots`
- Hypothesis: Replacing runtime NTT root initialization plus mutable `.bss` tables with `static const` tables would reduce code/data size and remove root-readiness checks from hot NTT paths.
- Change: Hardcoded `ZETA` and `GAMMA` as `static const uint16_t[128]`, made `init_ntt_roots` a compatibility no-op, and removed `ensure_roots` calls from NTT operations.
- Baseline: `c2d46b6` with code reverted to pre-experiment state; `./bench 1000` x3 median `keygen_ns_avg=92605`, `encaps_ns_avg=80085`, `decaps_ns_avg=103386`; previous baseline size `bench dec=25265`, `ntt.o dec=5039`, `testc dec=46300`.
- Result: `make test` passed. `./bench 1000` x3 median `keygen_ns_avg=89670`, `encaps_ns_avg=82836`, `decaps_ns_avg=101584`. `make size`: `bench dec=23921`, `ntt.o dec=3686`, `testc dec=44956`.
- Interpretation: Accepted for size. It removes 560 bytes of final `.bss` and cuts `ntt.o` by 1353 bytes. Runtime impact is small and noisy; keygen/decaps improved in the same-run comparison while encaps regressed slightly.
- Next idea: Look for a Keccak or sampling change with clear speed wins, but avoid table-heavy changes unless size is neutral.

## 2026-06-05: SampleNTT rate-buffered squeeze

- Branch: `exp/sample-ntt-buffer`
- Hypothesis: Squeezing SHAKE128 output in 168-byte rate chunks inside `SampleNTT` would reduce per-candidate function-call overhead versus squeezing 3 bytes at a time.
- Change: Added a 168-byte local buffer in `sample_ntt_inner` and parsed 3-byte candidate blocks from it.
- Baseline: `4a86ee6`; `make test` passed; `./bench 1000` x3 median `keygen_ns_avg=89670`, `encaps_ns_avg=82836`, `decaps_ns_avg=101584`; `bench dec=23921`, `sample.o dec=1108`, `testc dec=44956`.
- Result: `make test` passed, but `./bench 1000` x3 median `keygen_ns_avg=135378`, `encaps_ns_avg=123269`, `decaps_ns_avg=129856`; `bench dec=23993`, `sample.o dec=1180`, `testc dec=45028`.
- Why it failed or was not accepted: The extra stack buffer and refill branch increased code size and did not improve latency. The expected function-call reduction is apparently not the bottleneck under current compiler/code layout.
- Next idea: Try a smaller arithmetic change in modular reduction or NTT butterfly code where code size can stay flat.

## 2026-06-05: signed Barrett reduction fast path

- Branch: `exp/reduce-signed-barrett`
- Hypothesis: Replacing `reduce_signed`'s `% Q` with a Barrett fast path would speed inverse NTT and NTT-domain multiplication by avoiding integer division in hot paths.
- Change: Added a signed Barrett approximation with two corrections and a `% Q` fallback for out-of-range public API inputs; extended reduction tests across `[-30000000, 30000000]`.
- Baseline: `639e641` current best; `make test` passed; `./bench 1000` x3 median from accepted static-root experiment `keygen_ns_avg=89670`, `encaps_ns_avg=82836`, `decaps_ns_avg=101584`; `bench dec=23921`, `reduce.o dec=204`, `testc dec=44956`.
- Result: `make test` passed, but `./bench 1000` x5 median `keygen_ns_avg=140723`, `encaps_ns_avg=138473`, `decaps_ns_avg=171085`; `bench dec=23985`, `reduce.o dec=259`, `testc dec=45212`.
- Why it failed or was not accepted: The correction and fallback path increased code size, and the compiler/hardware division cost was not the observed bottleneck in this benchmark shape.
- Next idea: Improve measurement quality before more micro-optimizations, then inspect generated assembly for actual hot instructions rather than guessing from source.

## 2026-06-05: comparison against `main`

- Branch: `exp/ntt-static-roots`
- Question: Is the current best implementation faster than `main`, and why?
- Method: Built a temporary random top-level ML-KEM benchmark for current best and a temporary worktree benchmark for `main`, both with `gcc -D_GNU_SOURCE -O3 -Wall -Wextra -std=c99 -march=native`, 5 runs of `1000` iterations.
- Current best result: median `keygen_ns_avg=73686`, `encaps_ns_avg=71127`, `decaps_ns_avg=87059`, and all runs reported `match=1`.
- `main` result: median `keygen_ns_avg=401371`, `encaps_ns_avg=391236`, `decaps_ns_avg=417775`, but all runs reported `match=0`, so `main` is not a valid correctness-equivalent full-ML-KEM comparison target.
- Main cause of speed difference: `main`'s `sample_ntt` squeezes a fixed `3 * 4096 = 12288` bytes from SHAKE128 for every sampled matrix polynomial, then consumes only enough candidates to fill 256 coefficients. The current implementation streams 3 bytes at a time and stops as soon as 256 accepted coefficients are produced.
- Approximate cost difference: SHAKE128 rate is 168 bytes. `main` does about `12288 / 168 ~= 73` Keccak permutations per `SampleNTT`; current sampling usually needs about `157` three-byte blocks, roughly `471 / 168 ~= 3` Keccak permutations. K-PKE keygen/encrypt each generate the 3x3 matrix with 9 `SampleNTT` calls, so the wasted SHAKE output dominates the speed gap.
- Secondary differences: current best also has static const NTT root tables, reducing size and removing root-initialization checks, and decapsulation uses `compress_poly(1)`/`byte_encode_u16(1)` instead of `main`'s per-coefficient generalized bit decoder with `% Q`.
- Interpretation: The large speedup versus `main` mostly comes from avoiding unnecessary SHAKE128 output in `SampleNTT`; the accepted static-root change is mainly a size win, not the main explanation for the 5x benchmark gap.
