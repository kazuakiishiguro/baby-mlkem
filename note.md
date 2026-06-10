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

## 2026-06-05: inline modular reduction

- Branch: `exp/reduce-inline`
- Hypothesis: Making `barret_reduce` and `reduce_signed` `static inline` in `reduce.h` would remove function-call overhead from NTT inner loops and let GCC optimize the surrounding arithmetic better.
- Change: Added inline definitions in `reduce.h` while keeping exported definitions in `reduce.c` via `REDUCE_EXTERNAL`.
- Baseline: `0eb4fa8`; `make test` passed; `./bench 2000` x5 median `keygen_ns_avg=64557`, `encaps_ns_avg=61974`, `decaps_ns_avg=76263`; `bench dec=23921`, `ntt.o dec=3686`, `testc dec=44956`.
- Result: `make test` passed. `objdump` showed no `call` instructions in the NTT hot functions after inlining. `./bench 2000` x5 median `keygen_ns_avg=58052`, `encaps_ns_avg=50130`, `decaps_ns_avg=59052`. `make size`: `bench dec=31849`, `ntt.o dec=11612`, `testc dec=51924`.
- Interpretation: Accepted for speed. The inline change lets GCC aggressively optimize/vectorize NTT code and improves median latency by about 10% for keygen, 19% for encaps, and 23% for decaps. The tradeoff is a large code-size regression, mostly in `ntt.o`.
- Next idea: Search for a controlled version of this win: keep reduce inlined for hot NTT paths but limit code growth, or add hand-written NTT/Keccak assembly only where it beats the compiler without excessive text growth.

## 2026-06-05: inline Barrett only

- Branch: `exp/reduce-inline-barrett-only`
- Hypothesis: Keeping only `barret_reduce` inline would preserve most forward-NTT speedup while avoiding the large code growth caused by inlining `reduce_signed` into inverse NTT and NTT-domain multiplication.
- Change: Left `barret_reduce` as `static inline` but restored `reduce_signed` to an external function call.
- Baseline: `1a3dff6` full inline speed branch; `make test` passed; `./bench 2000` x5 median `keygen_ns_avg=58052`, `encaps_ns_avg=50130`, `decaps_ns_avg=59052`; `bench dec=31849`, `ntt.o dec=11612`, `testc dec=51924`.
- Comparison to pre-inline baseline: `0eb4fa8` had median `keygen_ns_avg=64557`, `encaps_ns_avg=61974`, `decaps_ns_avg=76263`; `bench dec=23921`, `ntt.o dec=3686`, `testc dec=44956`.
- Result: `make test` passed. `./bench 2000` x5 median `keygen_ns_avg=59241`, `encaps_ns_avg=57870`, `decaps_ns_avg=69102`; `bench dec=26161`, `ntt.o dec=5958`, `testc dec=46932`.
- Interpretation: Accepted as a balanced size/speed branch. It is slower than full inline, especially for encaps/decaps, but it cuts `ntt.o` almost in half relative to full inline while still beating the pre-inline baseline on all three operations.
- Next idea: If pursuing absolute speed, continue from `exp/reduce-inline`; if pursuing compact fast code, continue from `exp/reduce-inline-barrett-only`.

## 2026-06-06: NTT-local bounded reduction

- Branch: `exp/ntt-local-signed`
- Hypothesis: Replacing only safe bounded NTT reductions with inline Barrett reduction will recover part of the full-inline speedup without the full `ntt.o` text growth.
- Conclusion that led here: `exp/reduce-inline` was fastest but grew `ntt.o` from `5958` to `11612` bytes, while `exp/reduce-inline-barrett-only` remained compact but left calls to `reduce_signed` in `ntt_inv` and `ntt_mul`.
- Baseline: `a2a8cea`; `make test` passed. `./bench 2000` x5 produced median `keygen_ns_avg=76962`, `encaps_ns_avg=67625`, `decaps_ns_avg=80659`. `make size`: `bench dec=26161`, `ntt.o dec=5958`, `testc dec=46932`.
- Compiler/flags: `gcc (GCC) 16.1.1 20260430`, `-D_GNU_SOURCE -O3 -Wall -Wextra -std=c99 -march=native`.
- CPU/OS: AMD Ryzen AI 9 HX 370, Arch Linux `7.0.9-arch2-1`, x86_64.
- Change: Used inline `barret_reduce` for non-negative `ntt_mul` products bounded below `2*Q*Q`, and for the inverse-NTT final scale product bounded below `Q*Q`. Added reduction edge tests for `2*Q*Q - 1` and `2*Q*Q`.
- Correctness: `make test` passed.
- Benchmark: Final candidate `./bench 2000` x12 median `keygen_ns_avg=70586`, `encaps_ns_avg=61857`, `decaps_ns_avg=73189`.
- Size: Final candidate `make size` produced `bench dec=27425`, `ntt.o dec=7215`, `testc dec=48196`.
- Tried variants: local signed inverse-NTT plus `ntt_mul` gave better encaps/decaps but grew `ntt.o` to `9351`; inverse-NTT only was slower and larger than the final candidate; disabling vectorization kept size tiny but regressed encaps/decaps; `ntt_mul` only was good, and adding final-scale Barrett improved encaps/decaps for another 256 bytes.
- Interpretation: Accepted. Versus baseline, median latency improved by about 8% keygen, 9% encaps, and 9% decaps. Size increased by 1257 bytes in `ntt.o`, still far below full inline's `11612` byte `ntt.o`.
- Next idea: Improve benchmark harness stability, then try a `sample_ntt` direct-squeeze experiment or a smaller hand-written `ntt_mul` that keeps the bounded Barrett win with less text.

## 2026-06-06: benchmark harness median output

- Branch: `exp/bench-harness`
- Hypothesis: Adding warmup, repeated rounds, and median/min/max output to `bench.c` will make later optimization decisions less sensitive to first-run and scheduler outliers.
- Baseline: `ab6c126`; `make test` passed. Old harness `./bench 2000` x5 produced median `keygen_ns_avg=65171`, `encaps_ns_avg=62270`, `decaps_ns_avg=72987`, with first-run outliers up to `keygen_ns_avg=90555` and `encaps_ns_avg=87304`. `make size`: `bench dec=27425`, `bench.o dec=1138`.
- Change: Reworked `bench.c` to run warmup iterations, measure multiple rounds, report median as `*_ns_avg`, and also print `*_ns_avg_min`/`*_ns_avg_max`. Added a post-timing decapsulation shared-key check.
- Correctness: `make test` passed.
- Benchmark: `./bench 2000 7` produced median lines `keygen_ns_avg=61539`, `encaps_ns_avg=64237`, `decaps_ns_avg=73180`; a second run produced `keygen_ns_avg=61083`, `encaps_ns_avg=61446`, `decaps_ns_avg=76146`.
- Size: `make size` produced `bench dec=30338`, `bench.o dec=3765`; library/test sizes were unchanged.
- Interpretation: Accepted as measurement infrastructure. The benchmark binary is larger, but the ML-KEM implementation objects are unchanged. Future experiment notes should use the new single-command median output instead of manually taking several one-round runs.
- Next idea: Use this harness for `exp/sample-ntt-direct-squeeze`.

## 2026-06-06: SampleNTT direct 3-byte squeeze

- Branch: `exp/sample-ntt-direct-squeeze`
- Hypothesis: `SampleNTT` can avoid per-candidate `keccak_squeeze(ctx, b, 3)` call overhead by reading 3 bytes directly from the SHAKE128 rate area and only calling `keccakf` at rate boundaries.
- Baseline: `bade2b7`; `make test` passed. `./bench 2000 7` produced `keygen_ns_avg=60881`, `encaps_ns_avg=61423`, `decaps_ns_avg=73185`. `make size`: `bench dec=30338`, `sample.o dec=1108`, `testc dec=48196`.
- Change: Added `sample_squeeze24` in `sample.c`, using the public `keccak_ctx` state byte view and `keccakf` when `pos == 168`. Parsed rejection candidates from the returned 24-bit word.
- Correctness: `make test` passed.
- Benchmark: `./bench 2000 7` produced `keygen_ns_avg=57492`, `encaps_ns_avg=59016`, `decaps_ns_avg=70494`; a second run produced `keygen_ns_avg=57414`, `encaps_ns_avg=58990`, `decaps_ns_avg=70526`.
- Size: `make size` produced `bench dec=30338`, `sample.o dec=1108`, `testc dec=48196`; no size change.
- Assembly check: `objdump -dr sample.o` showed no `keccak_squeeze` relocation in `sample_ntt_inner`; `mlkem_prf` still uses the generic squeeze API.
- Interpretation: Accepted. This improves keygen/encaps by removing many tiny squeeze calls in matrix sampling. Decaps also improves because decapsulation performs deterministic re-encryption.
- Next idea: Try specializing CBD sampling for `eta=2`, or reduce KEM stack traffic by avoiding full matrix materialization if size and clarity remain acceptable.

## 2026-06-06: ML-KEM-768 ACVP KAT

- Branch: `exp/kat-mlkem768`
- Hypothesis: Adding independent NIST ACVP ML-KEM-768 vectors will close the main FIPS 203 compatibility gap left by self-consistency tests.
- Source: NIST ACVP-Server `ML-KEM-keyGen-FIPS203/internalProjection.json` and `ML-KEM-encapDecap-FIPS203/internalProjection.json`.
- Source SHA-256: keyGen `d7a62a2c3476957f56dd8d24f9004ea6776ccfe995ffe71a65bb9506dc9c7b1b`; encapDecap `f1e22b7d399dde7bf61b838770c658a380e4b1cfc4bd395dbed9ec6c1d977d9d`.
- Baseline: `8dc1521`; `make test` passed. `make size`: `testc dec=48196`, `test.o dec=21512`; library and bench objects unchanged from the previous accepted branch.
- Change: Added `kat_mlkem768.h` with one ML-KEM-768 keyGen vector (`tgId=2`, `tcId=26`) and one encapsulation vector (`tgId=2`, `tcId=26`). Added `test_mlkem768_kat` to compare deterministic keygen `ek/dk`, deterministic encaps `K/c`, and decaps `K` byte-for-byte.
- Correctness: `make test-kem` passed; `make test` passed.
- Size: `make size` produced `testc dec=57588`, `test.o dec=30834`; `bench dec=30338`, `kem.o dec=4485`, `sample.o dec=1108`, and other implementation object sizes unchanged.
- Interpretation: Accepted as compatibility evidence. This does not optimize runtime, but it validates the current implementation against independent FIPS203 ACVP vectors and reduces the risk that round-trip tests were masking a spec deviation.
- Next idea: Add a small `kat` test group or expand KAT coverage to a few more ACVP cases only if needed; otherwise resume optimization from this FIPS-validated branch.

## 2026-06-10: plan sync after ACVP KAT

- Branch: `exp/plan-sync-fips-kat`
- Hypothesis: Keeping `plan.md` aligned with the accepted implementation state reduces the risk of repeating stale assumptions during the next optimization loop.
- Change: Updated `plan.md` for the current static NTT tables, bounded Barrett use in inverse final scaling and `ntt_mul`, SampleNTT direct 3-byte squeeze, current grouped Makefile/test flow, ACVP ML-KEM-768 KAT coverage, and the corrected root-order facts (`17^128 = -1`, `17^256 = 1`).
- Baseline: `exp/kat-mlkem768` at `3fcd17f`.
- Result: Documentation-only accepted state sync. `make test` passed.
- Next idea: Resume optimization from the FIPS-validated state, with CBD specialization or KEM stack/matrix materialization as the next candidate experiments.

## 2026-06-10: CBD eta=2 nibble specialization

- Branch: `exp/cbd-eta2`
- Hypothesis: Since ML-KEM-768 uses `eta1=eta2=2`, a direct one-nibble-to-one-coefficient CBD path would reduce the generic bit-indexing overhead in keygen, encaps, and deterministic re-encryption during decaps.
- Baseline: `exp/plan-sync-fips-kat` at `eb1a0cb`; `make test` passed. `./bench 2000 7` produced `keygen_ns_avg=57519`, `encaps_ns_avg=59363`, `decaps_ns_avg=70939`. `make size`: `bench dec=30338`, `sample.o dec=1108`, `testc dec=57588`.
- Change: Added an `eta == 2` fast path in `sample_poly_cbd` that processed two coefficients per byte through a small nibble helper, while keeping the generic path for other eta values.
- Result: `make test` passed, but `./bench 2000 7` produced `keygen_ns_avg=57735`, `encaps_ns_avg=59264`, `decaps_ns_avg=71229`. `make size`: `bench dec=32162`, `sample.o dec=2932`, `testc dec=59412`.
- Why it failed or was not accepted: Runtime did not improve clearly and code size regressed sharply. The compiler appears to already optimize the tiny generic eta=2 loop well enough; adding the specialized path increased text substantially for noise-level speed movement.
- Next idea: Drop this code change and switch strategy to KEM data-flow work, especially reducing matrix materialization or stack traffic.

## 2026-06-10: KEM data-flow streaming

- Branch: `exp/kem-stream-matrix`
- Hypothesis: Matrix elements and noise polynomials that are generated once and consumed once should be streamed through the KEM computation instead of stored in large temporary arrays. This should reduce stack traffic, code size, and possibly runtime.
- Baseline: `3226137` code-equivalent to `eb1a0cb`; `make test` passed. Same-link baseline built from `eb1a0cb:kem.c` in `/tmp` passed `/tmp/test-base`. `/tmp/bench-base 5000 9` produced `keygen_ns_avg=58455`, `encaps_ns_avg=59940`, `decaps_ns_avg=71660`; second run `keygen_ns_avg=58371`, `encaps_ns_avg=59993`, `decaps_ns_avg=71799`. Baseline size: `/tmp/bench-base dec=30338`, `/tmp/kem-base.o dec=4485`.
- Change: Removed full `A_hat[K][K]` materialization in keygen/encrypt and generated each matrix polynomial immediately before its multiply. Converted one-use sampled polynomial arrays (`s`, `e`, `rv`, `e1`, `u`, `that`) to temporary data flow where possible. Replaced the decapsulation `J(z || c)` staging buffer with streaming SHAKE-256 absorb.
- Correctness: `make test` passed, including ACVP ML-KEM-768 KAT.
- Benchmark: `./bench 5000 9` produced `keygen_ns_avg=57559`, `encaps_ns_avg=59314`, `decaps_ns_avg=70726`; second run `keygen_ns_avg=57822`, `encaps_ns_avg=59394`, `decaps_ns_avg=71115`.
- Size: `make size` produced `bench dec=30251`, `kem.o dec=4398`, `testc dec=57501`.
- Interpretation: Accepted. The speedup is small but repeated under same-link comparison, and the implementation object shrinks by 87 bytes while source-level stack use is reduced by several one-use polynomial arrays and the 1120-byte `J(z || c)` staging buffer.
- Next idea: Look for a similarly small KEM/encoding data-flow win, or try Keccak absorb/squeeze specialization for fixed small inputs only if it stays FIPS-compatible and measurable.
