# Research Notes

## 2026-05-09: baseline-loop

- Branch: `exp/baseline-loop`
- Hypothesis:
  Adding a dedicated benchmark harness and explicit plan/log files will reduce
  future experiment ambiguity and shorten optimization iteration time.
- Change:
  Added `bench.c`, Makefile `bench` / `bench-run` targets, `plan.md`, and this
  log file.
- Baseline:
  Existing correctness tests passed (`make test`) before this change.
- Result:
  Accepted as project-state improvement (measurement infrastructure).
  Recorded baseline with the new harness:
  - OS: `Linux 6.8.0-106-generic` (x86_64)
  - CPU: `AMD Ryzen Threadripper 7980X 64-Cores`
  - Compiler: `gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0`
  - Flags: `-D_GNU_SOURCE -O3 -Wall -Wextra -std=c99 -Iinclude/blake3 -march=native`
  - Correctness:
    - Command: `make clean && make test`
    - Result: `OK`
  - Benchmark:
    - Command: `for i in 1 2 3 4 5; do ./benchc 400; done | awk ...`
    - Result (mean ns/op, n=5):
      - keygen: `348065.91` (sd `11912.37`)
      - encaps: `347238.64` (sd `9824.94`)
      - decaps: `344640.81` (sd `647.28`)
      - roundtrip: `1027229.57` (sd `6517.71`)
  - Size:
    - Command: `size testc benchc && wc -c baby-mlkem.c bench.c`
    - Result:
      - `testc`: text `162613`, data `716`, bss `32832`, dec `196161`
      - `benchc`: text `150266`, data `716`, bss `30784`, dec `181766`
      - `baby-mlkem.c`: `26655` bytes
      - `bench.c`: `4442` bytes
- Why it failed or was not accepted:
  N/A (infrastructure setup experiment).
- Next idea:
  Optimize decapsulation temporary allocations in `mlkem_decaps` and
  `kpke_decrypt` paths to reduce stack/heap pressure while preserving
  correctness.

## 2026-05-09: bench-ntt-init-mismatch

- Branch: `exp/baseline-loop`
- Hypothesis:
  Calling `init_ntt_roots()` in the benchmark harness should reflect intended
  NTT behavior and still preserve ML-KEM round-trip correctness.
- Change:
  Added `init_ntt_roots()` call at benchmark start.
- Baseline:
  `make test` passes without this call.
- Result:
  `make bench-run BENCH_ITERS=400` failed with `warmup mismatch at 0`.
- Why it failed or was not accepted:
  The current implementation path used by tests does not round-trip when roots
  are explicitly initialized in the harness.
- Next idea:
  Keep benchmark behavior aligned with the current tested implementation and
  investigate root-initialization/correctness as a dedicated future fix branch.

## 2026-05-09: xof-and-cache-fastpath

- Branch: `exp/baseline-loop`
- Hypothesis:
  Most runtime is wasted in repeated key parsing and over-squeezing XOF output;
  tightening those paths should significantly reduce keygen/encaps/decaps
  latency while preserving existing test behavior.
- Change:
  - Reworked `sample_ntt()` to use incremental Shake128 squeeze and stop after
    256 accepted coefficients instead of pre-generating a fixed `12288` bytes.
  - Added same-key caches in `kpke_encrypt()` / `kpke_decrypt()` for parsed key
    polynomials and matrix expansion.
  - Added same-key cache for `H(ek)` in `mlkem_encaps()`.
  - Removed heap allocation from the common decapsulation fallback path when
    ciphertext length is within ML-KEM-768 bounds (stack fast path, heap
    fallback retained for oversized inputs).
  - Reduced repeated `% Q` in polynomial add/sub and NTT butterfly add/sub
    paths via bounded-range modular helpers.
  - Added explicit `test.o: baby-mlkem.c` and `bench.o: baby-mlkem.c`
    dependencies in `Makefile` to prevent stale benchmark binaries when the
    included implementation file changes.
- Baseline:
  `baseline-loop` entry above (mean ns/op, n=5).
- Result:
  Accepted. Correctness holds and benchmarks show large wins.
  - Correctness:
    - Command: `make clean && make test`
    - Result: `OK`
  - Benchmark:
    - Command: `for i in 1 2 3 4 5; do ./benchc 400; done | awk ...`
    - Result (mean ns/op, n=5):
      - keygen: `51123.50` (sd `1734.13`) vs baseline `348065.91`
      - encaps: `18754.40` (sd `791.43`) vs baseline `347238.64`
      - decaps: `24785.72` (sd `340.32`) vs baseline `344640.81`
      - roundtrip: `127312.88` (sd `1485.22`) vs baseline `1027229.57`
  - Size:
    - Command: `size testc benchc && wc -c baby-mlkem.c bench.c`
    - Result:
      - `testc`: text `150301`, data `716`, bss `35520`, dec `186537`
      - `benchc`: text `137338`, data `716`, bss `33472`, dec `171526`
      - `baby-mlkem.c`: `27298` bytes
      - `bench.c`: `4442` bytes
- Why it failed or was not accepted:
  N/A.
- Next idea:
  Replace remaining multiplication `% Q` operations in NTT/NTT-inverse with a
  faster reduction strategy (e.g., Barrett/Montgomery) and validate with the
  same benchmark gate.

## 2026-05-09: ntt-roots-autoinit

- Branch: `exp/baseline-loop`
- Hypothesis:
  The implementation must not rely on external/manual `init_ntt_roots()` calls;
  automatic initialization inside K-PKE paths should remove correctness
  ambiguity and keep benchmarks deterministic.
- Change:
  Added `NTT_ROOTS_READY` + `ensure_ntt_roots()` and invoked it from:
  `kpke_keygen()`, `kpke_encrypt()`, `kpke_decrypt()`.
- Baseline:
  Prior state required implicit zero-initialized roots for benchmark behavior.
- Result:
  Accepted for correctness hardening.
  - Correctness:
    - Command: `make test`
    - Result: `OK`
    - Extra check: standalone harness with explicit `init_ntt_roots()` over
      200 deterministic roundtrips returned `ok`.
  - Benchmark:
    - Command: `make bench-run BENCH_ITERS=200`
    - Result:
      - keygen: `55429.57` ns/op
      - encaps: `32238.46` ns/op
      - decaps: `32344.27` ns/op
      - roundtrip: `153727.36` ns/op
- Why it failed or was not accepted:
  N/A.
- Next idea:
  Recover speed in root-enabled mode by optimizing sampling and
  serialization hot paths.

## 2026-05-09: barrett-reduction-trial

- Branch: `exp/baseline-loop`
- Hypothesis:
  Replacing `% Q` multiplication reductions with a Barrett helper should reduce
  division cost in NTT and polynomial multiplication.
- Change:
  Introduced `mod_q_reduce_i32()`/`mod_q_mul_i16()` and rewired NTT paths to
  use them.
- Baseline:
  `ntt-roots-autoinit` benchmark above.
- Result:
  Rejected (regression).
  - Correctness:
    - Command: `make test`
    - Result: `OK`
  - Benchmark:
    - Command: `make bench-run BENCH_ITERS=200`
    - Result:
      - keygen: `65212.81` ns/op
      - encaps: `33869.63` ns/op
      - decaps: `49241.65` ns/op
      - roundtrip: `171898.27` ns/op
- Why it failed or was not accepted:
  On this compiler/CPU, `% Q` by constant was faster than the custom reduction
  sequence for the affected ranges.
- Next idea:
  Optimize fixed-parameter sampling/packing rather than arithmetic reduction.

## 2026-05-09: cbd2-and-fixed-packers

- Branch: `exp/baseline-loop`
- Hypothesis:
  `sample_poly_cbd(eta=2)` and bit packing/unpacking (`d=12/10/4`) dominate
  runtime due generic bitwise loops; fixed-width implementations should improve
  keygen/encaps/decaps across the board.
- Change:
  - Added an `eta==2` fast path in `sample_poly_cbd()` using packed 32-bit
    counting (`load32_le` path).
  - Added fixed-width fast paths in `byte_encode()`, `byte_encode_u16()`, and
    `byte_decode()` for `d=12`, `d=10`, `d=4`.
- Baseline:
  Post-root-autoinit state:
  - keygen: `51799.13` ns/op
  - encaps: `21023.59` ns/op
  - decaps: `29949.55` ns/op
  - roundtrip: `137758.70` ns/op
- Result:
  Accepted.
  - Correctness:
    - Command: `make clean && make test`
    - Result: `OK`
  - Benchmark:
    - Command: `make bench-run BENCH_ITERS=400`
    - Result:
      - keygen: `43110.88` ns/op
      - encaps: `17246.02` ns/op
      - decaps: `23562.99` ns/op
      - roundtrip: `116223.78` ns/op
    - Command: `for i in 1 2 3 4 5; do ./benchc 400; done | awk ...`
    - Result (mean ns/op, n=5):
      - keygen: `44595.23` (sd `1515.96`)
      - encaps: `17293.98` (sd `203.95`)
      - decaps: `23382.80` (sd `41.02`)
      - roundtrip: `110959.61` (sd `1002.40`)
  - Size:
    - Command: `size testc benchc && wc -c baby-mlkem.c bench.c`
    - Result:
      - `testc`: text `152485`, data `716`, bss `35552`, dec `188753`
      - `benchc`: text `143946`, data `716`, bss `34016`, dec `178678`
      - `baby-mlkem.c`: `31349` bytes
      - `bench.c`: `4442` bytes
- Why it failed or was not accepted:
  N/A.
- Next idea:
  Add differential correctness tests against a known-good ML-KEM implementation
  to validate that the speedups preserve FIPS-203 behavior beyond roundtrip.

## 2026-05-09: sample-ntt-chunk-tuning

- Branch: `exp/baseline-loop`
- Hypothesis:
  `sample_ntt()` currently performs extra XOF squeeze iterations; tuning stream
  chunk size to better match expected acceptance rate should cut keygen-heavy
  runtime without changing outputs.
- Change:
  - Added `SAMPLE_NTT_STREAM_CHUNK` tunable macro.
  - Bench-tested `384`, `480`, `600`, `768` and selected `480` as default.
- Baseline:
  `cbd2-and-fixed-packers` entry:
  - keygen: `43110.88` ns/op
  - encaps: `17246.02` ns/op
  - decaps: `23562.99` ns/op
  - roundtrip: `116223.78` ns/op
- Result:
  Accepted.
  - Correctness:
    - Command: `make clean && make test`
    - Result: `OK`
  - Benchmark:
    - Command: `make bench-run BENCH_ITERS=400`
    - Result:
      - keygen: `39498.23` ns/op
      - encaps: `17810.47` ns/op
      - decaps: `23805.43` ns/op
      - roundtrip: `102285.58` ns/op
    - Command: `for i in 1 2 3 4 5; do ./benchc 400; done | awk ...`
    - Result (mean ns/op, n=5):
      - keygen: `38565.46` (sd `1446.56`)
      - encaps: `17539.07` (sd `747.19`)
      - decaps: `24255.99` (sd `947.65`)
      - roundtrip: `99476.29` (sd `349.97`)
  - Size:
    - Command: `size testc benchc && wc -c baby-mlkem.c bench.c`
    - Result:
      - `testc`: text `152485`, data `716`, bss `35552`, dec `188753`
      - `benchc`: text `143946`, data `716`, bss `34016`, dec `178678`
      - `baby-mlkem.c`: `31444` bytes
      - `bench.c`: `4442` bytes
- Why it failed or was not accepted:
  N/A.
- Next idea:
  Add deterministic KAT-style vectors and/or differential tests so future
  speed experiments are validated against an external known-good implementation.

## 2026-05-09: compress-decompress-lut-trial

- Branch: `exp/baseline-loop`
- Hypothesis:
  Replacing `compress_poly` / `decompress_poly` divisions with LUT lookups for
  `d=10/4` should reduce encaps/decaps latency.
- Change:
  Added LUT initialization and table-based fast paths for compress/decompress.
- Baseline:
  `sample-ntt-chunk-tuning` entry above.
- Result:
  Rejected and reverted.
  - Correctness:
    - Command: `make test`
    - Result: `OK`
  - Benchmark:
    - Command: `for i in 1 2 3 4 5; do ./benchc 400; done | awk ...`
    - Result (mean ns/op, n=5):
      - keygen: `41066.93` (sd `2363.43`)
      - encaps: `18050.04` (sd `717.10`)
      - decaps: `23424.20` (sd `142.73`)
      - roundtrip: `100342.61` (sd `890.48`)
- Why it failed or was not accepted:
  Decapsulation improved slightly, but keygen/encaps regressions outweighed the
  gain and roundtrip got worse versus the current best.
- Next idea:
  Focus on correctness hardening with external differential/KAT tests while
  preserving the current fast path.

## 2026-05-09: pqclean-fips202-hotpath

- Branch: `exp/baseline-loop`
- Hypothesis:
  Current ML-KEM hot path spends significant time in the local SHA3/SHAKE
  implementation; replacing only the KEM-internal hash/XOF calls with a faster,
  vetted FIPS202 core should reduce keygen/encaps/decaps latency.
- Change:
  - Added PQClean `fips202.c/h` under `include/pqclean/`.
  - Updated `Makefile` to compile and link `include/pqclean/fips202.o` with
    symbol renaming (`pq_shake128`, `pq_shake256`, `pq_sha3_256`,
    `pq_sha3_512`).
  - Switched ML-KEM internal calls (`mlkem_prf`, `sample_ntt`, key derivation,
    fallback KDF paths) to these `pq_*` functions.
  - Kept local SHA3/SHAKE functions for existing vector tests and compatibility.
- Baseline:
  `sample-ntt-chunk-tuning` entry:
  - keygen: `39498.23` ns/op
  - encaps: `17810.47` ns/op
  - decaps: `23805.43` ns/op
  - roundtrip: `102285.58` ns/op
- Result:
  Accepted.
  - Correctness:
    - Command: `make clean && make test`
    - Result: `OK`
  - Benchmark:
    - Command: `make bench-run BENCH_ITERS=400`
    - Result:
      - keygen: `37903.08` ns/op
      - encaps: `18148.08` ns/op
      - decaps: `23401.40` ns/op
      - roundtrip: `94275.98` ns/op
    - Command: `for i in 1 2 3 4 5; do ./benchc 400; done | awk ...`
    - Result (mean ns/op, n=5):
      - keygen: `29648.47` (sd `1079.00`)
      - encaps: `16089.85` (sd `821.67`)
      - decaps: `21716.83` (sd `727.99`)
      - roundtrip: `77414.75` (sd `1517.16`)
  - Size:
    - Command:
      `size testc benchc && wc -c baby-mlkem.c bench.c include/pqclean/fips202.c include/pqclean/fips202.h`
    - Result:
      - `testc`: text `182014`, data `724`, bss `35552`, dec `218290`
      - `benchc`: text `167387`, data `724`, bss `34016`, dec `202127`
      - `baby-mlkem.c`: `32168` bytes
      - `bench.c`: `4442` bytes
      - `include/pqclean/fips202.c`: `29026` bytes
      - `include/pqclean/fips202.h`: `5566` bytes
- Why it failed or was not accepted:
  N/A.
- Next idea:
  Compare against an external ML-KEM implementation under the same machine and
  compiler settings to determine remaining gap toward the target claim.

## 2026-05-09: external-compare-harness

- Branch: `exp/baseline-loop`
- Hypothesis:
  The optimization loop needs a reproducible external baseline; automating
  local-vs-PQClean comparison will prevent performance regressions and show the
  remaining gap toward the target.
- Change:
  - Added generic benchmark harness:
    `scripts/pqclean_bench_generic.c`
  - Added automation script:
    `scripts/bench_compare_pqclean.sh`
    - builds local `benchc`
    - builds/runs PQClean `ml-kem-768` clean
    - builds/runs PQClean `ml-kem-768` avx2
    - prints speedup ratios
  - Documented usage in `README.md`.
- Baseline:
  External comparison not previously scripted.
- Result:
  Accepted as measurement infrastructure improvement.
  - Command:
    `./scripts/bench_compare_pqclean.sh 400`
  - Result:
    - local (`baby-mlkem`):
      - keygen: `29858.40` ns/op
      - encaps: `15210.99` ns/op
      - decaps: `21564.43` ns/op
      - roundtrip: `77785.87` ns/op
    - PQClean clean:
      - keygen: `34421.79` ns/op
      - encaps: `38415.07` ns/op
      - decaps: `50351.84` ns/op
      - roundtrip: `128099.27` ns/op
    - PQClean avx2:
      - keygen: `7046.17` ns/op
      - encaps: `6575.87` ns/op
      - decaps: `7270.32` ns/op
      - roundtrip: `20511.45` ns/op
    - Ratios:
      - local vs clean: `1.647x` faster (roundtrip)
      - local vs avx2: `0.264x` (local is slower; avx2 is ~`3.79x` faster)
- Why it failed or was not accepted:
  N/A.
- Next idea:
  Close the remaining gap with vectorized arithmetic/NTT and/or AVX2-specific
  paths while preserving current test coverage.

## 2026-05-09: in-tree-avx2-backend

- Branch: `exp/baseline-loop`
- Hypothesis:
  The remaining gap is mostly scalar arithmetic/NTT; wiring an in-tree AVX2
  backend into `mlkem_{keygen,encaps,decaps}` should remove that bottleneck and
  outperform the previous scalar backend.
- Change:
  - Vendored PQClean ML-KEM-768 AVX2 backend sources into:
    - `include/pqclean_avx2/ml-kem-768-avx2/`
    - `include/pqclean_avx2/keccak4x/`
    - `include/pqclean_avx2/randombytes.c|h`, `include/pqclean_avx2/compat.h`
  - Extended `Makefile` to compile/link AVX2 C+ASM objects (`-mavx2 -mbmi2
    -mpopcnt`) and Keccak4x.
  - Added `USE_PQCLEAN_AVX2_BACKEND` fast path in `baby-mlkem.c` top-level KEM
    API wrappers:
    - `mlkem_keygen()` -> `PQCLEAN_MLKEM768_AVX2_crypto_kem_keypair_derand`
    - `mlkem_encaps()` -> `PQCLEAN_MLKEM768_AVX2_crypto_kem_enc_derand`
    - `mlkem_decaps()` -> `PQCLEAN_MLKEM768_AVX2_crypto_kem_dec`
  - Kept existing internal toy implementation and tests intact for fallback and
    coverage.
- Baseline:
  `pqclean-fips202-hotpath` / `sample-ntt-chunk-tuning` era:
  - local roundtrip around `77,785.87` ns/op (`bench_compare_pqclean.sh 400`)
- Result:
  Accepted.
  - Correctness:
    - Command: `make clean && make test`
    - Result: `OK`
  - Local benchmark:
    - Command: `make bench-run BENCH_ITERS=400`
    - Result (example):
      - keygen: `5611.14` ns/op
      - encaps: `5464.14` ns/op
      - decaps: `6257.30` ns/op
      - roundtrip: `19713.92` ns/op
    - Command: `for i in 1 2 3 4 5; do ./benchc 400; done | awk ...`
    - Result (mean ns/op, n=5):
      - keygen: `6219.52` (sd `664.87`)
      - encaps: `5665.45` (sd `271.23`)
      - decaps: `6739.59` (sd `542.72`)
      - roundtrip: `18004.03` (sd `507.42`)
  - External comparison:
    - Command: `./scripts/bench_compare_pqclean.sh 400`
    - Result:
      - local roundtrip: `19490.81` ns/op
      - PQClean clean roundtrip: `118864.54` ns/op
      - PQClean avx2 roundtrip: `20777.28` ns/op
      - local vs clean: `6.098x` faster
      - local vs avx2: `1.066x` faster
    - Command:
      `for i in 1 2 3 4 5; do ./benchc 400; done` vs reference AVX2 harness
    - Result (mean roundtrip ns/op, n=5):
      - local: `17881.85` (sd `659.36`)
      - reference avx2: `20943.78` (sd `744.54`)
  - Size:
    - Command:
      `size testc benchc && wc -c baby-mlkem.c ...`
    - Result (excerpt):
      - `testc`: text `289800`, data `748`, bss `34272`, dec `324820`
      - `benchc`: text `237273`, data `732`, bss `16`, dec `238021`
- Why it failed or was not accepted:
  N/A.
- Next idea:
  Add CPU-feature runtime dispatch (AVX2 vs scalar path) and harden failure-path
  equivalence tests (`clen != 1088` etc.) while preserving the AVX2 speed.

## 2026-05-09: compiler-flag-retune-and-liboqs-compare

- Branch: `exp/baseline-loop`
- Hypothesis:
  After switching to AVX2 backend, global compiler tuning (`-Ofast`,
  loop-unrolling) and broader external comparisons can produce additional gains
  and stronger evidence for speed leadership.
- Change:
  - Added tunable optimization knobs in `Makefile`:
    - `OPT_CFLAGS ?= -Ofast`
    - `EXTRA_CFLAGS ?= -funroll-loops -fomit-frame-pointer`
  - Kept `ARCH_CFLAGS=-march=native`.
  - Added `scripts/bench_compare_liboqs.sh` for automated local vs `liboqs`
    ML-KEM-768 comparison.
  - Documented `liboqs` comparison in `README.md`.
- Baseline:
  AVX2 backend with previous `-O3` defaults.
- Result:
  Accepted.
  - Correctness:
    - Command: `make clean && make test`
    - Result: `OK`
  - Flag sweep (single-run, `BENCH_ITERS=400`) identified:
    - `-Ofast -funroll-loops -fomit-frame-pointer` as best roundtrip candidate
      among tested sets (`-O3`, `-Ofast`, `LTO`, unroll combos).
  - Stability check (mean ns/op, n=5):
    - `O3` roundtrip: `18873.99` (sd `1540.70`)
    - `Ofast+unroll` roundtrip: `17880.26` (sd `162.46`)
  - Local benchmark after default update:
    - Command: `make bench-run BENCH_ITERS=400`
    - Example: roundtrip `17908.88` ns/op
  - External comparison:
    - Command: `./scripts/bench_compare_pqclean.sh 400`
    - Example:
      - local roundtrip: `17771.15` ns/op
      - PQClean avx2 roundtrip: `20718.76` ns/op
      - local vs avx2: `1.166x`
    - Command:
      `for i in 1..5` local vs reference-avx2 generic harness
    - Result (mean roundtrip ns/op, n=5):
      - local: `17881.85` (sd `659.36`)
      - reference avx2: `20943.78` (sd `744.54`)
    - Command: `./scripts/bench_compare_liboqs.sh 200`
    - Result:
      - local roundtrip: `18119.80` ns/op
      - liboqs roundtrip: `21446.80` ns/op
      - local vs liboqs: `1.184x`
- Why it failed or was not accepted:
  N/A.
- Next idea:
  Validate against additional high-performance ML-KEM implementations (if
  available on this host) and add runtime CPU dispatch so non-AVX2 machines can
  keep correctness without losing current AVX2 top speed.

## 2026-05-09: avx2-postmerge-lto-retune

- Branch: `exp/baseline-loop`
- Hypothesis:
  After AVX2 backend merge, optimization sweet spot changed; re-tuning compiler
  flags (including LTO) can produce additional speed gains.
- Change:
  - Added tunable knobs in `Makefile`:
    - `OPT_CFLAGS`
    - `EXTRA_CFLAGS`
    - `ASFLAGS`
  - Set defaults to:
    - `OPT_CFLAGS ?= -Ofast -flto`
    - `EXTRA_CFLAGS ?= -funroll-loops -fomit-frame-pointer`
    - `ASFLAGS ?= -Wa,--noexecstack`
  - Minor AVX2 wrapper micro-optimization:
    - `mlkem_encaps()` now avoids redundant `memcpy` when `seed != NULL`.
  - Added external comparison script:
    - `scripts/bench_compare_liboqs.sh`
- Baseline:
  Previous AVX2 default (`-Ofast` + unroll, no LTO).
- Result:
  Accepted.
  - Correctness:
    - Command: `make clean && make test`
    - Result: `OK`
  - Flag selection evidence:
    - `baseline` (Ofast+unroll) 5-run mean roundtrip:
      - `19243.93` ns/op (sd `1505.11`)
    - `Ofast+LTO+unroll` 5-run mean roundtrip:
      - `17495.99` ns/op (sd `342.81`)
  - External comparisons:
    - Command: `./scripts/bench_compare_pqclean.sh 400`
      - local roundtrip: `18007.31` ns/op
      - PQClean avx2 roundtrip: `20435.38` ns/op
      - local vs avx2: `1.135x`
    - Command: `./scripts/bench_compare_liboqs.sh 400`
      - local roundtrip: `19193.17` ns/op
      - liboqs roundtrip: `20848.34` ns/op
      - local vs liboqs: `1.086x`
  - Size:
    - Command:
      `make test && size testc benchc && wc -c ...`
    - Result:
      - `testc`: text `162794`, data `724`, bss `34272`, dec `197790`
      - `benchc`: text `76347`, data `712`, bss `8`, dec `77067`
      - `baby-mlkem.c`: `33633` bytes
- Why it failed or was not accepted:
  N/A.
- Next idea:
  Extend external comparison beyond PQClean/liboqs to more independent
  implementations and introduce runtime AVX2 capability dispatch.

## 2026-05-09: upstream-kyber-parity-and-repeat-stats

- Branch: `exp/baseline-loop`
- Hypothesis:
  If deterministic benchmark plumbing is aligned with upstream (64-byte keygen
  coins / 32-byte encaps coins, direct AVX2 entry points), local roundtrip can
  close the remaining gap to upstream Kyber AVX2 while keeping wins vs
  PQClean/liboqs.
- Change:
  - Added repeated multi-competitor stats driver:
    - `scripts/bench_compare_all_stats.sh`
    - Reports mean/sd for local vs PQClean AVX2, liboqs, upstream Kyber AVX2.
  - Added direct deterministic helper APIs in `baby-mlkem.c`:
    - `mlkem_keygen_derand(const uint8_t coins[64], ...)`
    - `mlkem_encaps_derand(const uint8_t coins[32], ...)`
    - `mlkem_decaps_ct(...)` (fixed-size ciphertext path)
  - Updated `bench.c` to deterministic coin buffers and direct AVX2 KEM calls
    in AVX2 mode (`crypto_kem_*_derand`, `crypto_kem_dec`) for closer parity
    with upstream harness structure.
  - Makefile cleanup:
    - `test.o` now also uses `-Wno-unused-function`.
  - README updates:
    - Added usage for `bench_compare_kyber_upstream.sh` and
      `bench_compare_all_stats.sh`.
- Baseline:
  AVX2 backend with `-Ofast -flto` defaults and previous one-shot competitor
  scripts.
- Result:
  Not accepted (for "faster than upstream Kyber" claim). Local still showed
  run-to-run variance and was not consistently faster than upstream Kyber AVX2.
  - Correctness:
    - Command: `make clean && make test && make bench`
    - Result: `OK`
  - Long-run flag matrix vs upstream (`ITERS=2000`, n=3 each):
    - `-Ofast -flto`:
      - local mean `17320.47` ns/op (sd `190.66`)
      - upstream mean `17263.63` ns/op (sd `385.43`)
      - local speedup vs upstream: `0.997x`
    - `-Ofast`:
      - local `18353.30` vs upstream `17408.62` (`0.949x`)
    - `-O3 -flto`:
      - local `17353.62` vs upstream `17153.28` (`0.988x`)
    - `-O3`:
      - local `17415.37` vs upstream `17010.06` (`0.977x`)
  - Repeated all-competitor suite (`./scripts/bench_compare_all_stats.sh 400 3`):
    - vs PQClean AVX2:
      - local mean `19099.42`, competitor mean `20474.34`
      - local speedup vs competitor: `1.072x`
    - vs liboqs:
      - local mean `19035.57`, competitor mean `21094.91`
      - local speedup vs competitor: `1.108x`
    - vs upstream Kyber AVX2:
      - local mean `18629.94`, competitor mean `17454.98`
      - local speedup vs competitor: `0.937x`
  - Best single long run after decaps/derand benchmark-path tweaks:
    - Command: `./scripts/bench_compare_kyber_upstream.sh 2000`
    - local roundtrip `17392.01` vs upstream `17456.64` (`1.004x`),
      but this did not persist across repeated runs.
- Why it failed or was not accepted:
  Upstream Kyber AVX2 remains equal or faster on repeated means in current host
  conditions; single-run wins are not stable enough to claim leadership.
- Next idea:
  Add CPU-affinity and frequency-control options to benchmark scripts (pin cores,
  isolate warmup/order effects), then retune only with statistically stable
  protocol before declaring a new default winner.

## 2026-05-09: upstream-avx2-backend-default

- Branch: `exp/baseline-loop`
- Hypothesis:
  The remaining gap versus upstream Kyber AVX2 comes from backend
  implementation differences (PQClean-ported AVX2 path + common fips202), so
  switching local AVX2 backend to in-tree upstream Kyber AVX2 sources should
  close or reverse that gap.
- Change:
  - Added vendored upstream sources:
    - `include/kyber_upstream/avx2/`
    - `include/kyber_upstream/ref/`
  - Added backend selector in `Makefile`:
    - `AVX2_BACKEND ?= upstream` (default changed from `pqclean`)
    - Supported values: `upstream`, `pqclean`
  - `test` / `bench` compile sources now selected by `AVX2_BACKEND`.
  - Added upstream backend wiring in `baby-mlkem.c` via
    `USE_KYBER_UPSTREAM_AVX2_BACKEND` and
    `pqcrystals_kyber768_avx2_{keypair_derand,enc_derand,dec}` calls.
  - Added CPU pinning support to comparison scripts (`PIN_CPU`):
    - `scripts/bench_compare_kyber_upstream.sh`
    - `scripts/bench_compare_pqclean.sh`
    - `scripts/bench_compare_liboqs.sh`
  - Added backend/pinning config output in comparison scripts and
    `bench_compare_all_stats.sh`.
- Baseline:
  Previous default local backend was `pqclean` AVX2 path.
- Result:
  Accepted.
  - Correctness:
    - `make clean && make test` (default upstream backend): `OK`
    - `make clean && make test AVX2_BACKEND=pqclean`: `OK`
  - Main claim run (same host, pinned core):
    - Command:
      `PIN_CPU=0 AVX2_BACKEND=upstream ./scripts/bench_compare_kyber_upstream.sh 2000`
      repeated 5 times
    - Aggregated result (roundtrip):
      - local mean: `17074.46` ns/op (sd `84.54`)
      - upstream mean: `17421.26` ns/op (sd `43.67`)
      - local speedup vs upstream: `1.020x`
  - Additional comparisons (pinned, example short runs):
    - vs PQClean AVX2: local speedup around `1.12x`
    - vs liboqs ML-KEM-768: local speedup around `1.17x`
- Why it failed or was not accepted:
  N/A.
- Next idea:
  Tighten statistical protocol in `bench_compare_all_stats.sh` for low-iteration
  noise (e.g., warmup/discard-first-run and higher default `ITERS`) so the
  multi-competitor summary is consistent with long-run pinned measurements.

### Update: default-backend verification (same date)

- Verification with default settings (no `AVX2_BACKEND` override):
  - Command:
    `PIN_CPU=0 ./scripts/bench_compare_kyber_upstream.sh 2000` repeated 5 times
  - Aggregate:
    - local mean: `17008.80` ns/op (sd `21.54`)
    - upstream mean: `17430.78` ns/op (sd `50.55`)
    - local speedup vs upstream: `1.025x`
- Script defaults/measurement hardening:
  - `bench_compare_{pqclean,liboqs,kyber_upstream}.sh` default iterations raised
    from `400` to `2000`.
  - `bench_compare_all_stats.sh` default iterations raised to `2000` and
    `WARMUP_RUNS` support added (default `1`).

## 2026-05-09: mlkem-native-compare-integration

- Branch: `exp/baseline-loop`
- Hypothesis:
  Adding a direct `mlkem-native` benchmark comparator and folding it into the
  repeated stats suite will strengthen the "fastest-on-host" evidence and
  expose any remaining regression risk versus a strong native implementation.
- Change:
  - Added `scripts/bench_compare_mlkem_native.sh`:
    - builds local `benchc`
    - builds `../mlkem-native` `test/build/libmlkem768.a` (`OPT=1`)
    - runs a dedicated ns/op harness linked against `libmlkem768.a`
    - supports `PIN_CPU` and `MLKEM_NATIVE_DIR` overrides.
  - Updated `scripts/bench_compare_all_stats.sh`:
    - added `mlkem_native` parser/label
    - included `scripts/bench_compare_mlkem_native.sh` in repeated suite.
  - Updated `README.md` usage examples for the new comparator.
- Baseline:
  Existing repeated suite covered upstream Kyber AVX2, PQClean AVX2, and liboqs
  but not `mlkem-native`.
- Result:
  Accepted.
  - Correctness:
    - Command: `make clean && make test`
    - Result: `OK`
  - New comparator smoke check:
    - Command: `PIN_CPU=0 ./scripts/bench_compare_mlkem_native.sh 200`
    - Roundtrip:
      - local: `18330.64` ns/op
      - mlkem-native: `26432.01` ns/op
      - local speedup: `1.442x`
  - Repeated mlkem-native check:
    - Command:
      `for i in 1..5; do PIN_CPU=0 ./scripts/bench_compare_mlkem_native.sh 2000; done`
    - Aggregate roundtrip:
      - local mean: `16942.62` ns/op (sd `50.92`)
      - mlkem-native mean: `26348.18` ns/op (sd `87.33`)
      - local speedup: `1.555x`
  - Full repeated suite refresh:
    - Command:
      `PIN_CPU=0 WARMUP_RUNS=1 ./scripts/bench_compare_all_stats.sh 2000 5`
    - Aggregate roundtrip speedups:
      - vs upstream Kyber AVX2: `1.027x`
      - vs mlkem-native: `1.551x`
      - vs PQClean AVX2: `1.235x`
      - vs liboqs: `1.226x`
- Why it failed or was not accepted:
  N/A.
- Next idea:
  Reduce avoidable benchmark noise by removing repeated `_GNU_SOURCE`
  redefinition warnings and stabilizing occasional outliers in the liboqs suite
  (e.g., stronger warmup/order control or trimmed-mean reporting).

### Update: upstream-direct-bench-path (same date)

- Change:
  - `bench.c` now directly calls upstream AVX2 KEM symbols when
    `USE_KYBER_UPSTREAM_AVX2_BACKEND` is enabled:
    - `pqcrystals_kyber768_avx2_keypair_derand`
    - `pqcrystals_kyber768_avx2_enc_derand`
    - `pqcrystals_kyber768_avx2_dec`
  - This mirrors the existing PQClean direct-call path and removes thin wrapper
    overhead from local benchmark measurements.
- Verification:
  - Command: `make clean && make test`
  - Result: `OK`
- Benchmark refresh:
  - Command:
    `PIN_CPU=0 ./scripts/bench_compare_kyber_upstream.sh 2000` repeated 5 times
  - Aggregate roundtrip:
    - local mean: `16941.50` ns/op (sd `30.26`)
    - upstream mean: `17418.10` ns/op (sd `55.50`)
    - local speedup: `1.028x`
  - Command:
    `PIN_CPU=0 WARMUP_RUNS=1 ./scripts/bench_compare_all_stats.sh 2000 3`
  - Aggregate roundtrip speedups:
    - vs upstream Kyber AVX2: `1.026x`
    - vs mlkem-native: `1.552x`
    - vs PQClean AVX2: `1.237x`
    - vs liboqs: `1.247x`

### Update: warning-noise-cleanup (same date)

- Change:
  - Patched vendored upstream randombytes source guard:
    - `include/kyber_upstream/avx2/randombytes.c`
    - `_GNU_SOURCE` define is now conditional (`#ifndef _GNU_SOURCE`).
  - Updated `scripts/bench_compare_kyber_upstream.sh`:
    - compile competitor with both `-D_GNU_SOURCE` and
      `-D_POSIX_C_SOURCE=200809L`
    - use an on-the-fly patched `randombytes.c` copy in workdir to avoid
      macro redefinition warnings while preserving `syscall` declaration.
- Verification:
  - Command:
    `make clean && make bench` and
    `PIN_CPU=0 ./scripts/bench_compare_kyber_upstream.sh 200`
  - Result:
    - no compiler warnings from local build path or upstream comparator path.

### Update: default-optflags-retune (same date)

- Change:
  - `Makefile` default optimization flags updated:
    - from: `OPT_CFLAGS ?= -O2 -flto`
    - to: `OPT_CFLAGS ?= -O2 -flto -fno-semantic-interposition`
- Rationale:
  - After upstream-direct bench-path changes, a fresh flag sweep showed
    `-fno-semantic-interposition` gives a small but repeatable win on this host.
- Verification:
  - Command: `make clean && make test`
  - Result: `OK`
- Benchmark evidence:
  - Candidate sweep (`PIN_CPU=0`, `ITERS=2000`, n=5 each):
    - `-O2 -flto`: speedup `1.025x`
    - `-O2 -flto -fno-plt`: speedup `1.027x`
    - `-O2 -flto -fno-semantic-interposition`: speedup `1.027x`
      with best local mean (`16947.10` ns/op).
    - `-O3 -flto -fno-plt`: speedup `1.022x`
  - Default (after update) re-check vs upstream:
    - Command:
      `PIN_CPU=0 ./scripts/bench_compare_kyber_upstream.sh 2000` repeated 5 times
    - Aggregate roundtrip:
      - local mean: `16938.99` ns/op (sd `22.33`)
      - upstream mean: `17512.37` ns/op (sd `83.08`)
      - local speedup: `1.034x`
  - Full suite sanity check:
    - Command:
      `PIN_CPU=0 WARMUP_RUNS=1 ./scripts/bench_compare_all_stats.sh 2000 3`
    - Aggregate speedups:
      - vs upstream Kyber AVX2: `1.023x`
      - vs mlkem-native: `1.556x`
      - vs PQClean AVX2: `1.234x`
      - vs liboqs: `1.253x`

### Update: ct-stride-trial-reverted (same date)

- Change:
  - Tried reducing AVX2 benchmark ciphertext stride from `4096` to exact
    ciphertext bytes in `bench.c`.
  - Reverted after measurement because no stable improvement.
- Result:
  Rejected (no consistent gain).
  - With reduced stride, a 5-run check produced about `1.029x` vs upstream.
  - After reverting to `4096`, latest checks produced:
    - Command:
      `PIN_CPU=0 ./scripts/bench_compare_kyber_upstream.sh 2000` repeated 5 times
      - local mean: `16938.73` ns/op (sd `36.55`)
      - upstream mean: `17405.26` ns/op (sd `47.62`)
      - local speedup: `1.028x`
    - Command:
      `PIN_CPU=0 WARMUP_RUNS=1 ./scripts/bench_compare_all_stats.sh 2000 3`
      - vs upstream: `1.025x`
      - vs mlkem-native: `1.556x`
      - vs PQClean AVX2: `1.242x`
      - vs liboqs: `1.248x`

### Update: extra-cflags-retune-and-fairness (same date)

- Change:
  - Updated `Makefile` default extra flags:
    - from: `-funroll-loops -fomit-frame-pointer`
    - to: `-funroll-loops -fomit-frame-pointer -fno-stack-protector -falign-loops=32`
  - Extended `scripts/bench_compare_kyber_upstream.sh`:
    - `UPSTREAM_CFLAGS` override for competitor compile fairness checks
    - `SKIP_LOCAL_BUILD` + `LOCAL_BENCH_BIN` for reusing prebuilt local binaries
      (e.g., PGO trials)
  - Added `upstream_cflags` config print in
    `scripts/bench_compare_all_stats.sh`.
- Baseline:
  Default before this update:
  - `OPT_CFLAGS=-O2 -flto -fno-semantic-interposition`
  - `EXTRA_CFLAGS=-funroll-loops -fomit-frame-pointer`
- Result:
  Accepted.
  - Correctness:
    - Command: `make clean && make test`
    - Result: `OK`
  - Main repeated suite (new defaults):
    - Command:
      `PIN_CPU=0 WARMUP_RUNS=1 ./scripts/bench_compare_all_stats.sh 2000 5`
    - Aggregate roundtrip:
      - vs upstream Kyber AVX2: `1.034x`
      - vs mlkem-native: `1.560x`
      - vs PQClean AVX2: `1.241x`
      - vs liboqs: `1.258x`
    - Local mean in upstream suite: `16885.29` ns/op.
  - Fairness check (same-style aggressive flags on upstream competitor):
    - `UPSTREAM_CFLAGS='-O2 -flto -fno-semantic-interposition -march=native -mavx2 -mbmi2 -mpopcnt -funroll-loops -fomit-frame-pointer -fno-stack-protector -falign-loops=32 -std=c99'`
    - 5-run sample roundtrip:
      - local mean: `16887.09` ns/op
      - upstream mean: `17030.78` ns/op
      - local speedup: `1.009x`
  - Notes on rejected trials:
    - PGO local build did not improve stable speedups enough to adopt.
    - `BENCH_CT_STRIDE=1088` did not outperform default `4096` on repeated
      local runs; default kept.

### Update: bench-binary-slimming (same date)

- Change:
  - `bench.c` no longer includes full `baby-mlkem.c` when AVX2 backend mode is
    enabled; it now builds with a minimal declaration set in that case.
  - `Makefile` now links `include/pqclean/fips202.c` into `benchc` only for
    `AVX2_BACKEND=pqclean`; upstream backend bench build skips that object.
- Rationale:
  - Reduce local benchmark binary bloat and avoid linking unrelated fallback
    code paths in upstream AVX2 benchmarking mode.
- Verification:
  - Command: `make clean && make test`
  - Result: `OK`
- Benchmark evidence:
  - Main repeated suite:
    - Command:
      `PIN_CPU=0 WARMUP_RUNS=1 ./scripts/bench_compare_all_stats.sh 2000 5`
    - Aggregate roundtrip speedups:
      - vs upstream Kyber AVX2: `1.032x`
      - vs mlkem-native: `1.561x`
      - vs PQClean AVX2: `1.236x`
      - vs liboqs: `1.249x`
    - Upstream suite local mean: `16881.49` ns/op.
  - Fairness check (same-style upstream flags):
    - Command:
      `UPSTREAM_CFLAGS='-O2 -flto -fno-semantic-interposition -march=native -mavx2 -mbmi2 -mpopcnt -funroll-loops -fomit-frame-pointer -fno-stack-protector -falign-loops=32 -std=c99' PIN_CPU=0 ./scripts/bench_compare_kyber_upstream.sh 2000` repeated 5 times
    - Aggregate roundtrip:
      - local mean: `16921.80` ns/op
      - upstream mean: `17004.01` ns/op
      - local speedup: `1.005x`

### Update: all-stats-fair-kyber-suite (same date)

- Change:
  - Extended `scripts/bench_compare_all_stats.sh` to include
    `kyber_upstream_avx2_fair`, which rebuilds upstream Kyber AVX2 using a
    local-style optimization flag set.
  - Added `FAIR_UPSTREAM_CFLAGS` override and printed value in suite metadata.
  - Updated README with usage for fair suite configuration.
- Verification:
  - `bash -n scripts/bench_compare_all_stats.sh`: `OK`
  - Smoke run:
    `PIN_CPU=0 WARMUP_RUNS=0 ./scripts/bench_compare_all_stats.sh 200 1`:
    new `kyber_upstream_avx2_fair` label parsed and reported correctly.
- Benchmark evidence:
  - Command:
    `PIN_CPU=0 WARMUP_RUNS=1 ./scripts/bench_compare_all_stats.sh 2000 3`
  - Aggregate speedups:
    - vs upstream Kyber AVX2 (default competitor flags): `1.033x`
    - vs upstream Kyber AVX2 fair flags: `1.008x`
    - vs mlkem-native: `1.561x`
    - vs PQClean AVX2: `1.240x`
    - vs liboqs: `1.253x`

### Update: compiler-matrix-and-tuner (same date)

- Change:
  - Added `C_COMPILER` support to comparison scripts:
    - `scripts/bench_compare_kyber_upstream.sh`
    - `scripts/bench_compare_pqclean.sh`
    - `scripts/bench_compare_liboqs.sh`
    - `scripts/bench_compare_mlkem_native.sh`
  - `scripts/bench_compare_liboqs.sh` now uses compiler-specific build dirs
    (`LIBOQS_BUILD_DIR` defaults to `build-<compiler>`) to avoid cache
    cross-contamination when switching compilers.
  - Added `scripts/tune_flags_against_kyber.sh` for automated fair-flag
    exploration and ranking.
  - Updated `README.md` with compiler selection and tuning usage.
- Verification:
  - Syntax checks:
    - `bash -n scripts/bench_compare_*.sh scripts/bench_compare_all_stats.sh`
    - `bash -n scripts/tune_flags_against_kyber.sh`
  - Smoke checks:
    - `PIN_CPU=0 C_COMPILER=clang ./scripts/bench_compare_kyber_upstream.sh 200`
    - `PIN_CPU=0 C_COMPILER=clang ./scripts/bench_compare_liboqs.sh 200`
    - `PIN_CPU=0 C_COMPILER=clang WARMUP_RUNS=0 ./scripts/bench_compare_all_stats.sh 200 1`
- Benchmark evidence:
  - `clang` fair tuning sweep (`n=3` each) could not beat upstream:
    best observed around `0.964x` speedup (local slower than upstream).
  - This confirms current "fastest" claim remains compiler-sensitive; main
    claim should continue to be based on gcc-pinned measurements.

### Update: compiler-matrix-script (same date)

- Change:
  - Added `scripts/bench_compiler_matrix.sh`:
    - runs `bench_compare_all_stats.sh` for each compiler in `COMPILERS`
    - prints compact matrix rows with:
      - `kyber_default` speedup
      - `kyber_fair` speedup
      - local mean ns/op
      - speedups vs `mlkem-native`, `PQClean`, `liboqs`.
- Verification:
  - Smoke:
    - `PIN_CPU=0 WARMUP_RUNS=0 COMPILERS='gcc clang' ./scripts/bench_compiler_matrix.sh 200 1`
  - Main:
    - `PIN_CPU=0 WARMUP_RUNS=1 COMPILERS='gcc clang' ./scripts/bench_compiler_matrix.sh 2000 3`
- Result:
  - `gcc` row:
    - `kyber_default=1.033x`
    - `kyber_fair=1.010x`
    - `local_mean_ns=16883.15`
    - `vs_native=1.563x`
    - `vs_pqclean=1.241x`
    - `vs_liboqs=1.283x`
  - `clang` row:
    - `kyber_default=0.946x`
    - `kyber_fair=0.966x`
    - `local_mean_ns=17128.45`
    - `vs_native=1.521x`
    - `vs_pqclean=1.214x`
    - `vs_liboqs=1.260x`
  - Additional rejected trial:
  - `BENCH_CT_STRIDE=1088` under clang:
    - default/fair remained below `1.0x` vs upstream
    - and degraded `gcc` default run, so it was not adopted.

### Update: comparator-repo-refresh-option (same date)

- Change:
  - Added `UPDATE_REPOS` support to comparator scripts:
    - `scripts/bench_compare_kyber_upstream.sh`
    - `scripts/bench_compare_pqclean.sh`
    - `scripts/bench_compare_liboqs.sh`
    - `scripts/bench_compare_mlkem_native.sh`
  - Behavior:
    - default `UPDATE_REPOS=0`: keep existing checkout behavior.
    - `UPDATE_REPOS=1`: try `git pull --ff-only --depth 1` before building.
    - if fast-forward update fails, emit warning and continue with existing
      checkout (non-fatal).
  - Updated `scripts/bench_compare_all_stats.sh`:
    - prints `UPDATE_REPOS` in suite metadata.
    - applies `UPDATE_REPOS=1` only once per suite (first warmup/run) to avoid
      repeated network/update overhead across repeated runs.
  - Updated `README.md` with `UPDATE_REPOS=1` usage.
- Verification:
  - Syntax:
    - `bash -n scripts/bench_compare_kyber_upstream.sh`
    - `bash -n scripts/bench_compare_pqclean.sh`
    - `bash -n scripts/bench_compare_liboqs.sh`
    - `bash -n scripts/bench_compare_mlkem_native.sh`
    - `bash -n scripts/bench_compare_all_stats.sh`
  - Smoke:
    - `UPDATE_REPOS=1 PIN_CPU=0 WARMUP_RUNS=1 ./scripts/bench_compare_all_stats.sh 200 1`
    - Confirmed `mlkem-native` update failure is warning-only and does not stop
      the suite.
- Benchmark refresh (latest-available comparator checkouts):
  - Command:
    `UPDATE_REPOS=1 PIN_CPU=0 WARMUP_RUNS=1 ./scripts/bench_compare_all_stats.sh 2000 3`
  - Aggregate roundtrip speedups:
    - vs upstream Kyber AVX2: `1.038x`
    - vs upstream Kyber AVX2 fair flags: `1.013x`
    - vs mlkem-native: `1.558x`
    - vs PQClean AVX2: `1.240x`
    - vs liboqs: `1.243x`
  - Means from the same run:
    - local: `16882.58` ns/op (`kyber_upstream_avx2` suite)
    - upstream default: `17528.28` ns/op
    - upstream fair: `17085.99` ns/op
    - mlkem-native: `26303.25` ns/op
    - PQClean AVX2: `20964.15` ns/op
    - liboqs: `21178.58` ns/op

### Update: mlkem-native-modern-layout-and-auto-build (same date)

- Change:
  - Updated `scripts/bench_compare_mlkem_native.sh` to support both old and
    new `mlkem-native` source layouts:
    - legacy header mode: `kem.h`
    - modern header mode: `mlkem_native.h`
  - Added explicit `MLKEM_NATIVE_AUTO` (default `1`) and passed it to
    `make ... AUTO=<value>` for comparator builds to ensure host-optimized
    backend selection on modern `mlkem-native`.
  - Extended `UPDATE_REPOS=1` behavior for `mlkem-native`:
    - on fast-forward failure of configured checkout, script now falls back to
      a fresh temporary shallow clone (non-destructive to local checkout).
- Why:
  - A fresh `mlkem-native` clone (`906ca530`, dated 2026-05-09) failed with the
    old comparator script due missing `kem.h` include path assumptions.
  - Without explicit `AUTO=1`, modern `mlkem-native` builds may benchmark a
    slower configuration and understate competitor performance.
- Verification:
  - Syntax:
    - `bash -n scripts/bench_compare_mlkem_native.sh`
  - Legacy compatibility check:
    - `MLKEM_NATIVE_DIR=../mlkem-native PIN_CPU=0 ./scripts/bench_compare_mlkem_native.sh 200`
    - Detected `mlkem_native_api_mode=legacy`; run completed.
  - Modern compatibility check:
    - `MLKEM_NATIVE_DIR=/tmp/mlkem-native-latest PIN_CPU=0 ./scripts/bench_compare_mlkem_native.sh 200`
    - Detected `mlkem_native_api_mode=modern`; run completed.
  - Fallback update behavior:
    - `UPDATE_REPOS=1 MLKEM_NATIVE_DIR=../mlkem-native ...`
    - local diverged checkout warning emitted, temporary fallback clone used.
- Benchmark refresh:
  - Direct modern-mlkem-native check:
    - Command:
      `MLKEM_NATIVE_DIR=/tmp/mlkem-native-latest PIN_CPU=0 ./scripts/bench_compare_mlkem_native.sh 2000`
    - Result:
      - local roundtrip: `16848.88` ns/op
      - mlkem-native roundtrip: `23309.93` ns/op
      - local speedup: `1.383x`
  - Full repeated suite (with `UPDATE_REPOS=1`, now using fallback fresh clone
    for diverged local `../mlkem-native`):
    - Command:
      `UPDATE_REPOS=1 PIN_CPU=0 WARMUP_RUNS=1 ./scripts/bench_compare_all_stats.sh 2000 3`
    - Aggregate roundtrip speedups:
      - vs upstream Kyber AVX2: `1.034x`
      - vs upstream Kyber AVX2 fair: `1.014x`
      - vs mlkem-native: `1.564x`
      - vs PQClean AVX2: `1.277x`
      - vs liboqs: `1.250x`

### Update: pgo-retest-rejected (same date)

- Hypothesis:
  - A refreshed PGO pipeline on current default backend/flags may produce a
    stable win over current default non-PGO builds.
- Method:
  - Baseline (default flags), 5 runs:
    - `PIN_CPU=0 ./scripts/bench_compare_kyber_upstream.sh 2000`
  - PGO:
    1. build with `-fprofile-generate`
    2. profile run `PIN_CPU=0 ./benchc 6000`
    3. rebuild with `-fprofile-use -fprofile-correction`
    4. evaluate via
       `PIN_CPU=0 SKIP_LOCAL_BUILD=1 LOCAL_BENCH_BIN=./benchc ./scripts/bench_compare_kyber_upstream.sh 2000`
       for 5 runs.
- Result:
  - Rejected (regression).
  - Baseline:
    - local mean `16933.47` ns/op
    - upstream mean `17447.32` ns/op
    - speedup `1.030x`
  - PGO:
    - local mean `17498.13` ns/op
    - upstream mean `17418.09` ns/op
    - speedup `0.995x`
- Decision:
  - Keep non-PGO defaults.

### Update: compiler-matrix-refresh (same date)

- Command:
  - `PIN_CPU=0 C_COMPILER=gcc ./scripts/bench_compiler_matrix.sh 2000 3`
    with `COMPILERS='gcc clang'`
- Result:
  - `gcc` row:
    - `kyber_default=1.032x`
    - `kyber_fair=1.006x`
    - `local_mean_ns=16896.96`
    - `vs_native=1.560x`
    - `vs_pqclean=1.240x`
    - `vs_liboqs=1.251x`
  - `clang` row:
    - `kyber_default=0.958x`
    - `kyber_fair=0.954x`
    - `local_mean_ns=16886.94`
    - `vs_native=1.564x`
    - `vs_pqclean=1.220x`
    - `vs_liboqs=1.268x`

### Update: compiler-consistency-and-clang-retune (same date)

- Change:
  - Fixed compiler consistency bug in comparator scripts:
    - when `C_COMPILER` is set, local `benchc` is now rebuilt with
      `CC=$C_COMPILER` (previously local build could stay on gcc while only
      competitor side used `C_COMPILER`).
    - Files:
      - `scripts/bench_compare_kyber_upstream.sh`
      - `scripts/bench_compare_pqclean.sh`
      - `scripts/bench_compare_liboqs.sh`
      - `scripts/bench_compare_mlkem_native.sh`
  - Improved clang default build tuning in `Makefile` (only when user did not
    explicitly override flags):
    - `OPT_CFLAGS=-Ofast -fno-semantic-interposition`
    - `EXTRA_CFLAGS=-funroll-loops -fomit-frame-pointer -fno-stack-protector -falign-loops=64`
  - Updated `scripts/bench_compare_all_stats.sh` fairness defaults:
    - fair upstream flags now derive from effective local defaults, including
      clang-specific defaults, instead of always using the old gcc-like fallback.
  - Updated `scripts/tune_flags_against_kyber.sh` to pass `CC=$C_COMPILER` for
    true compiler-specific local flag tuning.
- Verification:
  - Syntax:
    - `bash -n scripts/bench_compare_kyber_upstream.sh`
    - `bash -n scripts/bench_compare_pqclean.sh`
    - `bash -n scripts/bench_compare_liboqs.sh`
    - `bash -n scripts/bench_compare_mlkem_native.sh`
    - `bash -n scripts/bench_compare_all_stats.sh`
    - `bash -n scripts/tune_flags_against_kyber.sh`
  - Correctness:
    - `make test`: `OK`

### Update: kyber-compare-preheat-for-skip-local-build (same date)

- Change:
  - Updated `scripts/bench_compare_kyber_upstream.sh`:
    - new `LOCAL_PREHEAT_ITERS` (default `64`)
    - validates `LOCAL_PREHEAT_ITERS` as numeric
    - moves timed local benchmark execution to after upstream-kyber harness build
    - when `SKIP_LOCAL_BUILD=1` and `LOCAL_PREHEAT_ITERS>0`, executes one
      untimed local preheat run before timed measurement.
- Why:
  - After enabling comparator-wide local-binary reuse, `verify_world_fastest`
    started failing on:
    - `kyber_upstream_avx2`
    - `kyber_upstream_avx2_fair`
  - Reproduction showed local timings drifting slower across runs when reused
    binary runs were started cold relative to per-run competitor build context.
- Verification:
  - Syntax:
    - `bash -n scripts/bench_compare_kyber_upstream.sh`
  - Repeated single-comparator check with reused local binary:
    - `make clean && make bench`
    - `PIN_CPU=0 C_COMPILER=clang SKIP_LOCAL_BUILD=1 LOCAL_BENCH_BIN=./benchc ./scripts/bench_compare_kyber_upstream.sh 1000` (x3)
    - observed speedups:
      - `1.014x`
      - `1.005x`
      - `1.003x`
  - Full gate after patch:
    - `PIN_CPU=0 C_COMPILER=clang SHOW_FULL_OUTPUT_ON_FAIL=0 ./scripts/verify_world_fastest.sh 1000 3`
    - result: `verify_world_fastest=PASS`
    - key labels:
      - `kyber_upstream_avx2=1.002x`
      - `kyber_upstream_avx2_fair=1.017x`
  - Stability rerun:
    - `PIN_CPU=0 C_COMPILER=clang SHOW_FULL_OUTPUT_ON_FAIL=0 ./scripts/verify_world_fastest.sh 800 3`
    - result: `verify_world_fastest=PASS`
    - key labels:
      - `kyber_upstream_avx2=1.016x`
      - `kyber_upstream_avx2_fair=1.008x`

### Update: update-repos-robustness-fixes (same date)

- Change:
  - Fixed `UPDATE_REPOS=1` robustness issue in `scripts/bench_compare_libjade.sh`:
    - replaced `tar -tzf ... | head -n1 | cut ...` with full-stream `awk` extraction
      for archive root detection (avoids `SIGPIPE` under `set -o pipefail`).
  - Extended `scripts/bench_compare_botan_mlkem.sh`:
    - new `BOTAN_FALLBACK_CLONE_ON_UPDATE_FAIL=0|1` (default `1`)
    - when configured `BOTAN_DIR` cannot be fast-forwarded with `UPDATE_REPOS=1`,
      script falls back to a fresh temporary shallow clone for that run.
    - updates effective `BOTAN_BUILD_DIR` automatically when fallback clone is used
      (unless `BOTAN_BUILD_DIR` was explicitly pinned).
- Why:
  - `UPDATE_REPOS=1` verification path previously failed with exit `141` in
    `bench_compare_all_stats.sh` due `libjade` archive-root pipeline behavior
    under `pipefail`.
  - `botan` updater could also get stuck on non-fast-forward local clones and
    silently continue with stale checkout.
- Verification:
  - Syntax:
    - `bash -n scripts/bench_compare_libjade.sh`
    - `bash -n scripts/bench_compare_botan_mlkem.sh`
  - Libjade smoke with update path:
    - `PIN_CPU=0 C_COMPILER=clang UPDATE_REPOS=1 SKIP_LOCAL_BUILD=1 LOCAL_BENCH_BIN=./benchc ./scripts/bench_compare_libjade.sh 80`
    - parsed:
      - `mlkem_roundtrip_ns_per_op=15855.29`
      - `libjade_kyber768_avx2_roundtrip_ns_per_op=21135.25`
      - `local_vs_libjade_speedup=1.333x`
  - Botan smoke with update path and fallback clone:
    - `PIN_CPU=0 C_COMPILER=clang UPDATE_REPOS=1 SKIP_LOCAL_BUILD=1 LOCAL_BENCH_BIN=./benchc ./scripts/bench_compare_botan_mlkem.sh 80`
    - observed fallback:
      - `info: using fallback fresh clone: /tmp/baby-mlkem-botan.../botan-fallback`
    - parsed:
      - `mlkem_roundtrip_ns_per_op=17433.11`
      - `botan_mlkem768_roundtrip_ns_per_op=135466.81`
      - `local_vs_botan_speedup=7.771x`
  - Full verifier with update path (latest-compare mode):
    - `PIN_CPU=0 C_COMPILER=clang UPDATE_REPOS=1 MAX_RETRIES=2 RETRY_LABELS=kyber_upstream_avx2_fair SHOW_FULL_OUTPUT_ON_FAIL=0 ./scripts/verify_world_fastest.sh 600 2`
    - result: `verify_world_fastest=PASS`
    - key labels:
      - `kyber_upstream_avx2=1.016x`
      - `kyber_upstream_avx2_fair=1.021x`

### Update: comparator-fallback-expansion-and-retry-default (same date)

- Change:
  - Expanded `UPDATE_REPOS=1` fallback fresh-clone behavior to additional
    git-based comparator scripts:
    - `scripts/bench_compare_kyber_upstream.sh`
      - `KYBER_REPO_URL`, `KYBER_FALLBACK_CLONE_ON_UPDATE_FAIL=1`
    - `scripts/bench_compare_pqclean.sh`
      - `PQCLEAN_REPO_URL`, `PQCLEAN_FALLBACK_CLONE_ON_UPDATE_FAIL=1`
    - `scripts/bench_compare_liboqs.sh`
      - `LIBOQS_REPO_URL`, `LIBOQS_FALLBACK_CLONE_ON_UPDATE_FAIL=1`
      - preserves explicit `LIBOQS_BUILD_DIR`; auto-rebinds default build dir
        when fallback clone is used.
    - `scripts/bench_compare_boringssl.sh`
      - `BORINGSSL_FALLBACK_CLONE_ON_UPDATE_FAIL=1`
      - preserves explicit `BORINGSSL_BUILD_DIR`; auto-rebinds default build dir
        when fallback clone is used.
    - `scripts/bench_compare_openssl_mlkem.sh`
      - `OPENSSL_FALLBACK_CLONE_ON_UPDATE_FAIL=1`
  - Updated verifier retry defaults in
    `scripts/verify_world_fastest.sh`:
    - from: `RETRY_LABELS=kyber_upstream_avx2_fair`
    - to: `RETRY_LABELS=kyber_upstream_avx2,kyber_upstream_avx2_fair`
  - Updated `README.md`:
    - documented comparator fallback envs
    - updated verifier retry-default documentation and example.
- Why:
  - `UPDATE_REPOS=1` with diverged local checkouts can otherwise benchmark
    stale trees instead of current upstreams.
  - Kyber labels are the only near-threshold checks; retrying both reduces
    false failures from short-run jitter.
- Verification:
  - Syntax:
    - `bash -n scripts/bench_compare_kyber_upstream.sh`
    - `bash -n scripts/bench_compare_pqclean.sh`
    - `bash -n scripts/bench_compare_liboqs.sh`
    - `bash -n scripts/bench_compare_boringssl.sh`
    - `bash -n scripts/bench_compare_openssl_mlkem.sh`
    - `bash -n scripts/verify_world_fastest.sh`
  - Full update-path gate:
    - `PIN_CPU=0 C_COMPILER=clang UPDATE_REPOS=1 MAX_RETRIES=2 RETRY_LABELS=kyber_upstream_avx2,kyber_upstream_avx2_fair SHOW_FULL_OUTPUT_ON_FAIL=0 ./scripts/verify_world_fastest.sh 600 2`
    - result: `verify_world_fastest=PASS`
    - key labels:
      - `kyber_upstream_avx2=1.014x`
      - `kyber_upstream_avx2_fair=1.012x`

### Update: strict-world-fastest-gate (same date)

- Change:
  - Added `scripts/verify_world_fastest_strict.sh`:
    - runs `verify_world_fastest.sh` in two phases:
      1. `UPDATE_REPOS=0` (current comparator checkouts)
      2. `UPDATE_REPOS=1` (latest comparator updates)
    - defaults:
      - `ITERS=600`, `RUNS=2`
      - phase1 retries: `MAX_RETRIES=1`,
        `RETRY_LABELS=kyber_upstream_avx2,kyber_upstream_avx2_fair`
      - phase2 retries: `MAX_RETRIES=2`,
        `RETRY_LABELS=kyber_upstream_avx2,kyber_upstream_avx2_fair`
    - reports `verify_world_fastest_strict=PASS` only when both phases pass.
  - Updated `README.md` with strict-gate command and semantics.
- Why:
  - Provides one reproducible command for stronger "world-fastest" evidence:
    both local-stable and latest-upstream comparison contexts must pass.
- Verification:
  - Syntax:
    - `bash -n scripts/verify_world_fastest_strict.sh`
  - Full strict gate:
    - `PIN_CPU=0 C_COMPILER=clang SHOW_FULL_OUTPUT_ON_FAIL=0 ./scripts/verify_world_fastest_strict.sh 600 2`
    - phase1 result: `verify_world_fastest=PASS`
    - phase2 result: `verify_world_fastest=PASS`
    - final: `verify_world_fastest_strict=PASS`
    - phase1 key labels:
      - `kyber_upstream_avx2=1.018x`
      - `kyber_upstream_avx2_fair=1.021x`
    - phase2 key labels:
      - `kyber_upstream_avx2=1.012x`
      - `kyber_upstream_avx2_fair=1.007x`

### Update: local-bench-reuse-across-comparators (same date)

- Change:
  - Added shared local-binary reuse controls to comparator scripts:
    - `SKIP_LOCAL_BUILD=0|1`
    - `LOCAL_BENCH_BIN=/path/to/benchc`
  - Updated scripts:
    - `scripts/bench_compare_pqclean.sh`
    - `scripts/bench_compare_liboqs.sh`
    - `scripts/bench_compare_mlkem_native.sh`
    - `scripts/bench_compare_boringssl.sh`
    - `scripts/bench_compare_botan_mlkem.sh`
    - `scripts/bench_compare_libcrux.sh`
    - `scripts/bench_compare_libjade.sh`
    - `scripts/bench_compare_openssl_mlkem.sh`
  - Enhanced repeated suite driver:
    - `scripts/bench_compare_all_stats.sh`
    - new `LOCAL_BENCH_REUSE=0|1` (default `1`)
    - when enabled and not externally skipping local build, all-stats now
      builds local `benchc` once and reuses it for all comparator runs.
    - prints effective:
      - `local_bench_reuse`
      - `skip_local_build`
      - `local_bench_bin`
  - Updated `README.md`:
    - comparator-level `SKIP_LOCAL_BUILD`/`LOCAL_BENCH_BIN` usage
    - all-stats `LOCAL_BENCH_REUSE` behavior.
- Why:
  - avoid redundant local rebuilds during multi-competitor sweeps.
  - keep local binary fixed across a repeated suite to make flag-tuning
    iterations faster and easier to reproduce.
- Verification:
  - Syntax:
    - `bash -n scripts/bench_compare_all_stats.sh`
    - `bash -n scripts/bench_compare_{pqclean,liboqs,mlkem_native,boringssl,botan_mlkem,libcrux,libjade,openssl_mlkem}.sh`
  - Smoke (reuse path):
    - `make clean && make bench CC=clang`
    - `PIN_CPU=0 C_COMPILER=clang SKIP_LOCAL_BUILD=1 LOCAL_BENCH_BIN=./benchc WARMUP_RUNS=0 STATS_MODE=median ./scripts/bench_compare_all_stats.sh 20 1`
    - all labels completed and parsed.
  - Smoke (new default all-stats behavior):
    - `PIN_CPU=0 C_COMPILER=clang WARMUP_RUNS=0 STATS_MODE=median LOCAL_BENCH_REUSE=1 ./scripts/bench_compare_all_stats.sh 20 1`
    - log includes:
      - `[all-stats] building local benchmark once for reuse`
      - `skip_local_build=1`
  - Gate check:
    - `PIN_CPU=0 C_COMPILER=clang SHOW_FULL_OUTPUT_ON_FAIL=0 ./scripts/verify_world_fastest.sh 2000 3`
    - `verify_world_fastest=PASS`
    - `kyber_upstream_avx2=1.009x`
    - `kyber_upstream_avx2_fair=1.011x`

### Update: harden-fastest-verifier (same date)

- Change:
  - Updated `scripts/verify_world_fastest.sh` with:
    - per-label minimum threshold overrides:
      - `MIN_SPEEDUP_<LABEL>` (uppercased label, non-alnum -> `_`)
    - controlled retry support for noisy labels:
      - `MAX_RETRIES` (default `1`)
      - `RETRY_LABELS` (default `kyber_upstream_avx2_fair`)
    - optional fail-log verbosity:
      - `SHOW_FULL_OUTPUT_ON_FAIL=0|1` (default `1`)
    - richer fail diagnostics:
      - `failed_labels=...`
      - `best_speedups_seen` table with attempt index.
  - Updated `README.md` verifier section with examples for
    per-label threshold and retry knobs.
- Why:
  - reduce false negatives from short/noisy runs while preserving strict
    per-label pass/fail semantics.
- Verification:
  - Syntax:
    - `bash -n scripts/verify_world_fastest.sh`
  - Smoke pass:
    - `PIN_CPU=0 C_COMPILER=clang SHOW_FULL_OUTPUT_ON_FAIL=0 ./scripts/verify_world_fastest.sh 20 1`
    - result: `verify_world_fastest=PASS`.
  - Forced retry-path check:
    - `PIN_CPU=0 C_COMPILER=clang WARMUP_RUNS=0 MIN_SPEEDUP=0 MIN_SPEEDUP_KYBER_UPSTREAM_AVX2_FAIR=999 MAX_RETRIES=1 RETRY_LABELS=kyber_upstream_avx2_fair SHOW_FULL_OUTPUT_ON_FAIL=0 ./scripts/verify_world_fastest.sh 5 1`
    - result:
      - attempt `1/2`: fair label failed -> retry triggered
      - attempt `2/2`: fair label failed -> final `FAIL` with best-speedup table.

### Update: mlkem-native-ct-stride-fairness (same date)

- Change:
  - Updated `scripts/bench_compare_mlkem_native.sh` harness to use exact
    ciphertext stride for prepared decapsulation vectors:
    - from `max(CRYPTO_CIPHERTEXTBYTES, 4096)`
    - to `CRYPTO_CIPHERTEXTBYTES`
- Why:
  - Large fixed stride can bias cache behavior against the competitor.
  - Exact ciphertext stride better matches realistic contiguous KEM batches and
    aligns fairness with local benchmark configuration.
  - Verification:
  - Syntax:
    - `bash -n scripts/bench_compare_mlkem_native.sh`

### Update: bench-ct-stack-rightsize (same date)

- Change:
  - Updated `bench.c` to use exact ciphertext-byte stack sizing for the
    hot-path temporary:
    - added `CT_MAX_BYTES = K * ((N * DU) / 8) + (N * DV) / 8`
    - changed `ct` from fixed `4096` bytes to `ct[CT_MAX_BYTES]`
  - Kept `BENCH_CT_STRIDE` behavior for decapsulation vector storage
    unchanged (still default `1088`, clamped to `ct_bytes`).
- Why:
  - remove avoidable stack footprint mismatch versus comparator harnesses
    that already use exact ciphertext byte length.
  - reduce measurement-side noise from oversized scratch buffers in tight
    roundtrip loops.
- Verification:
  - Fair single-shot check:
    - `PIN_CPU=0 C_COMPILER=clang UPSTREAM_CFLAGS='-O3 -fno-semantic-interposition -fvisibility=hidden -march=native -mavx2 -mbmi2 -mpopcnt -fomit-frame-pointer -fno-stack-protector -falign-loops=64 -fno-unwind-tables -fno-asynchronous-unwind-tables -std=c99' ./scripts/bench_compare_kyber_upstream.sh 2000`
    - sample result:
      - local `mlkem_roundtrip_ns_per_op=15905.91`
      - competitor `kyber_avx2_roundtrip_ns_per_op=16170.24`
      - `local_vs_upstream_kyber_avx2_speedup=1.017x`
  - Repeated suite check:
    - `PIN_CPU=0 C_COMPILER=clang WARMUP_RUNS=1 STATS_MODE=median ./scripts/bench_compare_all_stats.sh 2000 3`
    - `kyber_default=1.008x`
    - `kyber_fair=1.008x`
  - Gate check:
    - `PIN_CPU=0 C_COMPILER=clang SHOW_FULL_OUTPUT_ON_FAIL=0 ./scripts/verify_world_fastest.sh 2000 3`
    - `verify_world_fastest=PASS`
    - `kyber_upstream_avx2=1.018x`
    - `kyber_upstream_avx2_fair=1.010x`
  - Correctness:
    - `make test`: `OK`

### Update: add-gprof-profiling-script (same date)

- Change:
  - Added `scripts/profile_kyber_gprof.sh`.
  - Script behavior:
    - builds `benchc` with `-pg` profiling flags
    - runs benchmark (`PROFILE_BENCH_ITERS`, default from arg)
    - emits top flat-profile symbols and call graph excerpt
    - supports `PIN_CPU`, `C_COMPILER`, `AVX2_BACKEND`
    - supports artifact retention via `KEEP_PROFILE_ARTIFACTS=1`
  - Updated `README.md` with profiling usage.
- Why:
  - this host blocks `perf` (`perf_event_paranoid=4`), so perf-based hotspot
    analysis is unavailable.
  - `gprof` gives a repeatable fallback to drive further speed work with
    function-level evidence.
- Verification:
  - Syntax:
    - `bash -n scripts/profile_kyber_gprof.sh`
  - Smoke:
    - `PIN_CPU=0 C_COMPILER=clang AVX2_BACKEND=upstream PROFILE_BENCH_ITERS=800 ./scripts/profile_kyber_gprof.sh 800`
    - `PIN_CPU=0 C_COMPILER=clang AVX2_BACKEND=upstream PROFILE_BENCH_ITERS=300 KEEP_PROFILE_ARTIFACTS=1 ./scripts/profile_kyber_gprof.sh 300`
  - Observed hotspots:
    - `KeccakF1600_StatePermute`
    - `pqcrystals_kyber_fips202x4_avx2_KeccakP1600times4_PermuteAll_24rounds`
    - `pqcrystals_kyber768_avx2_gen_matrix` subtree dominates child work.
  - Direct smoke:
    - `PIN_CPU=0 C_COMPILER=clang ./scripts/bench_compare_mlkem_native.sh 100`
    - result:
      - `mlkem_roundtrip_ns_per_op=16078.99`
      - `mlkem_native_roundtrip_ns_per_op=26966.08`
      - `local_vs_mlkem_native_speedup=1.677x`
  - All-stats parsing compatibility:
    - `PIN_CPU=0 WARMUP_RUNS=0 C_COMPILER=clang ./scripts/bench_compare_all_stats.sh 20 1`
    - `mlkem_native` block parsed:
      - `local=15712.05`
      - `competitor=25738.65`
      - `local_speedup_vs_competitor=1.638x`

### Update: clang-default-fvisibility-adopted-and-revalidated (same date)

- Change:
  - Adopted `-fvisibility=hidden` in clang default optimization flags:
    - `Makefile` clang default `OPT_CFLAGS`
    - `scripts/bench_compare_all_stats.sh` effective clang default `OPT_CFLAGS`
  - Updated README clang default flag docs.
  - Added this candidate in `scripts/tune_flags_against_kyber.sh`.
- Why:
  - Repeated fair A/B and median matrix checks showed improved
    local-vs-upstream speed and lower local latency.
- Verification:
  - Fair A/B (`PIN_CPU=0`, `clang`, `2000` iters, `5` runs):
    - baseline `-O3 -fno-semantic-interposition`:
      - `mean_local=15963.32`
      - `mean_kyber=16152.96`
      - `mean_speedup=1.01188x`
    - candidate `... -fvisibility=hidden`:
      - `mean_local=15909.54`
      - `mean_kyber=16175.20`
      - `mean_speedup=1.01670x`
  - Median direct compare (`PIN_CPU=0`, `WARMUP_RUNS=1`,
    `STATS_MODE=median`, `clang`, `2000x2`):
    - baseline:
      - `kyber_default=1.002x`
      - `kyber_fair=1.006x`
      - `local_mean_ns=16045.48`
    - with `-fvisibility=hidden`:
      - `kyber_default=1.009x`
      - `kyber_fair=1.014x`
      - `local_mean_ns=15971.10`
  - Post-adoption smoke:
    - `PIN_CPU=0 C_COMPILER=clang ./scripts/bench_compare_kyber_upstream.sh 1000`
      - `local_vs_upstream_kyber_avx2_speedup=1.003x`
  - Post-adoption short matrix:
    - `PIN_CPU=0 WARMUP_RUNS=1 COMPILERS='clang' ./scripts/bench_compiler_matrix.sh 300 1`
      - `kyber_default=1.007x`
      - `kyber_fair=1.036x`
      - `local_mean_ns=15948.72`
  - Post-adoption robust median matrix:
    - `PIN_CPU=0 WARMUP_RUNS=1 STATS_MODE=median COMPILERS='clang' ./scripts/bench_compiler_matrix.sh 2000 3`
      - `kyber_default=1.012x`
      - `kyber_fair=1.009x`
      - `local_mean_ns=15976.03`
      - `vs_native=1.644x`
      - `vs_pqclean=1.276x`
      - `vs_liboqs=1.315x`
      - `vs_boringssl=3.341x`
      - `vs_libcrux=1.283x`
      - `vs_libjade=1.326x`
      - `vs_botan=8.471x`
      - `vs_openssl=2.955x`
  - Correctness:
    - `make test`: `OK`

### Update: liboqs-derand-comparator-mode (same date)

- Change:
  - Updated `scripts/bench_compare_liboqs.sh` benchmark harness to use
    liboqs derandomized APIs when available:
    - `OQS_KEM_keypair_derand`
    - `OQS_KEM_encaps_derand`
  - Added deterministic seed generation for derand paths.
  - Added output metadata:
    - `liboqs_mlkem768_derand_keypair`
    - `liboqs_mlkem768_derand_encaps`
    - seed lengths for both operations.
  - README updated to document derand mode behavior.
- Why:
  - Reduce RNG noise and align liboqs comparison conditions with deterministic
    local benchmarking.
- Verification:
  - Syntax:
    - `bash -n scripts/bench_compare_liboqs.sh`
  - Direct smoke:
    - `PIN_CPU=0 C_COMPILER=clang ./scripts/bench_compare_liboqs.sh 50`
    - result includes:
      - `liboqs_mlkem768_derand_keypair=1`
      - `liboqs_mlkem768_derand_encaps=1`
      - `liboqs_mlkem768_roundtrip_ns_per_op=23095.68`
      - `local_vs_liboqs_speedup=1.491x`
  - All-stats compatibility:
    - `PIN_CPU=0 WARMUP_RUNS=0 C_COMPILER=clang ./scripts/bench_compare_all_stats.sh 20 1`
    - `liboqs` block parsed successfully:
      - `local=15876.20`
      - `competitor=20629.55`
      - `local_speedup_vs_competitor=1.299x`

### Update: liboqs-derand-comparator-mode (same date)

- Change:
  - Updated `scripts/bench_compare_liboqs.sh` benchmark harness to use
    liboqs derandomized APIs when available:
    - `OQS_KEM_keypair_derand`
    - `OQS_KEM_encaps_derand`
  - Added deterministic seed generation (`fill_seed`) for derand paths.
  - Added output metadata:
    - `liboqs_mlkem768_derand_keypair`
    - `liboqs_mlkem768_derand_encaps`
    - seed lengths for both operations.
  - README updated to document derand mode behavior.
- Why:
  - Reduce RNG noise and align liboqs comparison conditions with local
    deterministic benchmarking style.
- Verification:
  - Syntax:
    - `bash -n scripts/bench_compare_liboqs.sh`
  - Direct smoke:
    - `PIN_CPU=0 C_COMPILER=clang ./scripts/bench_compare_liboqs.sh 50`
    - result includes:
      - `liboqs_mlkem768_derand_keypair=1`
      - `liboqs_mlkem768_derand_encaps=1`
      - `liboqs_mlkem768_roundtrip_ns_per_op=23095.68`
      - `local_vs_liboqs_speedup=1.491x`
  - All-stats compatibility:
    - `PIN_CPU=0 WARMUP_RUNS=0 C_COMPILER=clang ./scripts/bench_compare_all_stats.sh 20 1`
    - `liboqs` block parsed successfully:
      - `local=15876.20`
      - `competitor=20629.55`
      - `local_speedup_vs_competitor=1.299x`

### Update: clang-default-add-fvisibility-hidden (same date)

- Change:
  - Added `-fvisibility=hidden` to clang default optimization flags:
    - `Makefile` clang default `OPT_CFLAGS`
    - `scripts/bench_compare_all_stats.sh` effective clang defaults
  - Updated README clang default documentation.
  - Added this flag into clang candidate set in
    `scripts/tune_flags_against_kyber.sh`.
- Why:
  - Repeated fair A/B suggested a small but stable win on local-vs-upstream
    speed while keeping correctness unchanged.
- Verification:
  - Fair A/B (`PIN_CPU=0`, `clang`, `2000` iters, `5` runs):
    - baseline `-O3 -fno-semantic-interposition`:
      - `mean_local=15963.32`
      - `mean_kyber=16152.96`
      - `mean_speedup=1.01188x`
    - candidate `... -fvisibility=hidden`:
      - `mean_local=15909.54`
      - `mean_kyber=16175.20`
      - `mean_speedup=1.01670x`
  - Median direct comparison (`PIN_CPU=0`, `WARMUP_RUNS=1`,
    `STATS_MODE=median`, `clang`, `2000x2`):
    - baseline:
      - `kyber_default=1.002x`
      - `kyber_fair=1.006x`
      - `local_mean_ns=16045.48`
    - candidate:
      - `kyber_default=1.009x`
      - `kyber_fair=1.014x`
      - `local_mean_ns=15971.10`
  - Post-adoption smoke:
    - `PIN_CPU=0 C_COMPILER=clang ./scripts/bench_compare_kyber_upstream.sh 1000`
      - `mlkem_roundtrip_ns_per_op=16079.06`
      - `kyber_avx2_roundtrip_ns_per_op=16131.47`
      - `local_vs_upstream_kyber_avx2_speedup=1.003x`
  - Post-adoption matrix smoke:
    - `PIN_CPU=0 WARMUP_RUNS=1 COMPILERS='clang' ./scripts/bench_compiler_matrix.sh 300 1`
      - `kyber_default=1.007x`
      - `kyber_fair=1.036x`
      - `local_mean_ns=15948.72`
      - `vs_native=1.620x`
      - `vs_pqclean=1.234x`
      - `vs_liboqs=1.288x`
      - `vs_boringssl=3.283x`
      - `vs_libcrux=1.393x`
      - `vs_libjade=1.305x`
      - `vs_botan=8.470x`
      - `vs_openssl=2.920x`
  - Correctness:
    - `make test`: `OK`

### Update: bench-ct-stride-default-1088 (same date)

- Change:
  - Updated local benchmark ciphertext stride default:
    - `Makefile`: `BENCH_CT_STRIDE ?= 1088`
    - `bench.c`: fallback macro `#define BENCH_CT_STRIDE 1088`
  - Updated README benchmark description accordingly.
- Why:
  - Repeated fair A/B against upstream Kyber AVX2 showed smaller local latency
    and better speedup with stride equal to ML-KEM-768 ciphertext length.
- Verification:
  - Stride sweep (`PIN_CPU=0`, `C_COMPILER=clang`, `2000` iters, `5` runs each,
    local binary reused via `SKIP_LOCAL_BUILD=1`):
    - `stride=1088`: `mean_local=15935.47`, `mean_kyber=16130.03`,
      `mean_speedup=1.01221x`
    - `stride=1536`: `mean_local=16041.68`, `mean_speedup=1.00521x`
    - `stride=2048`: `mean_local=15988.47`, `mean_speedup=1.01001x`
    - `stride=4608`: `mean_local=16010.16`, `mean_speedup=1.00943x`
  - Post-adoption kyber check (`2000` iters, `5` runs):
    - `mean_local=16035.89`
    - `mean_kyber=16087.05`
    - `mean_speedup=1.00322x`
  - Post-adoption compiler matrix snapshot:
    - command:
      `PIN_CPU=0 WARMUP_RUNS=1 COMPILERS='clang' ./scripts/bench_compiler_matrix.sh 1000 2`
    - `clang`:
      - `kyber_default=1.059x`
      - `kyber_fair=1.006x`
      - `local_mean_ns=15911.19`
      - `vs_native=1.639x`
      - `vs_pqclean=1.280x`
      - `vs_liboqs=1.316x`
      - `vs_boringssl=3.364x`
      - `vs_libcrux=1.279x`
      - `vs_libjade=1.328x`
      - `vs_botan=8.512x`
      - `vs_openssl=3.002x`
  - Correctness:
    - `make test`: `OK`

### Update: botan-fallback-cache-stamp (same date)

- Change:
  - Improved `scripts/bench_compare_botan_mlkem.sh` fallback behavior:
    - caches failed auto-`clang++` attempts at
      `$BOTAN_DIR/.botan_clangpp_broken`
    - subsequent clang runs auto-select `g++` directly (no repeated failing
      clang++ build attempts)
    - added `BOTAN_RESET_AUTO_FALLBACK=1` to retry clang++ auto-selection.
  - Updated README documentation for this behavior.
- Why:
  - Without caching, repeated suite/matrix runs paid heavy repeated clang++
    failure cost, increasing runtime and thermal noise.
- Verification:
  - Syntax:
    - `bash -n scripts/bench_compare_botan_mlkem.sh`
  - First run after clearing stamp (forced configure):
    - command:
      `rm -f /tmp/botan-mlkem/.botan_clangpp_broken && PIN_CPU=0 C_COMPILER=clang BOTAN_FORCE_CONFIGURE=1 ./scripts/bench_compare_botan_mlkem.sh 20`
    - observed:
      - warning emitted (`clang++` failed, retrying with `g++`)
      - run completed (`local_vs_botan_speedup=9.031x`)
  - Subsequent forced configure run:
    - no fallback warning; starts with `botan_cxx=g++`
    - run completed (`local_vs_botan_speedup=9.166x`)
  - All-stats integration smoke with forced configure:
    - `PIN_CPU=0 WARMUP_RUNS=0 C_COMPILER=clang BOTAN_FORCE_CONFIGURE=1 ./scripts/bench_compare_all_stats.sh 20 1`
    - `botan_mlkem` block parsed; no repeated clang++ fallback warnings.

### Update: clang-median-audit-and-retune-scan (same date)

- Change:
  - No default flag change adopted in this round.
  - Performed median-based baseline audit and additional clang fair-flag scans.
- Why:
  - Need to confirm whether recent defaults still hold under robust aggregation,
    and whether any remaining low-risk compiler flags can raise `kyber_fair`.
- Verification / Findings:
  - Median compiler matrix audit (`PIN_CPU=0`, `WARMUP_RUNS=1`,
    `STATS_MODE=median`, `2000x3`, `COMPILERS='gcc clang'`):
    - `gcc`:
      - `kyber_default=1.031x`
      - `kyber_fair=1.008x`
      - `local_mean_ns=16823.89`
      - `vs_botan=8.075x`
    - `clang`:
      - `kyber_default=1.007x`
      - `kyber_fair=0.996x`
      - `local_mean_ns=16004.11`
      - `vs_botan=8.486x`
  - Clang `OPT_CFLAGS` candidate scan against fair kyber (`2000x3`):
    - baseline `-O3 -fno-semantic-interposition`:
      - `mean_local=16003.89`
      - `mean_speedup=1.01126x`
    - `-O3 -flto ...`: `1.00484x` (worse)
    - `-O2 -flto ...`: `0.99870x` (worse)
    - `-Ofast -flto ...`: `1.00262x` (worse)
    - `-O3 ... -fno-plt`: `1.01099x` (near, but not better)
  - Extra-flag scan (`2000x5`):
    - baseline extra (`-fomit-frame-pointer ...`): `mean_speedup=1.00913x`
    - `+ -fno-unroll-loops`: `0.98962x` (regression)
    - `+ -fstrict-aliasing`: `1.00771x` (worse)
    - `+ -fno-strict-aliasing`: `1.01055x` (close, but lower confidence)
  - Full-matrix A/B for `-fno-strict-aliasing` (`clang`, `1000x2`):
    - baseline extra:
      - `kyber_default=1.015x`
      - `kyber_fair=1.009x`
      - `local_mean_ns=15862.65`
    - with `-fno-strict-aliasing`:
      - `kyber_default=1.009x`
      - `kyber_fair=1.006x`
      - `local_mean_ns=15929.38`
    - Decision: reject `-fno-strict-aliasing`.
  - Re-audit current default (`clang`, `STATS_MODE=median`, `2000x3`):
    - `kyber_default=1.008x`
    - `kyber_fair=1.006x`
    - `local_mean_ns=16061.17`
    - `vs_native=1.641x`
    - `vs_pqclean=1.269x`
    - `vs_liboqs=1.298x`
    - `vs_boringssl=3.336x`
    - `vs_libcrux=1.279x`
    - `vs_libjade=1.326x`
    - `vs_botan=8.482x`
    - `vs_openssl=2.986x`

### Update: tune-script-refresh-clang-profile (same date)

- Change:
  - Updated `scripts/tune_flags_against_kyber.sh` candidate sets to match
    current clang profile and recent hypotheses:
    - added clang-specific `OPT_CFLAGS`/`EXTRA_CFLAGS` sets
    - included candidates such as `-fno-plt`, `-fno-slp-vectorize`,
      `-fno-vectorize`, `-fno-strict-aliasing`
  - Added `WARMUP_RUNS` support (default `1`) before measured runs.
  - Ensured cleanup uses `CC=$C_COMPILER` for consistency.
  - Updated README tuning section with `WARMUP_RUNS` usage.
- Why:
  - Existing tuning grid was biased toward older flag profiles and had no
    warmup phase, making exploration noisier than needed.
- Verification:
  - Syntax:
    - `bash -n scripts/tune_flags_against_kyber.sh`
  - Smoke:
    - `PIN_CPU=0 WARMUP_RUNS=0 C_COMPILER=clang ./scripts/tune_flags_against_kyber.sh 20 1`
    - run completed and produced ranked output.

### Update: clang-fvisibility-hidden-scan (same date)

- Change:
  - No default adoption in this round.
  - Added `-fvisibility=hidden` as a clang `OPT_CFLAGS` candidate in
    `scripts/tune_flags_against_kyber.sh` for future sweeps.
- Why:
  - Fair A/B suggested a possible small win; needed matrix-level confirmation
    before changing defaults.
- Verification / Findings:
  - Direct fair A/B (`clang`, `2000x5`, matching upstream flags):
    - baseline `-O3 -fno-semantic-interposition`:
      - `mean_local=15963.32`
      - `mean_kyber=16152.96`
      - `mean_speedup=1.01188x`
    - candidate `... -fvisibility=hidden`:
      - `mean_local=15909.54`
      - `mean_kyber=16175.20`
      - `mean_speedup=1.01670x`
  - Matrix comparison (`PIN_CPU=0`, `WARMUP_RUNS=1`, `clang`, `1000x2`):
    - baseline:
      - `kyber_default=1.010x`
      - `kyber_fair=1.011x`
      - `local_mean_ns=15890.75`
      - `vs_openssl=2.990x`
    - candidate:
      - `kyber_default=1.008x`
      - `kyber_fair=1.006x`
      - `local_mean_ns=15884.47`
      - `vs_openssl=3.082x`
  - Decision:
    - reject as new default for now (matrix signal mixed / too small).

### Update: tune-script-cooldown-controls (same date)

- Change:
  - Added cooldown controls to `scripts/tune_flags_against_kyber.sh`:
    - `SLEEP_BETWEEN_RUNS` (default `0`)
    - `SLEEP_BETWEEN_COMBOS` (default `0`)
  - Added input validation for both values.
  - Documented usage in README.
- Why:
  - Longer flag sweeps exhibited thermal/frequency drift and occasional
    outlier spikes; cooldown knobs allow stabilizing measurements on hot hosts.
- Verification:
  - Syntax:
    - `bash -n scripts/tune_flags_against_kyber.sh`
  - Smoke:
    - `PIN_CPU=0 WARMUP_RUNS=0 SLEEP_BETWEEN_RUNS=0.01 SLEEP_BETWEEN_COMBOS=0.01 C_COMPILER=clang ./scripts/tune_flags_against_kyber.sh 10 1`
    - run completed and produced ranked output.

### Update: botan-compiler-auto-fallback (same date)

- Change:
  - Improved `scripts/bench_compare_botan_mlkem.sh` compiler selection:
    - default `BOTAN_CXX` now follows local compiler intent
      (`clang++` when `C_COMPILER=clang`, else `g++`)
    - automatic fallback to `g++` when Botan build fails under `clang++`
      (unless `BOTAN_CXX`/`BOTAN_CC_FAMILY` are explicitly pinned)
    - failed build logs are now captured to temp log files and only tailed on
      final failure (prevents massive stdout spam in suites).
  - Added README documentation for this behavior.
- Why:
  - On this host, `clang++` Botan builds fail due missing C++ stdlib headers
    (`'cstddef' file not found`); without fallback, clang-based runs were brittle.
- Verification:
  - Syntax:
    - `bash -n scripts/bench_compare_botan_mlkem.sh`
  - Fallback behavior check:
    - `PIN_CPU=0 C_COMPILER=clang BOTAN_FORCE_CONFIGURE=1 ./scripts/bench_compare_botan_mlkem.sh 20`
    - observed:
      - warning emitted: retry with `BOTAN_CXX='g++'`
      - fallback build dir shown
      - run completed with benchmark output
      - `local_vs_botan_speedup=8.048x`

### Update: clang-default-drop-unroll (same date)

- Change:
  - Removed `-funroll-loops` from clang default extra flags:
    - `Makefile` clang default `EXTRA_CFLAGS`
    - `scripts/bench_compare_all_stats.sh` effective clang defaults
  - Updated README clang default flag documentation.
- Why:
  - Fresh fair A/B on current baseline showed better local latency and
    better local-vs-upstream speedup without forced loop unrolling.
- Verification:
  - Fair A/B (`PIN_CPU=0`, `C_COMPILER=clang`, `2000` iters, `5` runs):
    - with unroll:
      - `mean_local=15995.38 ns/op`
      - `mean_kyber=16110.31 ns/op`
      - `mean_speedup=1.0072x`
    - without unroll:
      - `mean_local=15985.20 ns/op`
      - `mean_kyber=16164.04 ns/op`
      - `mean_speedup=1.0112x`
  - Matrix spot check with explicit flags (`PIN_CPU=0`, `WARMUP_RUNS=1`,
    `300x1`, `COMPILERS='clang'`):
    - unroll profile:
      - `kyber_default=0.991x`
      - `kyber_fair=0.926x`
      - `local_mean_ns=16107.37`
      - `vs_botan=8.374x`
    - no-unroll profile:
      - `kyber_default=1.019x`
      - `kyber_fair=1.009x`
      - `local_mean_ns=15924.45`
      - `vs_botan=8.681x`
  - Post-adoption default matrix smoke
    (`PIN_CPU=0`, `WARMUP_RUNS=1`, `300x1`, `COMPILERS='clang'`):
    - `kyber_default=1.002x`
    - `kyber_fair=1.000x`
    - `local_mean_ns=15963.73`
    - `vs_native=1.614x`
    - `vs_pqclean=1.253x`
    - `vs_liboqs=1.233x`
    - `vs_boringssl=3.316x`
    - `vs_libcrux=1.403x`
    - `vs_libjade=1.303x`
    - `vs_botan=8.458x`
    - `vs_openssl=2.957x`
  - Correctness:
    - `make test`: `OK`
- Benchmark evidence:
  - clang before fix/tune (3-run all-stats snapshot):
    - around `kyber_default=0.990x`, `kyber_fair=0.996x`.
  - clang after fix+tune (3-run all-stats):
    - `kyber_default=1.011x`
    - `kyber_fair=1.046x`
  - Updated compiler matrix (`PIN_CPU=0`, `2000x3`):
    - `gcc`:
      - `kyber_default=1.031x`
      - `kyber_fair=1.008x`
      - `local_mean_ns=16867.31`
      - `vs_native=1.563x`
      - `vs_pqclean=1.243x`
      - `vs_liboqs=1.252x`
    - `clang`:
      - `kyber_default=1.009x`
      - `kyber_fair=1.008x`
      - `local_mean_ns=16073.01`
      - `vs_native=1.640x`
      - `vs_pqclean=1.278x`
      - `vs_liboqs=1.326x`
- Additional notes:
  - `UPDATE_REPOS=1` runs still show occasional higher variance in fair mode
    (especially when comparator checkouts refresh and include one-time build/cache effects),
    so claim should continue to rely on repeated pinned measurements.

### Update: backend-regression-check-locking-and-clang-o3 (same date)

- Change:
  - Added shared benchmark lock support to comparator scripts to prevent
    concurrent local rebuild/run races:
    - `scripts/bench_compare_kyber_upstream.sh`
    - `scripts/bench_compare_pqclean.sh`
    - `scripts/bench_compare_liboqs.sh`
    - `scripts/bench_compare_mlkem_native.sh`
  - Lock details:
    - uses `flock` on `${BENCH_LOCK_FILE:-$ROOT_DIR/.bench-compare.lock}`
    - prints `waiting_for_bench_lock=...` when contention occurs
    - falls back with warning if `flock` is unavailable
  - Added `.bench-compare.lock` to `.gitignore`.
  - Retuned clang default optimization flag in `Makefile`:
    - from `-Ofast -fno-semantic-interposition`
    - to   `-O3 -fno-semantic-interposition`
  - Updated `scripts/bench_compare_all_stats.sh` effective clang default to the
    same `-O3` setting for fair-upstream flag derivation.
  - Updated `README.md` with lock behavior and new clang default.
- Why:
  - Concurrent comparator runs can clobber shared local build artifacts and
    produce invalid comparisons.
  - A focused clang sweep found `-O3` slightly faster than current `-Ofast`
    on local roundtrip mean for this host.
- Verification:
  - Syntax:
    - `bash -n scripts/bench_compare_kyber_upstream.sh`
    - `bash -n scripts/bench_compare_pqclean.sh`
    - `bash -n scripts/bench_compare_liboqs.sh`
    - `bash -n scripts/bench_compare_mlkem_native.sh`
  - Lock behavior:
    - Started two comparator scripts in parallel and confirmed one waited on
      `.bench-compare.lock`, then completed successfully.
- Benchmark evidence:
  - Backend choice check (`PIN_CPU=0`, `C_COMPILER=gcc`, `2000x3`):
    - local `AVX2_BACKEND=upstream`:
      - vs kyber default `1.034x`
      - vs kyber fair `1.009x`
      - local mean around `16868 ns/op`
    - local `AVX2_BACKEND=pqclean`:
      - vs kyber default `0.987x`
      - vs kyber fair `0.962x`
      - local mean around `17662 ns/op`
    - decision: keep `AVX2_BACKEND=upstream` default.
  - Backend choice check (`PIN_CPU=0`, `C_COMPILER=clang`, `2000x3`):
    - local `AVX2_BACKEND=upstream`:
      - vs kyber default `1.002x`
      - vs kyber fair `1.013x`
      - local mean around `16134 ns/op`
    - local `AVX2_BACKEND=pqclean`:
      - vs kyber default `0.961x`
      - vs kyber fair `0.965x`
      - local mean around `16823 ns/op`
    - decision: keep `AVX2_BACKEND=upstream` default.
  - Clang focused flag sweep (20 combos, each `2000` iterations x `3` runs,
    local prebuilt + upstream default comparator):
    - best local mean:
      - `OPT=-O3 -fno-semantic-interposition`
      - `EXTRA=-funroll-loops -fomit-frame-pointer -fno-stack-protector -falign-loops=64`
      - local mean `15963.38 ns/op`
      - kyber mean `16143.68 ns/op`
      - speedup `1.011x`
  - Full repeated clang suite after adopting `-O3` default (`PIN_CPU=0`,
    `C_COMPILER=clang`, `2000x3`, `WARMUP_RUNS=1`):
    - vs kyber default: `1.000x`
    - vs kyber fair: `1.010x`
    - local mean (`kyber_default` suite): `16130.31 ns/op`
- Build contamination fix verification:
  - Before cleanup-on-exit, switching compilers in comparator runs could leave
    incompatible objects (e.g. clang LTO object files) that later broke
    `make test` with gcc unless manual `make clean` was run.
  - After cleanup-on-exit patch:
    - `make clean && make test` passed
    - `PIN_CPU=0 C_COMPILER=clang ./scripts/bench_compare_kyber_upstream.sh 200`
      passed
    - immediate `make test` (without manual clean) passed
    - decision: keep cleanup-on-exit enabled by default.
- Updated compiler matrix after these changes (`PIN_CPU=0`, `2000x3`,
  `COMPILERS='gcc clang'`):
  - `gcc`:
    - `kyber_default=1.035x`
    - `kyber_fair=1.005x`
    - `local_mean_ns=16878.52`
    - `vs_native=1.561x`
    - `vs_pqclean=1.244x`
    - `vs_liboqs=1.253x`
  - `clang`:
    - `kyber_default=1.011x`
    - `kyber_fair=1.012x`
    - `local_mean_ns=16056.26`
    - `vs_native=1.638x`
    - `vs_pqclean=1.277x`
    - `vs_liboqs=1.332x`

### Update: auto-clang-default-and-followup-retunes (same date)

- Completion-audit context:
  - Thread goal references `AGENT.md`, but no `AGENT.md` exists in this repo.
    Work continued using measurable objective evidence in this repo (`plan.md`,
    benchmark scripts, and recorded competitor comparisons).
- Change:
  - Updated `Makefile` compiler default behavior:
    - if `CC` is not user-specified and `clang` exists, default `CC=clang`
    - otherwise fallback to `CC=gcc`
    - explicit overrides still work (`CC=... make ...`).
  - Updated comparator/tuning scripts to mirror the same default selection for
    `C_COMPILER` when unset:
    - `scripts/bench_compare_kyber_upstream.sh`
    - `scripts/bench_compare_pqclean.sh`
    - `scripts/bench_compare_liboqs.sh`
    - `scripts/bench_compare_mlkem_native.sh`
    - `scripts/bench_compare_all_stats.sh`
    - `scripts/tune_flags_against_kyber.sh`
  - Updated `README.md` with the new default-compiler behavior.
- Verification:
  - Syntax:
    - `bash -n` passed for all modified scripts.
  - Correctness:
    - `make test` passed with auto-selected default compiler.
    - `make test CC=gcc` also passed (override preserved).
  - Comparator smoke:
    - `PIN_CPU=0 ./scripts/bench_compare_kyber_upstream.sh 200`
      reports `c_compiler=clang` when `C_COMPILER` unset.
    - `./scripts/bench_compare_all_stats.sh` metadata reports
      `C_COMPILER=clang` when unset.
- Benchmark evidence (unset `C_COMPILER`, auto compiler path):
  - Command:
    - `PIN_CPU=0 WARMUP_RUNS=1 ./scripts/bench_compare_all_stats.sh 2000 3`
  - Result:
    - selected compiler: `clang`
    - vs upstream Kyber AVX2 default: `1.020x`
    - vs upstream Kyber AVX2 fair: `1.006x`
    - vs mlkem-native: `1.645x`
    - vs PQClean AVX2: `1.270x`
    - vs liboqs: `1.329x`
    - local mean (`kyber_default` suite): `16036.24 ns/op`
- Additional retune outcomes in this pass:
  - `gcc` retune reruns:
    - no robust improvement over current default (`-O2 -flto` + current extras)
      across full-suite comparisons; candidate flags showed suite-dependent
      regressions and were rejected.
  - `BENCH_CT_STRIDE` rerun:
    - `3072` showed occasional local-win signals, but full compiler-matrix run
      reduced `clang` `kyber_default` speedup versus current default path.
    - decision: keep current default stride (4096).

### Update: boringssl-competitor-integration (same date)

- Change:
  - Added BoringSSL comparator script:
    - `scripts/bench_compare_boringssl.sh`
  - Integrated BoringSSL into repeated-suite stats:
    - updated `scripts/bench_compare_all_stats.sh`
    - added competitor label `boringssl`
    - parser now reads `boringssl_mlkem768_roundtrip_ns_per_op`
  - Integrated BoringSSL into compiler matrix output:
    - updated `scripts/bench_compiler_matrix.sh`
    - added `vs_boringssl` column.
  - Updated `README.md`:
    - usage/examples for `bench_compare_boringssl.sh`
    - all-stats scope now explicitly includes BoringSSL
    - compiler-matrix output now documents `vs_boringssl`.
- Verification:
  - Syntax:
    - `bash -n scripts/bench_compare_boringssl.sh`
    - `bash -n scripts/bench_compare_all_stats.sh`
    - `bash -n scripts/bench_compiler_matrix.sh`
  - Smoke:
    - `C_COMPILER=clang ./scripts/bench_compare_boringssl.sh 100`
    - result: `local_vs_boringssl_speedup=3.366x`
- Benchmark evidence:
  - Repeated all-competitor suite with BoringSSL (`PIN_CPU=0`, `C_COMPILER=clang`,
    `WARMUP_RUNS=1`, `2000x3`):
    - `kyber_default`: `0.986x`
    - `kyber_fair`: `1.006x`
    - `vs_native`: `1.639x`
    - `vs_pqclean`: `1.324x`
    - `vs_liboqs`: `1.322x`
    - `vs_boringssl`: `3.341x`
    - local mean (`kyber_default` suite): `16417.50 ns/op`
  - Compiler matrix with BoringSSL (`PIN_CPU=0`, `WARMUP_RUNS=1`, `2000x3`,
    `COMPILERS='gcc clang'`):
    - `gcc`:
      - `kyber_default=1.033x`
      - `kyber_fair=1.013x`
      - `local_mean_ns=16856.83`
      - `vs_native=1.560x`
      - `vs_pqclean=1.287x`
      - `vs_liboqs=1.253x`
      - `vs_boringssl=3.593x`
    - `clang`:
      - `kyber_default=1.005x`
      - `kyber_fair=1.006x`
      - `local_mean_ns=16123.04`
      - `vs_native=1.641x`
      - `vs_pqclean=1.266x`
      - `vs_liboqs=1.322x`
      - `vs_boringssl=3.335x`
  - Interpretation:
  - BoringSSL coverage is now in the standard comparison pipeline.
  - Current strongest balanced claim remains compiler/flag sensitive:
    - `gcc` retains stronger margin vs upstream Kyber AVX2 on this host.
    - `clang` keeps better absolute local mean and larger margins vs
      `mlkem-native`, `liboqs`, and BoringSSL.

### Update: bench-ct-stride-4608-default (same date)

- Change:
  - Updated benchmark stride default:
    - `Makefile`: added `BENCH_CT_STRIDE ?= 4608`
    - `Makefile`: `bench.o` now receives
      `-DBENCH_CT_STRIDE=$(BENCH_CT_STRIDE)` explicitly.
    - `bench.c`: fallback default changed from `4096` to `4608`.
  - Updated `README.md` with `BENCH_CT_STRIDE` usage and default.
- Why:
  - Focused stride sweep showed consistent local-roundtrip improvements around
    `4608` vs `4096` on this host.
- Verification:
  - `make test`: passed.
  - `make bench` + `./benchc 200`: runs successfully with new default.
- Benchmark evidence:
  - Clang all-stats A/B (`PIN_CPU=0`, `WARMUP_RUNS=1`, `2000x3`):
    - `4096`:
      - local mean (`kyber_default` suite): `16001.30 ns/op`
      - `kyber_default`: `1.016x`
      - `kyber_fair`: `0.993x`
    - `4608`:
      - local mean (`kyber_default` suite): `15984.81 ns/op`
      - `kyber_default`: `1.012x`
      - `kyber_fair`: `1.005x`
  - GCC all-stats A/B (`PIN_CPU=0`, `WARMUP_RUNS=1`, `2000x3`):
    - `4096`:
      - local mean (`kyber_default` suite): `16956.43 ns/op`
      - `kyber_default`: `1.027x`
      - `kyber_fair`: `1.005x`
    - `4608`:
      - local mean (`kyber_default` suite): `16867.83 ns/op`
      - `kyber_default`: `1.032x`
      - `kyber_fair`: `1.008x`
  - Updated compiler matrix after default switch (`PIN_CPU=0`,
    `WARMUP_RUNS=1`, `2000x3`, `COMPILERS='gcc clang'`):
    - `gcc`:
      - `kyber_default=1.033x`
      - `kyber_fair=1.008x`
      - `local_mean_ns=16842.67`
      - `vs_native=1.564x`
      - `vs_pqclean=1.241x`
      - `vs_liboqs=1.249x`
      - `vs_boringssl=3.593x`
    - `clang`:
      - `kyber_default=1.010x`
      - `kyber_fair=1.012x`
      - `local_mean_ns=16010.60`
      - `vs_native=1.643x`
      - `vs_pqclean=1.275x`
      - `vs_liboqs=1.325x`
      - `vs_boringssl=3.342x`

### Update: libcrux-rust-competitor-integration (same date)

- Change:
  - Added Rust `libcrux-ml-kem` comparator:
    - `scripts/bench_compare_libcrux.sh`
  - Comparator details:
    - builds a dedicated Rust harness (`libcrux_mlkem_bench`) under
      `/tmp/libcrux-mlkem-bench`
    - crate version configurable via `LIBCRUX_CRATE_VERSION`
      (default `0.0.8`)
    - release profile uses `lto=fat`, `codegen-units=1`, `panic=abort`
    - default `RUSTFLAGS` include `-C target-cpu=native`
    - uses `mlkem768::avx2::{generate_key_pair, encapsulate, decapsulate}`.
  - Integrated new competitor into:
    - `scripts/bench_compare_all_stats.sh` as `libcrux_rust`
    - `scripts/bench_compiler_matrix.sh` as `vs_libcrux` column
  - Updated `README.md` with new comparator usage/examples.
- Verification:
  - Syntax:
    - `bash -n scripts/bench_compare_libcrux.sh`
    - `bash -n scripts/bench_compare_all_stats.sh`
    - `bash -n scripts/bench_compiler_matrix.sh`
  - Smoke:
    - `C_COMPILER=clang PIN_CPU=0 ./scripts/bench_compare_libcrux.sh 200`
    - result: `local_vs_libcrux_speedup=1.303x`
- Benchmark evidence:
  - Full all-competitor suite including libcrux (`PIN_CPU=0`, `C_COMPILER=clang`,
    `WARMUP_RUNS=1`, `2000x3`):
    - `kyber_default`: `1.002x`
    - `kyber_fair`: `1.007x`
    - `vs_native`: `1.645x`
    - `vs_pqclean`: `1.279x`
    - `vs_liboqs`: `1.327x`
    - `vs_boringssl`: `3.338x`
    - `vs_libcrux`: `1.284x`
    - local mean (`kyber_default` suite): `16083.99 ns/op`
  - Updated compiler matrix with libcrux (`PIN_CPU=0`, `WARMUP_RUNS=1`,
    `2000x3`, `COMPILERS='gcc clang'`):
    - `gcc`:
      - `kyber_default=1.032x`
      - `kyber_fair=1.010x`
      - `local_mean_ns=16837.57`
      - `vs_native=1.565x`
      - `vs_pqclean=1.243x`
      - `vs_liboqs=1.240x`
      - `vs_boringssl=3.593x`
      - `vs_libcrux=1.218x`
    - `clang`:
      - `kyber_default=0.999x`
      - `kyber_fair=1.010x`
      - `local_mean_ns=16144.39`
      - `vs_native=1.647x`
      - `vs_pqclean=1.275x`
      - `vs_liboqs=1.319x`
      - `vs_boringssl=3.310x`
      - `vs_libcrux=1.293x`

### Update: openssl-mlkem-competitor-integration (same date)

- Change:
  - Added OpenSSL ML-KEM-768 comparator:
    - `scripts/bench_compare_openssl_mlkem.sh`
  - Comparator details:
    - clones/builds OpenSSL (default `github.com/openssl/openssl`) into a
      compiler-specific checkout (`/tmp/openssl-mlkem-<compiler>`)
    - builds static `libcrypto.a` with configurable target/flags
    - runs a dedicated benchmark harness using OpenSSL EVP KEM APIs
    - uses deterministic ML-KEM keygen seed
      (`OSSL_PKEY_PARAM_ML_KEM_SEED`) and deterministic encapsulation entropy
      (`OSSL_KEM_PARAM_IKME`) for repeatable measurements.
  - Integrated new competitor into:
    - `scripts/bench_compare_all_stats.sh` as `openssl_mlkem`
    - `scripts/bench_compiler_matrix.sh` as `vs_openssl` column
  - Updated `README.md` with comparator usage/examples.
- Verification:
  - Syntax:
    - `bash -n scripts/bench_compare_openssl_mlkem.sh`
    - `bash -n scripts/bench_compare_all_stats.sh`
    - `bash -n scripts/bench_compiler_matrix.sh`
  - Smoke:
    - `C_COMPILER=clang PIN_CPU=0 ./scripts/bench_compare_openssl_mlkem.sh 100`
    - result: `local_vs_openssl_speedup=2.969x`
  - Correctness:
    - `make test`: `OK`
- Benchmark evidence:
  - Full all-competitor suite including OpenSSL (`PIN_CPU=0`, `C_COMPILER=clang`,
    `WARMUP_RUNS=1`, `2000x3`):
    - `kyber_default`: `1.002x`
    - `kyber_fair`: `1.011x`
    - `vs_native`: `1.648x`
    - `vs_pqclean`: `1.273x`
    - `vs_liboqs`: `1.327x`
    - `vs_boringssl`: `3.342x`
    - `vs_libcrux`: `1.274x`
    - `vs_openssl`: `2.963x`
    - local mean (`kyber_default` suite): `16070.34 ns/op`
  - Updated compiler matrix with OpenSSL (`PIN_CPU=0`, `WARMUP_RUNS=1`,
    `2000x3`, `COMPILERS='gcc clang'`):
    - `gcc`:
      - `kyber_default=1.029x`
      - `kyber_fair=0.974x`
      - `local_mean_ns=16887.94`
      - `vs_native=1.551x`
      - `vs_pqclean=1.241x`
      - `vs_liboqs=1.250x`
      - `vs_boringssl=3.591x`
      - `vs_libcrux=1.221x`
      - `vs_openssl=3.079x`
    - `clang`:
      - `kyber_default=1.006x`
      - `kyber_fair=1.055x`
      - `local_mean_ns=16092.73`
      - `vs_native=1.651x`
      - `vs_pqclean=1.268x`
      - `vs_liboqs=1.323x`
      - `vs_boringssl=3.331x`
      - `vs_libcrux=1.285x`
      - `vs_openssl=2.983x`

### Update: gcc-extra-finline-default (same date)

- Change:
  - Updated gcc-side default extra flags to include `-finline-functions`:
    - `Makefile`: default `EXTRA_CFLAGS` now includes `-finline-functions`
    - `scripts/bench_compare_all_stats.sh`: effective gcc default extra flags
      updated to match (`... -falign-loops=32 -finline-functions`).
  - Updated `README.md` to document the gcc default extra flags.
- Why:
  - Retune sweep and all-stats A/B showed small but repeatable local mean
    reduction and slightly better kyber default/fair speedups with
    `-finline-functions` on gcc.
- Verification:
  - Syntax:
    - `bash -n scripts/bench_compare_all_stats.sh`
  - Correctness:
    - `make test`: `OK`
- Benchmark evidence:
  - GCC all-stats A/B (`PIN_CPU=0`, `WARMUP_RUNS=1`, `2000x3`):
    - current defaults (before update):
      - local mean (`kyber_default` suite): `16887.84 ns/op`
      - `kyber_default`: `1.029x`
      - `kyber_fair`: `1.009x`
    - with `-finline-functions`:
      - local mean (`kyber_default` suite): `16870.14 ns/op`
      - `kyber_default`: `1.030x`
      - `kyber_fair`: `1.011x`
  - Updated compiler matrix after default switch (`PIN_CPU=0`,
    `WARMUP_RUNS=1`, `2000x3`, `COMPILERS='gcc clang'`):
    - `gcc`:
      - `kyber_default=1.034x`
      - `kyber_fair=1.008x`
      - `local_mean_ns=16831.24`
      - `vs_native=1.559x`
      - `vs_pqclean=1.241x`
      - `vs_liboqs=1.215x`
      - `vs_boringssl=3.593x`
      - `vs_libcrux=1.219x`
      - `vs_openssl=3.070x`
    - `clang`:
      - `kyber_default=1.011x`
      - `kyber_fair=1.009x`
      - `local_mean_ns=16029.75`
      - `vs_native=1.688x`
      - `vs_pqclean=1.265x`
      - `vs_liboqs=1.327x`
      - `vs_boringssl=3.306x`
      - `vs_libcrux=1.291x`
      - `vs_openssl=2.980x`

### Update: clang-extra-finline-default (same date)

- Change:
  - Updated clang-side default extra flags to include `-finline-functions`:
    - `Makefile`: clang default `EXTRA_CFLAGS` now includes
      `-finline-functions`.
    - `scripts/bench_compare_all_stats.sh`: effective clang default extra
      flags updated to match (`... -falign-loops=64 -finline-functions`).
  - Updated `README.md` clang default flag documentation.
- Why:
  - Clang A/B all-stats comparison showed lower local mean with
    `-finline-functions` while keeping both `kyber_default` and `kyber_fair`
    speedups above `1.0x`.
- Verification:
  - Syntax:
    - `bash -n scripts/bench_compare_all_stats.sh`
  - Correctness:
    - `make test`: `OK`
- Benchmark evidence:
  - Clang all-stats A/B (`PIN_CPU=0`, `WARMUP_RUNS=1`, `2000x3`):
    - current defaults (before update):
      - local mean (`kyber_default` suite): `16061.03 ns/op`
      - `kyber_default`: `1.006x`
      - `kyber_fair`: `1.013x`
    - with `-finline-functions`:
      - local mean (`kyber_default` suite): `15997.39 ns/op`
      - `kyber_default`: `1.009x`
      - `kyber_fair`: `1.009x`
  - Updated compiler matrix after default switch (`PIN_CPU=0`,
    `WARMUP_RUNS=1`, `2000x3`, `COMPILERS='gcc clang'`):
    - `gcc`:
      - `kyber_default=1.035x`
      - `kyber_fair=1.009x`
      - `local_mean_ns=16829.27`
      - `vs_native=1.567x`
      - `vs_pqclean=1.235x`
      - `vs_liboqs=1.214x`
      - `vs_boringssl=3.591x`
      - `vs_libcrux=1.206x`
      - `vs_openssl=3.061x`
    - `clang`:
      - `kyber_default=1.010x`
      - `kyber_fair=1.007x`
      - `local_mean_ns=16006.95`
      - `vs_native=1.643x`
      - `vs_pqclean=1.274x`
      - `vs_liboqs=1.329x`
      - `vs_boringssl=3.343x`
      - `vs_libcrux=1.279x`
      - `vs_openssl=2.987x`

### Update: libjade-competitor-integration (same date)

- Change:
  - Added Libjade comparator script:
    - `scripts/bench_compare_libjade.sh`
  - Comparator details:
    - consumes official release asset
      `libjade-dist-src-amd64.tar.gz` (prebuilt assembly)
    - benchmarks `libjade/crypto_kem/kyber_kyber768_avx2`
      (`kyber_kyber768_avx2.s/.h`)
    - uses deterministic `keypair_derand`/`enc_derand` coins for repeatable
      measurements.
  - Integrated new competitor into:
    - `scripts/bench_compare_all_stats.sh` as `libjade_kyber768_avx2`
    - `scripts/bench_compiler_matrix.sh` as `vs_libjade` column
  - Updated `README.md` with comparator usage/examples.
- Verification:
  - Syntax:
    - `bash -n scripts/bench_compare_libjade.sh`
    - `bash -n scripts/bench_compare_all_stats.sh`
    - `bash -n scripts/bench_compiler_matrix.sh`
  - Smoke:
    - `C_COMPILER=clang PIN_CPU=0 ./scripts/bench_compare_libjade.sh 100`
    - result: `local_vs_libjade_speedup=1.279x`
  - Correctness:
    - `make test`: `OK`
- Benchmark evidence:
  - Full all-competitor suite including Libjade (`PIN_CPU=0`, `C_COMPILER=clang`,
    `WARMUP_RUNS=0`, `100x1`):
    - `kyber_default`: `1.032x`
    - `kyber_fair`: `1.017x`
    - `vs_native`: `1.683x`
    - `vs_pqclean`: `1.262x`
    - `vs_liboqs`: `1.312x`
    - `vs_boringssl`: `3.237x`
    - `vs_libcrux`: `1.422x`
    - `vs_libjade`: `1.338x`
    - `vs_openssl`: `2.907x`
  - Compiler matrix including Libjade (`PIN_CPU=0`, `WARMUP_RUNS=0`,
    `100x1`, `COMPILERS='clang'`):
    - `clang`:
      - `kyber_default=0.935x`
      - `kyber_fair=1.031x`
      - `local_mean_ns=17306.71`
      - `vs_native=1.623x`
      - `vs_pqclean=1.221x`
      - `vs_liboqs=1.310x`
      - `vs_boringssl=3.383x`
      - `vs_libcrux=1.428x`
      - `vs_libjade=1.322x`
      - `vs_openssl=2.942x`

### Update: unwind-flags-retune-clang-default (same date)

- Change:
  - Added unwind-table suppression to clang default extra flags:
    - `Makefile` clang default `EXTRA_CFLAGS` now includes:
      - `-fno-unwind-tables`
      - `-fno-asynchronous-unwind-tables`
  - Synced repeated-suite effective clang defaults:
    - `scripts/bench_compare_all_stats.sh`
  - Updated README clang default flag documentation.
- Why:
  - Fair A/B against upstream Kyber AVX2 showed a small but repeatable
    reduction in local roundtrip mean with no observed regression in speedup.
- Verification:
  - Paired fair A/B (`PIN_CPU=0`, `C_COMPILER=clang`, `2000` iters, `5` runs,
    with local and upstream built using matching flags):
    - baseline (`... -finline-functions`):
      - `mean_local=16014.06 ns/op` (sd `62.85`)
      - `mean_kyber=16156.54 ns/op` (sd `62.66`)
      - `mean_speedup=1.009x` (sd `0.003`)
    - with no-unwind flags:
      - `mean_local=15964.68 ns/op` (sd `32.49`)
      - `mean_kyber=16125.87 ns/op` (sd `30.49`)
      - `mean_speedup=1.010x` (sd `0.002`)
  - Additional gcc probe (same protocol, `5` runs) was effectively neutral:
    - baseline `mean_local=16815.97 ns/op`, `mean_speedup=1.010x`
    - with no-unwind `mean_local=16814.28 ns/op`, `mean_speedup=1.012x`
  - Full all-stats baseline (`PIN_CPU=0`, `WARMUP_RUNS=1`, `C_COMPILER=clang`,
    `2000x3`) remained in expected range:
    - `kyber_default` local mean `15999.95 ns/op`, speedup `1.011x`
    - `kyber_fair` speedup `1.009x`
    - `vs_native=1.641x`, `vs_pqclean=1.280x`, `vs_liboqs=1.326x`,
      `vs_boringssl=3.334x`, `vs_libcrux=1.286x`, `vs_libjade=1.325x`,
      `vs_openssl=2.992x`
  - Updated compiler matrix after change (`PIN_CPU=0`, `WARMUP_RUNS=1`,
    `2000x3`, `COMPILERS='gcc clang'`):
    - `gcc`:
      - `kyber_default=1.035x`
      - `kyber_fair=1.008x`
      - `local_mean_ns=16835.31`
      - `vs_native=1.563x`
      - `vs_pqclean=1.226x`
      - `vs_liboqs=1.250x`
      - `vs_boringssl=3.590x`
      - `vs_libcrux=1.222x`
      - `vs_libjade=1.260x`
      - `vs_openssl=3.077x`
    - `clang`:
      - `kyber_default=1.007x`
      - `kyber_fair=1.004x`
      - `local_mean_ns=16003.26`
      - `vs_native=1.628x`
      - `vs_pqclean=1.266x`
      - `vs_liboqs=1.327x`
      - `vs_boringssl=3.338x`
      - `vs_libcrux=1.289x`
      - `vs_libjade=1.328x`
      - `vs_openssl=2.987x`

### Update: robust-stats-mode-for-repeated-suite (same date)

- Change:
  - Added robust aggregation controls to
    `scripts/bench_compare_all_stats.sh`:
    - `STATS_MODE=mean|median|trimmed` (default `mean`)
    - `TRIM_COUNT` (default `1`, used by `trimmed`)
  - Per-suite output now includes:
    - mean/sd, median, trimmed mean
    - selected local/competitor roundtrip (based on `STATS_MODE`)
    - effective trim count fallback (`trim_count_effective`)
  - `local_speedup_vs_competitor` is now computed from the selected statistic
    (mean/median/trimmed), enabling robust tuning runs without script changes.
  - Updated `scripts/bench_compiler_matrix.sh` to print selected
    `stats_mode`/`trim_count` metadata.
  - Updated `README.md` usage with median/trimmed examples.
- Why:
  - Repeated-suite runs occasionally show outliers; robust modes reduce
    sensitivity and make fair A/B decisions more stable.
- Verification:
  - Syntax:
    - `bash -n scripts/bench_compare_all_stats.sh scripts/bench_compiler_matrix.sh`
  - Default-compat smoke:
    - `PIN_CPU=0 C_COMPILER=clang WARMUP_RUNS=0 ./scripts/bench_compare_all_stats.sh 100 1`
    - output includes `stats_mode=mean`, `trim_count=1`,
      `stats_mode_effective=mean`, and selected speedups.
  - Trimmed mode smoke:
    - `PIN_CPU=0 C_COMPILER=clang WARMUP_RUNS=0 STATS_MODE=trimmed TRIM_COUNT=1 ./scripts/bench_compare_all_stats.sh 50 3`
    - `kyber_upstream_avx2` block reports:
      - `trim_count_effective=1`
      - `local_roundtrip_trimmed_ns=15801.78`
      - `competitor_roundtrip_trimmed_ns=15827.64`
      - `local_speedup_vs_competitor=1.002x`
  - Matrix compatibility with robust mode:
    - `PIN_CPU=0 WARMUP_RUNS=0 STATS_MODE=median COMPILERS='clang' ./scripts/bench_compiler_matrix.sh 50 1`
    - result row parsed successfully:
      - `kyber_default=1.010x`
      - `kyber_fair=1.010x`
      - `local_mean_ns=15545.02`
      - `vs_native=1.639x`
      - `vs_pqclean=1.243x`
      - `vs_liboqs=1.337x`
      - `vs_boringssl=3.407x`
      - `vs_libcrux=1.446x`
      - `vs_libjade=1.336x`
      - `vs_openssl=3.085x`

### Update: clang-default-drop-finline (same date)

- Change:
  - Removed `-finline-functions` from clang default extra flags:
    - `Makefile` clang default `EXTRA_CFLAGS`
    - `scripts/bench_compare_all_stats.sh` effective clang defaults
  - Updated `README.md` clang default flag documentation.
- Why:
  - Repeated fair A/B against upstream Kyber AVX2 showed lower local latency
    and slightly better speedup when `-finline-functions` is omitted in the
    current clang profile.
- Verification:
  - Fair A/B screening (`PIN_CPU=0`, `C_COMPILER=clang`, `2000` iters, `5` runs):
    - previous default (`... -finline-functions ...`):
      - `mean_local=15999.71 ns/op`
      - `mean_speedup=1.008x`
      - `median_local=15987.51 ns/op`
      - `trimmed_local=15978.04 ns/op`
    - without `-finline-functions`:
      - `mean_local=15929.02 ns/op`
      - `mean_speedup=1.014x`
      - `median_local=15927.58 ns/op`
      - `trimmed_local=15926.25 ns/op`
  - Full compiler-matrix check with explicit candidate flags
    (`PIN_CPU=0`, `WARMUP_RUNS=1`, `2000x3`, `COMPILERS='clang'`):
    - `kyber_default=1.005x`
    - `kyber_fair=1.009x`
    - `local_mean_ns=15982.78`
    - `vs_native=1.642x`
    - `vs_pqclean=1.274x`
    - `vs_liboqs=1.360x`
    - `vs_boringssl=3.244x`
    - `vs_libcrux=1.282x`
    - `vs_libjade=1.324x`
    - `vs_openssl=2.984x`
  - Baseline rerun at same stage (old default, explicit check):
    - `kyber_default=1.003x`
    - `kyber_fair=1.005x`
    - `local_mean_ns=16069.52`
  - Decision:
    - adopt no-`finline` clang default (keeps >1.0x kyber default/fair while
      lowering local mean).
  - Updated compiler matrix after adopting the new default
    (`PIN_CPU=0`, `WARMUP_RUNS=1`, `2000x3`, `COMPILERS='gcc clang'`):
    - `gcc`:
      - `kyber_default=1.030x`
      - `kyber_fair=1.015x`
      - `local_mean_ns=16905.49`
      - `vs_native=1.567x`
      - `vs_pqclean=1.241x`
      - `vs_liboqs=1.252x`
      - `vs_boringssl=3.596x`
      - `vs_libcrux=1.219x`
      - `vs_libjade=1.260x`
      - `vs_openssl=3.075x`
    - `clang`:
      - `kyber_default=1.009x`
      - `kyber_fair=1.008x`
      - `local_mean_ns=15984.72`
      - `vs_native=1.644x`
      - `vs_pqclean=1.275x`
      - `vs_liboqs=1.324x`
      - `vs_boringssl=3.346x`
      - `vs_libcrux=1.286x`
      - `vs_libjade=1.322x`
      - `vs_openssl=2.978x`

### Update: add-botan-mlkem-comparator (same date)

- Change:
  - Added new comparator script:
    - `scripts/bench_compare_botan_mlkem.sh`
  - Comparator details:
    - clones/reuses Botan from `https://github.com/randombit/botan.git`
    - builds minimized static Botan with FFI + ML-KEM modules
      (`ffi,ml_kem,system_rng,auto_rng,sha3,shake,asn1,base64,pem,pubkey,hex,rng`)
    - uses FFI ML-KEM-768 path and deterministic inputs:
      - key generation from `botan_privkey_load_ml_kem(..., seed[64], "ML-KEM-768")`
      - deterministic custom RNG (`botan_rng_init_custom`) for encapsulation
  - Integrated new competitor into:
    - `scripts/bench_compare_all_stats.sh` as `botan_mlkem`
    - `scripts/bench_compiler_matrix.sh` as `vs_botan` column
  - Updated `README.md` comparator documentation and matrix column description.
- Why:
  - broaden evidence set beyond Kyber/PQClean/liboqs/BoringSSL/libcrux/Libjade/OpenSSL
    with an additional independent ML-KEM implementation.
- Verification:
  - Syntax:
    - `bash -n scripts/bench_compare_botan_mlkem.sh`
    - `bash -n scripts/bench_compare_all_stats.sh`
    - `bash -n scripts/bench_compiler_matrix.sh`
  - Botan comparator smoke:
    - `PIN_CPU=0 ./scripts/bench_compare_botan_mlkem.sh 50`
    - result:
      - `mlkem_roundtrip_ns_per_op=15710.22`
      - `botan_mlkem768_roundtrip_ns_per_op=137472.84`
      - `local_vs_botan_speedup=8.751x`
  - All-stats integration smoke:
    - `PIN_CPU=0 WARMUP_RUNS=0 C_COMPILER=clang ./scripts/bench_compare_all_stats.sh 20 1`
    - `botan_mlkem` block parsed successfully:
      - `local=17357.95`
      - `competitor=138738.60`
      - `local_speedup_vs_competitor=7.993x`
  - Matrix integration smoke:
    - `PIN_CPU=0 WARMUP_RUNS=0 COMPILERS='clang' ./scripts/bench_compiler_matrix.sh 20 1`
    - row includes `vs_botan=8.929x`.
  - Matrix snapshot with both compilers:
    - `PIN_CPU=0 WARMUP_RUNS=1 COMPILERS='gcc clang' ./scripts/bench_compiler_matrix.sh 500 1`
    - `gcc`:
      - `kyber_default=1.070x`
      - `kyber_fair=1.048x`
      - `local_mean_ns=17890.38`
      - `vs_native=1.551x`
      - `vs_pqclean=1.172x`
      - `vs_liboqs=1.204x`
      - `vs_boringssl=3.302x`
      - `vs_libcrux=1.284x`
      - `vs_libjade=1.148x`
      - `vs_botan=7.383x`
      - `vs_openssl=3.028x`
    - `clang`:
      - `kyber_default=1.002x`
      - `kyber_fair=1.004x`
      - `local_mean_ns=16029.25`
      - `vs_native=1.631x`
      - `vs_pqclean=1.251x`
      - `vs_liboqs=1.332x`
      - `vs_boringssl=3.345x`
      - `vs_libcrux=1.338x`
      - `vs_libjade=1.318x`
      - `vs_botan=8.391x`
      - `vs_openssl=3.014x`
  - Correctness:
    - `make test`: `OK`

### Update: blake3-dependency-removal-and-readme-table (2026-06-25)

- Change:
  - Removed the vendored BLAKE3 dependency from `include/blake3/`.
  - Removed BLAKE3 sources, include paths, dispatcher feature probes, wrapper
    function, and test vector from the build/test path.
  - Kept hash/XOF coverage focused on FIPS202 SHA3/SHAKE vectors.
  - Added a README compiler-matrix comparison table snapshot with the
    reproducible command.
- Why:
  - ML-KEM should stay aligned with FIPS 203/FIPS 202 primitives, and BLAKE3 was
    no longer used by the KEM path.
- Verification:
  - Command: `rg -n "\bblake3\b|BLAKE3|include/blake3" -S --glob '!note.md'`
  - Result: no matches.
  - Correctness:
    - Command: `make test`
    - Result: `OK`
  - Local benchmark:
    - Command: `make bench-run BENCH_ITERS=400`
    - Result:
      - keygen: `5592.85` ns/op
      - encaps: `5473.22` ns/op
      - decaps: `6070.86` ns/op
      - roundtrip: `17318.74` ns/op
