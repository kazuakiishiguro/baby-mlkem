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
