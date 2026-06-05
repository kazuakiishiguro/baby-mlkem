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
