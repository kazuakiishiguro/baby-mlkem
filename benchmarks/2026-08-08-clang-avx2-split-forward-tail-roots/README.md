# Clang AVX2 Split Forward-NTT Tail Roots

Commit `dc09558236d1141437b1e5f41bd464a026f0b456` changes only the
generated representation of the three lower forward-NTT Montgomery-factor
levels used by the Clang AVX2-only core. Its baseline is
`753961b3bace2dcbf43ba4d3c145f4056f17da72`.

The baseline exposes each low/high factor family as one `[3][8]` array.
Clang folds level 0 into its existing `.rodata.cst32` instruction operands,
but levels 1 and 2 require indexed addressing. The single source array keeps
all three explicit levels reachable even though the first level is duplicated
in the compiler pool.

The candidate generates level 0 as a separate `[8]` array and keeps levels 1
and 2 together as `[2][8]`. Section GC can then discard both explicit level-0
arrays. The indexed levels still share one base address per low/high family,
so the forward transform does not acquire another address calculation. GCC
continues to use its existing runtime arrays; native AVX512 and scalar paths
do not retain the generated AVX2 tables.

This is repository-local core code. It adds no external library, external
cryptographic object, third-party implementation, cache, runtime dispatch,
API, algorithm, or wire-format dependency.

## Environment

- CPU: AMD Ryzen Threadripper 7980X 64-Cores.
- Clang: Ubuntu Clang 18.1.3.
- GCC: Ubuntu GCC 13.3.0.
- Linker: GNU ld 2.42.
- Stage: CPU 0, two warmup pairs, nine alternating measured pairs per batch,
  two batches, 30,000 iterations.
- KEM: CPU 0, three warmup pairs, sixteen alternating measured pairs per
  batch, two batches, 100,000 iterations.
- Direct forward NTT: CPU 0, four warmup pairs, thirty-one alternating pairs
  per batch, two batches, 1,000,000 iterations.

Exact flags, kernel, microcode, governor, commits, and run settings are in
[`environment.txt`](environment.txt).

## Production Size

Both products use the normal production/no-cache speed flags.

| Profile | Compiler | Baseline primary | Candidate primary | Delta | Candidate code | Candidate read-only | Candidate writable |
|---|---|---:|---:|---:|---:|---:|---:|
| AVX2-only | Clang | 54,150 B | 53,638 B | -512 B | 44,701 B | 8,937 B | 26,593 B |

The size change decomposes exactly as follows:

| Component | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Forward-transform code | 3,584 B | 3,584 B | 0 B |
| Compiler-local `.rodata.cst32` | 4,512 B | 4,512 B | 0 B |
| Explicit forward-tail factors | 1,536 B | 1,024 B | -512 B |
| Net primary | 54,150 B | 53,638 B | -512 B |

The compiler-local constant pool is byte-identical, with SHA-256
`419259063db41f83416b249c796e2d528be4c5e7fa774ec58b015e0a1ce9e80a`.
The accepted product has SHA-256
`8219abeb783e39b6ba0e40ee80ea715ac004332720c321a404ccae53bbe9361d`.
See [`size-baseline.txt`](size-baseline.txt),
[`size-candidate.txt`](size-candidate.txt),
[`section-accounting.txt`](section-accounting.txt), and
[`artifact-identity.txt`](artifact-identity.txt).

## KEM Regression Gate

Ratios are baseline time divided by candidate time. The two equal-size batches
are combined geometrically.

| Operation | Batch 1 | Batch 2 | Combined 32-pair gmean |
|---|---:|---:|---:|
| Decaps | 1.0077x | 1.0023x | 1.004997x |
| Decaps core | 1.0162x | 1.0007x | 1.008417x |
| Encaps | 0.9988x | 1.0001x | 0.999450x |
| Encaps core | 1.0007x | 1.0027x | 1.001699x |
| Keygen | 1.0056x | 0.9957x | 1.000638x |
| Keygen core | 1.0066x | 0.9944x | 1.000484x |
| Roundtrip | 1.0049x | 0.9971x | 1.000992x |
| Roundtrip core | 1.0066x | 0.9992x | 1.002892x |

The combined minimum is `0.999450x`, above the `0.995x` internal operation
regression floor. The batch movement is small and inconsistent, so no speed
gain is credited. See [`kem-combined.txt`](kem-combined.txt),
[`kem-batch1-16x100k.txt`](kem-batch1-16x100k.txt), and
[`kem-batch2-16x100k.txt`](kem-batch2-16x100k.txt).

## Timing Diagnostics

The broad stage harness is mixed. Its selected combined rows range from
`0.990445x` for an isolated keygen NTT diagnostic to `1.002839x` for the
encryption noise/NTT boundary. Complete cached and uncached encryption are
`1.002637x` and `1.000850x`; complete K-PKE key generation is `0.994945x`.
These rows are retained as layout-sensitive diagnostics, not presented as a
stage performance pass. Complete stage-oracle correctness passes in all six
compiler/ISA builds. See [`stage-combined.txt`](stage-combined.txt),
[`stage-batch1-9x30k.txt`](stage-batch1-9x30k.txt), and
[`stage-batch2-9x30k.txt`](stage-batch2-9x30k.txt).

A dedicated two-batch forward-NTT harness isolates the changed transform:

| Batch | Paired gmean | Paired median | Wins |
|---|---:|---:|---:|
| 1 | 1.009043589x | 1.002443575x | 20/31 |
| 2 | 0.992673088x | 0.998653425x | 14/31 |
| Combined | 1.000824868x | 1.001313810x | 34/62 |

The opposite batch movement supports a neutral result. The larger NTT suite
also contains unrelated outliers: `mlkem_ntt_inplace` has a `0.9824x` gmean
but a `0.9985x` median while the directly affected tail rows remain near
`1.0x`. It is retained for diagnosis and not used to claim a gain. See
[`direct-forward-ntt-combined.txt`](direct-forward-ntt-combined.txt),
[`direct-forward-ntt-batch1-31x1m.txt`](direct-forward-ntt-batch1-31x1m.txt),
[`direct-forward-ntt-batch2-31x1m.txt`](direct-forward-ntt-batch2-31x1m.txt),
[`direct-forward-ntt-harness.c`](direct-forward-ntt-harness.c), and
[`ntt-batch1-15x500k.txt`](ntt-batch1-15x500k.txt).

## Generated-Factor Identity

An independent extractor serialized the legacy `[3][8]` low/high arrays and
the new level-0 plus level-1/2 arrays in the same order. Both outputs contain
1,536 bytes and have SHA-256
`be9b80b0d0cc69a3145b52753aed9c51b6f521d0155dfbc5ebb214ff83d4b896`.

Clang and GCC reproduce identical generated headers and the unchanged inverse
assembly file. The generator passes ASan+UBSan and rejects an unknown output
mode. See [`ntt-roots.txt`](ntt-roots.txt).

## Correctness And Isolation

The implementation commit passes:

- GCC and Clang native, AVX2-only, and scalar KAT, production API, and complete
  stage-oracle validation;
- Clang AVX2 ASan+UBSan and GCC AVX2 UBSan KAT, directly linked production API,
  and complete stage validation;
- all 16 core, product, upstream, and PQClean corpus paths, each producing
  381,228 bytes with SHA-256
  `e4d8f908f9a3c59171deeed712925760b194d692b0c571861f204eabef976b67`;
- byte-identical native, scalar, and GCC products relative to the baseline;
- the same three KEM API functions and unresolved runtime symbols;
- no AVX512 register or symbol in the AVX2-only product; and
- a non-executable GNU stack declaration.

See [`correctness-matrix.txt`](correctness-matrix.txt),
[`sanitizers.txt`](sanitizers.txt),
[`cross-path-corpus.txt`](cross-path-corpus.txt),
[`abi-audit.txt`](abi-audit.txt), [`source-audit.txt`](source-audit.txt), and
[`final-smoke.txt`](final-smoke.txt).

## Stack

Eight guarded alternate-stack runs leave every operation unchanged:

| Operation | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Keygen | 4,544 B | 4,544 B | 0 B |
| Encaps | 4,176 B | 4,176 B | 0 B |
| Decaps valid | 4,512 B | 4,512 B | 0 B |
| Decaps invalid | 4,512 B | 4,512 B | 0 B |
| Maximum | 4,544 B | 4,544 B | 0 B |

See [`stack.txt`](stack.txt).

## Rejected Candidate

Moving all three forward-tail levels into the existing generated assembly
object raised code by 61 bytes and primary size to 53,699 bytes. Its direct
NTT result did not survive the operation gate: keygen and keygen-core were
`0.9944x` and `0.9943x` against the accepted split layout. It was removed.
See [`rejected-candidates.txt`](rejected-candidates.txt) and
[`rejected-external-vs-split-kem-16x100k.txt`](rejected-external-vs-split-kem-16x100k.txt).

## Remaining Size Gap

Using the pinned same-method OpenSSL AVX2-only size of 45,049 bytes, the Clang
AVX2 primary deficit falls from 9,101 to 8,589 bytes. The unchanged native
mlkem-native deficit remains 21,862 bytes. This is not a complete
same-revision ten-comparator size or speed rerun, so both size gates and the
overall optimization Goal remain incomplete.

## Reproduction

```bash
make clean
make -j"$(nproc)" product test-product CC=clang \
  ARCH_CFLAGS="-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f"
./scripts/measure_product_size.sh baby_mlkem768_product.o

make check-ntt-roots HOSTCC=clang
make check-ntt-roots HOSTCC=gcc

RUNS=16 WARMUP_RUNS=3 RUN_ORDER=alternating SUITES=kem \
  KEM_ITERS=100000 PIN_CPU=0 C_COMPILER=clang \
  ARCH_CFLAGS="-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f" \
  ./scripts/bench_core_ab.sh 753961b

JOBS="$(nproc)" ./scripts/verify_cross_path_corpus.sh
```

Run the A/B command twice to reproduce the 32-pair combined gate. File
integrity for this directory is recorded in `checksums.sha256`.
