# Clang AVX2 Rolled Inverse-Add Loop

Commit `8fab80d9cd14556fd5514f56fd1d8b7bdeca98e8` prevents Clang from
unrolling the fixed three-iteration inverse-add loop inside the already shared
AVX2 encryption finish. Clang had emitted three copies of the complete
row-local inverse-NTT tail/final body. The pragma keeps one body and iterates it
over `u[0]`, `u[1]`, and `u[2]` in the same order.

This does not batch inverse levels across polynomials, change arithmetic,
change representation, or add a helper call. It is independent baby-mlkem core
code and adds no vendored backend call, external cryptographic object, runtime
library, persistent cache, table, API, algorithm, or wire-format dependency.

## Environment

- CPU: AMD Ryzen Threadripper 7980X 64-Cores.
- Clang: Ubuntu Clang 18.1.3.
- GCC: Ubuntu GCC 13.3.0.
- Linker: GNU ld 2.42.
- Product timing: CPU 0, three batches, three warmup pairs and sixteen
  measured pairs per batch, 100,000 iterations, alternating process order.

Exact host, kernel, microcode, governor, flags, revisions, and run settings
are in [`environment.txt`](environment.txt).

## Production Size

Both artifacts use the normal Clang AVX2 production/no-cache flags. Primary
size is allocatable executable plus read-only data.

| Profile | Baseline | Candidate | Delta | Candidate code | Candidate read-only | Candidate writable |
|---|---:|---:|---:|---:|---:|---:|
| Clang AVX2-only | 48,146 B | 47,501 B | -645 B | 41,546 B | 5,955 B | 26,593 B |

The linked size difference is isolated to one text section. Clang also changes
the order of existing values in one same-size constant-pool section:

| Section | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| `.text.kpke_encrypt_finish_avx2` | 3,841 B | 3,196 B | -645 B |
| Other 22 text sections | 38,350 B | 38,350 B | 0 B, byte-identical |
| `.rodata` | 115 B | 115 B | 0 B; 12 raw bytes differ |
| Other 13 read-only sections | 5,840 B | 5,840 B | 0 B, byte-identical |
| Net primary | 48,146 B | 47,501 B | -645 B |

The `.rodata` difference is confined to offsets `0x40..0x4f`: the same eight
16-bit values are present in a different compiler-pool order. No constant is
added or removed, and total read-only size remains 5,955 bytes.

The relocatable ELF file also falls from 74,272 to 73,152 bytes. Writable
storage and stack are unchanged. The accepted object has SHA-256
`bdf2c0a541ff857137991666d08f904e9952664fdf192ad75053aa60502f3a8d`.

See [`size-baseline.txt`](size-baseline.txt),
[`size-candidate.txt`](size-candidate.txt),
[`section-accounting.txt`](section-accounting.txt), and the two retained finish
disassemblies. Raw read-only identities are retained in
[`readonly-sections-baseline.sha256`](readonly-sections-baseline.sha256) and
[`readonly-sections-candidate.sha256`](readonly-sections-candidate.sha256).

## Product Regression Gate

The baseline/candidate objects and benchmark executable pair are fixed for all
48 measured pairs. Every process confirms that normal and `*_core` metrics are
equal because the product API disables internal caches. No sample is filtered.

| Operation | Batch 1 | Batch 2 | Batch 3 | Combined 48 | 95% CI |
|---|---:|---:|---:|---:|---:|
| Keygen | 0.999775447x | 1.003985036x | 0.989333708x | 0.997679015x | 0.994320018x-1.000817418x |
| Encaps | 0.999136279x | 1.001608091x | 0.995676586x | 0.998804022x | 0.996040620x-1.001682336x |
| Decaps | 1.006832429x | 0.995133427x | 0.993502198x | 0.998471748x | 0.990598596x-1.005876242x |
| Roundtrip | 1.000892689x | 0.998872764x | 0.991913187x | 0.997218785x | 0.994036445x-1.000285106x |

Batch 3 fails its standalone floor at keygen `0.989333708x`; that operation
does not execute the changed encryption finish, and the batch's baseline-first
keygen median is `0.983237570x`. The batch and all samples are retained. The
predefined decision statistic is the combined 48-pair geometric mean, whose
minimum is roundtrip at `0.997218785x`, above the `0.995x` floor. The intervals
and order split do not support a speed claim, so this is accepted only as a
size optimization.

See [`product-ab-combined-48x100k.txt`](product-ab-combined-48x100k.txt),
the three `product-ab-batch*-16x100k.txt` files, and the retained
[`product-ab-screen-16x50k.txt`](product-ab-screen-16x50k.txt).

## Correctness And Isolation

The implementation commit passes:

- GCC and Clang native, AVX2-only, and scalar KAT, product API, and complete
  1,000-iteration stage-oracle validation;
- Clang AVX2 ASan+UBSan KAT, direct-linked product API, complete stage harness,
  and both generated NTT outputs with no sanitizer diagnostics;
- all 16 core, product, upstream, and PQClean corpus paths, each producing
  381,228 bytes with SHA-256
  `e4d8f908f9a3c59171deeed712925760b194d692b0c571861f204eabef976b67`;
- byte-identical products in all five non-target compiler/profile builds;
- unchanged defined and unresolved symbols, no AVX512 instruction registers,
  and no executable GNU stack; and
- a clean committed product byte-identical to the timed and validation object.

See [`correctness-matrix.txt`](correctness-matrix.txt),
[`sanitizers.txt`](sanitizers.txt),
[`cross-path-corpus.txt`](cross-path-corpus.txt),
[`abi-audit.txt`](abi-audit.txt), and
[`postcommit-smoke.txt`](postcommit-smoke.txt).

## Stack

Eight guarded alternate-stack runs are unchanged:

| Operation | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Keygen | 4,512 B | 4,512 B | 0 B |
| Encaps | 4,144 B | 4,144 B | 0 B |
| Decaps valid | 4,512 B | 4,512 B | 0 B |
| Decaps invalid | 4,512 B | 4,512 B | 0 B |
| Maximum | 4,512 B | 4,512 B | 0 B |

See [`stack.txt`](stack.txt), [`stack-baseline-raw.txt`](stack-baseline-raw.txt),
and [`stack-candidate-raw.txt`](stack-candidate-raw.txt).

## Goal Impact

Using the still-pinned OpenSSL AVX2-only product at 45,049 primary bytes, the
residual gap falls from 3,097 to 2,452 bytes. The remaining gap consists of
458 code bytes and 1,994 read-only bytes. That comparator was not rebuilt for
this local A/B, and the complete ten-comparator matrix has not been rerun. The
primary-size gate therefore still fails, and the overall fastest-and-smallest
Goal remains incomplete.

Run the self-contained evidence audit with:

```bash
./benchmarks/2026-08-10-clang-avx2-rolled-inverse-add-loop/verify-evidence.sh
```
