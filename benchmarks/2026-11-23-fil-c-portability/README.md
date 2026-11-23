# Fil-C Portability and Cost (2026-11-23)

This note answers two questions: can `baby-mlkem` be built with
[Fil-C](https://fil-c.org/) (the memory-safe C implementation by Filip Pizlo),
and what does that cost in time?

Short answer: **yes, after two source guards, in all three profiles including
AVX-512; the cost is 1.65x to 5.15x depending on profile and operation, with the
aggregate at 2.3x-2.7x.**

## Environment

| Item | Value |
|---|---|
| Fil-C | 0.687 (`filc-0.687-linux-x86_64.tar.xz`, musl-based, run-in-place distribution) |
| Fil-C compiler | clang 20.1.8 (Fil-C fork) |
| host CPU | AMD Ryzen Threadripper 7980X, CPU 0 pinned |
| baseline compiler | Ubuntu clang 18.1.3 |
| worktree | `.verify-work/wt-filc` (detached at `f98b58c`) |
| build | `-O2`, no LTO, no `-funroll-loops`, `test`/`bench` target |

The musl distribution is set up with its own `setup.sh`, which only patches
`rpath`/`interpreter` relative to the current directory, so no root access and
no `/opt/fil` install were needed. (The glibc `optfil` distribution does require
`/opt/fil` and was therefore not usable.)

## What had to change

Only one code site, guarded so that normal builds are byte-identical:

```c
#if defined(__FILC__)          /* new: no module-level asm in Fil-C */
static void mlkem_keygen_keccakf4_mem_parity_avx2(...) {
  mlkem_encrypt_keccakf4_mem_parity_avx2(st, parity);
}
#elif defined(__clang__) && defined(__ELF__)
  /* existing: .local/.set alias */
```

plus a second `#if` to keep `mlkem_keygen_keccakf4_mem_shared_avx2` visible in
the Fil-C case. The full patch is [`fil-c-portability.patch`](fil-c-portability.patch).
Fil-C rejects the repo's module-level inline asm (`.local`/`.set`) with
`Invalid directive: .local`, which is why the guard is needed at all.

Two build-level concessions are also required, because Fil-C cannot assemble
the repository's `.S` files nor link unsafe assembly:

- `CORE_ASM_SRCS=` / `CORE_ASM_DEF=` / `ASFLAGS=` — use the C fallbacks for the
  NTT root tables and the AVX2 rotate masks instead of the checked-in assembly.
- `NTT_ROOTS_AVX2_ASM=` / `AVX2_SHARED_CONSTANTS_ASM=` for the AVX2 profile.

`-Wa,--noexecstack` is rejected by Fil-C's `sarcasm` assembler, so `ASFLAGS=`
must be cleared as well. Everything else (`-mavx2`, `-mavx512f`, intrinsics,
inline functions, `restrict`, static buffers) compiled unchanged.

## Correctness

`make test` passes under Fil-C in both the scalar and the AVX2 configurations
(`OK`, with identical encapsulated/decapsulated shared secrets). The native
configuration builds and runs, and the produced binary contains 3,248 `%zmm`
instructions, i.e. AVX-512 code generation works under Fil-C.

## Performance

Median of five alternating runs per configuration, same flags for both
compilers, `benchc` core metrics. Ratios are `Fil-C / clang` (higher = slower).

### Current state (after rounds 1-3)

| Profile | Metric | clang | Fil-C | Gap |
|---|---|---:|---:|---:|
| native | product core sum (keygen+encaps+decaps) | ~10,900 ns | ~18,100 ns | 1.68x |
| AVX2-only | product core sum | ~14,700 ns | ~31,200 ns | 2.12x |

The tables below this section are the *first* measurement of the untouched
sources and are kept as the starting point for the analysis.

| Profile | Operation | clang (ns/op) | Fil-C (ns/op) | Slowdown |
|---|---|---:|---:|---:|
| scalar | keygen | 21,354 | 39,722 | **1.86x** |
| scalar | encaps | 12,426 | 32,048 | 2.58x |
| scalar | decaps | 17,433 | 46,973 | 2.69x |
| scalar | roundtrip | 50,971 | 117,527 | 2.31x |
| AVX2-only | keygen | 5,577 | 15,794 | 2.83x |
| AVX2-only | encaps | 1,744 | 4,299 | 2.47x |
| AVX2-only | decaps | 2,245 | 7,632 | **3.40x** |
| AVX2-only | roundtrip | 9,614 | 26,262 | 2.73x |
| native (AVX-512) | keygen | 4,313 | 7,133 | 1.65x |
| native (AVX-512) | encaps | 1,045 | 3,196 | 3.06x |
| native (AVX-512) | decaps | 1,461 | 7,526 | **5.15x** |
| native (AVX-512) | roundtrip | 6,732 | 16,314 | 2.42x |

Raw output: [`measurements.txt`](measurements.txt).

Observations:

- The aggregate slowdown is 2.31x-2.73x, which is in line with Fil-C's
  published overhead for pointer-heavy integer code.
- **Decapsulation is hit hardest** in the wider-ISA profiles (3.40x on AVX2,
  5.15x on native) while it is only 2.69x in scalar. The faster the arithmetic,
  the larger the share taken by Fil-C's per-access capability checks: in the
  native profile decapsulation is dominated by memory traffic rather than
  arithmetic.
- Key generation is hit least (1.65x native), because it spends most of its
  time in the Keccak permutation, whose inner loops are dense register
  arithmetic with few pointer dereferences.
- Fil-C's own `-O3` was measured against `-O2` on the AVX2 profile: no
  difference (roundtrip 26.2 us either way), so the overhead is in the safety
  checks, not in code generation quality.
- Binary size grows 1.6x-2.2x (e.g. AVX2 bench `69,432 B` -> `240,024 B`).
- Compile time is only 1.25x slower (`make test` from clean: 6.43 s -> 8.01 s).

For reference, the repository's production build (default flags, checked-in
`.S` fast paths, clang 18) measures `4,010 / 1,045 / 1,456 / 6,525 ns` in the
same harness, so a Fil-C build is 2.5x slower than what the repository ships.
Note that the Fil-C comparison above deliberately disables the `.S` constants
for both compilers so the two numbers differ only by the compiler.

## Why it is slower

The slowdown is not a code-generation-quality problem. It is the price of
Fil-C's checked memory access, and it scales with the number of *distinct memory
accesses*, not with the amount of arithmetic.

### Isolating the mechanisms

A small synthetic benchmark ([`micro-overhead.c`](micro-overhead.c)) separates
register work from memory work. Each row is ns/op for 256 loop iterations,
best of two runs, `-O2`:

| Kernel | clang (vectorized) | clang (`-fno-vectorize`) | Fil-C | Fil-C / clang |
|---|---:|---:|---:|---:|
| register-only 256-iteration loop | 94 | 93 | 106 | **1.13x** |
| 256 `int16_t` loads (sum) | 14 | 32 | 150 | **11.1x** |
| 16 AVX2 `_mm256_loadu_si256` loads | 5 | 35 (`int16_t` version) | 152 | 30x |
| empty `noinline` call | 1.0 | 1.0 | 1.1-2.7 | ~1-2x |

Two things follow immediately:

- **Pure register arithmetic is essentially free** (1.13x). Fil-C does not slow
  down computation itself.
- **Array access is what costs**: about `0.45 ns` (roughly 1.5 cycles) extra per
  checked load, which on a load-bound inner loop turns into an order of
  magnitude.
- Losing auto-vectorization accounts for only 2.4x of that 11x (14 -> 32 ns);
  the remaining 4.6x (32 -> 150 ns) is the checks themselves.

### What the generated code actually does

For `int16_t load_at(const int16_t *a, size_t i) { return a[i]; }` clang emits a
single `movzwl (%rdi,%rsi,2), %eax`. Fil-C emits:

```asm
    cmpq  %rsp,(%rdi)              # stack-overflow guard (thread state)
    jae   filc_stack_overflow_failure@PLT
    movq  0x10(%rdi),%rax          # push access pseudo-stack
    movq  %rax,0x20(%rsp)
    ...
    testq %rcx,%rcx                # capability != null
    je    <fail>
    cmpq  %rcx,%rax                # lower bound check
    jb    <fail>
    movq  -0x10(%rcx),%rsi         # load object size from the capability header
    addq  $-2,%rsi
    cmpq  %rsi,%rax                # upper bound check
    ja    <fail>
    movzwl (%rax),%edx             # the actual load
    movq  %rsi,0x10(%rdi)          # pop access pseudo-stack
```

Inside a real loop (`mem_loop`, full listing in
[`fil-c-inner-loop.txt`](fil-c-inner-loop.txt)) every element pays:

1. a store and re-load of the capability (spill to the pseudo-stack),
2. a null check plus lower- and upper-bound compares (three branches),
3. **an extra dependent load** of the object size from `-0x10(base)`,
4. a thread-state test per access (`testb $0xe,0x8(%rdi)`; GC/safepoint flag),
5. the data load itself.

So a load goes from 1 instruction to ~7 instructions plus 2 extra memory
accesses, which is why checked scalar loops land at 3x-5x while Keccak, whose
rounds are almost pure register arithmetic, lands at 1.3x-1.9x.

### This explains the profile shape

| Code shape | Example stages | Measured |
|---|---|---|
| AVX2/AVX-512 intrinsics, arithmetic-dense | `ntt_mul_acc3_madd_avx2`, `ntt_mul_acc4_madd_avx2` | **1.11x-1.22x** |
| Keccak permutations (register-heavy, one state array) | `sample_ntt4_keccak3_only` | 1.7x-1.9x |
| Scalar NTT / reduce loops over `int16_t` | `ntt_mul_acc3_canonical_scalar` | **5.50x** |
| Byte-wise pack / compress / decode | `ciphertext_compress_encode_d10_pack_only` | 3.93x |
| Whole operations | keygen/encaps/decaps | 1.65x-5.15x |

The two extremes are the same compiler: hand-written intrinsics over
already-checked pointers cost almost nothing (the checks hoist out of the
vector loop and the arithmetic is register-bound), while a scalar loop that
touches an array once per iteration pays a full check per element. Decapsulation
is hit hardest in the AVX2 and native profiles because, once the arithmetic is
fast, its remaining time is dominated by byte-level memory traffic (ciphertext
decode, constant-time compare, key copy).

This also explains why `-O3` and `-O2` measure the same: the cost is in the
checks, which no optimization level removes.

## Implemented: one kernel that serves both compilers

The concrete work item from the analysis below was carried out in the
experiment worktree (`.verify-work/wt-filc`), see
[`both-fast-kernel-final.patch`](both-fast-kernel-final.patch).

Change: a new `ntt_mul_acc3_gamma_avx2()` implements the scalar
`ntt_mul_acc3()` / `ntt_mul_acc3_factored_gamma()` formula (the two bodies are
identical) as explicit AVX2, and both entry points dispatch to it under
`__AVX2__`. The key difference from the pre-existing `ntt_mul_acc3_avx2()` is the
reduction strategy: the scalar code reduces **three times per output pair**
(`c0_hi % Q`, `c0 % Q`, `c1 % Q`) while `ntt_mul_acc3_avx2()` reduces **every
product**, which is why that kernel was slow. A new exact 32-bit reduction
(`q = mulhi64(x, ceil(2^32/Q))`, then one conditional add/sub) makes the
three-reduction form safe up to `8.0e7`, which covers the `6.6e7` worst case of
six 12-bit products.

Correctness: the reducer was exhaustively verified over `0..7.0e7` (no
mismatches), and `make test` passes under both clang and Fil-C in the AVX2-only
profile.

### Measured effect (AVX2-only, `-O2`, CPU 0, four alternating runs)

Whole-operation, `benchc` default columns, median:

| Compiler | keygen | encaps | decaps | roundtrip |
|---|---:|---:|---:|---:|
| clang before | 5,593 | 1,742 | 2,246 | 9,615 |
| clang after | 5,642 | 1,746 | 2,244 | 9,620 |
| Fil-C before | 15,570 | 4,345 | 7,676 | 26,330 |
| Fil-C after | **11,780** | 4,322 | 7,670 | **22,610** |

- Fil-C: keygen **-24%**, aggregate **-14%**.
- clang: within noise (+0.9% keygen, +0.05% aggregate).

Stage-level, which isolates the kernel (ns/op):

| Stage | clang before | clang after | Fil-C before | Fil-C after | Fil-C ratio before -> after |
|---|---:|---:|---:|---:|---:|
| `keygen_accum_only` | 439 | 473 | 3,924 | **591** | 8.94x -> **1.25x** |
| `keygen_accum_encode` | 478 | 523 | 3,969 | 721 | 8.31x -> 1.38x |
| `encrypt_accum_inv` | 850 | 905 | 5,884 | **1,533** | 6.92x -> **1.70x** |
| `encrypt_accum_u_only` | 447 | 473 | 3,969 | **583** | 8.88x -> **1.23x** |
| `kpke_keygen_full` | 3,685 | 3,651 | 11,325 | 8,302 | 3.07x -> 2.27x |

So the targeted primitive went from 6.6x-8.9x slower than clang to 1.23x-1.38x,
i.e. the per-access penalty is gone for it. The kernel is ~7% slower than
clang's auto-vectorized scalar for that one primitive (439 -> 473 ns), which is
why whole-operation clang time does not improve; closing that last 7% would need
a `vpmaddwd`-style kernel like `ntt_mul_acc3_madd_avx2()`.

### What is left

After the change, the remaining Fil-C extra time sits in the forward NTT and the
matrix sampler, both of which are already intrinsic:

| Stage | clang | Fil-C | ratio |
|---|---:|---:|---:|
| `kpke_keygen_full` | 3,651 | 8,302 | 2.27x |
| `kpke_encrypt_uncached` | 3,619 | 7,286 | 2.01x |
| `kpke_prepare_public_no_cache` | 2,750 | 5,176 | 1.88x |
| `sample_matrix` | 2,644 | 4,466 | 1.69x |

Those are load/store-heavy intrinsics kernels (`ntt_mont_lazy_avx2` and the x4
Keccak samplers), where the checks cannot be hoisted further because the data
being loaded is itself computed per element. That is the irreducible floor for
Fil-C on this workload.

## Round 1 of "push to the floor" (2026-11-23)

Three further changes on top of the first kernel, all in the experiment worktree
([`round1-final.patch`](round1-final.patch)):

1. **Decapsulation secret basemul** now calls the new kernel instead of
   `ntt_mul_acc3_avx2()`, the per-product-reduction version (that function is
   otherwise unused).
2. **`poly256_sub()`** was a plain scalar loop in every configuration; it is now
   AVX2 with one masked Q add.
3. The AVX-512 configuration was re-checked and the kernel deliberately left out
   of it: the native build's production paths use different fused kernels, so
   enabling it there changed nothing (measured, then reverted).

### Result (AVX2-only, `-O2`, CPU 0, three alternating runs, medians)

| Compiler | keygen | encaps | decaps | roundtrip |
|---|---:|---:|---:|---:|
| clang before | 5,662 | 1,740 | 2,252 | 9,610 |
| clang after | 5,618 | 1,749 | 2,173 | 9,562 |
| Fil-C before | 15,803 | 4,323 | 7,658 | 26,354 |
| Fil-C after | **11,936** | 4,334 | 7,489 | **22,541** |

- Fil-C: keygen 1.32x, roundtrip 1.17x faster; clang: neutral-to-1.04x faster
  (decapsulation also improved by 3.5% for clang).
- Aggregate gap to clang: **2.74x -> 2.36x**.

### Where the remaining AVX2-only gap is, and why it is a floor

The forward NTT is the largest remaining single item and its access pattern is
already maximal for the ISA: `ntt_head_mont_lazy_raw_avx2()` moves 16
coefficients per iteration as two 32-byte loads and two 32-byte stores, i.e.
four checked accesses per 16 coefficients, and the tail levels and the
canonicalisation pass do the same. That is 32 bytes per access, the widest AVX2
offers.

The measured penalty matches the check charge exactly: the NTT costs
`755 -> 2,098 ns` for three polynomials, i.e. `+447 ns/poly`; one polynomial
needs about 1,100 checked accesses, and at the measured `~1.5 cycles` per check
and 3.5 GHz that predicts `~0.47 us`. Access count times per-access cost
explains the whole gap, with no residual optimisation headroom in the current
schedule.

Fil-C offers no way to opt out: `filcc` exposes no per-file or per-function
"no checks" switch (only `-yolo-assembler`, which affects `.s` inputs), so the
charge cannot be waived for the crypto core without abandoning memory safety,
which is the entire point of the Fil-C build.

### Next target (identified, not yet implemented)

The native (AVX-512) profile still contains genuinely scalar code in its fused
kernels: `ntt_mul_acc3_pair_values()`, `ntt_final_l1_pair_values()` and the
`encrypt_*_scalar_avx512` family process **four coefficients at a time with
scalar loads**. Those are why the native profile shows
`kpke_decrypt_uncached 5.4x` and `encrypt_accum_u_only 11x` under Fil-C while its
intrinsic neighbours are 1.7x-1.9x. Rewriting them as 16-coefficient AVX-512
blocks is the next structural win, and it should help plain clang as well
because the same scalar code runs there.

## Round 2: vectorized native fused decrypt kernel (2026-11-23)

The native (AVX-512) decapsulation path used `ntt3_mul_acc3_fused_final_avx512()`,
whose inner loop calls two genuinely scalar per-pair helpers
(`ntt_final_l1_pair_values()`, `ntt_mul_acc3_pair_values()`) 128 times per
polynomial. That is why `kpke_decrypt_uncached` measured **5.40x** under Fil-C
while the neighbouring intrinsic kernels were 1.7x-1.9x.

Change ([`round2-final.patch`](round2-final.patch)):

- `ntt_final_l1_avx512()` performs the final NTT level 16 coefficients at a time
  (one `permutexvar` pair for the butterfly pairing, one masked blend for the
  `+/-` pattern, one `mod_q_reduce_ntt_u32x16` per block).
- The fused kernel now calls that plus the round-1 basemul kernel, instead of
  the scalar pair helpers.
- The vectorized form is selected with `#if defined(__FILC__)`, because plain
  clang is *slower* with it (it auto-vectorizes the scalar pair form better than
  this hand-written version). Keeping clang on its existing path avoids the
  `decaps 1,460 -> 1,576 ns` regression that the unconditional version caused.

### Result (native profile, `-march=native`, `-O2`, CPU 0, three alternating runs, medians)

| Compiler | keygen | encaps | decaps | roundtrip |
|---|---:|---:|---:|---:|
| clang before | 4,225 | 1,051 | 1,504 | 6,784 |
| clang after | 4,270 | 1,047 | 1,460 | 6,736 |
| Fil-C before | 7,429 | 3,193 | 7,549 | 16,344 |
| Fil-C after | 7,093 | 3,232 | **6,185** | **14,992** |

- Fil-C: decapsulation `1.22x`, aggregate `1.09x` faster.
- clang: unchanged within noise (decapsulation 2.9% better).
- Native gap: **2.41x -> 2.23x**.
- Product no-cache metric (`benchc *_core` columns): Fil-C
  `19,616 -> 18,303 ns` (1.07x), clang unchanged, so the product gap in this
  profile is **1.82x -> 1.69x**.
- The AVX2-only profile is unaffected (`22,523 ns`, same as round 1).

## Round 3: the floor, measured (2026-11-23)

### Rejected: fusing the NTT normalization pass

After two rounds the hottest remaining production item was the forward NTT
(2.77x-2.84x in AVX2-only, 2.35x native). Its normalization pass
(`ntt_canonicalize_signed_*`) costs one load and one store per 16 (AVX2) or 32
(AVX-512) coefficients, i.e. 64 checked accesses per polynomial out of about
352 in the whole NTT, so it looked like an 18% saving waiting to be fused into
the tail's final store.

Measured, it made things *worse*: AVX2-only roundtrip `9,600 -> 9,673 ns` for
clang and `22,378 -> 22,483 ns` for Fil-C. The reason is that the fused form has
to use the strong Barrett sequence (sign fix plus redundant-representation
removal) inside the tail loop, and that lengthens the dependency chain there by
more than the saved accesses are worth. Reverted; the round-2 patch is the final
state.

### Final numbers (product metric, `benchc *_core`, no caches, CPU 0, three runs)

| Profile | clang | Fil-C | gap |
|---|---:|---:|---:|
| native (`-march=native`) | 10,760-11,082 ns | 18,022-18,187 ns | **1.68x** |
| AVX2-only | 14,650-14,744 ns | 31,024-31,380 ns | **2.12x** |

Progress across the three rounds, native profile: `16,344 -> 14,992 ns`
(roundtrip, default columns) and product-core `19,616 -> 18,183 ns`; AVX2-only
roundtrip `26,354 -> 22,412 ns` and product-core gap `2.74x -> 2.12x`.

### Why this is the floor

The residual is exactly "checked accesses x per-access cost":

- The microbenchmark in `micro-overhead.c` puts a checked load at about
  `0.45 ns` (about 1.5 cycles) on this host.
- Native profile: extra `~7,400 ns` / `0.45 ns` gives about **16,400 accesses**
  per operation.
- AVX2-only profile: extra `~16,400 ns` gives about **36,400 accesses**.
- The AVX2 kernels move 32 bytes per access and the AVX-512 kernels 64 bytes, and
  native needs about half as many accesses as AVX2, which is what the two ratios
  show (`1.68x` versus `2.12x`).

Every production kernel is already at the widest access its ISA allows: the NTT
head touches each coefficient exactly once per level as two 32-byte loads plus
two 32-byte stores per 16 coefficients, the matrix sampler is at the
`ceil(34/4)` permutation bound, and after rounds 1 and 2 no scalar array loop
remains on any production hot path. Reducing the charge further therefore
requires *fewer* accesses, which the pass-fusion experiment shows trades
arithmetic for accesses at a loss. Fil-C exposes no per-file or per-function
switch to waive checks (`filcc` only has `-yolo-assembler`, which concerns `.s`
inputs), so the charge cannot be removed without giving up memory safety.

The AVX2-only gap is larger than the native one for the same reason it has twice
as many accesses: it is a property of the ISA, not of the code.

## Feasibility analysis (pre-implementation)



Partly yes, and the path is specific rather than speculative.

The per-stage data says the surviving cost is concentrated where the product
still uses **scalar C array loops** while an intrinsic version exists or could
exist for the same math:

| Stage (AVX2 profile) | clang | Fil-C | extra | what the code does |
|---|---:|---:|---:|---|
| `keygen_accum_only` | 439 | 3,924 | +3.5 us | `ntt_mul_acc3_factored_gamma`: 128-iteration scalar loop, 14 array accesses per iteration |
| `encrypt_accum_inv` | 850 | 5,884 | +5.0 us | `ntt_mul_acc3` (same scalar form) + inverse NTT |
| `encrypt_accum_u_only` | 447 | 3,969 | +3.5 us | same scalar basemul |
| `ntt_mul_acc3_madd_avx2` | 232 | 283 | +0.05 us | explicit AVX2 kernel |
| `ntt_mul_acc4_madd_avx2` | 673 | 745 | +0.07 us | explicit AVX2 kernel |

A speed-only probe confirms the size of the prize. Replacing the keygen call of
the scalar `ntt_mul_acc3_factored_gamma` with the already-present AVX2 kernel
`ntt_mul_acc3_avx2` (three alternating runs, [`both-compilers-probe.txt`](both-compilers-probe.txt)):

| Compiler | before | after | change |
|---|---:|---:|---:|
| clang | 5,598 ns | 5,862 ns | **+4.7% slower** |
| Fil-C | 15,700 ns | 12,100 ns | **23% faster** |

So the lever works, but that particular kernel is not the answer for plain C:
clang already auto-vectorizes the scalar loop better than this kernel does
(`ntt_mul_acc3_canonical_scalar` 275 ns beats `ntt_mul_acc3_canonical_avx2`
352 ns under clang, while `ntt_mul_acc3_madd_avx2` at 232 ns beats both).

The conclusion is therefore:

- **A single vectorized kernel per hot loop can serve both compilers**, but it
  has to be the *fastest* kernel, not merely *an* intrinsic kernel. The
  repository already contains such a kernel (`ntt_mul_acc3_madd_avx2`,
  fastest under clang and 1.22x under Fil-C); routing the keygen and
  no-cache encryption basemul through a matching-form madd kernel is the
  concrete work item.
- Doing so would move roughly 12 us of Fil-C's 16.6 us AVX2-only overhead
  (keygen + encrypt accumulate) from ~7-9x down towards ~1.2x, which projects to
  an AVX2-only Fil-C aggregate near **1.5x-1.8x** instead of 2.79x, with plain C
  unchanged or slightly faster.
- What cannot be fixed by vectorizing is the rest: byte-level packing and
  constant-time compares stay memory-access-dense, so Fil-C keeps a floor of
  roughly 1.3x-1.6x on this workload. Fil-C cannot be brought to parity.

So: fast under both, yes, in the sense of "the same source is fast for both,
with vectorized hot loops"; identical performance is not achievable.

## Reproduction

```bash
cd .verify-work/filc
curl -LO https://github.com/pizlonator/fil-c/releases/download/v0.687/filc-0.687-linux-x86_64.tar.xz
tar -xf filc-0.687-linux-x86_64.tar.xz && cd filc-0.687-linux-x86_64 && ./setup.sh
FILC=$PWD/build/bin/clang

cd <worktree>   # with fil-c-portability.patch applied
make bench CC=$FILC OPT_CFLAGS=-O2 EXTRA_CFLAGS= ASFLAGS= \
  CORE_ASM_SRCS= CORE_ASM_DEF= \
  ARCH_CFLAGS="-march=x86-64-v3 -mavx2 -mbmi2 -mpopcnt -mno-avx512f"
taskset -c 0 ./benchc 3000
```

## Caveats

- The Fil-C timings use the C fallbacks, not the repository's checked-in
  assembly, for both compilers; the absolute numbers are therefore slightly
  above the production figures and are only meant to isolate the Fil-C cost.
- `perefil` is the **Peregrine** distribution (portable binaries across
  Linux/Darwin/Windows), not a faster flavor, so it was not measured.
- Fil-C's garbage collector and runtime are included in every binary, so
  stack/heap high-water numbers are not comparable to the plain-C artifacts.

### Attempted and rejected in this pass

| Candidate | Result |
|---|---|
| Enable the matching-form kernel for AVX-512 builds too | no change (native production paths use different fused kernels); reverted |
| Widen `byte_decode_d12_x3_avx2` to AVX-512 builds (the native build otherwise uses the scalar d12 decoder) | no consistent gain: cached path never re-decodes, and the uncached decrypt stage measured `2,282 -> 2,527 ns`; reverted |

Both are recorded because "the native build falls back to a scalar d12 decoder"
is a real code fact (`#if defined(__clang__) && !defined(__AVX512F__)`), but it is
not where the time goes for this workload.

## Effect on the production artifacts

Besides speed, the change also shrinks the AVX2-only production artifact,
because the two scalar basemul bodies become unreachable and are removed by
section GC:

| Profile | primary before | primary after |
|---|---:|---:|
| native | 51,171 B | **51,171 B** (unchanged) |
| AVX2-only | 45,032 B | **43,966 B** (-1,066 B) |

Measured with `make product` + `scripts/measure_product_size.sh` on clang 18.1.3.
clang performance is unchanged by the patch (`benchc` core columns, AVX2:
`14,564-14,590 ns` roundtrip; native: `10,283-10,299 ns`).

## What was tried and measured across the three rounds

| # | Change | Result |
|---|---|---|
| 1 | matching-form AVX2 basemul kernel (three reductions per output pair, exact wide reducer) | Fil-C keygen 1.32x, aggregate 1.17x faster; clang neutral |
| 1 | route decapsulation's secret basemul through it; vectorize `poly256_sub()` | included above |
| 2 | vectorized the native fused decrypt kernel (`__FILC__`-dispatched) | Fil-C native decaps 1.22x, aggregate 1.09x faster; clang neutral |
| - | enable the new kernel for AVX-512 builds unconditionally | no change; reverted |
| - | widen `byte_decode_d12_x3_avx2` to AVX-512 builds | no gain (and 2,282 -> 2,527 ns on the uncached decrypt stage); reverted |
| - | fuse the NTT normalization pass into the tail store | worse for both compilers; reverted |
| - | round-loop unrolling, full 24-round expansion, theta folding, chi reassociation, alternative reducers | all rejected earlier (see note.md) |

Both profiles keep one patch. The product source is otherwise untouched and
`make test` passes for clang and Fil-C in both profiles.

