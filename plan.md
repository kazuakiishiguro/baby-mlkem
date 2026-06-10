# Bottom-Up Reimplementation Plan for baby-mlkem

## Context

Reimplement ML-KEM-768 from scratch (FIPS 203, August 2024) to deepen understanding. Each step only depends on what has already been built and tested. Target: clean C99 implementation, gcc, no external dependencies.

## ML-KEM-768 Parameters (Table 2, FIPS 203)

| Symbol | Value | Meaning                                             |
|--------|-------|-----------------------------------------------------|
| n      | 256   | Polynomial degree                                   |
| q      | 3329  | Prime modulus                                       |
| k      | 3     | Module rank (number of polynomials in vectors)      |
| eta1   | 2     | CBD parameter for keygen secrets s, e and encrypt r |
| eta2   | 2     | CBD parameter for encrypt noise e1, e2              |
| du     | 10    | Compression bits for ciphertext component u         |
| dv     | 4     | Compression bits for ciphertext component v         |

**Derived sizes (bytes):**

| Artifact                  | Formula         | Bytes |
|---------------------------|-----------------|-------|
| ek (encapsulation key)    | 384*k + 32      | 1184  |
| dk (decapsulation key)    | 768*k + 96      | 2400  |
| dk_pke (K-PKE secret key) | 384*k           | 1152  |
| ciphertext c              | 32*du*k + 32*dv | 1088  |
| c1 (u component)          | 32*du*k         | 960   |
| c2 (v component)          | 32*dv           | 128   |
| shared key K              | 32              | 32    |

**Ring:** R_q = Z_q[X] / (X^256 + 1), where q = 3329.

**Primitive root:** zeta = 17 has order 256 modulo 3329: `17^128 = -1 mod 3329` and `17^256 = 1 mod 3329`. This is the FIPS 203 root used by the negacyclic NTT over `R_q`.

**Hash functions used:**
- G = SHA3-512 (rate=72, domain=0x06, output=64 bytes)
- H = SHA3-256 (rate=136, domain=0x06, output=32 bytes)
- J = SHAKE-256 (rate=136, domain=0x1F, output=32 bytes)
- PRF(s, b) = SHAKE-256(s || b), variable-length output
- XOF(seed, a, b) = SHAKE-128(seed || byte(a) || byte(b)), streaming output

---

## File Structure

Split the implementation into independently compilable modules. Each `.c` file compiles on its own and can be tested in isolation.

```
baby-mlkem/
├── params.h              # N, Q, K, ETA1, ETA2, DU, DV, all derived size macros
├── reduce.h / reduce.c   # barret_reduce (non-negative), reduce_signed (any int32_t)
├── poly.h / poly.c       # poly256 type, poly256_add, poly256_sub
├── ntt.h / ntt.c         # bitrev7, modexp, init_ntt_roots, ntt, ntt_inv, ntt_mul
├── keccak.h / keccak.c   # keccakf, sponge ctx, sha3_256, sha3_512, shake128, shake256
├── sample.h / sample.c   # mlkem_prf, sample_poly_cbd, sample_ntt
├── encode.h / encode.c   # byte_encode, byte_decode, compress_poly, decompress_poly
├── kem.h / kem.c         # kpke_keygen/encrypt/decrypt, mlkem_keygen/encaps/decaps
├── random.h / random.s   # randombytes (x86-64 getrandom syscall)
├── kat_mlkem768.h        # embedded ACVP ML-KEM-768 KAT vectors for test.c
├── test.c                # all tests: deterministic unit + ACVP KAT + random stress
├── bench.c               # local benchmark harness with warmup and median rounds
└── Makefile
```

**Why split:** Each `.c` compiles independently. You can test keccak without linking NTT. You can swap `random.s` for a deterministic stub. No `#ifdef TEST` guards needed — test.c simply calls the public APIs.

**Dependency between modules:**
- `reduce.c` depends on `params.h`
- `poly.c` depends on `params.h`, `reduce.h`
- `ntt.c` depends on `params.h`, `reduce.h`, `poly.h`
- `keccak.c` depends on nothing (self-contained)
- `encode.c` depends on `params.h`
- `sample.c` depends on `params.h`, `keccak.h`
- `kem.c` depends on everything

---


## Build System

```makefile
CC = gcc
CFLAGS = -D_GNU_SOURCE -O3 -Wall -Wextra -std=c99
ASFLAGS = -masm=intel
ARCH_CFLAGS = -march=native

OBJS = reduce.o poly.o ntt.o keccak.o encode.o sample.o kem.o random.o
TARGET = testc
BENCH = bench

all: $(TARGET)
$(TARGET): test.o $(OBJS)
	$(CC) $^ -o $@ $(CFLAGS) $(ARCH_CFLAGS)
$(BENCH): bench.o $(OBJS)
	$(CC) $^ -o $@ $(CFLAGS) $(ARCH_CFLAGS)

test: $(TARGET)
	./$(TARGET)
test-reduce: $(TARGET)
	./$(TARGET) reduce
test-ntt: $(TARGET)
	./$(TARGET) ntt
test-keccak: $(TARGET)
	./$(TARGET) keccak
test-encode: $(TARGET)
	./$(TARGET) encode
test-sample: $(TARGET)
	./$(TARGET) sample
test-kem: $(TARGET)
	./$(TARGET) kem
bench-run: $(BENCH)
	./$(BENCH)
size: $(TARGET) $(BENCH)
	size $(TARGET) $(BENCH) *.o
```

The current Makefile builds one test binary and dispatches test groups by command-line argument. This keeps link behavior identical across groups while still allowing `make test-keccak`, `make test-sample`, and `make test-kem` during bottom-up work. `make test-kem` runs the dependency groups plus the ACVP ML-KEM-768 KAT. `make size` records executable and object sizes for experiment notes.

---

## Step 1: Parameters & Types

**Files:** `params.h`, `poly.h`

```c
// params.h
#ifndef PARAMS_H
#define PARAMS_H

// Ring constants
#define N    256
#define Q    3329

// ML-KEM-768 parameters (FIPS 203, Table 2)
#define K    3
#define ETA1 2
#define ETA2 2
#define DU   10
#define DV   4

// Derived byte sizes — eliminates magic numbers everywhere
#define POLY_BYTES       (N * 12 / 8)                          // 384
#define EK_SIZE          (K * POLY_BYTES + 32)                  // 1184
#define DK_PKE_SIZE      (K * POLY_BYTES)                       // 1152
#define DK_SIZE          (DK_PKE_SIZE + EK_SIZE + 32 + 32)     // 2400
#define CT_U_SIZE        (K * N * DU / 8)                       // 960
#define CT_V_SIZE        (N * DV / 8)                           // 128
#define CT_SIZE          (CT_U_SIZE + CT_V_SIZE)                // 1088
#define SHARED_KEY_SIZE  32

// NTT constants
#define NTT_INV_FACTOR   3303   // 128^{-1} mod Q
#define ZETA_PRIMITIVE   17     // primitive 256th root of unity mod Q

#endif
```

```c
// poly.h
#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "params.h"

typedef int16_t poly256[N];

void poly256_add(const poly256 a, const poly256 b, poly256 out);
void poly256_sub(const poly256 a, const poly256 b, poly256 out);

#endif
```

**Why first:** Every module depends on these constants and this type.

**Test:** None needed — just definitions. Verify with static assertions:
```c
_Static_assert(EK_SIZE == 1184, "ek size");
_Static_assert(DK_SIZE == 2400, "dk size");
_Static_assert(CT_SIZE == 1088, "ct size");
```

---

## Step 2: Modular Reduction

**Files:** `reduce.h`, `reduce.c`

**What:** Two reduction functions — one fast path for bounded non-negative values, one general path for possibly-negative values.

```c
// reduce.h
#ifndef REDUCE_H
#define REDUCE_H

#include <stdint.h>
#include "params.h"

#define REDUCE_BARRETT_Q_INV 20158

#ifdef REDUCE_EXTERNAL
int16_t barret_reduce(int32_t a);
#else
static inline int16_t barret_reduce(int32_t a) {
    int32_t t = (int32_t)(((int64_t)a * REDUCE_BARRETT_Q_INV) >> 26);
    a -= t * Q;
    if (a >= Q) a -= Q;
    return (int16_t)a;
}
#endif

// General reduction for possibly-negative a. Result in [0, Q-1].
int16_t reduce_signed(int32_t a);

#endif
```

```c
#define REDUCE_EXTERNAL
#include "reduce.h"

int16_t barret_reduce(int32_t a) {
    int32_t t = (int32_t)(((int64_t)a * REDUCE_BARRETT_Q_INV) >> 26);
    a -= t * Q;
    if (a >= Q) a -= Q;
    return (int16_t)a;
}

int16_t reduce_signed(int32_t a) {
    a = a % Q;
    if (a < 0) a += Q;
    return (int16_t)a;
}
```

**Why two functions:** The forward NTT only produces non-negative bounded intermediates, so Barrett is safe and fast there. The inverse NTT butterfly has a signed term (`u - t`), so that zeta-multiply still uses `reduce_signed`. Measured optimization accepted later: the inverse final scale and `ntt_mul` products are non-negative and bounded below `2*Q*Q`, so they use `barret_reduce` instead of `reduce_signed` in the current implementation.

**Input range for Barrett:** Non-negative `a` through the current hot-path bound `2*Q*Q = 22,164,482`, which fits in int32_t and is covered by tests.

**Test:**
- `barret_reduce(0) == 0`
- `barret_reduce(Q) == 0`
- `barret_reduce(Q + 1) == 1`
- `barret_reduce(Q * Q - 1) == (Q*Q - 1) % Q` — max input boundary
- `barret_reduce(2 * Q * Q - 1) == (2*Q*Q - 1) % Q`
- `barret_reduce(2 * Q * Q) == 0`
- `reduce_signed(-1) == Q - 1`
- `reduce_signed(-Q) == 0`
- `reduce_signed(Q) == 0`
- Spot-check both against `((a % Q) + Q) % Q` for values: 0, 1, -1, 3328, 3329, 3330, -3329, 10000, -10000, 11075584

---

## Step 3: Polynomial Add / Sub

**File:** `poly.c`

**What:** Coefficient-wise addition and subtraction mod q.

```c
void poly256_add(const poly256 a, const poly256 b, poly256 out) {
    for (int i = 0; i < N; i++) {
        int32_t t = (int32_t)a[i] + (int32_t)b[i];
        if (t >= Q) t -= Q;
        out[i] = (int16_t)t;
    }
}

void poly256_sub(const poly256 a, const poly256 b, poly256 out) {
    for (int i = 0; i < N; i++) {
        int32_t t = (int32_t)a[i] - (int32_t)b[i];
        if (t < 0) t += Q;
        out[i] = (int16_t)t;
    }
}
```

**Precondition:** Inputs have coefficients in [0, Q-1].

**Test:**
- Zero + zero = zero
- f + f: each coeff doubles (mod Q)
- Wrap: coeff (Q-1) + 1 = 0
- Sub: 0 - 1 = Q - 1
- Sub: f - f = zero
- Commutativity: a + b == b + a
- In-place: poly256_add(a, b, a) works (output aliases input)

---

## Step 4: NTT Helpers — `bitrev7` and `modexp`

**File:** `ntt.c`

**What:**
- `bitrev7(n)`: Reverse the low 7 bits. Used to compute zeta table indices per FIPS 203.
- `modexp(base, exp)`: Modular exponentiation mod Q via square-and-multiply.

```c
static inline uint16_t bitrev7(uint16_t n) {
    uint16_t r = 0;
    for (int i = 0; i < 7; i++) {
        r = (r << 1) | (n & 1);
        n >>= 1;
    }
    return r;
}

static inline uint16_t modexp(uint16_t base, uint16_t exp) {
    uint32_t result = 1, b = base;
    while (exp > 0) {
        if (exp & 1) result = (result * b) % Q;
        b = (b * b) % Q;
        exp >>= 1;
    }
    return (uint16_t)result;
}
```

**Test:**
- `bitrev7(0) = 0`, `bitrev7(1) = 64`, `bitrev7(2) = 32`, `bitrev7(4) = 16`, `bitrev7(127) = 127`
- `modexp(17, 0) = 1`, `modexp(17, 1) = 17`, `modexp(17, 2) = 289`
- `modexp(2, 10) = 1024`, `modexp(17, 128) = Q - 1 = 3328`, `modexp(17, 256) = 1`

---

## Step 5: NTT Root Tables

**File:** `ntt.c`

**What:** Use two precomputed `static const` tables of 128 entries each:
- `ZETA[i] = 17^bitrev7(i) mod Q` for i = 0..127
- `GAMMA[i] = 17^(2*bitrev7(i) + 1) mod Q` for i = 0..127

The ZETA table is indexed by the NTT butterfly counter `k` (starting at k=1 for forward, k=127 for inverse). The GAMMA table provides the twiddle factors for base-case multiplication (Algorithm 11).

```c
static const uint16_t ZETA[128] = { /* generated and checked values */ };
static const uint16_t GAMMA[128] = { /* generated and checked values */ };

void init_ntt_roots(void) {
    (void)ZETA;  // compatibility no-op; tables are static const
}
```

**Implementation state:** An earlier runtime table-generation version was replaced by checked static tables. This removes root initialization work and keeps `ntt.c` deterministic without mutable global state.

**Key values for verification:**
- ZETA[0] = 17^bitrev7(0) = 17^0 = 1
- ZETA[1] = 17^bitrev7(1) = 17^64 mod 3329 = 1729
- GAMMA[0] = 17^(2*0 + 1) = 17^1 = 17
- GAMMA[1] = 17^(2*64 + 1) = 17^129 mod 3329

**Test:**
- Verify ZETA[0] == 1, GAMMA[0] == 17
- Verify ZETA[1] == 1729

---

## Step 6: Forward NTT (Algorithm 9, FIPS 203)

**File:** `ntt.c`

**Algorithm 9 — NTT(f):**
```
Input: polynomial f with coefficients in Z_q
Output: NTT representation f_hat

f_hat <- copy of f
k <- 1
for len in {128, 64, 32, 16, 8, 4, 2}:     // 7 layers, halving each time
    for start = 0 to 255 step 2*len:
        zeta <- ZETA[k]
        k <- k + 1
        for j = start to start + len - 1:
            t <- barret_reduce(zeta * f_hat[j + len])
            u <- f_hat[j]
            f_hat[j + len] <- u - t          // add Q once if negative
            f_hat[j]       <- barret_reduce(u + t)
return f_hat
```

**Implementation notes:**
- Copy input to output first, then operate in-place on output.
- The product `zeta * f_hat[j+len]` fits in int32_t (max ~3328*3328 = ~11M) and is reduced before the butterfly update.
- The subtraction result is in `(-(Q-1), Q-1)`, so one conditional add of `Q` returns it to [0, Q-1]. The addition path uses `barret_reduce`.
- `k` runs from 1 to 127 (total 127 zeta values used across all layers).

**Test:**
- NTT of the zero polynomial is zero.
- Spot-check with a simple polynomial (e.g., f = [1, 0, 0, ..., 0]).
- Round-trip test (combined with Step 7): `ntt_inv(ntt(f)) == f`.

---

## Step 7: Inverse NTT (Algorithm 10, FIPS 203)

**File:** `ntt.c`

**Algorithm 10 — NTT^{-1}(f_hat):**
```
Input: NTT-domain polynomial f_hat
Output: polynomial f with coefficients in Z_q

f <- copy of f_hat
k <- 127
for len in {2, 4, 8, 16, 32, 64, 128}:     // 7 layers, doubling each time
    for start = 0 to 255 step 2*len:
        zeta <- ZETA[k]
        k <- k - 1
        for j = start to start + len - 1:
            t <- f[j]
            f[j]       <- barret_reduce(t + f[j + len])
            f[j + len] <- reduce_signed(zeta * (int32_t)(f[j+len] - t))
for i = 0 to 255:
    f[i] <- barret_reduce(f[i] * NTT_INV_FACTOR)   // multiply by 128^{-1} mod q = 3303
return f
```

**Implementation notes:**
- The subtraction `f[j+len] - t` can be negative, so use `reduce_signed` for the zeta-multiply path.
- The addition `t + f[j+len]` is always non-negative (both in [0, Q-1]), so `barret_reduce` works.
- The final multiplication by 3303 normalizes the transform (128^{-1} mod Q). The product is non-negative and below `Q*Q`, so the current implementation uses `barret_reduce` here.
- `k` starts at 127 and decrements, consuming 127 zeta values total (matching the forward NTT).

**Test (critical — validates both forward and inverse):**
- `ntt_inv(ntt(f)) == f` for several random polynomials with coefficients in [0, Q-1].
- Linearity: `ntt_inv(ntt(a) + ntt(b)) == poly_add(a, b)`.

---

## Step 8: NTT-Domain Multiplication (Algorithm 11, FIPS 203)

**File:** `ntt.c`

**Algorithm 11 — MultiplyNTTs(f_hat, g_hat):**

For each of 128 pairs (i = 0..127), apply BaseCaseMultiply:

```
BaseCaseMultiply(a0, a1, b0, b1, gamma):
    c0 = a0*b0 + a1*b1*gamma   (mod q)
    c1 = a0*b1 + a1*b0         (mod q)
    return (c0, c1)
```

Where: `a0 = f_hat[2i]`, `a1 = f_hat[2i+1]`, `b0 = g_hat[2i]`, `b1 = g_hat[2i+1]`, `gamma = GAMMA[i] = 17^(2*bitrev7(i)+1) mod q`.

**Semantics:** In the NTT domain, each pair of coefficients (2i, 2i+1) represents an element of Z_q[X]/(X^2 - gamma_i). The base-case multiply is degree-1 polynomial multiplication modulo (X^2 - gamma_i).

**Implementation:**
```c
void ntt_mul(const poly256 a, const poly256 b, poly256 out) {
    for (int i = 0; i < 128; i++) {
        int32_t a0 = a[2*i], a1 = a[2*i+1];
        int32_t b0 = b[2*i], b1 = b[2*i+1];
        int32_t g  = GAMMA[i];

        // Reduce a1*b1 first to keep c0 below 2*Q*Q.
        int32_t a1b1 = barret_reduce(a1 * b1);
        out[2*i]   = barret_reduce(a0 * b0 + a1b1 * g);
        out[2*i+1] = barret_reduce(a0 * b1 + a1 * b0);
    }
}
```

**Overflow and reduction analysis:** `a1*b1` is at most 3328^2 = ~11M, fits in int32_t. After `barret_reduce`, it is < 3329. Then `a1b1 * g` is at most 3328 * 3328 = ~11M, and `a0*b0 + a1b1*g` is below `2*Q*Q`, which fits in int32_t and is inside the tested Barrett range. `c1` has the same non-negative bound. This avoids `reduce_signed` calls in the NTT-domain multiplication hot path.

**Test:**
- Multiply two known polynomials in NTT domain, inverse-NTT the result, compare against naive schoolbook multiplication mod (X^256 + 1).
- `ntt_inv(ntt_mul(ntt(a), ntt(b))) == schoolbook_mul(a, b)`.

---

## Step 9: Keccak-f[1600] Permutation

**File:** `keccak.c`

**What:** 24-round permutation on `uint64_t state[25]` (= 1600 bits = 200 bytes). The five sub-steps per round:

1. **Theta** — column parity mixing:
   ```
   C[x] = state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20]   for x=0..4
   D[x] = C[(x+4)%5] ^ ROTL64(C[(x+1)%5], 1)
   state[i] ^= D[i % 5]   for i=0..24
   ```

2. **Rho + Pi** — lane rotation and permutation:
   ```
   temp[pi[i]] = ROTL64(state[i], rho[i])   for i=0..23
   // state[0] is unchanged by Pi
   ```

3. **Chi** — row-wise nonlinear mixing:
   ```
   For each row y (5 lanes): state[y*5+x] ^= (~state[y*5+(x+1)%5]) & state[y*5+(x+2)%5]
   ```

4. **Iota** — round constant XOR:
   ```
   state[0] ^= RC[round]
   ```

**Constants to hardcode:**
- `rc[24]`: Round constants (64-bit each). First few: 0x0000000000000001, 0x0000000000008082, 0x800000000000808A, ...
- `rho[24]`: Rotation offsets: {1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,44,20,61} (for lanes 1..24, not lane 0)
- `pi[24]`: Permutation: {10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1}

**Test:** Apply keccakf to the all-zero state, compare output against the known Keccak test vector:
```
Input:  25 * 0x0000000000000000
Output: state[0] = 0xF1258F7940E1DDE7, state[1] = 0x84D5CCF933C0478A, ...
```
(Full 25 output words from the Keccak reference.)

---

## Step 10: Keccak Sponge (absorb / squeeze)

**File:** `keccak.c`

**What:** The sponge construction parameterized by rate (in bytes):

```c
typedef struct {
    uint64_t state[25];
    int rate_bytes;    // rate in bytes (capacity = 200 - rate)
    int absorb_pos;    // current absorption position in bytes
    int finalized;     // has padding been applied?
} keccak_ctx;
```

**Operations:**

1. **`keccak_init(ctx, rate_bytes)`**: Zero the state, set rate, `absorb_pos = 0`, `finalized = 0`.

2. **`keccak_absorb(ctx, data, len)`**: XOR data bytes into the state (treating state as a byte array), permuting whenever a full rate-block is absorbed:
   ```
   for each byte of data:
       state_bytes[absorb_pos] ^= byte
       absorb_pos++
       if absorb_pos == rate_bytes:
           keccakf(state)
           absorb_pos = 0
   ```

3. **`keccak_finalize(ctx, domain_byte)`**: Apply FIPS 202 padding:
   ```
   state_bytes[absorb_pos] ^= domain_byte   // 0x06 for SHA3, 0x1F for SHAKE
   state_bytes[rate_bytes - 1] ^= 0x80       // pad10*1
   keccakf(state)
   absorb_pos = 0
   finalized = 1
   ```

4. **`keccak_squeeze(ctx, out, outlen)`**: Extract bytes from the state:
   ```
   for each output byte needed:
       if absorb_pos == rate_bytes:
           keccakf(state)
           absorb_pos = 0
       out[i] = state_bytes[absorb_pos]
       absorb_pos++
   ```

**Implementation note:** Access state as `uint8_t *` pointing to the `uint64_t[25]` array. This works on little-endian (x86-64). For portability, use explicit byte extraction, but for this project little-endian is fine.

**Test:** Tested indirectly through SHA3 and SHAKE in the next steps.

---

## Step 11: SHA3-256 and SHA3-512

**File:** `keccak.c`

**What:** Fixed-output hash functions built on the sponge.

```c
void sha3_256(const uint8_t *in, size_t inlen, uint8_t out[32]) {
    keccak_ctx ctx;
    keccak_init(&ctx, 136);          // rate = 136 bytes (capacity = 64)
    keccak_absorb(&ctx, in, inlen);
    keccak_finalize(&ctx, 0x06);     // SHA3 domain separator
    keccak_squeeze(&ctx, out, 32);
}

void sha3_512(const uint8_t *in, size_t inlen, uint8_t out[64]) {
    keccak_ctx ctx;
    keccak_init(&ctx, 72);           // rate = 72 bytes (capacity = 128)
    keccak_absorb(&ctx, in, inlen);
    keccak_finalize(&ctx, 0x06);
    keccak_squeeze(&ctx, out, 64);
}
```

In FIPS 203 naming: **G = sha3_512**, **H = sha3_256**.

**Test against NIST vectors (FIPS 202):**

| Function | Input | Expected (hex, first bytes) |
|----------|-------|-----------------------------|
| SHA3-256 | "" (empty) | `a7ffc6f8bf1ed76651c14756a061d662...` |
| SHA3-256 | "abc" | `3a985da74fe225b2045c172d6bd390bd...` |
| SHA3-512 | "" (empty) | `a69f73cca23a9ac5c8b567dc185a756e...` |
| SHA3-512 | "abc" | `b751850b1a57168a5693cd924b6b096e...` |

Full test vectors are in the existing `test.c` on the `main` branch.

---

## Step 12: SHAKE-128 and SHAKE-256

**File:** `keccak.c`

**What:** Extendable-output functions (XOFs) — same sponge, different rate and domain byte.

```c
void shake128(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen) {
    keccak_ctx ctx;
    keccak_init(&ctx, 168);          // rate = 168 bytes
    keccak_absorb(&ctx, in, inlen);
    keccak_finalize(&ctx, 0x1F);     // SHAKE domain separator
    keccak_squeeze(&ctx, out, outlen);
}

void shake256(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen) {
    keccak_ctx ctx;
    keccak_init(&ctx, 136);          // rate = 136 bytes
    keccak_absorb(&ctx, in, inlen);
    keccak_finalize(&ctx, 0x1F);
    keccak_squeeze(&ctx, out, outlen);
}
```

**FIPS 203 role:**
- **XOF(seed, a, b)** = SHAKE-128(seed || byte(a) || byte(b)); Algorithm 12 generates matrix entries with `SampleNTT(XOF(rho, j, i))`
- **PRF(s, b)** = SHAKE-256(s || byte(b)) — used for CBD sampling
- **J(z || c)** = SHAKE-256(z || c) with 32-byte output — implicit rejection key

**Test against NIST vectors:**
- SHAKE-128("") with 32 bytes output: `7f9c2ba4e88f827d616045507605853e...`
- SHAKE-256("") with 32 bytes output: `46b9dd2b0ba88d13233b3feb743eeb24...`
- SHAKE-128 and SHAKE-256 with 200 bytes of 0xa3 as input

---

## Step 13: Random Bytes

**File:** `random.h`, `random.s`

**What:** x86-64 assembly using `getrandom` syscall (#318 on Linux) with a 256-byte static buffer for efficiency.

```asm
; random.s - Intel syntax, x86-64
; void randombytes(uint8_t *out, size_t outlen)
;
; Strategy:
;   Maintain a 256-byte buffer filled by getrandom.
;   Fast path for 16-byte requests: SSE movups load/store.
;   Generic path: rep movsb for arbitrary sizes.
```

**Design:**
- `.bss` section: 256-byte `random_buffer` + 8-byte `bytes_in_buffer` counter.
- When buffer is empty (or insufficient), refill via `syscall(SYS_getrandom, buf, 256, 0)`.
- Copy requested bytes from buffer, decrement counter.
- Returns 0 on success, -1 on syscall failure.

**Test:**
- Generate two 16-byte buffers, assert they differ (probabilistic, overwhelming probability).
- Generate 1000 bytes, assert not all zero.

---

## Step 14: Byte Encoding / Decoding (Algorithms 4 & 5, FIPS 203)

**File:** `encode.c`

**Algorithm 4 — ByteEncode_d(F):**
```
Input:  F[0..255], each in [0, 2^d)
Output: B[0..32d-1] (byte array)

Treat output as a bitstream. For each i=0..255:
    a <- F[i]
    for j = 0 to d-1:
        bit[i*d + j] <- a mod 2
        a <- a >> 1
Pack bits into bytes, LSB-first.
```

**Algorithm 5 — ByteDecode_d(B):**
```
Input:  B[0..32d-1] (byte array)
Output: F[0..255]

Treat input as a bitstream. For each i=0..255:
    F[i] <- sum_{j=0}^{d-1} bit[i*d + j] * 2^j
    if d == 12: F[i] <- F[i] mod q
```

**Output sizes:** `256 * d / 8 = 32*d` bytes.

| d | Bytes | Usage |
|---|-------|-------|
| 1 | 32 | Message encoding |
| 4 | 128 | Ciphertext v (dv=4) |
| 10 | 320 | Ciphertext u per polynomial (du=10) |
| 12 | 384 | Key polynomials (exact representation) |

**Implementation approach:** Process bits via shifting and masking on the byte array. For d=12, two coefficients span exactly 3 bytes, enabling an efficient byte-level implementation:
```
For i = 0 to 127:
    byte offset = i * 3
    coeff[2i]   = B[offset] | ((B[offset+1] & 0x0F) << 8)
    coeff[2i+1] = (B[offset+1] >> 4) | (B[offset+2] << 4)
```

Also implement `byte_encode_u16(d, vals, out)` for encoding from `uint16_t` arrays (needed after compression which produces uint16_t values).

**Test:**
- Round-trip for d = 1, 4, 10, 12: `ByteDecode(d, ByteEncode(d, F)) == F` (with coefficients masked to d bits).
- Edge: all-zeros, all max-value (masked to d bits), alternating pattern.

---

## Step 15: Compress / Decompress (Section 4.2.1, FIPS 203)

**File:** `encode.c`

**Compress_d(x):**
```
round(2^d / q * x) mod 2^d
= floor((2^d * x + q/2) / q) mod 2^d
= ((x << d) + (Q + 1) / 2) / Q) & ((1 << d) - 1)
```

**Decompress_d(y):**
```
round(q / 2^d * y)
= (q * y + 2^(d-1)) >> d
= (Q * y + (1 << (d-1))) >> d
```

These are applied coefficient-wise to a polynomial.

**Implementation:**
```c
void compress_poly(int d, const poly256 x, uint16_t out[N]) {
    for (int i = 0; i < N; i++) {
        uint32_t val = (uint32_t)x[i];
        out[i] = (uint16_t)(((val << d) + (Q + 1) / 2) / Q) & ((1 << d) - 1);
    }
}

void decompress_poly(int d, const uint16_t in[N], poly256 out) {
    for (int i = 0; i < N; i++) {
        out[i] = (int16_t)((Q * (uint32_t)in[i] + (1 << (d - 1))) >> d);
    }
}
```

**Properties:**
- `Compress_1(x)`: 0 maps to 0, values near Q/2 = 1664.5 map to 1. Specifically, `Compress_1(0) = 0`, `Compress_1(1665) = 1` (since (Q+1)/2 = 1665).
- Round-trip `Decompress(d, Compress(d, x))` approximates x with error at most `round(q / 2^(d+1))`.

**Test:**
- `Compress_1(0) == 0`, `Compress_1(1665) == 1`
- Round-trip error bound for d = 1, 4, 10: for all x in [0, Q-1], compute `|Decompress(Compress(x)) - x|` (mod Q, taking the shorter distance around the ring), verify it never exceeds `round(Q / 2^(d+1))`.
  - d=1: max error <= 832
  - d=4: max error <= 104
  - d=10: max error <= 1
- Edge cases: x = 0, x = Q-1.

---

## Step 16: PRF — SHAKE-256 Wrapper

**File:** `sample.c`

**What:** `PRF(s, b)` = SHAKE-256(s || b), outputting `64 * eta` bytes.

```c
void mlkem_prf(int eta, const uint8_t *data, size_t dlen, uint8_t b, uint8_t *out) {
    uint8_t tmp[dlen + 1];
    memcpy(tmp, data, dlen);
    tmp[dlen] = b;
    shake256(tmp, dlen + 1, out, 64 * eta);
}
```

In FIPS 203, `data` is always the 32-byte seed sigma (or r in encryption), and `b` is a counter N (0..8 for k=3).

**Test:**
- Deterministic: same (data, b) always produces the same output.
- Different b values produce different outputs.

---

## Step 17: SamplePolyCBD (Algorithm 7/8, FIPS 203)

**File:** `sample.c`

**Algorithm 7 — SamplePolyCBD_eta(B):**

For ML-KEM-768, eta1 = eta2 = 2. Input: `64 * eta = 128` bytes = 1024 bits.

```
For eta = 2:
    b <- BytesToBits(B)    // 1024 bits from 128 bytes
    for i = 0 to 255:
        x = b[4*i + 0] + b[4*i + 1]              // sum of 2 bits
        y = b[4*i + 2] + b[4*i + 3]              // sum of 2 bits
        f[i] = (x - y) mod q                      // in {-2, -1, 0, 1, 2}
```

**Bit extraction:** To get bit j from byte array B: `(B[j/8] >> (j%8)) & 1`.

**Output range:** Coefficients in {Q-eta, ..., Q-1, 0, 1, ..., eta} (i.e., {-eta, ..., eta} mod Q).

**Implementation note:** For negative results, add Q to get the canonical representative in [0, Q-1].

**Test:**
- All output coefficients should be in [0, eta] union [Q-eta, Q-1].
- Statistical: over 1000 samples (256,000 coefficients), verify:
  - Mean is approximately 0 (tolerance: |mean| < 0.05)
  - Variance is approximately eta/2 = 1.0 (tolerance: |var - 1.0| < 0.1)
  - All 5 values {-2, -1, 0, 1, 2} appear (no bit-extraction bug silently zeroing a nibble)

---

## Step 18: SampleNTT (Algorithm 6, FIPS 203)

**File:** `sample.c`

**Algorithm 6 — SampleNTT(B):**

Input: byte stream from XOF(rho, j, i) = SHAKE-128(rho || byte(j) || byte(i)).

```
ctx <- SHAKE-128 init
absorb(rho || j || i)
finalize()

a_hat[256]
j <- 0
while j < 256:
    squeeze 3 bytes: B[0], B[1], B[2]
    d1 <- B[0] + 256 * (B[1] mod 16)          // low 12 bits of (B[0] || B[1])
    d2 <- floor(B[1] / 16) + 16 * B[2]        // high 4 bits of B[1] || B[2] = next 12 bits
    if d1 < Q:
        a_hat[j] <- d1
        j <- j + 1
    if d2 < Q and j < 256:
        a_hat[j] <- d2
        j <- j + 1
return a_hat
```

**Implementation:** Use the streaming sponge interface — absorb the seed, finalize, then consume 3 bytes at a time in a loop. Each 3 bytes yields two 12-bit candidates; reject values >= 3329.

**Current optimization:** `sample_ntt_inner` avoids calling the generic `keccak_squeeze(ctx, b, 3)` for every candidate pair. Instead, `sample_squeeze24` reads three bytes directly from the SHAKE128 rate area of `keccak_ctx`, calls `keccakf` only when `pos == 168`, and returns the 24-bit word for parsing. This keeps the same byte stream while removing many tiny squeeze calls. `mlkem_prf` still uses the generic squeeze API.

**Note on indices:** FIPS 203 Algorithm 12 (K-PKE.KeyGen) line 6 calls `SampleNTT(XOF(rho, j, i))` — note the order is `(j, i)` not `(i, j)`. The XOF input is `rho || byte(j) || byte(i)`.

**Test:**
- All 256 output coefficients in [0, Q).
- Same (seed, i, j) always gives the same polynomial.
- Different (i, j) give different polynomials.
- Rejection rate check: over many runs, count total 3-byte blocks consumed to fill 256 coefficients. Expected: ~256 / (2 * 3329/4096) = ~157 blocks. Actual rejection rate should be ~18.7% per candidate ((4096-3329)/4096). If the rate is wildly off (e.g., 0% or 50%), the 12-bit parsing is wrong.

---

## Step 19: K-PKE.KeyGen (Algorithm 12, FIPS 203)

**File:** `kem.c`

**Algorithm 12 — K-PKE.KeyGen(d):**

```
Input:  d[32] — 32-byte seed
Output: ek_pke[EK_SIZE], dk_pke[DK_PKE_SIZE]

1.  (rho, sigma) <- G(d || k)         // G = SHA3-512; k = 3 as a single byte
                                       // rho = first 32 bytes, sigma = next 32 bytes

2.  N <- 0                            // counter for PRF calls

3.  for i = 0 to K-1:                 // Generate matrix A_hat (K x K)
        for j = 0 to K-1:
            A_hat[i][j] <- SampleNTT(XOF(rho, j, i))   // NOTE: XOF(rho, j, i) not (i, j)

4.  for i = 0 to K-1:                 // Sample secret vector s
        s[i] <- SamplePolyCBD_ETA1(PRF(sigma, N))
        N <- N + 1

5.  for i = 0 to K-1:                 // Sample error vector e
        e[i] <- SamplePolyCBD_ETA1(PRF(sigma, N))
        N <- N + 1

6.  s_hat[i] <- NTT(s[i])   for i = 0..K-1
7.  e_hat[i] <- NTT(e[i])   for i = 0..K-1

8.  for i = 0 to K-1:                 // t_hat = A_hat * s_hat + e_hat
        t_hat[i] <- e_hat[i]
        for j = 0 to K-1:
            t_hat[i] <- t_hat[i] + A_hat[i][j] * s_hat[j]   // ntt_mul then ntt_add

9.  ek_pke <- ByteEncode_12(t_hat[0]) || ... || ByteEncode_12(t_hat[K-1]) || rho
    // = POLY_BYTES * K + 32 = EK_SIZE = 1184 bytes

10. dk_pke <- ByteEncode_12(s_hat[0]) || ... || ByteEncode_12(s_hat[K-1])
    // = POLY_BYTES * K = DK_PKE_SIZE = 1152 bytes

11. return (ek_pke, dk_pke)
```

**Byte layout of ek_pke (1184 bytes):**
```
[0..383]     ByteEncode_12(t_hat[0])
[384..767]   ByteEncode_12(t_hat[1])
[768..1151]  ByteEncode_12(t_hat[2])
[1152..1183] rho (32 bytes)
```

**Byte layout of dk_pke (1152 bytes):**
```
[0..383]     ByteEncode_12(s_hat[0])
[384..767]   ByteEncode_12(s_hat[1])
[768..1151]  ByteEncode_12(s_hat[2])
```

**Test:**
- Deterministic: fixed d -> fixed (ek_pke, dk_pke).
- Output sizes are exactly EK_SIZE and DK_PKE_SIZE bytes.
- All decoded t_hat coefficients are in [0, Q-1].

---

## Step 20: K-PKE.Encrypt (Algorithm 13, FIPS 203)

**File:** `kem.c`

**Algorithm 13 — K-PKE.Encrypt(ek_pke, m, r):**

```
Input:  ek_pke[EK_SIZE], m[32] (message), r[32] (randomness)
Output: c[CT_SIZE] (ciphertext)

1.  for i = 0 to K-1:
        t_hat[i] <- ByteDecode_12(ek_pke[POLY_BYTES*i .. POLY_BYTES*(i+1)-1])

2.  rho <- ek_pke[POLY_BYTES*K .. POLY_BYTES*K+31]

3.  for i = 0 to K-1:                 // Re-generate A_hat
        for j = 0 to K-1:
            A_hat[i][j] <- SampleNTT(XOF(rho, j, i))

4.  N <- 0

5.  for i = 0 to K-1:                 // Sample randomness vector r_vec
        r_vec[i] <- SamplePolyCBD_ETA1(PRF(r, N))
        N <- N + 1

6.  for i = 0 to K-1:                 // Sample error vector e1
        e1[i] <- SamplePolyCBD_ETA2(PRF(r, N))
        N <- N + 1

7.  e2 <- SamplePolyCBD_ETA2(PRF(r, N))   // Single error polynomial

8.  r_hat[i] <- NTT(r_vec[i])   for i = 0..K-1

9.  for i = 0 to K-1:                 // u = NTT^{-1}(A_hat^T * r_hat) + e1
        // Note: A_hat^T[i][j] = A_hat[j][i]
        tmp <- 0
        for j = 0 to K-1:
            tmp <- tmp + A_hat[j][i] * r_hat[j]   // ntt_mul then ntt_add
        u[i] <- NTT_inv(tmp) + e1[i]              // poly_add in normal domain

10. mu <- Decompress_1(ByteDecode_1(m))   // each bit b -> round(Q/2 * b) = 0 or 1665

11. // v = NTT^{-1}(t_hat^T * r_hat) + e2 + mu
    tmp <- 0
    for i = 0 to K-1:
        tmp <- tmp + t_hat[i] * r_hat[i]   // ntt_mul then ntt_add
    v <- NTT_inv(tmp) + e2 + mu            // two poly_adds

12. c1 <- ByteEncode_DU(Compress_DU(u[0])) || ... || ByteEncode_DU(Compress_DU(u[K-1]))
    // = 32 * DU * K = CT_U_SIZE = 960 bytes

13. c2 <- ByteEncode_DV(Compress_DV(v))
    // = 32 * DV = CT_V_SIZE = 128 bytes

14. return c1 || c2   // CT_SIZE = 1088 bytes
```

**Ciphertext byte layout (1088 bytes):**
```
[0..319]     ByteEncode_10(Compress_10(u[0]))
[320..639]   ByteEncode_10(Compress_10(u[1]))
[640..959]   ByteEncode_10(Compress_10(u[2]))
[960..1087]  ByteEncode_4(Compress_4(v))
```

**Test:**
- Deterministic: fixed (ek, m, r) -> fixed c.
- Output ciphertext is exactly CT_SIZE bytes.

---

## Step 21: K-PKE.Decrypt (Algorithm 14, FIPS 203)

**File:** `kem.c`

**Algorithm 14 — K-PKE.Decrypt(dk_pke, c):**

```
Input:  dk_pke[DK_PKE_SIZE], c[CT_SIZE]
Output: m[32]

1.  for i = 0 to K-1:
        u[i] <- Decompress_DU(ByteDecode_DU(c[32*DU*i .. 32*DU*(i+1)-1]))
        // ByteDecode_10 on 320-byte chunks, then Decompress_10

2.  v <- Decompress_DV(ByteDecode_DV(c[CT_U_SIZE .. ]))
    // ByteDecode_4 on last 128 bytes, then Decompress_4

3.  for i = 0 to K-1:
        s_hat[i] <- ByteDecode_12(dk_pke[POLY_BYTES*i .. POLY_BYTES*(i+1)-1])

4.  // w = v - NTT^{-1}(s_hat^T * NTT(u))
    tmp <- 0
    for i = 0 to K-1:
        u_hat[i] <- NTT(u[i])
        tmp <- tmp + s_hat[i] * u_hat[i]    // ntt_mul then ntt_add
    w <- v - NTT_inv(tmp)                    // poly_sub in normal domain

5.  m <- ByteEncode_1(Compress_1(w))
    // Each coefficient of w: if closer to 0, bit=0; if closer to Q/2, bit=1
    // 256 bits = 32 bytes

6.  return m
```

**Decryption correctness intuition:** `w = v - s^T * u`. Substituting:
- `v = t^T * r + e2 + mu = (A*s + e)^T * r + e2 + mu`
- `s^T * u = s^T * (A^T * r + e1)`
- `w = s^T * A^T * r + e^T * r + e2 + mu - s^T * A^T * r - s^T * e1`
- `w = mu + (e^T * r + e2 - s^T * e1)` — the noise term is small if s, e, r, e1, e2 are small.

**Bit recovery:** `Compress_1(w_i)` rounds `w_i * 2 / Q`. If w_i is near 0, result is 0. If w_i is near Q/2 = 1665, result is 1. The threshold is Q/4 = 832.

**Test:**
- **Full round-trip:** `K-PKE.Decrypt(dk, K-PKE.Encrypt(ek, m, r)) == m` with deterministic seed.
- Test with all-zero message and all-one message (32 bytes of 0xFF).

---

## Step 22: ML-KEM.KeyGen (Algorithm 15, FIPS 203)

**File:** `kem.c`

**Algorithm 15 — ML-KEM.KeyGen():**

```
Input:  (implicit: OS randomness)
Output: ek[EK_SIZE], dk[DK_SIZE]

1.  z <- random 32 bytes
2.  d <- random 32 bytes
3.  (ek_PKE, dk_PKE) <- K-PKE.KeyGen(d)
4.  ek <- ek_PKE                    // EK_SIZE bytes
5.  dk <- dk_PKE || ek || H(ek) || z
    //   = DK_PKE_SIZE + EK_SIZE + 32 + 32 = DK_SIZE bytes
6.  return (ek, dk)
```

**Byte layout of dk (2400 bytes):**
```
[0..1151]     dk_PKE (s_hat encoded)
[1152..2335]  ek (= ek_PKE = t_hat encoded || rho)
[2336..2367]  H(ek) = SHA3-256(ek) — 32 bytes
[2368..2399]  z — 32 bytes (implicit rejection seed)
```

**For deterministic testing:** accept `(d, z)` as explicit parameters instead of generating them randomly.

**Test:**
- Output sizes: ek = EK_SIZE, dk = DK_SIZE.
- `dk[DK_PKE_SIZE .. DK_PKE_SIZE+EK_SIZE-1] == ek` (dk contains ek as a substring).
- `dk[DK_PKE_SIZE+EK_SIZE .. DK_PKE_SIZE+EK_SIZE+31] == SHA3-256(ek)`.

---

## Step 23: ML-KEM.Encaps (Algorithm 16, FIPS 203)

**File:** `kem.c`

**Algorithm 16 — ML-KEM.Encaps(ek):**

```
Input:  ek[EK_SIZE]
Output: K[SHARED_KEY_SIZE] (shared key), c[CT_SIZE] (ciphertext)

1.  m <- random 32 bytes
2.  (K, r) <- G(m || H(ek))         // G = SHA3-512
    // K = first 32 bytes, r = next 32 bytes
3.  c <- K-PKE.Encrypt(ek, m, r)
4.  return (K, c)
```

**For deterministic testing:** accept m as an explicit parameter.

**Test:**
- Deterministic: fixed (ek, m) -> fixed (K, c).
- K is SHARED_KEY_SIZE bytes, c is CT_SIZE bytes.

---

## Step 24: ML-KEM.Decaps (Algorithm 17, FIPS 203)

**File:** `kem.c`

**Algorithm 17 — ML-KEM.Decaps(dk, c):**

```
Input:  dk[DK_SIZE], c[CT_SIZE]
Output: K[SHARED_KEY_SIZE] (shared key)

1.  dk_PKE <- dk[0 .. DK_PKE_SIZE-1]
2.  ek_PKE <- dk[DK_PKE_SIZE .. DK_PKE_SIZE+EK_SIZE-1]
3.  h      <- dk[DK_PKE_SIZE+EK_SIZE .. DK_PKE_SIZE+EK_SIZE+31]       // = H(ek)
4.  z      <- dk[DK_PKE_SIZE+EK_SIZE+32 .. DK_PKE_SIZE+EK_SIZE+63]

5.  m' <- K-PKE.Decrypt(dk_PKE, c)

6.  (K', r') <- G(m' || h)            // G = SHA3-512

7.  K_bar <- J(z || c)                // J = SHAKE-256(z || c), 32-byte output
    // This is the implicit rejection key

8.  c' <- K-PKE.Encrypt(ek_PKE, m', r')

9.  if c == c':                        // constant-time comparison!
        return K'
    else:
        return K_bar                   // implicit rejection
```

**Constant-time comparison:** The comparison `c == c'` MUST be done in constant time to prevent timing side-channels. Use a byte-by-byte XOR-and-OR accumulator:
```c
uint8_t diff = 0;
for (int i = 0; i < CT_SIZE; i++)
    diff |= c[i] ^ c_prime[i];
// diff == 0 iff c == c'
```

Then use a constant-time conditional select to choose between K' and K_bar:
```c
uint8_t mask = (uint8_t)(-(diff == 0));  // 0xFF if equal, 0x00 if not
for (int i = 0; i < SHARED_KEY_SIZE; i++)
    K_out[i] = (K_prime[i] & mask) | (K_bar[i] & ~mask);
```

**Implicit rejection:** If the ciphertext was tampered with, decryption will recover a wrong m', the re-encryption will produce a different c', and the output will be `J(z || c)` — which is deterministic per (z, c) but unpredictable to the attacker (since z is secret). This prevents chosen-ciphertext attacks.

**Test:**
- **Happy path:** `Decaps(dk, c)` returns the same K that `Encaps` produced.
- **Rejection path:** Flip a byte in c, verify Decaps returns 32 bytes but a *different* key.
- **Rejection determinism:** Flip the same byte in c twice (same tampered ciphertext), verify the rejection key is identical both times. This confirms `J(z || c)` is deterministic.

---

## Step 25: NIST Known-Answer Tests (KATs)

**Files:** `test.c`, `kat_mlkem768.h`

**What:** Verify the implementation against independent NIST ACVP ML-KEM-768 vectors for FIPS 203 compatibility.

The current KAT fixes all random inputs and checks byte-for-byte outputs:

```c
void test_mlkem768_kat(void) {
    uint8_t ek[EK_SIZE], dk[DK_SIZE];
    uint8_t c[CT_SIZE], k[SHARED_KEY_SIZE], k_dec[SHARED_KEY_SIZE];

    mlkem_keygen_deterministic(KAT_KEYGEN_D, KAT_KEYGEN_Z, ek, dk);
    assert(memcmp(ek, KAT_KEYGEN_EK, EK_SIZE) == 0);
    assert(memcmp(dk, KAT_KEYGEN_DK, DK_SIZE) == 0);

    mlkem_encaps_deterministic(KAT_ENCAP_EK, KAT_ENCAP_M, k, c);
    assert(memcmp(k, KAT_ENCAP_K, SHARED_KEY_SIZE) == 0);
    assert(memcmp(c, KAT_ENCAP_C, CT_SIZE) == 0);

    mlkem_decaps(KAT_ENCAP_DK, KAT_ENCAP_C, k_dec);
    assert(memcmp(k_dec, KAT_ENCAP_K, SHARED_KEY_SIZE) == 0);
}
```

**Why this is the most important compatibility test:** Self-consistency tests (encrypt then decrypt) can pass with a wrong implementation — e.g., if you swap (i,j) in SampleNTT, both keygen and encrypt make the same "mistake" and it still round-trips. KAT tests catch this class of error because they compare against an independent reference implementation.

**Current vector source:** `kat_mlkem768.h` embeds one ML-KEM-768 keyGen case (`tgId=2`, `tcId=26`) and one encapsulation/decapsulation case (`tgId=2`, `tcId=26`) from NIST ACVP-Server:
- `ML-KEM-keyGen-FIPS203/internalProjection.json`
- `ML-KEM-encapDecap-FIPS203/internalProjection.json`

Recorded source SHA-256:
- keyGen: `d7a62a2c3476957f56dd8d24f9004ea6776ccfe995ffe71a65bb9506dc9c7b1b`
- encapDecap: `f1e22b7d399dde7bf61b838770c658a380e4b1cfc4bd395dbed9ec6c1d977d9d`

**Scope:** This is not exhaustive ACVP certification coverage. It is an independent compatibility smoke test that checks deterministic keygen `ek/dk`, deterministic encaps `K/c`, and decaps `K` against official FIPS 203 vectors. Expanding to more ACVP cases is a future compatibility hardening step, not a prerequisite for optimization experiments.

**Implementation requirement:** The keygen and encaps functions expose deterministic variants that accept explicit random inputs (`d`, `z`, `m`) instead of calling `randombytes`. These are required for KATs and are also useful for deterministic debugging and benchmarking.

---

## Step 26: Final Integration & Stress Test

**File:** `test.c`

**What:** End-to-end test with OS randomness.

```c
void test_mlkem_e2e(void) {
    uint8_t ek[EK_SIZE], dk[DK_SIZE];
    uint8_t K_enc[SHARED_KEY_SIZE], K_dec[SHARED_KEY_SIZE];
    uint8_t c[CT_SIZE];

    // Generate keys
    mlkem_keygen(ek, dk);

    // Encapsulate
    mlkem_encaps(ek, K_enc, c);

    // Decapsulate
    mlkem_decaps(dk, c, K_dec);

    // Shared keys must match
    assert(memcmp(K_enc, K_dec, SHARED_KEY_SIZE) == 0);

    // Rejection test: flip a byte
    c[0] ^= 0x01;
    uint8_t K_reject[SHARED_KEY_SIZE];
    mlkem_decaps(dk, c, K_reject);
    assert(memcmp(K_enc, K_reject, SHARED_KEY_SIZE) != 0);  // must differ

    // Rejection determinism: same tampered ciphertext -> same rejection key
    uint8_t K_reject2[SHARED_KEY_SIZE];
    mlkem_decaps(dk, c, K_reject2);
    assert(memcmp(K_reject, K_reject2, SHARED_KEY_SIZE) == 0);

    // Current lightweight stress: run 10 iterations with fresh randomness
    for (int iter = 0; iter < 10; iter++) {
        mlkem_keygen(ek, dk);
        mlkem_encaps(ek, K_enc, c);
        mlkem_decaps(dk, c, K_dec);
        assert(memcmp(K_enc, K_dec, SHARED_KEY_SIZE) == 0);
    }
}
```

---

## Test Architecture

### Test Organization

```c
// test.c
#include <assert.h>
#include <string.h>
#include <stdio.h>

// Include all module headers
#include "params.h"
#include "reduce.h"
#include "poly.h"
#include "ntt.h"
#include "keccak.h"
#include "encode.h"
#include "sample.h"
#include "kem.h"
#include "kat_mlkem768.h"
#include "random.h"

static void run_reduce_group(void);
static void run_ntt_group(void);
static void run_keccak_group(void);
static void run_encode_group(void);
static void run_sample_group(void);
static void run_kem_group(void);        // includes ML-KEM deterministic tests + ACVP KAT
static void test_random_and_stress(void);

int main(int argc, char **argv) {
    const char *group = argc > 1 ? argv[1] : "all";

    if (strcmp(group, "reduce") == 0) {
        run_reduce_group();
    } else if (strcmp(group, "ntt") == 0) {
        run_ntt_group();
    } else if (strcmp(group, "keccak") == 0) {
        run_keccak_group();
    } else if (strcmp(group, "encode") == 0) {
        run_encode_group();
    } else if (strcmp(group, "sample") == 0) {
        run_sample_group();
    } else if (strcmp(group, "kem") == 0) {
        run_reduce_group();
        run_ntt_group();
        run_keccak_group();
        run_encode_group();
        run_sample_group();
        run_kem_group();
    } else if (strcmp(group, "random") == 0) {
        test_random_and_stress();
    } else if (strcmp(group, "all") == 0) {
        run_reduce_group();
        run_ntt_group();
        run_keccak_group();
        run_encode_group();
        run_sample_group();
        run_kem_group();
        test_random_and_stress();
    } else {
        return 2;
    }
    return 0;
}
```

### What Each Test Category Catches

| Category | Catches | Doesn't Catch |
|----------|---------|---------------|
| **Deterministic unit** | Logic bugs in individual functions, off-by-one errors, modular arithmetic mistakes | Interoperability issues, integration bugs hidden by self-consistency |
| **KAT (known-answer)** | Wrong index ordering (i,j vs j,i), wrong parameter, wrong domain separator, many spec deviations | Coverage is only as broad as the embedded vectors; one ACVP smoke case is strong evidence, not certification |
| **Random/stress** | Rare edge cases that only manifest with specific random inputs, memory corruption, uninitialized data | Reproducibility issues (failures are hard to debug without the seed) |

---

## Dependency Graph

```
Step 1: params.h, poly.h (types + all size macros)
  |
  +---> Step 2: Barrett + signed reduction (reduce.c)
  |       |
  |       +---> Step 3: poly_add, poly_sub (poly.c)
  |
  +---> Step 4: bitrev7, modexp (ntt.c helpers)
  |       |
  |       +---> Step 5: NTT root tables (ZETA, GAMMA)
  |               |
  |               +---> Step 6: Forward NTT
  |               |       |
  |               |       +---> Step 7: Inverse NTT
  |               |               |
  |               +---> Step 8: NTT multiplication (BaseCaseMultiply)
  |
  +---> Step 9: Keccak-f[1600] (keccak.c)
  |       |
  |       +---> Step 10: Keccak sponge (absorb/squeeze)
  |               |
  |               +---> Step 11: SHA3-256, SHA3-512 (= H, G)
  |               |
  |               +---> Step 12: SHAKE-128, SHAKE-256 (= XOF, PRF, J)
  |
  +---> Step 13: randombytes (random.s)
  |
  +---> Step 14: ByteEncode / ByteDecode (encode.c)
  |
  +---> Step 15: Compress / Decompress (encode.c)
  |
  +--- Steps 2-15 all feed into: ---->
  |
  +---> Step 16: PRF wrapper (sample.c)
  +---> Step 17: SamplePolyCBD (sample.c)
  +---> Step 18: SampleNTT (sample.c)
  |       |
  |       +---> Step 19: K-PKE.KeyGen (kem.c)
  |               |
  |               +---> Step 20: K-PKE.Encrypt
  |               |
  |               +---> Step 21: K-PKE.Decrypt
  |                       |
  |                       +---> Step 22: ML-KEM.KeyGen
  |                               |
  |                               +---> Step 23: ML-KEM.Encaps
  |                               |
  |                               +---> Step 24: ML-KEM.Decaps
  |                                       |
  |                                       +---> Step 25: NIST KAT Tests
  |                                               |
  |                                               +---> Step 26: Stress Tests
```

## Complete Test Checklist

| Step | Test | Type | What It Catches |
|------|------|------|-----------------|
| 2 | Barrett reduce boundary (0, Q, Q+1, Q*Q-1, 2*Q*Q) | Unit | Barrett constant error, off-by-one |
| 2 | reduce_signed with negative inputs (-1, -Q) | Unit | Sign handling bugs |
| 3 | poly_add wrap-around, zero identity | Unit | Modular arithmetic errors |
| 3 | poly_sub: f-f=0, 0-1=Q-1 | Unit | Missing sign correction |
| 4 | bitrev7 known values (0,1,2,4,127) | Unit | Bit reversal logic |
| 4 | modexp: 17^128 = Q-1 and 17^256 = 1 | Unit | Modular exponentiation and root-order assumptions |
| 5 | ZETA[0]=1, ZETA[1]=1729, GAMMA[0]=17 | Unit | Root table computation |
| 6 | NTT(zero) = zero | Unit | NTT butterfly logic |
| 7 | ntt_inv(ntt(f)) == f (round-trip) | Unit | Forward/inverse mismatch |
| 7 | ntt_inv(ntt(a) + ntt(b)) == a + b | Unit | Linearity, normalization |
| 8 | ntt_mul vs schoolbook multiply | Unit | Base-case multiply, gamma indexing |
| 9 | Keccak-f all-zero state test vector | Unit | Permutation correctness |
| 11 | SHA3-256/512 NIST vectors | Unit | Hash correctness, padding |
| 12 | SHAKE-128/256 NIST vectors | Unit | XOF correctness, domain byte |
| 13 | Two random buffers differ | Random | RNG not stuck |
| 14 | ByteEncode/Decode round-trip d=1,4,10,12 | Unit | Bit packing/unpacking |
| 15 | Compress/Decompress error bounds | Unit | Rounding formula correctness |
| 15 | Compress_1(0)=0, Compress_1(1665)=1 | Unit | Message encoding threshold |
| 17 | CBD coefficients in [-eta, eta] mod Q | Unit | Bit extraction correctness |
| 17 | CBD mean~0, variance~eta/2 | Statistical | Subtle bit extraction bugs |
| 18 | SampleNTT outputs in [0,Q), deterministic | Unit | Rejection sampling, 12-bit parsing |
| 18 | SampleNTT rejection rate ~18.7% | Statistical | Parsing logic (wrong 12-bit split) |
| 21 | K-PKE encrypt/decrypt round-trip | Integration | End-to-end PKE correctness |
| 24 | ML-KEM encaps/decaps happy path | Integration | FO transform correctness |
| 24 | ML-KEM decaps rejection (flipped byte) | Integration | Implicit rejection |
| 24 | ML-KEM decaps rejection determinism | Integration | J(z\|\|c) consistency |
| 25 | **NIST ACVP ML-KEM-768 KAT vector** | **KAT** | **FIPS 203 compatibility smoke test** |
| 26 | 10 iterations with OS randomness | Stress | Rare edge cases |

## Verification

After each step, run `make test` (or the per-module target like `make test-keccak`) to confirm all tests pass. The progression:

1. Steps 1-3: `make test-reduce` (Barrett, poly add/sub)
2. Steps 4-8: `make test-ntt` (NTT round-trip, multiplication)
3. Steps 9-12: `make test-keccak` (SHA3, SHAKE)
4. Steps 14-15: `make test-encode` (byte encoding, compression)
5. Steps 16-18: `make test-sample` (PRF, CBD, SampleNTT)
6. Steps 19-26: `make test-kem` (full ML-KEM with KATs)
7. Final: `make test` (everything including stress tests)
