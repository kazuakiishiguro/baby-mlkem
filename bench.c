#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "kem.h"

#define DEFAULT_ITERS 2000
#define DEFAULT_ROUNDS 7
#define MAX_ROUNDS 31

static uint64_t ns_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void init_inputs(uint8_t d[32], uint8_t z[32], uint8_t m[32], int round) {
    for (int i = 0; i < 32; i++) {
        d[i] = (uint8_t)(i * 3 + 1 + round);
        z[i] = (uint8_t)(i * 5 + 7 + round);
        m[i] = (uint8_t)(i * 11 + 13 + round);
    }
}

static uint64_t bench_keygen_once(int iters, int round, volatile uint8_t *sink) {
    uint8_t d[32], z[32], m[32];
    uint8_t ek[EK_SIZE], dk[DK_SIZE];

    init_inputs(d, z, m, round);

    uint64_t t0 = ns_now();
    for (int i = 0; i < iters; i++) {
        d[0] = (uint8_t)i;
        d[1] = (uint8_t)(i >> 8);
        mlkem_keygen_deterministic(d, z, ek, dk);
        *sink ^= ek[0] ^ dk[0];
    }
    uint64_t t1 = ns_now();

    return (t1 - t0) / (uint64_t)iters;
}

static uint64_t bench_encaps_once(int iters, int round, volatile uint8_t *sink) {
    uint8_t d[32], z[32], m[32];
    uint8_t ek[EK_SIZE], dk[DK_SIZE], c[CT_SIZE], k[SHARED_KEY_SIZE];

    init_inputs(d, z, m, round);
    mlkem_keygen_deterministic(d, z, ek, dk);

    uint64_t t0 = ns_now();
    for (int i = 0; i < iters; i++) {
        m[0] = (uint8_t)i;
        m[1] = (uint8_t)(i >> 8);
        mlkem_encaps_deterministic(ek, m, k, c);
        *sink ^= c[0] ^ k[0];
    }
    uint64_t t1 = ns_now();

    return (t1 - t0) / (uint64_t)iters;
}

static uint64_t bench_decaps_once(int iters, int round, volatile uint8_t *sink) {
    uint8_t d[32], z[32], m[32];
    uint8_t ek[EK_SIZE], dk[DK_SIZE], c[CT_SIZE];
    uint8_t k1[SHARED_KEY_SIZE], k2[SHARED_KEY_SIZE];

    init_inputs(d, z, m, round);
    mlkem_keygen_deterministic(d, z, ek, dk);
    mlkem_encaps_deterministic(ek, m, k1, c);

    uint64_t t0 = ns_now();
    for (int i = 0; i < iters; i++) {
        mlkem_decaps(dk, c, k2);
        *sink ^= k2[0];
    }
    uint64_t t1 = ns_now();

    if (memcmp(k1, k2, SHARED_KEY_SIZE) != 0) {
        fprintf(stderr, "decapsulation mismatch\n");
        exit(1);
    }
    return (t1 - t0) / (uint64_t)iters;
}

static void sort_u64(uint64_t vals[MAX_ROUNDS], int n) {
    for (int i = 1; i < n; i++) {
        uint64_t x = vals[i];
        int j = i - 1;
        while (j >= 0 && vals[j] > x) {
            vals[j + 1] = vals[j];
            j--;
        }
        vals[j + 1] = x;
    }
}

static uint64_t median_u64(const uint64_t vals[MAX_ROUNDS], int n) {
    uint64_t tmp[MAX_ROUNDS];

    memcpy(tmp, vals, (size_t)n * sizeof(tmp[0]));
    sort_u64(tmp, n);
    if (n & 1) return tmp[n / 2];
    return (tmp[n / 2 - 1] + tmp[n / 2]) / 2;
}

static uint64_t min_u64(const uint64_t vals[MAX_ROUNDS], int n) {
    uint64_t best = vals[0];
    for (int i = 1; i < n; i++) {
        if (vals[i] < best) best = vals[i];
    }
    return best;
}

static uint64_t max_u64(const uint64_t vals[MAX_ROUNDS], int n) {
    uint64_t best = vals[0];
    for (int i = 1; i < n; i++) {
        if (vals[i] > best) best = vals[i];
    }
    return best;
}

static void print_stat(const char *name, const uint64_t vals[MAX_ROUNDS], int n) {
    printf("%s_ns_avg=%llu\n", name, (unsigned long long)median_u64(vals, n));
    printf("%s_ns_avg_min=%llu\n", name, (unsigned long long)min_u64(vals, n));
    printf("%s_ns_avg_max=%llu\n", name, (unsigned long long)max_u64(vals, n));
}

int main(int argc, char **argv) {
    int iters = DEFAULT_ITERS;
    int rounds = DEFAULT_ROUNDS;
    uint64_t keygen[MAX_ROUNDS], encaps[MAX_ROUNDS], decaps[MAX_ROUNDS];
    volatile uint8_t sink = 0;

    if (argc > 1) iters = atoi(argv[1]);
    if (argc > 2) rounds = atoi(argv[2]);
    if (iters <= 0) iters = DEFAULT_ITERS;
    if (rounds <= 0) rounds = DEFAULT_ROUNDS;
    if (rounds > MAX_ROUNDS) rounds = MAX_ROUNDS;

    int warmup_iters = iters / 10;
    if (warmup_iters < 1) warmup_iters = 1;
    if (warmup_iters > 200) warmup_iters = 200;

    (void)bench_keygen_once(warmup_iters, -1, &sink);
    (void)bench_encaps_once(warmup_iters, -1, &sink);
    (void)bench_decaps_once(warmup_iters, -1, &sink);

    for (int i = 0; i < rounds; i++) {
        keygen[i] = bench_keygen_once(iters, i, &sink);
        encaps[i] = bench_encaps_once(iters, i, &sink);
        decaps[i] = bench_decaps_once(iters, i, &sink);
    }

    printf("iters=%d\n", iters);
    printf("rounds=%d\n", rounds);
    printf("warmup_iters=%d\n", warmup_iters);
    print_stat("keygen", keygen, rounds);
    print_stat("encaps", encaps, rounds);
    print_stat("decaps", decaps, rounds);
    printf("sink=%u\n", sink);
    return 0;
}
