#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "kem.h"

static uint64_t ns_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

int main(int argc, char **argv) {
    int iters = 20;
    uint8_t d[32], z[32], m[32];
    uint8_t ek[EK_SIZE], dk[DK_SIZE], c[CT_SIZE], k1[SHARED_KEY_SIZE], k2[SHARED_KEY_SIZE];
    volatile uint8_t sink = 0;

    if (argc > 1) iters = atoi(argv[1]);
    if (iters <= 0) iters = 20;

    for (int i = 0; i < 32; i++) {
        d[i] = (uint8_t)(i * 3 + 1);
        z[i] = (uint8_t)(i * 5 + 7);
        m[i] = (uint8_t)(i * 11 + 13);
    }

    uint64_t t0 = ns_now();
    for (int i = 0; i < iters; i++) {
        d[0] = (uint8_t)i;
        mlkem_keygen_deterministic(d, z, ek, dk);
        sink ^= ek[0];
    }
    uint64_t t1 = ns_now();

    mlkem_keygen_deterministic(d, z, ek, dk);
    uint64_t t2 = ns_now();
    for (int i = 0; i < iters; i++) {
        m[0] = (uint8_t)i;
        mlkem_encaps_deterministic(ek, m, k1, c);
        sink ^= c[0] ^ k1[0];
    }
    uint64_t t3 = ns_now();

    mlkem_encaps_deterministic(ek, m, k1, c);
    uint64_t t4 = ns_now();
    for (int i = 0; i < iters; i++) {
        mlkem_decaps(dk, c, k2);
        sink ^= k2[0];
    }
    uint64_t t5 = ns_now();

    printf("iters=%d\n", iters);
    printf("keygen_ns_avg=%llu\n", (unsigned long long)((t1 - t0) / (uint64_t)iters));
    printf("encaps_ns_avg=%llu\n", (unsigned long long)((t3 - t2) / (uint64_t)iters));
    printf("decaps_ns_avg=%llu\n", (unsigned long long)((t5 - t4) / (uint64_t)iters));
    printf("sink=%u\n", sink);
    return 0;
}
