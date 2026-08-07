#ifndef STAGE_SOURCE
#define STAGE_SOURCE "../../bench_core_stages.c"
#endif

#define main unused_stage_main
#include STAGE_SOURCE
#undef main

static uint8_t target_seeds[1024][32];
static poly256 target_out[8];
static volatile uint64_t target_sink;

int main(int argc, char **argv) {
  size_t iters = argc == 2 ? (size_t)strtoull(argv[1], NULL, 10) : 500000;
  uint64_t x = 0x9e3779b97f4a7c15ULL;
  for (size_t i = 0; i < 1024; i++) {
    for (size_t j = 0; j < 32; j++) {
      x ^= x >> 12;
      x ^= x << 25;
      x ^= x >> 27;
      target_seeds[i][j] = (uint8_t)(x * 0x2545f4914f6cdd1dULL);
    }
  }

  uint64_t t0 = now_ns();
  uint64_t acc = 0;
  for (size_t i = 0; i < iters; i++) {
    sample_ntt8_matrix(target_seeds[i & 1023],
                       target_out[0], target_out[1], target_out[2],
                       target_out[3], target_out[4], target_out[5],
                       target_out[6], target_out[7]);
    acc ^= (uint16_t)target_out[i & 7][i & 255];
  }
  uint64_t elapsed = now_ns() - t0;
  target_sink = acc;
  printf("ns_per_op=%.6f sink=%llu\n", (double)elapsed / (double)iters,
         (unsigned long long)target_sink);
  return 0;
}
