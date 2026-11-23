#ifndef STAGE_SOURCE
#error "STAGE_SOURCE must name bench_core_stages.c"
#endif

#define main unused_stage_main
#include STAGE_SOURCE
#undef main

int main(int argc, char **argv) {
  size_t iters = argc == 2 ? parse_iters(argv[1]) : 200000;
  validate_core_stage_helpers();
  print_metric("inv_add4_eta2_i8",
               bench_encrypt_inv_add4_eta2_i8_raw_avx512(iters), iters);
  print_metric("decrypt_inv_sub", bench_decrypt_inv_sub_from(iters), iters);
  printf("sink=%llu\n", (unsigned long long)bench_stage_sink);
  return EXIT_SUCCESS;
}
