#include <stdio.h>
#include <time.h>
#include "random.h"

int main(void) {
  size_t outlen = 16;
  uint8_t buffer1[outlen];

  struct timespec start_time, end_time;
  long long elapsed_nanoseconds;
  int num_calls = 1000000;

  if (clock_gettime(CLOCK_MONOTONIC, &start_time) == -1) {
    perror("clock_gettime (start)");
    return 1;
  }


  for (int i = 0; i < num_calls; i++) {
    randombytes(buffer1, outlen);
  }

  if (clock_gettime(CLOCK_MONOTONIC, &end_time) == -1) {
    perror("clock_gettime (end)");
    return 1;
  }

  elapsed_nanoseconds = (long long)(end_time.tv_sec - start_time.tv_sec) * 1000000000LL +
                        (end_time.tv_nsec - start_time.tv_nsec);

  // Convert to seconds for a more readable output
  double elapsed_seconds = (double)elapsed_nanoseconds / 1000000000.0;

  // Calculate average time per call and calls per second
  double avg_ns_per_call = (double)elapsed_nanoseconds / num_calls;
  double calls_per_sec = (double)num_calls / elapsed_seconds;

  printf("----------------------------------------\n");
  printf("Total elapsed time:       %.4f seconds\n", elapsed_seconds);
  printf("Average time per call:    %.2f nanoseconds\n", avg_ns_per_call);
  printf("Throughput:               %.0f calls/second\n", calls_per_sec);
  printf("----------------------------------------\n");
}
