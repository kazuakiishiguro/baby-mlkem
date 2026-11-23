#include <assert.h>
#include <stdint.h>
#include <stdio.h>

enum {
  Q = 3329,
  N = 8
};

typedef int16_t poly[N];

static int16_t mod_q(int32_t value) {
  int32_t reduced = value % Q;
  if (reduced < 0) {
    reduced += Q;
  }
  return (int16_t)reduced;
}

static void poly_add(const poly a, const poly b, poly out) {
  for (size_t i = 0; i < N; i++) {
    out[i] = mod_q((int32_t)a[i] + b[i]);
  }
}

/*
 * Schoolbook multiplication in Z_q[x] / (x^N + 1).
 *
 * A term x^(N+k) wraps to -x^k because x^N = -1 in this ring.
 * N is deliberately tiny so every intermediate can be inspected.
 */
static void poly_mul_negacyclic(const poly a, const poly b, poly out) {
  int32_t accum[N] = {0};

  for (size_t i = 0; i < N; i++) {
    for (size_t j = 0; j < N; j++) {
      size_t degree = i + j;
      int32_t product = (int32_t)a[i] * b[j];

      if (degree < N) {
        accum[degree] += product;
      } else {
        accum[degree - N] -= product;
      }
    }
  }

  for (size_t i = 0; i < N; i++) {
    out[i] = mod_q(accum[i]);
  }
}

static void print_poly(const char *label, const poly value) {
  printf("%s[", label);
  for (size_t i = 0; i < N; i++) {
    printf("%s%d", i == 0 ? "" : ", ", value[i]);
  }
  puts("]");
}

static void test_mod_q(void) {
  assert(mod_q(0) == 0);
  assert(mod_q(Q) == 0);
  assert(mod_q(Q + 7) == 7);
  assert(mod_q(-1) == Q - 1);
}

static void test_add(void) {
  const poly a = {Q - 1, 1, 2, 3, 4, 5, 6, 7};
  const poly b = {1, 2, 3, 4, 5, 6, 7, 8};
  const poly expected = {0, 3, 5, 7, 9, 11, 13, 15};
  poly out;

  poly_add(a, b, out);
  for (size_t i = 0; i < N; i++) {
    assert(out[i] == expected[i]);
  }
}

static void test_negacyclic_wrap(void) {
  poly x = {0};
  poly x_to_n_minus_1 = {0};
  poly out;

  x[1] = 1;
  x_to_n_minus_1[N - 1] = 1;
  poly_mul_negacyclic(x, x_to_n_minus_1, out);

  assert(out[0] == Q - 1);
  for (size_t i = 1; i < N; i++) {
    assert(out[i] == 0);
  }
}

int main(void) {
  const poly a = {1, 2, 3, 4, 0, 0, 0, 0};
  const poly b = {4, 3, 2, 1, 0, 0, 0, 0};
  poly sum;
  poly product;

  test_mod_q();
  test_add();
  test_negacyclic_wrap();

  poly_add(a, b, sum);
  poly_mul_negacyclic(a, b, product);

  printf("toy ring: Z_%d[x] / (x^%d + 1)\n", Q, N);
  print_poly("a + b = ", sum);
  print_poly("a * b = ", product);
  puts("OK");
  return 0;
}
