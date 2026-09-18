#include <stdint.h>

/* Keep a real private pointer edge available to the transform after O2. */
__attribute__((noinline)) static void tile_step(uint64_t *tile, uint64_t a,
                                               uint64_t b) {
  unsigned index = b & 1;
  uint64_t v = ((tile[index] + b) ^ tile[1]) * 3;
  v = ((v >> 1) - a) | 1;
  tile[index] = v;
}

__attribute__((noinline)) void kernel(uint64_t a, uint64_t b, uint64_t *out) {
  uint64_t tile[2] = {a, b};
  tile_step(tile, a, b);
  out[0] = tile[0];
  out[1] = tile[1];
  out[2] = a ^ b;
  out[3] = a + b;
}

void invoke(uint64_t a, uint64_t b, uint64_t *out) { kernel(a, b, out); }
