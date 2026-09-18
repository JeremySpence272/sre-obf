#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifndef TILE_OUTPUT_CELLS
#define TILE_OUTPUT_CELLS 4
#endif
#if TILE_OUTPUT_CELLS < 4 || TILE_OUTPUT_CELLS > 8
#error "conformance tile output width must be 4..8"
#endif

extern void invoke(uint64_t, uint64_t, uint64_t *);

static void *worker(void *arg) {
  uintptr_t id = (uintptr_t)arg;
  uint64_t expected[TILE_OUTPUT_CELLS], actual[TILE_OUTPUT_CELLS];
  for (uint64_t k = 0; k < 128; ++k) {
    invoke(k + id, k * 13, expected);
    for (unsigned r = 0; r < 4; ++r) {
      invoke(k + id, k * 13, actual);
      if (memcmp(actual, expected, sizeof actual)) return (void *)1;
    }
  }
  return NULL;
}

int main(int argc, char **argv) {
  if (argc == 2 && !strcmp(argv[1], "--threads")) {
    pthread_t threads[4];
    for (uintptr_t k = 0; k < 4; ++k)
      if (pthread_create(&threads[k], NULL, worker, (void *)k)) return 2;
    for (unsigned k = 0; k < 4; ++k) {
      void *result;
      if (pthread_join(threads[k], &result) || result) return 3;
    }
    return 0;
  }
  uint64_t a, b, out[TILE_OUTPUT_CELLS];
  while (scanf("%" SCNu64 " %" SCNu64, &a, &b) == 2) {
    invoke(a, b, out);
    for (unsigned k = 0; k < TILE_OUTPUT_CELLS; ++k) {
      if (k) putchar(' ');
      printf("%016" PRIx64, out[k]);
    }
    putchar('\n');
  }
  return ferror(stdin) ? 2 : 0;
}
