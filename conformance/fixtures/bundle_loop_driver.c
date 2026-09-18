#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern void invoke(uint64_t, uint64_t, uint32_t, uint64_t *, uint64_t *);

struct batch {
  uint64_t salt;
  uint64_t values[32][2];
};

static void *run_batch(void *arg) {
  struct batch *b = arg;
  for (unsigned i = 0; i < 32; ++i)
    invoke(b->salt + i, ~b->salt - i, i, &b->values[i][0], &b->values[i][1]);
  return NULL;
}

int main(void) {
  /* Distinct per-activation state, serial reentry and concurrent calls. */
  struct batch expected[2] = {{.salt = 17}, {.salt = UINT64_MAX - 91}};
  struct batch parallel[2] = {{.salt = 17}, {.salt = UINT64_MAX - 91}};
  pthread_t threads[2];
  for (unsigned i = 0; i < 2; ++i) run_batch(&expected[i]);
  for (unsigned i = 0; i < 2; ++i)
    if (pthread_create(&threads[i], NULL, run_batch, &parallel[i])) return 2;
  for (unsigned i = 0; i < 2; ++i) {
    if (pthread_join(threads[i], NULL)) return 2;
    if (memcmp(expected[i].values, parallel[i].values, sizeof expected[i].values)) return 3;
  }
  uint64_t a, b, x, y, again_x, again_y;
  uint32_t count;
  while (scanf("%" SCNu64 " %" SCNu64 " %" SCNu32, &a, &b, &count) == 3) {
    invoke(a, b, count, &x, &y);
    invoke(a, b, count, &again_x, &again_y);
    if (x != again_x || y != again_y) return 4;
    printf("%" PRIu64 " %" PRIu64 "\n", x, y);
  }
  return ferror(stdin) ? 1 : 0;
}
