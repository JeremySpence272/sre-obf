#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern void invoke(uint64_t, uint64_t, uint64_t *);

static void *worker(void *arg) {
  uintptr_t id = (uintptr_t)arg;
  uint64_t expected[4], actual[4];
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
  uint64_t a, b, out[4];
  while (scanf("%" SCNu64 " %" SCNu64, &a, &b) == 2) {
    invoke(a, b, out);
    printf("%016" PRIx64 " %016" PRIx64 " %016" PRIx64 " %016" PRIx64 "\n",
           out[0], out[1], out[2], out[3]);
  }
  return ferror(stdin) ? 2 : 0;
}
