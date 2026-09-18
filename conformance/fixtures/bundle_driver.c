#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

extern uint64_t invoke(uint64_t, uint64_t);

int main(void) {
  uint64_t x, y;
  while (scanf("%" SCNu64 " %" SCNu64, &x, &y) == 2)
    printf("%016" PRIx64 "\n", invoke(x, y));
  return ferror(stdin) ? 2 : 0;
}
