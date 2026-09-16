#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

extern uint32_t obf_target(uint32_t, uint32_t);

int main(void) {
    uint32_t x, y;
    while (scanf("%" SCNu32 " %" SCNu32, &x, &y) == 2)
        printf("%08" PRIx32 "\n", obf_target(x, y));
    return ferror(stdin) ? 2 : 0;
}
