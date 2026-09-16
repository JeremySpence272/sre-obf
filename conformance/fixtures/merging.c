#include <stdint.h>

__attribute__((noinline))
static uint32_t first(uint32_t x, uint32_t y) {
    for (unsigned i = 0; i < (y & 7) + 1; ++i)
        x = (x * 1664525u + 1013904223u) ^ (x >> 9);
    return x;
}

__attribute__((noinline))
static uint32_t second(uint32_t x, uint32_t y) {
    for (unsigned i = 0; i < (x & 3) + 1; ++i)
        y = (y << 3 | y >> 29) + (x ^ 0x57ed3981u);
    return y;
}

uint32_t obf_target(uint32_t x, uint32_t y) {
    return first(x, y) ^ second(y, x);
}
