#include <stdint.h>

static uint32_t initial;

__attribute__((constructor))
static void initialize(void) {
    initial = UINT32_C(0x13579bdf);
}

__attribute__((noinline))
static uint32_t step(uint32_t x) {
    return (x ^ initial) * UINT32_C(0x9e3779b1);
}

uint32_t obf_target(uint32_t x, uint32_t y) {
    return step(x) ^ step(y);
}
