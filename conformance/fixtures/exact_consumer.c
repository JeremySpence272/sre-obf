#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void produce(uint8_t out[32], uint64_t seed) {
    for (unsigned i = 0; i < 32; ++i) {
        seed ^= seed >> 13;
        seed = seed * UINT64_C(0x9e3779b97f4a7c15) + i;
        out[i] = (uint8_t)(seed >> 11);
    }
}
static int exact(uint64_t seed, unsigned flip) {
    uint8_t observed[32], expected[32];
    produce(observed, seed);
    produce(expected, seed);
    for (unsigned i = 0; i < 32; ++i)
        if (i == flip) observed[i] ^= 1;
    return memcmp(observed, expected, 32) == 0;
}
static int ordering(unsigned value) {
    uint8_t a[2] = {(uint8_t)value, 1}, b[2] = {7, 1};
    int r = memcmp(a, b, 2);
    return (r > 0) - (r < 0);
}
static int volatile_boundary(unsigned value) {
    volatile uint8_t a[2], b[2];
    a[0] = (uint8_t)value; a[1] = 3; b[0] = 7; b[1] = 3;
    return memcmp((const void *)a, (const void *)b, 2) != 0;
}
int main(void) {
    for (unsigned j = 0; j < 19; ++j)
        for (unsigned flip = 0; flip <= 32; ++flip) {
            uint64_t seed = UINT64_C(0xfeedfacedeadbeef) * (j + 1);
            int e = exact(seed, flip);
            if (e != (flip == 32)) return 2;
            printf("%u %u %d %d %d\n", j, flip, e, ordering(j), volatile_boundary(j));
        }
    return 0;
}
