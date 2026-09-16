#include <stdint.h>

uint32_t obf_target(uint32_t x, uint32_t y) {
    uint32_t a = x ^ UINT32_C(0x13579bdf);
    for (uint32_t i = 0; i < (y & 7u) + 1u; ++i) {
        switch ((a ^ y) & 3u) {
        case 0: a = a * UINT32_C(1664525) + UINT32_C(1013904223); break;
        case 1: a = ((a << 7) | (a >> 25)) ^ y; break;
        case 2: a = (a + y) ^ (a >> 11); break;
        default: a = a - (y ^ UINT32_C(0x93a25e71)); break;
        }
    }
    return a ^ (y * UINT32_C(0x9e3779b1));
}
