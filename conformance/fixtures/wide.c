#include <stdint.h>
uint32_t obf_target(uint32_t x, uint32_t y) {
    uint32_t a = (x ^ y) + (x & y), b = (x | y) - (x >> 3);
    for (unsigned i = 0; i < (y & 3) + 1; ++i) {
        uint8_t lo = (uint8_t)(a ^ b);
        int16_t sign = (int16_t)(b >> 7);
        uint64_t wide = ((uint64_t)a << 32) | b;
        a = (uint32_t)(wide >> 11) + (uint32_t)(int32_t)sign;
        b = (b ^ lo) + (a | (b >> 1));
    }
    return a ^ b;
}
