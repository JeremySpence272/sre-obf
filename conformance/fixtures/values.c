#include <stdint.h>

__attribute__((noinline)) uint8_t values8(uint8_t a, uint8_t b) {
    a = (uint8_t)(a + b);
    b = (uint8_t)(a * b);
    return (uint8_t)((a + b) * (b + 3u));
}

__attribute__((noinline)) uint16_t values16(uint16_t a, uint16_t b) {
    a = (uint16_t)(a + b);
    /* Explicit unsigned widening avoids C's signed-int promotion overflow. */
    b = (uint16_t)((uint32_t)a * b);
    return (uint16_t)(((uint32_t)a + b) * ((uint32_t)b + 3u));
}

__attribute__((noinline)) uint64_t values64(uint64_t a, uint64_t b) {
    uint64_t sum = a + b, product = a * b;
    return (sum - product) * (product + UINT64_C(0xfedcba9876543211));
}

uint32_t obf_target(uint32_t x, uint32_t y) {
    uint32_t a = x + y, b = x * y;
    for (unsigned i = 0; i < (y & 7u) + 1u; ++i) {
        uint32_t next = (a + b) * (b + 3u);
        b = (a << 3) - b;
        if (next & 1u) a = next + y;
        else a = next - x;
    }
    uint64_t wide = values64(((uint64_t)x << 32) | y, ((uint64_t)y << 32) | x);
    return a ^ b ^ values8((uint8_t)x, (uint8_t)y) ^ values16((uint16_t)x, (uint16_t)y)
           ^ (uint32_t)wide ^ (uint32_t)(wide >> 32);
}
