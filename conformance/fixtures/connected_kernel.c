#include <stdint.h>
#include <string.h>

uint32_t producer(uint32_t x, uint32_t y) {
    uint32_t words[8];
    uint8_t bytes[8], copy[8];
    for (unsigned i = 0; i < 8; ++i) {
        words[i] = (x ^ (y + i)) + (x >> i);
        bytes[i] = (uint8_t)(words[i] >> 3);
    }
    memcpy(copy, bytes, sizeof(copy));
    uint32_t result = 0;
    for (unsigned i = 0; i < 8; ++i) {
        uint32_t a = words[i], b = (uint32_t)copy[i];
        result ^= (a < y) ? (a + b) : (a ^ b);
        result += ((int32_t)a < (int32_t)x) | ((a == x) << 1);
        result ^= ((a >= y) && (b != (x & 255))) ? 0x7831u : 0x9117u;
    }
    return result;
}
