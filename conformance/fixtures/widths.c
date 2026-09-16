#include <stdint.h>

static const int8_t t8[8] = {-128, -1, 0, 1, 7, 31, 63, 127};
static const int16_t t16[8] = {-32768, -1, 0, 1, 257, 12345, 30000, 32767};
static const uint32_t t32[8] = {
    0, 1, 0xffffffff, 0x80000000, 0x13579bdf, 31, 32, 0x7fffffff
};
static const uint64_t t64[8] = {
    0, 1, UINT64_MAX, UINT64_C(0x8000000000000000),
    UINT64_C(0xfedcba9876543210), 63, 64, UINT64_C(0x7fffffffffffffff)
};
static uint32_t startup;

__attribute__((noinline))
static uint32_t read_tables(uint32_t x, uint32_t y) {
    uint64_t wide = t64[x & 7] + t64[y & 7];
    return (uint32_t)(int32_t)t8[x & 7] ^ (uint32_t)(int32_t)t16[y & 7] ^
           t32[(x ^ y) & 7] ^ (uint32_t)wide ^ (uint32_t)(wide >> 32);
}

__attribute__((constructor))
static void initialize(void) { startup = read_tables(3, 4); }

uint32_t obf_target(uint32_t x, uint32_t y) {
    return read_tables(x, y) + startup;
}
