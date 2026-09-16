#include <stdint.h>
#include <string.h>
/* Separate TU deliberately preserves the O0 call and intermediate object. */
static __attribute__((noinline)) uint32_t consume(uint32_t x, uint32_t y) {
    return ((x ^ y) + (x << 3)) ^ (y >> 5);
}
uint32_t producer(uint32_t x, uint32_t y) {
    uint32_t a[8];
    for (unsigned i = 0; i < 8; ++i) a[i] = consume(x + i, y ^ i);
    a[y & 7] ^= x;
    uint64_t material = ((uint64_t)x << 32) | y;
    uint8_t bytes[8];
    memcpy(bytes, &material, sizeof bytes);
    bytes[x & 7] ^= (uint8_t)y;
    return (a[x & 7] + a[(x + y) & 7]) ^ bytes[y & 7];
}
