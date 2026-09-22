#include <stdint.h>
#include <stdio.h>
static uint64_t persistent = 17;
static uint32_t mix32(uint32_t x, uint32_t y) {
    x ^= y + 0x12345678u;
    x = (x << 7) | (x >> 25);
    return (x * 0x9e3779b9u) ^ (y >> 3);
}
static uint64_t mix64(uint64_t x, uint64_t y) {
    x += y * UINT64_C(0x9e3779b97f4a7c15);
    x ^= x >> 29;
    return (x << 11) ^ (x >> 53) ^ y;
}
static uint64_t signed_transfer(uint32_t x, uint64_t y) {
    int64_t a = (int64_t)(int32_t)x;
    return ((uint64_t)a >> (y & 63)) + (a < (int64_t)y) +
           (uint32_t)y / ((x & 31u) + 1u);
}
static uint32_t pointer_boundary(uint32_t *p) { *p += 17; return *p; }
static double floating_boundary(double x) { return x * 1.25 + 2.0; }
int main(void) {
    uint32_t a = 0xffffffffu;
    for (unsigned i = 0; i < 513; ++i) {
        persistent ^= UINT64_C(0xfedcba9876543210) * (i + 1);
        a = mix32(a, i * 0x87654321u);
        uint64_t b = mix64(persistent, ((uint64_t)a << 32) | i);
        b ^= signed_transfer(a, b);
        printf("%u %08x %016llx %.2f\n", i, pointer_boundary(&a),
               (unsigned long long)b, floating_boundary(i));
    }
    return 0;
}
