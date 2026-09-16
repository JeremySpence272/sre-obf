#include <stdint.h>

/* Non-tail recursion leaves dispatcher state live across another activation.
 * External linkage prevents the merge pass from hiding this test boundary. */
__attribute__((noinline))
uint32_t state_recurse(uint32_t x, uint32_t depth) {
    if (!depth) return (x * UINT32_C(0x45d9f3b)) ^ (x >> 13);
    uint32_t a = state_recurse(x ^ (depth * 97u), depth - 1u);
    if (x & 1u) a += state_recurse(x + 19u, depth - 1u);
    for (uint32_t i = 0; i != (x & 3u) + 1u; ++i)
        a = ((a << 5) | (a >> 27)) ^ (x + i);
    return a + depth;
}

uint32_t obf_target(uint32_t x, uint32_t y) {
    uint32_t out = 0;
    for (uint32_t i = 0; i != (y & 3u) + 1u; ++i)
        out ^= state_recurse(x + i, (y >> 3) & 3u) + i;
    return out;
}
