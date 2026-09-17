/* A second translation unit, so connected_aggregate.c has a genuinely
 * external callee to hand a local aggregate's address to. */
#include <stdint.h>

struct rec { uint32_t a; uint16_t b; uint8_t c; uint64_t d; };

uint32_t external_mix(const struct rec *r) {
    return r->a ^ ((uint32_t)r->b << 8) ^ ((uint32_t)r->c << 3) ^ (uint32_t)(r->d >> 5);
}
