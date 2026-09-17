/* Private encoded-call interfaces (P5).
 *
 * Private helpers with 8/16/32/64-bit arguments and results, each reached from
 * more than one caller, plus a void-returning helper, so an encoded interface
 * has to carry pairs at every supported width. The negative cases exist to be
 * skipped with a named reason, never quietly: one recursive helper, one
 * varargs helper and one helper whose address is taken.
 *
 * Every value the drivers print comes from stack-local state, so the four
 * concurrent callers of driver_threads.c must agree with the single-threaded
 * driver on every vector.
 */
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>

#define PRIVATE static __attribute__((noinline))

/* Written and never read: it keeps a void-returning private interface alive
 * without making any printed result depend on inter-thread ordering. */
static _Atomic uint32_t fixture_tap;

PRIVATE uint8_t fold8(uint8_t a, uint8_t b) {
    uint8_t v = (uint8_t)(a * 31u + b);
    return (uint8_t)(v ^ (uint8_t)(v >> 3));
}

PRIVATE uint16_t fold16(uint16_t a, uint8_t b) {
    uint16_t v = (uint16_t)(a ^ ((uint16_t)b << 5));
    return (uint16_t)(v + (uint16_t)(a >> 2));
}

PRIVATE uint32_t fold32(uint32_t a, uint32_t b) {
    uint32_t v = (a ^ (b + 0x9e3779b9u)) + (a << 3);
    return v ^ (v >> 7);
}

PRIVATE uint64_t fold64(uint64_t a, uint32_t b) {
    uint64_t v = a ^ ((uint64_t)b << 32);
    return v + (v >> 11) + fold32((uint32_t)a, b);
}

PRIVATE void tap(uint32_t v) {
    atomic_store_explicit(&fixture_tap, v, memory_order_relaxed);
}

PRIVATE uint32_t stage2(uint32_t x, uint16_t y) {
    uint32_t r = fold32(x, y);
    r ^= fold16(y, (uint8_t)x);
    r += fold8((uint8_t)x, (uint8_t)y);
    r ^= (uint32_t)(fold64(r, x) >> 8);
    if (r & 1u) r = fold32(r, x);
    tap(r);
    return r;
}

/* Negative case: self-recursive, so the encoded ABI must skip it. */
PRIVATE uint32_t climb(uint32_t n, uint32_t depth) {
    if (!depth || n <= 1u) return n;
    return climb((n & 1u) ? (3u * n + 1u) : (n >> 1), depth - 1u) ^ (n << 1);
}

/* Negative case: variadic. */
PRIVATE uint32_t gather(uint32_t count, ...) {
    uint32_t total = 0;
    va_list ap;
    va_start(ap, count);
    for (uint32_t i = 0; i < count; ++i) total = (total << 1) ^ va_arg(ap, uint32_t);
    va_end(ap);
    return total;
}

/* Negative case: the address escapes into a volatile local, so no
 * optimization level can recover a direct call. */
PRIVATE uint32_t scale(uint32_t x, uint32_t y) {
    return (x * 2654435761u) ^ (y >> 3);
}

uint32_t obf_target(uint32_t x, uint32_t y) {
    uint32_t lanes[8];
    uint32_t r = stage2(x, (uint16_t)y);
    r ^= stage2(y ^ 0x5a5au, (uint16_t)(x >> 16));
    for (unsigned i = 0; i < 8; ++i) lanes[i] = fold32(x + i, y ^ i);
    for (unsigned i = 0; i < 8; ++i) r += lanes[(i + x) & 7u] ^ (uint32_t)i;
    r ^= (uint32_t)fold64(((uint64_t)x << 32) | y, r);
    r ^= fold16((uint16_t)r, (uint8_t)y);
    r += fold8((uint8_t)(r >> 8), (uint8_t)x);
    r ^= climb(x | 1u, 6u);
    r += climb(y | 1u, 4u);
    r ^= gather(3u, x, y, r);
    r += gather(2u, r, x);
    uint32_t (*volatile indirect)(uint32_t, uint32_t) = scale;
    r ^= indirect(x, r);
    r += indirect(r, y);
    tap(r);
    return r;
}

uint32_t producer(uint32_t x, uint32_t y) {
    uint32_t r = obf_target(x, y);
    return r ^ stage2(r, (uint16_t)y) ^ fold32(r, x);
}
