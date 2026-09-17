/* Closed and non-closed local aggregates, of the shapes ordinary C produces.
 *
 * closed_aggregates() holds three closed constant-index objects: a struct of
 * integer fields, a nested fixed array, and a struct containing an array.
 * open_aggregates() holds three that must be reported as honest skips and
 * never encoded: an escaping local, a runtime-indexed array of structs, and
 * an aggregate whose address reaches a function in another translation unit.
 * flat_words() is the pre-existing flat-array shape, kept so one run shows
 * the widened denominator next to the narrow one.
 *
 * The helpers have external linkage on purpose: bounded function merging
 * only collapses local-linkage definitions, and a merged super-function
 * moves its allocas out of the entry block, where no object is eligible.
 * The bodies stay small on purpose: this fixture must fit the ordinary
 * module instruction cap, which is not raised for it. */
#include <stdint.h>

struct rec { uint32_t a; uint16_t b; uint8_t c; uint64_t d; };
struct box { uint8_t tag; uint32_t lane[4]; };

extern uint32_t external_mix(const struct rec *r);
static uint32_t *volatile escaped_field;

/* Closed: a struct of integer fields, a nested fixed array, and a struct
 * containing an array. Every access is a constant leaf of its object. */
__attribute__((noinline)) uint32_t closed_aggregates(uint32_t x, uint32_t y) {
    struct rec r;
    uint32_t grid[2][4];
    struct box b;

    r.a = x ^ 0x9e3779b9u;
    r.b = (uint16_t)(y + 0x1234u);
    r.c = (uint8_t)(x >> 24);
    r.d = (uint64_t)x * 3u + y;

    grid[0][0] = x;
    grid[0][1] = x + y;
    grid[0][2] = x ^ y;
    grid[0][3] = x - y;
    grid[1][0] = y;
    grid[1][1] = y ^ 0x5au;

    b.tag = (uint8_t)(x & 7u);
    b.lane[0] = x;
    b.lane[1] = y;
    b.lane[2] = x ^ y;
    b.lane[3] = x + y;

    uint32_t v = r.a ^ ((uint32_t)r.b << 3);
    v ^= (uint32_t)r.c << 8;
    v ^= (uint32_t)(r.d >> 7);
    v ^= grid[0][0] & grid[1][1];
    v ^= grid[0][1] | grid[1][0];
    v ^= (grid[0][2] << 2) ^ grid[0][3];
    v ^= (uint32_t)b.tag ^ b.lane[0];
    v ^= b.lane[1] & b.lane[2];
    v ^= b.lane[3];
    return v;
}

/* Three objects that are not closed, each for a different reason: a leaf
 * address escapes into module state and is read back through it, a runtime
 * index selects which element is touched, and an aggregate's address is
 * handed to a function in another translation unit. */
__attribute__((noinline)) uint32_t open_aggregates(uint32_t x, uint32_t y) {
    struct rec escapee, handed;
    struct rec table[4];

    escapee.a = x;
    escapee.b = (uint16_t)y;
    escapee.c = 0;
    escapee.d = 0;
    escaped_field = &escapee.a;
    uint32_t v = *escaped_field ^ (uint32_t)escapee.b;

    for (unsigned i = 0; i < 4; ++i) {
        table[i].a = x ^ i;
        table[i].b = (uint16_t)(y ^ i);
        table[i].c = 0;
        table[i].d = 0;
    }
    unsigned k = (x ^ y) & 3u;
    v ^= table[k].a ^ (uint32_t)table[k].b;

    handed.a = y;
    handed.b = (uint16_t)x;
    handed.c = 0;
    handed.d = 0;
    return v ^ external_mix(&handed);
}

/* The narrow pre-existing shape: a flat array of one integer width, with a
 * runtime index and a comparison, so a run also has predicate coverage. */
__attribute__((noinline)) uint32_t flat_words(uint32_t x, uint32_t y) {
    uint32_t words[8];
    for (unsigned i = 0; i < 8; ++i)
        words[i] = (x ^ (y + i)) + (x >> (i & 31u));
    uint32_t v = 0;
    for (unsigned i = 0; i < 8; ++i)
        v ^= (words[i] < y) ? (words[i] + i) : (words[i] ^ i);
    return v;
}

uint32_t producer(uint32_t x, uint32_t y) {
    uint32_t v = closed_aggregates(x, y);
    v ^= open_aggregates(x, y);
    v += flat_words(x, y);
    return v;
}
