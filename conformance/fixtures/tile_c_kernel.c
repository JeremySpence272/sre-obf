#include <stdint.h>
#ifdef TILE_WORD32
typedef uint32_t Word;
#else
typedef uint64_t Word;
#endif

/* Ordinary C and ordinary -O2. No optnone, volatile, inline assembly, forced
 * compiler flags or source annotations that make the tile pass accept it. */
__attribute__((noinline))
void kernel(Word a, Word b, uint64_t out[4]) {
  Word state[2] = {a, b};
  Word carry = a ^ b;
  unsigned count = (unsigned)(b & 15) + 1;
  for (unsigned k = 0; k < count; ++k) {
    unsigned idx = (unsigned)((a + k) & 1);
    Word x = state[idx];
    x += b;
    x ^= carry;
    x *= 3;
    x >>= 1;
    x -= a;
    state[idx] = x | 1;
  }
  out[0] = state[0];
  out[1] = state[1];
  out[2] = carry;
  out[3] = 0;
}

void invoke(uint64_t a, uint64_t b, uint64_t out[4]) {
  kernel((Word)a, (Word)b, out);
}
