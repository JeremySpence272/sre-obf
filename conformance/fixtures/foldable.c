#include <stdint.h>
uint32_t obf_target(uint32_t x, uint32_t y) {
    /* A deliberately ineffective source transform: the two XORs cancel. */
    uint32_t a = x ^ UINT32_C(0x6b12c9a7);
    return (a ^ UINT32_C(0x6b12c9a7)) + y;
}
