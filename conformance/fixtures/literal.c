#include <stdint.h>
uint32_t obf_target(uint32_t x, uint32_t y) {
    return (x ^ UINT32_C(0x13579bdf)) + y;
}
