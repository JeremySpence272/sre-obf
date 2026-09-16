#include <stdint.h>

static const uint32_t table[8] = {
    0x13579bdfu, 0x728ab561u, 0x983725cbu, 0xab438719u,
    0x294d7e83u, 0xbc29476fu, 0x62f781adu, 0xc517ab39u
};

uint32_t obf_target(uint32_t x, uint32_t y) {
    return table[x & 7u] + (table[(x ^ y) & 7u] ^ y);
}
