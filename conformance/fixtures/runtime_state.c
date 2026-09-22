#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint8_t buffer[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
static uint16_t words[8] = {1, 0xffff, 0x8000, 7, 9, 11, 13, 17};
static uint8_t escaped_buffer[8] = {1};
static uint8_t *buffer_address(void) { return escaped_buffer; }
static uint32_t buffer_step(unsigned i) {
    if (i % 19 == 0) memset(buffer, (int)(i & 255), sizeof(buffer));
    buffer[i & 31] ^= (uint8_t)i;
    words[i & 7] = (uint16_t)(words[(i + 1) & 7] + i * 17);
    buffer_address()[i & 7] ^= (uint8_t)i;
    uint32_t out = 0;
    for (unsigned j = 0; j < 32; ++j) out = out * 13u + buffer[j];
    return out + words[(i + 3) & 7] + escaped_buffer[i & 7];
}
static uint64_t wide = UINT64_C(0xfedcba9876543210);
static uint32_t word = 0x81234567u;
static uint16_t half = 0xfedcu;
static uint8_t byte = 0x81u;
static uint32_t escaped = 19;
static volatile uint32_t external_observation = 0;
static uint32_t *address(void) { return &escaped; }
static uint64_t snapshot(void) { return wide; }

static uint64_t step(uint64_t x, unsigned i) {
    wide ^= x;
    wide = (wide << 13) | (wide >> 51);
    wide = wide * UINT64_C(0x9e3779b97f4a7c15) + x;
    word += (uint32_t)(wide >> 17);
    half = (uint16_t)((half ^ word) * 13u);
    byte = (uint8_t)(byte + (half >> 3));
    if (i % 17 == 0) { wide = x; word = 7; half = 9; byte = 11; }
    external_observation = i;
    *address() += (i & 3);
    /* Equality stays exact; division/variable shifts are declared exits. */
    return (snapshot() == x) + (word != 7) + ((uint64_t)(int64_t)(int8_t)byte) +
           (uint64_t)half + wide / 7u + (word >> (i & 15)) + escaped;
}
int main(void) {
    uint64_t sum = 0;
    for (unsigned i = 0; i < 513; ++i) {
        uint64_t x = UINT64_C(0x1020304050607080) * (i + 1);
        sum ^= step(x, i) + buffer_step(i);
        printf("%u %016llx\n", i, (unsigned long long)sum);
    }
    return 0;
}
