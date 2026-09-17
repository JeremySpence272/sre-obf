#include <stdint.h>
uint32_t producer(uint32_t x, uint32_t y) {
    return (x + y) * (x - y) + (x << 3);
}
