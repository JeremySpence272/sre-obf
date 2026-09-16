#include <stdint.h>
#include <stdio.h>
extern uint32_t producer(uint32_t x, uint32_t y);
int main(void) {
    uint32_t x, y;
    while (scanf("%u %u", &x, &y) == 2) printf("%u\n", producer(x, y));
    return 0;
}
