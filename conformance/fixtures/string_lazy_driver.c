#include <stdio.h>

#ifndef EXPECT_DECRYPTS
#define EXPECT_DECRYPTS 1
#endif
volatile unsigned strenc_test_calls;
extern unsigned lazy_hot(unsigned);
extern void lazy_cold(int);
extern void lazy_loop(int, int);
extern void lazy_branches(int, int);
extern void lazy_recursive(int, int);
extern void lazy_nested(int, int);
extern void lazy_phi(int);
extern void lazy_cycle(int);

#define CHECK(n) do { \
    if (EXPECT_DECRYPTS && strenc_test_calls != (n)) { \
        fprintf(stderr, "line %d: decoder calls %u, expected %u\n", \
                __LINE__, strenc_test_calls, (unsigned)(n)); \
        return 1; \
    } \
    strenc_test_calls = 0; \
} while (0)

int main(void) {
    for (unsigned i = 0; i < 64; ++i)
        if (lazy_hot(i) != i * 13u + 7u) return 2;
    CHECK(0);
    lazy_cold(0);
    CHECK(0);
    lazy_cold(1);
    CHECK(1);
    lazy_cold(1);
    CHECK(1); /* A new activation must not reuse cached plaintext. */
    lazy_loop(0, 1);
    CHECK(0);
    lazy_loop(8, 0);
    CHECK(0);
    lazy_loop(8, 1);
    CHECK(1);
    lazy_branches(0, 0);
    CHECK(0);
    lazy_branches(1, 0);
    CHECK(1);
    lazy_branches(0, 1);
    CHECK(1);
    lazy_branches(1, 1);
    CHECK(1);
    lazy_recursive(3, 0);
    CHECK(0);
    lazy_recursive(3, 1);
    CHECK(4);
    lazy_nested(0, 1);
    CHECK(0);
    lazy_nested(4, 0);
    CHECK(0);
    lazy_nested(4, 1);
    CHECK(1);
    lazy_phi(0);
    CHECK(0);
    lazy_phi(1);
    CHECK(1);
    lazy_phi(2);
    CHECK(1);
    lazy_phi(3);
    CHECK(1);
    lazy_cycle(0);
    CHECK(0);
    lazy_cycle(1);
    CHECK(1);
    lazy_cycle(2);
    CHECK(1);
    puts("lazy-string-ok");
    return 0;
}
