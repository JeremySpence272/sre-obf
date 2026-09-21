#include <string.h>

static const char *saved;

void lifetime_keep(const char *p) {
    saved = p;
}

int lifetime_check(const char *expected) {
    return strcmp(saved, expected);
}

__attribute__((noinline)) void lifetime_clobber(void) {
    volatile unsigned char scratch[65536];
    for (unsigned i = 0; i < sizeof(scratch); ++i)
        scratch[i] = (unsigned char)(i | 1);
}
