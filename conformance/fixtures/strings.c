#include <stdint.h>

extern uint32_t fixture_text(const char *, uint32_t);

uint32_t obf_target(uint32_t x, uint32_t y) {
    const char *text = x & 1 ? "cobalt-kinetic-conformance" : "amber-vector-fixture";
    return fixture_text(text, x) + fixture_text("separate-string-user", y);
}
