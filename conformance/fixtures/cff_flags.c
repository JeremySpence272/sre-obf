#include <stdint.h>
#ifndef FLA_SPEC
#error "The dedicated flag regression must supply FLA_SPEC"
#endif
__attribute__((annotate("obf: " FLA_SPEC)))
uint32_t obf_target(uint32_t, uint32_t);
#include "arithmetic.c"
