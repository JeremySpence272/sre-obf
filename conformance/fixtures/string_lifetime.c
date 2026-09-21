#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifndef OBF_SPEC
#define OBF_SPEC "obf: strenc(cipher=aes,minlen=1,keysplit=1)"
#endif
#define PROTECT __attribute__((noinline, annotate(OBF_SPEC)))

/* Separate TU deliberately hides a consumer that retains its argument. */
extern void lifetime_keep(const char *);
extern int lifetime_check(const char *);
extern void lifetime_clobber(void);

static const char *table[] = {"global-table-literal", "second-table-literal"};

PROTECT static const char *direction(unsigned d) {
    switch (d) {
    case 0: return "north-return-literal";
    case 1: return "east-return-literal";
    case 2: return "south-return-literal";
    default: return "west-return-literal";
    }
}

PROTECT static void output_slot(const char **out) {
    *out = "output-slot-literal";
}

PROTECT static void captured_call(void) {
    lifetime_keep("retained-call-literal");
}

PROTECT static const char *derived_return(void) {
    return strchr("search-result-literal", '-');
}

PROTECT static const char *table_pointer(unsigned n) {
    return table[n & 1];
}

PROTECT static void safe_consumer(void) {
    puts("local-consumer-secret");
}

PROTECT int main(void) {
    const char *expected[] = {"north-return-literal", "east-return-literal",
                             "south-return-literal", "west-return-literal"};
    for (unsigned i = 0; i < 4; ++i) {
        const char *p = direction(i);
        lifetime_clobber();
        if (strcmp(p, expected[i])) return 10 + i;
    }
    const char *p;
    output_slot(&p);
    lifetime_clobber();
    if (strcmp(p, "output-slot-literal")) return 20;
    captured_call();
    lifetime_clobber();
    if (lifetime_check("retained-call-literal")) return 21;
    p = derived_return();
    lifetime_clobber();
    if (strcmp(p, "-result-literal")) return 22;
    p = table_pointer(0);
    lifetime_clobber();
    if (p != table[0] || strcmp(p, "global-table-literal")) return 23;
    if ((uintptr_t)(p + 1) != (uintptr_t)(table[0] + 1)) return 24;
    safe_consumer();
    return 0;
}
