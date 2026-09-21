#include <stdio.h>

#ifndef OBF_SPEC
#define OBF_SPEC "obf: strenc(cipher=aes,minlen=1,keysplit=1)"
#endif
#define PROTECT __attribute__((noinline, annotate(OBF_SPEC)))

PROTECT static unsigned hot_impl(unsigned x) {
    return x * 13u + 7u;
}

PROTECT static void cold_impl(int take) {
    if (take) {
        puts("cold-only-secret");
        puts("cold-only-secret");
    }
}

PROTECT static void loop_impl(int n, int mask) {
    for (int i = 0; i < n; ++i)
        if (i & mask) puts("loop-only-secret");
}

PROTECT static void branches_impl(int first, int second) {
    if (first) puts("shared-branch-secret");
    if (second) puts("shared-branch-secret");
}

PROTECT static void recursive_impl(int n, int take) {
    if (n > 0) recursive_impl(n - 1, take);
    if (take) puts("recursive-only-secret");
}

PROTECT static void nested_impl(int n, int take) {
    for (int i = 0; i < n; ++i)
        for (int j = 0; j < i; ++j)
            if (take) puts("nested-only-secret");
}

/* Public wrappers keep the driver separate while making implementations
 * eligible for fmerge's local-linkage contract. */
unsigned lazy_hot(unsigned x) { return hot_impl(x); }
void lazy_cold(int take) { cold_impl(take); }
void lazy_loop(int n, int mask) { loop_impl(n, mask); }
void lazy_branches(int first, int second) { branches_impl(first, second); }
void lazy_recursive(int n, int take) { recursive_impl(n, take); }
void lazy_nested(int n, int take) { nested_impl(n, take); }
