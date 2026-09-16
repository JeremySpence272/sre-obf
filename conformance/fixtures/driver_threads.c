#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

extern uint32_t obf_target(uint32_t, uint32_t);

uint32_t fixture_text(const char *text, uint32_t seed) {
    while (*text) seed = seed * 33u ^ (unsigned char)*text++;
    return seed;
}

struct job { uint32_t x, y, out; };
static struct job jobs[4096];
static unsigned count;

static void *worker(void *argument) {
    unsigned id = *(unsigned *)argument;
    for (unsigned i = id; i < count; i += 4)
        jobs[i].out = obf_target(jobs[i].x, jobs[i].y);
    return NULL;
}

int main(void) {
    uint32_t x, y;
    while (scanf("%" SCNu32 " %" SCNu32, &x, &y) == 2) {
        if (count == 4096) return 2;
        jobs[count++] = (struct job){x, y, 0};
    }
    if (ferror(stdin)) return 2;
    pthread_t threads[4];
    unsigned ids[4] = {0, 1, 2, 3};
    for (unsigned i = 0; i < 4; ++i)
        if (pthread_create(&threads[i], NULL, worker, &ids[i])) return 3;
    for (unsigned i = 0; i < 4; ++i)
        if (pthread_join(threads[i], NULL)) return 3;
    for (unsigned i = 0; i < count; ++i)
        printf("%08" PRIx32 "\n", jobs[i].out);
    return 0;
}
