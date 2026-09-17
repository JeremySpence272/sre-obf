/* Four concurrent callers of the same private encoded interfaces, in the
 * pattern of driver_threads.c but over the whole-program vector protocol of
 * whole_main.c. Per-activation interface state lives on the stack, so this
 * build must print exactly what the single-threaded main prints. */
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

extern uint32_t producer(uint32_t x, uint32_t y);

struct job { uint32_t x, y, out; };
static struct job jobs[4096];
static unsigned count;

static void *worker(void *argument) {
    unsigned id = *(unsigned *)argument;
    for (unsigned i = id; i < count; i += 4) jobs[i].out = producer(jobs[i].x, jobs[i].y);
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
    for (unsigned i = 0; i < count; ++i) printf("%u\n", jobs[i].out);
    return 0;
}
