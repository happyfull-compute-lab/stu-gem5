#define _GNU_SOURCE
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct worker_arg {
    uint64_t seed;
    uint64_t result;
};

static void *worker(void *opaque)
{
    struct worker_arg *arg = opaque;
    uint64_t x = arg->seed;
    for (int i = 0; i < 250000; ++i) {
        x ^= x >> 12;
        x *= 0x9e3779b97f4a7c15ULL;
        x ^= x << 25;
        x += (uint64_t)i;
    }
    arg->result = x;
    return NULL;
}

int main(void)
{
    pthread_t threads[4];
    struct worker_arg args[4];
    int created = 0;
    uint64_t checksum = 0;

    for (int i = 0; i < 4; ++i) {
        args[i].seed = 0x123456789abcdef0ULL + (uint64_t)i;
        args[i].result = 0;
        if (pthread_create(&threads[i], NULL, worker, &args[i]) != 0)
            break;
        ++created;
    }
    for (int i = 0; i < created; ++i) {
        pthread_join(threads[i], NULL);
        checksum ^= args[i].result;
    }
    printf("[PTHREAD] requested=4 created=%d checksum=%llu\n",
           created, (unsigned long long)checksum);
    return created == 4 ? 0 : 1;
}
