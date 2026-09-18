#include <stdio.h>
#include <stdint.h>
#include <x86intrin.h>

static uint8_t buf[64] __attribute__((aligned(64)));

static inline uint64_t rdtsc(void)
{
    unsigned lo, hi;
    asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

int main(void)
{
    volatile uint8_t *p = buf;
    uint64_t t0, t1, hit, miss;
    *p = 1;
    t0 = rdtsc();
    (void)*p;
    t1 = rdtsc();
    hit = t1 - t0;
    __builtin_ia32_clflush((const void *)p);
    t0 = rdtsc();
    (void)*p;
    t1 = rdtsc();
    miss = t1 - t0;
    printf("hit=%lu miss=%lu ratio=%.2f\n", hit, miss,
           miss / (double)(hit ? hit : 1));
    return 0;
}
