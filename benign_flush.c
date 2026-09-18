#include <stdint.h>
#include <stdio.h>
#include <x86intrin.h>

#define LINES 64
#define ITERATIONS 200000

static uint8_t buffer[LINES * 64] __attribute__((aligned(4096)));
static volatile uint64_t sink;

int main(void)
{
    uint64_t x = 0x6a09e667f3bcc909ULL;
    for (int i = 0; i < ITERATIONS; i++) {
        x ^= x << 7;
        x ^= x >> 9;
        x += (uint64_t)i * 0x9e3779b97f4a7c15ULL;
        buffer[(i * 17) & (sizeof(buffer) - 1)] ^= (uint8_t)x;
        if (i % 1000 == 0) {
            for (int line = 0; line < LINES; line++)
                _mm_clflush(&buffer[line * 64]);
            _mm_mfence();
        }
    }
    for (int line = 0; line < LINES; line++)
        sink += buffer[line * 64];
    printf("benign-flush checksum=%llu\n", (unsigned long long)(x ^ sink));
    return 0;
}
