#include <stdint.h>
#include <stdio.h>

int main(void)
{
    uint64_t x = 0x123456789abcdef0ULL;
    for (uint64_t i = 0; i < 200000; i++) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x += i * 0x9e3779b97f4a7c15ULL;
    }
    printf("benign-compute checksum=%llu\n", (unsigned long long)x);
    return 0;
}
