#include <stdint.h>
#include <stdio.h>

#define SIZE (16 * 1024 * 1024)

static uint8_t data[SIZE] __attribute__((aligned(4096)));

int main(void)
{
    uint64_t sum = 0;
    for (size_t i = 0; i < SIZE; i++)
        data[i] = (uint8_t)(i * 17 + 3);
    for (int pass = 0; pass < 2; pass++)
        for (size_t i = 0; i < SIZE; i += 64)
            sum += data[i];
    printf("benign-cache checksum=%llu\n", (unsigned long long)sum);
    return 0;
}
