#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

int main(void)
{
    unsigned long sum = 0;
    for (int i = 0; i < 100000; i++)
        sum += (unsigned long)getpid();
    printf("benign-syscall checksum=%lu\n", sum);
    return 0;
}
