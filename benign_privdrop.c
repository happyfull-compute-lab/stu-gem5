#define _GNU_SOURCE
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int child(void *arg) { (void)arg; _exit(0); }

static uint64_t fill(uint64_t x)
{
    for (int i = 0; i < 1800; ++i) {
        x ^= x >> 13;
        x *= 0x9e3779b97f4a7c15ULL;
        x ^= x << 17;
    }
    return x;
}

int main(void)
{
    const int rounds = 240;
    int clones = 0, setuids = 0;
    uint64_t checksum = 0x123456789abcdef0ULL;

    for (int i = 0; i < rounds; ++i) {
        checksum = fill(checksum + (uint64_t)i);
        char *stack = malloc(16384);
        if (stack) {
            int ret = clone(child, stack + 16384, SIGCHLD, NULL);
            ++clones;
            if (ret > 0)
                waitpid(ret, NULL, 0);
            free(stack);
        }
        if (i % 48 == 0) {
            (void)syscall(SYS_setuid, (uid_t)1000);
            ++setuids;
        }
    }
    printf("[PRIVDROP] clones=%d setuid=%d done checksum=%llu\n",
           clones, setuids, (unsigned long long)checksum);
    return 0;
}
