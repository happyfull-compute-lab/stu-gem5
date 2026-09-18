#define _GNU_SOURCE
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int child(void *arg) { (void)arg; _exit(0); }

int main(void)
{
    unsigned long checksum = 0;
    for (int i = 0; i < 8; ++i) {
        char *stack = malloc(16384);
        if (stack) {
            int ret = clone(child, stack + 16384, SIGCHLD, NULL);
            if (ret > 0) {
                checksum += (unsigned long)ret;
                waitpid(ret, NULL, 0);
            }
            free(stack);
        }
        checksum += (unsigned long)getpid();
        checksum += (unsigned long)syscall(SYS_getuid);
    }
    printf("benign-proc-mix checksum=%lu\n", checksum);
    return 0;
}
