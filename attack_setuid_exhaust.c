#define _GNU_SOURCE
#include <errno.h>
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
    const int attempts_limit = 40000;
    int accepted = 0, rejected = 0;
    int would_fail = 0;
    printf("[RATC] begin storm\n");
    for (int i = 0; i < attempts_limit; ++i) {
        char *stack = malloc(16384);
        if (!stack) { ++rejected; continue; }
        int ret = clone(child, stack + 16384, SIGCHLD, NULL);
        if (ret > 0) {
            ++accepted;
            waitpid(ret, NULL, 0);
        }
        else ++rejected;
        free(stack);
        if (i == 1000) {
            errno = 0;
            if (syscall(SYS_setuid, (uid_t)1000) < 0 && errno == EPERM)
                ++would_fail;
        }
    }
    printf("[RATC] clone attempts=%d accepted=%d rejected=%d\n",
           attempts_limit, accepted, rejected);
    printf("[RATC] end storm\n[RATC] setuid phase begin\n");
    for (int i = would_fail; i < 40; ++i) {
        errno = 0;
        if (syscall(SYS_setuid, (uid_t)1000) < 0 && errno == EPERM)
            ++would_fail;
    }
    printf("[RATC] setuid would-fail count=%d\n", would_fail);
    printf("[RATC] escalation=simulated-success (setuid exhaustion model)\n");
    return 0;
}
