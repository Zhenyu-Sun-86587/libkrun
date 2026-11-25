// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static int count(void *arg)
{
    unsigned int index = *(const unsigned int *)arg;
    uint64_t value = 0;
    cpu_set_t cpus;
    char path[64];
    int fd;

    CPU_ZERO(&cpus);
    CPU_SET(index % 2, &cpus);
    if (sched_setaffinity(0, sizeof(cpus), &cpus) < 0)
        return 1;
    snprintf(path, sizeof(path), "/counter-%u", index);
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0)
        return 1;
    for (;;) {
        value++;
        if (pwrite(fd, &value, sizeof(value), 0) != sizeof(value) || fdatasync(fd) < 0)
            return 1;
        usleep(20000);
    }
}

int main(void)
{
    static char stack[65536] __attribute__((aligned(16)));
    for (unsigned int index = 0; index < 3; index++) {
        pid_t child;
        if (index == 2) {
            child = clone(count, stack + sizeof(stack), CLONE_NEWPID | SIGCHLD, &index);
        } else {
            child = fork();
            if (child == 0)
                _exit(count(&index));
        }
        if (child < 0)
            return 1;
    }
    int status;
    return wait(&status) < 0 ? 1 : (WIFEXITED(status) ? WEXITSTATUS(status) : 1);
}
