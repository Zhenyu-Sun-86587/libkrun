// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/wait.h>
#include <unistd.h>

static int count(void *arg)
{
    unsigned int index = *(const unsigned int *)arg;
    struct { uint64_t count, monotonic_ns; } sample = {0};
    struct timespec clock;
    int disk = -1;
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
    if (index == 0) {
        char marker[sizeof("smolvm-standby-test")];
        int probe = open("/dev/vda", O_RDWR | O_CLOEXEC);
        if (probe >= 0) {
            if (pread(probe, marker, sizeof(marker), 0) == sizeof(marker) &&
                memcmp(marker, "smolvm-standby-test", sizeof(marker)) == 0)
                disk = probe;
            else
                close(probe);
        }
    }
    for (;;) {
        sample.count++;
        if (clock_gettime(CLOCK_MONOTONIC, &clock) < 0)
            return 1;
        sample.monotonic_ns = (uint64_t)clock.tv_sec * 1000000000 + clock.tv_nsec;
        if (disk >= 0 && (pwrite(disk, &sample.count, 8, 512) != 8 || fdatasync(disk) < 0))
            return 1;
        if (pwrite(fd, &sample, sizeof(sample), 0) != sizeof(sample) || fdatasync(fd) < 0)
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
