// SPDX-License-Identifier: Apache-2.0
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

/* Test the real kernel's response to losing its measured helper while armed. */
int main(void)
{
    char ready[80] = {'S', 'G', 'A', '1', 1};
    int fd = open("/dev/smolvm-identity", O_RDWR | O_CLOEXEC | O_NOFOLLOW);

    if (fd < 0 || mlockall(MCL_CURRENT | MCL_FUTURE) < 0 ||
        write(fd, ready, sizeof(ready)) != sizeof(ready))
        return 1;

    struct timespec pause = {.tv_sec = 1, .tv_nsec = 250 * 1000 * 1000};
    while (nanosleep(&pause, &pause) < 0 && errno == EINTR)
        ;
    return raise(SIGKILL) != 0;
}
