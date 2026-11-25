// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <unistd.h>

int main(void)
{
    const char source_id[] = "0102030405060708090a0b0c0d0e0f10\n";
    char hostname[65] = {0}, id[34] = {0};
    if (mount("tmpfs", "/etc", "tmpfs", MS_NOSUID | MS_NODEV, "mode=0755") ||
        sethostname("capture-source", 14))
        return 1;
    int file = open("/etc/machine-id", O_WRONLY | O_CREAT | O_EXCL, 0444);
    if (file < 0 || write(file, source_id, 33) != 33 || close(file))
        return 2;
    for (unsigned int tick = 0;;tick++) {
        file = open("/etc/machine-id", O_RDONLY | O_CLOEXEC);
        if (file < 0 || read(file, id, 32) != 32 || close(file) || gethostname(hostname, sizeof(hostname)))
            return 3;
        dprintf(1, "IDENTITY_TICK %u %d %s %.32s\n", tick, getpid(), hostname, id);
        usleep(80000);
    }
}
