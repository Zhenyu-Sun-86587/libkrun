// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE
#include <fcntl.h>
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <net/route.h>
#include <string.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <unistd.h>

/* A present eth0 makes this the managed-uplink fixture. The read-only
 * Guest variant without networking uses precisely the same executable. */
static int configure_uplink(void)
{
    struct ifreq ifr = { .ifr_name = "eth0" };
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    if (ioctl(fd, SIOCGIFINDEX, &ifr)) {
        int absent = errno == ENODEV;
        close(fd);
        return absent ? 0 : -1;
    }
    if (ioctl(fd, SIOCGIFFLAGS, &ifr))
        goto fail;
    ifr.ifr_flags |= IFF_UP;
    if (ioctl(fd, SIOCSIFFLAGS, &ifr))
        goto fail;
    struct sockaddr_in addr = {.sin_family = AF_INET};
    inet_pton(AF_INET, "10.91.0.2", &addr.sin_addr);
    memcpy(&ifr.ifr_addr, &addr, sizeof(addr));
    if (ioctl(fd, SIOCSIFADDR, &ifr))
        goto fail;
    inet_pton(AF_INET, "255.255.255.0", &addr.sin_addr);
    memcpy(&ifr.ifr_netmask, &addr, sizeof(addr));
    if (ioctl(fd, SIOCSIFNETMASK, &ifr))
        goto fail;
    struct rtentry route = { .rt_flags = RTF_UP | RTF_GATEWAY, .rt_dev = ifr.ifr_name };
    route.rt_dst.sa_family = route.rt_genmask.sa_family = AF_INET;
    inet_pton(AF_INET, "10.91.0.1", &addr.sin_addr);
    memcpy(&route.rt_gateway, &addr, sizeof(addr));
    if (ioctl(fd, SIOCADDRT, &route))
        goto fail;
    close(fd);
    return 1;
fail:
    perror("configure managed uplink");
    close(fd);
    return -1;
}

static void report_uplink(void)
{
    struct ifreq ifr = { .ifr_name = "eth0" };
    int sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    struct in_addr ip = {0};
    if (sock < 0 || ioctl(sock, SIOCGIFADDR, &ifr))
        return;
    memcpy(&ip, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, sizeof(ip));
    if (ioctl(sock, SIOCGIFHWADDR, &ifr)) {
        close(sock);
        return;
    }
    const unsigned char *m = (unsigned char *)ifr.ifr_hwaddr.sa_data;
    char dns[64] = {0};
    int file = open("/etc/resolv.conf", O_RDONLY | O_CLOEXEC);
    if (file >= 0) {
        ssize_t n = read(file, dns, sizeof(dns)-1);
        if (n > 0)
            dns[strcspn(dns, "\r\n")] = 0;
        close(file);
    }
    dprintf(1, "UPLINK %s %02x:%02x:%02x:%02x:%02x:%02x %s\n",
            inet_ntoa(ip), m[0], m[1], m[2], m[3], m[4], m[5], dns);
    close(sock);
}

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
    int uplink = configure_uplink();
    if (uplink < 0)
        return 4;
    for (unsigned int tick = 0;;tick++) {
        file = open("/etc/machine-id", O_RDONLY | O_CLOEXEC);
        if (file < 0 || read(file, id, 32) != 32 || close(file) || gethostname(hostname, sizeof(hostname)))
            return 3;
        if (uplink)
            report_uplink();
        dprintf(1, "IDENTITY_TICK %u %d %s %.32s\n", tick, getpid(), hostname, id);
        usleep(80000);
    }
}
