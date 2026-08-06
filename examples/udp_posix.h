/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* nuGreeC - example transport: BSD sockets over IPv4/UDP.
 *
 * This file is not part of the library. It shows what a port needs to
 * provide: two functions and a context. lwIP, ESP-IDF, Zephyr and an RTOS
 * raw-UDP callback all map onto the same two calls.
 */
#ifndef NUGREEC_UDP_POSIX_H
#define NUGREEC_UDP_POSIX_H

#include "gree.h"

struct udp_ctx {
    int fd;
    struct ac_addr bcast;   /* where ac_discover's broadcast goes */
};

/* Bind a UDP socket with broadcast enabled. Returns 0 or -1.
 *
 * The broadcast address defaults to 255.255.255.255, which the kernel sends
 * out the default route only. On a host with several interfaces (docker,
 * VPNs) that is usually the wrong one, so set u->bcast to the subnet
 * broadcast of the interface the A/C is on, e.g. 192.168.1.255. */
int udp_open(struct udp_ctx *u);
void udp_close(struct udp_ctx *u);

/* Build an ac_addr from a dotted-quad string and a port. */
int udp_addr(struct ac_addr *a, const char *ip, unsigned port);

extern const struct ac_transport udp_transport;

#endif
