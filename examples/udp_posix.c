/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* nuGreeC - example transport: BSD sockets over IPv4/UDP. */

#include "udp_posix.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define GREE_PORT 7000

/* ac_addr layout used by this transport: 4 bytes IPv4, 2 bytes port (BE). */

static void addr_to_sock(const struct ac_addr *a, struct sockaddr_in *s)
{
    memset(s, 0, sizeof *s);
    s->sin_family = AF_INET;
    memcpy(&s->sin_addr, a->b, 4);
    s->sin_port = htons((unsigned short)((a->b[4] << 8) | a->b[5]));
}

static void sock_to_addr(const struct sockaddr_in *s, struct ac_addr *a)
{
    unsigned short p = ntohs(s->sin_port);

    memset(a, 0, sizeof *a);
    memcpy(a->b, &s->sin_addr, 4);
    a->b[4] = (unsigned char)(p >> 8);
    a->b[5] = (unsigned char)p;
}

int udp_addr(struct ac_addr *a, const char *ip, unsigned port)
{
    struct in_addr in;

    if (inet_pton(AF_INET, ip, &in) != 1) return -1;
    memset(a, 0, sizeof *a);
    memcpy(a->b, &in, 4);
    if (!port) port = GREE_PORT;
    a->b[4] = (unsigned char)(port >> 8);
    a->b[5] = (unsigned char)port;
    return 0;
}

int udp_open(struct udp_ctx *u)
{
    struct sockaddr_in me;
    int on = 1;

    u->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (u->fd < 0) return -1;

    setsockopt(u->fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof on);
    setsockopt(u->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);

    memset(&me, 0, sizeof me);
    me.sin_family = AF_INET;
    me.sin_addr.s_addr = htonl(INADDR_ANY);
    me.sin_port = 0;                       /* ephemeral */
    if (bind(u->fd, (struct sockaddr *)&me, sizeof me) < 0) {
        close(u->fd);
        u->fd = -1;
        return -1;
    }
    udp_addr(&u->bcast, "255.255.255.255", GREE_PORT);
    return 0;
}

void udp_close(struct udp_ctx *u)
{
    if (u->fd >= 0) close(u->fd);
    u->fd = -1;
}

static int tx(void *ctx, const void *buf, unsigned len, const struct ac_addr *peer)
{
    struct udp_ctx *u = ctx;
    struct sockaddr_in to;

    addr_to_sock(peer ? peer : &u->bcast, &to);
    if (sendto(u->fd, buf, len, 0, (struct sockaddr *)&to, sizeof to) < 0)
        return -1;
    return 0;
}

static int rx(void *ctx, void *buf, unsigned cap, unsigned timeout_ms,
              struct ac_addr *peer)
{
    struct udp_ctx *u = ctx;
    struct sockaddr_in from;
    socklen_t fl = sizeof from;
    struct timeval tv;
    ssize_t n;

    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(u->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    n = recvfrom(u->fd, buf, cap, 0, (struct sockaddr *)&from, &fl);
    if (n < 0) return 0;                   /* treat EAGAIN as a timeout */
    if (peer) sock_to_addr(&from, peer);
    return (int)n;
}

const struct ac_transport udp_transport = { tx, rx };
