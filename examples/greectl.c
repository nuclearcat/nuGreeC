/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/*
 * greectl - command line driver for nuGreeC, and a worked example of the API.
 *
 *   greectl scan
 *   greectl status <ip> <id> [key]
 *   greectl set    <ip> <id> <key> [on|off] [temp N] [mode auto|cool|dry|fan|heat]
 *                                  [fan auto|1..5] [light on|off] [turbo on|off]
 *
 * Without a key the tool binds and prints the one the device hands out; store
 * it and pass it back on later runs so you do not re-bind every time.
 */

#include "gree.h"
#include "udp_posix.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *MODES[] = { "auto", "cool", "dry", "fan", "heat" };

static int die(struct ac_state *ac, const char *what, int rc)
{
    (void)ac;
    fprintf(stderr, "%s: %s\n", what, ac_strerror(rc));
    return 1;
}

static void dump(struct ac_state *ac)
{
    int m = ac_get(ac, AC_MOD);
    int t = ac_room_temp(ac);

    printf("power    %s\n", ac_is_on(ac) ? "on" : "off");
    printf("mode     %s\n", (m >= 0 && m < 5) ? MODES[m] : "?");
    printf("target   %d\n", ac_get(ac, AC_SETTEM));
    if (t != AC_UNKNOWN) printf("room     %d\n", t);
    printf("fan      %d\n", ac_get(ac, AC_WDSPD));
    printf("turbo    %d\n", ac_get(ac, AC_TUR));
    printf("quiet    %d\n", ac_get(ac, AC_QUIET));
    printf("light    %d\n", ac_get(ac, AC_LIG));
    printf("xfan     %d\n", ac_get(ac, AC_BLO));
    printf("sleep    %d\n", ac_get(ac, AC_SWHSLP));
    printf("filter   %d\n", ac_get(ac, AC_DFLTR));
}

static int connect_to(struct ac_state *ac, struct udp_ctx *u,
                      const char *ip, const char *id, const char *key)
{
    struct ac_addr peer;
    int rc;

    if (udp_addr(&peer, ip, 0) < 0) {
        fprintf(stderr, "bad address: %s\n", ip);
        return 1;
    }

    ac_init(ac);
    ac_set_transport(ac, &udp_transport, u);
    ac_set_peer(ac, &peer);

    if (ac_set_device(ac, id) != AC_OK) {
        fprintf(stderr, "device id must be 12 hex characters\n");
        return 1;
    }

    if (key) {
        /* Keys handed out by V2 devices are indistinguishable from V1 keys,
         * so try one and fall back to the other. */
        ac_set_key(ac, key, AC_CIPHER_V1);
        if (ac_poll(ac) == AC_OK) return 0;
        ac_set_key(ac, key, AC_CIPHER_V2);
        rc = ac_poll(ac);
        if (rc != AC_OK) return die(ac, "poll", rc);
        return 0;
    }

    rc = ac_bind(ac);
    if (rc != AC_OK) return die(ac, "bind", rc);
    fprintf(stderr, "bound, key=%s (cipher v%d)\n", ac_get_key(ac), ac->cipher);
    return 0;
}

static int cmd_scan(const char *bcast)
{
    struct udp_ctx u;
    struct ac_state ac;
    struct ac_device dev[8];
    int n, i;

    if (udp_open(&u) < 0) { perror("socket"); return 1; }

    if (bcast && udp_addr(&u.bcast, bcast, 0) < 0) {
        fprintf(stderr, "bad broadcast address: %s\n", bcast);
        udp_close(&u);
        return 1;
    }

    ac_init(&ac);
    ac_set_transport(&ac, &udp_transport, &u);
    /* Replies come back in ~40 ms, but modules ignore a large share of
     * scans, so prefer many short attempts over a few long waits. */
    ac_set_timeout(&ac, 700, 9);

    n = ac_discover(&ac, dev, 8);
    if (n < 0) { udp_close(&u); return die(&ac, "scan", n); }

    for (i = 0; i < n; i++)
        printf("%s  %u.%u.%u.%u  %s\n", dev[i].id,
               dev[i].addr.b[0], dev[i].addr.b[1], dev[i].addr.b[2],
               dev[i].addr.b[3], dev[i].name);
    if (!n)
        printf("no devices answered on %u.%u.%u.%u\n",
               u.bcast.b[0], u.bcast.b[1], u.bcast.b[2], u.bcast.b[3]);

    udp_close(&u);
    return 0;
}

int main(int argc, char **argv)
{
    struct udp_ctx u;
    struct ac_state ac;
    int rc, i;

    if (argc < 2) {
        fprintf(stderr,
                "usage: %s scan [broadcast-addr]\n"
                "       %s status <ip> <id> [key]\n"
                "       %s set <ip> <id> <key> [on|off] [temp N] [mode M]"
                " [fan F] [light on|off] [turbo on|off]\n",
                argv[0], argv[0], argv[0]);
        return 2;
    }

    if (!strcmp(argv[1], "scan")) return cmd_scan(argc > 2 ? argv[2] : 0);

    if (argc < 4) { fprintf(stderr, "missing <ip> <id>\n"); return 2; }
    if (udp_open(&u) < 0) { perror("socket"); return 1; }

    rc = connect_to(&ac, &u, argv[2], argv[3], argc > 4 ? argv[4] : 0);
    if (rc) { udp_close(&u); return rc; }

    if (!strcmp(argv[1], "status")) {
        rc = ac_poll(&ac);
        if (rc != AC_OK) { udp_close(&u); return die(&ac, "poll", rc); }
        dump(&ac);
        udp_close(&u);
        return 0;
    }

    if (strcmp(argv[1], "set")) {
        fprintf(stderr, "unknown command %s\n", argv[1]);
        udp_close(&u);
        return 2;
    }

    for (i = 5; i < argc; i++) {
        const char *a = argv[i];
        const char *v = (i + 1 < argc) ? argv[i + 1] : 0;

        if (!strcmp(a, "on"))       ac_power(&ac, 1);
        else if (!strcmp(a, "off")) ac_power(&ac, 0);
        else if (!strcmp(a, "temp") && v)  { ac_set_temp(&ac, atoi(v)); i++; }
        else if (!strcmp(a, "fan") && v)   { ac_set_fan(&ac, (enum ac_fan)atoi(v)); i++; }
        else if (!strcmp(a, "light") && v) { ac_set(&ac, AC_LIG, !strcmp(v, "on")); i++; }
        else if (!strcmp(a, "turbo") && v) { ac_set(&ac, AC_TUR, !strcmp(v, "on")); i++; }
        else if (!strcmp(a, "mode") && v) {
            int m;
            for (m = 0; m < 5 && strcmp(v, MODES[m]); m++) ;
            if (m == 5) { fprintf(stderr, "bad mode %s\n", v); udp_close(&u); return 2; }
            ac_set_mode(&ac, (enum ac_mode)m);
            i++;
        } else {
            fprintf(stderr, "bad argument %s\n", a);
            udp_close(&u);
            return 2;
        }
    }

    rc = ac_commit(&ac);
    if (rc != AC_OK) { udp_close(&u); return die(&ac, "commit", rc); }

    dump(&ac);
    udp_close(&u);
    return 0;
}
