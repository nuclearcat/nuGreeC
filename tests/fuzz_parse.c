/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/*
 * nuGreeC parser fuzzer.
 *
 * Everything the library parses arrives from the network, so the receive path
 * has to survive arbitrary bytes without reading or writing out of bounds.
 * This is a self-contained deterministic fuzzer (no libFuzzer needed):
 *
 *     make fuzz            # ~200k cases under ASan/UBSan
 *     make fuzz FUZZ_N=5000000
 *
 * It drives rx_unpack() and take_reply() directly, which is where hostile
 * input lands, and mutates both raw datagrams and structurally valid ones.
 */

#include "../src/gree.c"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t rnd_state = 0x2c6d1f3b;

static uint32_t rnd(void)
{
    rnd_state ^= rnd_state << 13;
    rnd_state ^= rnd_state >> 17;
    rnd_state ^= rnd_state << 5;
    return rnd_state;
}

static const char *FRAGMENTS[] = {
    "{", "}", "[", "]", "\"", ":", ",", "\\", "pack", "tag", "t", "dat", "res",
    "cols", "opt", "val", "p", "r", "key", "bindok", "mac", "Pow", "SetTem",
    "200", "-1", "99999999999", "0", "true", "null", "\"\"", "AAAA", "==",
    "\\\"", "\xff\xfe", " ", "\n"
};

/* Build a plausible-looking datagram out of random fragments. */
static unsigned gen_soup(char *out, unsigned cap)
{
    unsigned n = 0, parts = rnd() % 40 + 1;

    while (parts-- && n + 24 < cap) {
        const char *f = FRAGMENTS[rnd() % (sizeof FRAGMENTS / sizeof *FRAGMENTS)];
        unsigned l = (unsigned)strlen(f);
        memcpy(out + n, f, l);
        n += l;
    }
    out[n] = 0;
    return n;
}

/* Build a real encrypted packet, then corrupt it. */
static unsigned gen_mutated(char *out, unsigned cap, const char *key, int cipher)
{
    uint8_t tmp[GREE_INNER_BUF];
    uint8_t tag[16];
    struct jw w;
    unsigned clen, n, flips;
    static const char INNER[] =
        "{\"t\":\"dat\",\"r\":200,\"mac\":\"502cc6aabbcc\","
        "\"cols\":[\"Pow\",\"Mod\",\"SetTem\"],\"dat\":[1,4,30]}";

    n = (unsigned)strlen(INNER);
    memcpy(tmp, INNER, n);

    if (cipher == AC_CIPHER_V2) {
        gree_gcm_encrypt((const uint8_t *)key, tmp, n, tag);
        clen = n;
    } else {
        clen = gree_ecb_encrypt((const uint8_t *)key, tmp, n, sizeof tmp);
    }

    w.p = (uint8_t *)out;
    w.left = cap - 1;
    w.ovf = 0;
    w_str(&w, "{\"t\":\"pack\",\"i\":0,\"pack\":\"");
    w_b64(&w, tmp, clen);
    w_ch(&w, '"');
    if (cipher == AC_CIPHER_V2) {
        w_str(&w, ",\"tag\":\"");
        w_b64(&w, tag, 16);
        w_ch(&w, '"');
    }
    w_ch(&w, '}');
    n = cap - 1 - w.left;

    for (flips = rnd() % 6; flips; flips--) {
        unsigned at = rnd() % n;
        out[at] = (char)(rnd() & 0xff);
    }
    if (rnd() & 1) n -= rnd() % (n / 2 + 1);   /* truncate */

    out[n] = 0;
    return n;
}

int main(int argc, char **argv)
{
    unsigned long iters = (argc > 1) ? strtoul(argv[1], 0, 10) : 200000;
    unsigned long i;
    static struct ac_state ac;
    static char pkt[GREE_PKT_BUF];

    for (i = 0; i < iters; i++) {
        unsigned n;
        int cipher, rc;
        const char *key;

        ac_init(&ac);
        ac_set_device(&ac, "502cc6aabbcc");

        cipher = (rnd() & 1) ? AC_CIPHER_V1 : AC_CIPHER_V2;
#if !GREE_ENABLE_V2
        cipher = AC_CIPHER_V1;
#endif
#if !GREE_ENABLE_V1
        cipher = AC_CIPHER_V2;
#endif
        key = (cipher == AC_CIPHER_V2) ? "{yxAHAY_Lm6pbC/<" : "a3K8Bx%2r8Y7#xDh";

        switch (rnd() % 3) {
        case 0:                                  /* raw noise */
            n = rnd() % (sizeof pkt - 1);
            {
                unsigned k;
                for (k = 0; k < n; k++) pkt[k] = (char)(rnd() & 0xff);
                pkt[n] = 0;
            }
            break;
        case 1:
            n = gen_soup(pkt, sizeof pkt - 1);
            break;
        default:
            n = gen_mutated(pkt, sizeof pkt - 1, key, cipher);
            break;
        }

        memcpy(ac.buf, pkt, n);
        rc = rx_unpack(&ac, n, key, cipher);

        /* Whatever came out, the higher layers must also survive it. */
        if (rc == AC_OK) {
            take_reply(&ac, "dat");
            take_reply(&ac, "res");
            take_reply(&ac, "bindok");
            ac_room_temp(&ac);
        }
    }

    printf("fuzz: %lu cases, no faults\n", iters);
    return 0;
}
