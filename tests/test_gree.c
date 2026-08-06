/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/*
 * nuGreeC self-tests.
 *
 * gree.c is #included so the tests can reach its internal JSON and base64
 * helpers, and so the mock device can reuse them instead of growing a second
 * parser. The crypto known-answer vectors were produced with pycryptodome
 * using the protocol's real keys, nonce and AAD.
 */

#include "../src/gree.c"

#include <stdio.h>
#include <string.h>

static int fails;

#define CHECK(cond) do {                                            \
        if (!(cond)) {                                              \
            printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);  \
            fails++;                                                \
        }                                                           \
    } while (0)

#define CHECK_EQ(got, want) do {                                            \
        long g_ = (long)(got), w_ = (long)(want);                           \
        if (g_ != w_) {                                                     \
            printf("FAIL %s:%d  %s = %ld, want %ld\n",                      \
                   __FILE__, __LINE__, #got, g_, w_);                       \
            fails++;                                                        \
        }                                                                   \
    } while (0)

static const char SAMPLE[] =
    "{\"t\":\"status\",\"mac\":\"502cc6aabbcc\",\"cols\":[\"Pow\",\"Mod\"]}";

/* ------------------------------------------------------------- crypto KAT */

static void b64_of(const uint8_t *p, unsigned n, char *out, unsigned cap)
{
    struct jw w;
    w.p = (uint8_t *)out;
    w.left = cap - 1;
    w.ovf = 0;
    w_b64(&w, p, n);
    out[cap - 1 - w.left] = 0;
}

/* Cipher the mock falls back to when only one is compiled in. */
#if GREE_ENABLE_V1
#define ANY_CIPHER AC_CIPHER_V1
#else
#define ANY_CIPHER AC_CIPHER_V2
#endif

/* A 26-property poll needs roughly this much room for the reply. */
#define FULL_POLL_FITS (GREE_INNER_BUF >= 448 && GREE_PKT_BUF >= 700)

#if GREE_ENABLE_V1 && GREE_ENABLE_V2
#define GENERIC_KEY(c) ((c) == AC_CIPHER_V2 ? KEY_V2 : KEY_V1)
#elif GREE_ENABLE_V1
#define GENERIC_KEY(c) (KEY_V1)
#else
#define GENERIC_KEY(c) (KEY_V2)
#endif

#if GREE_ENABLE_V1
static void test_ecb(void)
{
    uint8_t buf[128];
    char b64[256];
    unsigned n = (unsigned)strlen(SAMPLE), clen;

    memcpy(buf, SAMPLE, n);
    clen = gree_ecb_encrypt((const uint8_t *)KEY_V1, buf, n, sizeof buf);
    CHECK_EQ(clen, 64);                 /* 56 bytes + 8 bytes of PKCS#7 */

    b64_of(buf, clen, b64, sizeof b64);
    CHECK(!strcmp(b64,
        "eSn7Wn1ITLUrYQYF4JLC10Og7rJVL6QwWw9Qi8/JcVi7xk1ffvnyAhbTMKWn"
        "/BGVv54rTu8Jnl5JirOS+ec8XA=="));

    CHECK_EQ(gree_ecb_decrypt((const uint8_t *)KEY_V1, buf, clen), 0);
    CHECK(!memcmp(buf, SAMPLE, n));

    /* A plaintext that is already a multiple of 16 still gains a full block. */
    memcpy(buf, SAMPLE, 32);
    CHECK_EQ(gree_ecb_encrypt((const uint8_t *)KEY_V1, buf, 32, sizeof buf), 48);

    /* Padding that does not fit must be refused, not truncated. */
    memcpy(buf, SAMPLE, 20);
    CHECK_EQ(gree_ecb_encrypt((const uint8_t *)KEY_V1, buf, 20, 24), 0);
}
#endif /* GREE_ENABLE_V1 */

#if GREE_ENABLE_V2
static void test_gcm(void)
{
    static const uint8_t WANT_CT[] = {
        0x26,0xda,0x0a,0x96,0x2c,0x2d,0xba,0x84,0xb2,0xf2,0x89,0xc4,0x78,0x65,
        0x57,0x5a,0xce,0x22,0xaa,0xd9,0x00,0xd7,0x17,0xf4,0x63,0x07,0x62,0x5c,
        0xbb,0x89,0xc4,0xab,0x92,0x34,0x21,0x4d,0x8e,0x0e,0x32,0x39,0xca,0xaf,
        0x8c,0xae,0xf4,0x05,0x92,0x9c,0xcf,0xbd,0xdd,0x5d,0xc2,0xad,0x51,0xab
    };
    static const uint8_t WANT_TAG[] = {
        0x9d,0xbc,0xdc,0x2f,0x2c,0xff,0x64,0x14,
        0x0f,0x42,0xbd,0x75,0xe5,0x9f,0xd5,0x30
    };
    uint8_t buf[128], tag[16];
    unsigned n = (unsigned)strlen(SAMPLE);

    CHECK_EQ(n, sizeof WANT_CT);

    memcpy(buf, SAMPLE, n);
    gree_gcm_encrypt((const uint8_t *)KEY_V2, buf, n, tag);
    CHECK(!memcmp(buf, WANT_CT, n));
    CHECK(!memcmp(tag, WANT_TAG, 16));

    CHECK_EQ(gree_gcm_decrypt((const uint8_t *)KEY_V2, buf, n, WANT_TAG), 0);
    CHECK(!memcmp(buf, SAMPLE, n));

    /* Every single-bit tag change must be rejected. */
    {
        uint8_t bad[16];
        unsigned b;
        for (b = 0; b < 128; b++) {
            memcpy(bad, WANT_TAG, 16);
            bad[b / 8] ^= (uint8_t)(1u << (b % 8));
            memcpy(buf, WANT_CT, n);
            CHECK_EQ(gree_gcm_decrypt((const uint8_t *)KEY_V2, buf, n, bad), -1);
        }
        memcpy(buf, WANT_CT, n);
        CHECK_EQ(gree_gcm_decrypt((const uint8_t *)KEY_V2, buf, n, WANT_TAG), 0);
    }

    /* Partial trailing block: 5 bytes exercises the short-block path. */
    memcpy(buf, SAMPLE, 5);
    gree_gcm_encrypt((const uint8_t *)KEY_V2, buf, 5, tag);
    CHECK_EQ(gree_gcm_decrypt((const uint8_t *)KEY_V2, buf, 5, tag), 0);
    CHECK(!memcmp(buf, SAMPLE, 5));
}
#endif /* GREE_ENABLE_V2 */

/* ------------------------------------------------------------ base64/JSON */

static void test_b64(void)
{
    uint8_t out[64];
    char enc[64];
    unsigned i;

    for (i = 0; i < 5; i++) {
        static const uint8_t src[4] = { 0x00, 0xff, 0x10, 0xab };
        int n;

        b64_of(src, i > 4 ? 4 : i, enc, sizeof enc);
        n = b64_decode(enc, out, sizeof out);
        CHECK_EQ(n, i);
        CHECK(!memcmp(out, src, i));
    }

    /* Decoding stops at the closing quote, not at the end of the buffer. */
    CHECK_EQ(b64_decode("QUJD\",\"tag\":\"x", out, sizeof out), 3);
    CHECK(!memcmp(out, "ABC", 3));

    /* Overflow is reported, never written past cap. */
    CHECK_EQ(b64_decode("QUJDREVG", out, 2), -1);
}

static void test_json(void)
{
    static const char OBJ[] =
        "{\"t\":\"pack\",\"i\":0,\"uid\":0,\"pack\":\"AAA\",\"n\":-7}";
    const char *p;

    p = j_find(OBJ, "t");
    CHECK(j_is(p, "pack"));

    /* "pack" appears as a value before it appears as a key: the scanner must
     * not stop on the value. */
    p = j_find(OBJ, "pack");
    CHECK(p && p[0] == '"' && p[1] == 'A');

    CHECK_EQ(j_int(j_find(OBJ, "n")), -7);
    CHECK_EQ(j_int(j_find(OBJ, "i")), 0);
    CHECK(j_find(OBJ, "nope") == 0);

    /* A key that is a prefix of another must not match it. */
    CHECK(j_find("{\"tag\":\"x\"}", "t") == 0);
    CHECK(j_find("{\"t\":1,\"tag\":2}", "tag") != 0);
}

static void test_props(void)
{
    unsigned i;

    for (i = 0; i < AC_PROP_COUNT; i++) {
        const char *n = p_name(i);
        CHECK_EQ(p_index(n, (unsigned)strlen(n)), (int)i);
    }
    CHECK(!strcmp(p_name(AC_POW), "Pow"));
    CHECK(!strcmp(p_name(AC_SETTEM), "SetTem"));
    CHECK(!strcmp(p_name(AC_BUZZER), "Buzzer_ON_OFF"));
    CHECK_EQ(p_index("Nope", 4), -1);
    CHECK_EQ(p_index("Po", 2), -1);          /* prefix must not match Pow */
}

/* ------------------------------------------------------------ mock device */

#define MOCK_KEY "MockKey123456789"

static struct {
    int cipher;                 /* cipher the client used on the last request */
    int bound;
    int16_t val[AC_PROP_COUNT];
    int reply_len;
    int corrupt_tag;
    int drop_next;              /* swallow one request to exercise retries */
    int bloat;                  /* pad the reply past the client's buffer */
    int requests;
} dev;

static void mock_reset(void)
{
    unsigned i;
    memset(&dev, 0, sizeof dev);
    for (i = 0; i < AC_PROP_COUNT; i++) dev.val[i] = 0;
    dev.val[AC_POW] = 1;
    dev.val[AC_MOD] = AC_MODE_HEAT;
    dev.val[AC_SETTEM] = 30;
    dev.val[AC_TEMSEN] = 63;             /* firmware that adds 40 */
    dev.val[AC_WDSPD] = 1;
    dev.val[AC_LIG] = 1;
}

/* The mock has its own, deliberately larger, buffers: it must be able to
 * produce replies that the client cannot swallow. */
#define MOCK_INNER (GREE_INNER_BUF + 256)
#define MOCK_OUTER (GREE_PKT_BUF + 512)

static uint8_t mock_out[MOCK_OUTER];

static void mock_wrap(const char *inner, int cipher, const char *key)
{
    uint8_t tmp[MOCK_INNER];
    uint8_t tag[16];
    unsigned n = (unsigned)strlen(inner), clen;
    struct jw w;

    memcpy(tmp, inner, n);
    if (cipher == AC_CIPHER_V2) {
#if GREE_ENABLE_V2
        gree_gcm_encrypt((const uint8_t *)key, tmp, n, tag);
        clen = n;
        if (dev.corrupt_tag) tag[0] ^= 0xff;
#else
        return;
#endif
    } else {
#if GREE_ENABLE_V1
        clen = gree_ecb_encrypt((const uint8_t *)key, tmp, n, sizeof tmp);
#else
        return;
#endif
    }

    w.p = mock_out;
    w.left = sizeof mock_out;
    w.ovf = 0;
    w_str(&w, "{\"t\":\"pack\",\"i\":0,\"uid\":0,\"cid\":\"502cc6aabbcc\","
              "\"tcid\":\"app\",\"pack\":\"");
    w_b64(&w, tmp, clen);
    w_ch(&w, '"');
    if (cipher == AC_CIPHER_V2) {
        w_str(&w, ",\"tag\":\"");
        w_b64(&w, tag, 16);
        w_ch(&w, '"');
    }
    w_ch(&w, '}');
    CHECK(!w.ovf);
    dev.reply_len = (int)(sizeof mock_out - w.left);
}

/* Append the requested column names and the device's values for them. */
static void mock_status(const char *cols, char *out, unsigned cap)
{
    char vals[256];
    unsigned o = 0, v = 0;

    o += (unsigned)snprintf(out + o, cap - o,
                            "{\"t\":\"dat\",\"r\":200,\"mac\":\"502cc6aabbcc\",\"cols\":[");
    cols++;
    for (;;) {
        const char *ns, *ne;
        int idx;

        while (is_ws(*cols) || *cols == ',') cols++;
        if (*cols != '"') break;
        ns = cols + 1;
        ne = ns;
        while (*ne && *ne != '"') ne++;
        cols = ne + 1;

        idx = p_index(ns, (unsigned)(ne - ns));
        o += (unsigned)snprintf(out + o, cap - o, "%s\"%.*s\"",
                                v ? "," : "", (int)(ne - ns), ns);
        v += (unsigned)snprintf(vals + v, sizeof vals - v, "%s%d",
                                v ? "," : "", idx < 0 ? 0 : dev.val[idx]);
    }
    o += (unsigned)snprintf(out + o, cap - o, "],\"dat\":[%s]", vals);

    if (dev.bloat) {
        /* A field the client does not model, sized so the inner packet just
         * exceeds GREE_INNER_BUF while the datagram still fits GREE_PKT_BUF.
         * Real firmware does add fields we did not plan for. */
        unsigned target = GREE_INNER_BUF + 8;

        o += (unsigned)snprintf(out + o, cap - o, ",\"junk\":\"");
        while (o + 2 < target && o + 3 < cap) out[o++] = 'x';
        o += (unsigned)snprintf(out + o, cap - o, "\"");
    }
    snprintf(out + o, cap - o, "}");
}

static void mock_cmd(const char *opt, const char *p, char *out, unsigned cap)
{
    char names[256], vals[128];
    unsigned no = 0, v = 0;

    opt++;
    p++;
    for (;;) {
        const char *ns, *ne;
        long val = 0;
        int idx, kind;

        while (is_ws(*opt) || *opt == ',') opt++;
        if (*opt != '"') break;
        ns = opt + 1;
        ne = ns;
        while (*ne && *ne != '"') ne++;
        opt = ne + 1;

        kind = next_val(&p, &val);
        if (kind < 0) break;

        idx = p_index(ns, (unsigned)(ne - ns));
        if (idx >= 0) dev.val[idx] = (int16_t)val;

        no += (unsigned)snprintf(names + no, sizeof names - no, "%s\"%.*s\"",
                                 no ? "," : "", (int)(ne - ns), ns);
        v += (unsigned)snprintf(vals + v, sizeof vals - v, "%s%ld",
                                v ? "," : "", val);
    }
    snprintf(out, cap, "{\"t\":\"res\",\"r\":200,\"mac\":\"502cc6aabbcc\","
                       "\"opt\":[%s],\"val\":[%s]}", names, vals);
}

static int mock_send(void *ctx, const void *buf, unsigned len,
                     const struct ac_addr *peer)
{
    static char req[MOCK_OUTER];
    static char inner[MOCK_INNER];
    static char out[MOCK_INNER];
    const char *p, *key;
    int cipher, n, i;

    (void)ctx; (void)peer;
    dev.requests++;
    dev.reply_len = 0;

    if (len >= sizeof req) return -1;
    memcpy(req, buf, len);
    req[len] = 0;

    if (dev.drop_next) { dev.drop_next = 0; return 0; }

    if (j_is(j_find(req, "t"), "scan")) {
        mock_wrap("{\"t\":\"dev\",\"mac\":\"502cc6aabbcc\",\"name\":\"bedroom\","
                  "\"brand\":\"gree\",\"ver\":\"V1.45\"}",
                  ANY_CIPHER, GENERIC_KEY(ANY_CIPHER));
        return 0;
    }

    p = j_find(req, "pack");
    if (!p || *p != '"') return -1;

    cipher = j_find(req, "tag") ? AC_CIPHER_V2 : AC_CIPHER_V1;
    dev.cipher = cipher;

    /* i == 1 marks bind, which still uses the generic key. */
    key = j_int(j_find(req, "i")) == 1 ? GENERIC_KEY(cipher) : MOCK_KEY;

    n = b64_decode(p + 1, (uint8_t *)inner, sizeof inner - 1);
    if (n <= 0) return -1;

    if (cipher == AC_CIPHER_V2) {
#if GREE_ENABLE_V2
        uint8_t tag[16];
        /* The mock trusts its own client, so recompute rather than verify. */
        gree_gcm_encrypt((const uint8_t *)key, (uint8_t *)inner, (unsigned)n, tag);
#else
        return -1;
#endif
    } else {
#if GREE_ENABLE_V1
        if (gree_ecb_decrypt((const uint8_t *)key, (uint8_t *)inner, (unsigned)n) < 0)
            return -1;
#else
        return -1;
#endif
    }
    for (i = n - 1; i >= 0 && inner[i] != '}'; i--) ;
    if (i < 0) return -1;
    inner[i + 1] = 0;

    if (j_is(j_find(inner, "t"), "bind")) {
        dev.bound = 1;
        snprintf(out, sizeof out,
                 "{\"t\":\"bindok\",\"mac\":\"502cc6aabbcc\",\"key\":\"%s\",\"r\":200}",
                 MOCK_KEY);
    } else if (j_is(j_find(inner, "t"), "status")) {
        mock_status(j_find(inner, "cols"), out, sizeof out);
    } else if (j_is(j_find(inner, "t"), "cmd")) {
        mock_cmd(j_find(inner, "opt"), j_find(inner, "p"), out, sizeof out);
    } else {
        return -1;
    }

    mock_wrap(out, cipher, key);
    return 0;
}

static int mock_recv(void *ctx, void *buf, unsigned cap, unsigned timeout_ms,
                     struct ac_addr *peer)
{
    int n = dev.reply_len;

    (void)ctx; (void)timeout_ms;
    if (n <= 0) return 0;
    if (n > (int)cap) n = (int)cap;    /* real UDP truncates too */

    memcpy(buf, mock_out, (unsigned)n);
    dev.reply_len = 0;
    if (peer) {
        memset(peer, 0, sizeof *peer);
        peer->b[0] = 192; peer->b[1] = 168; peer->b[2] = 1; peer->b[3] = 50;
        peer->b[4] = 27; peer->b[5] = 88;
    }
    return n;
}

static const struct ac_transport mock_transport = { mock_send, mock_recv };

static void setup(struct ac_state *ac)
{
    struct ac_addr peer;

    memset(&peer, 0, sizeof peer);
    peer.b[0] = 192; peer.b[3] = 50;

    ac_init(ac);
    ac_set_transport(ac, &mock_transport, 0);
    ac_set_peer(ac, &peer);
    CHECK_EQ(ac_set_device(ac, "502cc6aabbcc"), AC_OK);
}

/* ------------------------------------------------------------ end to end */

static void test_session(int force_cipher)
{
    struct ac_state ac;

    mock_reset();
    setup(&ac);
    if (force_cipher) ac.cipher = (uint8_t)force_cipher;

    CHECK_EQ(ac_bind(&ac), AC_OK);
    CHECK(ac_get_key(&ac) && !strcmp(ac_get_key(&ac), MOCK_KEY));
    if (force_cipher) CHECK_EQ(dev.cipher, force_cipher);

#if !FULL_POLL_FITS
    /* Buffers were trimmed below what a 26-property reply needs: the client
     * must say so instead of overrunning. */
    CHECK_EQ(ac_poll(&ac), AC_E_NOBUF);
    return;
#endif
    CHECK_EQ(ac_poll(&ac), AC_OK);
    CHECK_EQ(ac_get(&ac, AC_POW), 1);
    CHECK_EQ(ac_get(&ac, AC_MOD), AC_MODE_HEAT);
    CHECK_EQ(ac_get(&ac, AC_SETTEM), 30);
    CHECK_EQ(ac_get(&ac, AC_TEMSEN), 63);
    CHECK_EQ(ac_room_temp(&ac), 23);          /* 63 - 40 */
    CHECK_EQ(ac_is_on(&ac), 1);

    /* Write path: three properties in one command. */
    ac_power(&ac, 0);
    ac_set_temp(&ac, 21);
    ac_set_mode(&ac, AC_MODE_COOL);
    CHECK(ac.dirty != 0);
    CHECK_EQ(ac_commit(&ac), AC_OK);
    CHECK_EQ(ac.dirty, 0);
    CHECK_EQ(dev.val[AC_POW], 0);
    CHECK_EQ(dev.val[AC_SETTEM], 21);
    CHECK_EQ(dev.val[AC_MOD], AC_MODE_COOL);

    /* A no-op commit must not touch the wire. */
    {
        int before = dev.requests;
        CHECK_EQ(ac_commit(&ac), AC_OK);
        CHECK_EQ(dev.requests, before);
    }

    /* Read back through a fresh poll. */
    CHECK_EQ(ac_poll(&ac), AC_OK);
    CHECK_EQ(ac_get(&ac, AC_POW), 0);
    CHECK_EQ(ac_get(&ac, AC_SETTEM), 21);
}

static void test_subset_poll(void)
{
    static const uint8_t want[] = { AC_POW, AC_SETTEM, AC_TEMSEN };
    struct ac_state ac;

    mock_reset();
    setup(&ac);
    CHECK_EQ(ac_bind(&ac), AC_OK);
    CHECK_EQ(ac_poll_props(&ac, want, 3), AC_OK);

    CHECK_EQ(ac_get(&ac, AC_POW), 1);
    CHECK_EQ(ac_get(&ac, AC_SETTEM), 30);
    CHECK_EQ(ac_get(&ac, AC_TEMSEN), 63);
    CHECK_EQ(ac_get(&ac, AC_LIG), AC_UNKNOWN);    /* not requested */
}

static void test_unbound_and_retry(void)
{
    static const uint8_t want[] = { AC_POW, AC_SETTEM };
    struct ac_state ac;

    mock_reset();
    setup(&ac);
    CHECK_EQ(ac_poll_props(&ac, want, 2), AC_E_NOTBOUND);

    CHECK_EQ(ac_bind(&ac), AC_OK);

    /* First request is swallowed; the retry must recover. */
    dev.drop_next = 1;
    CHECK_EQ(ac_poll_props(&ac, want, 2), AC_OK);
    CHECK_EQ(ac_get(&ac, AC_SETTEM), 30);

    /* No retries left: the same drop now surfaces as a timeout. */
    ac_set_timeout(&ac, 10, 0);
    dev.drop_next = 1;
    CHECK_EQ(ac_poll_props(&ac, want, 2), AC_E_TIMEOUT);
}

/* An oversized reply must fail cleanly and without retrying. */
static void test_oversized_reply(void)
{
    static const uint8_t want[] = { AC_POW, AC_SETTEM };
    struct ac_state ac;
    int before;

    mock_reset();
    setup(&ac);
    ac_set_timeout(&ac, 10, 2);
    CHECK_EQ(ac_bind(&ac), AC_OK);

    dev.bloat = 1;
    before = dev.requests;
    CHECK_EQ(ac_poll_props(&ac, want, 2), AC_E_NOBUF);
    CHECK_EQ(dev.requests, before + 1);

    dev.bloat = 0;
    CHECK_EQ(ac_poll_props(&ac, want, 2), AC_OK);
}

#if GREE_ENABLE_V2
static void test_bad_tag(void)
{
    struct ac_state ac;

    mock_reset();
    setup(&ac);
    ac.cipher = AC_CIPHER_V2;
    ac_set_timeout(&ac, 10, 0);

    dev.corrupt_tag = 1;
    CHECK_EQ(ac_bind(&ac), AC_E_CRYPTO);
    CHECK(ac_get_key(&ac) == 0);

    dev.corrupt_tag = 0;
    ac.cipher = AC_CIPHER_V2;
    CHECK_EQ(ac_bind(&ac), AC_OK);
}
#endif

static void test_wrong_key(void)
{
    static const uint8_t want[] = { AC_POW };
    struct ac_state ac;

    mock_reset();
    setup(&ac);
    ac_set_timeout(&ac, 10, 0);
    CHECK_EQ(ac_set_key(&ac, "0000000000000000", ANY_CIPHER), AC_OK);

    /* Garbage plaintext must be rejected, not parsed. */
    CHECK(ac_poll_props(&ac, want, 1) != AC_OK);
    CHECK_EQ(ac_get(&ac, AC_POW), AC_UNKNOWN);

    CHECK_EQ(ac_set_key(&ac, "short", ANY_CIPHER), AC_E_ARG);
    CHECK_EQ(ac_set_key(&ac, "0000000000000000", AC_CIPHER_AUTO), AC_E_ARG);
    CHECK_EQ(ac_set_device(&ac, "502cc6"), AC_E_ARG);
}

#if GREE_ENABLE_DISCOVERY
static void test_discovery(void)
{
    struct ac_state ac;
    struct ac_device found[4];
    int n;

    mock_reset();
    setup(&ac);
    ac_set_timeout(&ac, 10, 0);

    n = ac_discover(&ac, found, 4);
    CHECK_EQ(n, 1);
    if (n == 1) {
        CHECK(!strcmp(found[0].id, "502cc6aabbcc"));
#if GREE_NAME_LEN > 0
        CHECK(!strcmp(found[0].name, "bedroom"));
#endif
        CHECK_EQ(found[0].addr.b[3], 50);
    }

    ac_select(&ac, &found[0]);
    CHECK(!strcmp(ac.id, "502cc6aabbcc"));
}
#endif /* GREE_ENABLE_DISCOVERY */

static void test_temp_modes(void)
{
    static const uint8_t want[] = { AC_TEMSEN, AC_SETTEM };
    struct ac_state ac;

    /* Firmware that reports plain celsius (< 40) must not be offset. */
    mock_reset();
    dev.val[AC_TEMSEN] = 24;
    setup(&ac);
    CHECK_EQ(ac_bind(&ac), AC_OK);
    CHECK_EQ(ac_poll_props(&ac, want, 2), AC_OK);
    CHECK_EQ(ac_room_temp(&ac), 24);

    /* No sensor at all: fall back to the target temperature. */
    mock_reset();
    dev.val[AC_TEMSEN] = 0;
    dev.val[AC_SETTEM] = 26;
    setup(&ac);
    CHECK_EQ(ac_bind(&ac), AC_OK);
    CHECK_EQ(ac_poll_props(&ac, want, 2), AC_OK);
    CHECK_EQ(ac_room_temp(&ac), 26);
}

int main(void)
{
#if GREE_ENABLE_V1
    test_ecb();
#endif
#if GREE_ENABLE_V2
    test_gcm();
#endif
    test_b64();
    test_json();
    test_props();

    test_session(0);                 /* auto cipher selection */
#if GREE_ENABLE_V1
    test_session(AC_CIPHER_V1);
#endif
#if GREE_ENABLE_V2
    test_session(AC_CIPHER_V2);
#endif

    test_subset_poll();
    test_unbound_and_retry();
    test_oversized_reply();
#if GREE_ENABLE_V2
    test_bad_tag();
#endif
    test_wrong_key();
#if GREE_ENABLE_DISCOVERY
    test_discovery();
#endif
    test_temp_modes();

    printf("struct ac_state = %u bytes\n", (unsigned)sizeof(struct ac_state));
    printf(fails ? "%d FAILURES\n" : "all tests passed\n", fails);
    return fails != 0;
}
