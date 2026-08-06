/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/*
 * nuGreeC - Gree local UDP protocol.
 *
 * The wire format is JSON, so this file contains a JSON writer and a reader.
 * Both are deliberately minimal: the writer streams straight into the packet
 * buffer, and the reader is a key scanner that never builds a tree. Nothing
 * allocates, and no libc is used beyond <stdint.h>.
 *
 * Buffer discipline: ac->in holds the inner packet (plaintext, then
 * ciphertext), ac->buf holds the datagram that goes on the wire and the one
 * that comes back. The two never alias, which is what keeps this readable at
 * the cost of ~400 bytes of RAM.
 */

#include "gree.h"
#include "gree_crypto.h"

/* Keys shipped in every Gree module; used until the device hands out its own. */
#if GREE_ENABLE_V1
static const char KEY_V1[17] = "a3K8Bx%2r8Y7#xDh";
#endif
#if GREE_ENABLE_V2
static const char KEY_V2[17] = "{yxAHAY_Lm6pbC/<";
#endif

/* Room sensor readings above this are offset by 40; see ac_room_temp(). */
#define TEMP_OFFSET 40

/* ------------------------------------------------------- property names */

/* Packed, in enum ac_prop order. Walked rather than indexed: 26 pointers of
 * index table would cost more flash than the walk costs cycles. */
static const char P_NAMES[] =
    "Pow\0"     "Mod\0"        "SetTem\0"  "TemUn\0"   "TemRec\0" "TemSen\0"
    "WdSpd\0"   "Air\0"        "Blo\0"     "Health\0"  "SwhSlp\0" "SlpMod\0"
    "Lig\0"     "SwingLfRig\0" "SwUpDn\0"  "Quiet\0"   "Tur\0"    "StHt\0"
    "SvSt\0"    "Dwet\0"       "DwatSen\0" "Dfltr\0"   "DwatFul\0" "Dmod\0"
    "HeatCoolType\0" "Buzzer_ON_OFF\0";

static const char *p_name(unsigned i)
{
    const char *s = P_NAMES;
    while (i--) { while (*s) s++; s++; }
    return s;
}

static int p_index(const char *s, unsigned len)
{
    const char *n = P_NAMES;
    unsigned i;

    for (i = 0; i < AC_PROP_COUNT; i++) {
        unsigned k = 0;
        while (n[k]) k++;
        if (k == len) {
            unsigned j = 0;
            while (j < len && n[j] == s[j]) j++;
            if (j == len) return (int)i;
        }
        n += k + 1;
    }
    return -1;
}

/* ------------------------------------------------------------ JSON write */

struct jw {
    uint8_t *p;
    unsigned left;
    uint8_t ovf;
};

static void w_ch(struct jw *w, char c)
{
    if (w->left) { *w->p++ = (uint8_t)c; w->left--; }
    else w->ovf = 1;
}

static void w_str(struct jw *w, const char *s)
{
    while (*s) w_ch(w, *s++);
}

static void w_int(struct jw *w, int v)
{
    char t[8];
    unsigned n = 0;
    unsigned u;

    if (v < 0) { w_ch(w, '-'); u = (unsigned)(-(long)v); }
    else u = (unsigned)v;

    do { t[n++] = (char)('0' + u % 10); u /= 10; } while (u);
    while (n) w_ch(w, t[--n]);
}

static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void w_b64(struct jw *w, const uint8_t *p, unsigned n)
{
    unsigned i = 0;

    while (i + 3 <= n) {
        uint32_t v = ((uint32_t)p[i] << 16) | ((uint32_t)p[i + 1] << 8) | p[i + 2];
        w_ch(w, B64[v >> 18]);
        w_ch(w, B64[(v >> 12) & 63]);
        w_ch(w, B64[(v >> 6) & 63]);
        w_ch(w, B64[v & 63]);
        i += 3;
    }
    if (i < n) {
        uint32_t v = (uint32_t)p[i] << 16;
        int two = (i + 1 < n);
        if (two) v |= (uint32_t)p[i + 1] << 8;
        w_ch(w, B64[v >> 18]);
        w_ch(w, B64[(v >> 12) & 63]);
        w_ch(w, two ? B64[(v >> 6) & 63] : '=');
        w_ch(w, '=');
    }
}

/* ------------------------------------------------------------- JSON read */

static int is_ws(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

/* p points at the opening quote; returns the character after the closing one. */
static const char *skip_str(const char *p)
{
    for (p++; *p; p++) {
        if (*p == '\\' && p[1]) p++;
        else if (*p == '"') return p + 1;
    }
    return p;
}

/* Find the value of `key` in the NUL-terminated JSON text `s`.
 * Only object keys are matched: string *values* are skipped wholesale, so a
 * value that happens to contain the key text cannot produce a false hit. */
static const char *j_find(const char *s, const char *key)
{
    while (*s) {
        if (*s == '"') {
            const char *first = s + 1;
            const char *end = skip_str(s);        /* just past closing quote */
            const char *q = end;

            while (is_ws(*q)) q++;
            if (*q == ':') {
                const char *a = first;
                const char *b = key;
                while (*b && a < end - 1 && *a == *b) { a++; b++; }
                if (!*b && a == end - 1) {
                    q++;
                    while (is_ws(*q)) q++;
                    return q;
                }
            }
            s = end;
        } else {
            s++;
        }
    }
    return 0;
}

/* True when the value at p is exactly the string literal `lit`. */
static int j_is(const char *p, const char *lit)
{
    if (!p || *p != '"') return 0;
    p++;
    while (*lit && *p == *lit) { p++; lit++; }
    return !*lit && *p == '"';
}

static long j_int(const char *p)
{
    long v = 0;
    int neg = 0;

    if (!p) return 0;
    if (*p == '-') { neg = 1; p++; }
    while (*p >= '0' && *p <= '9') v = v * 10 + (*p++ - '0');
    return neg ? -v : v;
}

/* Decode base64 running from `s` up to the closing quote. */
static int b64_decode(const char *s, uint8_t *dst, unsigned cap)
{
    uint32_t acc = 0;
    unsigned bits = 0, out = 0;

    for (; *s && *s != '"'; s++) {
        int v;
        char c = *s;

        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
        else if (c >= '0' && c <= '9') v = c - '0' + 52;
        else if (c == '+') v = 62;
        else if (c == '/') v = 63;
        else continue;                     /* padding and whitespace */

        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (out >= cap) return -1;
            dst[out++] = (uint8_t)(acc >> bits);
        }
    }
    return (int)out;
}

/* ----------------------------------------------------------- small utils */

static void scpy(char *d, const char *s, unsigned cap)
{
    unsigned i = 0;
    while (s[i] && i + 1 < cap) { d[i] = s[i]; i++; }
    d[i] = 0;
}

static unsigned slen(const char *s)
{
    unsigned n = 0;
    while (s[n]) n++;
    return n;
}

/* --------------------------------------------------------- request build */

enum { REQ_BIND = 0, REQ_STATUS, REQ_CMD };

struct req {
    uint8_t kind;
    const uint8_t *props;    /* NULL means "every known property" */
    unsigned n;
};

static int build_inner(struct ac_state *ac, const struct req *r)
{
    struct jw w;
    unsigned i;

    w.p = ac->in;
    w.left = sizeof ac->in;
    w.ovf = 0;

    w_str(&w, "{\"t\":\"");
    w_str(&w, r->kind == REQ_BIND ? "bind" : r->kind == REQ_STATUS ? "status" : "cmd");
    w_str(&w, "\",\"mac\":\"");
    w_str(&w, ac->id);
    w_ch(&w, '"');

    if (r->kind == REQ_BIND) {
        w_str(&w, ",\"uid\":0");
    } else if (r->kind == REQ_STATUS) {
        unsigned n = r->props ? r->n : AC_PROP_COUNT;

        w_str(&w, ",\"cols\":[");
        for (i = 0; i < n; i++) {
            if (i) w_ch(&w, ',');
            w_ch(&w, '"');
            w_str(&w, p_name(r->props ? r->props[i] : i));
            w_ch(&w, '"');
        }
        w_ch(&w, ']');
    } else {
        int first = 1;

        w_str(&w, ",\"opt\":[");
        for (i = 0; i < AC_PROP_COUNT; i++) {
            if (!(ac->dirty & (1u << i))) continue;
            if (!first) w_ch(&w, ',');
            first = 0;
            w_ch(&w, '"');
            w_str(&w, p_name(i));
            w_ch(&w, '"');
        }
        w_str(&w, "],\"p\":[");
        first = 1;
        for (i = 0; i < AC_PROP_COUNT; i++) {
            if (!(ac->dirty & (1u << i))) continue;
            if (!first) w_ch(&w, ',');
            first = 0;
            w_int(&w, ac->val[i]);
        }
        w_ch(&w, ']');
    }

    w_ch(&w, '}');
    if (w.ovf) return AC_E_NOBUF;
    return (int)(sizeof ac->in - w.left);
}

/* Encrypt ac->in (ilen bytes) and wrap it into the datagram in ac->buf.
 * Returns the datagram length. */
static int tx_pack(struct ac_state *ac, unsigned ilen, int i_flag,
                   const char *key, int cipher)
{
    struct jw w;
    unsigned clen;
#if GREE_ENABLE_V2
    uint8_t tag[16];
#endif

    if (cipher == AC_CIPHER_V2) {
#if GREE_ENABLE_V2
        gree_gcm_encrypt((const uint8_t *)key, ac->in, ilen, tag);
        clen = ilen;
#else
        return AC_E_ARG;
#endif
    } else {
#if GREE_ENABLE_V1
        clen = gree_ecb_encrypt((const uint8_t *)key, ac->in, ilen, sizeof ac->in);
        if (!clen) return AC_E_NOBUF;
#else
        return AC_E_ARG;
#endif
    }

    w.p = ac->buf;
    w.left = sizeof ac->buf;
    w.ovf = 0;

    w_str(&w, "{\"cid\":\"app\",\"i\":");
    w_ch(&w, i_flag ? '1' : '0');
    w_str(&w, ",\"t\":\"pack\",\"uid\":0,\"tcid\":\"");
    w_str(&w, ac->id);
    w_str(&w, "\",\"pack\":\"");
    w_b64(&w, ac->in, clen);
    w_ch(&w, '"');
#if GREE_ENABLE_V2
    if (cipher == AC_CIPHER_V2) {
        w_str(&w, ",\"tag\":\"");
        w_b64(&w, tag, 16);
        w_ch(&w, '"');
    }
#endif
    w_ch(&w, '}');

    if (w.ovf) return AC_E_NOBUF;
    return (int)(sizeof ac->buf - w.left);
}

/* Turn the datagram in ac->buf into NUL-terminated inner JSON in ac->in. */
static int rx_unpack(struct ac_state *ac, unsigned rxlen,
                     const char *key, int cipher)
{
    const char *p;
    int n, i;

    if (rxlen >= sizeof ac->buf) return AC_E_NOBUF;
    ac->buf[rxlen] = 0;

    p = j_find((const char *)ac->buf, "pack");
    if (!p || *p != '"') return AC_E_PROTO;

    n = b64_decode(p + 1, ac->in, sizeof ac->in - 1);
    if (n < 0) return AC_E_NOBUF;      /* reply larger than GREE_INNER_BUF */
    if (n == 0) return AC_E_PROTO;

    if (cipher == AC_CIPHER_V2) {
#if GREE_ENABLE_V2
        const char *t = j_find((const char *)ac->buf, "tag");
        uint8_t tag[17];

        if (!t || *t != '"') return AC_E_CRYPTO;
        if (b64_decode(t + 1, tag, sizeof tag) != 16) return AC_E_CRYPTO;

        /* Authenticate before trusting a byte of it. */
        if (gree_gcm_decrypt((const uint8_t *)key, ac->in, (unsigned)n, tag))
            return AC_E_CRYPTO;
#else
        return AC_E_ARG;
#endif
    } else {
#if GREE_ENABLE_V1
        if (gree_ecb_decrypt((const uint8_t *)key, ac->in, (unsigned)n) < 0)
            return AC_E_PROTO;
#else
        return AC_E_ARG;
#endif
    }

    /* Trailing padding (V1) or trailing junk: keep everything up to the last
     * closing brace. A wrong key almost always fails right here. */
    for (i = n - 1; i >= 0; i--)
        if (ac->in[i] == '}') break;
    if (i < 0 || ac->in[0] != '{') return AC_E_CRYPTO;
    ac->in[i + 1] = 0;

    return AC_OK;
}

/* Send a request and wait for one decodable reply. */
static int xact(struct ac_state *ac, const struct req *r, int i_flag,
                const char *key, int cipher)
{
    unsigned att;
    int rc = AC_E_TIMEOUT;
    int err = 0;                 /* most specific reason a reply was rejected */

    if (!ac->tr || !ac->tr->send || !ac->tr->recv) return AC_E_ARG;
    if (!ac->has_peer || !ac->id[0]) return AC_E_ARG;

    for (att = 0; att <= ac->retries; att++) {
        int ilen = build_inner(ac, r);
        int olen;
        unsigned ignored;

        if (ilen < 0) return ilen;
        olen = tx_pack(ac, (unsigned)ilen, i_flag, key, cipher);
        if (olen < 0) return olen;

        if (ac->tr->send(ac->ctx, ac->buf, (unsigned)olen, &ac->peer) < 0)
            return AC_E_NET;

        /* Tolerate a few foreign datagrams (other devices answering a
         * broadcast, late replies) before giving up on this attempt. */
        for (ignored = 0; ignored < 4; ignored++) {
            int n = ac->tr->recv(ac->ctx, ac->buf, sizeof ac->buf - 1,
                                 ac->timeout_ms, 0);
            if (n < 0) return AC_E_NET;
            if (n == 0) { rc = AC_E_TIMEOUT; break; }

            rc = rx_unpack(ac, (unsigned)n, key, cipher);
            if (rc == AC_OK) return AC_OK;
            if (rc == AC_E_NOBUF) return rc;   /* a retry cannot shrink it */
            err = rc;
        }
    }
    /* A wrong key looks like silence otherwise, which is the single most
     * confusing failure to debug in the field. */
    return err ? err : rc;
}

/* ------------------------------------------------------- reply -> state */

/* Advance *pp past one array element. Returns 1 and sets *out for a number,
 * 0 for any other element type, -1 at the end of the array. */
static int next_val(const char **pp, long *out)
{
    const char *p = *pp;

    while (is_ws(*p) || *p == ',') p++;
    if (*p == ']' || !*p) { *pp = p; return -1; }

    if (*p == '-' || (*p >= '0' && *p <= '9')) {
        *out = j_int(p);
        if (*p == '-') p++;
        while (*p >= '0' && *p <= '9') p++;
        *pp = p;
        return 1;
    }
    if (*p == '"') { *pp = skip_str(p); return 0; }

    while (*p && *p != ',' && *p != ']') p++;    /* true/false/null/object */
    *pp = p;
    return 0;
}

/* Zip a ["Pow","Mod"] name array against a [1,4] value array. */
static int apply_pairs(struct ac_state *ac, const char *names, const char *vals)
{
    if (!names || !vals || *names != '[' || *vals != '[') return AC_E_PROTO;
    names++;
    vals++;

    for (;;) {
        const char *ns, *ne;
        long v = 0;
        int idx, kind;

        while (is_ws(*names) || *names == ',') names++;
        if (*names != '"') break;

        ns = names + 1;
        ne = ns;
        while (*ne && *ne != '"') ne++;
        if (!*ne) break;
        names = ne + 1;

        kind = next_val(&vals, &v);
        if (kind < 0) break;
        if (kind == 0) continue;                 /* non-numeric: ignore */

        idx = p_index(ns, (unsigned)(ne - ns));
        if (idx < 0) continue;                   /* property we do not model */

        ac->val[idx] = (int16_t)v;
        ac->known |= 1u << idx;

        if (idx == AC_TEMSEN && v != 0 && ac->temp_mode == 0)
            ac->temp_mode = (v >= TEMP_OFFSET) ? 1 : 2;
    }
    return AC_OK;
}

/* Common tail for status and cmd replies. */
static int take_reply(struct ac_state *ac, const char *type)
{
    const char *in = (const char *)ac->in;
    const char *p;

    p = j_find(in, "r");
    ac->last_r = p ? (uint8_t)j_int(p) : 200;

    if (!j_is(j_find(in, "t"), type)) return AC_E_PROTO;
    if (ac->last_r != 200) return AC_E_DEVICE;

    if (type[0] == 'd')                          /* "dat" */
        return apply_pairs(ac, j_find(in, "cols"), j_find(in, "dat"));

    p = j_find(in, "val");                       /* "res": val or p */
    if (!p) p = j_find(in, "p");
    return apply_pairs(ac, j_find(in, "opt"), p);
}

/* ------------------------------------------------------------------ API */

void ac_init(struct ac_state *ac)
{
    unsigned i;
    uint8_t *b = (uint8_t *)ac;

    for (i = 0; i < sizeof *ac; i++) b[i] = 0;

    ac->cipher = AC_CIPHER_AUTO;
    ac->timeout_ms = GREE_TIMEOUT_MS;
    ac->retries = GREE_RETRIES;
    ac->last_r = 200;
}

void ac_set_transport(struct ac_state *ac, const struct ac_transport *tr, void *ctx)
{
    ac->tr = tr;
    ac->ctx = ctx;
}

int ac_set_device(struct ac_state *ac, const char *id)
{
    if (!id || slen(id) != 12) return AC_E_ARG;
    scpy(ac->id, id, sizeof ac->id);
    return AC_OK;
}

void ac_set_peer(struct ac_state *ac, const struct ac_addr *peer)
{
    unsigned i;
    for (i = 0; i < GREE_ADDR_SZ; i++) ac->peer.b[i] = peer->b[i];
    ac->has_peer = 1;
}

void ac_select(struct ac_state *ac, const struct ac_device *dev)
{
    ac_set_peer(ac, &dev->addr);
    scpy(ac->id, dev->id, sizeof ac->id);
}

int ac_set_key(struct ac_state *ac, const char *key, enum ac_cipher cipher)
{
    if (!key || slen(key) != 16) return AC_E_ARG;
    if (cipher != AC_CIPHER_V1 && cipher != AC_CIPHER_V2) return AC_E_ARG;
    scpy(ac->key, key, sizeof ac->key);
    ac->cipher = (uint8_t)cipher;
    ac->bound = 1;
    return AC_OK;
}

const char *ac_get_key(const struct ac_state *ac)
{
    return ac->bound ? ac->key : 0;
}

void ac_set_timeout(struct ac_state *ac, unsigned ms, unsigned retries)
{
    ac->timeout_ms = (uint16_t)ms;
    ac->retries = (uint8_t)retries;
}

#if GREE_ENABLE_DISCOVERY
/* Decode a scan reply, which is encrypted with a generic key. */
static int scan_parse(struct ac_state *ac, unsigned n, struct ac_device *dev)
{
    const char *in, *p;
    int rc = AC_E_CRYPTO;

#if GREE_ENABLE_V1
    rc = rx_unpack(ac, n, KEY_V1, AC_CIPHER_V1);
#endif
#if GREE_ENABLE_V2
    if (rc != AC_OK) rc = rx_unpack(ac, n, KEY_V2, AC_CIPHER_V2);
#endif
    if (rc != AC_OK) return rc;

    in = (const char *)ac->in;
    p = j_find(in, "mac");
    if (!p) p = j_find(in, "cid");
    if (!p || *p != '"') return AC_E_PROTO;

    {
        unsigned k = 0;
        p++;
        while (p[k] && p[k] != '"' && k + 1 < sizeof dev->id) {
            dev->id[k] = p[k];
            k++;
        }
        dev->id[k] = 0;
        if (!k) return AC_E_PROTO;
    }

#if GREE_NAME_LEN > 0
    dev->name[0] = 0;
    p = j_find(in, "name");
    if (p && *p == '"') {
        unsigned k = 0;
        p++;
        while (p[k] && p[k] != '"' && k + 1 < sizeof dev->name) {
            dev->name[k] = p[k];
            k++;
        }
        dev->name[k] = 0;
    }
#endif
    return AC_OK;
}

int ac_discover(struct ac_state *ac, struct ac_device *out, unsigned max)
{
    static const char SCAN[] = "{\"t\":\"scan\"}";
    unsigned found = 0, i, att;

    if (!ac->tr || !ac->tr->send || !ac->tr->recv || !out || !max)
        return AC_E_ARG;

    /* Modules answer a broadcast scan unreliably - some rate-limit it, and a
     * single lost datagram is indistinguishable from "nothing out there" - so
     * repeat the scan and let the dedupe below absorb the duplicates. */
    for (att = 0; att <= ac->retries && found < max; att++) {
        for (i = 0; i + 1 < sizeof SCAN; i++) ac->buf[i] = (uint8_t)SCAN[i];
        if (ac->tr->send(ac->ctx, ac->buf, sizeof SCAN - 1, 0) < 0)
            return found ? (int)found : AC_E_NET;

        while (found < max) {
            struct ac_addr from;
            struct ac_device *dev = &out[found];
            int n = ac->tr->recv(ac->ctx, ac->buf, sizeof ac->buf - 1,
                                 ac->timeout_ms, &from);
            if (n < 0) return found ? (int)found : AC_E_NET;
            if (n == 0) break;                   /* quiet: try again */

            if (scan_parse(ac, (unsigned)n, dev) != AC_OK) continue;

            for (i = 0; i < found; i++) {
                unsigned k = 0;
                while (out[i].id[k] && out[i].id[k] == dev->id[k]) k++;
                if (!out[i].id[k] && !dev->id[k]) break;
            }
            if (i < found) continue;             /* already seen */

            dev->addr = from;
            found++;
        }
    }
    return (int)found;
}
#endif /* GREE_ENABLE_DISCOVERY */

static int bind_with(struct ac_state *ac, const char *gkey, int cipher)
{
    static const struct req r = { REQ_BIND, 0, 0 };
    const char *p;
    int rc = xact(ac, &r, 1, gkey, cipher);

    if (rc != AC_OK) return rc;
    if (!j_is(j_find((const char *)ac->in, "t"), "bindok")) return AC_E_PROTO;

    p = j_find((const char *)ac->in, "key");
    if (!p || *p != '"') return AC_E_PROTO;

    {
        unsigned k;
        p++;
        for (k = 0; k < 16; k++) {
            if (!p[k] || p[k] == '"') return AC_E_PROTO;   /* key too short */
            ac->key[k] = p[k];
        }
        ac->key[16] = 0;
        if (p[16] != '"') return AC_E_PROTO;               /* key too long */
    }

    ac->cipher = (uint8_t)cipher;
    ac->bound = 1;
    return AC_OK;
}

int ac_bind(struct ac_state *ac)
{
    int rc = AC_E_ARG;

    ac->bound = 0;

#if GREE_ENABLE_V1
    if (ac->cipher == AC_CIPHER_AUTO || ac->cipher == AC_CIPHER_V1)
        rc = bind_with(ac, KEY_V1, AC_CIPHER_V1);
#endif
#if GREE_ENABLE_V2
    if (rc != AC_OK && (ac->cipher == AC_CIPHER_AUTO || ac->cipher == AC_CIPHER_V2))
        rc = bind_with(ac, KEY_V2, AC_CIPHER_V2);
#endif
    if (rc != AC_OK) ac->cipher = AC_CIPHER_AUTO;
    return rc;
}

int ac_poll_props(struct ac_state *ac, const uint8_t *props, unsigned n)
{
    struct req r;
    int rc;

    if (!ac->bound) return AC_E_NOTBOUND;
    if (props && !n) return AC_E_ARG;

    r.kind = REQ_STATUS;
    r.props = props;
    r.n = n;

    rc = xact(ac, &r, 0, ac->key, ac->cipher);
    if (rc != AC_OK) return rc;
    return take_reply(ac, "dat");
}

int ac_poll(struct ac_state *ac)
{
    return ac_poll_props(ac, 0, 0);
}

int ac_commit(struct ac_state *ac)
{
    static const struct req r = { REQ_CMD, 0, 0 };
    int rc;

    if (!ac->dirty) return AC_OK;
    if (!ac->bound) return AC_E_NOTBOUND;

    rc = xact(ac, &r, 0, ac->key, ac->cipher);
    if (rc != AC_OK) return rc;

    rc = take_reply(ac, "res");
    if (rc == AC_OK) ac->dirty = 0;
    return rc;
}

int ac_get(const struct ac_state *ac, enum ac_prop p)
{
    if ((unsigned)p >= AC_PROP_COUNT) return AC_UNKNOWN;
    if (!(ac->known & (1u << p))) return AC_UNKNOWN;
    return ac->val[p];
}

void ac_set(struct ac_state *ac, enum ac_prop p, int value)
{
    if ((unsigned)p >= AC_PROP_COUNT) return;
    ac->val[p] = (int16_t)value;
    ac->known |= 1u << p;
    ac->dirty |= 1u << p;
}

int ac_room_temp(const struct ac_state *ac)
{
    int v = ac_get(ac, AC_TEMSEN);

    if (v == AC_UNKNOWN || v == 0)
        return ac_get(ac, AC_SETTEM);            /* no sensor on this model */
    return ac->temp_mode == 1 ? v - TEMP_OFFSET : v;
}

const char *ac_strerror(int err)
{
    switch (err) {
    case AC_OK:         return "ok";
    case AC_E_ARG:      return "bad argument";
    case AC_E_NET:      return "transport error";
    case AC_E_TIMEOUT:  return "timeout";
    case AC_E_CRYPTO:   return "decrypt failed";
    case AC_E_PROTO:    return "bad reply";
    case AC_E_NOBUF:    return "buffer too small";
    case AC_E_NOTBOUND: return "not bound";
    case AC_E_DEVICE:   return "device error";
    default:            return "?";
    }
}
