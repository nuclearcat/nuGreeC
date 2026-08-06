/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/*
 * nuGreeC - AES-128 in ECB (protocol V1) and GCM (protocol V2).
 *
 * Table-light implementation: one 256 byte S-box, plus the inverse S-box only
 * when ECB decryption is compiled in. No T-tables, no key schedule cached in
 * RAM - the schedule is expanded on the stack per packet (176 bytes), which
 * costs a few microseconds and saves the same amount of RAM permanently.
 *
 * Not constant-time. The threat model here is a local UDP link to an air
 * conditioner, not an adversary co-located on the MCU.
 */

#include "gree_crypto.h"

#if GREE_CRYPTO == GREE_CRYPTO_BUILTIN

/* ------------------------------------------------------------- primitives */

static void bcpy(uint8_t *d, const uint8_t *s, unsigned n)
{
    while (n--) *d++ = *s++;
}

static void bzero16(uint8_t *d)
{
    unsigned i;
    for (i = 0; i < 16; i++) d[i] = 0;
}

static void xor16(uint8_t *d, const uint8_t *s)
{
    unsigned i;
    for (i = 0; i < 16; i++) d[i] ^= s[i];
}

/* ---------------------------------------------------------------- AES core */

static const uint8_t SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

#define XTIME(x) ((uint8_t)(((x) << 1) ^ (((x) & 0x80) ? 0x1b : 0)))

/* Round keys for AES-128: 11 * 16 bytes. */
#define RK_LEN 176

static void aes_expand(const uint8_t key[16], uint8_t rk[RK_LEN])
{
    unsigned i;
    uint8_t rcon = 1;

    for (i = 0; i < 16; i++) rk[i] = key[i];

    for (i = 16; i < RK_LEN; i += 4) {
        uint8_t t0 = rk[i - 4], t1 = rk[i - 3], t2 = rk[i - 2], t3 = rk[i - 1];

        if ((i & 15) == 0) {
            uint8_t u = t0;
            t0 = (uint8_t)(SBOX[t1] ^ rcon);
            t1 = SBOX[t2];
            t2 = SBOX[t3];
            t3 = SBOX[u];
            rcon = XTIME(rcon);
        }
        rk[i + 0] = rk[i - 16] ^ t0;
        rk[i + 1] = rk[i - 15] ^ t1;
        rk[i + 2] = rk[i - 14] ^ t2;
        rk[i + 3] = rk[i - 13] ^ t3;
    }
}

static void shift_rows(uint8_t *b)
{
    uint8_t t;
    t = b[1];  b[1] = b[5];   b[5] = b[9];   b[9] = b[13];  b[13] = t;
    t = b[2];  b[2] = b[10];  b[10] = t;
    t = b[6];  b[6] = b[14];  b[14] = t;
    t = b[15]; b[15] = b[11]; b[11] = b[7];  b[7] = b[3];   b[3] = t;
}

static void mix_cols(uint8_t *b)
{
    unsigned i;
    for (i = 0; i < 16; i += 4) {
        uint8_t a0 = b[i], a1 = b[i + 1], a2 = b[i + 2], a3 = b[i + 3];
        uint8_t s = a0 ^ a1 ^ a2 ^ a3;
        b[i + 0] ^= s ^ XTIME(a0 ^ a1);
        b[i + 1] ^= s ^ XTIME(a1 ^ a2);
        b[i + 2] ^= s ^ XTIME(a2 ^ a3);
        b[i + 3] ^= s ^ XTIME(a3 ^ a0);
    }
}

static void aes_encrypt_block(const uint8_t rk[RK_LEN], uint8_t b[16])
{
    unsigned r, i;

    xor16(b, rk);
    for (r = 1; r < 10; r++) {
        for (i = 0; i < 16; i++) b[i] = SBOX[b[i]];
        shift_rows(b);
        mix_cols(b);
        xor16(b, rk + r * 16);
    }
    for (i = 0; i < 16; i++) b[i] = SBOX[b[i]];
    shift_rows(b);
    xor16(b, rk + 160);
}

#if GREE_ENABLE_V1

static const uint8_t RSBOX[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
};

/* Multiply in GF(2^8); only used by InvMixColumns, so keep it small. */
static uint8_t gmul(uint8_t a, uint8_t b)
{
    uint8_t r = 0;
    while (b) {
        if (b & 1) r ^= a;
        a = XTIME(a);
        b >>= 1;
    }
    return r;
}

static void inv_shift_rows(uint8_t *b)
{
    uint8_t t;
    t = b[13]; b[13] = b[9];  b[9] = b[5];   b[5] = b[1];   b[1] = t;
    t = b[2];  b[2] = b[10];  b[10] = t;
    t = b[6];  b[6] = b[14];  b[14] = t;
    t = b[3];  b[3] = b[7];   b[7] = b[11];  b[11] = b[15]; b[15] = t;
}

static void inv_mix_cols(uint8_t *b)
{
    unsigned i;
    for (i = 0; i < 16; i += 4) {
        uint8_t a0 = b[i], a1 = b[i + 1], a2 = b[i + 2], a3 = b[i + 3];
        b[i + 0] = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9);
        b[i + 1] = gmul(a0, 9)  ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13);
        b[i + 2] = gmul(a0, 13) ^ gmul(a1, 9)  ^ gmul(a2, 14) ^ gmul(a3, 11);
        b[i + 3] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9)  ^ gmul(a3, 14);
    }
}

static void aes_decrypt_block(const uint8_t rk[RK_LEN], uint8_t b[16])
{
    unsigned r, i;

    xor16(b, rk + 160);
    for (r = 9; r > 0; r--) {
        inv_shift_rows(b);
        for (i = 0; i < 16; i++) b[i] = RSBOX[b[i]];
        xor16(b, rk + r * 16);
        inv_mix_cols(b);
    }
    inv_shift_rows(b);
    for (i = 0; i < 16; i++) b[i] = RSBOX[b[i]];
    xor16(b, rk);
}

/* ------------------------------------------------------------- ECB (V1) */

unsigned gree_ecb_encrypt(const uint8_t key[16], uint8_t *buf, unsigned len,
                          unsigned cap)
{
    uint8_t rk[RK_LEN];
    unsigned pad = 16 - (len & 15);   /* PKCS#7: always 1..16 bytes */
    unsigned total = len + pad, i;

    if (total > cap) return 0;
    for (i = len; i < total; i++) buf[i] = (uint8_t)pad;

    aes_expand(key, rk);
    for (i = 0; i < total; i += 16) aes_encrypt_block(rk, buf + i);
    return total;
}

int gree_ecb_decrypt(const uint8_t key[16], uint8_t *buf, unsigned len)
{
    uint8_t rk[RK_LEN];
    unsigned i;

    if (len == 0 || (len & 15)) return -1;

    aes_expand(key, rk);
    for (i = 0; i < len; i += 16) aes_decrypt_block(rk, buf + i);
    return 0;
}

#endif /* GREE_ENABLE_V1 */

/* ------------------------------------------------------------- GCM (V2) */

#if GREE_ENABLE_V2

/* Fixed by the protocol: every V2 packet reuses this nonce and AAD. */
static const uint8_t GCM_NONCE[12] = {
    0x54, 0x40, 0x78, 0x44, 0x49, 0x67, 0x5a, 0x51, 0x6c, 0x5e, 0x63, 0x13
};
static const uint8_t GCM_AAD[13] = {
    'q', 'u', 'a', 'l', 'c', 'o', 'm', 'm', '-', 't', 'e', 's', 't'
};

/* y = y * h over GF(2^128) (GHASH convention), bitwise: no tables, 128
 * iterations per block. Slower than a 4-bit table but saves 256 bytes of RAM
 * and our packets are a few hundred bytes. */
static void gf_mul(uint8_t *y, const uint8_t *h)
{
    uint8_t z[16], v[16];
    unsigned i, j, k, lsb;

    bzero16(z);
    bcpy(v, h, 16);

    for (i = 0; i < 16; i++) {
        for (j = 0; j < 8; j++) {
            if (y[i] & (0x80u >> j)) xor16(z, v);

            lsb = v[15] & 1;
            for (k = 15; k > 0; k--)
                v[k] = (uint8_t)((v[k] >> 1) | (v[k - 1] << 7));
            v[0] >>= 1;
            if (lsb) v[0] ^= 0xe1;
        }
    }
    bcpy(y, z, 16);
}

/* GHASH n bytes, zero padded to a block boundary. */
static void ghash(uint8_t *y, const uint8_t *h, const uint8_t *p, unsigned n)
{
    while (n) {
        unsigned c = n < 16 ? n : 16, i;
        for (i = 0; i < c; i++) y[i] ^= p[i];
        gf_mul(y, h);
        p += c;
        n -= c;
    }
}

static void gcm_core(const uint8_t key[16], uint8_t *buf, unsigned len,
                     uint8_t tag[16], int dec)
{
    uint8_t rk[RK_LEN];
    uint8_t h[16], j0[16], ctr[16], ks[16], y[16];
    unsigned i, off;

    aes_expand(key, rk);

    /* H = E(0), J0 = nonce || 0x00000001 (the nonce is always 12 bytes). */
    bzero16(h);
    aes_encrypt_block(rk, h);

    bcpy(j0, GCM_NONCE, 12);
    j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;

    bzero16(y);
    ghash(y, h, GCM_AAD, sizeof GCM_AAD);

    /* The tag covers the ciphertext, so hash before decrypting / after
     * encrypting. */
    if (dec) ghash(y, h, buf, len);

    bcpy(ctr, j0, 16);
    for (off = 0; off < len; off += 16) {
        unsigned c = len - off < 16 ? len - off : 16;

        /* inc32 on the low 32 bits of the counter block */
        for (i = 16; i-- > 12;)
            if (++ctr[i]) break;

        bcpy(ks, ctr, 16);
        aes_encrypt_block(rk, ks);
        for (i = 0; i < c; i++) buf[off + i] ^= ks[i];
    }

    if (!dec) ghash(y, h, buf, len);

    /* Length block: bit lengths of AAD and ciphertext, big endian. */
    {
        uint8_t lb[16];
        for (i = 0; i < 16; i++) lb[i] = 0;
        lb[7]  = (uint8_t)(sizeof GCM_AAD * 8);
        lb[12] = (uint8_t)((uint32_t)len >> 21);
        lb[13] = (uint8_t)((uint32_t)len >> 13);
        lb[14] = (uint8_t)((uint32_t)len >> 5);
        lb[15] = (uint8_t)((uint32_t)len << 3);
        ghash(y, h, lb, 16);
    }

    aes_encrypt_block(rk, j0);          /* j0 becomes E(J0) */
    for (i = 0; i < 16; i++) tag[i] = (uint8_t)(y[i] ^ j0[i]);
}

void gree_gcm_encrypt(const uint8_t key[16], uint8_t *buf, unsigned len,
                      uint8_t tag[16])
{
    gcm_core(key, buf, len, tag, 0);
}

int gree_gcm_decrypt(const uint8_t key[16], uint8_t *buf, unsigned len,
                     const uint8_t tag[16])
{
    uint8_t got[16];
    unsigned i;
    uint8_t diff = 0;

    gcm_core(key, buf, len, got, 1);
    for (i = 0; i < 16; i++) diff |= (uint8_t)(got[i] ^ tag[i]);
    return diff ? -1 : 0;               /* no early exit: comparison is fixed time */
}

#endif /* GREE_ENABLE_V2 */

#endif /* GREE_CRYPTO_BUILTIN */
