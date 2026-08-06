/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/*
 * nuGreeC - crypto backend built on the classic mbedTLS API.
 *
 * For mbedTLS 2.x and 3.x, which is what ESP-IDF 5.x and earlier ship. On
 * ESP-IDF these calls are redirected to the AES accelerator when
 * CONFIG_MBEDTLS_HARDWARE_AES is set (the default), and the port takes care
 * of locking the shared peripheral.
 *
 * mbedTLS 4.x moved these headers to mbedtls/private/ and made PSA the public
 * API - use GREE_CRYPTO_PSA there instead.
 *
 * Build: -DGREE_CRYPTO=GREE_CRYPTO_MBEDTLS
 */

#include "gree_crypto.h"

#if GREE_CRYPTO == GREE_CRYPTO_MBEDTLS

#if GREE_ENABLE_V1
#include "mbedtls/aes.h"
#endif
#if GREE_ENABLE_V2
#include "mbedtls/gcm.h"
#endif

/* Fixed by the protocol: every V2 packet reuses this nonce and AAD. */
#if GREE_ENABLE_V2
static const unsigned char GCM_NONCE[12] = {
    0x54, 0x40, 0x78, 0x44, 0x49, 0x67, 0x5a, 0x51, 0x6c, 0x5e, 0x63, 0x13
};
static const unsigned char GCM_AAD[13] = {
    'q', 'u', 'a', 'l', 'c', 'o', 'm', 'm', '-', 't', 'e', 's', 't'
};
#endif

#if GREE_ENABLE_V1

unsigned gree_ecb_encrypt(const uint8_t key[16], uint8_t *buf, unsigned len,
                          unsigned cap)
{
    mbedtls_aes_context c;
    unsigned pad = 16 - (len & 15);
    unsigned total = len + pad, i;
    int rc;

    if (total > cap) return 0;
    for (i = len; i < total; i++) buf[i] = (uint8_t)pad;

    mbedtls_aes_init(&c);
    rc = mbedtls_aes_setkey_enc(&c, key, 128);
    for (i = 0; rc == 0 && i < total; i += 16) {
        unsigned char out[16];
        rc = mbedtls_aes_crypt_ecb(&c, MBEDTLS_AES_ENCRYPT, buf + i, out);
        if (rc == 0) {
            unsigned j;
            for (j = 0; j < 16; j++) buf[i + j] = out[j];
        }
    }
    mbedtls_aes_free(&c);
    return rc == 0 ? total : 0;
}

int gree_ecb_decrypt(const uint8_t key[16], uint8_t *buf, unsigned len)
{
    mbedtls_aes_context c;
    unsigned i;
    int rc;

    if (len == 0 || (len & 15)) return -1;

    mbedtls_aes_init(&c);
    rc = mbedtls_aes_setkey_dec(&c, key, 128);
    for (i = 0; rc == 0 && i < len; i += 16) {
        unsigned char out[16];
        rc = mbedtls_aes_crypt_ecb(&c, MBEDTLS_AES_DECRYPT, buf + i, out);
        if (rc == 0) {
            unsigned j;
            for (j = 0; j < 16; j++) buf[i + j] = out[j];
        }
    }
    mbedtls_aes_free(&c);
    return rc == 0 ? 0 : -1;
}

#endif /* GREE_ENABLE_V1 */

#if GREE_ENABLE_V2

void gree_gcm_encrypt(const uint8_t key[16], uint8_t *buf, unsigned len,
                      uint8_t tag[16])
{
    mbedtls_gcm_context c;

    mbedtls_gcm_init(&c);
    if (mbedtls_gcm_setkey(&c, MBEDTLS_CIPHER_ID_AES, key, 128) == 0)
        mbedtls_gcm_crypt_and_tag(&c, MBEDTLS_GCM_ENCRYPT, len,
                                  GCM_NONCE, sizeof GCM_NONCE,
                                  GCM_AAD, sizeof GCM_AAD,
                                  buf, buf, 16, tag);
    mbedtls_gcm_free(&c);
}

int gree_gcm_decrypt(const uint8_t key[16], uint8_t *buf, unsigned len,
                     const uint8_t tag[16])
{
    mbedtls_gcm_context c;
    int rc;

    mbedtls_gcm_init(&c);
    rc = mbedtls_gcm_setkey(&c, MBEDTLS_CIPHER_ID_AES, key, 128);
    if (rc == 0)
        rc = mbedtls_gcm_auth_decrypt(&c, len,
                                      GCM_NONCE, sizeof GCM_NONCE,
                                      GCM_AAD, sizeof GCM_AAD,
                                      tag, 16, buf, buf);
    mbedtls_gcm_free(&c);
    return rc == 0 ? 0 : -1;
}

#endif /* GREE_ENABLE_V2 */

#endif /* GREE_CRYPTO_MBEDTLS */

/* Keep this a valid translation unit when the backend is not selected. */
typedef int gree_crypto_backend_placeholder;
