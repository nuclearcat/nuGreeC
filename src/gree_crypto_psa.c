/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/*
 * nuGreeC - crypto backend built on PSA Crypto.
 *
 * For mbedTLS 4.x, which is what ESP-IDF 6.x ships. mbedTLS 4 moved
 * mbedtls/aes.h and mbedtls/gcm.h under mbedtls/private/ and made PSA the
 * public API, so this is the supported path there. ESP-IDF routes PSA to the
 * AES accelerator through its own PSA driver.
 *
 * The caller must have run psa_crypto_init() once before any nuGreeC call
 * that touches the network. ESP-IDF apps that already use TLS have normally
 * done this; calling it twice is harmless.
 *
 * Build: -DGREE_CRYPTO=GREE_CRYPTO_PSA
 */

#include "gree_crypto.h"

#if GREE_CRYPTO == GREE_CRYPTO_PSA

#include "psa/crypto.h"

#if GREE_ENABLE_V2
/* Fixed by the protocol: every V2 packet reuses this nonce and AAD. */
static const uint8_t GCM_NONCE[12] = {
    0x54, 0x40, 0x78, 0x44, 0x49, 0x67, 0x5a, 0x51, 0x6c, 0x5e, 0x63, 0x13
};
static const uint8_t GCM_AAD[13] = {
    'q', 'u', 'a', 'l', 'c', 'o', 'm', 'm', '-', 't', 'e', 's', 't'
};
#endif

/* Import the 16 byte packet key as a volatile PSA key. Gree rotates keys per
 * device, not per session, so there is nothing to cache usefully here. */
static psa_status_t key_import(const uint8_t key[16], psa_algorithm_t alg,
                               psa_key_usage_t usage,
                               mbedtls_svc_key_id_t *out)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t st;

    psa_set_key_usage_flags(&attr, usage);
    psa_set_key_algorithm(&attr, alg);
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 128);

    st = psa_import_key(&attr, key, 16, out);
    psa_reset_key_attributes(&attr);
    return st;
}

#if GREE_ENABLE_V1

unsigned gree_ecb_encrypt(const uint8_t key[16], uint8_t *buf, unsigned len,
                          unsigned cap)
{
    mbedtls_svc_key_id_t id;
    psa_status_t st;
    size_t out_len = 0;
    unsigned pad = 16 - (len & 15);
    unsigned total = len + pad, i;

    if (total > cap) return 0;
    for (i = len; i < total; i++) buf[i] = (uint8_t)pad;

    /* We pad ourselves, so ask PSA for raw ECB. It emits no IV for ECB, and
     * in-place is not promised, so go through a stack block per chunk. */
    st = key_import(key, PSA_ALG_ECB_NO_PADDING,
                    PSA_KEY_USAGE_ENCRYPT, &id);
    if (st != PSA_SUCCESS) return 0;

    for (i = 0; i < total; i += 16) {
        uint8_t out[16];
        st = psa_cipher_encrypt(id, PSA_ALG_ECB_NO_PADDING, buf + i, 16,
                                out, sizeof out, &out_len);
        if (st != PSA_SUCCESS || out_len != 16) break;
        {
            unsigned j;
            for (j = 0; j < 16; j++) buf[i + j] = out[j];
        }
    }
    psa_destroy_key(id);
    return (st == PSA_SUCCESS && out_len == 16) ? total : 0;
}

int gree_ecb_decrypt(const uint8_t key[16], uint8_t *buf, unsigned len)
{
    mbedtls_svc_key_id_t id;
    psa_status_t st;
    size_t out_len = 0;
    unsigned i;

    if (len == 0 || (len & 15)) return -1;

    st = key_import(key, PSA_ALG_ECB_NO_PADDING,
                    PSA_KEY_USAGE_DECRYPT, &id);
    if (st != PSA_SUCCESS) return -1;

    for (i = 0; i < len; i += 16) {
        uint8_t out[16];
        st = psa_cipher_decrypt(id, PSA_ALG_ECB_NO_PADDING, buf + i, 16,
                                out, sizeof out, &out_len);
        if (st != PSA_SUCCESS || out_len != 16) break;
        {
            unsigned j;
            for (j = 0; j < 16; j++) buf[i + j] = out[j];
        }
    }
    psa_destroy_key(id);
    return (st == PSA_SUCCESS && out_len == 16) ? 0 : -1;
}

#endif /* GREE_ENABLE_V1 */

#if GREE_ENABLE_V2

/* PSA keeps ciphertext and tag in one buffer, the protocol keeps them in two
 * separate JSON fields, so both directions stage through GREE_INNER_BUF + 16
 * bytes of stack. That is the price of not exposing a raw GHASH. */
void gree_gcm_encrypt(const uint8_t key[16], uint8_t *buf, unsigned len,
                      uint8_t tag[16])
{
    mbedtls_svc_key_id_t id;
    psa_status_t st;
    uint8_t out[GREE_INNER_BUF + 16];
    size_t out_len = 0;
    unsigned i;

    if (len + 16 > sizeof out) return;

    st = key_import(key, PSA_ALG_GCM, PSA_KEY_USAGE_ENCRYPT, &id);
    if (st != PSA_SUCCESS) return;

    st = psa_aead_encrypt(id, PSA_ALG_GCM,
                          GCM_NONCE, sizeof GCM_NONCE,
                          GCM_AAD, sizeof GCM_AAD,
                          buf, len,
                          out, sizeof out, &out_len);
    psa_destroy_key(id);

    if (st != PSA_SUCCESS || out_len != (size_t)len + 16) return;

    for (i = 0; i < len; i++) buf[i] = out[i];
    for (i = 0; i < 16; i++) tag[i] = out[len + i];
}

int gree_gcm_decrypt(const uint8_t key[16], uint8_t *buf, unsigned len,
                     const uint8_t tag[16])
{
    mbedtls_svc_key_id_t id;
    psa_status_t st;
    uint8_t in[GREE_INNER_BUF + 16];
    uint8_t out[GREE_INNER_BUF];
    size_t out_len = 0;
    unsigned i;

    if (len + 16 > sizeof in || len > sizeof out) return -1;

    for (i = 0; i < len; i++) in[i] = buf[i];
    for (i = 0; i < 16; i++) in[len + i] = tag[i];

    st = key_import(key, PSA_ALG_GCM, PSA_KEY_USAGE_DECRYPT, &id);
    if (st != PSA_SUCCESS) return -1;

    /* PSA verifies the tag internally and refuses to emit plaintext on a
     * mismatch, which is exactly the contract this interface wants. */
    st = psa_aead_decrypt(id, PSA_ALG_GCM,
                          GCM_NONCE, sizeof GCM_NONCE,
                          GCM_AAD, sizeof GCM_AAD,
                          in, (size_t)len + 16,
                          out, sizeof out, &out_len);
    psa_destroy_key(id);

    if (st != PSA_SUCCESS || out_len != len) return -1;
    for (i = 0; i < len; i++) buf[i] = out[i];
    return 0;
}

#endif /* GREE_ENABLE_V2 */

#endif /* GREE_CRYPTO_PSA */

/* Keep this a valid translation unit when the backend is not selected. */
typedef int gree_crypto_backend_placeholder;
