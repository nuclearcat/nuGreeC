/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/*
 * nuGreeC - crypto backend interface.
 *
 * Four functions, no state kept between calls. Selecting GREE_CRYPTO picks
 * one implementation; see gree_config.h. If you port to a platform we do not
 * cover, implementing this header against your own AES is the whole job.
 *
 * Decryption *verifies* rather than returning a computed tag: PSA Crypto and
 * most hardware AEAD blocks never expose the tag they computed, only a
 * pass/fail. Keeping the comparison behind this interface also keeps it
 * constant-time in the backends that care.
 */
#ifndef NUGREEC_GREE_CRYPTO_H
#define NUGREEC_GREE_CRYPTO_H

#include <stdint.h>
#include "gree_config.h"

#if GREE_ENABLE_V1
/* PKCS#7-pad buf in place and encrypt. Returns the padded length, or 0 if
 * the padding would not fit in cap. */
unsigned gree_ecb_encrypt(const uint8_t key[16], uint8_t *buf, unsigned len,
                          unsigned cap);

/* Decrypt in place. len must be a non-zero multiple of 16. Returns 0 or -1.
 * ECB is unauthenticated: a wrong key yields garbage, not an error. */
int gree_ecb_decrypt(const uint8_t key[16], uint8_t *buf, unsigned len);
#endif

#if GREE_ENABLE_V2
/* AES-128-GCM with the protocol's fixed nonce and AAD. Encrypts buf in place
 * and writes the 16 byte tag. */
void gree_gcm_encrypt(const uint8_t key[16], uint8_t *buf, unsigned len,
                      uint8_t tag[16]);

/* Verify tag and decrypt buf in place. Returns 0 on success, -1 if the tag
 * does not match, in which case buf must be treated as untrusted. */
int gree_gcm_decrypt(const uint8_t key[16], uint8_t *buf, unsigned len,
                     const uint8_t tag[16]);
#endif

#endif /* NUGREEC_GREE_CRYPTO_H */
