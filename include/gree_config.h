/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/*
 * nuGreeC - compile-time configuration.
 *
 * Every knob below can be overridden from the build system
 * (-DGREE_PKT_BUF=512 ...) or by defining it before including gree.h.
 * Nothing here allocates; sizes only affect struct ac_state.
 */
#ifndef NUGREEC_GREE_CONFIG_H
#define NUGREEC_GREE_CONFIG_H

/* --- buffers (all live inside struct ac_state, no malloc anywhere) ------- */

/* Outer UDP datagram buffer: JSON envelope with the base64 payload.
 * Must hold ~4/3 * GREE_INNER_BUF plus ~110 bytes of envelope. */
#ifndef GREE_PKT_BUF
#define GREE_PKT_BUF 768
#endif

/* Scratch for the inner (plaintext / ciphertext) packet.
 * A 26-column status reply needs ~390 bytes. Shrink it together with
 * ac_poll_props() if you only ever read a handful of properties. */
#ifndef GREE_INNER_BUF
#define GREE_INNER_BUF 448
#endif

/* Opaque transport address token (e.g. sockaddr_in fits in 8 bytes worth of
 * ip+port). Enlarge for IPv6 or for a bigger handle. */
#ifndef GREE_ADDR_SZ
#define GREE_ADDR_SZ 8
#endif

/* Longest device name kept from a scan reply, including NUL. 0 disables. */
#ifndef GREE_NAME_LEN
#define GREE_NAME_LEN 20
#endif

/* --- protocol features -------------------------------------------------- */

/* AES-128-ECB packets ("CipherV1"): older modules and most units in the
 * field. Costs the AES inverse cipher (~600 bytes of flash). */
#ifndef GREE_ENABLE_V1
#define GREE_ENABLE_V1 1
#endif

/* AES-128-GCM packets ("CipherV2"): protocol V3.4+ modules, replies carry
 * a "tag" field. Encrypt-only AES, no inverse cipher needed. */
#ifndef GREE_ENABLE_V2
#define GREE_ENABLE_V2 1
#endif

/* --- crypto backend ------------------------------------------------------
 *
 * The built-in AES is portable and self-contained. If your platform already
 * links an AES implementation - which any ESP-IDF app with WiFi or TLS does -
 * pointing nuGreeC at it removes ~2.2 KB of duplicate code and usually gets
 * you the hardware accelerator for free.
 *
 *   GREE_CRYPTO_BUILTIN   own AES-128; no dependencies      (default)
 *   GREE_CRYPTO_MBEDTLS   mbedtls_aes_* / mbedtls_gcm_*     (mbedTLS 2.x/3.x,
 *                                                            ESP-IDF <= 5.x)
 *   GREE_CRYPTO_PSA       psa_cipher_* / psa_aead_*         (mbedTLS 4.x,
 *                                                            ESP-IDF 6.x)
 *
 * Pick MBEDTLS or PSA by mbedTLS major version, not by chip: mbedTLS 4.x
 * moved mbedtls/aes.h and mbedtls/gcm.h to mbedtls/private/ and made PSA the
 * public API. With PSA, call psa_crypto_init() once before using nuGreeC.
 *
 * GCM note: only ESP32-S2 and ESP32-P4 have a GCM hardware block. Everywhere
 * else (ESP32, S3, C3, C6, H2) the AES rounds are accelerated but GHASH stays
 * in software - still correct, just not free.
 */
#define GREE_CRYPTO_BUILTIN 0
#define GREE_CRYPTO_MBEDTLS 1
#define GREE_CRYPTO_PSA     2

#ifndef GREE_CRYPTO
#define GREE_CRYPTO GREE_CRYPTO_BUILTIN
#endif

/* Broadcast scan support (ac_discover). Drop it if the device address and
 * id are provisioned out of band. */
#ifndef GREE_ENABLE_DISCOVERY
#define GREE_ENABLE_DISCOVERY 1
#endif

/* --- timing ------------------------------------------------------------- */

#ifndef GREE_TIMEOUT_MS
#define GREE_TIMEOUT_MS 2000
#endif

/* Extra send attempts after the first one (UDP has no retransmission). */
#ifndef GREE_RETRIES
#define GREE_RETRIES 2
#endif

#if !GREE_ENABLE_V1 && !GREE_ENABLE_V2
#error "nuGreeC: enable at least one of GREE_ENABLE_V1 / GREE_ENABLE_V2"
#endif

#endif /* NUGREEC_GREE_CONFIG_H */
