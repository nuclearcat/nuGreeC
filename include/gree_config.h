/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/**
 * @file gree_config.h
 * @brief Compile-time configuration.
 *
 * Every knob below can be overridden from the build system
 * (@c -DGREE_PKT_BUF=512 ...) or by defining it before including gree.h.
 * Nothing here allocates; the sizes only affect @ref ac_state.
 */
#ifndef NUGREEC_GREE_CONFIG_H
#define NUGREEC_GREE_CONFIG_H

/**
 * @defgroup config Configuration
 * Compile-time options. All are overridable from the build.
 * @{
 */

/**
 * @brief Outer UDP datagram buffer, in bytes. Default 768.
 *
 * Holds the JSON envelope with its base64 payload, so it must fit roughly
 * 4/3 * #GREE_INNER_BUF plus about 110 bytes of envelope.
 */
#ifndef GREE_PKT_BUF
#define GREE_PKT_BUF 768
#endif

/**
 * @brief Scratch buffer for the inner packet, in bytes. Default 448.
 *
 * Holds the decrypted request or reply. A 26-column status reply needs about
 * 390 bytes. Shrink this together with ac_poll_props() if you only ever read
 * a handful of properties; an undersized buffer is reported as #AC_E_NOBUF
 * rather than overflowing.
 */
#ifndef GREE_INNER_BUF
#define GREE_INNER_BUF 448
#endif

/**
 * @brief Size of the opaque transport address token, in bytes. Default 8.
 *
 * Enough for an IPv4 address plus a port. Enlarge it for IPv6 or for a bigger
 * handle. @see ac_addr
 */
#ifndef GREE_ADDR_SZ
#define GREE_ADDR_SZ 8
#endif

/**
 * @brief Longest device name kept from a scan reply, including the NUL.
 *        Default 20; 0 drops the field entirely.
 */
#ifndef GREE_NAME_LEN
#define GREE_NAME_LEN 20
#endif

/**
 * @brief Compile in AES-128-ECB ("V1") packet support. Default 1.
 *
 * Older modules and most units in the field. Costs the AES inverse cipher,
 * roughly 760 bytes of flash including the inverse S-box.
 */
#ifndef GREE_ENABLE_V1
#define GREE_ENABLE_V1 1
#endif

/**
 * @brief Compile in AES-128-GCM ("V2") packet support. Default 1.
 *
 * Protocol V3.4+ modules, whose replies carry a @c tag field. Needs only the
 * forward cipher, so it is the cheaper of the two.
 */
#ifndef GREE_ENABLE_V2
#define GREE_ENABLE_V2 1
#endif

/** @brief Built-in AES. No dependencies. @see GREE_CRYPTO */
#define GREE_CRYPTO_BUILTIN 0
/** @brief mbedTLS 2.x/3.x classic API, i.e. ESP-IDF 5.x and earlier. @see GREE_CRYPTO */
#define GREE_CRYPTO_MBEDTLS 1
/** @brief PSA Crypto, i.e. mbedTLS 4.x and ESP-IDF 6.x. @see GREE_CRYPTO */
#define GREE_CRYPTO_PSA     2

/**
 * @brief Which crypto implementation to use. Default #GREE_CRYPTO_BUILTIN.
 *
 * The built-in AES is portable and self-contained. If your platform already
 * links an AES implementation - which any ESP-IDF app with WiFi or TLS does -
 * pointing nuGreeC at it removes about 2 KB of duplicate code and usually gets
 * you the hardware accelerator for free.
 *
 * Choose between #GREE_CRYPTO_MBEDTLS and #GREE_CRYPTO_PSA by mbedTLS major
 * version, not by chip: mbedTLS 4.x moved @c mbedtls/aes.h and @c mbedtls/gcm.h
 * to @c mbedtls/private/ and made PSA the public API. With PSA, call
 * @c psa_crypto_init() once before using nuGreeC.
 *
 * @note Only ESP32-S2 and ESP32-P4 have a GCM hardware block. Elsewhere the
 *       AES rounds are accelerated but GHASH stays in software.
 */
#ifndef GREE_CRYPTO
#define GREE_CRYPTO GREE_CRYPTO_BUILTIN
#endif

/**
 * @brief Compile in ac_discover() and the scan parser. Default 1.
 *
 * Drop it if the device address and id are provisioned out of band; saves
 * roughly 500 bytes.
 */
#ifndef GREE_ENABLE_DISCOVERY
#define GREE_ENABLE_DISCOVERY 1
#endif

/**
 * @brief Default per-attempt reply timeout, in milliseconds. Default 2000.
 * @see ac_set_timeout()
 */
#ifndef GREE_TIMEOUT_MS
#define GREE_TIMEOUT_MS 2000
#endif

/**
 * @brief Default number of extra attempts after the first. Default 2.
 *
 * UDP has no retransmission of its own. @see ac_set_timeout()
 */
#ifndef GREE_RETRIES
#define GREE_RETRIES 2
#endif

/** @} */

#if !GREE_ENABLE_V1 && !GREE_ENABLE_V2
#error "nuGreeC: enable at least one of GREE_ENABLE_V1 / GREE_ENABLE_V2"
#endif

#endif /* NUGREEC_GREE_CONFIG_H */
