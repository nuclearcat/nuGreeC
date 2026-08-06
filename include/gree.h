/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/**
 * @file gree.h
 * @brief nuGreeC - Gree / Sinclair / Tosot air-conditioner local protocol client.
 *
 * Freestanding C99: no malloc, no stdio, no sockets. All state lives in one
 * caller-owned struct; the datagram transport is two function pointers.
 *
 * @code
 * struct ac_state ac;
 *
 * ac_init(&ac);
 * ac_set_transport(&ac, &my_udp_ops, &my_socket);
 * ac_set_device(&ac, "502cc6aabbcc");
 * ac_bind(&ac);                       // or ac_set_key() from stored config
 *
 * ac_poll(&ac);
 * int t = ac_room_temp(&ac);
 *
 * ac_power(&ac, 1);
 * ac_set_temp(&ac, 22);
 * ac_commit(&ac);
 * @endcode
 *
 * Every call is blocking and synchronous: one request, one reply, then return.
 * There is no callback machinery and no state machine to service.
 */
#ifndef NUGREEC_GREE_H
#define NUGREEC_GREE_H

#include <stdint.h>
#include "gree_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup errors Result codes
 * Returned by every call that can fail. Negative values are errors.
 * @see ac_strerror()
 * @{
 */
enum {
    AC_OK         =  0, /**< Success. */
    AC_E_ARG      = -1, /**< Bad argument, or the client is not configured. */
    AC_E_NET      = -2, /**< The transport reported an error. */
    AC_E_TIMEOUT  = -3, /**< No usable reply arrived; the device is silent. */
    AC_E_CRYPTO   = -4, /**< Undecryptable payload or bad GCM tag: wrong key. */
    AC_E_PROTO    = -5, /**< Reply did not parse, or was an unexpected type. */
    AC_E_NOBUF    = -6, /**< Request or reply does not fit the configured buffers. */
    AC_E_NOTBOUND = -7, /**< No device key; call ac_bind() or ac_set_key() first. */
    AC_E_DEVICE   = -8  /**< The unit answered with a non-200 result code. */
};
/** @} */

/**
 * @defgroup props Device properties
 * @{
 */

/**
 * @brief Device properties, addressed by ac_get() and ac_set().
 *
 * Values are the raw wire values the unit uses, not cooked units. Each entry
 * below states its range; where a value has named constants, they are linked.
 *
 * @warning nuGreeC does not validate values. It sends what you give it and
 *          reports what comes back, because the accepted range is
 *          model-specific and no unit publishes it. An out-of-range write is
 *          typically clamped or ignored by the device, and shows up as the old
 *          value on the next poll rather than as an error.
 *
 * @note Properties the device reports that are not listed here are ignored
 *       rather than treated as an error. To add one, append it to this enum
 *       and to @c P_NAMES in @c src/gree.c, keeping both in the same order.
 *       The property count is limited to 32 by the dirty/known bitmasks.
 */
enum ac_prop {
    AC_POW = 0,      /**< Power. 0 off, 1 on. */
    AC_MOD,          /**< Operating mode. 0-4; see #ac_mode. */
    AC_SETTEM,       /**< Target temperature in the unit selected by #AC_TEMUN.
                          Typically 16-30 &deg;C (61-86 &deg;F); 8 &deg;C appears as the
                          frost-protection setpoint. Limits are model-specific. */
    AC_TEMUN,        /**< Temperature unit. 0 celsius, 1 fahrenheit. */
    AC_TEMREC,       /**< Fahrenheit half-degree bit. 0 or 1. */
    AC_TEMSEN,       /**< Raw room sensor. Not degrees, and 0 means "no sensor" -
                          use ac_room_temp() instead of reading this. */
    AC_WDSPD,        /**< Fan speed. 0-5; see #ac_fan. */
    AC_AIR,          /**< Fresh-air valve. 0 off, 1 on. Often unsupported. */
    AC_BLO,          /**< X-Fan / coil dry: runs the fan on to dry the coil. 0 or 1. */
    AC_HEALTH,       /**< Ionizer / "health" function. 0 or 1. Often unsupported. */
    AC_SWHSLP,       /**< Sleep on/off. 0 or 1. Write together with #AC_SLPMOD. */
    AC_SLPMOD,       /**< Sleep companion field. 0 or 1, matching #AC_SWHSLP.
                          No reliable meaning is known beyond that pairing. */
    AC_LIG,          /**< Front-panel display. 0 off, 1 on. */
    AC_SWINGLFRIG,   /**< Horizontal louver. 0-6; see #ac_swing_h. */
    AC_SWUPDN,       /**< Vertical louver. 0-11; see #ac_swing_v. */
    AC_QUIET,        /**< Quiet mode. 0 off, and usually 2 - not 1 - for on.
                          Model dependent. */
    AC_TUR,          /**< Turbo. 0 or 1. Mutually exclusive with quiet on most units. */
    AC_STHT,         /**< 8 &deg;C frost protection. 0 or 1. Heating models only. */
    AC_SVST,         /**< Energy-saving mode. 0 or 1. */
    AC_DWET,         /**< Dehumidifier target humidity, encoded rather than a
                          percentage. 0 on a unit without the feature. */
    AC_DWATSEN,      /**< Dehumidifier humidity sensor. 0 usually means
                          unsupported, not 0% RH. */
    AC_DFLTR,        /**< Clean-filter alert. 0 clear, 1 raised. Read-only in practice. */
    AC_DWATFUL,      /**< Water-tank-full alert. 0 clear, 1 raised. Dehumidifiers. */
    AC_DMOD,         /**< Dehumidifier mode. 0 default, 9 anion-only; 0 on an
                          air conditioner. Distinct from #AC_MODE_DRY. */
    AC_HEATCOOLTYPE, /**< Undocumented model/configuration flag. Range unknown;
                          exposed raw. Not the current operating direction. */
    AC_BUZZER,       /**< @c Buzzer_ON_OFF, and inverted: write 1 to *suppress*
                          the beep on a command. 0 is the normal beeping default. */
    AC_PROP_COUNT    /**< Number of properties. Not a property. */
};

/**
 * @brief Operating modes, the value of #AC_MOD.
 */
enum ac_mode {
    AC_MODE_AUTO = 0, /**< Automatic. */
    AC_MODE_COOL,     /**< Cooling. */
    AC_MODE_DRY,      /**< Dehumidify. Distinct from the #AC_DMOD family. */
    AC_MODE_FAN,      /**< Fan only. */
    AC_MODE_HEAT      /**< Heating. */
};

/**
 * @brief Fan speeds, the value of #AC_WDSPD. Range 0-5.
 *
 * @note Three-speed units collapse this: they typically accept 0, 1, 3 and 5
 *       and round anything else. The device decides; nuGreeC passes the value
 *       through unchanged.
 */
enum ac_fan {
    AC_FAN_AUTO = 0, /**< Automatic. */
    AC_FAN_LOW,      /**< Low. */
    AC_FAN_MEDLOW,   /**< Medium-low. */
    AC_FAN_MED,      /**< Medium. */
    AC_FAN_MEDHIGH,  /**< Medium-high. */
    AC_FAN_HIGH      /**< High. */
};

/**
 * @brief Horizontal louver positions, the value of #AC_SWINGLFRIG. Range 0-6.
 */
enum ac_swing_h {
    AC_SWING_H_DEFAULT = 0,  /**< Leave as-is / last position. */
    AC_SWING_H_FULL,         /**< Sweep the full range. */
    AC_SWING_H_LEFT,         /**< Fixed left. */
    AC_SWING_H_LEFT_CENTER,  /**< Fixed left of centre. */
    AC_SWING_H_CENTER,       /**< Fixed centre. */
    AC_SWING_H_RIGHT_CENTER, /**< Fixed right of centre. */
    AC_SWING_H_RIGHT         /**< Fixed right. */
};

/**
 * @brief Vertical louver positions, the value of #AC_SWUPDN. Range 0-11.
 *
 * Values 2-6 park the blade; 7-11 sweep within a band.
 */
enum ac_swing_v {
    AC_SWING_V_DEFAULT = 0,      /**< Leave as-is / last position. */
    AC_SWING_V_FULL,             /**< Sweep the full range. */
    AC_SWING_V_FIXED_UPPER,      /**< Fixed, highest. */
    AC_SWING_V_FIXED_UPPER_MID,  /**< Fixed, upper-middle. */
    AC_SWING_V_FIXED_MID,        /**< Fixed, middle. */
    AC_SWING_V_FIXED_LOWER_MID,  /**< Fixed, lower-middle. */
    AC_SWING_V_FIXED_LOWER,      /**< Fixed, lowest. */
    AC_SWING_V_SWING_UPPER,      /**< Sweep the upper band. */
    AC_SWING_V_SWING_UPPER_MID,  /**< Sweep the upper-middle band. */
    AC_SWING_V_SWING_MID,        /**< Sweep the middle band. */
    AC_SWING_V_SWING_LOWER_MID,  /**< Sweep the lower-middle band. */
    AC_SWING_V_SWING_LOWER       /**< Sweep the lower band. */
};

/**
 * @brief Returned by ac_get() for a property the device has never reported.
 *
 * Distinct from a genuine zero: a unit that does not implement a property
 * simply omits it, and reading 0 would be a wrong answer rather than no answer.
 */
#define AC_UNKNOWN INT16_MIN

/** @} */

/**
 * @defgroup transport Transport
 * The library never touches a network API; you supply one.
 * @{
 */

/**
 * @brief Opaque peer address, sized by #GREE_ADDR_SZ.
 *
 * nuGreeC never looks inside it. Your @c recv fills it in, and it comes back
 * to your @c send unchanged. Put a @c sockaddr_in, an lwIP address plus port,
 * or a connection index in it - the library does no name resolution and makes
 * no assumption about the contents.
 */
struct ac_addr {
    uint8_t b[GREE_ADDR_SZ]; /**< Opaque bytes, meaningful only to your transport. */
};

/**
 * @brief The two functions nuGreeC needs in order to talk to anything.
 *
 * Maps directly onto BSD sockets, lwIP, ESP-IDF, Zephyr, or a raw-UDP RTOS
 * callback. See @c examples/udp_posix.c for a complete implementation.
 */
struct ac_transport {
    /**
     * @brief Send one datagram.
     * @param ctx  The context pointer given to ac_set_transport().
     * @param buf  Bytes to send.
     * @param len  Number of bytes.
     * @param peer Destination, or @c NULL meaning "broadcast to the Gree port"
     *             (7000). Only ac_discover() ever passes @c NULL.
     * @return 0 on success, negative on error.
     */
    int (*send)(void *ctx, const void *buf, unsigned len,
                const struct ac_addr *peer);

    /**
     * @brief Receive one datagram.
     * @param ctx        The context pointer given to ac_set_transport().
     * @param buf        Where to put the datagram.
     * @param cap        Capacity of @p buf. Oversized datagrams may be truncated.
     * @param timeout_ms How long to wait before giving up.
     * @param peer       If not @c NULL, store the sender here.
     * @return The datagram length, 0 on timeout, negative on error.
     */
    int (*recv)(void *ctx, void *buf, unsigned cap, unsigned timeout_ms,
                struct ac_addr *peer);
};

/** @} */

/**
 * @defgroup state Client state
 * @{
 */

/**
 * @brief One entry of an ac_discover() result.
 */
struct ac_device {
    struct ac_addr addr;    /**< Where the reply came from; pass to ac_select(). */
    char id[13];            /**< Device id (its MAC), 12 hex chars, NUL terminated. */
#if GREE_NAME_LEN > 0
    char name[GREE_NAME_LEN]; /**< Device name, often empty. Omitted if #GREE_NAME_LEN is 0. */
#endif
};

/**
 * @brief Which packet format to speak.
 *
 * Not a quality setting - it is dictated by the WiFi module's firmware.
 */
enum ac_cipher {
    AC_CIPHER_AUTO = 0, /**< Probe V1, then V2, while binding. Costs two timeouts if the device is offline. */
    AC_CIPHER_V1,       /**< AES-128-ECB. Older modules. Unauthenticated. */
    AC_CIPHER_V2        /**< AES-128-GCM. Protocol V3.4+ modules; replies carry a tag. */
};

/**
 * @brief The entire client. Allocate one; the library allocates nothing.
 *
 * Put it in @c .bss, on a task stack, or in a static. Most of its size is the
 * two packet buffers, tunable with #GREE_PKT_BUF and #GREE_INNER_BUF.
 *
 * @note Treat the fields as read-only unless a setter exists. @c cipher and
 *       @c last_r are the ones worth reading directly.
 */
struct ac_state {
    const struct ac_transport *tr; /**< Installed by ac_set_transport(). */
    void *ctx;                     /**< Opaque context handed back to your transport. */

    struct ac_addr peer;           /**< Where requests go. */
    char id[13];                   /**< Device id, used as the @c mac and @c tcid fields. */
    char key[17];                  /**< 16-byte packet key, NUL terminated. @see ac_get_key() */

    uint8_t cipher;                /**< Cipher in use; an #ac_cipher value. */
    uint8_t bound;                 /**< Non-zero once @c key is a device key, not the generic one. */
    uint8_t has_peer;              /**< Non-zero once a peer address is set. */
    uint8_t temp_mode;             /**< Sensor convention: 0 unknown, 1 reports C+40, 2 plain C. */

    uint16_t timeout_ms;           /**< Per-attempt reply timeout. @see ac_set_timeout() */
    uint8_t retries;               /**< Extra attempts after the first. @see ac_set_timeout() */
    uint8_t last_r;                /**< Result code from the device's last reply; 200 is success. */

    uint32_t known;                /**< Bit per property the device has ever reported. */
    uint32_t dirty;                /**< Bit per property awaiting an ac_commit(). */
    int16_t val[AC_PROP_COUNT];    /**< Last known wire value of each property. */

    uint8_t buf[GREE_PKT_BUF];     /**< Outer datagram, transmit and receive. */
    uint8_t in[GREE_INNER_BUF];    /**< Inner packet: plaintext, then ciphertext. */
};

/** @} */

/**
 * @defgroup setup Setup
 * @{
 */

/**
 * @brief Reset a client to defaults. Call this first, always.
 *
 * Zeroes everything and installs the default timeout and retry count. Does not
 * touch the transport-side world: no sockets are opened or closed.
 *
 * @param ac Client to initialise.
 */
void ac_init(struct ac_state *ac);

/**
 * @brief Install the transport.
 * @param ac  Client.
 * @param tr  Your two functions. Must outlive @p ac; it is not copied.
 * @param ctx Passed back to every transport call. May be @c NULL.
 */
void ac_set_transport(struct ac_state *ac, const struct ac_transport *tr, void *ctx);

/**
 * @brief Set the target device id.
 * @param ac Client.
 * @param id Device id as 12 hex characters with no separators, e.g. @c "502cc6aabbcc".
 *           This is the module's MAC, and is what ac_discover() reports.
 * @retval AC_OK    Accepted.
 * @retval AC_E_ARG @p id was not exactly 12 characters.
 */
int  ac_set_device(struct ac_state *ac, const char *id);

/**
 * @brief Set the peer address directly, when not using discovery.
 * @param ac   Client.
 * @param peer Address, in whatever form your transport understands.
 */
void ac_set_peer(struct ac_state *ac, const struct ac_addr *peer);

/**
 * @brief Point the client at a device returned by ac_discover().
 *
 * Equivalent to ac_set_peer() plus ac_set_device() in one call.
 *
 * @param ac  Client.
 * @param dev An entry from an ac_discover() result.
 */
void ac_select(struct ac_state *ac, const struct ac_device *dev);

/**
 * @brief Restore a key saved from an earlier ac_bind().
 *
 * Binding on every boot is slow and unnecessary. Persist ac_get_key() and the
 * cipher that produced it, then restore both here.
 *
 * @param ac     Client.
 * @param key    The 16-character key from a previous ac_get_key().
 * @param cipher The cipher that produced it: #AC_CIPHER_V1 or #AC_CIPHER_V2.
 *               #AC_CIPHER_AUTO is not valid here - the key alone does not say
 *               which format it belongs to.
 * @retval AC_OK    Accepted.
 * @retval AC_E_ARG @p key was not 16 characters, or @p cipher was not V1 or V2.
 */
int  ac_set_key(struct ac_state *ac, const char *key, enum ac_cipher cipher);

/**
 * @brief The device key obtained by ac_bind(), for persisting.
 * @param ac Client.
 * @return NUL-terminated 16-character key, or @c NULL if not bound.
 * @warning This is the credential for controlling the unit. Do not log it.
 */
const char *ac_get_key(const struct ac_state *ac);

/**
 * @brief Set the reply timeout and retry count.
 *
 * Applies per attempt, so the worst case is @c ms * (@c retries + 1).
 *
 * @param ac      Client.
 * @param ms      Milliseconds to wait for each reply. Stored as @c uint16_t,
 *                so 0-65535; a healthy unit replies in about 40 ms.
 * @param retries Extra attempts after the first. Stored as @c uint8_t, so
 *                0-255. UDP has no retransmission of its own, so 0 means one
 *                shot and one chance.
 */
void ac_set_timeout(struct ac_state *ac, unsigned ms, unsigned retries);

/** @} */

/**
 * @defgroup protocol Protocol operations
 * @{
 */

#if GREE_ENABLE_DISCOVERY
/**
 * @brief Broadcast a scan and collect the units that answer.
 *
 * Sends @c retries+1 scans and dedupes replies by device id. That repetition
 * is not paranoia: modules ignore a large share of broadcast scans - one
 * tested unit answered roughly every other one - so a single scan frequently
 * finds nothing. A module that intends to answer does so in about 40 ms, so
 * prefer many short attempts to a few long waits.
 *
 * @code
 * ac_set_timeout(&ac, 700, 9);      // 10 scans, ~7 s worst case
 * n = ac_discover(&ac, devs, 8);
 * @endcode
 *
 * Requires only a transport; no device id or key is needed yet.
 *
 * @param ac  Client with a transport installed.
 * @param out Array to fill, at least @p max entries.
 * @param max Capacity of @p out, must be non-zero. Collection stops once it is
 *            full, so a small @p max on a busy network hides devices.
 * @return Number of devices written, or a negative #errors code.
 *
 * @note Where the broadcast goes is your transport's business. One tested unit
 *       answered @c 255.255.255.255 but never its own subnet broadcast.
 * @note Compiled out when #GREE_ENABLE_DISCOVERY is 0.
 */
int ac_discover(struct ac_state *ac, struct ac_device *out, unsigned max);
#endif

/**
 * @brief Exchange the generic key for this device's own key.
 *
 * Needs the peer address and device id set. On success the key is in
 * @c ac->key and the working cipher in @c ac->cipher; save both.
 *
 * @param ac Client.
 * @retval AC_OK      Bound; ac_get_key() is now valid.
 * @retval AC_E_TIMEOUT   The device did not answer.
 * @retval AC_E_CRYPTO    A reply arrived but could not be authenticated.
 * @retval AC_E_ARG   No transport, peer or device id.
 *
 * @note With #AC_CIPHER_AUTO this tries V1 then V2, so binding against an
 *       offline device costs two timeouts. Pin @c ac->cipher once you know it.
 */
int ac_bind(struct ac_state *ac);

/**
 * @brief Read every property nuGreeC models.
 *
 * One round trip for all 26. Needs buffers big enough for the reply; if you
 * have trimmed them, use ac_poll_props() instead.
 *
 * @param ac Client.
 * @return #AC_OK or a negative #errors code.
 * @retval AC_E_NOBUF The reply did not fit #GREE_INNER_BUF.
 */
int ac_poll(struct ac_state *ac);

/**
 * @brief Read a chosen subset of properties.
 *
 * Cheaper on the wire than ac_poll(), and it is what lets you shrink
 * #GREE_INNER_BUF on a constrained target.
 *
 * @code
 * static const uint8_t want[] = { AC_POW, AC_SETTEM, AC_TEMSEN };
 * ac_poll_props(&ac, want, 3);
 * @endcode
 *
 * @param ac    Client.
 * @param props Array of #ac_prop values, or @c NULL to mean "all of them".
 * @param n     Number of entries in @p props, 1 to #AC_PROP_COUNT. Must be
 *              non-zero unless @p props is @c NULL.
 * @return #AC_OK or a negative #errors code.
 */
int ac_poll_props(struct ac_state *ac, const uint8_t *props, unsigned n);

/**
 * @brief Send every queued write as a single command.
 *
 * Batches whatever ac_set() and the convenience setters have marked dirty into
 * one datagram. The dirty set is cleared only on success, so a failed commit
 * can simply be retried.
 *
 * @param ac Client.
 * @retval AC_OK Sent and acknowledged, or nothing was pending.
 * @retval AC_E_DEVICE The unit rejected the command; see @c ac->last_r.
 * @return Otherwise a negative #errors code.
 */
int ac_commit(struct ac_state *ac);

/** @} */

/**
 * @defgroup values Reading and writing values
 * @{
 */

/**
 * @brief Last known wire value of a property.
 * @param ac Client.
 * @param p  Property.
 * @return The raw wire value, in the range documented for that property in
 *         #ac_prop, or #AC_UNKNOWN if the device has never reported it.
 */
int ac_get(const struct ac_state *ac, enum ac_prop p);

/**
 * @brief Queue a write. Takes effect on the next ac_commit().
 *
 * Updates the local value immediately, so ac_get() reflects your intent before
 * the device has confirmed it. A later poll overwrites it with reality.
 *
 * @param ac    Client.
 * @param p     Property. Out-of-enum values are ignored.
 * @param value Raw wire value. See #ac_prop for the range of each property;
 *              nuGreeC does not validate it. Stored as @c int16_t, so the
 *              representable range is -32768 to 32767 and anything wider is
 *              truncated.
 */
void ac_set(struct ac_state *ac, enum ac_prop p, int value);

/**
 * @brief Room temperature, with the firmware quirk applied.
 *
 * #AC_TEMSEN is not degrees. Most firmware reports celsius + 40; some reports
 * celsius directly. This detects which on the first reading, and falls back to
 * the target temperature on models with no room sensor, which report 0.
 *
 * Use this rather than reading #AC_TEMSEN yourself.
 *
 * @param ac Client.
 * @return Temperature in the unit the device is configured for, or
 *         #AC_UNKNOWN if neither a sensor reading nor a target is known.
 */
int ac_room_temp(const struct ac_state *ac);

/**
 * @brief Human-readable form of a result code.
 * @param err Any #errors value.
 * @return A short static string. Never @c NULL.
 */
const char *ac_strerror(int err);

/** @} */

/**
 * @defgroup sugar Convenience wrappers
 * Thin inline wrappers over ac_set() and ac_get(). They cost nothing and are
 * omitted entirely if unused.
 * @{
 */

/**
 * @brief Queue a power change.
 * @param ac Client.
 * @param on Non-zero for on. Normalised to 0 or 1 before sending.
 */
static inline void ac_power(struct ac_state *ac, int on)
{ ac_set(ac, AC_POW, !!on); }

/**
 * @brief Queue an operating-mode change.
 * @param ac Client.
 * @param m  Mode, #AC_MODE_AUTO to #AC_MODE_HEAT (0-4). A cooling-only unit
 *           will not enter #AC_MODE_HEAT.
 */
static inline void ac_set_mode(struct ac_state *ac, enum ac_mode m)
{ ac_set(ac, AC_MOD, (int)m); }

/**
 * @brief Queue a target-temperature change.
 * @param ac      Client.
 * @param degrees Target in the unit currently selected by #AC_TEMUN - check it
 *                before assuming celsius. Typically 16-30 &deg;C or 61-86 &deg;F;
 *                the exact limits are model-specific and enforced by the
 *                device, not here. Out-of-range values are usually clamped.
 */
static inline void ac_set_temp(struct ac_state *ac, int degrees)
{ ac_set(ac, AC_SETTEM, degrees); }

/**
 * @brief Queue a fan-speed change.
 * @param ac Client.
 * @param f  Fan speed, #AC_FAN_AUTO to #AC_FAN_HIGH (0-5). Units with fewer
 *           speeds round to what they support.
 */
static inline void ac_set_fan(struct ac_state *ac, enum ac_fan f)
{ ac_set(ac, AC_WDSPD, (int)f); }

/**
 * @brief Whether the unit last reported itself as on.
 * @param ac Client.
 * @return Non-zero if powered on. Also 0 when the state is unknown.
 */
static inline int ac_is_on(const struct ac_state *ac)
{ return ac_get(ac, AC_POW) == 1; }

/** @} */

#ifdef __cplusplus
}
#endif
#endif /* NUGREEC_GREE_H */
