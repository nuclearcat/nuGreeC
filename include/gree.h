/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/*
 * nuGreeC - Gree / Sinclair / Tosot air-conditioner local protocol client.
 *
 * Freestanding C99: no malloc, no stdio, no sockets. All state lives in one
 * caller-owned struct; the datagram transport is two function pointers.
 *
 *     struct ac_state ac;
 *
 *     ac_init(&ac);
 *     ac_set_transport(&ac, &my_udp_ops, &my_socket);
 *     ac_set_device(&ac, "502cc6aabbcc");
 *     ac_bind(&ac);                       // or ac_set_key() from NVS
 *
 *     ac_poll(&ac);
 *     int t = ac_room_temp(&ac);
 *
 *     ac_power(&ac, 1);
 *     ac_set_temp(&ac, 22);
 *     ac_commit(&ac);
 */
#ifndef NUGREEC_GREE_H
#define NUGREEC_GREE_H

#include <stdint.h>
#include "gree_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ codes */

enum {
    AC_OK         =  0,
    AC_E_ARG      = -1, /* bad argument or unconfigured state */
    AC_E_NET      = -2, /* transport reported an error */
    AC_E_TIMEOUT  = -3, /* no usable reply within the timeout */
    AC_E_CRYPTO   = -4, /* undecryptable payload or bad GCM tag */
    AC_E_PROTO    = -5, /* reply did not parse / unexpected packet type */
    AC_E_NOBUF    = -6, /* request or reply does not fit the buffers */
    AC_E_NOTBOUND = -7, /* no device key: call ac_bind() or ac_set_key() */
    AC_E_DEVICE   = -8  /* device answered with r != 200 */
};

/* ------------------------------------------------------------- properties */

/* Raw device properties. Values are the wire values; see ac_room_temp() for
 * the one field that needs interpretation. */
enum ac_prop {
    AC_POW = 0,      /* 0/1 power */
    AC_MOD,          /* enum ac_mode */
    AC_SETTEM,       /* target temperature in the unit selected by AC_TEMUN */
    AC_TEMUN,        /* 0 celsius, 1 fahrenheit */
    AC_TEMREC,       /* fahrenheit half-degree bit */
    AC_TEMSEN,       /* raw room sensor, see ac_room_temp() */
    AC_WDSPD,        /* enum ac_fan */
    AC_AIR,          /* fresh air valve */
    AC_BLO,          /* X-Fan / coil dry */
    AC_HEALTH,       /* ionizer */
    AC_SWHSLP,       /* sleep on/off  (write together with AC_SLPMOD) */
    AC_SLPMOD,       /* sleep companion field */
    AC_LIG,          /* front panel display */
    AC_SWINGLFRIG,   /* horizontal louver */
    AC_SWUPDN,       /* vertical louver */
    AC_QUIET,        /* 0 off, 2 quiet (model dependent) */
    AC_TUR,          /* turbo */
    AC_STHT,         /* 8 C frost protection */
    AC_SVST,         /* energy saving */
    AC_DWET,         /* dehumidifier target humidity (encoded) */
    AC_DWATSEN,      /* dehumidifier humidity sensor */
    AC_DFLTR,        /* clean filter alert */
    AC_DWATFUL,      /* water tank full alert */
    AC_DMOD,         /* dehumidifier mode */
    AC_HEATCOOLTYPE, /* undocumented model/config flag */
    AC_BUZZER,       /* Buzzer_ON_OFF: write 1 to suppress the command beep */
    AC_PROP_COUNT
};

enum ac_mode { AC_MODE_AUTO = 0, AC_MODE_COOL, AC_MODE_DRY, AC_MODE_FAN, AC_MODE_HEAT };
enum ac_fan  { AC_FAN_AUTO = 0, AC_FAN_LOW, AC_FAN_MEDLOW, AC_FAN_MED, AC_FAN_MEDHIGH, AC_FAN_HIGH };

/* Value returned by ac_get() for a property the device never reported. */
#define AC_UNKNOWN INT16_MIN

/* --------------------------------------------------------------- transport */

/* Opaque peer address. nuGreeC never looks inside it: the transport fills it
 * in on receive and gets it back on send. */
struct ac_addr {
    uint8_t b[GREE_ADDR_SZ];
};

struct ac_transport {
    /* Send one datagram. peer == NULL means "broadcast to the Gree port"
     * (only used by ac_discover). Return 0 on success, negative on error. */
    int (*send)(void *ctx, const void *buf, unsigned len,
                const struct ac_addr *peer);

    /* Receive one datagram, at most cap bytes, waiting up to timeout_ms.
     * Store the sender in *peer when peer != NULL.
     * Return the length, 0 on timeout, negative on error. */
    int (*recv)(void *ctx, void *buf, unsigned cap, unsigned timeout_ms,
                struct ac_addr *peer);
};

/* ------------------------------------------------------------------ state */

/* One entry of an ac_discover() result. */
struct ac_device {
    struct ac_addr addr;
    char id[13];                  /* device id / mac, 12 hex chars */
#if GREE_NAME_LEN > 0
    char name[GREE_NAME_LEN];
#endif
};

enum ac_cipher {
    AC_CIPHER_AUTO = 0, /* probe V1 then V2 while binding */
    AC_CIPHER_V1,       /* AES-128-ECB */
    AC_CIPHER_V2        /* AES-128-GCM */
};

struct ac_state {
    const struct ac_transport *tr;
    void *ctx;

    struct ac_addr peer;
    char id[13];                  /* device id used as mac/tcid */
    char key[17];                 /* 16 byte device key, NUL terminated */

    uint8_t cipher;               /* enum ac_cipher, in use */
    uint8_t bound;                /* key is a device key, not the generic one */
    uint8_t has_peer;
    uint8_t temp_mode;            /* 0 unknown, 1 sensor reports C+40, 2 plain C */

    uint16_t timeout_ms;
    uint8_t retries;
    uint8_t last_r;               /* device result code of the last reply */

    uint32_t known;               /* bit per property ever reported */
    uint32_t dirty;               /* bit per property pending an ac_commit() */
    int16_t val[AC_PROP_COUNT];

    uint8_t buf[GREE_PKT_BUF];    /* outer datagram */
    uint8_t in[GREE_INNER_BUF];   /* inner plaintext / ciphertext */
};

/* ------------------------------------------------------------------- setup */

/* Reset ac to defaults. Does not touch the transport-side world. */
void ac_init(struct ac_state *ac);

void ac_set_transport(struct ac_state *ac, const struct ac_transport *tr, void *ctx);

/* Target device id ("502cc6aabbcc", 12 hex chars, no separators). */
int  ac_set_device(struct ac_state *ac, const char *id);

/* Peer address, if not taken from ac_discover(). */
void ac_set_peer(struct ac_state *ac, const struct ac_addr *peer);

/* Point the client at a device found by ac_discover(). */
void ac_select(struct ac_state *ac, const struct ac_device *dev);

/* Restore a key persisted from a previous ac_bind(). cipher must be the one
 * that produced it (AC_CIPHER_V1 or AC_CIPHER_V2). */
int  ac_set_key(struct ac_state *ac, const char *key, enum ac_cipher cipher);

/* Key obtained by ac_bind(), to be stored in NVS. NULL if not bound. */
const char *ac_get_key(const struct ac_state *ac);

void ac_set_timeout(struct ac_state *ac, unsigned ms, unsigned retries);

/* --------------------------------------------------------------- protocol */

#if GREE_ENABLE_DISCOVERY
/* Broadcast a scan and collect replies until the timeout expires.
 * Returns the number of devices written to out, or a negative error. */
int ac_discover(struct ac_state *ac, struct ac_device *out, unsigned max);
#endif

/* Exchange the generic key for this device's key. Fills ac->key. */
int ac_bind(struct ac_state *ac);

/* Read every property nuGreeC knows about. */
int ac_poll(struct ac_state *ac);

/* Read a subset: props is an array of n enum ac_prop values. Cheaper on the
 * wire and lets you shrink GREE_INNER_BUF. */
int ac_poll_props(struct ac_state *ac, const uint8_t *props, unsigned n);

/* Push every property marked dirty by ac_set() and friends. No-op when
 * nothing is pending. */
int ac_commit(struct ac_state *ac);

/* ----------------------------------------------------------------- values */

/* Wire value of a property, or AC_UNKNOWN if the device never reported it. */
int ac_get(const struct ac_state *ac, enum ac_prop p);

/* Queue a write. Takes effect on ac_commit(). */
void ac_set(struct ac_state *ac, enum ac_prop p, int value);

/* Room temperature in the unit reported by the device, or AC_UNKNOWN.
 * Applies the +40 offset used by newer firmware. */
int ac_room_temp(const struct ac_state *ac);

/* Human readable form of an AC_E_* code. */
const char *ac_strerror(int err);

/* ------------------------------------------------------- sugar (no cost) */

static inline void ac_power(struct ac_state *ac, int on)
{ ac_set(ac, AC_POW, !!on); }

static inline void ac_set_mode(struct ac_state *ac, enum ac_mode m)
{ ac_set(ac, AC_MOD, (int)m); }

static inline void ac_set_temp(struct ac_state *ac, int degrees)
{ ac_set(ac, AC_SETTEM, degrees); }

static inline void ac_set_fan(struct ac_state *ac, enum ac_fan f)
{ ac_set(ac, AC_WDSPD, (int)f); }

static inline int ac_is_on(const struct ac_state *ac)
{ return ac_get(ac, AC_POW) == 1; }

#ifdef __cplusplus
}
#endif
#endif /* NUGREEC_GREE_H */
