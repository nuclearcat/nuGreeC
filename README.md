# nuGreeC

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Language: C99](https://img.shields.io/badge/language-C99-orange.svg)](#)
[![Flash: 5 KB](https://img.shields.io/badge/flash-from%205.0%20KB-green.svg)](#footprint)

**A Gree / Sinclair / Tosot air-conditioner client for microcontrollers.**

Speaks the local UDP protocol used by the Gree+ app: broadcast discovery,
binding, status polling and commands, with both the AES-128-ECB and
AES-128-GCM packet formats. No dynamic allocation, no sockets, no libc beyond
`<stdint.h>`.

- **5.0–6.6 KB of flash**, one ~1.3 KB struct of RAM, zero `malloc`
- **Bring your own transport** — two function pointers, so lwIP, ESP-IDF,
  Zephyr, an RTOS callback or BSD sockets all work
- **Optional platform crypto** — reuse the AES your ESP-IDF or OpenWrt image
  already links and drop ~2 KB
- **Tested against real hardware**, plus known-answer vectors, a mock device,
  sanitizers and a parser fuzzer

Runs anywhere from a Cortex-M to an OpenWrt router. Tested on a Gree unit with
firmware `U-WB05RT13 V1.45`.

```c
struct ac_state ac;

ac_init(&ac);
ac_set_transport(&ac, &my_udp_ops, &my_socket);
ac_set_device(&ac, "502cc6aabbcc");
ac_bind(&ac);                       /* once; persist ac_get_key() afterwards */

ac_poll(&ac);
printf("room %d C, target %d\n", ac_room_temp(&ac), ac_get(&ac, AC_SETTEM));

ac_power(&ac, 1);
ac_set_mode(&ac, AC_MODE_COOL);
ac_set_temp(&ac, 22);
ac_commit(&ac);                     /* one datagram for all three */
```

## Footprint

Cortex-M (Thumb-2, `-Os`), library only, excluding your transport:

| Configuration | Flash | RAM (`struct ac_state`) |
| --- | ---: | ---: |
| default (V1 + V2 + discovery) | 6.6 KB | 1332 B |
| V1 + discovery | 5.8 KB | 1332 B |
| V1 only, no discovery | 5.3 KB | 1332 B |
| V2 only, no discovery | 5.0 KB | 1332 B |
| default, trimmed buffers | 6.6 KB | 956 B |

RAM is one struct that you own — put it in `.bss`, on a task stack, or in a
static. The library allocates nothing, has no global mutable state, and never
calls `malloc`, `printf`, or a socket API. Peak stack use is about 250 bytes
(the AES key schedule is expanded per packet rather than cached, trading a few
microseconds for 176 bytes of permanent RAM).

Most of the struct is the two packet buffers. Shrink them with
`-DGREE_PKT_BUF` / `-DGREE_INNER_BUF` if you poll a fixed subset of properties
via `ac_poll_props()` instead of all 26. Undersized buffers are detected and
reported as `AC_E_NOBUF`; they never overflow.

## Build

```sh
make                       # libgree.a + the greectl example
make test                  # unit tests, mock device, crypto known-answer vectors
make check                 # tests + sanitizers + parser fuzzing
make size                  # footprint report
make CONFIG='-DGREE_ENABLE_V2=0 -DGREE_ENABLE_DISCOVERY=0'
```

C99, no build-system requirements: drop `src/` and `include/` into your
project. With the default backend only `gree.c` and `gree_crypto.c` produce
any code — the other two backends compile to nothing unless selected.

## The transport

The library never touches a network API. You supply two functions:

```c
struct ac_transport {
    int (*send)(void *ctx, const void *buf, unsigned len,
                const struct ac_addr *peer);
    int (*recv)(void *ctx, void *buf, unsigned cap, unsigned timeout_ms,
                struct ac_addr *peer);
};
```

`send` returns 0 or negative; `peer == NULL` means broadcast to the Gree port
(7000), which only `ac_discover()` uses. `recv` returns the datagram length,
0 on timeout, or negative on error.

`struct ac_addr` is an opaque `GREE_ADDR_SZ`-byte token. The library only ever
copies it: your `recv` fills it in, and it comes back to your `send`. Put a
`sockaddr_in`, an lwIP `ip_addr_t` plus port, or a connection index in it —
nuGreeC does not care and does not do name resolution.

`examples/udp_posix.c` is a complete implementation in about 100 lines, and
maps directly onto lwIP, ESP-IDF, Zephyr or an RTOS raw-UDP callback.

### Discovery is lossy

Modules ignore a large share of broadcast scans — the unit tested here
answered roughly every other one, with no reply at all to several in a row.
`ac_discover()` therefore sends `retries + 1` scans and dedupes by device id,
so set retries generously: many short attempts beat a few long waits, because
a module that is going to answer does so in about 40 ms.

```c
ac_set_timeout(&ac, 700, 9);        /* 10 scans, ~7 s worst case */
```

That unit also answered `255.255.255.255` but never its own subnet broadcast
(`192.168.1.255`). Prefer the limited broadcast address; the example lets you
override it (`greectl scan 192.168.1.255`) for hosts where the default route
points at a VPN or docker bridge.

## API

| Call | Purpose |
| --- | --- |
| `ac_init(&ac)` | Reset to defaults. Always first. |
| `ac_set_transport(&ac, ops, ctx)` | Install your two functions. |
| `ac_set_device(&ac, "502cc6aabbcc")` | Device id (12 hex chars, no separators). |
| `ac_set_peer(&ac, &addr)` | Where to send, if not using discovery. |
| `ac_discover(&ac, devs, n)` | Broadcast scan; returns how many answered. |
| `ac_select(&ac, &dev)` | Point at a discovered device. |
| `ac_bind(&ac)` | Trade the generic key for the device's own. |
| `ac_get_key(&ac)` / `ac_set_key(&ac, key, cipher)` | Persist and restore the key. |
| `ac_poll(&ac)` / `ac_poll_props(&ac, props, n)` | Read all / some properties. |
| `ac_get(&ac, AC_SETTEM)` | Last known value, or `AC_UNKNOWN`. |
| `ac_set(&ac, AC_SETTEM, 22)` | Queue a write. |
| `ac_commit(&ac)` | Send every queued write as one command. |
| `ac_room_temp(&ac)` | Room temperature with the firmware quirk applied. |
| `ac_strerror(rc)` | Text for an `AC_E_*` code. |

All calls are blocking and synchronous: one request, one reply, then return.
There is no callback machinery and no internal state machine to service, so
`ac_poll()` from a timer task is a complete integration. Retries and the
per-attempt timeout are `ac_set_timeout(&ac, ms, retries)`.

Errors are distinct enough to act on: `AC_E_TIMEOUT` (device silent),
`AC_E_CRYPTO` (wrong key or failed GCM tag — the reply arrived but could not
be trusted), `AC_E_NOTBOUND`, `AC_E_NOBUF`, `AC_E_DEVICE` (the unit answered
with a non-200 result).

### Binding and keys

`ac_bind()` performs the key exchange with the generic key and stores the
device's key in `ac->key`. **Save it** (`ac_get_key()`) to NVS and restore it
with `ac_set_key()` on the next boot — re-binding on every power-up is slow
and unnecessary. Record the cipher alongside it; `ac->cipher` holds the one
that worked.

With `AC_CIPHER_AUTO` (the default) `ac_bind()` tries V1 and falls back to V2,
so a bind against an offline device costs two timeouts. Pin the cipher once
you know it.

## Properties

`ac_get`/`ac_set` take an `enum ac_prop` and use raw wire values: `AC_POW`,
`AC_MOD`, `AC_SETTEM`, `AC_TEMUN`, `AC_TEMREC`, `AC_TEMSEN`, `AC_WDSPD`,
`AC_AIR`, `AC_BLO`, `AC_HEALTH`, `AC_SWHSLP`, `AC_SLPMOD`, `AC_LIG`,
`AC_SWINGLFRIG`, `AC_SWUPDN`, `AC_QUIET`, `AC_TUR`, `AC_STHT`, `AC_SVST`,
`AC_DWET`, `AC_DWATSEN`, `AC_DFLTR`, `AC_DWATFUL`, `AC_DMOD`,
`AC_HEATCOOLTYPE`, `AC_BUZZER`.

Worth knowing:

- **`AC_TEMSEN`** is not degrees. Most firmware reports celsius + 40; some
  reports celsius directly. `ac_room_temp()` detects which on the first
  reading and falls back to the target temperature when the model has no
  sensor (reports 0). Use it instead of reading `AC_TEMSEN` yourself.
- **Sleep** needs `AC_SWHSLP` and `AC_SLPMOD` set together.
- **`AC_BUZZER`** is inverted: set it to 1 to make a command *silent*.
- **`AC_QUIET`** is 0 for off and usually 2 for on, not 1.
- **`AC_DWET`, `AC_DWATSEN`, `AC_DMOD`, `AC_DWATFUL`** are dehumidifier
  fields. A mini-split reports 0 for all of them; that means "unsupported",
  not a real reading.
- **`AC_HEATCOOLTYPE`** has no established meaning. It is exposed raw.

`ac_set()` updates the local value immediately, so `ac_get()` reflects your
intent before `ac_commit()` confirms it. A poll overwrites it with reality.

Properties the device reports that nuGreeC does not model are ignored, not an
error. To read one, add it to `P_NAMES` in `src/gree.c` and to `enum ac_prop`
(the two must stay in the same order; a test enforces it). The property set is
limited to 32 by the dirty/known bitmasks.

## Reusing the platform's crypto

AES is a third of this library. If your platform already links one — every
ESP-IDF app with WiFi or TLS does — you can point nuGreeC at it and delete
that third, usually picking up the hardware accelerator on the way.

`src/gree_crypto.h` is the whole seam: four functions, no state kept between
calls. Pick a backend with `-DGREE_CRYPTO=…`:

| `GREE_CRYPTO` | Uses | For |
| --- | --- | --- |
| `GREE_CRYPTO_BUILTIN` | own AES-128 | default; no dependencies |
| `GREE_CRYPTO_MBEDTLS` | `mbedtls_aes_*`, `mbedtls_gcm_*` | mbedTLS 2.x/3.x, **ESP-IDF ≤ 5.x** |
| `GREE_CRYPTO_PSA` | `psa_cipher_*`, `psa_aead_*` | mbedTLS 4.x, **ESP-IDF 6.x** |

**Choose by mbedTLS major version, not by chip.** mbedTLS 4.x moved
`mbedtls/aes.h` and `mbedtls/gcm.h` to `mbedtls/private/` and made PSA the
public API, so `GREE_CRYPTO_MBEDTLS` will not compile there. ESP-IDF v6
defines `MBEDTLS_MAJOR_VERSION=4`; v5 and earlier are 3.x.

With the PSA backend, call `psa_crypto_init()` once at startup before any
nuGreeC call. Apps already using TLS have normally done this; calling it twice
is harmless.

### What it saves

Measured on xtensa ESP32, `-Os`, nuGreeC's own crypto object:

| Backend | nuGreeC crypto | Library total |
| --- | ---: | ---: |
| builtin | 2453 B | 6773 B |
| mbedTLS / PSA | 436 B | 4756 B |

**≈2.0 KB saved** — but only if the platform AES is *already* in your image.
Check before assuming:

```sh
xtensa-esp32-elf-gcc-nm --print-size build/your-app.elf | grep -E "esp_aes_|mbedtls_gcm_"
```

Across four ESP32 projects checked this way, AES-ECB was linked in all four
and GCM in three. The fourth had no GCM at all — there, switching backends
would have *added* ~1.4 KB of mbedTLS GCM to replace nuGreeC's own 541 B
implementation. Reuse only wins when the code is already there.

### Hardware acceleration

ESP-IDF enables `CONFIG_MBEDTLS_HARDWARE_AES` by default wherever
`SOC_AES_SUPPORTED` is set, which is every ESP32 variant, and its port handles
locking the shared AES peripheral. Speed is irrelevant here — a Gree packet is
a few hundred bytes once a minute — so treat the accelerator as a side effect
and the flash saving as the point.

Only **ESP32-S2 and ESP32-P4** have a GCM hardware block
(`SOC_AES_SUPPORT_GCM`). On ESP32, S3, C3, C6 and H2 the AES rounds are
accelerated but GHASH stays in software.

## OpenWrt

OpenWrt is just Linux, so `examples/udp_posix.c` works unchanged against musl
— there is nothing to port. `openwrt/Makefile` is a package recipe:

```sh
cp -r nuGreeC/openwrt <buildroot>/package/nugreec
make package/nugreec/compile V=s NUGREEC_SRC=/path/to/nuGreeC
```

It builds `greectl` against the platform mbedTLS. Verified against a real
OpenWrt 24.10.5 image (ramips/mt7620, ZBT WE826):

- rootfs is `ld-musl-mipsel-sf` — **MIPS32r2 little-endian, soft float**
- `libmbedcrypto.so.3.6.5` is already installed (450 KB), and exports all ten
  functions the mbedTLS backend calls
- **no Python on the image**, so the `greeclimate` route would mean adding
  python3 plus pycryptodome to a 16 MB device

Linking the system mbedTLS instead of the built-in AES removes 1599 B of
`.text` and 540 B of `.rodata` — the same ~2.1 KB seen on ESP32. On a router
that is noise; use whichever you prefer, and drop the `DEPENDS` line plus the
`CONFIG`/`LIBS` overrides for a self-contained binary.

The library is endian- and alignment-clean by construction: no multi-byte
pointer casts, no unions, no unaligned loads, and the one big-endian protocol
field (the GCM length block) is assembled byte by byte. That matters for MIPS,
which traps on unaligned access, and for big-endian targets like ath79.

The package recipe itself has **not been built** — that needs an OpenWrt SDK,
which is not installed here. Everything it depends on was verified from the
image above.

### Porting to something else

Implement the four functions in `src/gree_crypto.h` against your own AES and
add a `GREE_CRYPTO_*` value. Note that decryption **verifies** a supplied tag
rather than returning a computed one — PSA and most hardware AEAD blocks never
expose the tag they computed, only pass/fail, and keeping the comparison
behind the interface keeps it constant-time.

Validate a new backend by building `tests/test_gree.c` against it: the
known-answer vectors, the 128 single-bit tag-tamper checks and the mock-device
round trip all run unchanged.

## Configuration

Everything in `include/gree_config.h` is overridable from the build:

| Macro | Default | Effect |
| --- | ---: | --- |
| `GREE_PKT_BUF` | 768 | Datagram buffer. |
| `GREE_INNER_BUF` | 448 | Decrypted packet scratch. |
| `GREE_ADDR_SZ` | 8 | Size of the opaque address token. |
| `GREE_NAME_LEN` | 20 | Device name kept from a scan; 0 drops it. |
| `GREE_ENABLE_V1` | 1 | AES-128-ECB packets. |
| `GREE_ENABLE_V2` | 1 | AES-128-GCM packets. |
| `GREE_CRYPTO` | `…_BUILTIN` | Crypto backend; see above. |
| `GREE_ENABLE_DISCOVERY` | 1 | `ac_discover()` and the scan parser. |
| `GREE_TIMEOUT_MS` | 2000 | Per-attempt reply timeout. |
| `GREE_RETRIES` | 2 | Extra attempts after the first. |

GCM tags are always verified. There is no option to skip the check: it is a
handful of bytes, PSA cannot decrypt without it, and a V2 packet you have not
authenticated is a V1 packet with extra steps.

## Testing

`make check` runs three things:

1. **Known-answer vectors** for AES-128-ECB and AES-128-GCM, generated with
   pycryptodome using the protocol's real keys, nonce and AAD. The
   implementations are byte-exact against the reference, not merely
   self-consistent.
2. **A mock device** that decrypts requests and encrypts replies, exercising
   bind, poll, subset poll, command, retry-after-loss, wrong key, corrupted
   GCM tag, oversized reply, discovery and both firmware temperature
   conventions — over every combination of the cipher and feature flags.
   The GCM tag check is additionally hit with all 128 single-bit tamperings.
3. **A parser fuzzer** (`tests/fuzz_parse.c`) throwing random bytes, JSON
   soup, and bit-flipped valid packets at the receive path under
   ASan/UBSan. The current tree is clean over 2.3M cases.

The test suite was itself mutation-checked: deliberate faults injected into
the GHASH reduction, the GCM length block, and the temperature offset are all
caught.

### Backend verification status

- **`GREE_CRYPTO_BUILTIN`** — full suite, plus ASan/UBSan and 2.5M+ fuzz cases.
- **`GREE_CRYPTO_MBEDTLS`** — full suite passing against a real
  libmbedcrypto 3.6.5, across V1-only, V2-only and both.
- **`GREE_CRYPTO_PSA`** — compiles warning-clean against the real ESP-IDF v6 /
  mbedTLS 4.x headers, but has **not been run**: PSA's `psa_set_key_*` are
  static inline, so it cannot be exercised without a full PSA build. Run
  `tests/test_gree.c` on target once before trusting it.

### Field tested

Against a Gree unit running firmware `362001065279 / U-WB05RT13 V1.45`
(protocol `V3.4.M`, AES-GCM): discovery, bind, key persistence and reconnect
without re-binding, a 26-property poll, and a command round-trip (`r=200`)
all verified on real hardware.

## Security notes

The protocol's "encryption" is a fixed key shipped in every module, and the
GCM nonce is a constant reused for every packet. That is not a property of
this implementation; it is what the device does. Treat the link as
authenticated only against accidents, never against an attacker on the same
L2 segment.

The AES here is not constant-time. The threat model is a UDP link to an air
conditioner, not an adversary sharing your MCU.

Received packets are parsed before they can be authenticated (V1 has no
authentication at all), so the parser is the real attack surface — hence the
fuzzing. It never allocates, bounds every write, and rejects anything that
does not decrypt to a plausible JSON object.

## Protocol reference

UDP port 7000, JSON in both directions. Requests carry an encrypted, base64
inner packet in the `pack` field; V2 adds a `tag`.

```text
outer  {"cid":"app","i":0,"t":"pack","uid":0,"tcid":"<id>","pack":"<b64>"}
bind   {"t":"bind","mac":"<id>","uid":0}          -> {"t":"bindok","key":"..."}
status {"t":"status","mac":"<id>","cols":[...]}   -> {"t":"dat","cols":[...],"dat":[...]}
cmd    {"t":"cmd","mac":"<id>","opt":[...],"p":[...]} -> {"t":"res","opt":[...],"val":[...]}
scan   {"t":"scan"}  (broadcast, unencrypted)     -> encrypted with the generic key
```

`i` is 1 for scan and bind (generic key), 0 afterwards (device key).

- V1: AES-128-ECB, PKCS#7, generic key `a3K8Bx%2r8Y7#xDh`.
- V2: AES-128-GCM, generic key `{yxAHAY_Lm6pbC/<`, fixed 12-byte nonce,
  AAD `qualcomm-test`, tag base64 in the outer `tag` field.

## Layout

```
include/gree.h            public API
include/gree_config.h     compile-time knobs
src/gree.c                protocol, JSON, base64
src/gree_crypto.h         crypto backend interface (4 functions)
src/gree_crypto.c           built-in AES-128 ECB + GCM
src/gree_crypto_mbedtls.c   backend: mbedTLS 2.x/3.x
src/gree_crypto_psa.c       backend: PSA Crypto / mbedTLS 4.x
examples/udp_posix.c      reference transport (BSD sockets)
examples/greectl.c        CLI: scan / status / set
openwrt/Makefile          OpenWrt package recipe
tests/                    unit tests, mock device, fuzzer
LICENSE-MIT, LICENSE-APACHE, NOTICE
```

Unselected backends compile to an empty translation unit, so listing all
three in your build is harmless.

## greectl

```sh
./greectl scan
./greectl status 192.168.1.50 502cc6aabbcc            # binds, prints the key
./greectl status 192.168.1.50 502cc6aabbcc <key>
./greectl set 192.168.1.50 502cc6aabbcc <key> on temp 22 mode cool fan 2
```

## Credits

nuGreeC would not exist without the people who reverse-engineered this
protocol and published what they found. None of it is documented by Gree.

- **[tomikaa87/gree-remote](https://github.com/tomikaa87/gree-remote)** — the
  original public description of the Gree LAN protocol: the packet envelope,
  the scan/bind/status/cmd flow, the property names, and the generic AES key.
  Nearly every other implementation, this one included, starts from that
  write-up.
- **[cmroche/greeclimate](https://github.com/cmroche/greeclimate)** — the
  reference for the AES-GCM ("V2") packet format used by newer modules,
  including the fixed nonce and the `qualcomm-test` AAD, and for the
  `TemSen` +40 firmware quirk.
- **[asafbiton/gree-python-api](https://github.com/asafbiton/gree-python-api)**
  — an early, very readable Python implementation.
- **[bekmansurov/gree-hvac-protocol](https://github.com/bekmansurov/gree-hvac-protocol)**
  and **[gekkehenkie11/esphome_gree_ac](https://github.com/gekkehenkie11/esphome_gree_ac)**
  — the *other* Gree protocol: the 4800 8E1 binary bus between the WiFi module
  and the indoor unit. Not used here, but the reason this library knows what
  it is not.
- **[maxim-smirnov/gree-wifimodule-firmware](https://github.com/maxim-smirnov/gree-wifimodule-firmware)**
  — firmware archive and fetcher, useful for identifying module generations.
- **[Kaspars Dambis](https://kaspars.net/blog/gree-amber-nordic-gwh09yd-s6dba1)**
  — a careful write-up of the Gree+ firmware-query sequence.

Thank you, all of you.

### Relationship to that work

nuGreeC is an independent implementation in C. It contains **no code** from any
of the projects above; it was written from the protocol they documented, and
from packet captures and firmware analysis of a physical unit.

Please note that **gree-remote and greeclimate are GPL-licensed**. They were
used here as protocol documentation — the wire format, field names, and the
fixed key material every Gree module ships with are factual interoperability
information rather than authored expression. If you plan to build something
commercial on nuGreeC and that distinction matters to you, satisfy yourself
about it independently; this note is not legal advice.

The AES S-box and inverse S-box were generated from the algebraic definition in
FIPS PUB 197, not copied from an existing implementation.

## Contributing

Issues and pull requests are welcome. Two requests:

1. Run `make check` before opening a PR — tests, sanitizers and the fuzzer.
2. If you add a device property, add it to **both** `enum ac_prop` in
   `include/gree.h` and `P_NAMES` in `src/gree.c`, in the same order. A test
   enforces this, and it will fail loudly if they drift.

Reports from models this has not been tried on are especially useful,
particularly ones that turn out to use the V1/ECB packet format — the only
unit tested so far speaks V2/GCM. Please redact device ids, IP addresses and
encryption keys from any logs you attach.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this work, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.

## Disclaimer

Not affiliated with, endorsed by, or supported by Gree Electric Appliances.
"Gree", "Sinclair" and "Tosot" are trademarks of their respective owners, used
here only to say what this software talks to.

This controls a heating and cooling appliance. Do not build anything on it
where a missed command or a stale reading has safety consequences — it is a
best-effort UDP client for a device that answers roughly half of its broadcast
scans.
