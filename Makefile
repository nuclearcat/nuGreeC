# SPDX-License-Identifier: MIT OR Apache-2.0
# nuGreeC - minimal Gree A/C client
#
#   make           library + greectl example
#   make test      run the self-tests
#   make size      per-symbol footprint report
#   make CONFIG='-DGREE_ENABLE_V2=0 -DGREE_ENABLE_DISCOVERY=0'   trimmed build

CC      ?= cc
AR      ?= ar
CONFIG  ?=
CFLAGS  ?= -Os -std=c99 -Wall -Wextra -Wpedantic -ffunction-sections -fdata-sections
CPPFLAGS = -Iinclude $(CONFIG)
LDFLAGS ?= -Wl,--gc-sections
LIBS    ?=            # e.g. -lmbedcrypto when GREE_CRYPTO=GREE_CRYPTO_MBEDTLS

LIB_SRC = src/gree.c src/gree_crypto.c \
          src/gree_crypto_mbedtls.c src/gree_crypto_psa.c
LIB_OBJ = $(LIB_SRC:.c=.o)

all: libgree.a greectl

libgree.a: $(LIB_OBJ)
	$(AR) rcs $@ $^

greectl: examples/greectl.o examples/udp_posix.o libgree.a
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

examples/%.o: examples/%.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -Iexamples -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

BACKEND_SRC = src/gree_crypto.c src/gree_crypto_mbedtls.c src/gree_crypto_psa.c
TESTDEP = $(LIB_SRC) src/gree_crypto.h include/gree.h include/gree_config.h
SAN     = -fsanitize=address,undefined -fno-sanitize-recover=all
FUZZ_N ?= 200000

test: tests/test_gree
	./tests/test_gree

tests/test_gree: tests/test_gree.c $(TESTDEP)
	$(CC) -std=c99 -g -O1 -Wall -Wextra $(CPPFLAGS) -o $@ $< $(BACKEND_SRC) $(LIBS)

# Same tests with the sanitizers on.
asan: tests/test_gree.c $(TESTDEP)
	$(CC) -std=c99 -g -O1 -Wall -Wextra $(SAN) $(CPPFLAGS) \
	  -o tests/test_asan $< $(BACKEND_SRC) $(LIBS)
	./tests/test_asan

# Throw malformed datagrams at the receive path.
fuzz: tests/fuzz_parse.c $(TESTDEP)
	$(CC) -std=c99 -g -O1 -Wall -Wextra $(SAN) $(CPPFLAGS) \
	  -o tests/fuzz_parse $< $(BACKEND_SRC) $(LIBS)
	./tests/fuzz_parse $(FUZZ_N)

check: test asan fuzz

# API reference. Fetches the theme on first run. Warnings are failures here
# too, so `make docs` and the docs CI job agree.
THEME_URL = https://github.com/jothepro/doxygen-awesome-css.git
THEME_TAG = v2.3.4

docs:
	@command -v doxygen >/dev/null || { echo "doxygen not installed"; exit 1; }
	@test -d .doxygen-awesome || git clone --depth 1 --branch $(THEME_TAG) \
	    $(THEME_URL) .doxygen-awesome || git clone --depth 1 $(THEME_URL) .doxygen-awesome
	@doxygen Doxyfile 2>doxygen.log; rc=$$?; \
	  if grep -qE '(warning|error):' doxygen.log || [ $$rc -ne 0 ]; then \
	    cat doxygen.log; echo "docs: build not clean"; exit 1; fi
	@echo "open docs/html/index.html"


# Footprint of the library alone, without the POSIX example or libc.
size: libgree.a
	@size -t libgree.a | tail -3
	@echo
	@echo "--- largest symbols ---"
	@nm --print-size --size-sort --radix=d libgree.a 2>/dev/null | \
	  awk '$$3 ~ /[tTrRdD]/ {printf "%6d  %s\n", $$2, $$4}' | sort -rn | head -20

clean:
	rm -f $(LIB_OBJ) examples/*.o libgree.a greectl \
	      tests/test_gree tests/test_asan tests/fuzz_parse
	rm -rf docs/html

.PHONY: all test asan fuzz check docs size clean
