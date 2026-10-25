# SPDX-License-Identifier: AGPL-3.0-only
CC ?= cc
AR ?= ar
PKG_CONFIG ?= pkg-config
CPPFLAGS += -Iinclude -D_POSIX_C_SOURCE=200809L $(shell $(PKG_CONFIG) --cflags libpcre2-8 libcurl json-c)
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -Werror
LDLIBS += $(shell $(PKG_CONFIG) --libs libpcre2-8 libcurl json-c) -lm

CORE_SOURCES := $(filter-out src/main.c,$(wildcard src/*.c))
DETECTOR_SOURCES := $(shell find src/detectors -type f -name '*.c' 2>/dev/null)
SOURCES := $(CORE_SOURCES) $(DETECTOR_SOURCES)
OBJECTS := $(patsubst %.c,build/%.o,$(SOURCES))
CORE_TESTS := $(patsubst tests/core/%.c,build/tests/core/%,$(wildcard tests/core/test_*.c))
DETECTOR_TESTS := $(patsubst tests/detectors/%.c,build/tests/detectors/%,$(wildcard tests/detectors/test_*.c))
PROXY_TEST := build/tests/core/proxy_connect

.PHONY: all check check-core check-proxy check-detectors check-e2e clean
all: build/briar build/libbriar.a

build/briar: build/src/main.o build/libbriar.a
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

build/libbriar.a: $(OBJECTS)
	$(AR) rcs $@ $^

build/%.o: %.c include/briar.h
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

build/tests/core/%: tests/core/%.c build/libbriar.a include/briar.h
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< build/libbriar.a $(LDLIBS)

build/tests/detectors/%: tests/detectors/%.c build/libbriar.a include/briar.h
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< build/libbriar.a $(LDLIBS)

check-core: $(CORE_TESTS)
	@set -e; for test in $(CORE_TESTS); do "$$test"; done

check-proxy: $(PROXY_TEST)
	unshare --user --map-root-user --net bash -eu -c 'ip link set dev lo up; exec python3 tests/core/proxy_connect.py "$$1"' _ $(PROXY_TEST)

check-detectors: $(DETECTOR_TESTS)
	@set -e; for test in $(DETECTOR_TESTS); do "$$test"; done

check-e2e: build/briar
	python3 tests/core/e2e.py build/briar

check: check-core check-proxy check-detectors check-e2e

clean:
	rm -f $(OBJECTS) $(OBJECTS:.o=.d) build/src/main.o build/src/main.d build/libbriar.a build/briar $(CORE_TESTS) $(DETECTOR_TESTS) $(PROXY_TEST)

-include $(OBJECTS:.o=.d) build/src/main.d
