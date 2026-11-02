# SPDX-License-Identifier: AGPL-3.0-only
CC ?= cc
AR ?= ar
PKG_CONFIG ?= pkg-config
BUILD_DIR ?= build
LIB_PACKAGES := libpcre2-8 libcurl json-c libcrypto libxml-2.0
CPPFLAGS += -Iinclude -D_POSIX_C_SOURCE=200809L $(shell $(PKG_CONFIG) --cflags $(LIB_PACKAGES))
CFLAGS ?= -O2 -g
override CFLAGS += -std=c17 -Wall -Wextra -Wpedantic -Werror -pthread
LDLIBS += $(shell $(PKG_CONFIG) --libs $(LIB_PACKAGES)) -lm

CORE_SOURCES := $(filter-out src/main.c,$(wildcard src/*.c))
DETECTOR_SOURCES := $(shell find src/detectors -type f -name '*.c' 2>/dev/null)
SOURCES := $(CORE_SOURCES) $(DETECTOR_SOURCES)
OBJECTS := $(patsubst %.c,$(BUILD_DIR)/%.o,$(SOURCES))
CORE_TESTS := $(patsubst tests/core/%.c,$(BUILD_DIR)/tests/core/%,$(wildcard tests/core/test_*.c))
DETECTOR_TESTS := $(patsubst tests/detectors/%.c,$(BUILD_DIR)/tests/detectors/%,$(wildcard tests/detectors/test_*.c))
PROXY_TEST := $(BUILD_DIR)/tests/core/proxy_connect
PROFILE_TEST := $(BUILD_DIR)/tests/core/http_profiles

.PHONY: all check check-core check-proxy check-http-profiles check-detectors check-e2e clean
all: $(BUILD_DIR)/briar $(BUILD_DIR)/libbriar.a

$(BUILD_DIR)/briar: $(BUILD_DIR)/src/main.o $(BUILD_DIR)/libbriar.a
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD_DIR)/libbriar.a: $(OBJECTS) Makefile
	@rm -f $@
	$(AR) rcs $@ $(OBJECTS)

$(BUILD_DIR)/%.o: %.c include/briar.h Makefile
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

$(BUILD_DIR)/tests/core/%: tests/core/%.c $(BUILD_DIR)/libbriar.a include/briar.h
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(BUILD_DIR)/libbriar.a $(LDLIBS)

$(BUILD_DIR)/tests/core/test_cli_io: src/main.c

$(BUILD_DIR)/tests/detectors/test_rabbitmq: src/detectors/rabbitmq.c

$(BUILD_DIR)/tests/detectors/test_sqlserver: src/detectors/sqlserver.c

$(BUILD_DIR)/tests/detectors/test_portainertoken: src/detectors/portainertoken.c

$(BUILD_DIR)/tests/detectors/%: tests/detectors/%.c $(BUILD_DIR)/libbriar.a include/briar.h tests/support/detector_test.h
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(BUILD_DIR)/libbriar.a $(LDLIBS)

check-core: $(CORE_TESTS)
	@set -e; for test in $(CORE_TESTS); do "$$test"; done

check-proxy: $(PROXY_TEST)
	unshare --user --map-root-user --net bash -eu -c 'ip link set dev lo up; exec python3 tests/core/proxy_connect.py "$$1"' _ $(PROXY_TEST)

check-detectors: $(DETECTOR_TESTS)
	@set -e; for test in $(DETECTOR_TESTS); do "$$test"; done

check-http-profiles: $(PROFILE_TEST)
	unshare --user --map-root-user --net bash -eu -c 'ip link set dev lo up; exec python3 tests/core/http_profiles.py "$$1"' _ $(PROFILE_TEST)

check-e2e: $(BUILD_DIR)/briar
	python3 tests/core/e2e.py $(BUILD_DIR)/briar

check: check-core check-proxy check-http-profiles check-detectors check-e2e

clean:
	rm -f $(OBJECTS) $(OBJECTS:.o=.d) $(BUILD_DIR)/src/main.o $(BUILD_DIR)/src/main.d $(BUILD_DIR)/libbriar.a $(BUILD_DIR)/briar $(CORE_TESTS) $(DETECTOR_TESTS) $(PROXY_TEST) $(PROFILE_TEST)

-include $(OBJECTS:.o=.d) $(BUILD_DIR)/src/main.d
