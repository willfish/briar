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
TEST_JOBS ?= 2
DOCKER_IMAGE ?= briar:local
DOCKER_TEST_IMAGE ?= briar:test
VCS_REF ?= $(shell git rev-parse HEAD)
DIST_DIR ?= dist
# The container entrypoint checks isolation before NETWORK_RUNNER is cleared.
NETWORK_RUNNER ?= unshare --user --map-root-user --net bash -eu -c 'ip link set dev lo up; exec "$$@"' briar-test
DOCKER_TEST_RUN = docker run --rm --platform=linux/amd64 --network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges --tmpfs /tmp:rw,exec,size=512m

.PHONY: all test-binaries check check-core check-proxy check-http-profiles check-detectors check-e2e check-cli-failures image test-image check-native-container check-image check-hook check-container clean
all: $(BUILD_DIR)/briar $(BUILD_DIR)/libbriar.a

test-binaries: $(CORE_TESTS) $(DETECTOR_TESTS) $(PROXY_TEST) $(PROFILE_TEST)

image:
	docker build --platform=linux/amd64 --build-arg VCS_REF="$(VCS_REF)" -t "$(DOCKER_IMAGE)" .

test-image:
	docker build --platform=linux/amd64 --target test --build-arg BUILD_JOBS="$(TEST_JOBS)" -t "$(DOCKER_TEST_IMAGE)" .

check-native-container: test-image
	$(DOCKER_TEST_RUN) "$(DOCKER_TEST_IMAGE)" bash -euo pipefail -c 'actionlint .github/workflows/ci.yml; shellcheck tools/ci_container_entrypoint.sh; python3 -m unittest discover -s tests -p test_ci_release.py -v; make -s -j"$$1" check NETWORK_RUNNER=' briar-check "$(TEST_JOBS)"

check-image: image test-image
	python3 tools/ci_image_smoke.py "$(DOCKER_IMAGE)" "$(DOCKER_TEST_IMAGE)" "$(VCS_REF)" "$(DIST_DIR)"

check-hook:
	pre-commit validate-manifest .pre-commit-hooks.yaml
	python3 tools/ci_hook_smoke.py "$(CURDIR)"

# This is the acceptance gate used by agents and CI. Archive only after all checks.
check-container: check-native-container check-image check-hook
	mkdir -p "$(DIST_DIR)"
	bash -euo pipefail -c 'docker save "$$1" | gzip -n > "$$2/briar-linux-amd64.docker.tar.gz"' briar-archive "$(DOCKER_IMAGE)" "$(DIST_DIR)"
	cd "$(DIST_DIR)" && sha256sum briar-linux-amd64.docker.tar.gz > SHA256SUMS

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
	$(NETWORK_RUNNER) python3 tests/core/proxy_connect.py $(PROXY_TEST)

check-detectors: $(DETECTOR_TESTS)
	@set -e; for test in $(DETECTOR_TESTS); do "$$test"; done

check-http-profiles: $(PROFILE_TEST)
	$(NETWORK_RUNNER) python3 tests/core/http_profiles.py $(PROFILE_TEST)

check-e2e: $(BUILD_DIR)/briar
	python3 tests/core/e2e.py $(BUILD_DIR)/briar

check-cli-failures: $(BUILD_DIR)/briar
	$(NETWORK_RUNNER) python3 tests/core/cli_failures.py $(BUILD_DIR)/briar

check: check-core check-proxy check-http-profiles check-detectors check-e2e check-cli-failures

clean:
	rm -f $(OBJECTS) $(OBJECTS:.o=.d) $(BUILD_DIR)/src/main.o $(BUILD_DIR)/src/main.d $(BUILD_DIR)/libbriar.a $(BUILD_DIR)/briar $(CORE_TESTS) $(DETECTOR_TESTS) $(PROXY_TEST) $(PROFILE_TEST)

-include $(OBJECTS:.o=.d) $(BUILD_DIR)/src/main.d
