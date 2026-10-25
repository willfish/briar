#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
cd "$(dirname "$0")/../.."
binary=$(mktemp tests/detectors/.native-XXXXXX)
trap 'rm -f "$binary"' EXIT
"${CC:-cc}" -std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Wpedantic \
    -Iinclude $(pkg-config --cflags json-c libpcre2-8 libcurl) \
    src/result.c src/regex.c src/http.c \
    src/detectors/registry.c src/detectors/first_batch.c src/detectors/second_batch.c \
    src/detectors/third_batch.c src/detectors/fourth_batch.c \
    tests/detectors/test_detectors.c \
    -o "$binary" $(pkg-config --libs json-c libpcre2-8 libcurl) -lm
"$binary"
