#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
cd "$(dirname "$0")/../.."
binary=$(mktemp tests/detectors/.native-fifth-XXXXXX)
trap 'rm -f "$binary"' EXIT
"${CC:-cc}" -std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Wpedantic -Werror \
    -Iinclude $(pkg-config --cflags json-c libpcre2-8 libcurl) \
    src/result.c src/regex.c src/http.c src/detectors/fifth_batch.c \
    tests/detectors/test_fifth_batch.c \
    -o "$binary" $(pkg-config --libs json-c libpcre2-8 libcurl)
"$binary"
