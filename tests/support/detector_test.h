/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef BRIAR_DETECTOR_TEST_H
#define BRIAR_DETECTOR_TEST_H

#include "briar.h"
#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t test_assertions;
#define CHECK(expr) do { \
    ++test_assertions; \
    if (!(expr)) { \
        fprintf(stderr, "FAIL %s:%d (%s): %s\n", __FILE__, __LINE__, __func__, #expr); \
        exit(1); \
    } \
} while (0)

typedef struct test_http test_http;
struct test_http {
    br_http_response response;
    const char *send_error;
    int send_rc;
    size_t calls, releases;
    void (*inspect)(test_http *, const br_scan_ctx *, const br_http_request *);
    void *user;
};

static inline int test_http_send(void *user, const br_scan_ctx *ctx,
                                  const br_http_request *request,
                                  br_http_response *response, char **error)
{
    test_http *http = user;
    ++http->calls;
    if (http->inspect) http->inspect(http, ctx, request);
    *response = http->response; /* Also populate failures to check release ownership. */
    *error = http->send_error ? strdup(http->send_error) : NULL;
    CHECK(!http->send_error || *error);
    return http->send_rc;
}

static inline void test_http_release(void *user, br_http_response *response)
{
    test_http *http = user;
    CHECK(response != NULL);
    ++http->releases;
}

static inline br_transport test_transport(test_http *http)
{
    return (br_transport){http, test_http_send, test_http_release};
}

static inline br_results test_scan(const br_detector *detector, const br_scan_ctx *ctx,
                                    bool verify, const void *data, size_t len)
{
    br_results results = {0};
    char *error = NULL;
    int rc = detector->scan(detector, ctx, verify, (br_slice){data, len}, &results, &error);
    if (error) fprintf(stderr, "scan error: %s\n", error);
    CHECK(rc == 0 && error == NULL);
    return results;
}

static inline void test_secret(char *out, size_t len, size_t shift)
{
    const char alphabet[] = "b7c9d2e5f6g8h3j4k1m0n2p4q6r8s1t3u5v7w9x2y4z6";
    for (size_t i = 0; i < len; ++i) out[i] = alphabet[(i + shift) % (sizeof(alphabet) - 1)];
    out[len] = '\0';
}

static inline void test_key_result(const br_result *result, int32_t type,
                                    const char *key, const char *part_name)
{
    CHECK(result->detector_type == type);
    CHECK(result->raw.len == strlen(key) && !memcmp(result->raw.data, key, strlen(key)));
    CHECK(!result->detector_name && !result->raw_v2.data && !result->raw_v2.len);
    CHECK(!result->redacted && !result->extra_data && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 1);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, part_name, &part));
    CHECK(json_object_is_type(part, json_type_string));
    CHECK(!strcmp(json_object_get_string(part), key));
    CHECK(!result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static inline int test_finish(const char *name)
{
    printf("%s: %zu assertions, 0 failures; synthetic injected HTTP only\n", name, test_assertions);
    return 0;
}

#endif
