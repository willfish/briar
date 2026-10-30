/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/pypi/pypi.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char upload_url[] = "https://upload.pypi.org/legacy/";
static const char digest_needle[] = "Include at least one message digest.";

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int set_cause(br_result *result, const char *cause)
{
    const br_slice secret = {result->raw.data, result->raw.len};
    return br_result_set_verification_error(result, cause, &secret, 1) ? -1 : 0;
}

static int append_mem(unsigned char *body, size_t *at, size_t cap, const void *src, size_t len)
{
    if (len > cap - *at) return -1;
    memcpy(body + *at, src, len);
    *at += len;
    return 0;
}

static int append_field(unsigned char *body, size_t *at, size_t cap, const char *boundary,
                        const char *name, const char *value)
{
    static const char prefix[] = "\r\nContent-Disposition: form-data; name=\"";
    if (append_mem(body, at, cap, "--", 2) || append_mem(body, at, cap, boundary, 60) ||
        append_mem(body, at, cap, prefix, sizeof(prefix) - 1) ||
        append_mem(body, at, cap, name, strlen(name)) || append_mem(body, at, cap, "\"\r\n\r\n", 5) ||
        append_mem(body, at, cap, value, strlen(value)) || append_mem(body, at, cap, "\r\n", 2))
        return -1;
    return 0;
}

/* Go's default scanner accepts a 65536-byte token and rejects the next byte.
 * An injected body error stands in for a reader failure before a match. */
static int digest_present(const br_http_response *response, bool *found, const char **cause)
{
    *found = false;
    *cause = NULL;
    if (response->body_error) {
        *cause = response->body_error;
        return 0;
    }
    br_slice body = response->body;
    br_slice needle = {(const unsigned char *)digest_needle, sizeof(digest_needle) - 1};
    size_t at = 0;
    while (at <= body.len) {
        size_t start = at, end = at;
        while (end < body.len && body.data[end] != '\n') ++end;
        size_t token = end;
        if (token > start && body.data[token - 1] == '\r') --token;
        if (token - start > 65536) {
            *cause = "bufio.Scanner: token too long";
            return 0;
        }
        if (br_slice_find((br_slice){body.data + start, token - start}, needle, 0) != SIZE_MAX) {
            *found = true;
            return 0;
        }
        if (end == body.len) break;
        at = end + 1;
    }
    return 0;
}

static int verify_pypi(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    unsigned char random[30];
    if (RAND_bytes(random, sizeof(random)) != 1) return -1;
    static const char hex[] = "0123456789abcdef";
    char boundary[61];
    for (size_t i = 0; i < sizeof(random); ++i) {
        boundary[2 * i] = hex[random[i] >> 4];
        boundary[2 * i + 1] = hex[random[i] & 15];
    }
    boundary[60] = '\0';
    /* WriteField and Close finish before NewRequestWithContext. */
    unsigned char body[1024];
    size_t at = 0;
    if (append_field(body, &at, sizeof(body), boundary, ":action", "file_upload") ||
        append_field(body, &at, sizeof(body), boundary, "name", "dummy-package") ||
        append_field(body, &at, sizeof(body), boundary, "version", "0.0.1") ||
        append_field(body, &at, sizeof(body), boundary, "filetype", "sdist") ||
        append_field(body, &at, sizeof(body), boundary, "content", "dummy-content") ||
        append_mem(body, &at, sizeof(body), "--", 2) ||
        append_mem(body, &at, sizeof(body), boundary, 60) ||
        append_mem(body, &at, sizeof(body), "--\r\n", 4))
        return -1;
    if (!ctx) return set_cause(result, "net/http: nil Context");
    if (key.len > 179) return -1;
    char authorization[192];
    memcpy(authorization, "token ", 6);
    memcpy(authorization + 6, key.data, key.len);
    authorization[6 + key.len] = '\0';
    char content_type[96];
    snprintf(content_type, sizeof(content_type), "multipart/form-data; boundary=%s", boundary);
    const br_header headers[] = {
        {"Authorization", authorization},
        {"Content-Type", content_type},
    };
    const br_http_request request = {
        .method = "POST", .url = upload_url, .headers = headers, .nheaders = 2,
        .body = {body, at}, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[64];
    const char *cause = NULL;
    bool verified = false;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &transport_error))
        cause = transport_error; /* NULL diagnostic stays NULL. */
    else if (response.status == 400) {
        bool found = false;
        rc = digest_present(&response, &found, &cause);
        if (!rc && !cause && found) verified = true;
        else if (!rc && !cause) {
            snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
            cause = status_error;
        }
    } else if (response.status != 403) {
        snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        cause = status_error;
    }
    if (!rc) rc = set_cause(result, cause);
    if (!rc) result->verified = verified;
    br_http_release(ctx, &response);
    free(transport_error);
    return rc;
}

static int scan_pypi(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized PyPI scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, true, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key"))
            rc = fail(&owned_error, "cannot create PyPI result");
        else if (verify && verify_pypi(ctx, key, &result))
            rc = fail(&owned_error, "cannot verify PyPI candidate");
        if (!rc && br_results_push(out, &result))
            rc = fail(&owned_error, "cannot append PyPI result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"pypi-AgEIcHlwaS5vcmcCJ"};
static br_detector detector = {
    .type = 998, .name = "PyPI", .custom_name = "",
    .description = "PyPI is a repository of software for the Python programming language. The credential allows for managing Pypi packages.",
    .keywords = keywords, .nkeywords = 1, .max_secret_size = -1, .start_offset = -1,
    .max_credential_span = -1, .scan = scan_pypi,
};

int br_pypi_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid PyPI detector output");
    *out = NULL;
    if (!detector.state &&
        br_regex_compile("(pypi-AgEIcHlwaS5vcmcCJ[a-zA-Z0-9-_]{150,157})",
                         (br_regex **)&detector.state, error))
        return -1;
    *out = &detector;
    return 0;
}
