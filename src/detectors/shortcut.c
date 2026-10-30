/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/shortcut/shortcut.go and
 * common.ResponseContainsSubstring. Line limits follow Go 1.26.7 bufio.Scanner. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* 1 found, 0 absent, -1 too long. Complete lines only when a read error is set;
 * EOF yields a final unterminated token at or below 65536 bytes. */
static int contains_line(br_slice body, const char *read_error, const char *needle, const char **cause)
{
    size_t nlen = strlen(needle), at = 0;
    bool eof = !read_error;
    while (at < body.len) {
        size_t remaining = body.len - at;
        size_t lf = SIZE_MAX;
        size_t window = remaining < 65537 ? remaining : 65537;
        for (size_t i = 0; i < window; ++i) if (body.data[at + i] == '\n') { lf = i; break; }
        if (lf == SIZE_MAX && remaining > 65536) { *cause = "bufio.Scanner: token too long"; return -1; }
        if (lf == SIZE_MAX && !eof) break;
        size_t len = lf == SIZE_MAX ? remaining : lf;
        if (len && body.data[at + len - 1] == '\r') --len;
        if (nlen <= len) {
            for (size_t i = 0; i + nlen <= len; ++i)
                if (!memcmp(body.data + at + i, needle, nlen)) return 1;
        }
        if (lf == SIZE_MAX) break;
        at += lf + 1;
    }
    if (read_error) *cause = read_error;
    return 0;
}

static int verify_shortcut(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    br_slice secret = {result->raw.data, result->raw.len};
    if (!ctx)
        return br_result_set_verification_error(result, "net/http: nil Context", &secret, 1) == 0 ? 0 : -1;
    const br_header headers[] = {{"Content-Type", "application/json"}, {"Shortcut-Token", key}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.app.shortcut.com/api/v3/member",
        .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *error = NULL;
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &error) != 0)
        cause = error;
    else {
        int found = contains_line(response.body, response.body_error, "name", &cause);
        if (found < 0) cause = "bufio.Scanner: token too long";
        else if (!cause && found == 1 && response.status >= 200 && response.status < 300)
            result->verified = true;
        /* Non-2xx, a missing marker, and a successful empty body are determinate. */
    }
    int rc = br_result_set_verification_error(result, cause, &secret, 1);
    br_http_release(ctx, &response);
    free(error);
    return rc == 0 ? 0 : -1;
}

static int scan_shortcut(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Shortcut scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        if (br_finding_key(&result, detector->type, keys.items[i], "key") != 0 ||
            (verify && verify_shortcut(ctx, keys.items[i], &result) != 0) ||
            br_results_push(out, &result) != 0)
            rc = fail(error, "out of memory creating Shortcut result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"shortcut"};
static br_detector shortcut = {
    .type = 587, .version = 0, .name = "Shortcut", .custom_name = "",
    .description = "Shortcut is a project management tool. Shortcut API keys can be used to access and modify project data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_shortcut,
};

int br_shortcut_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Shortcut detector output");
    *out = NULL;
    if (br_key_pattern_init(&shortcut,
            "\\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b", error) != 0)
        return -1;
    *out = &shortcut;
    return 0;
}
