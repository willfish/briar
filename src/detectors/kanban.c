/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/kanban/kanban.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *host; } kanban_patterns;
enum { KANBAN_KEY_SIZE = 12 };

static int kanban_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int kanban_verify(const br_scan_ctx *ctx, br_slice key, br_slice host,
                         br_result *result, bool *keep, char **error)
{
    static const char prefix[] = "https://";
    static const char path[] = "/api/v3/users/current.json";
    const size_t fixed = sizeof(prefix) - 1 + sizeof(path);
    *keep = true;
    /* fmt.Sprintf builds the URL before NewRequestWithContext. A nil context
     * or constructor failure drops only this pair. The host stays out of Raw. */
    if (host.len > SIZE_MAX - fixed)
        return kanban_fail(error, "Kanban URL too large");
    char *url = malloc(host.len + fixed);
    if (!url) return kanban_fail(error, "cannot allocate Kanban URL");
    size_t at = sizeof(prefix) - 1;
    memcpy(url, prefix, at);
    memcpy(url + at, host.data, host.len);
    at += host.len;
    memcpy(url + at, path, sizeof(path));
    if (!ctx) {
        *keep = false;
        free(url);
        return 0;
    }
    char authorization[sizeof("Bearer ") + KANBAN_KEY_SIZE];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, key.len);
    authorization[7 + key.len] = '\0';
    const br_header headers[] = {
        {"Accept", "application/vnd.kanban+json; version=3"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_DETECTOR_PUBLIC, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Do and preparation failures stay unverified. Body and read errors are
     * ignored. No setter. The URL, captures and both headers survive release. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(send_error);
    free(url);
    return 0;
}

static int kanban_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return kanban_fail(error, "invalid or uninitialized Kanban scan");
    const kanban_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->host)
        return kanban_fail(error, "invalid or uninitialized Kanban scan");
    size_t original_len = out->len;
    br_captures keys = {0}, hosts = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (rc == 0)
        rc = br_captures_find(patterns->host, input, &hosts, false, &owned_error);
    /* Key-major product, including duplicates. A key with no URL is absent
     * even in NoV. Do not use br_scan_key: a constructor drop must not publish.
     * TrimSpace is a no-op. The 1024 span belongs to the engine, not this scan. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        br_slice key = br_captures_at(&keys, k);
        for (size_t h = 0; rc == 0 && h < hosts.len; ++h) {
            br_slice host = br_captures_at(&hosts, h);
            br_result result = {0};
            bool keep = true;
            if (key.len != KANBAN_KEY_SIZE || !host.len) {
                kanban_fail(&owned_error, "invalid Kanban capture");
                rc = -1;
            } else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
                kanban_fail(&owned_error, "cannot create Kanban result");
                rc = -1;
            } else if (verify) {
                rc = kanban_verify(ctx, key, host, &result, &keep, &owned_error);
            }
            if (rc == 0 && keep && br_results_push(out, &result) != 0) {
                kanban_fail(&owned_error, "cannot append Kanban result");
                rc = -1;
            }
            br_result_clear(&result);
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&hosts);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static kanban_patterns kanban_compiled;
static const char *const kanban_keywords[] = {"kanban"};
static const br_detector kanban_detector = {
    .type = 686, .version = 0, .name = "Kanban", .custom_name = "",
    .description = "KanbanTool is a project management software that helps visualize and optimize workflow. Kanban API keys can be used to access and modify project data.",
    .keywords = kanban_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &kanban_compiled, .scan = kanban_scan,
};

int br_kanban_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return kanban_fail(error, "invalid Kanban detector output");
    *out = NULL;
    if (!kanban_compiled.key && br_regex_compile_prefixed(kanban_keywords, 1,
            "\\b([0-9A-Z]{12})\\b", &kanban_compiled.key, error) != 0)
        return -1;
    if (!kanban_compiled.host && br_regex_compile(
            "\\b([0-9a-z]{1,}\\.kanbantool\\.com)\\b", &kanban_compiled.host, error) != 0)
        return -1;
    *out = &kanban_detector;
    return 0;
}
