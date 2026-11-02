/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/newrelicbrowserkey/newrelicbrowserkey.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* Mandatory when verification ran, including a nil cause. No secrets. */
static int set_cause(br_result *result, const char *cause, char **error)
{
    if (br_result_set_verification_error(result, cause, NULL, 0) != 0)
        return fail(error, "cannot record NewRelicBrowserKey verification error");
    return 0;
}

static int add_string(br_json *object, const char *name, const char *value)
{
    br_json *part = json_object_new_string(value);
    if (!part) return -1;
    if (json_object_object_add(object, name, part) != 0) {
        json_object_put(part);
        return -1;
    }
    return 0;
}

static int redact(br_result *result, br_slice key, char **error)
{
    if (!key.data || key.len < 8) return fail(error, "cannot allocate NewRelicBrowserKey redaction");
    char shown[12];
    memcpy(shown, key.data, 8);
    memcpy(shown + 8, "...", 4);
    result->redacted = strdup(shown);
    if (!result->redacted) return fail(error, "cannot allocate NewRelicBrowserKey redaction");
    return 0;
}

/* Region is recorded only after a verified region wins. */
static int record_region(br_result *result, const char *region, char **error)
{
    result->extra_data = json_object_new_object();
    if (!result->extra_data) return fail(error, "cannot create NewRelicBrowserKey metadata");
    if (add_string(result->secret_parts, "region", region) != 0 ||
        add_string(result->extra_data, "region", region) != 0)
        return fail(error, "cannot record NewRelicBrowserKey region");
    return 0;
}

static int copy_text(const char *text, char **out)
{
    size_t len = strlen(text);
    if (len == SIZE_MAX) return -1;
    char *owned = malloc(len + 1);
    if (!owned) return -1;
    memcpy(owned, text, len + 1);
    *out = owned;
    return 0;
}

static int region_error(const char *region, const char *inner, char **out)
{
    static const char head[] = "error verifying region ";
    static const char mid[] = ": ";
    size_t region_len = strlen(region), inner_len = strlen(inner);
    const size_t fixed = sizeof(head) - 1 + sizeof(mid);
    if (region_len > SIZE_MAX - fixed || inner_len > SIZE_MAX - fixed - region_len) return -1;
    size_t n = sizeof(head) - 1 + region_len + sizeof(mid) - 1 + inner_len;
    char *text = malloc(n + 1);
    if (!text) return -1;
    size_t at = 0;
    memcpy(text + at, head, sizeof(head) - 1);
    at += sizeof(head) - 1;
    memcpy(text + at, region, region_len);
    at += region_len;
    memcpy(text + at, mid, sizeof(mid) - 1);
    at += sizeof(mid) - 1;
    memcpy(text + at, inner, inner_len + 1);
    *out = text;
    return 0;
}

static int join_errors(char *const *parts, size_t n, char **out)
{
    *out = NULL;
    if (!n) return 0;
    size_t total = 0;
    for (size_t i = 0; i < n; ++i) {
        size_t len = strlen(parts[i]);
        if (i && total == SIZE_MAX - 1) return -1;
        if (i) ++total;
        if (len > SIZE_MAX - total - 1) return -1;
        total += len;
    }
    char *joined = malloc(total + 1);
    if (!joined) return -1;
    size_t at = 0;
    for (size_t i = 0; i < n; ++i) {
        if (i) joined[at++] = '\n';
        size_t len = strlen(parts[i]);
        memcpy(joined + at, parts[i], len);
        at += len;
    }
    joined[at] = '\0';
    *out = joined;
    return 0;
}

static void free_parts(char **parts, size_t n)
{
    for (size_t i = 0; i < n; ++i) free(parts[i]);
}

/* 1 verified, 0 continue, -1 fatal. *text is an owned region error, or NULL. */
static int verify_region(const br_scan_ctx *ctx, br_slice key, const char *region,
                         const char *prefix, int32_t type, char **text, char **error)
{
    *text = NULL;
    char url[64];
    size_t prefix_len = strlen(prefix);
    if (key.len != 24 || prefix_len + key.len >= sizeof(url))
        return fail(error, "cannot verify NewRelicBrowserKey key");
    memcpy(url, prefix, prefix_len);
    memcpy(url + prefix_len, key.data, key.len);
    url[prefix_len + key.len] = '\0';
    const br_http_request request = {
        .method = "POST",
        .url = url,
        .profile = BR_HTTP_SANE,
        .timeout_ms = 0,
        .detector_type = type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &send_error);
    int status = response.status;
    int rc = 0;
    char status_text[64];
    char *inner = NULL;
    /* A missing transport cause stays NULL. Do not invent diagnostic text. */
    if (sent != 0) {
        if (send_error) {
            static const char head[] = "error making request: ";
            size_t head_len = sizeof(head) - 1, detail_len = strlen(send_error);
            if (detail_len > SIZE_MAX - head_len - 1 ||
                !(inner = malloc(head_len + detail_len + 1)))
                rc = fail(error, "cannot record NewRelicBrowserKey verification error");
            else {
                memcpy(inner, head, head_len);
                memcpy(inner + head_len, send_error, detail_len + 1);
            }
        }
    } else if (status != 400 && status != 403) {
        /* Source builds this error before the deferred close. */
        int n = snprintf(status_text, sizeof(status_text), "unexpected status code: %d", status);
        if (n < 0 || (size_t)n >= sizeof(status_text))
            rc = fail(error, "cannot format NewRelicBrowserKey verification status");
        else if (copy_text(status_text, &inner) != 0)
            rc = fail(error, "cannot record NewRelicBrowserKey verification error");
    }
    if (rc == 0 && inner && region_error(region, inner, text) != 0)
        rc = fail(error, "cannot record NewRelicBrowserKey verification error");
    /* Release once while the original URL bytes are still alive. */
    br_http_release(ctx, &response);
    free(inner);
    free(send_error);
    if (rc != 0) {
        free(*text);
        *text = NULL;
        return -1; /* Do not try another region, set a verdict, or call the setter. */
    }
    if (sent == 0 && status == 400) return 1;
    return 0;
}

static int verify_key(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    static const char *const regions[] = {"us", "eu"};
    static const char *const prefixes[] = {
        "https://bam.nr-data.net/1/",
        "https://bam.eu01.nr-data.net/1/",
    };
    char *parts[2] = {0};
    size_t nparts = 0;
    const char *verified = NULL;
    int rc = 0;
    /* Constructor failure reaches both regions and does not send or release. */
    if (!ctx) {
        static const char inner[] = "error constructing request: net/http: nil Context";
        for (size_t i = 0; i < 2; ++i) {
            if (region_error(regions[i], inner, &parts[nparts]) != 0) {
                rc = fail(error, "cannot record NewRelicBrowserKey verification error");
                break;
            }
            ++nparts;
        }
    } else {
        for (size_t i = 0; rc == 0 && i < 2 && !verified; ++i) {
            char *text = NULL;
            int verdict = verify_region(ctx, key, regions[i], prefixes[i], result->detector_type,
                                        &text, error);
            if (verdict < 0) rc = -1;
            else if (verdict > 0) verified = regions[i];
            else if (text) parts[nparts++] = text;
        }
    }
    if (rc != 0) {
        free_parts(parts, nparts);
        return rc;
    }
    /* A later verified region discards earlier region errors. */
    if (verified) {
        free_parts(parts, nparts);
        result->verified = true;
        if (record_region(result, verified, error) != 0) return -1;
        return set_cause(result, NULL, error);
    }
    char *joined = NULL;
    if (join_errors(parts, nparts, &joined) != 0) {
        free_parts(parts, nparts);
        return fail(error, "cannot record NewRelicBrowserKey verification error");
    }
    free_parts(parts, nparts);
    rc = set_cause(result, joined, error);
    free(joined);
    return rc;
}

static int scan_browser(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized NewRelicBrowserKey scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* Keyword is an engine hint. Keep every match, including duplicates.
     * Map order is unspecified; this scanner uses US then EU. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            fail(&owned_error, "cannot create NewRelicBrowserKey finding");
            rc = -1;
        } else if (redact(&result, key, &owned_error) != 0) {
            rc = -1;
        } else if (verify && verify_key(ctx, key, &result, &owned_error) != 0) {
            rc = -1;
        } else if (br_results_push(out, &result) != 0) {
            fail(&owned_error, "cannot append NewRelicBrowserKey finding");
            rc = -1;
        }
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const keywords[] = {"nrbr-"};
static br_detector browser = {
    .type = 1065,
    .version = 0,
    .name = "NewRelicBrowserKey",
    .custom_name = "",
    .description = "A New Relic Browser API key is used to authenticate and enable browser monitoring, allowing New Relic to collect performance data, page views, and user interactions from web applications to track and optimize front-end performance.",
    .keywords = keywords,
    .nkeywords = 1,
    .max_secret_size = -1,
    .start_offset = -1,
    .max_credential_span = -1,
    .scan = scan_browser,
};

int br_newrelicbrowserkey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid NewRelicBrowserKey detector output");
    *out = NULL;
    if (!browser.state) {
        br_regex *regex = NULL;
        if (br_regex_compile("\\b(NRBR-[0-9a-f]{19})\\b", &regex, error) != 0)
            return -1;
        browser.state = regex;
    }
    *out = &browser;
    return 0;
}
