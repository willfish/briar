/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/newrelicpersonalapikey/newrelicpersonalapikey.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int nr_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* Header value is the capture, which must outlive both releases. Timeout 0
 * selects the SANE default. X-Api-Key is already canonical. Transport errors
 * are freed and not classified. Release once even when preparation or Do fails. */
static int nr_send(const br_scan_ctx *ctx, const char *url, const char *key,
                   int32_t type, int *status)
{
    const br_header headers[] = {{"X-Api-Key", key}};
    const br_http_request request = {
        .method = "GET",
        .url = url,
        .headers = headers,
        .nheaders = 1,
        .profile = BR_HTTP_SANE,
        .timeout_ms = 0,
        .detector_type = type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &transport_error);
    free(transport_error);
    *status = response.status;
    br_http_release(ctx, &response);
    return send_rc;
}

/* Always send US then EU. A zero US return decides alone, including when
 * body_error is set; the EU status is ignored but that send is still released.
 * A nonzero US return, including +1, is an ordinary Do failure. A zero EU
 * return then uses the same 200-299 rule. Both failures stay unverified.
 * Source never reads the body and has no setter. */
static int nr_verify(const br_scan_ctx *ctx, const char *key, int32_t type, br_result *result)
{
    int us_status = 0, eu_status = 0;
    int us_rc = nr_send(ctx, "https://api.newrelic.com/v2/users.json", key, type, &us_status);
    int eu_rc = nr_send(ctx, "https://api.eu.newrelic.com/v2/users.json", key, type, &eu_status);
    if (us_rc == 0) {
        if (us_status >= 200 && us_status < 300) result->verified = true;
    } else if (eu_rc == 0) {
        if (eu_status >= 200 && eu_status < 300) result->verified = true;
    }
    return 0;
}

static int nr_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                   br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return nr_fail(error, "invalid or uninitialized NewRelicPersonalApiKey scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* unique=false keeps every match. The upstream duplicate case is prefix
     * consumption, not a uniqueness map. Nil context fails both constructors
     * after finding allocation: drop, no send, no release. NoV does not use it. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        /* TrimSpace is a no-op for this alphabet. Finding failure is fatal
         * before the constructor skip, either send, or publication. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = nr_fail(&owned_error, "cannot create NewRelicPersonalApiKey result");
        else if (!(verify && !ctx)) {
            if (verify) rc = nr_verify(ctx, keys.items[i], detector->type, &result);
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = nr_fail(&owned_error, "cannot append NewRelicPersonalApiKey result");
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

static const char *const nr_keywords[] = {"newrelic"};
static br_detector nr_detector = {
    .type = 50,
    .version = 0,
    .name = "NewRelicPersonalApiKey",
    .custom_name = "",
    .description = "New Relic is a software analytics and performance monitoring company. New Relic Personal API keys can be used to access and manage your New Relic account and data.",
    .keywords = nr_keywords,
    .nkeywords = 1,
    .max_secret_size = -1,
    .start_offset = -1,
    .max_credential_span = -1,
    .scan = nr_scan,
};

int br_newrelicpersonalapikey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return nr_fail(error, "invalid NewRelicPersonalApiKey detector output");
    *out = NULL;
    if (!nr_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(nr_detector.keywords, nr_detector.nkeywords,
                                      "\\b([A-Za-z0-9_\\.]{4}-[A-Za-z0-9_\\.]{42})\\b",
                                      &regex, error) != 0)
            return -1;
        nr_detector.state = regex;
    }
    *out = &nr_detector;
    return 0;
}
