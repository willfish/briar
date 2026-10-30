/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/whoxy/whoxy.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { WHOXY_ABORT = -1, WHOXY_KEEP = 0, WHOXY_SKIP = 1 } whoxy_outcome;

static int whoxy_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static whoxy_outcome whoxy_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    char url[sizeof("https://api.whoxy.com/?key=&account=balance") + 33];
    int n = snprintf(url, sizeof(url), "https://api.whoxy.com/?key=%.*s&account=balance",
                     (int)key.len, (const char *)key.data);
    if (n < 0 || (size_t)n >= sizeof(url)) {
        whoxy_fail(error, "cannot format Whoxy URL");
        return WHOXY_ABORT;
    }
    if (!ctx) return WHOXY_SKIP;
    const br_header headers[] = {{"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    whoxy_outcome outcome = WHOXY_KEEP;
    /* ReadAll failure continues past this occurrence. The marker includes the
     * space after the colon. Do errors still publish an unverified finding. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0) {
        if (response.body_error) outcome = WHOXY_SKIP;
        else {
            static const unsigned char marker[] = "\"status\": 1";
            bool ok = br_slice_find(response.body, (br_slice){marker, sizeof(marker) - 1}, 0) != SIZE_MAX;
            result->verified = response.status >= 200 && response.status < 300 && ok;
        }
    }
    br_http_release(ctx, &response);
    free(transport_error);
    return outcome;
}

static int whoxy_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return whoxy_fail(error, "invalid or uninitialized Whoxy scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        whoxy_outcome outcome = WHOXY_KEEP;
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            whoxy_fail(&owned_error, "cannot create Whoxy result");
            outcome = WHOXY_ABORT;
        } else if (verify)
            outcome = whoxy_verify(ctx, key, &result, &owned_error);
        if (outcome == WHOXY_ABORT) rc = -1;
        else if (outcome == WHOXY_KEEP && br_results_push(out, &result) != 0) {
            whoxy_fail(&owned_error, "cannot append Whoxy result");
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

static const char *const whoxy_keywords[] = {"whoxy"};
static br_detector whoxy_detector = {
    .type = 482, .version = 0, .name = "Whoxy", .custom_name = "",
    .description = "Whoxy is a service used to retrieve WHOIS data for domain names. "
                   "Whoxy API keys can be used to query WHOIS information.",
    .keywords = whoxy_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = whoxy_scan,
};

int br_whoxy_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return whoxy_fail(error, "invalid Whoxy detector output");
    *out = NULL;
    if (br_key_pattern_init(&whoxy_detector, "\\b([0-9a-z]{33})\\b", error) != 0) return -1;
    *out = &whoxy_detector;
    return 0;
}
