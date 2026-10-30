/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/signalwire/signalwire.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { WIRE_KEEP = 0, WIRE_DROP = 1, WIRE_FATAL = -1 };

static int wire_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return WIRE_FATAL;
}

static int wire_verify(const br_scan_ctx *ctx, br_slice key, br_slice id, br_slice host,
                       br_result *result, char **error)
{
    char *authorization = NULL;
    if (br_http_basic_auth(id, key, &authorization, error) != 0) return WIRE_FATAL;
    if (host.len > 160) {
        free(authorization);
        return wire_fail(error, "Signalwire host too large");
    }
    char url[8 + 160 + 31];
    int n = snprintf(url, sizeof(url), "https://%.*s/api/laml/2010-04-01/Accounts",
                     (int)host.len, (const char *)host.data);
    if (n < 0 || (size_t)n >= sizeof(url)) {
        free(authorization);
        return wire_fail(error, "cannot format Signalwire URL");
    }
    /* Basic value and URL exist before the nil-context constructor skip. */
    int outcome = ctx ? WIRE_KEEP : WIRE_DROP;
    if (outcome == WIRE_KEEP) {
        const br_header headers[] = {
            {"Content-Type", "application/json"},
            {"Authorization", authorization},
        };
        const br_http_request request = {
            .method = "GET", .url = url, .headers = headers, .nheaders = 2,
            .profile = BR_HTTP_DETECTOR_PUBLIC, .detector_type = result->detector_type,
        };
        br_http_response response = {0};
        char *send_error = NULL;
        if (br_http_send(ctx, &request, &response, &send_error) == 0)
            result->verified = response.status >= 200 && response.status < 300;
        br_http_release(ctx, &response);
        free(send_error);
    }
    free(authorization);
    return outcome;
}

static int wire_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    br_regex *const *patterns = detector ? detector->state : NULL;
    if (!detector || !patterns || !patterns[0] || !patterns[1] || !patterns[2] || !out ||
        (!input.data && input.len))
        return wire_fail(error, "invalid or uninitialized Signalwire scan");
    size_t original_len = out->len;
    br_captures keys = {0}, ids = {0}, hosts = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns[0], input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns[1], input, &ids, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns[2], input, &hosts, false, &owned_error);
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
            for (size_t h = 0; rc == 0 && h < hosts.len; ++h) {
                br_result result = {0};
                br_slice key = br_captures_at(&keys, k);
                int outcome = WIRE_KEEP;
                if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
                    outcome = wire_fail(&owned_error, "cannot create Signalwire result");
                else if (verify)
                    outcome = wire_verify(ctx, key, br_captures_at(&ids, i),
                                          br_captures_at(&hosts, h), &result, &owned_error);
                if (outcome == WIRE_FATAL) rc = -1;
                if (outcome == WIRE_DROP) {
                    br_result_clear(&result);
                    continue;
                }
                if (rc == 0 && br_results_push(out, &result) != 0)
                    rc = wire_fail(&owned_error, "cannot append Signalwire result");
                br_result_clear(&result);
            }
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&ids);
    br_captures_clear(&hosts);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const wire_keywords[] = {"signalwire"};
static const char *const wire_prefix[] = {"signalwire"};
static br_regex *wire_patterns[3];
static br_detector wire_detector = {
    .type = 611, .version = 0, .name = "Signalwire", .custom_name = "",
    .description = "SignalWire is a communications platform as a service (CPaaS) provider. SignalWire credentials can be used to access and manage communication services such as voice, messaging, and video.",
    .keywords = wire_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = wire_scan,
};

int br_signalwire_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return wire_fail(error, "invalid Signalwire detector output");
    *out = NULL;
    if (!wire_patterns[0] &&
        br_regex_compile_prefixed(wire_prefix, 1, "\\b([0-9A-Za-z]{50})\\b",
                                  &wire_patterns[0], error) != 0)
        return -1;
    if (!wire_patterns[1] &&
        br_regex_compile_prefixed(wire_prefix, 1,
                                  "\\b([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\\b",
                                  &wire_patterns[1], error) != 0)
        return -1;
    if (!wire_patterns[2] &&
        br_regex_compile("\\b([0-9a-z-]{3,64}\\.signalwire\\.com)\\b", &wire_patterns[2], error) != 0)
        return -1;
    wire_detector.state = wire_patterns;
    *out = &wire_detector;
    return 0;
}
