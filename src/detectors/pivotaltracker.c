/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/pivotaltracker/pivotaltracker.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

typedef struct pivotal_attempt {
    br_http_request request;
    br_http_response response;
    br_header headers[2];
} pivotal_attempt;

static int pivotal_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static pivotal_attempt *pivotal_request(const char *token)
{
    pivotal_attempt *attempt = malloc(sizeof(*attempt));
    if (!attempt) return NULL;
    *attempt = (pivotal_attempt){0};
    /* Header.Add canonicalizes source X-TrackerToken; the internal capital falls. */
    attempt->headers[0] = (br_header){"Content-Type", "application/json; charset=utf-8"};
    attempt->headers[1] = (br_header){"X-Trackertoken", token};
    attempt->request = (br_http_request){
        .method = "GET", .url = "https://www.pivotaltracker.com/services/v5/me",
        .headers = attempt->headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .detector_type = 23,
    };
    return attempt;
}

static void pivotal_release(const br_scan_ctx *ctx, pivotal_attempt *attempt)
{
    /* One immediate close. The provider frame remains readable through it. */
    br_http_release(ctx, &attempt->response);
    free(attempt);
}

static int pivotal_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return pivotal_fail(error, "invalid or uninitialized PivotalTracker scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = pivotal_fail(error, "cannot create PivotalTracker result");
        if (rc == 0 && verify && !ctx) {
            /* Checked finding first. Nil drops before request allocation and
             * does not publish net/http: nil Context. */
            br_result_clear(&result);
            continue;
        }
        if (rc == 0 && verify) {
            pivotal_attempt *attempt = pivotal_request(keys.items[i]);
            if (!attempt) rc = pivotal_fail(error, "cannot create PivotalTracker request");
            else {
                char *transport_error = NULL;
                /* Suppress the whole mixed preparation/Do domain. No setter. */
                int sent = br_http_send(ctx, &attempt->request, &attempt->response, &transport_error);
                int status = attempt->response.status;
                /* Successful and failed attempts close once, immediately, before
                 * the status decision and before publication. Not scan-wide LIFO.
                 * Release clears the response, so the decision uses the snapshot. */
                pivotal_release(ctx, attempt);
                free(transport_error);
                if (sent == 0) result.verified = status >= 200 && status < 300;
            }
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = pivotal_fail(error, "cannot append PivotalTracker result");
        br_result_clear(&result);
    }
    br_captures_clear(&keys);
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    return rc == 0 ? 0 : -1;
}

static const char *const pivotal_keywords[] = {"pivotal"};
static br_detector pivotal_detector = {
    .type = 23, .version = 0, .name = "PivotalTracker", .custom_name = "",
    .description = "PivotalTracker is a project management tool. PivotalTracker tokens can be used to access and manage projects and data within PivotalTracker.",
    .keywords = pivotal_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = pivotal_scan,
};

int br_pivotaltracker_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return pivotal_fail(error, "invalid PivotalTracker detector output");
    *out = NULL;
    /* No word boundaries and no endpoint tightening. Prefix folding is keyword-only. */
    if (br_key_pattern_init(&pivotal_detector, "([a-z0-9]{32})", error) != 0) return -1;
    *out = &pivotal_detector;
    return 0;
}
