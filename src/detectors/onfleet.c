/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/onfleet/onfleet.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct onfleet_attempt {
    br_http_request request;
    br_http_response response;
    br_header header;
    struct onfleet_attempt *previous;
    char *authorization;
} onfleet_attempt;

static int onfleet_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static void onfleet_release(const br_scan_ctx *ctx, onfleet_attempt *attempt)
{
    br_http_release(ctx, &attempt->response);
    free(attempt->authorization);
    free(attempt);
}

/* Always invoke the checked setter, including a NULL cause. Source redacts the
 * token but publishes no extra metadata. */
static int onfleet_commit(br_result *result, const char *cause, br_slice key, char **error)
{
    if (br_result_set_verification_error(result, cause, &key, 1) != 0)
        return onfleet_fail(error, "cannot store Onfleet verification error");
    return 0;
}

static int onfleet_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                          onfleet_attempt **pending, char **error)
{
    static const char url[] = "https://onfleet.com/api/v2/organization";
    result->verified = false;
    if (!ctx) {
        /* Constructor failure is an ordinary cause, not a drop. */
        return onfleet_commit(result, "net/http: nil Context", key, error);
    }
    onfleet_attempt *attempt = malloc(sizeof(*attempt));
    if (!attempt) return onfleet_fail(error, "cannot construct Onfleet request");
    *attempt = (onfleet_attempt){0};
    if (br_http_basic_auth(key, (br_slice){0}, &attempt->authorization, error) != 0) {
        free(attempt->authorization);
        free(attempt);
        return -1;
    }
    attempt->header = (br_header){"Authorization", attempt->authorization};
    attempt->request = (br_http_request){
        .method = "GET", .url = url, .headers = &attempt->header, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    char *send_error = NULL;
    char status_error[64];
    const char *cause = NULL;
    int rc = 0;
    if (br_http_send(ctx, &attempt->request, &attempt->response, &send_error) != 0) {
        /* The whole mixed preparation/Do domain is an ordinary cause. */
        cause = send_error;
        onfleet_release(ctx, attempt);
        attempt = NULL;
    } else {
        attempt->previous = *pending;
        *pending = attempt;
        if (attempt->response.status >= 200 && attempt->response.status < 300)
            result->verified = true;
        else if (attempt->response.status != 401) {
            int n = snprintf(status_error, sizeof(status_error),
                             "unexpected HTTP response status %d", attempt->response.status);
            if (n < 0 || (size_t)n >= sizeof(status_error))
                rc = onfleet_fail(error, "cannot format Onfleet status cause");
            else cause = status_error;
        }
    }
    if (rc == 0) rc = onfleet_commit(result, cause, key, error);
    free(send_error);
    return rc;
}

static int onfleet_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return onfleet_fail(error, "invalid or uninitialized Onfleet scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    onfleet_attempt *pending = NULL;
    char *owned_error = NULL;
    /* Source de-duplicates through a map before findings; first-seen order is
     * the native projection of that unordered set. */
    int rc = br_captures_find(detector->state, input, &keys, true, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 32 || br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = onfleet_fail(&owned_error, "cannot create Onfleet result");
        if (rc == 0 && verify)
            rc = onfleet_verify(ctx, key, &result, &pending, &owned_error);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = onfleet_fail(&owned_error, "cannot append Onfleet result");
        br_result_clear(&result);
    }
    /* Successful responses close LIFO after setter and publication; failed
     * attempts already released once. */
    while (pending) {
        onfleet_attempt *previous = pending->previous;
        onfleet_release(ctx, pending);
        pending = previous;
    }
    br_captures_clear(&keys);
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const onfleet_keywords[] = {"onfleet"};
static br_detector onfleet_detector = {
    .type = 986, .version = 0, .name = "Onfleet", .custom_name = "",
    .description = "Onfleet is a delivery management software that allows businesses to manage and analyze their delivery operations. Onfleet API keys can be used to access and manage the delivery data and operations.",
    .keywords = onfleet_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = onfleet_scan,
};

int br_onfleet_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return onfleet_fail(error, "invalid Onfleet detector output");
    *out = NULL;
    if (br_key_pattern_init(&onfleet_detector, "\\b([a-z0-9]{32})\\b", error) != 0) return -1;
    *out = &onfleet_detector;
    return 0;
}
