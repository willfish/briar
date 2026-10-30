/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/mixpanel/mixpanel.go. */
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int mixpanel_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

typedef struct { br_regex *key, *id; } mixpanel_patterns;
typedef struct mixpanel_pending mixpanel_pending;
struct mixpanel_pending {
    mixpanel_pending *next;
    br_http_request request;
    br_http_response response;
    br_header header;
    char *authorization;
};

static void mixpanel_release(const br_scan_ctx *ctx, mixpanel_pending *pending)
{
    while (pending) {
        mixpanel_pending *next = pending->next;
        br_http_release(ctx, &pending->response);
        free(pending->authorization);
        free(pending);
        pending = next;
    }
}

static int mixpanel_verify(const br_scan_ctx *ctx, br_slice key, br_slice id, br_result *result,
                            mixpanel_pending **pending, bool *keep, char **error)
{
    /* Fixed-URL constructor failure precedes all Basic/header allocation. */
    if (!ctx) { *keep = false; return 0; }
    mixpanel_pending *attempt = malloc(sizeof(*attempt));
    if (!attempt) return mixpanel_fail(error, "cannot construct Mixpanel request");
    *attempt = (mixpanel_pending){0};
    if (br_http_basic_auth(id, key, &attempt->authorization, error) != 0) {
        free(attempt->authorization);
        free(attempt);
        return -1;
    }
    attempt->header = (br_header){"Authorization", attempt->authorization};
    attempt->request = (br_http_request){
        .method = "GET", .url = "https://mixpanel.com/api/app/me",
        .headers = &attempt->header, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    char *send_error = NULL;
    if (br_http_send(ctx, &attempt->request, &attempt->response, &send_error) == 0) {
        result->verified = attempt->response.status >= 200 && attempt->response.status < 300;
        attempt->next = *pending;
        *pending = attempt;
    } else {
        /* Suppress the WHOLE shared preparation/Do domain, with no setter or
         * diagnostic classifier. Reached module-owned auth failures stay fatal. */
        mixpanel_release(ctx, attempt);
    }
    free(send_error);
    return 0;
}

static int mixpanel_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return mixpanel_fail(error, "invalid or uninitialized Mixpanel scan");
    const mixpanel_patterns *patterns = detector->state;
    size_t original_len = out->len;
    br_captures keys = {0}, ids = {0};
    mixpanel_pending *pending = NULL;
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    /* Independent full-match lists include overlaps/self-pairs. Always scan IDs
     * even without keys; inherited span 1024 is not a direct product limit. */
    if (rc == 0) rc = br_captures_find(patterns->id, input, &ids, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        for (size_t j = 0; rc == 0 && j < ids.len; ++j) {
            br_slice id = br_captures_at(&ids, j);
            br_result result = {0};
            bool keep = true;
            /* ID participates in Basic and NoV cardinality, not emitted fields. */
            if (key.len != 32 || id.len < 30 || id.len > 40 ||
                br_finding_key_bytes(&result, detector->type, key, "key") != 0)
                rc = mixpanel_fail(&owned_error, "cannot create Mixpanel result");
            if (rc == 0 && verify) rc = mixpanel_verify(ctx, key, id, &result, &pending, &keep, &owned_error);
            if (rc == 0 && keep && br_results_push(out, &result) != 0)
                rc = mixpanel_fail(&owned_error, "cannot append Mixpanel result");
            br_result_clear(&result);
        }
    }
    /* Successful closes are scan-wide LIFO after publication, not per key.
     * Keep original Basic/header/ID/key storage alive through release, without
     * extending ordinary synthesized preparation. Ignore bodies/read errors. */
    mixpanel_release(ctx, pending);
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&ids);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const mixpanel_keywords[] = {"mixpanel"};
static mixpanel_patterns mixpanel_compiled;
static br_detector mixpanel_detector = {
    .type = 371, .version = 0, .name = "Mixpanel", .custom_name = "",
    .description = "Mixpanel is an analytics service that tracks user interactions with web and mobile applications. Mixpanel keys can be used to access and analyze user data.",
    .keywords = mixpanel_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = mixpanel_scan,
};

int br_mixpanel_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return mixpanel_fail(error, "invalid Mixpanel detector output");
    *out = NULL;
    if (!mixpanel_detector.state) {
        mixpanel_patterns patterns = {0};
        if (br_regex_compile_prefixed(mixpanel_keywords, 1, "\\b([a-zA-Z0-9-]{32})\\b", &patterns.key, error) != 0)
            return -1;
        if (br_regex_compile_prefixed(mixpanel_keywords, 1, "\\b([a-zA-Z0-9.-]{30,40})\\b", &patterns.id, error) != 0) {
            br_regex_free(patterns.key);
            return -1;
        }
        mixpanel_compiled = patterns;
        mixpanel_detector.state = &mixpanel_compiled;
    }
    *out = &mixpanel_detector;
    return 0;
}
