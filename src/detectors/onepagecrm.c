/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/onepagecrm/onepagecrm.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } onepagecrm_patterns;
typedef struct onepagecrm_attempt {
    br_http_request request;
    br_http_response response;
    br_header header;
    struct onepagecrm_attempt *previous;
    char *authorization;
} onepagecrm_attempt;

static int onepagecrm_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static void onepagecrm_release(const br_scan_ctx *ctx, onepagecrm_attempt *attempt)
{
    br_http_release(ctx, &attempt->response);
    free(attempt->authorization);
    free(attempt);
}

static int onepagecrm_verify(const br_scan_ctx *ctx, br_slice key, br_slice id, br_result *result,
                             onepagecrm_attempt **pending, bool *keep, char **error)
{
    static const char url[] =
        "https://app.onepagecrm.com/api/v3/contacts.json?per_page=20&page=1";
    *keep = false;
    /* Fixed-URL constructor rejects nil before SetBasicAuth. */
    if (!ctx) return 0;
    onepagecrm_attempt *attempt = malloc(sizeof(*attempt));
    if (!attempt) return onepagecrm_fail(error, "cannot construct OnepageCRM request");
    *attempt = (onepagecrm_attempt){0};
    /* SetBasicAuth(user, token): the username is the captured ID. */
    if (br_http_basic_auth(id, key, &attempt->authorization, error) != 0) {
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
    /* Source suppresses the whole mixed preparation/Do domain, reads no body
     * and never calls a setter. */
    if (br_http_send(ctx, &attempt->request, &attempt->response, &send_error) == 0) {
        result->verified = attempt->response.status >= 200 && attempt->response.status < 300;
        attempt->previous = *pending;
        *pending = attempt;
    } else onepagecrm_release(ctx, attempt);
    free(send_error);
    *keep = true;
    return 0;
}

static int onepagecrm_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return onepagecrm_fail(error, "invalid or uninitialized OnepageCRM scan");
    const onepagecrm_patterns *patterns = detector->state;
    size_t original_len = out->len;
    br_captures keys = {0}, ids = {0};
    onepagecrm_attempt *pending = NULL;
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    /* The independent ID scan runs even without keys; 1024 is an engine hint. */
    if (rc == 0) rc = br_captures_find(patterns->id, input, &ids, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        for (size_t j = 0; rc == 0 && j < ids.len; ++j) {
            br_slice id = br_captures_at(&ids, j);
            br_result result = {0};
            bool keep = true;
            /* TrimSpace is a no-op for both ASCII grammars. The ID is hidden. */
            if (key.len != 44 || id.len != 24 ||
                br_finding_key_bytes(&result, detector->type, key, "key") != 0)
                rc = onepagecrm_fail(&owned_error, "cannot create OnepageCRM result");
            if (rc == 0 && verify) rc = onepagecrm_verify(ctx, key, id, &result, &pending, &keep, &owned_error);
            if (rc == 0 && keep && br_results_push(out, &result) != 0)
                rc = onepagecrm_fail(&owned_error, "cannot append OnepageCRM result");
            br_result_clear(&result);
        }
    }
    /* Successful responses close LIFO after publication; failed attempts
     * already released once with the original authorization. */
    while (pending) {
        onepagecrm_attempt *previous = pending->previous;
        onepagecrm_release(ctx, pending);
        pending = previous;
    }
    br_captures_clear(&ids);
    br_captures_clear(&keys);
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const onepagecrm_keywords[] = {"onepagecrm"};
static onepagecrm_patterns onepagecrm_compiled;
static br_detector onepagecrm_detector = {
    .type = 273, .version = 0, .name = "OnepageCRM", .custom_name = "",
    .description = "OnepageCRM is a simple CRM system designed for small businesses. The API keys can be used to access and manage contacts, deals, and other CRM data.",
    .keywords = onepagecrm_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &onepagecrm_compiled, .scan = onepagecrm_scan,
};

int br_onepagecrm_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return onepagecrm_fail(error, "invalid OnepageCRM detector output");
    *out = NULL;
    if (!onepagecrm_compiled.key &&
        br_regex_compile_prefixed(onepagecrm_keywords, 1, "\\b([a-zA-Z0-9=]{44})",
                                  &onepagecrm_compiled.key, error) != 0)
        return -1;
    if (!onepagecrm_compiled.id &&
        br_regex_compile_prefixed(onepagecrm_keywords, 1, "\\b([a-z0-9]{24})\\b",
                                  &onepagecrm_compiled.id, error) != 0) {
        br_regex_free(onepagecrm_compiled.key);
        onepagecrm_compiled.key = NULL;
        return -1;
    }
    *out = &onepagecrm_detector;
    return 0;
}
