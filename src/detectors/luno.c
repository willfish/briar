/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/luno/luno.go. */
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int luno_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

typedef struct { br_regex *key, *id; } luno_patterns;
typedef struct luno_pending luno_pending;
struct luno_pending {
    luno_pending *next;
    br_http_request request;
    br_http_response response;
    br_header header;
    char *authorization;
};

static void luno_release(const br_scan_ctx *ctx, luno_pending *pending)
{
    while (pending) {
        luno_pending *next = pending->next;
        br_http_release(ctx, &pending->response);
        free(pending->authorization);
        free(pending);
        pending = next;
    }
}

static int luno_verify(const br_scan_ctx *ctx, br_slice key, br_slice id, br_result *result,
                        luno_pending **pending, bool *keep, char **error)
{
    /* The fixed-URL constructor rejects nil context before SetBasicAuth. */
    if (!ctx) { *keep = false; return 0; }
    luno_pending *attempt = malloc(sizeof(*attempt));
    if (!attempt) return luno_fail(error, "cannot construct Luno request");
    *attempt = (luno_pending){0};
    if (br_http_basic_auth(id, key, &attempt->authorization, error) != 0) {
        free(attempt->authorization);
        free(attempt);
        return -1;
    }
    attempt->header = (br_header){"Authorization", attempt->authorization};
    attempt->request = (br_http_request){
        .method = "GET", .url = "https://api.luno.com/api/1/balance",
        .headers = &attempt->header, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    char *send_error = NULL;
    if (br_http_send(ctx, &attempt->request, &attempt->response, &send_error) == 0) {
        result->verified = attempt->response.status >= 200 && attempt->response.status < 300;
        attempt->next = *pending;
        *pending = attempt;
    } else {
        /* Suppress the WHOLE shared preparation/Do domain, never classify its
         * diagnostic text. Module-owned Basic failures are already fatal. */
        luno_release(ctx, attempt);
    }
    free(send_error);
    return 0;
}

static int luno_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return luno_fail(error, "invalid or uninitialized Luno scan");
    const luno_patterns *patterns = detector->state;
    size_t original_len = out->len;
    br_captures keys = {0}, ids = {0};
    luno_pending *pending = NULL;
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    /* Independently scan IDs even without keys; 1024 is only an engine hint. */
    if (rc == 0) rc = br_captures_find(patterns->id, input, &ids, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        for (size_t j = 0; rc == 0 && j < ids.len; ++j) {
            br_slice id = br_captures_at(&ids, j);
            br_result result = {0};
            bool keep = true;
            /* IDs are required for the full duplicate Cartesian product even
             * in NoV, but source findings deliberately emit only the key. */
            if (key.len != 43 || id.len != 13 || br_finding_key_bytes(&result, detector->type, key, "key") != 0)
                rc = luno_fail(&owned_error, "cannot create Luno result");
            if (rc == 0 && verify) rc = luno_verify(ctx, key, id, &result, &pending, &keep, &owned_error);
            if (rc == 0 && keep && br_results_push(out, &result) != 0)
                rc = luno_fail(&owned_error, "cannot append Luno result");
            br_result_clear(&result);
        }
    }
    /* Successful responses close scan-deferred, LIFO after publication. Keep
     * original auth/ID/key/request storage through release, not synthesized
     * prepared header-array/UA values. Bodies/read errors are ignored. */
    luno_release(ctx, pending);
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&ids);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const luno_keywords[] = {"luno"};
static luno_patterns luno_compiled;
static br_detector luno_detector = {
    .type = 655, .version = 0, .name = "Luno", .custom_name = "",
    .description = "Luno is a cryptocurrency exchange platform that allows users to buy, sell, and store digital currencies. Luno API keys can be used to access account information and perform transactions.",
    .keywords = luno_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = luno_scan,
};

int br_luno_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return luno_fail(error, "invalid Luno detector output");
    *out = NULL;
    if (!luno_detector.state) {
        luno_patterns patterns = {0};
        if (br_regex_compile_prefixed(luno_keywords, 1, "\\b([a-zA-Z0-9_-]{43})\\b", &patterns.key, error) != 0)
            return -1;
        if (br_regex_compile_prefixed(luno_keywords, 1, "\\b([a-z0-9]{13})\\b", &patterns.id, error) != 0) {
            br_regex_free(patterns.key);
            return -1;
        }
        luno_compiled = patterns;
        luno_detector.state = &luno_compiled;
    }
    *out = &luno_detector;
    return 0;
}
