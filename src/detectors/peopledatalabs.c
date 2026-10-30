/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/peopledatalabs/peopledatalabs.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int pdl_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* Successful Do closes are scan-deferred. A stack key cannot survive that
 * release, so the original header allocation stays with the response. The
 * stack header array is not retained. */
typedef struct pdl_pending pdl_pending;
struct pdl_pending {
    pdl_pending *next;
    br_http_response response;
    char *key;
};

static int pdl_retain(pdl_pending **pending, const br_http_response *response, char *key)
{
    pdl_pending *item = malloc(sizeof(*item));
    if (!item) return -1;
    item->next = *pending;
    item->response = *response;
    item->key = key;
    *pending = item;
    return 0;
}

static void pdl_release_held(const br_scan_ctx *ctx, pdl_pending *pending)
{
    while (pending) {
        pdl_pending *next = pending->next;
        br_http_release(ctx, &pending->response);
        free(pending->key);
        free(pending);
        pending = next;
    }
}

/* Finding already exists. Nil context drops before the header allocation.
 * 1 drops this occurrence. 0 publishes it. -1 is fatal. There is no setter. */
static int pdl_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                      pdl_pending **pending, char **error)
{
    if (!ctx) return 1;
    char *owned = malloc(key.len + 1);
    if (!owned) return pdl_fail(error, "cannot allocate PeopleDataLabs key");
    memcpy(owned, key.data, key.len);
    owned[key.len] = '\0';
    const br_header headers[] = {{"X-Api-Key", owned}};
    const br_http_request request = {
        .method = "GET",
        .url = "https://api.peopledatalabs.com/v5/person/enrich?min_likelihood=6&profile=https://linkedin.com/in/williamhgates",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &send_error);
    free(send_error);
    if (send_rc != 0) {
        br_http_release(ctx, &response);
        free(owned);
        return 0;
    }
    if (pdl_retain(pending, &response, owned) != 0) {
        br_http_release(ctx, &response);
        free(owned);
        return pdl_fail(error, "cannot retain PeopleDataLabs response for release");
    }
    /* Source never reads the body. A reached non-2xx is explicitly unverified. */
    if (response.status >= 200 && response.status < 300)
        result->verified = true;
    else
        result->verified = false;
    return 0;
}

static int pdl_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                    br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return pdl_fail(error, "invalid or uninitialized PeopleDataLabs scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    pdl_pending *pending = NULL;
    char *owned_error = NULL;
    /* Keep every duplicate. The class and boundaries make TrimSpace a no-op.
     * Finding resources precede the nil-context drop and any header allocation. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        bool keep = true;
        if (key.len != 64)
            rc = pdl_fail(&owned_error, "invalid PeopleDataLabs capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = pdl_fail(&owned_error, "cannot create PeopleDataLabs result");
        else if (verify) {
            int verdict = pdl_verify(ctx, key, &result, &pending, &owned_error);
            if (verdict < 0) rc = -1;
            else keep = verdict == 0;
        }
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = pdl_fail(&owned_error, "cannot append PeopleDataLabs result");
        br_result_clear(&result);
    }
    /* Successful responses close after publication, last success first. Fatal
     * paths drain the same list once, then roll back only this invocation. */
    pdl_release_held(ctx, pending);
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const pdl_keywords[] = {"peopledatalabs"};
/* Source suffix. Do not hand-expand the prefix and do not rewrite the class. */
static const char pdl_capture[] = "\\b([a-z0-9]{64})\\b";
static br_detector pdl_detector = {
    .type = 658, .version = 0, .name = "PeopleDataLabs", .custom_name = "",
    .description = "PeopleDataLabs provides access to person and company data through their API. The API keys can be used to enrich profiles with additional data.",
    .keywords = pdl_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = pdl_scan,
};

int br_peopledatalabs_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return pdl_fail(error, "invalid PeopleDataLabs detector output");
    *out = NULL;
    if (!pdl_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(pdl_keywords, 1, pdl_capture, &regex, error) != 0)
            return -1;
        pdl_detector.state = regex;
    }
    *out = &pdl_detector;
    return 0;
}
