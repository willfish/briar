/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/hypertrack/hypertrack.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *account, *key; } hypertrack_patterns;
typedef enum { HYPERTRACK_ABORT = -1, HYPERTRACK_KEEP = 0, HYPERTRACK_DROP = 1 } hypertrack_outcome;

static int hypertrack_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static hypertrack_outcome hypertrack_verify(const br_scan_ctx *ctx, br_slice account,
                                            br_slice key, br_result *result, char **error)
{
    br_http_request request = {
        .method = "GET", .url = "https://v3.api.hypertrack.com/trips/",
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    /* The fixed constructor can reject only a nil context. Basic encoding must
     * follow that drop, but every owned encoder failure is fatal, including +1. */
    if (!ctx) return HYPERTRACK_DROP;
    char *authorization = NULL;
    if (br_http_basic_auth(account, key, &authorization, error) != 0) {
        free(authorization);
        return HYPERTRACK_ABORT;
    }
    const br_header headers[] = {
        {"Authorization", authorization}, {"Content-Type", "application/json"},
    };
    request.headers = headers;
    request.nheaders = sizeof(headers) / sizeof(*headers);
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the whole mixed shared setup/Do error domain, without a setter
     * or diagnostic classifier. Status alone matters; all body errors are ignored. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    /* Provider originals survive release. Ordinary ABI1 synthesized request,
     * headers and UA instead end at send return; do not retain them here. */
    free(transport_error);
    free(authorization);
    return HYPERTRACK_KEEP;
}

static int hypertrack_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return hypertrack_fail(error, "invalid or uninitialized Hypertrack scan");
    const hypertrack_patterns *patterns = detector->state;
    if (!patterns->account || !patterns->key)
        return hypertrack_fail(error, "uninitialized Hypertrack patterns");
    size_t original_len = out->len;
    br_captures accounts = {0}, keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->account, input, &accounts, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    /* Independent account-major occurrence products, including duplicates and
     * overlapping roles. TrimSpace is a no-op; span1024 is only an engine hint. */
    for (size_t a = 0; rc == 0 && a < accounts.len; ++a) {
        for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
            br_slice key = br_captures_at(&keys, k);
            br_result result = {0};
            hypertrack_outcome outcome = HYPERTRACK_KEEP;
            /* Account participates in auth only, never in the result identity. */
            if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
                hypertrack_fail(&owned_error, "cannot create Hypertrack result");
                outcome = HYPERTRACK_ABORT;
            }
            if (outcome == HYPERTRACK_KEEP && verify)
                outcome = hypertrack_verify(ctx, br_captures_at(&accounts, a), key, &result, &owned_error);
            if (outcome == HYPERTRACK_KEEP && br_results_push(out, &result) != 0) {
                hypertrack_fail(&owned_error, "cannot append Hypertrack result");
                outcome = HYPERTRACK_ABORT;
            }
            br_result_clear(&result);
            if (outcome == HYPERTRACK_ABORT) rc = -1;
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&accounts);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static hypertrack_patterns hypertrack_compiled;
static const char *const hypertrack_keywords[] = {"hypertrack"};
static const br_detector hypertrack_detector = {
    .type = 459, .version = 0, .name = "Hypertrack", .custom_name = "",
    .description = "Hypertrack is a service that provides live location tracking for fleets and other mobile workforce management. Hypertrack keys can be used to access and manage these tracking services.",
    .keywords = hypertrack_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &hypertrack_compiled, .scan = hypertrack_scan,
};

int br_hypertrack_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return hypertrack_fail(error, "invalid Hypertrack detector output");
    *out = NULL;
    if (!hypertrack_compiled.account && br_regex_compile_prefixed(hypertrack_keywords, 1,
            "\\b([0-9a-zA-Z\\_\\-]{27})\\b", &hypertrack_compiled.account, error) != 0) return -1;
    if (!hypertrack_compiled.key && br_regex_compile_prefixed(hypertrack_keywords, 1,
            "\\b([0-9a-zA-Z\\_\\-]{54})\\b", &hypertrack_compiled.key, error) != 0) return -1;
    *out = &hypertrack_detector;
    return 0;
}
