/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/flowflu/flowflu.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *account; } flowflu_patterns;

static int flowflu_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* False is the constructor/read-error continue (DROP). A shared send error
 * instead suppresses the whole mixed cause domain and KEEPS a false finding. */
static bool flowflu_verify(const br_scan_ctx *ctx, br_slice key, br_slice account, br_result *result)
{
    static const char suffix[] = ".flowlu.com/api/v1/module/crm/lead/list?api_key=";
    char url[138];
    _Static_assert(8 + 30 + sizeof(suffix) - 1 + 51 + 1 == sizeof(url), "FlowFlu URL: max 137 bytes plus NUL");
    _Static_assert(8 + 4 + sizeof(suffix) - 1 + 51 == 111, "FlowFlu URL: min 111 bytes");
    /* Finding and COMPLETE original-case URL precede constructor. flowflu is
     * the source dispatch/prefix typo, but flowlu.com is its actual URL domain.
     * Exact capture bounds: no DNS normalization, formatter/encoder, heap copy,
     * extra cap or artificial allocation/failure seam. */
    size_t at = 8; memcpy(url, "https://", at);
    memcpy(url + at, account.data, account.len); at += account.len;
    memcpy(url + at, suffix, sizeof(suffix) - 1); at += sizeof(suffix) - 1;
    memcpy(url + at, key.data, key.len); at += key.len; url[at] = '\0';
    if (!ctx) return false;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
        /* Common UA ONLY. No invented provider headers or PUBLIC profile. */
    };
    br_http_response response = {0}; char *transport_error = NULL; bool keep = true;
    if (br_http_send(ctx, &request, &response, &transport_error) == 0) {
        /* ReadAll is BEFORE EVERY status. ANY non-NULL reader cause, including
         * an empty string, DROPS the pair, even if status/marker otherwise win. */
        if (response.body_error != NULL) keep = false;
        else {
            const br_slice marker = {(const unsigned char *)"total_result", sizeof("total_result") - 1};
            result->verified = response.status >= 200 && response.status < 300 &&
                               br_slice_find(response.body, marker, 0) != SIZE_MAX;
        }
    } /* Failed Do: false KEPT, even with populated body_error; no setter/classifier. */
    /* Binary substring only, not JSON/count/case/whitespace/UTF-8 normalization;
     * embedded NUL never terminates the search. Stack URL survives send AND
     * release. Source defers Close only AFTER successful ReadAll (no Close on
     * its read-error continue). ABI-owned always-release, eager Reader, native/
     * private-client/error-chain/regexp and global engine/output parity remain
     * partial. Native HTTP guards are unchanged. */
    br_http_release(ctx, &response);
    free(transport_error);
    return keep;
}

static int flowflu_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return flowflu_fail(error, "invalid or uninitialized FlowFlu scan");
    const flowflu_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->account) return flowflu_fail(error, "uninitialized FlowFlu patterns");
    size_t original_len = out->len;
    br_captures keys = {0}, accounts = {0}; char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (!rc) rc = br_captures_find(patterns->account, input, &accounts, false, &owned_error);
    /* Key-major original OCCURRENCE products, including duplicates. Required
     * account is HIDDEN even when verified. TrimSpace is a no-op; no unique set,
     * success break, equality skip or local span cap (1024 is an ENGINE HINT). */
    for (size_t k = 0; !rc && k < keys.len; ++k) for (size_t a = 0; !rc && a < accounts.len; ++a) {
        br_result result = {0}; bool keep = true;
        br_slice key = br_captures_at(&keys, k), account = br_captures_at(&accounts, a);
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = flowflu_fail(&owned_error, "cannot create FlowFlu finding");
        /* Owned nonzero failures remain fatal BEFORE skip/DROP/suppression. */
        if (!rc && verify) keep = flowflu_verify(ctx, key, account, &result);
        if (!rc && keep && br_results_push(out, &result) != 0)
            rc = flowflu_fail(&owned_error, "cannot append FlowFlu finding");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys); br_captures_clear(&accounts);
    if (error) *error = owned_error; else free(owned_error);
    return rc ? -1 : 0;
}

static flowflu_patterns flowflu_compiled;
static const char *const flowflu_keywords[] = {"flowflu"};
static const char *const flowflu_account_prefix[] = {"flowflu", "account"};
static const br_detector flowflu_detector = {
    .type = 265, .version = 0, .name = "FlowFlu", .custom_name = "",
    .description = "FlowFlu is a service used for managing customer relationships and projects. FlowFlu API keys can be used to access and manipulate CRM data.",
    .keywords = flowflu_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &flowflu_compiled, .scan = flowflu_scan,
};

int br_flowflu_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return flowflu_fail(error, "invalid FlowFlu detector output");
    *out = NULL;
    if (!flowflu_compiled.key) {
        br_regex *key = NULL, *account = NULL;
        int rc = br_regex_compile_prefixed(flowflu_keywords, 1, "\\b([a-zA-Z0-9]{51})\\b", &key, error);
        if (!rc) rc = br_regex_compile_prefixed(flowflu_account_prefix, 2, "\\b([a-zA-Z0-9]{4,30})\\b", &account, error);
        if (rc) { br_regex_free(key); br_regex_free(account); return -1; }
        flowflu_compiled = (flowflu_patterns){key, account};
    }
    *out = &flowflu_detector;
    return 0;
}
