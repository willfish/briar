/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/cloudelements/cloudelements.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *organization; } cloudelements_patterns;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* False means the source's constructor-failure continue, NOT an unverified
 * result. Every completed Do outcome instead retains the candidate. */
static bool verify_cloudelements(const br_scan_ctx *ctx, const char *key,
                                  const char *organization, br_result *result)
{
    if (!ctx) return false; /* Known constructor failure, BEFORE auth preparation. */
    /* Exactly 5+43+15+32=95 bytes plus NUL. Both captures are bounded ASCII.
     * Borrow this complete value through send/release; no heap duplicate. */
    char authorization[96];
    snprintf(authorization, sizeof(authorization), "User %s, Organization %s", key, organization);
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://staging.cloud-elements.com/elements/api-v2/accounts",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL;
    /* ALL Client.Do errors are suppressed. ABI1 also mixes adapter setup and
     * allocation errors into that domain; do not classify error text. */
    if (!br_http_send(ctx, &request, &response, &transport_error))
        result->verified = response.status >= 200 && response.status < 300;
    /* Body/read errors are ignored. Source scan-defers Close ONLY; ABI1 eager
     * buffering/per-request release and native configuration remain partial. */
    br_http_release(ctx, &response);
    free(transport_error);
    return true;
}

static int scan_cloudelements(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                              br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len)) return fail(error, "invalid CloudElements scan");
    const cloudelements_patterns *compiled = detector->state;
    if (!compiled->key || !compiled->organization) return fail(error, "uninitialized CloudElements patterns");
    br_captures keys = {0}, organizations = {0}; char *owned_error = NULL;
    size_t original_len = out->len;
    int rc = br_captures_find(compiled->key, input, &keys, false, &owned_error);
    if (!rc) rc = br_captures_find(compiled->organization, input, &organizations, false, &owned_error);
    /* Independent OCCURRENCE vectors, key-major/organization-minor. TrimSpace
     * changes neither ASCII alphabet. No uniqueness, entropy or success break. */
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        for (size_t o = 0; !rc && o < organizations.len; ++o) {
            br_result result = {0}; bool keep = true;
            if (br_finding_pair_bytes(&result, detector->type, br_captures_at(&keys, k), "key",
                                      br_captures_at(&organizations, o), "organization", (br_slice){0}))
                rc = fail(&owned_error, "cannot create CloudElements result");
            if (!rc && verify) keep = verify_cloudelements(ctx, keys.items[k], organizations.items[o], &result);
            if (!rc && keep && br_results_push(out, &result)) rc = fail(&owned_error, "cannot append CloudElements result");
            br_result_clear(&result);
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys); br_captures_clear(&organizations);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static cloudelements_patterns patterns;
static const char *const keywords[] = {"cloudelements"};
static const br_detector cloudelements = {
    .type = 650, .version = 0, .name = "CloudElements", .custom_name = "",
    .description = "CloudElements is an API integration platform that enables developers to connect their applications with various cloud services. CloudElements credentials can be used to access and manage these integrations.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_cloudelements,
};

int br_cloudelements_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid CloudElements detector output");
    *out = NULL;
    if (!patterns.key && br_regex_compile_prefixed(keywords, 1, "\\b([a-zA-Z0-9]{43})\\b", &patterns.key, error)) return -1;
    if (!patterns.organization && br_regex_compile_prefixed(keywords, 1, "\\b([a-z0-9]{32})\\b", &patterns.organization, error)) return -1;
    *out = &cloudelements;
    return 0;
}
