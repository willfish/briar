/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/salesmate/salesmate.go.
 * The domain is a verification input only; Raw and SecretParts store the key. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static br_regex *key_re, *domain_re;

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int verify_salesmate(const br_scan_ctx *ctx, const char *key, const char *domain,
                            br_result *result, char **error)
{
    char url[128];
    int n = snprintf(url, sizeof(url),
                     "https://%s.salesmate.io/apis/v3/companies/1?trackingRecentSearch=true", domain);
    if (n < 0 || (size_t)n >= sizeof(url)) return fail(error, "cannot format Salesmate URL");
    if (!ctx) return 1;
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"sessionToken", key},
    };
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_DETECTOR_PUBLIC, .timeout_ms = 10000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    if (!br_http_send(ctx, &request, &response, &transport_error) &&
        response.status >= 200 && response.status < 300)
        result->verified = true;
    br_http_release(ctx, &response);
    free(transport_error);
    return 0;
}

static int scan_salesmate(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !key_re || !domain_re || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Salesmate scan");
    size_t original_len = out->len;
    br_captures keys = {0}, domains = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(key_re, input, &keys, false, &owned_error);
    if (!rc) rc = br_captures_find(domain_re, input, &domains, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        for (size_t j = 0; !rc && j < domains.len; ++j) {
            br_result result = {0};
            int outcome = 0;
            if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0) {
                fail(&owned_error, "cannot create Salesmate result");
                outcome = -1;
            } else if (verify)
                outcome = verify_salesmate(ctx, keys.items[i], domains.items[j], &result, &owned_error);
            if (outcome == 0 && br_results_push(out, &result) != 0) {
                fail(&owned_error, "cannot append Salesmate result");
                outcome = -1;
            }
            br_result_clear(&result);
            if (outcome < 0) rc = -1;
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&domains);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"salesmate"};
static br_detector salesmate = {
    .type = 868, .version = 0, .name = "Salesmate", .custom_name = "",
    .description = "Salesmate is a customer relationship management (CRM) software. Salesmate keys can be used to access and manage customer data and interactions.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = scan_salesmate,
};

int br_salesmate_init(const br_detector **out, char **error)
{
    static const char *const prefix[] = {"salesmate"};
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Salesmate detector output");
    *out = NULL;
    if (!key_re && br_regex_compile_prefixed(prefix, 1,
            "\\b([0-9Aa-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b", &key_re, error) != 0)
        return -1;
    if (!domain_re && br_regex_compile_prefixed(prefix, 1, "\\b([a-z0-9A-Z]{3,22})\\b", &domain_re, error) != 0)
        return -1;
    salesmate.state = key_re;
    *out = &salesmate;
    return 0;
}
