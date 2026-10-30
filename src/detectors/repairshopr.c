/* SPDX-License-Identifier: AGPL-3.0-only */
/*
 * Repairshopr, from pinned TruffleHog pkg/detectors/repairshopr/repairshopr.go.
 * Every API key is paired with every subdomain. Only the key is stored.
 * Verification uses the public-address client and drops a nil context after
 * the URL is built.
 */
#include "captures.h"
#include "detectors.h"
#include "findings.h"
#include "../go_url.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *const prefix[] = {"repairshopr", NULL};
static br_regex *key_re, *domain_re;

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int verify(const br_scan_ctx *ctx, const char *domain, const char *key, br_result *result, char **error)
{
    char url[96];
    int n = snprintf(url, sizeof(url), "https://%s.repairshopr.com/api/v1/appointment_types", domain);
    if (n < 0 || (size_t)n >= sizeof(url)) return fail(error, "cannot format Repairshopr URL");
    if (!ctx) return 1;
    br_go_url_parts parts = {0};
    br_go_url_error rejection = {0};
    char *parse_error = NULL;
    int parsed = br_go_url_parse((br_slice){(const unsigned char *)url, (size_t)n}, &parts, &rejection, &parse_error);
    br_go_url_clear(&parts);
    if (parsed != 0) {
        if (error && !*error) *error = parse_error;
        else free(parse_error);
        return -1;
    }
    if (rejection.kind != BR_GO_URL_OK) return 1;
    char bearer[64];
    n = snprintf(bearer, sizeof(bearer), "Bearer %s", key);
    if (n < 0 || (size_t)n >= sizeof(bearer)) return fail(error, "cannot format Repairshopr authorization");
    const br_header headers[] = {
        {"Accept", "application/vnd.sugester+json; version=3"},
        {"Authorization", bearer},
    };
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 2,
        .timeout_ms = 10000, .detector_type = 702, .profile = BR_HTTP_DETECTOR_PUBLIC,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int rc = br_http_send(ctx, &request, &response, &transport_error);
    if (!rc && response.status >= 200 && response.status < 300) result->verified = true;
    br_http_release(ctx, &response);
    free(transport_error);
    return 0;
}

static int scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify_requested,
                br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !key_re || !domain_re || !out || (!input.data && input.len))
        return fail(error, "invalid Repairshopr scan arguments");
    size_t original = out->len;
    br_captures keys = {0}, domains = {0};
    char *owned = NULL;
    int rc = 0;
    if (br_captures_find(key_re, input, &keys, false, &owned) ||
        br_captures_find(domain_re, input, &domains, false, &owned))
        rc = -1;
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        for (size_t d = 0; !rc && d < domains.len; ++d) {
            br_result result = {0};
            int outcome = 0;
            if (br_finding_key(&result, detector->type, keys.items[k], "key") != 0)
                rc = fail(&owned, "cannot create Repairshopr finding");
            else if (verify_requested &&
                     (outcome = verify(ctx, domains.items[d], keys.items[k], &result, &owned)) < 0)
                rc = -1;
            else if (!outcome && br_results_push(out, &result) != 0)
                rc = fail(&owned, "cannot append Repairshopr finding");
            br_result_clear(&result);
        }
    }
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&domains);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static br_detector detector = {
    .name = "Repairshopr", .type = 702, .description =
        "RepairShopr is a CRM and ticketing system designed for repair shops. The API keys allow access to various functionalities such as managing appointments, customers, and invoices.",
    .keywords = (const char *[]){"repairshopr", NULL}, .nkeywords = 1, .scan = scan,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .custom_name = "",
};

int br_repairshopr_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Repairshopr detector output");
    *out = NULL;
    if ((!key_re && br_regex_compile_prefixed(prefix, 1, "\\b([a-zA-Z0-9-]{51})\\b", &key_re, error) != 0) ||
        (!domain_re && br_regex_compile_prefixed(prefix, 1, "\\b([a-zA-Z0-9_.!+$#^*]{3,32})\\b", &domain_re, error) != 0))
        return -1;
    detector.state = key_re;
    *out = &detector;
    return 0;
}
