/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/zenrows/zenrows.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_zenrows(const br_scan_ctx *ctx, const char *url, br_slice key, br_result *result)
{
    char status_error[48];
    const char *cause = NULL;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .detector_type = 824,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    if (!ctx) cause = "net/http: nil Context";
    else if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error;
    else if (response.status == 200) result->verified = true;
    else if (response.status != 401 && response.status != 402) {
        snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
        cause = status_error;
    }
    /* io.Copy drain errors are ignored; status remains decisive. */
    int rc = br_result_set_verification_error(result, cause, &key, 1);
    br_http_release(ctx, &response);
    free(transport_error);
    return rc == 0 ? 0 : -1;
}

static int scan_zenrows(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid ZenRows scan");
    br_captures keys = {0};
    char *owned = NULL;
    size_t original = out->len;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        char url[120];
        if (key.len != 40) rc = fail(&owned, "invalid ZenRows capture");
        else if (br_finding_key_bytes(&result, 824, key, "key") != 0)
            rc = fail(&owned, "cannot create ZenRows result");
        else if (verify) {
            int n = snprintf(url, sizeof(url),
                             "https://api.zenrows.com/v1/?apikey=%s&url=https://httpbin.org/anything",
                             keys.items[i]);
            if (n != 108) rc = fail(&owned, "cannot format ZenRows URL");
            else if (verify_zenrows(ctx, url, key, &result) != 0)
                rc = fail(&owned, "cannot record ZenRows verification error");
        }
        if (!rc && br_results_push(out, &result) != 0)
            rc = fail(&owned, "cannot append ZenRows result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"zenrows"};
static br_detector zenrows = {
    .type = 824, .version = 0, .name = "ZenRows", .custom_name = "",
    .description = "ZenRows is a web scraping API service that allows users to extract data from "
                   "websites. ZenRows API keys can be used to access and scrape web data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_zenrows,
};

int br_zenrows_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid ZenRows detector output");
    *out = NULL;
    if (!zenrows.state) {
        static const char *const prefixes[] = {"zenrows"};
        br_regex *compiled = NULL;
        if (br_regex_compile_prefixed(prefixes, 1, "\\b([0-9a-f]{40})\\b", &compiled, error) != 0)
            return -1;
        zenrows.state = compiled;
    }
    *out = &zenrows;
    return 0;
}
