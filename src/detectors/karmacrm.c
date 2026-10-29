/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/karmacrm/karmacrm.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static const char url_prefix[] = "https://app.karmacrm.com/api/v3/contacts.json?api_token=";
static const char url_suffix[] = "&page=1";

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

/* Source Sprintf runs after the finding and before NewRequestWithContext. */
static char *assemble_url(const char *key)
{
    size_t key_len = strlen(key);
    if (key_len > SIZE_MAX - (sizeof(url_prefix) - 1) - sizeof(url_suffix)) return NULL;
    char *url = malloc(sizeof(url_prefix) - 1 + key_len + sizeof(url_suffix));
    if (!url) return NULL;
    memcpy(url, url_prefix, sizeof(url_prefix) - 1);
    memcpy(url + sizeof(url_prefix) - 1, key, key_len);
    memcpy(url + sizeof(url_prefix) - 1 + key_len, url_suffix, sizeof(url_suffix));
    return url;
}

static int scan_karmacrm(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized KarmaCRM scan");

    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* Capture runs even when verify is set and ctx is NULL. Any nonzero,
     * including +1, is fatal before a nil-context drop. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    if (rc != 0) rc = -1;
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        if (br_finding_key(&result, detector->type, keys.items[i], "key") != 0)
            rc = fail(&owned_error, "out of memory creating KarmaCRM result");
        if (rc == 0 && verify) {
            char *url = assemble_url(keys.items[i]);
            if (!url)
                rc = fail(&owned_error, "out of memory creating KarmaCRM request");
            else if (!ctx) {
                /* NewRequestWithContext(nil) returns "net/http: nil Context".
                 * continue drops only this candidate: no headers, send, or release. */
                free(url);
                br_result_clear(&result);
                continue;
            } else {
                char authorization[sizeof("Bearer ") + 20];
                memcpy(authorization, "Bearer ", 7);
                memcpy(authorization + 7, keys.items[i], 21);
                const br_header headers[] = {
                    {"Accept", "application/vnd.karmacrm+json; version=3"},
                    {"Authorization", authorization},
                };
                const br_http_request request = {
                    .method = "GET", .url = url, .headers = headers, .nheaders = 2,
                    .profile = BR_HTTP_SANE, .detector_type = 296,
                };
                br_http_response response = {0};
                char *transport_error = NULL;
                /* Any 2xx verifies. Other statuses, send failures, and body
                 * errors stay unverified. Never set a verification error. */
                if (br_http_send(ctx, &request, &response, &transport_error) == 0)
                    result.verified = response.status >= 200 && response.status < 300;
                br_http_release(ctx, &response);
                free(transport_error);
                free(url);
            }
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = fail(&owned_error, "out of memory appending KarmaCRM result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const keywords[] = {"karmacrm"};
static const char *const prefix_keywords[] = {"karma"};
static br_detector karmacrm = {
    .type = 296, .version = 0, .name = "KarmaCRM", .custom_name = "",
    .description = "KarmaCRM is a customer relationship management tool. API tokens can be used to access and modify CRM data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_karmacrm,
};

int br_karmacrm_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) {
        if (error) *error = strdup("invalid KarmaCRM detector output");
        return -1;
    }
    *out = NULL;
    if (!karmacrm.state) {
        br_regex *regex = NULL;
        /* Dispatch keyword is karmacrm. Extraction prefix is karma, so the
         * following literal crm consumes three of the 40 gap characters. */
        if (br_regex_compile_prefixed(prefix_keywords, 1, "\\b([a-zA-Z0-9]{20})\\b",
                                     &regex, error) != 0)
            return -1;
        karmacrm.state = regex;
    }
    *out = &karmacrm;
    return 0;
}
