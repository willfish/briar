/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/getresponse/getresponse.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int getresponse_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void getresponse_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    static const char prefix[] = "api-key ";
    char auth[sizeof(prefix) + 32];
    memcpy(auth, prefix, sizeof(prefix) - 1);
    memcpy(auth + sizeof(prefix) - 1, key.data, key.len);
    auth[sizeof(auth) - 1] = '\0';
    const br_header headers[] = {{"X-Auth-Token", auth}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.getresponse.com/v3/accounts",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Upstream ignores the entire Do error domain and never reads the body. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Original request/header/auth storage survives release. Ordinary shared
     * effective-request headers and UA survive only until send returns. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int getresponse_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return getresponse_fail(error, "invalid or uninitialized Getresponse scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        /* TrimSpace is a no-op for this alphabet. Keep every occurrence. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = getresponse_fail(&owned_error, "cannot create Getresponse result");
        else if (!(verify && !ctx)) {
            /* The known nil-context constructor failure skips before auth. */
            if (verify) getresponse_verify(ctx, key, &result);
            if (br_results_push(out, &result) != 0)
                rc = getresponse_fail(&owned_error, "cannot append Getresponse result");
        }
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const getresponse_keywords[] = {"getresponse"};
static br_detector getresponse_detector = {
    .type = 861, .version = 0, .name = "Getresponse", .custom_name = "",
    .description = "GetResponse is an email marketing service. GetResponse API keys can be used to access and manage email marketing campaigns, contacts, and other related data.",
    .keywords = getresponse_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = getresponse_scan,
};

int br_getresponse_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return getresponse_fail(error, "invalid Getresponse detector output");
    *out = NULL;
    if (br_key_pattern_init(&getresponse_detector, "\\b([a-z0-9]{32})\\b", error) != 0) return -1;
    *out = &getresponse_detector;
    return 0;
}
