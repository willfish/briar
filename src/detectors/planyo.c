/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/planyo/planyo.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static bool contains(br_slice body, const char *needle)
{
    br_slice want = {(const unsigned char *)needle, strlen(needle)};
    return br_slice_find(body, want, 0) != SIZE_MAX;
}

/* Request construction and a body-read failure both skip the candidate.
 * A transport failure still appends an unverified result. */
static int verify_planyo(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    if (key.len != 62) return -1;
    static const char prefix[] = "https://www.planyo.com/rest/?method=get_site_info&api_key=";
    char url[sizeof(prefix) + 62];
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, 62);
    url[sizeof(prefix) - 1 + 62] = '\0';
    if (!ctx) return 1;
    const br_header headers[] = {{"Accept", "application/vnd.planyo+json; version=3"}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &transport_error);
    int skip = 0;
    if (!sent) {
        if (response.body_error) skip = 1;
        else if (response.status >= 200 && response.status < 300 &&
                 (contains(response.body, "data") || contains(response.body, "Your Planyo site has expired")))
            result->verified = true;
    }
    br_http_release(ctx, &response);
    free(transport_error);
    return skip;
}

static int scan_planyo(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Planyo scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        int skip = 0;
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key"))
            rc = fail(&owned_error, "cannot create Planyo result");
        else if (verify) skip = verify_planyo(ctx, key, &result);
        if (skip < 0) rc = fail(&owned_error, "cannot verify Planyo candidate");
        if (!rc && !skip && br_results_push(out, &result))
            rc = fail(&owned_error, "cannot append Planyo result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"planyo"};
static br_detector detector = {
    .type = 614, .name = "Planyo", .custom_name = "",
    .description = "Planyo is an online reservation system that offers various API methods to interact with its services. Planyo API keys can be used to access and modify reservation data.",
    .keywords = keywords, .nkeywords = 1, .max_secret_size = -1, .start_offset = -1,
    .max_credential_span = -1, .scan = scan_planyo,
};

int br_planyo_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Planyo detector output");
    *out = NULL;
    if (!detector.state &&
        br_regex_compile_prefixed(keywords, 1, "\\b([0-9a-z]{62})\\b", (br_regex **)&detector.state, error))
        return -1;
    *out = &detector;
    return 0;
}
