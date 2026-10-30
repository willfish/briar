/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/readme/readme.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "../http_internal.h"

#include <stdlib.h>
#include <string.h>

static int readme_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int readme_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    /* NewRequestWithContext fails before SetBasicAuth. A nil context skips. */
    if (!ctx) return 1;
    char *authorization = NULL;
    if (br_http_basic_auth(key, (br_slice){0}, &authorization, error) != 0)
        return readme_fail(error, "cannot create ReadMe basic authorization");
    const br_header headers[] = {
        {"Authorization", authorization},
        {"Accept", "application/json"},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://dash.readme.com/api/v1",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_PRIVATE_DEFAULT_CLIENT,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    const br_transport *transport = ctx->transport;
    int sent = -1;
    /* http.DefaultClient has no detector UA and no client timeout. The private
     * POST helper cannot represent this GET, so use the injected transport. */
    if (transport && transport->send && transport->release)
        sent = transport->send(transport->user, ctx, &request, &response, &transport_error);
    if (sent == 0) result->verified = response.status >= 200 && response.status < 300;
    if (transport && transport->release) br_http_release(ctx, &response);
    free(transport_error);
    free(authorization);
    return 0;
}

static int readme_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return readme_fail(error, "invalid or uninitialized ReadMe scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        int outcome = 0;
        if (key.len != 75) rc = readme_fail(&owned_error, "invalid ReadMe capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = readme_fail(&owned_error, "cannot create ReadMe result");
        else if (verify) outcome = readme_verify(ctx, key, &result, &owned_error);
        if (rc == 0 && outcome < 0) rc = -1;
        if (rc == 0 && outcome == 0 && br_results_push(out, &result) != 0)
            rc = readme_fail(&owned_error, "cannot append ReadMe result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const readme_keywords[] = {"rdme_"};
static br_regex *readme_regex;
static br_detector readme_detector = {
    .type = 495, .version = 0, .name = "ReadMe", .custom_name = "",
    .description = "ReadMe is a documentation platform that helps you build out your API and product documentation. ReadMe API keys can be used to access and modify your documentation data.",
    .keywords = readme_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = readme_scan,
};

int br_readme_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return readme_fail(error, "invalid ReadMe detector output");
    *out = NULL;
    if (!readme_regex && br_regex_compile("(rdme_[a-z0-9]{70})", &readme_regex, error) != 0)
        return -1;
    readme_detector.state = readme_regex;
    *out = &readme_detector;
    return 0;
}
