/* SPDX-License-Identifier: AGPL-3.0-only */
/*
 * Twitter v1 and v2, from pinned TruffleHog pkg/detectors/twitter/v1 and v2.
 * Both versions share VerifyTwitterToken and type 676. ExtraData records the
 * implementation version. Duplicates collapse to the first match.
 */
#include "captures.h"
#include "detectors.h"
#include "findings.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char twitter_url[] = "https://api.twitter.com/2/tweets/20";
static const char v1_capture[] =
    "\\b([A-Z]{22}%[a-zA-Z-0-9]{23}%[a-zA-Z-0-9]{6}%[a-zA-Z-0-9]{3}"
    "%[a-zA-Z-0-9]{9}%[a-zA-Z-0-9]{52})\\b";
static const char v2_capture[] =
    "\\b([a-zA-Z0-9]{20,59}%([a-zA-Z0-9]{3,}%){0,2}[a-zA-Z0-9]{52})\\b";

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int metadata(const br_detector *detector, br_result *result, char **error)
{
    char version[16];
    int n = snprintf(version, sizeof(version), "%d", detector->version);
    if (n < 0 || (size_t)n >= sizeof(version)) return fail(error, "cannot format Twitter version");
    result->extra_data = json_object_new_object();
    br_json *value = result->extra_data ? json_object_new_string(version) : NULL;
    if (!value || json_object_object_add(result->extra_data, "version", value) != 0) {
        json_object_put(value);
        return fail(error, "cannot create Twitter metadata");
    }
    return 0;
}

static int verify(const br_scan_ctx *ctx, const char *token, br_result *result, char **error)
{
    if (!ctx) {
        if (br_result_set_verification_error(result, "net/http: nil Context", NULL, 0) != 0)
            return fail(error, "cannot store Twitter verification error");
        return 0;
    }
    size_t token_len = strlen(token);
    char *bearer = malloc(7 + token_len + 1);
    if (!bearer) return fail(error, "cannot format Twitter authorization");
    memcpy(bearer, "Bearer ", 7);
    memcpy(bearer + 7, token, token_len + 1);
    const br_header headers[] = {{"Authorization", bearer}};
    const br_http_request request = {
        .method = "GET", .url = twitter_url, .headers = headers, .nheaders = 1,
        .timeout_ms = 5000, .detector_type = 676, .profile = BR_HTTP_SANE,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[64];
    const char *cause = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error; /* NULL diagnostic stays NULL. */
    else if (response.status == 200) result->verified = true;
    else if (response.status != 401) {
        int n = snprintf(status_error, sizeof(status_error), "unexpected status code %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error))
            rc = fail(error, "cannot format Twitter status error");
        else cause = status_error;
    }
    if (!rc && br_result_set_verification_error(result, cause, NULL, 0) != 0)
        rc = fail(error, "cannot store Twitter verification error");
    br_http_release(ctx, &response);
    free(transport_error);
    free(bearer);
    return rc;
}

static int scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify_requested,
                br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Twitter scan arguments");
    size_t original = out->len;
    br_captures found = {0};
    char *owned = NULL;
    int rc = br_captures_find(detector->state, input, &found, true, &owned);
    if (rc) rc = -1;
    for (size_t i = 0; !rc && i < found.len; ++i) {
        br_result result = {0};
        const char *token = found.items[i];
        if (br_finding_key(&result, detector->type, token, "key") != 0 ||
            metadata(detector, &result, &owned) != 0)
            rc = fail(&owned, "cannot create Twitter finding");
        else if (verify_requested && verify(ctx, token, &result, &owned) != 0)
            rc = -1;
        else if (br_results_push(out, &result) != 0)
            rc = fail(&owned, "cannot append Twitter finding");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&found);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static int init_one(br_detector *detector, const char *capture, const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Twitter detector output");
    *out = NULL;
    if (!detector->state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(detector->keywords, 1, capture, &regex, error) != 0)
            return -1;
        detector->state = regex;
    }
    *out = detector;
    return 0;
}

static br_detector v1 = {
    .name = "Twitter", .version = 1, .type = 676, .description =
        "Twitter API keys can be used to interact with the Twitter API to post tweets, read timelines, and access other Twitter functionalities.",
    .keywords = (const char *[]){"twitter", NULL}, .nkeywords = 1, .scan = scan,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .custom_name = "",
};
static br_detector v2 = {
    .name = "Twitter", .version = 2, .type = 676, .description =
        "Twitter API keys can be used to access and interact with Twitter's platform programmatically.",
    .keywords = (const char *[]){"twitter", NULL}, .nkeywords = 1, .scan = scan,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .custom_name = "",
};

int br_twitter_v1_init(const br_detector **out, char **error)
{
    return init_one(&v1, v1_capture, out, error);
}

int br_twitter_v2_init(const br_detector **out, char **error)
{
    return init_one(&v2, v2_capture, out, error);
}
