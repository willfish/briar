/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/shotstack/shotstack.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static const char shotstack_url[] = "https://api.shotstack.io/edit/v1/render";
/* The source raw string, including its tab indentation. */
static const char shotstack_body[] =
    "{\n"
    "\t\t\t\t\"timeline\":{\n"
    "\t\t\t\t   \"soundtrack\":{\n"
    "\t\t\t\t\t  \"src\":\"https://s3-ap-southeast-2.amazonaws.com/shotstack-assets/music/moment.mp3\",\n"
    "\t\t\t\t\t  \"effect\":\"fadeOut\"\n"
    "\t\t\t\t   },\n"
    "\t\t\t\t   \"background\":\"#000000\",\n"
    "\t\t\t\t   \"tracks\":[\n"
    "\t\t\t\t\t  {\n"
    "\t\t\t\t\t\t \"clips\":[\n"
    "\t\t\t\t\t\t\t{\n"
    "\t\t\t\t\t\t\t   \"asset\": {\n"
    "\t\t\t\t\t\t\t\t  \"type\":\"title\",\n"
    "\t\t\t\t\t\t\t\t  \"text\":\"Hello World\",\n"
    "\t\t\t\t\t\t\t\t  \"style\":\"minimal\"\n"
    "\t\t\t\t\t\t\t   },\n"
    "\t\t\t\t\t\t\t   \"start\":0,\n"
    "\t\t\t\t\t\t\t   \"length\":5,\n"
    "\t\t\t\t\t\t\t   \"transition\":{\n"
    "\t\t\t\t\t\t\t\t  \"in\":\"fade\",\n"
    "\t\t\t\t\t\t\t\t  \"out\":\"fade\"\n"
    "\t\t\t\t\t\t\t   }\n"
    "\t\t\t\t\t\t\t}\n"
    "\t\t\t\t\t\t ]\n"
    "\t\t\t\t\t  }\n"
    "\t\t\t\t   ]\n"
    "\t\t\t\t},\n"
    "\t\t\t\t\"output\":{\"format\":\"mp4\", \"resolution\":\"sd\"\n"
    "\t\t\t\t}\n"
    "\t\t\t}";

static int shotstack_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static bool shotstack_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    _Static_assert(sizeof(shotstack_body) - 1 == 598, "Shotstack body is the 598-byte source literal");
    if (!ctx) return false;
    /* Canonical MIME header for source x-api-key. */
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"X-Api-Key", key},
    };
    const br_http_request request = {
        .method = "POST", .url = shotstack_url, .headers = headers, .nheaders = 2,
        .body = {(const unsigned char *)shotstack_body, sizeof(shotstack_body) - 1},
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(transport_error);
    return true;
}

static int shotstack_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return shotstack_fail(error, "invalid or uninitialized Shotstack scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        bool keep = true;
        if (key.len != 40)
            rc = shotstack_fail(&owned_error, "invalid Shotstack capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = shotstack_fail(&owned_error, "cannot create Shotstack result");
        else if (verify)
            keep = shotstack_verify(ctx, keys.items[i], &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = shotstack_fail(&owned_error, "cannot append Shotstack result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const shotstack_keywords[] = {"shotstack"};
static br_detector shotstack_detector = {
    .type = 674, .version = 0, .name = "Shotstack", .custom_name = "",
    .description = "Shotstack is a video editing API service. Shotstack API keys can be used to access and utilize the video rendering and editing capabilities of the Shotstack platform.",
    .keywords = shotstack_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = shotstack_scan,
};

int br_shotstack_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return shotstack_fail(error, "invalid Shotstack detector output");
    *out = NULL;
    if (br_key_pattern_init(&shotstack_detector, "\\b([0-9a-zA-Z]{40})\\b", error) != 0)
        return -1;
    *out = &shotstack_detector;
    return 0;
}
