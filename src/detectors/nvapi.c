/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/nvapi/nvapi.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { bool verified; char *cause; } nvapi_verdict;

static int nvapi_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int nvapi_cause(const char *message, char **cause, char **error)
{
    *cause = strdup(message);
    return *cause ? 0 : nvapi_fail(error, "cannot allocate NVAPI verification cause");
}

static int nvapi_status_cause(int status, char **cause, char **error)
{
    char message[80];
    int n = snprintf(message, sizeof(message), "unexpected HTTP response status %d", status);
    if (n < 0 || (size_t)n >= sizeof(message)) return nvapi_fail(error, "cannot format NVAPI status cause");
    return nvapi_cause(message, cause, error);
}

static int nvapi_verify(const br_scan_ctx *ctx, br_slice key,
                         nvapi_verdict *verdict, char **error)
{
    /* Values.Encode leaves this entire reachable alphabet unchanged. Build the
     * COMPLETE credentials= + token form BEFORE nil-context construction. */
    static const char prefix[] = "credentials=";
    unsigned char body[sizeof(prefix) + 70];
    _Static_assert(sizeof(body) == 83, "NVAPI form contains 82 bytes plus NUL");
    memcpy(body, prefix, sizeof(prefix) - 1);
    memcpy(body + sizeof(prefix) - 1, key.data, 70);
    body[sizeof(body) - 1] = 0;
    if (!ctx) return nvapi_cause("net/http: nil Context", &verdict->cause, error);

    const br_header headers[] = {{"Content-Type", "application/x-www-form-urlencoded"}};
    const br_http_request request = {
        .method = "POST", .url = "https://api.ngc.nvidia.com/v3/keys/get-caller-info",
        .headers = headers, .nheaders = 1, .body = {body, sizeof(body) - 1},
        .profile = BR_HTTP_SANE, .detector_type = 997,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &send_error) != 0) {
        /* The WHOLE preparation/Do error domain is ordinary indeterminate.
         * Transfer its OPTIONAL owned leaf as-is: consumed NULL stays NULL. */
        verdict->cause = send_error;
        send_error = NULL;
    } else if (response.status == 200) verdict->verified = true;
    else if (response.status != 401) rc = nvapi_status_cause(response.status, &verdict->cause, error);
    /* Body/read/drain/close errors do not affect this source verdict. Construct
     * status causes BEFORE release, then return BEFORE outer verdict/setter.
     * Provider ORIGINAL URL/header/body/key stay live through exactly one
     * release per attempt; never retain ordinary synthesized headers/UA. */
    br_http_release(ctx, &response);
    free(send_error);
    return rc;
}

static int nvapi_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return nvapi_fail(error, "invalid or uninitialized NVAPI scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* Collect the complete byte-unique set BEFORE findings. First-seen C
     * iteration is not a claim about Go's unspecified map iteration order. */
    int rc = br_captures_find(detector->state, input, &keys, true, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        nvapi_verdict verdict = {0};
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = nvapi_fail(&owned_error, "cannot create NVAPI finding");
        if (rc == 0 && verify) {
            rc = nvapi_verify(ctx, key, &verdict, &owned_error);
            if (rc == 0) {
                result.verified = verdict.verified;
                result.extra_data = NULL; /* Source helper returns nil Extra. */
                /* Mandatory EVEN NULL on 200/401/consumed errors, and WITH the
                 * FULL70-byte token. Helper release has already completed. */
                if (br_result_set_verification_error(&result, verdict.cause, &key, 1) != 0)
                    rc = nvapi_fail(&owned_error, "cannot set NVAPI verification error");
            }
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = nvapi_fail(&owned_error, "cannot append NVAPI finding");
        free(verdict.cause);
        br_result_clear(&result);
    }
    if (rc != 0) {
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
        nvapi_fail(&owned_error, "cannot collect NVAPI tokens");
    }
    br_captures_clear(&keys);
    if (error) *error = owned_error; else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const nvapi_keywords[] = {"nvapi-"};
static br_detector nvapi_detector = {
    .type = 997, .version = 0, .name = "NVAPI", .custom_name = "",
    .description = "NVAPI keys are used to authenticate API requests to NVIDIA's NGC API. They allow access to NVIDIA's NGC API to manage user data and perform actions on behalf of users.",
    .keywords = nvapi_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = nvapi_scan,
};

int br_nvapi_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return nvapi_fail(error, "invalid NVAPI detector output");
    *out = NULL;
    if (!nvapi_detector.state) {
        br_regex *pattern = NULL;
        if (br_regex_compile("\\b(nvapi-[a-zA-Z0-9_-]{64})\\b", &pattern, error) != 0) {
            br_regex_free(pattern);
            return -1;
        }
        nvapi_detector.state = pattern;
    }
    *out = &nvapi_detector;
    return 0;
}
