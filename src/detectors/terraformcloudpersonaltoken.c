/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/terraformcloudpersonaltoken/terraformcloudpersonaltoken.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { TF_ABORT = -1, TF_KEEP = 0, TF_SKIP = 1 } tf_outcome;

static int tf_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static tf_outcome tf_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    char authorization[sizeof("Bearer ") + 90];
    int n = snprintf(authorization, sizeof(authorization), "Bearer %.*s",
                     (int)key.len, (const char *)key.data);
    if (n < 0 || (size_t)n >= sizeof(authorization)) {
        tf_fail(error, "cannot format TerraformCloudPersonalToken authorization");
        return TF_ABORT;
    }
    if (!ctx) return TF_SKIP;
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://app.terraform.io/api/v2/account/details",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(transport_error);
    return TF_KEEP;
}

static int tf_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                   br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return tf_fail(error, "invalid or uninitialized TerraformCloudPersonalToken scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        tf_outcome outcome = TF_KEEP;
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            tf_fail(&owned_error, "cannot create TerraformCloudPersonalToken result");
            outcome = TF_ABORT;
        } else if (verify)
            outcome = tf_verify(ctx, key, &result, &owned_error);
        if (outcome == TF_ABORT) rc = -1;
        else if (outcome == TF_KEEP && br_results_push(out, &result) != 0) {
            tf_fail(&owned_error, "cannot append TerraformCloudPersonalToken result");
            rc = -1;
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

static const char *const tf_keywords[] = {".atlasv1."};
static br_regex *tf_regex;
static br_detector tf_detector = {
    .type = 93, .version = 0, .name = "TerraformCloudPersonalToken", .custom_name = "",
    .description = "Terraform Cloud is a service that provides infrastructure automation. "
                   "Terraform Cloud personal tokens can be used to access and manage infrastructure as code.",
    .keywords = tf_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = tf_scan,
};

int br_terraformcloudpersonaltoken_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return tf_fail(error, "invalid TerraformCloudPersonalToken detector output");
    *out = NULL;
    /* Direct pattern, not PrefixRegex. Each '.' is any non-newline, matching
     * the Go source rather than a literal dot. Keyword is engine dispatch only. */
    if (!tf_regex && br_regex_compile("\\b([A-Za-z0-9]{14}.atlasv1.[A-Za-z0-9]{67})\\b",
                                      &tf_regex, error) != 0)
        return -1;
    tf_detector.state = tf_regex;
    *out = &tf_detector;
    return 0;
}
