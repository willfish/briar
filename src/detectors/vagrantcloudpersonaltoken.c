/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/vagrantcloudpersonaltoken/vagrantcloudpersonaltoken.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char vagrant_url[] = "https://app.vagrantup.com/api/v2/authenticate";

static int vagrant_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int vagrant_store(br_result *result, const char *cause, const char *key, char **error)
{
    br_slice secret = {(const unsigned char *)key, 90};
    if (br_result_set_verification_error(result, cause, &secret, 1) != 0)
        return vagrant_fail(error, "cannot set VagrantCloudPersonalToken verification error");
    return 0;
}

static int vagrant_verify(const br_scan_ctx *ctx, const char *key, br_result *result, bool *keep,
                          char **error)
{
    char authorization[98];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key, 90);
    authorization[97] = '\0';
    *keep = false;
    /* Complete header before the nil-context constructor drop. */
    if (!ctx) return 0;
    *keep = true;
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = vagrant_url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &transport_error);
    if (send_rc != 0) {
        int stored = vagrant_store(result, transport_error, key, error);
        free(transport_error);
        br_http_release(ctx, &response);
        return stored;
    }
    free(transport_error);
    if (response.status == 200 || response.status == 201 || response.status == 202)
        result->verified = true;
    else if (response.status != 401) {
        char status_error[64];
        int n = snprintf(status_error, sizeof(status_error),
                         "unexpected HTTP response status %d", response.status);
        br_http_release(ctx, &response);
        if (n < 0 || (size_t)n >= sizeof(status_error))
            return vagrant_fail(error, "cannot format VagrantCloudPersonalToken status");
        return vagrant_store(result, status_error, key, error);
    }
    br_http_release(ctx, &response);
    return 0;
}

static int vagrant_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return vagrant_fail(error, "invalid or uninitialized VagrantCloudPersonalToken scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* Both dots are unescaped any-bytes. 401 is unverified and silent. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        bool keep = true;
        if (key.len != 90)
            rc = vagrant_fail(&owned_error, "invalid VagrantCloudPersonalToken capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = vagrant_fail(&owned_error, "cannot create VagrantCloudPersonalToken result");
        else if (verify)
            rc = vagrant_verify(ctx, keys.items[i], &result, &keep, &owned_error);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = vagrant_fail(&owned_error, "cannot append VagrantCloudPersonalToken result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const vagrant_keywords[] = {"vagrant"};
static br_detector vagrant_detector = {
    .type = 946, .version = 0, .name = "VagrantCloudPersonalToken", .custom_name = "",
    .description = "Vagrant Cloud is a service for managing and distributing development environments. Personal tokens can be used to authenticate and interact with the Vagrant Cloud API.",
    .keywords = vagrant_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = vagrant_scan,
};

int br_vagrantcloudpersonaltoken_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return vagrant_fail(error, "invalid VagrantCloudPersonalToken detector output");
    *out = NULL;
    if (br_key_pattern_init(&vagrant_detector, "\\b([A-Za-z0-9]{14}.atlasv1.[A-Za-z0-9]{67})\\b", error) != 0)
        return -1;
    *out = &vagrant_detector;
    return 0;
}
