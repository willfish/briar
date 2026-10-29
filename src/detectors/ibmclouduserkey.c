/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/ibmclouduserkey/ibmclouduserkey.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

typedef enum { IBM_ABORT = -1, IBM_KEEP = 0, IBM_DROP = 1 } ibm_outcome;
enum { IBM_KEY_SIZE = 44 };

static int ibm_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static ibm_outcome ibm_verify(const br_scan_ctx *ctx, br_slice key,
                              br_result *result, char **error)
{
    static const char prefix[] = "apikey=";
    static const char suffix[] = "&grant_type=urn%3Aibm%3Aparams%3Aoauth%3Agrant-type%3Aapikey";
    const size_t form_size = sizeof(prefix) - 1 + IBM_KEY_SIZE + sizeof(suffix);
    char *form = malloc(form_size);
    if (!form) {
        ibm_fail(error, "cannot construct IBM Cloud user-key form");
        return IBM_ABORT;
    }
    /* The exact ASCII grammar needs no encoder. Source concatenation and its
     * strings.Reader both precede the nil-context constructor drop. */
    memcpy(form, prefix, sizeof(prefix) - 1);
    memcpy(form + sizeof(prefix) - 1, key.data, IBM_KEY_SIZE);
    memcpy(form + sizeof(prefix) - 1 + IBM_KEY_SIZE, suffix, sizeof(suffix));
    const br_slice payload = {(const unsigned char *)form, form_size - 1};
    if (!ctx) {
        free(form);
        return IBM_DROP;
    }
    const br_header headers[] = {
        {"Content-Type", "application/x-www-form-urlencoded"},
        {"Authorization", "Basic Yng6Yng="},
    };
    const br_http_request request = {
        .method = "POST", .url = "https://iam.cloud.ibm.com/identity/token",
        .headers = headers, .nheaders = 2, .body = payload,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Shared preparation and Do errors form one suppressed domain; their
     * signs and diagnostic text never classify provider-owned failures. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Ignore body/read errors at every status. Keep original form, headers
     * and captures through one ordinary release per attempt, even failed
     * preparation. Synthesized request/header-array/UA end at send return. */
    br_http_release(ctx, &response);
    free(send_error);
    free(form);
    return IBM_KEEP;
}

static int ibm_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                    br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return ibm_fail(error, "invalid or uninitialized IBM Cloud user-key scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        ibm_outcome outcome = IBM_KEEP;
        /* TrimSpace cannot change this ASCII capture. Preserve each original
         * occurrence, including duplicates and contextual hyphen boundaries. */
        if (key.len != IBM_KEY_SIZE) {
            ibm_fail(&owned_error, "invalid IBM Cloud user-key capture");
            outcome = IBM_ABORT;
        } else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            ibm_fail(&owned_error, "cannot create IBM Cloud user-key result");
            outcome = IBM_ABORT;
        } else if (verify) {
            outcome = ibm_verify(ctx, key, &result, &owned_error);
        }
        if (outcome == IBM_KEEP && br_results_push(out, &result) != 0) {
            ibm_fail(&owned_error, "cannot append IBM Cloud user-key result");
            outcome = IBM_ABORT;
        }
        br_result_clear(&result);
        if (outcome == IBM_ABORT) rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const ibm_keywords[] = {"ibm"};
static br_detector ibm_detector = {
    .type = 73, .version = 0, .name = "IbmCloudUserKey", .custom_name = "",
    .description = "IBM Cloud is a suite of cloud computing services from IBM that offers both platform as a service (PaaS) and infrastructure as a service (IaaS). IBM Cloud API keys can be used to access and manage IBM Cloud services and resources.",
    .keywords = ibm_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = ibm_scan,
};

int br_ibmclouduserkey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return ibm_fail(error, "invalid IBM Cloud user-key detector output");
    *out = NULL;
    if (br_key_pattern_init(&ibm_detector, "\\b([A-Za-z0-9_-]{44})\\b", error) != 0)
        return -1;
    *out = &ibm_detector;
    return 0;
}
