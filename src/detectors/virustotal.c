/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/virustotal/virustotal.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int virustotal_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static bool virustotal_verified(const br_scan_ctx *ctx, const char *key, int32_t type)
{
    /* Constructor and Do failures are false, with no verification error. */
    if (!ctx) return false;
    char api_key[65];
    memcpy(api_key, key, 64);
    api_key[64] = '\0';
    const br_header header = {"X-Apikey", api_key};
    const br_http_request request = {
        .method = "GET", .url = "https://www.virustotal.com/api/v3/metadata",
        .headers = &header, .nheaders = 1, .profile = BR_HTTP_SANE, .detector_type = type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    bool verified = false;
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(transport_error);
    return verified;
}

static int virustotal_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return virustotal_fail(error, "invalid or uninitialized VirusTotal scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        if (key.len != 64) rc = virustotal_fail(&owned_error, "invalid VirusTotal capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = virustotal_fail(&owned_error, "cannot create VirusTotal result");
        else if (verify) result.verified = virustotal_verified(ctx, keys.items[i], detector->type);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = virustotal_fail(&owned_error, "cannot append VirusTotal result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const virustotal_keywords[] = {"virustotal"};
static br_detector virustotal_detector = {
    .type = 497, .version = 0, .name = "VirusTotal", .custom_name = "",
    .description = "VirusTotal is an online service that analyzes files and URLs for viruses, worms, trojans, and other kinds of malicious content. VirusTotal API keys can be used to access and integrate this service into applications.",
    .keywords = virustotal_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = virustotal_scan,
};

int br_virustotal_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return virustotal_fail(error, "invalid VirusTotal detector output");
    *out = NULL;
    if (br_key_pattern_init(&virustotal_detector, "\\b([a-f0-9]{64})\\b", error) != 0) return -1;
    *out = &virustotal_detector;
    return 0;
}
