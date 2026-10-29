/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/ipinfo/ipinfo.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int ipinfo_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int ipinfo_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                         bool *keep, char **error)
{
    static const char base[] = "https://ipinfo.io/json?token=";
    /* TrimSpace and URL escaping are no-ops for the fixed lowercase-hex capture.
     * Build the complete URL before the nil-context constructor's continue. */
    char url[sizeof(base) + 14];
    _Static_assert(sizeof(url) == 44, "IPInfo URL is 43 bytes plus NUL");
    memcpy(url, base, sizeof(base) - 1);
    memcpy(url + sizeof(base) - 1, key.data, 14);
    url[sizeof(url) - 1] = '\0';
    if (!ctx) { *keep = false; return 0; }
    unsigned char dedup_key[18];
    memcpy(dedup_key, "939:", 4);
    memcpy(dedup_key + 4, key.data, 14);
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
        .dedup_key = {dedup_key, sizeof(dedup_key)},
    };
    br_http_response response = {0};
    char *send_error = NULL;
    const char *cause = NULL;
    char status_error[80];
    int rc = 0;
    bool reached_error = false;
    /* Preserve the selected client and full key, including the borrowed keyed
     * guard. Owned clients buffer/promote read failures before Do succeeds;
     * this detector does not read the replay body. Retain the whole mixed
     * shared setup/Do cause without classifying diagnostic text. */
    if (br_http_send(ctx, &request, &response, &send_error) != 0) {
        reached_error = true;
        cause = send_error;
    } else if (response.status >= 200 && response.status < 300)
        result->verified = true;
    else if (response.status != 403) {
        reached_error = true;
        int n = snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error))
            rc = ipinfo_fail(error, "cannot format IPInfo verification status");
        else cause = status_error;
    }
    if (rc == 0 && reached_error && br_result_set_verification_error(result, cause, &key, 1) != 0)
        rc = ipinfo_fail(error, "cannot set IPInfo verification error");
    /* Verdict/setter precede ordinary release, even on a fatal owned failure.
     * Original URL/key/cause survive release; synthesized shared headers/UA do
     * not gain a provider-managed lifetime beyond send return. */
    br_http_release(ctx, &response);
    free(send_error);
    return rc;
}

static int ipinfo_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return ipinfo_fail(error, "invalid or uninitialized IPInfo scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        bool keep = true;
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = ipinfo_fail(&owned_error, "cannot create IPInfo result");
        if (rc == 0 && verify)
            rc = ipinfo_verify(ctx, key, &result, &keep, &owned_error);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = ipinfo_fail(&owned_error, "cannot append IPInfo result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const ipinfo_keywords[] = {"ipinfo"};
static br_detector ipinfo_detector = {
    .type = 939, .version = 0, .name = "IPInfo", .custom_name = "",
    .description = "IPInfo provides detailed information about IP addresses. IPInfo API keys can be used to access and retrieve this information.",
    .keywords = ipinfo_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = ipinfo_scan,
};

int br_ipinfo_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return ipinfo_fail(error, "invalid IPInfo detector output");
    *out = NULL;
    if (!ipinfo_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(ipinfo_keywords, 1, "\\b([a-f0-9]{14})\\b", &regex, error) != 0)
            return -1;
        ipinfo_detector.state = regex;
    }
    *out = &ipinfo_detector;
    return 0;
}
