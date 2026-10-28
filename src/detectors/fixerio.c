/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/fixerio/fixerio.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int fixerio_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* False denotes constructor skip OR successful-Do ReadAll error (source
 * continue). Mixed shared setup/allocation/Do failures instead KEEP false. */
static bool fixerio_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    static const char base[] = "https://data.fixer.io/api/latest?access_key=";
    /* Source completes the URL BEFORE construction. Exact 32-byte ASCII grammar
     * needs only this bound, no encoder/formatter/heap copy or failure seam. */
    char url[sizeof(base) + 32];
    _Static_assert(sizeof(url) == 77, "FixerIO URL is 76 bytes plus NUL");
    memcpy(url, base, sizeof(base) - 1); memcpy(url + sizeof(base) - 1, key.data, 32); url[76] = '\0';
    if (!ctx) return false;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *send_error = NULL; bool keep = true;
    /* Suppress the WHOLE mixed shared setup/allocation/Do domain, without a
     * setter or text classifier. Only successful Do can reach ReadAll/DROP. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0) {
        if (response.body_error != NULL) keep = false; /* Even empty errors DROP, at EVERY status. */
        else {
            static const unsigned char success[] = "\"success\": true";
            static const unsigned char restricted[] = "\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\"";
            bool valid = br_slice_find(response.body, (br_slice){success, sizeof(success) - 1}, 0) != SIZE_MAX ||
                         br_slice_find(response.body, (br_slice){restricted, sizeof(restricted) - 1}, 0) != SIZE_MAX;
            /* Successful ReadAll and exact binary substring checks precede the
             * status gate. No JSON parsing, normalization or UTF-8/NUL barrier. */
            result->verified = response.status >= 200 && response.status < 300 && valid;
        }
    }
    /* Full stack URL stays live through synchronous send AND release. Source
     * registers duplicate scan-deferred Close on successful read; do NOT mimic
     * double-close/leaks. Release ABI-owned responses once, even on errors/drop.
     * Full Reader/close timing/native client/regexp and global source/engine/
     * output parity remain partial. Shared native guards remain unchanged. */
    br_http_release(ctx, &response);
    free(send_error);
    return keep;
}

static int fixerio_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fixerio_fail(error, "invalid or uninitialized FixerIO scan");
    size_t original_len = out->len; br_captures keys = {0}; char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0}; br_slice key = br_captures_at(&keys, i); bool keep = true;
        /* TrimSpace is a no-op. Preserve original occurrences/duplicates with
         * no validation/filter/cache. Owned finding failures precede URL prep,
         * constructor skips, read-error DROPs and suppressed send outcomes. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = fixerio_fail(&owned_error, "cannot create FixerIO result");
        if (rc == 0 && verify) keep = fixerio_verify(ctx, key, &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = fixerio_fail(&owned_error, "cannot append FixerIO result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error; else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const fixerio_keywords[] = {"fixer"};
static br_detector fixerio_detector = {
    .type = 149, .version = 0, .name = "FixerIO", .custom_name = "",
    .description = "Fixer.io is a foreign exchange rates and currency conversion API. Fixer.io API keys can be used to access and retrieve current and historical foreign exchange rates.",
    .keywords = fixerio_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1, .scan = fixerio_scan,
};

int br_fixerio_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fixerio_fail(error, "invalid FixerIO detector output");
    *out = NULL;
    if (br_key_pattern_init(&fixerio_detector, "\\b([A-Za-z0-9]{32})\\b", error) != 0) return -1;
    *out = &fixerio_detector;
    return 0;
}
