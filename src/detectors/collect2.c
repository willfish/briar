/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/collect2/collect2.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void verify_collect2(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    static const char prefix[] = "https://collect2.com/api/", suffix[] = "/datarecord/";
    /* Complete bounded URL including NUL. Captured key is exactly 36
     * unreserved bytes; no escaping, heap URL copy or artificial size cap. */
    char url[sizeof(prefix) - 1 + 36 + sizeof(suffix)];
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, key.len);
    memcpy(url + sizeof(prefix) - 1 + key.len, suffix, sizeof(suffix));
    const br_header headers[] = {{"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL;
    /* Source suppresses the entire Do error domain. ABI1 also combines
     * adapter setup/allocation errors here; no diagnostic-text classifier. */
    if (!br_http_send(ctx, &request, &response, &transport_error))
        result->verified = response.status >= 200 && response.status < 300;
    /* Body/read errors are ignored. Source scan-defers Close ONLY; eager ABI1
     * release/full native-client configuration and global parity stay partial.
     * The borrowed stack URL remains live through synchronous send/release. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int scan_collect2(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len)) return fail(error, "invalid Collect2 scan");
    br_captures keys = {0}; char *owned_error = NULL;
    size_t original_len = out->len;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0}; br_slice key = br_captures_at(&keys, i);
        /* TrimSpace changes nothing. Keep duplicate occurrences, and prepare
         * the finding BEFORE the known nil-context constructor skip. */
        if (br_finding_key_bytes(&result, detector->type, key, "key"))
            rc = fail(&owned_error, "cannot create Collect2 result");
        else if (!verify || ctx) {
            if (verify) verify_collect2(ctx, key, &result);
            if (br_results_push(out, &result)) rc = fail(&owned_error, "cannot append Collect2 result");
        } /* verify && !ctx: source NewRequestWithContext failure skips candidate. */
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"collect2"};
static br_detector collect2 = {
    .type = 823, .version = 0, .name = "Collect2", .custom_name = "",
    .description = "An API to Collect, Modify, Filter and Export Data using webhooks. API keys can create read update and delete data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_collect2,
};

int br_collect2_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Collect2 detector output");
    *out = NULL;
    /* LOWER HEX shape only, not broad alnum or UUID-version validation. */
    if (br_key_pattern_init(&collect2, "\\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b", error)) return -1;
    *out = &collect2;
    return 0;
}
