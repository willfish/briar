/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/worldcoinindex/worldcoinindex.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static bool contains_markets(br_slice body)
{
    static const char needle[] = "\"Markets\"";
    return br_slice_find(body, (br_slice){(const unsigned char *)needle, sizeof(needle) - 1}, 0) != SIZE_MAX;
}

static int verify_worldcoinindex(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    if (key.len != 35) return -1;
    static const char prefix[] = "https://www.worldcoinindex.com/apiservice/ticker?key=";
    static const char suffix[] = "&label=ethbtc-ltcbtc&fiat=btc";
    char url[sizeof(prefix) + 35 + sizeof(suffix)];
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, 35);
    memcpy(url + sizeof(prefix) - 1 + 35, suffix, sizeof(suffix));
    if (!ctx) return 1;
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* A read failure does not continue; the unverified result is still appended.
     * Close is deferred only after a successful read. Release here is equivalent
     * for an already-buffered body and does not change the kept result. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0 && !response.body_error &&
        response.status >= 200 && response.status < 300 && contains_markets(response.body))
        result->verified = true;
    br_http_release(ctx, &response);
    free(transport_error);
    return 0;
}

static int scan_worldcoinindex(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                               br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized WorldCoinIndex scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        int skip = 0;
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key"))
            rc = fail(&owned_error, "cannot create WorldCoinIndex result");
        else if (verify) skip = verify_worldcoinindex(ctx, key, &result);
        if (skip < 0) rc = fail(&owned_error, "cannot verify WorldCoinIndex candidate");
        if (!rc && !skip && br_results_push(out, &result))
            rc = fail(&owned_error, "cannot append WorldCoinIndex result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"worldcoinindex"};
static br_detector detector = {
    .type = 415, .name = "WorldCoinIndex", .custom_name = "",
    .description = "WorldCoinIndex is a cryptocurrency market data provider. API keys from WorldCoinIndex can be used to access market data and other information.",
    .keywords = keywords, .nkeywords = 1, .max_secret_size = -1, .start_offset = -1,
    .max_credential_span = -1, .scan = scan_worldcoinindex,
};

int br_worldcoinindex_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid WorldCoinIndex detector output");
    *out = NULL;
    if (!detector.state &&
        br_regex_compile_prefixed(keywords, 1, "\\b([a-zA-Z0-9]{35})\\b", (br_regex **)&detector.state, error))
        return -1;
    *out = &detector;
    return 0;
}
