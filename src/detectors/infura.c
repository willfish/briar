/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/infura/infura.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int infura_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int infura_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                         bool *keep, char **error)
{
    static const unsigned char payload[] =
        "{\"jsonrpc\":\"2.0\",\"method\":\"eth_blockNumber\",\"params\":[],\"id\":1}";
    const br_slice body = {payload, sizeof(payload) - 1};
    static const char prefix[] = "https://mainnet.infura.io/v3/";
    if (key.len > SIZE_MAX - sizeof(prefix))
        return infura_fail(error, "Infura URL too large");
    char *url = malloc(sizeof(prefix) + key.len);
    if (!url) return infura_fail(error, "cannot construct Infura URL");
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, key.len);
    url[sizeof(prefix) - 1 + key.len] = '\0';
    /* Source constructs the payload reader and complete literal URL before
     * NewRequestWithContext can reject nil and drop the finding. */
    if (!ctx) {
        free(url);
        *keep = false;
        return 0;
    }
    const br_header headers[] = {{"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "POST", .url = url, .headers = headers, .nheaders = 1,
        .body = body, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int rc = 0;
    /* All mixed shared setup/Do failures keep an unverified finding. Do not
     * classify diagnostics or set a verification error. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0) {
        /* ReadAll precedes the marker decision at every HTTP status. Even an
         * empty, non-NULL read error drops partial bytes and the finding. */
        if (response.body_error) *keep = false;
        else if (!response.body.data && response.body.len)
            rc = infura_fail(error, "invalid Infura response body slice");
        else {
            static const unsigned char marker[] = "\"result\"";
            result->verified = br_slice_find(response.body,
                (br_slice){marker, sizeof(marker) - 1}, 0) != SIZE_MAX;
        }
    }
    /* Keep provider URL/body/header/captures through one ordinary release per
     * attempt, including failed shared preparation. Synthesized headers/UA end
     * at send return; source's leaks and scan-deferred closes are not copied. */
    br_http_release(ctx, &response);
    free(send_error);
    free(url);
    return rc;
}

static int infura_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return infura_fail(error, "invalid or uninitialized Infura scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        bool keep = true;
        /* TrimSpace cannot change this ASCII capture. Preserve occurrences and
         * duplicates without imposing hex, entropy or whole-token validation. */
        if (key.len != 32)
            rc = infura_fail(&owned_error, "invalid Infura capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = infura_fail(&owned_error, "cannot create Infura result");
        if (rc == 0 && verify)
            rc = infura_verify(ctx, key, &result, &keep, &owned_error);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = infura_fail(&owned_error, "cannot append Infura result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const infura_keywords[] = {"infura"};
static br_detector infura_detector = {
    .type = 906, .version = 0, .name = "Infura", .custom_name = "",
    .description = "Infura provides the infrastructure for decentralized applications to connect to the Ethereum blockchain. Infura keys can be used to interact with the Ethereum network.",
    .keywords = infura_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = infura_scan,
};

int br_infura_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return infura_fail(error, "invalid Infura detector output");
    *out = NULL;
    if (br_key_pattern_init(&infura_detector, "\\b([0-9a-z]{32})\\b", error) != 0)
        return -1;
    *out = &infura_detector;
    return 0;
}
