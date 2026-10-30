/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/web3storage/web3storage.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_web3storage(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    static const char bearer[] = "Bearer ";
    if (key.len > SIZE_MAX - sizeof(bearer)) return fail(error, "Web3Storage token too large");
    char *auth = malloc(sizeof(bearer) + key.len);
    if (!auth) return fail(error, "cannot allocate Web3Storage Authorization header");
    memcpy(auth, bearer, sizeof(bearer) - 1);
    memcpy(auth + sizeof(bearer) - 1, key.data, key.len);
    auth[sizeof(bearer) - 1 + key.len] = '\0';
    int rc = 0;
    if (!ctx) { free(auth); return 1; }
    const br_header headers[] = {{"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.web3.storage/user/uploads",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error;
    else if (response.status >= 200 && response.status < 300) result->verified = true;
    else if (response.status != 401) {
        snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        cause = status_error;
    }
    br_slice secret = {result->raw.data, result->raw.len};
    if (br_result_set_verification_error(result, cause, &secret, 1) != 0)
        rc = fail(error, "out of memory recording Web3Storage verification error");
    br_http_release(ctx, &response);
    free(transport_error);
    free(auth);
    return rc;
}

static int scan_web3storage(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Web3Storage scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = fail(&owned, "out of memory creating Web3Storage result");
        else if (verify) {
            int checked = verify_web3storage(ctx, key, &result, &owned);
            if (checked < 0) rc = -1;
            else if (checked > 0) { br_result_clear(&result); continue; }
        }
        if (!rc && br_results_push(out, &result) != 0)
            rc = fail(&owned, "out of memory appending Web3Storage result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"web3"};
static br_detector web3storage = {
    .type = 930, .version = 0, .name = "Web3Storage", .custom_name = "",
    .description = "Web3.storage is a service offering decentralized storage solutions. Web3.storage API keys can be used to access and manage stored data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_web3storage,
};

int br_web3storage_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Web3Storage detector output");
    *out = NULL;
    if (br_key_pattern_init(&web3storage,
            "\\b(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\\.eyJ[A-Za-z0-9-_]{100,300}\\.[A-Za-z0-9-_]{25,100})\\b",
            error) != 0)
        return -1;
    *out = &web3storage;
    return 0;
}
