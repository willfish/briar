/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/protocolsio/protocolsio.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int protocolsio_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static void protocolsio_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char authorization[72];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key, 64);
    authorization[71] = '\0';
    const br_header header = {"Authorization", authorization};
    const br_http_request request = {
        .method = "GET", .url = "https://www.protocols.io/api/v3/session/profile",
        .headers = &header, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Do errors are ignored. Close does not read the body. No setter. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(transport_error);
}

static int protocolsio_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return protocolsio_fail(error, "invalid or uninitialized ProtocolsIO scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        bool keep = true;
        if (key.len != 64) rc = protocolsio_fail(&owned_error, "invalid ProtocolsIO capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = protocolsio_fail(&owned_error, "cannot create ProtocolsIO result");
        else if (verify && !ctx) keep = false; /* NewRequestWithContext skips this candidate. */
        else if (verify) protocolsio_verify(ctx, keys.items[i], &result);
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = protocolsio_fail(&owned_error, "cannot append ProtocolsIO result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const protocolsio_keywords[] = {"protocols"};
static br_detector protocolsio_detector = {
    .type = 411, .version = 0, .name = "ProtocolsIO", .custom_name = "",
    .description = "Protocols.io is a platform for developing and sharing reproducible research protocols. The API keys can be used to access and manage protocols and data on the platform.",
    .keywords = protocolsio_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = protocolsio_scan,
};

int br_protocolsio_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return protocolsio_fail(error, "invalid ProtocolsIO detector output");
    *out = NULL;
    if (br_key_pattern_init(&protocolsio_detector, "\\b([a-z0-9]{64})\\b", error) != 0) return -1;
    *out = &protocolsio_detector;
    return 0;
}
