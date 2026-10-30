/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/teamworkdesk/teamworkdesk.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static const char teamwork_url[] = "https://example.teamwork.com/desk/api/v2/me.json";

static int teamwork_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static bool teamwork_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char authorization[87];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key, 79);
    authorization[86] = '\0';
    if (!ctx) return false;
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = teamwork_url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(transport_error);
    return true;
}

static int teamwork_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return teamwork_fail(error, "invalid or uninitialized TeamworkDesk scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* The capture includes one required trailing space, CR, or LF. TrimSpace
     * removes that byte. Keep every occurrence. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice captured = br_captures_at(&keys, i);
        br_result result = {0};
        bool keep = true;
        char token[80];
        if (captured.len != 80 || (captured.data[79] != ' ' && captured.data[79] != '\r' &&
                                   captured.data[79] != '\n'))
            rc = teamwork_fail(&owned_error, "invalid TeamworkDesk capture");
        else {
            memcpy(token, captured.data, 79);
            token[79] = '\0';
            if (br_finding_key_bytes(&result, detector->type,
                                     (br_slice){(const unsigned char *)token, 79}, "key") != 0)
                rc = teamwork_fail(&owned_error, "cannot create TeamworkDesk result");
            else if (verify)
                keep = teamwork_verify(ctx, token, &result);
        }
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = teamwork_fail(&owned_error, "cannot append TeamworkDesk result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const teamwork_keywords[] = {"teamwork", "teamworkdesk"};
static br_detector teamwork_detector = {
    .type = 629, .version = 0, .name = "TeamworkDesk", .custom_name = "",
    .description = "TeamworkDesk is a helpdesk software that allows teams to manage customer communications. TeamworkDesk tokens can be used to access and manage customer support tickets and other related data.",
    .keywords = teamwork_keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = teamwork_scan,
};

int br_teamworkdesk_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return teamwork_fail(error, "invalid TeamworkDesk detector output");
    *out = NULL;
    if (br_key_pattern_init(&teamwork_detector, "\\b(tkn\\.v1_[0-9A-Za-z]{71}=[ \\r\\n]{1})", error) != 0)
        return -1;
    *out = &teamwork_detector;
    return 0;
}
