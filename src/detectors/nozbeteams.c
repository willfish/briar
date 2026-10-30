/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/nozbeteams/nozbeteams.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int nozbeteams_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* The capture is 82 bytes and must end in one space, CR, or LF. Trim only
 * that suffix. Do not apply a wider Unicode trim. */
static bool nozbeteams_suffix(unsigned char byte)
{
    return byte == ' ' || byte == '\r' || byte == '\n';
}

static br_slice nozbeteams_key(br_slice captured)
{
    return (br_slice){captured.data, 81};
}

/* Successful Do only. The stack header array dies at send return and is not
 * retained. This item keeps the original Authorization through its own release. */
typedef struct {
    br_http_response response;
    char *authorization;
} nozbeteams_pending;

typedef struct {
    nozbeteams_pending *items;
    size_t len, cap;
} nozbeteams_closes;

/* After this attempt's release, the key must not remain readable. */
static void nozbeteams_forget(char *authorization)
{
    if (!authorization) return;
    memset(authorization, 'X', strlen(authorization));
    free(authorization);
}

static void nozbeteams_release_deferred(const br_scan_ctx *ctx, nozbeteams_closes *closes)
{
    while (closes->len) {
        nozbeteams_pending *item = &closes->items[--closes->len];
        br_http_release(ctx, &item->response);
        nozbeteams_forget(item->authorization);
        item->authorization = NULL;
    }
    free(closes->items);
    memset(closes, 0, sizeof(*closes));
}

static int nozbeteams_defer(nozbeteams_closes *closes, const br_http_response *response,
                            char *authorization)
{
    if (closes->len == closes->cap) {
        size_t cap = closes->cap ? closes->cap * 2 : 4;
        if (cap < closes->cap || cap > SIZE_MAX / sizeof(*closes->items)) return -1;
        nozbeteams_pending *items = realloc(closes->items, cap * sizeof(*items));
        if (!items) return -1;
        closes->items = items;
        closes->cap = cap;
    }
    closes->items[closes->len].response = *response;
    closes->items[closes->len].authorization = authorization;
    ++closes->len;
    return 0;
}

/* False keep is the source constructor continue, not a false finding.
 * NewRequestWithContext rejects only a nil context for this fixed GET.
 * The Go client field is a test seam; verification uses the scan transport. */
static int nozbeteams_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                             bool *keep, nozbeteams_closes *closes, char **error)
{
    static const char url[] = "https://api4.nozbe.com/v1/api/users";
    _Static_assert(sizeof(url) - 1 == 35, "NozbeTeams URL");
    *keep = false;
    if (key.len != 81) return nozbeteams_fail(error, "invalid NozbeTeams capture");
    /* Drop after the finding exists. No Authorization, send, release, or setter. */
    if (!ctx) return 0;
    /* A stack copy dies at send return and cannot survive scan-return release.
     * Authorization is the trimmed key alone, with no Bearer prefix. */
    char *authorization = malloc(key.len + 1);
    if (!authorization)
        return nozbeteams_fail(error, "cannot allocate NozbeTeams authorization");
    memcpy(authorization, key.data, key.len);
    authorization[key.len] = '\0';
    br_http_response response = {0};
    char *transport_error = NULL;
    int send_rc;
    {
        /* Synthesized header storage dies at send return. Do not retain it. */
        const br_header headers[] = {
            {"Accept", "application/json"},
            {"Authorization", authorization},
        };
        const br_http_request request = {
            .method = "GET", .url = url, .headers = headers, .nheaders = 2,
            .profile = BR_HTTP_SANE, .timeout_ms = 5000,
            .detector_type = result->detector_type,
        };
        send_rc = br_http_send(ctx, &request, &response, &transport_error);
    }
    free(transport_error);
    if (send_rc != 0) {
        /* Do or preparation failed. Do not invent a cause. Release once now,
         * while the original Authorization is intact, then free it. Not retained. */
        br_http_release(ctx, &response);
        nozbeteams_forget(authorization);
        *keep = true;
        return 0;
    }
    /* Register before the verdict. Source never reads the body, so a
     * body_error cannot suppress a 2xx or drop the finding. */
    if (nozbeteams_defer(closes, &response, authorization) != 0) {
        br_http_release(ctx, &response);
        nozbeteams_forget(authorization);
        return nozbeteams_fail(error, "cannot retain NozbeTeams response");
    }
    if (response.status >= 200 && response.status < 300)
        result->verified = true;
    *keep = true;
    return 0;
}

static int nozbeteams_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return nozbeteams_fail(error, "invalid or uninitialized NozbeTeams scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    nozbeteams_closes closes = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* br_scan_key always publishes, so it cannot express the constructor drop.
     * Keep every occurrence, including duplicates, in match order. Raw and the
     * key part are the trimmed 81 bytes. RawV2 stays unset. */
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        bool keep = true;
        br_slice captured = br_captures_at(&keys, i);
        br_slice key = {0};
        if (captured.len != 82 || !captured.data || !nozbeteams_suffix(captured.data[81]))
            rc = nozbeteams_fail(&owned_error, "invalid NozbeTeams capture");
        else {
            key = nozbeteams_key(captured);
            if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
                rc = nozbeteams_fail(&owned_error, "cannot create NozbeTeams finding");
        }
        if (!rc && verify)
            rc = nozbeteams_verify(ctx, key, &result, &keep, &closes, &owned_error);
        if (!rc && keep && br_results_push(out, &result) != 0)
            rc = nozbeteams_fail(&owned_error, "cannot append NozbeTeams finding");
        br_result_clear(&result);
    }
    /* LIFO after publication. Each successful send is released once here.
     * Failed sends already released. Fatal paths still drain once. */
    nozbeteams_release_deferred(ctx, &closes);
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const nozbeteams_keywords[] = {"nozbe", "nozbeteams"};
static br_detector nozbeteams_detector = {
    .type = 716, .version = 0, .name = "NozbeTeams", .custom_name = "",
    .description = "NozbeTeams is a collaborative task and project management tool. NozbeTeams API keys can be used to access and manage tasks and projects within a NozbeTeams account.",
    .keywords = nozbeteams_keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = nozbeteams_scan,
};

int br_nozbeteams_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return nozbeteams_fail(error, "invalid NozbeTeams detector output");
    *out = NULL;
    if (br_key_pattern_init(&nozbeteams_detector,
                            "\\b([0-9A-Za-z]{16}_[0-9A-Za-z\\-_]{64}[ \\r\\n]{1})", error) != 0)
        return -1;
    *out = &nozbeteams_detector;
    return 0;
}
