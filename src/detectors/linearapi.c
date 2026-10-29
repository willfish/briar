/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/linearapi/linearapi.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int linearapi_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* strings.Contains on a reached ReadAll. A NUL must not hide the needle.
 * Call only after send succeeded, ReadAll succeeded, and status is 2xx. */
static bool linearapi_has_data(br_slice body)
{
    static const unsigned char needle[] = {'"', 'd', 'a', 't', 'a', '"', ':'};
    if (!body.data || body.len < sizeof(needle)) return false;
    for (size_t i = 0; i + sizeof(needle) <= body.len; ++i)
        if (!memcmp(body.data + i, needle, sizeof(needle))) return true;
    return false;
}

/* Successful Do only, including a later ReadAll drop. The stack header array
 * dies at send return. This node keeps the raw Authorization through its own
 * release, then frees it. */
typedef struct linearapi_pending linearapi_pending;
struct linearapi_pending {
    linearapi_pending *next;
    br_http_response response;
    char *authorization;
};

/* After this attempt's release, the key must not remain readable. */
static void linearapi_forget_authorization(char *authorization)
{
    if (!authorization) return;
    memset(authorization, 'X', 48);
    authorization[48] = '\0';
    free(authorization);
}

static void linearapi_drain(const br_scan_ctx *ctx, linearapi_pending *pending)
{
    while (pending) {
        linearapi_pending *next = pending->next;
        br_http_release(ctx, &pending->response);
        linearapi_forget_authorization(pending->authorization);
        free(pending);
        pending = next;
    }
}

/* False keep is the source constructor continue or ReadAll continue.
 * NewRequestWithContext rejects only a nil context for this fixed POST.
 * The Go client field is a test seam; verification uses the scan transport. */
static int linearapi_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                            bool *keep, linearapi_pending **pending, char **error)
{
    static const char url[] = "https://api.linear.app/graphql";
    static const char query[] = "{ \"query\": \"{ viewer { id name } }\" }";
    _Static_assert(sizeof(query) - 1 == 37, "LinearAPI body must be the 37-byte source literal");
    *keep = false;
    if (key.len != 48) return linearapi_fail(error, "invalid LinearAPI capture");
    /* Drop after the finding exists. No Authorization, send, release, or Bearer. */
    if (!ctx) return 0;
    /* Authorization is the raw key, not Bearer. It must stay alive through
     * send and this attempt's own release. */
    char *authorization = malloc(49);
    if (!authorization) return linearapi_fail(error, "cannot allocate LinearAPI authorization");
    memcpy(authorization, key.data, key.len);
    authorization[key.len] = '\0';
    br_http_response response = {0};
    char *transport_error = NULL;
    int send_rc;
    {
        /* Synthesized header storage dies at send return. Do not retain it.
         * The body is the static literal. Do not make an owned copy. */
        const br_header headers[] = {
            {"Content-Type", "application/json"},
            {"Authorization", authorization},
        };
        const br_http_request request = {
            .method = "POST", .url = url, .headers = headers, .nheaders = 2,
            .body = {(const unsigned char *)query, sizeof(query) - 1},
            .profile = BR_HTTP_SANE, .timeout_ms = 5000,
            .detector_type = result->detector_type,
        };
        send_rc = br_http_send(ctx, &request, &response, &transport_error);
    }
    free(transport_error);
    if (send_rc != 0) {
        /* Do failed: do not inspect the body. Release once now, while the
         * raw key is intact, then free it. Publish unverified. No setter. */
        br_http_release(ctx, &response);
        linearapi_forget_authorization(authorization);
        *keep = true;
        return 0;
    }
    /* Register before any body decision. Source defers Body.Close until
     * FromData returns, including when ReadAll later fails. */
    linearapi_pending *attempt = malloc(sizeof(*attempt));
    if (!attempt) {
        br_http_release(ctx, &response);
        linearapi_forget_authorization(authorization);
        linearapi_drain(ctx, *pending);
        *pending = NULL;
        return linearapi_fail(error, "cannot retain LinearAPI response");
    }
    *attempt = (linearapi_pending){.next = *pending, .response = response,
                                   .authorization = authorization};
    *pending = attempt;
    if (response.body_error) {
        /* ReadAll failed, including an empty string. Drop. Do not search. */
        return 0;
    }
    /* Reached read. NULL plus a nonzero length is fatal before status,
     * including a non-2xx status. The epilogue drains this and earlier. */
    if (!response.body.data && response.body.len)
        return linearapi_fail(error, "invalid LinearAPI body");
    if (response.status >= 200 && response.status < 300 && linearapi_has_data(response.body))
        result->verified = true;
    *keep = true;
    return 0;
}

static int linearapi_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return linearapi_fail(error, "invalid or uninitialized LinearAPI scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    linearapi_pending *pending = NULL;
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* br_scan_key always publishes, so it cannot express the constructor or
     * ReadAll drop. TrimSpace is a no-op. Keep every occurrence, including
     * duplicates, in match order. The token already contains the keyword. */
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        bool keep = true;
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 48)
            rc = linearapi_fail(&owned_error, "invalid LinearAPI capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = linearapi_fail(&owned_error, "cannot create LinearAPI finding");
        if (!rc && verify)
            rc = linearapi_verify(ctx, key, &result, &keep, &pending, &owned_error);
        if (!rc && keep && br_results_push(out, &result) != 0)
            rc = linearapi_fail(&owned_error, "cannot append LinearAPI finding");
        br_result_clear(&result);
    }
    /* LIFO after publication, including dropped ReadAll responses and fatal
     * returns. Each successful send is released once here. Failed sends already released. */
    linearapi_drain(ctx, pending);
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const linearapi_keywords[] = {"lin_api_"};
static br_detector linearapi_detector = {
    .type = 177, .version = 0, .name = "LinearAPI", .custom_name = "",
    .description = "LinearAPI is a project management software. LinearAPI keys can be used to access and modify project data.",
    .keywords = linearapi_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = linearapi_scan,
};

int br_linearapi_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return linearapi_fail(error, "invalid LinearAPI detector output");
    *out = NULL;
    if (linearapi_detector.state) {
        *out = &linearapi_detector;
        return 0;
    }
    br_regex *regex = NULL;
    if (br_regex_compile("\\b(lin_api_[0-9A-Za-z]{40})\\b", &regex, error) != 0) return -1;
    linearapi_detector.state = regex;
    *out = &linearapi_detector;
    return 0;
}
