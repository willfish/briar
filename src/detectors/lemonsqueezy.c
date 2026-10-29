/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/lemonsqueezy/lemonsqueezy.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int lemonsqueezy_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* Successful Do only. The stack header array is not retained; it dies when
 * verify returns. The owned Bearer string stays alive through this node's
 * own release, then is freed. */
typedef struct lemonsqueezy_pending lemonsqueezy_pending;
struct lemonsqueezy_pending {
    lemonsqueezy_pending *next;
    br_http_response response;
    char *authorization;
};

/* After this attempt's release, the Bearer must not remain readable. A later
 * release then cannot mistake a closed attempt for one still held. */
static void lemonsqueezy_forget_authorization(char *authorization)
{
    if (!authorization) return;
    memset(authorization, 'X', 7 + 864);
    authorization[7 + 864] = '\0';
    free(authorization);
}

static void lemonsqueezy_drain(const br_scan_ctx *ctx, lemonsqueezy_pending *pending)
{
    while (pending) {
        lemonsqueezy_pending *next = pending->next;
        br_http_release(ctx, &pending->response);
        lemonsqueezy_forget_authorization(pending->authorization);
        free(pending);
        pending = next;
    }
}

/* False keep is the source constructor continue, not a false finding.
 * NewRequestWithContext rejects only a nil context for this fixed GET.
 * The Go client field is a test seam; verification uses the scan transport. */
static int lemonsqueezy_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                               bool *keep, lemonsqueezy_pending **pending, char **error)
{
    static const char url[] = "https://api.lemonsqueezy.com/v1/products/";
    *keep = false;
    if (key.len != 864) return lemonsqueezy_fail(error, "invalid LemonSqueezy capture");
    /* Drop after the finding exists. No Bearer, send, release, or setter. */
    if (!ctx) return 0;
    char *authorization = malloc(7 + key.len + 1);
    if (!authorization)
        return lemonsqueezy_fail(error, "cannot allocate LemonSqueezy authorization");
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, key.len);
    authorization[7 + key.len] = '\0';
    br_http_response response = {0};
    char *transport_error = NULL;
    int send_rc;
    {
        /* Synthesized header storage dies at send return. Do not retain it. */
        const br_header headers[] = {{"Authorization", authorization}};
        const br_http_request request = {
            .method = "GET", .url = url, .headers = headers, .nheaders = 1,
            .profile = BR_HTTP_SANE, .timeout_ms = 5000,
            .detector_type = result->detector_type,
        };
        send_rc = br_http_send(ctx, &request, &response, &transport_error);
    }
    if (send_rc != 0) {
        /* Do failed: no source defer. Release once now, while this Bearer is
         * still alive, then pass the reached cause through. NULL is a no-op.
         * Do not invent a diagnostic. Setter +1 must not skip the release. */
        br_http_release(ctx, &response);
        lemonsqueezy_forget_authorization(authorization);
        int rc = 0;
        if (br_result_set_verification_error(result, transport_error, &key, 1) != 0)
            rc = lemonsqueezy_fail(error, "cannot sanitize LemonSqueezy verification error");
        free(transport_error);
        if (rc) return rc;
        *keep = true;
        return 0;
    }
    /* Register before status formatting, verdict, and the conditional setter.
     * Source defers Body.Close until FromData returns. */
    lemonsqueezy_pending *attempt = malloc(sizeof(*attempt));
    if (!attempt) {
        br_http_release(ctx, &response);
        lemonsqueezy_forget_authorization(authorization);
        lemonsqueezy_drain(ctx, *pending);
        *pending = NULL;
        free(transport_error);
        return lemonsqueezy_fail(error, "cannot retain LemonSqueezy response");
    }
    *attempt = (lemonsqueezy_pending){.next = *pending, .response = response,
                                      .authorization = authorization};
    *pending = attempt;
    free(transport_error);
    int status = response.status; /* Body and read errors are ignored. */
    int rc = 0;
    if (status >= 200 && status < 300) {
        result->verified = true;
    } else if (status != 401) {
        char cause[64];
        int n = snprintf(cause, sizeof(cause), "unexpected HTTP response status %d", status);
        if (n < 0 || (size_t)n >= sizeof(cause))
            rc = lemonsqueezy_fail(error, "cannot format LemonSqueezy status cause");
        else if (br_result_set_verification_error(result, cause, &key, 1) != 0)
            rc = lemonsqueezy_fail(error, "cannot sanitize LemonSqueezy verification error");
    }
    if (rc) return rc;
    *keep = true;
    return 0;
}

static int lemonsqueezy_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                             br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return lemonsqueezy_fail(error, "invalid or uninitialized LemonSqueezy scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    lemonsqueezy_pending *pending = NULL;
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    /* br_scan_key always publishes, so it cannot express the constructor drop.
     * TrimSpace is a no-op for this grammar. Keep every occurrence, including
     * duplicates, in match order. */
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        bool keep = true;
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 864)
            rc = lemonsqueezy_fail(&owned_error, "invalid LemonSqueezy capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = lemonsqueezy_fail(&owned_error, "cannot create LemonSqueezy finding");
        if (!rc && verify)
            rc = lemonsqueezy_verify(ctx, key, &result, &keep, &pending, &owned_error);
        if (!rc && keep && br_results_push(out, &result) != 0)
            rc = lemonsqueezy_fail(&owned_error, "cannot append LemonSqueezy finding");
        br_result_clear(&result);
    }
    /* LIFO after publication, including formatter, setter, and push failures.
     * Each successful send is released once here. Failed sends already released. */
    lemonsqueezy_drain(ctx, pending);
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const lemonsqueezy_keywords[] = {"lemonsqueezy"};
static br_detector lemonsqueezy_detector = {
    .type = 952, .version = 0, .name = "LemonSqueezy", .custom_name = "",
    .description = "LemonSqueezy is a platform for selling digital products. Its API tokens can be used to manage products, orders, and other resources.",
    .keywords = lemonsqueezy_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = lemonsqueezy_scan,
};

int br_lemonsqueezy_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return lemonsqueezy_fail(error, "invalid LemonSqueezy detector output");
    *out = NULL;
    if (br_key_pattern_init(&lemonsqueezy_detector,
                            "\\b(eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9\\.[0-9A-Za-z]{314}\\.[0-9A-Za-z-_]{512})\\b",
                            error) != 0)
        return -1;
    *out = &lemonsqueezy_detector;
    return 0;
}
