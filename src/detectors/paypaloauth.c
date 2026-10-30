/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/paypaloauth/paypaloauth.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    br_regex *id;
    br_regex *key;
} paypal_patterns;

static int paypal_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* Successful Do closes are scan-deferred. A stack token cannot survive that
 * release, so the original Authorization allocation stays with the response.
 * The stack header array is not retained. The body is static and is not copied. */
typedef struct paypal_pending paypal_pending;
struct paypal_pending {
    paypal_pending *next;
    br_http_response response;
    char *authorization;
};

static int paypal_retain(paypal_pending **pending, const br_http_response *response,
                         char *authorization)
{
    paypal_pending *item = malloc(sizeof(*item));
    if (!item) return -1;
    item->next = *pending;
    item->response = *response;
    item->authorization = authorization;
    *pending = item;
    return 0;
}

static void paypal_release_held(const br_scan_ctx *ctx, paypal_pending *pending)
{
    while (pending) {
        paypal_pending *next = pending->next;
        br_http_release(ctx, &pending->response);
        free(pending->authorization);
        free(pending);
        pending = next;
    }
}

/* Finding already exists. Authorization is built before the nil check.
 * 1 drops only this pair. 0 publishes it. -1 is fatal, including allocation
 * failure when context is nil. There is no setter. */
static int paypal_verify(const br_scan_ctx *ctx, br_slice id, br_slice secret,
                         br_result *result, paypal_pending **pending, char **error)
{
    char *authorization = NULL;
    if (br_http_basic_auth(id, secret, &authorization, error) != 0) return -1;
    if (!ctx) {
        free(authorization);
        return 1;
    }
    static const char grant_type[] = "grant_type=client_credentials";
    const br_header headers[] = {
        {"Accept", "application/json"},
        {"Accept-Language", "en_US"},
        {"Content-Type", "application/x-www-form-urlencoded"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "POST", .url = "https://api-m.sandbox.paypal.com/v1/oauth2/token",
        .headers = headers, .nheaders = 4,
        .body = {(const unsigned char *)grant_type, sizeof(grant_type) - 1},
        .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &send_error);
    free(send_error);
    if (send_rc != 0) {
        br_http_release(ctx, &response);
        free(authorization);
        return 0;
    }
    if (paypal_retain(pending, &response, authorization) != 0) {
        br_http_release(ctx, &response);
        free(authorization);
        return paypal_fail(error, "cannot retain PaypalOauth response for release");
    }
    /* Source never reads the body. A reached non-2xx is explicitly unverified. */
    if (response.status >= 200 && response.status < 300)
        result->verified = true;
    else
        result->verified = false;
    return 0;
}

static int paypal_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return paypal_fail(error, "invalid or uninitialized PaypalOauth scan");
    const paypal_patterns *patterns = detector->state;
    if (!patterns->id || !patterns->key)
        return paypal_fail(error, "invalid or uninitialized PaypalOauth scan");
    size_t original_len = out->len;
    br_captures ids = {0}, keys = {0};
    paypal_pending *pending = NULL;
    char *owned_error = NULL;
    /* Neither pattern is prefixed. Keep every match, including an ID that also
     * matches the key pattern. Outer ID order, inner key order. The credential
     * span is not a FromData filter. */
    int rc = br_captures_find(patterns->id, input, &ids, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
        br_slice id = br_captures_at(&ids, i);
        if (id.len != 80 && id.len != 44)
            rc = paypal_fail(&owned_error, "invalid PaypalOauth capture");
        for (size_t j = 0; rc == 0 && j < keys.len; ++j) {
            br_result result = {0};
            br_slice secret = br_captures_at(&keys, j);
            bool keep = true;
            if (secret.len < 44 || secret.len > 80)
                rc = paypal_fail(&owned_error, "invalid PaypalOauth capture");
            else if (br_finding_key_bytes(&result, detector->type, secret, "key") != 0)
                rc = paypal_fail(&owned_error, "cannot create PaypalOauth result");
            else if (verify) {
                int verdict = paypal_verify(ctx, id, secret, &result, &pending, &owned_error);
                if (verdict < 0) rc = -1;
                else keep = verdict == 0;
            }
            if (rc == 0 && keep && br_results_push(out, &result) != 0)
                rc = paypal_fail(&owned_error, "cannot append PaypalOauth result");
            br_result_clear(&result);
        }
    }
    /* Successful responses close after publication, last success first. Fatal
     * paths drain the same list once, then roll back only this invocation. */
    paypal_release_held(ctx, pending);
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&ids);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const paypal_keywords[] = {"paypal"};
/* Source spelling. The ID hyphen is a separator. Do not rewrite either class
 * and do not add a keyword prefix. */
static const char paypal_id_pattern[] =
    "\\b([A-Za-z0-9_\\.]{7}-[A-Za-z0-9_\\.]{72}|[A-Za-z0-9_\\.]{5}-[A-Za-z0-9_\\.]{38})\\b";
static const char paypal_key_pattern[] = "\\b([A-Za-z0-9_\\.\\-]{44,80})\\b";
static paypal_patterns paypal_state;
static br_detector paypal_detector = {
    .type = 31, .version = 0, .name = "PaypalOauth", .custom_name = "",
    .description = "PaypalOauth is used for authenticating with PayPal's API. These credentials can be used to access and perform transactions on behalf of a PayPal account.",
    .keywords = paypal_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = paypal_scan,
};

int br_paypaloauth_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return paypal_fail(error, "invalid PaypalOauth detector output");
    *out = NULL;
    if (!paypal_detector.state) {
        br_regex *id = NULL, *key = NULL;
        if (br_regex_compile(paypal_id_pattern, &id, error) != 0) return -1;
        if (br_regex_compile(paypal_key_pattern, &key, error) != 0) {
            br_regex_free(id);
            return -1;
        }
        paypal_state.id = id;
        paypal_state.key = key;
        paypal_detector.state = &paypal_state;
    }
    *out = &paypal_detector;
    return 0;
}
