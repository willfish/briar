/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/braintreepayments. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } braintree_patterns;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int set_cause(br_result *result, const char *cause)
{
    const br_slice secret = {result->raw.data, result->raw.len};
    /* Only the private key is redacted. The public ID is deliberately absent
     * from the result and from the source's verification-error secret list. */
    return br_result_set_verification_error(result, cause, &secret, 1) ? -1 : 0;
}

static int verify_braintree(const br_scan_ctx *ctx, br_slice public_id, br_slice private_key, br_result *result)
{
    if (!ctx) return set_cause(result, "net/http: nil Context");
    char *auth = NULL, *auth_error = NULL;
    if (br_http_basic_auth(public_id, private_key, &auth, &auth_error)) {
        free(auth); free(auth_error);
        return -1; /* Core +1 is a resource failure, not a provider outcome. */
    }
    static const unsigned char payload[] = "{\"query\": \"query { ping }\"}";
    const br_header headers[] = {
        {"Content-Type", "application/json"}, {"Braintree-Version", "2019-01-01"}, {"Authorization", auth},
    };
    const br_http_request request = {
        .method = "POST", .url = "https://payments.braintree-api.com/graphql",
        .headers = headers, .nheaders = 3, .body = {payload, sizeof(payload) - 1},
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL;
    char status_error[80]; const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error)) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else if (response.body_error) {
        /* Source ReadAll happens before EVERY status check, including 401. */
        cause = response.body_error;
    } else if (response.status != 200) {
        snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        cause = status_error;
    } else {
        static const unsigned char marker[] = "\"data\":{";
        result->verified = br_slice_find(response.body, (br_slice){marker, sizeof(marker) - 1}, 0) != SIZE_MAX;
    }
    int rc = set_cause(result, cause);
    /* Source installs its defer only AFTER successful ReadAll and leaks that
     * response on read failure. Always release C-owned responses instead; Go
     * streaming/drain/close lifecycle parity is explicitly not claimed. Native
     * SANE POST redirect guards remain fail-closed, without another profile. */
    br_http_release(ctx, &response);
    free(transport_error); free(auth_error); free(auth);
    return rc ? -1 : 0;
}

static int scan_braintree(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized BraintreePayments scan");
    const braintree_patterns *compiled = detector->state;
    if (!compiled->key || !compiled->id) return fail(error, "uninitialized BraintreePayments patterns");
    br_captures keys = {0}, ids = {0}; char *owned_error = NULL;
    size_t original_len = out->len;
    int rc = br_captures_find(compiled->key, input, &keys, false, &owned_error);
    if (!rc) rc = br_captures_find(compiled->id, input, &ids, false, &owned_error);
    /* TrimSpace is a no-op for both alphabets. Preserve every occurrence and
     * the complete key-major/ID-minor product, including duplicate pairs. */
    for (size_t key = 0; !rc && key < keys.len; ++key) {
        for (size_t id = 0; !rc && id < ids.len; ++id) {
            br_result result = {0};
            if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, key), "key"))
                rc = fail(&owned_error, "cannot create BraintreePayments result");
            if (!rc && verify && verify_braintree(ctx, br_captures_at(&ids, id), br_captures_at(&keys, key), &result))
                rc = fail(&owned_error, "cannot verify BraintreePayments candidate");
            if (!rc && br_results_push(out, &result)) rc = fail(&owned_error, "cannot append BraintreePayments result");
            br_result_clear(&result);
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys); br_captures_clear(&ids);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static braintree_patterns patterns;
static const char *const keywords[] = {"braintree"};
static const br_detector braintree = {
    .type = 828, .version = 0, .name = "BraintreePayments", .custom_name = "",
    .description = "Braintree is a full-stack payment platform that makes it easy to accept payments in your mobile app or website. Braintree API keys can be used to access and manage payment transactions, customer data, and other payment-related operations.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_braintree,
};

int br_braintreepayments_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid BraintreePayments detector output");
    *out = NULL;
    if (!patterns.key && br_regex_compile_prefixed(keywords, 1, "\\b([0-9a-f]{32})\\b", &patterns.key, error)) return -1;
    if (!patterns.id && br_regex_compile_prefixed(keywords, 1, "\\b([0-9a-z]{16})\\b", &patterns.id, error)) return -1;
    /* Default production path only. Source's private useTestURL sandbox flag
     * has no public ABI1 configuration seam; do not invent one here. */
    *out = &braintree;
    return 0;
}
