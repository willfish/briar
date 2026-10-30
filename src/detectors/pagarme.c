/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/pagarme/pagarme.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int pagarme_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* The body contains the key. After this attempt's release, it must not remain readable. */
static void pagarme_forget_body(char *body)
{
    if (!body) return;
    memset(body, 'X', 52);
    free(body);
}

static int pagarme_set_error(br_result *result, const char *cause, br_slice key, char **error)
{
    /* NULL cause is a checked no-op. +1 is fatal. The key is the one redaction secret. */
    if (br_result_set_verification_error(result, cause, &key, 1) != 0)
        return pagarme_fail(error, "cannot sanitize Pagarme verification error");
    return 0;
}

/* Go closes the body inside verifyMatch, before SetVerificationError and before
 * append. Do not retain the response until scan return. The stack header array
 * dies at send return and is not retained. The original body stays alive through
 * send and that attempt's own release. */
static int pagarme_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    static const char url[] = "https://api.pagar.me/1/balance";
    static const char prefix[] = "{\"api_key\":\"";
    static const char suffix[] = "\"}";
    _Static_assert(sizeof(url) - 1 == 30, "Pagarme URL");
    _Static_assert(sizeof(prefix) - 1 == 12, "Pagarme body prefix");
    _Static_assert(sizeof(suffix) - 1 == 2, "Pagarme body suffix");
    if (key.len != 38) return pagarme_fail(error, "invalid Pagarme capture");
    /* Allocate before the nil-context check. Failure is fatal even when ctx is nil.
     * No encoding. The value is the prefix, the raw key, and the suffix. */
    char *body = malloc(12 + key.len + 2 + 1);
    if (!body) return pagarme_fail(error, "cannot allocate Pagarme body");
    memcpy(body, prefix, 12);
    memcpy(body + 12, key.data, key.len);
    memcpy(body + 12 + key.len, suffix, 2);
    body[12 + key.len + 2] = '\0';
    /* Source sets a header before checking the constructor error, so a nil
     * context panics. Do not panic and do not set a header on a missing request. */
    if (!ctx) {
        pagarme_forget_body(body);
        if (pagarme_set_error(result, "net/http: nil Context", key, error) != 0) return -1;
        return 0;
    }
    br_http_response response = {0};
    char *transport_error = NULL;
    int send_rc;
    {
        const br_header headers[] = {{"Content-Type", "application/json"}};
        const br_http_request request = {
            .method = "GET", .url = url, .headers = headers, .nheaders = 1,
            .body = {(const unsigned char *)body, 52},
            .profile = BR_HTTP_SANE, .timeout_ms = 5000,
            .detector_type = result->detector_type,
        };
        send_rc = br_http_send(ctx, &request, &response, &transport_error);
    }
    if (send_rc != 0) {
        /* Do or preparation failed. Release once while the original body is
         * intact, free it, then pass the reached cause through. Do not invent one. */
        br_http_release(ctx, &response);
        pagarme_forget_body(body);
        int rc = pagarme_set_error(result, transport_error, key, error);
        free(transport_error);
        return rc;
    }
    free(transport_error);
    /* Decide before release. Body and read errors do not change the verdict. */
    const char *cause = NULL;
    char status_error[64];
    int status = response.status;
    if (status >= 200 && status < 300) {
        result->verified = true;
    } else if (status != 401) {
        int n = snprintf(status_error, sizeof(status_error),
                         "unexpected HTTP response status %d", status);
        if (n < 0 || (size_t)n >= sizeof(status_error)) {
            br_http_release(ctx, &response);
            pagarme_forget_body(body);
            return pagarme_fail(error, "cannot format Pagarme status cause");
        }
        cause = status_error;
    }
    /* Close inside verify, before the setter and before publication.
     * Setter +1 must not release again. */
    br_http_release(ctx, &response);
    pagarme_forget_body(body);
    return pagarme_set_error(result, cause, key, error);
}

static int pagarme_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return pagarme_fail(error, "invalid or uninitialized Pagarme scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* Direct regex, not a prefix. unique keeps first-seen order. Source uses a
     * map, which does not preserve order and does not keep every duplicate. */
    int rc = br_captures_find(detector->state, input, &keys, true, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 38)
            rc = pagarme_fail(&owned_error, "invalid Pagarme capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = pagarme_fail(&owned_error, "cannot create Pagarme finding");
        if (!rc && verify)
            rc = pagarme_verify(ctx, key, &result, &owned_error);
        if (!rc && br_results_push(out, &result) != 0)
            rc = pagarme_fail(&owned_error, "cannot append Pagarme finding");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const pagarme_keywords[] = {"ak_live_"};
static br_detector pagarme_detector = {
    .type = 985, .version = 0, .name = "Pagarme", .custom_name = "",
    .description = "Pagarme is a payment service provider. Pagarme API keys can be used to access and manage payment transactions and other related services.",
    .keywords = pagarme_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = pagarme_scan,
};

int br_pagarme_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return pagarme_fail(error, "invalid Pagarme detector output");
    *out = NULL;
    if (!pagarme_detector.state) {
        br_regex *regex = NULL;
        /* The keyword is inside the capture. A prefixed helper would require it twice. */
        if (br_regex_compile("\\b(ak_live_[a-zA-Z0-9]{30})\\b", &regex, error) != 0) return -1;
        pagarme_detector.state = regex;
    }
    *out = &pagarme_detector;
    return 0;
}
