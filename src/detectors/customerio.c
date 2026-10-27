/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/customerio/customerio.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

static int customerio_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int customerio_verify(const br_scan_ctx *ctx, br_slice key, br_slice id,
                              br_result *result, bool *keep, char **error)
{
    /* This POST MUTATES a remote customer by recording a purchase. Acceptance
     * must use synthetic credentials and an injected offline transport only. */
    static const unsigned char payload[] =
        "name=purchase&data%5Bprice%5D=23.45&data%5Bproduct%5D=socks";
    /* Source prepares payload and standard Base64(ID + ':' + KEY) BEFORE the
     * context-bound constructor. Fixed 20-byte captures need no heap copies. */
    unsigned char credentials[41];
    memcpy(credentials, id.data, 20);
    credentials[20] = ':';
    memcpy(credentials + 21, key.data, 20);
    char authorization[63];
    memcpy(authorization, "Basic ", 6);
    if (EVP_EncodeBlock((unsigned char *)authorization + 6, credentials, sizeof(credentials)) != 56)
        return customerio_fail(error, "CustomerIO native Base64 encoding failed");
    authorization[62] = '\0'; /* 56 Base64 bytes, exactly one '=', plus Basic. */
    if (!ctx) {
        *keep = false;
        return 0;
    }
    const br_header headers[] = {
        {"Content-Type", "application/x-www-form-urlencoded"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "POST", .url = "https://track.customer.io/api/v1/customers/5/events",
        .headers = headers, .nheaders = 2, .body = {payload, sizeof(payload) - 1},
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the WHOLE combined shared setup/allocation/Do domain, without
     * diagnostic classification or a verification-error setter. Own finding
     * and encoding failures stay fatal, outside this domain. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Stack auth remains live through send AND release. Source scan-defers
     * Close ONLY and ignores body/read errors. Eager buffering/release, native
     * POST redirects/full client and global engine/output parity stay partial. */
    br_http_release(ctx, &response);
    free(transport_error);
    return 0;
}

static int customerio_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return customerio_fail(error, "invalid or uninitialized CustomerIO scan");
    size_t original_len = out->len;
    br_captures occurrences = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &occurrences, false, &owned_error);
    /* The two upstream patterns are IDENTICAL. Share their occurrence storage,
     * but retain the complete key-major N squared product, including self-pairs
     * and duplicates. TrimSpace is a no-op; do not consume/deduplicate matches. */
    for (size_t k = 0; rc == 0 && k < occurrences.len; ++k) {
        br_slice key = br_captures_at(&occurrences, k);
        for (size_t i = 0; rc == 0 && i < occurrences.len; ++i) {
            br_result result = {0};
            br_slice id = br_captures_at(&occurrences, i);
            bool keep = true;
            /* Finding resources precede payload/auth preparation and any skip. */
            if (br_finding_pair_bytes(&result, detector->type, key, "key", id, "id", (br_slice){0}) != 0)
                rc = customerio_fail(&owned_error, "cannot create CustomerIO result");
            if (rc == 0 && verify && customerio_verify(ctx, key, id, &result, &keep, &owned_error) != 0)
                rc = -1;
            if (rc == 0 && keep && br_results_push(out, &result) != 0)
                rc = customerio_fail(&owned_error, "cannot append CustomerIO result");
            br_result_clear(&result);
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&occurrences);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const customerio_keywords[] = {"customerio"};
static br_detector customerio_detector = {
    .type = 211, .version = 0, .name = "CustomerIO", .custom_name = "",
    .description = "CustomerIO is a platform for sending automated emails, push notifications, and SMS messages. CustomerIO API keys can be used to interact with the CustomerIO service to manage customer data and trigger events.",
    .keywords = customerio_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = customerio_scan,
};

int br_customerio_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return customerio_fail(error, "invalid CustomerIO detector output");
    *out = NULL;
    if (!customerio_detector.state) {
        /* Dispatch says customerio, but BOTH source patterns use customer.
         * Compile that exact prefix, with case-insensitivity scoped to it. */
        static const char *const extraction_keywords[] = {"customer"};
        br_regex *compiled = NULL;
        if (br_regex_compile_prefixed(extraction_keywords, 1, "\\b([a-z0-9A-Z]{20})\\b", &compiled, error) != 0)
            return -1;
        customerio_detector.state = compiled;
    }
    *out = &customerio_detector;
    return 0;
}
