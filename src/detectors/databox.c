/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/databox/databox.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
    DATABOX_ABORT = -1, DATABOX_KEEP = 0, DATABOX_SKIP = 1
} databox_outcome;

static int databox_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static databox_outcome databox_verify(const br_scan_ctx *ctx, br_slice key,
                                      br_result *result, char **error)
{
    /* This POST MUTATES remote metrics. Acceptance must remain offline with
     * synthetic credentials, never a real Databox push or service call. */
    unsigned char credentials[22];
    memcpy(credentials, key.data, 21);
    credentials[21] = ':';
    char authorization[39];
    memcpy(authorization, "Basic ", 6);
    if (EVP_EncodeBlock((unsigned char *)authorization + 6, credentials, sizeof(credentials)) != 32) {
        databox_fail(error, "Databox native Base64 encoding failed");
        return DATABOX_ABORT;
    }
    authorization[38] = '\0'; /* 22 ASCII bytes => 32 standard Base64 bytes, two '='. */
    /* Exact upstream raw literal: retain every tab/space and no final newline.
     * Source prepares both auth and body BEFORE the context-bound constructor. */
    static const unsigned char payload[] =
        "{\n"
        "\t\t\t\t\"data\":[\n"
        "\t\t\t\t  {\n"
        "\t\t\t\t\t\"$sales\": 420,\n"
        "\t\t\t\t\t\"$visitors\": 123000\n"
        "\t\t\t\t  }\n"
        "\t\t\t\t]\n"
        "\t\t\t  }";
    if (!ctx) return DATABOX_SKIP;
    unsigned char dedup_key[25] = "834:";
    memcpy(dedup_key + 4, key.data, 21);
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"Accept", "application/vnd.databox.v2+json"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "POST", .url = "https://push.databox.com",
        .headers = headers, .nheaders = 3,
        .body = {payload, sizeof(payload) - 1},
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
        .dedup_key = {dedup_key, sizeof(dedup_key)}, /* Exact 834:KEY, no NUL. */
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Preserve the nonempty key. ABI1's unchanged shared coalescing guard
     * rejects it BEFORE both injected and native send callbacks. Suppress the
     * WHOLE combined setup/allocation/Do domain, never classifying error text. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0 && response.body_error == NULL)
        result->verified = response.status >= 200 && response.status < 300;
    /* The 2xx/body-ignored branch above is UNEXERCISED behind that guard.
     * Future supported sends must promote any body_error (even "") to Do
     * failure: singleflight ReadAll precedes the source's status inspection.
     * Stack auth/key live through send AND release. Source scan-defers Close
     * only for replay bodies. Eager buffering/release, native POST redirects,
     * full client/coalescing and global engine/output parity remain gaps. */
    br_http_release(ctx, &response);
    free(transport_error);
    return DATABOX_KEEP;
}

static int databox_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return databox_fail(error, "invalid or uninitialized Databox scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        databox_outcome outcome = DATABOX_KEEP;
        /* TrimSpace is a no-op. Retain all occurrences, without uniqueness,
         * entropy, local false-positive filtering or a persistent cache.
         * Finding resources precede encoding/body prep and any constructor skip. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            databox_fail(&owned_error, "cannot create Databox result");
            outcome = DATABOX_ABORT;
        }
        if (outcome == DATABOX_KEEP && verify)
            outcome = databox_verify(ctx, key, &result, &owned_error);
        if (outcome == DATABOX_KEEP && br_results_push(out, &result) != 0) {
            databox_fail(&owned_error, "cannot append Databox result");
            outcome = DATABOX_ABORT;
        }
        br_result_clear(&result);
        if (outcome == DATABOX_ABORT) rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const databox_keywords[] = {"databox"};
static br_detector databox_detector = {
    .type = 834, .version = 0, .name = "Databox", .custom_name = "",
    .description = "Databox is a business analytics platform that pulls all your data into one place, so you can track performance and discover insights in real-time. Databox API keys can be used to access and modify data within your Databox account.",
    .keywords = databox_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = databox_scan,
};

int br_databox_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return databox_fail(error, "invalid Databox detector output");
    *out = NULL;
    if (br_key_pattern_init(&databox_detector, "\\b([0-9a-z]{21})\\b", error) != 0)
        return -1;
    *out = &databox_detector;
    return 0;
}
