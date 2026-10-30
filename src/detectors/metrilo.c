/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/metrilo/metrilo.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int metrilo_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static void metrilo_verify(const br_scan_ctx *ctx, const char payload[192], br_result *result)
{
    /* Preserve the source's logical Content-Length header AND complete body.
     * Shared native framing already derives wire length from the body instead. */
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"Content-Length", "0"},
    };
    const br_http_request request = {
        .method = "POST", .url = "https://trk.mtrl.me/category",
        .headers = headers, .nheaders = 2,
        .body = {(const unsigned char *)payload, 191},
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Source suppresses the WHOLE mixed preparation/Do error domain with no
     * setter; any successful 2xx verifies and body/read errors are ignored. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Provider payload/header/key/URL storage survives one release per send.
     * Synthesized prepared headers/UA end at ordinary send return instead. */
    br_http_release(ctx, &response);
    free(send_error);
}

static int metrilo_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return metrilo_fail(error, "invalid or uninitialized Metrilo scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        /* TrimSpace is a no-op on the lowercase ASCII-alphanumeric grammar.
         * Retain original occurrence order, duplicates and key-only fields. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = metrilo_fail(&owned_error, "cannot create Metrilo finding");
        if (rc == 0 && verify) {
            /* Source concatenates the exact payload AFTER the finding but
             * BEFORE the constructor's nil-context skip. Never reserialize. */
            const char prefix[] = "{\"time\":1518004715732,\"token\": \"";
            const char suffix[] = "\" ,\"platform\":\"Wordpress 4.2.7 / Woocommerce 3.5\",\"pluginVersion\":\"1.1.0\",\"params\":{\"id\":\"12\",\"name\":\"Clothing\",\"url\":\"https://dummysite.com\"}}";
            char payload[sizeof(prefix) - 1 + 16 + sizeof(suffix)];
            _Static_assert(sizeof(payload) == 192, "Metrilo payload must contain exactly 191 bytes");
            memcpy(payload, prefix, sizeof(prefix) - 1);
            memcpy(payload + sizeof(prefix) - 1, keys.items[i], 16);
            memcpy(payload + sizeof(prefix) - 1 + 16, suffix, sizeof(suffix));
            if (!ctx) { br_result_clear(&result); continue; }
            metrilo_verify(ctx, payload, &result);
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = metrilo_fail(&owned_error, "cannot append Metrilo finding");
        br_result_clear(&result);
    }
    if (rc != 0) {
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
        metrilo_fail(&owned_error, "cannot collect Metrilo keys");
    }
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const metrilo_keywords[] = {"metrilo"};
static br_detector metrilo_detector = {
    .type = 297, .version = 0, .name = "Metrilo", .custom_name = "",
    .description = "Metrilo is an analytics and CRM platform for e-commerce. Metrilo API keys can be used to access and manage e-commerce data.",
    .keywords = metrilo_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = metrilo_scan,
};

int br_metrilo_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return metrilo_fail(error, "invalid Metrilo detector output");
    *out = NULL;
    if (!metrilo_detector.state) {
        br_regex *pattern = NULL;
        if (br_regex_compile_prefixed(metrilo_keywords, 1, "\\b([a-z0-9]{16})\\b", &pattern, error) != 0) {
            br_regex_free(pattern);
            return -1;
        }
        metrilo_detector.state = pattern;
    }
    *out = &metrilo_detector;
    return 0;
}
