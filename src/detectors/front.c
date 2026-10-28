/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/front/front.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int front_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void front_verify(const br_scan_ctx *ctx, br_slice key, br_result *result)
{
    /* Constructor's known nil-context skip has passed. Accept FIRST, then the
     * complete Bearer value. Source grammar bounds bytes to 36 + rune4 + 244;
     * 292 stack bytes fit prefix7 + KEY284 + NUL, no formatter/heap copy/cap. */
    br_header headers[2] = {{"Accept", "application/json"}};
    char authorization[292];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, key.len);
    authorization[key.len + 7] = '\0';
    /* ABI1 C-string headers cannot carry NUL. Only AFTER constructor AND full
     * assembly, retain false/no error/zero IO, never truncate into success.
     * Other Unicode/control bytes keep existing WHOLE-domain header policies. */
    if (memchr(key.data, '\0', key.len)) return;
    headers[1] = (br_header){"Authorization", authorization};
    const br_http_request request = {
        .method = "GET", .url = "https://api2.frontapp.com/accounts", .profile = BR_HTTP_SANE,
        .headers = headers, .nheaders = 2, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the WHOLE mixed shared setup/allocation/Do domain, keeping a
     * false finding without setter/classifier. All successful-send 2xx verify;
     * body contents and read errors are deliberately ignored. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Complete stack authorization remains live through send AND release.
     * Source scan-defers Close; ABI1 eagerly reads/releases even failures. Full
     * Reader/native/private client/regexp and global parity remain partial. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int front_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return front_fail(error, "invalid or uninitialized Front scan");
    size_t original_len = out->len;
    br_captures keys = {0}; char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        /* TrimSpace is a no-op for first/last alphabets. Preserve original
         * occurrences, duplicates, wildcard Unicode/NUL and byte lengths. Own
         * finding resources precede constructor skip/header guard/suppression. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = front_fail(&owned_error, "cannot create Front result");
        else if (!verify || ctx) {
            if (verify) front_verify(ctx, br_captures_at(&keys, i), &result);
            if (br_results_push(out, &result) != 0)
                rc = front_fail(&owned_error, "cannot append Front result");
        }
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const front_keywords[] = {"front"};
static br_detector front_detector = {
    .type = 427, .version = 0, .name = "Front", .custom_name = "",
    .description = "Front is a customer communication hub that allows teams to manage email, social media, SMS, and other channels in one place. Front API keys can be used to access and manage this communication data.",
    .keywords = front_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = front_scan,
};

int br_front_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return front_fail(error, "invalid Front detector output");
    *out = NULL;
    /* FIRST separator is an arbitrary RUNE except LF, not a literal JWT dot.
     * Keep source greedy ending-word-boundary backtracking, not full-token validation. */
    if (br_key_pattern_init(&front_detector,
            "\\b([0-9a-zA-Z]{36}.[0-9a-zA-Z\\.\\-\\_]{188,244})\\b", error) != 0) return -1;
    *out = &front_detector;
    return 0;
}
