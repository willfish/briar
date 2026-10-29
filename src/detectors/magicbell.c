/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/magicbell/magicbell.go. */
#include "detectors.h"
#include "captures.h"
#include "email_pattern.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *email; } magicbell_patterns;

static int magicbell_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static void magicbell_verify(const br_scan_ctx *ctx, const char *key,
                              const char *email, br_result *result)
{
    /* Preserve source Header.Add order and Go-canonical names. Do not reject
     * quoted/control-byte emails here: header guards belong to the mixed Do
     * domain, whose errors the source suppresses without a setter. */
    const br_header headers[] = {
        {"X-Magicbell-Api-Key", key},
        {"X-Magicbell-User-Email", email},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.magicbell.com/notification_preferences",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Provider-original key/email/header storage survives one release per
     * attempt. Prepared headers/UA end at send return, not at release. */
    br_http_release(ctx, &response);
    free(send_error);
}

static int magicbell_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return magicbell_fail(error, "invalid or uninitialized MagicBell scan");
    const magicbell_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->email)
        return magicbell_fail(error, "uninitialized MagicBell patterns");
    size_t original_len = out->len;
    br_captures keys = {0}, emails = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    /* Source collects ALL emails even with zero keys or NoV. Capture 1 is the
     * full address. Both grammars have non-space outer bytes, so TrimSpace is
     * a no-op, including quoted local parts with internal control bytes. */
    if (rc == 0) rc = br_captures_find(patterns->email, input, &emails, true, &owned_error);
    /* Key occurrence order is specified; first-seen email-set order is one
     * realization of Go-map iteration. No span cap or finding deduplication. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        for (size_t e = 0; rc == 0 && e < emails.len; ++e) {
            br_result result = {0};
            if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, k), "key") != 0)
                rc = magicbell_fail(&owned_error, "cannot create MagicBell finding");
            /* Email is required but hidden in every output field. A complete
             * finding precedes the fixed constructor's nil-context skip. */
            if (rc == 0 && (!verify || ctx)) {
                if (verify) magicbell_verify(ctx, keys.items[k], emails.items[e], &result);
                if (br_results_push(out, &result) != 0)
                    rc = magicbell_fail(&owned_error, "cannot append MagicBell finding");
            }
            br_result_clear(&result);
        }
    }
    if (rc != 0) {
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
        magicbell_fail(&owned_error, "cannot collect MagicBell credentials");
    }
    br_captures_clear(&emails);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const magicbell_keywords[] = {"magicbell"};
static magicbell_patterns magicbell_compiled;
static br_detector magicbell_detector = {
    .type = 786, .version = 0, .name = "MagicBell", .custom_name = "",
    .description = "MagicBell is a notification service. API keys can be used to manage and send notifications.",
    .keywords = magicbell_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = magicbell_scan,
};

int br_magicbell_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return magicbell_fail(error, "invalid MagicBell detector output");
    *out = NULL;
    if (!magicbell_detector.state) {
        magicbell_patterns patterns = {0};
        int rc = br_regex_compile_prefixed(magicbell_keywords, 1,
            "\\b([a-zA-Z-0-9]{40})\\b", &patterns.key, error);
        if (rc == 0) rc = br_regex_compile(br_email_pattern, &patterns.email, error);
        if (rc != 0) {
            br_regex_free(patterns.email);
            br_regex_free(patterns.key);
            return -1;
        }
        magicbell_compiled = patterns;
        magicbell_detector.state = &magicbell_compiled;
    }
    *out = &magicbell_detector;
    return 0;
}
