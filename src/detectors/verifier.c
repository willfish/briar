/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/verifier/verifier.go. */
#include "detectors.h"
#include "captures.h"
#include "email_pattern.h"
#include "findings.h"
#include "../go_url.h"

#include <stdlib.h>
#include <string.h>

typedef enum { VER_ABORT = -1, VER_KEEP = 0, VER_SKIP = 1 } ver_outcome;

static int ver_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static ver_outcome ver_verify(const br_scan_ctx *ctx, br_slice key, br_slice email,
                              br_result *result, char **error)
{
    /* The complete URL is built before the nil-context drop. The captured
     * classes cannot make this URL fail to parse; a parser rejection is still
     * fatal rather than an ordinary skip. */
    static const char prefix[] = "https://verifier.meetchopra.com/verify/";
    static const char query[] = "?token=";
    if (key.len > SIZE_MAX - sizeof(prefix) - sizeof(query) ||
        email.len > SIZE_MAX - sizeof(prefix) - sizeof(query) - key.len)
        return ver_fail(error, "cannot build Verifier URL"), VER_ABORT;
    char *url = malloc(sizeof(prefix) - 1 + email.len + sizeof(query) - 1 + key.len + 1);
    if (!url) return ver_fail(error, "cannot build Verifier URL"), VER_ABORT;
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, email.data, email.len);
    memcpy(url + sizeof(prefix) - 1 + email.len, query, sizeof(query) - 1);
    memcpy(url + sizeof(prefix) - 1 + email.len + sizeof(query) - 1, key.data, key.len);
    url[sizeof(prefix) - 1 + email.len + sizeof(query) - 1 + key.len] = '\0';
    ver_outcome outcome = VER_KEEP;
    if (!ctx) {
        outcome = VER_SKIP;
    } else {
        br_go_url_parts parts = {0};
        br_go_url_error parsed = {0};
        char *fatal = NULL;
        int rc = br_go_url_parse((br_slice){(const unsigned char *)url, strlen(url)}, &parts, &parsed, &fatal);
        if (rc != 0 || parsed.kind != BR_GO_URL_OK) {
            ver_fail(error, fatal ? fatal : "invalid Verifier URL");
            free(fatal);
            br_go_url_clear(&parts);
            outcome = VER_ABORT;
        } else {
            br_go_url_clear(&parts);
            const br_http_request request = {
                .method = "GET", .url = url, .profile = BR_HTTP_SANE,
                .detector_type = result->detector_type,
            };
            br_http_response response = {0};
            char *transport_error = NULL;
            /* Do failures stay unverified with no setter. Body and read errors
             * are ignored. Only 2xx verifies. */
            if (br_http_send(ctx, &request, &response, &transport_error) == 0)
                result->verified = response.status >= 200 && response.status < 300;
            br_http_release(ctx, &response);
            free(transport_error);
        }
    }
    free(url);
    return outcome;
}

static int ver_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                    br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return ver_fail(error, "invalid or uninitialized Verifier scan");
    const br_regex *const *patterns = detector->state;
    size_t original_len = out->len;
    br_captures keys = {0}, emails = {0};
    char *owned_error = NULL;
    /* Keys keep ordered duplicates. Emails are unique; first seen is one
     * possible map order. The finding stores only the key. */
    int rc = br_captures_find(patterns[0], input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns[1], input, &emails, true, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 96) {
            ver_fail(&owned_error, "invalid Verifier key capture");
            rc = -1;
            break;
        }
        for (size_t j = 0; j < emails.len; ++j) {
            br_slice email = br_captures_at(&emails, j);
            br_result result = {0};
            ver_outcome outcome = VER_KEEP;
            if (!email.len) {
                ver_fail(&owned_error, "invalid Verifier email capture");
                outcome = VER_ABORT;
            } else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
                ver_fail(&owned_error, "cannot create Verifier result");
                outcome = VER_ABORT;
            } else if (verify) {
                outcome = ver_verify(ctx, key, email, &result, &owned_error);
            }
            if (outcome == VER_KEEP && br_results_push(out, &result) != 0) {
                ver_fail(&owned_error, "cannot append Verifier result");
                outcome = VER_ABORT;
            }
            br_result_clear(&result);
            if (outcome == VER_ABORT) {
                rc = -1;
                break;
            }
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&emails);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const ver_keywords[] = {"verifier"};
static br_regex *ver_patterns[2];
static br_detector ver_detector = {
    .type = 373, .version = 0, .name = "Verifier", .custom_name = "",
    .description = "Verifier is a service used to verify the authenticity of a credential. The tokens can be used to validate user identities.",
    .keywords = ver_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = ver_scan, .state = ver_patterns,
};

int br_verifier_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return ver_fail(error, "invalid Verifier detector output");
    *out = NULL;
    if (!ver_patterns[0]) {
        const char *const prefix[] = {"verifier"};
        if (br_regex_compile_prefixed(prefix, 1, "\\b([a-z0-9]{96})\\b", &ver_patterns[0], error) != 0 ||
            br_regex_compile_prefixed(prefix, 1, br_email_pattern, &ver_patterns[1], error) != 0)
            return -1;
    }
    *out = &ver_detector;
    return 0;
}
