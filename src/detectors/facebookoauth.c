/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/facebookoauth/facebookoauth.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *id, *secret; } facebookoauth_patterns;

static int facebookoauth_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static bool facebookoauth_verify(const br_scan_ctx *ctx, br_slice id, br_slice secret,
                                 br_result *result)
{
    static const char prefix[] = "https://graph.facebook.com/me?access_token=";
    char url[sizeof(prefix) + 18 + 1 + 32];
    _Static_assert(sizeof(url) == 95, "FacebookOAuth URL must fit 94 bytes plus NUL");
    /* Independent private captures guarantee 15..18 digits and 32 alnum bytes.
     * Prepare the COMPLETE literal-pipe URL BEFORE context-bound construction,
     * without escaping, formatting, a heap copy or a scanner-local cap. */
    size_t at = sizeof(prefix) - 1;
    memcpy(url, prefix, at);
    memcpy(url + at, id.data, id.len); at += id.len;
    url[at++] = '|';
    memcpy(url + at, secret.data, secret.len); at += secret.len;
    url[at] = '\0';
    if (!ctx) return false; /* Constructor failure SKIPS this product. */

    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the WHOLE mixed shared setup/allocation/Do error domain. There
     * is no verification-error setter or diagnostic classifier in the source. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Keep the complete stack URL live through BOTH send and release. Source
     * scan-defers Close only after successful Do and ignores response bodies.
     * Eager buffering/release, Reader/close timing, private clients, full SANE/
     * RE2 and global engine/output behavior remain parity gaps. */
    br_http_release(ctx, &response);
    free(transport_error);
    return true;
}

static int facebookoauth_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                             br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return facebookoauth_fail(error, "invalid or uninitialized FacebookOAuth scan");
    const facebookoauth_patterns *patterns = detector->state;
    size_t original_len = out->len;
    br_captures ids = {0}, secrets = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->id, input, &ids, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->secret, input, &secrets, false, &owned_error);
    /* Preserve original ID-major occurrence products, including duplicates.
     * TrimSpace is a no-op. The 1024 engine hint is NOT a local distance cap. */
    for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
        br_slice id = br_captures_at(&ids, i);
        for (size_t s = 0; rc == 0 && s < secrets.len; ++s) {
            br_slice secret = br_captures_at(&secrets, s);
            br_result result = {0};
            bool keep = true;
            /* Raw is SECRET, never ID. Reuse the pair builder's resources, but
             * overwrite ONLY its V2 order with source's ID+SECRET. */
            if (br_finding_pair_bytes(&result, detector->type, secret, "secret", id, "id", (br_slice){0}) != 0)
                rc = facebookoauth_fail(&owned_error, "cannot create FacebookOAuth result");
            if (rc == 0) {
                memcpy(result.raw_v2.data, id.data, id.len);
                memcpy(result.raw_v2.data + id.len, secret.data, secret.len);
                result.redacted = strdup((const char *)id.data); /* Captures have a trailing NUL. */
                if (!result.redacted)
                    rc = facebookoauth_fail(&owned_error, "cannot create FacebookOAuth result");
            }
            /* Finding/RawV2/Redacted resources precede URL prep and all skips. */
            if (rc == 0 && verify) keep = facebookoauth_verify(ctx, id, secret, &result);
            if (rc == 0 && keep && br_results_push(out, &result) != 0)
                rc = facebookoauth_fail(&owned_error, "cannot append FacebookOAuth result");
            br_result_clear(&result);
            /* No uniqueness, equality skip, verified break, cache or filtering. */
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&ids);
    br_captures_clear(&secrets);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const facebookoauth_keywords[] = {"facebook"};
static facebookoauth_patterns facebookoauth_state;
static br_detector facebookoauth_detector = {
    .type = 40, .version = 0, .name = "FacebookOAuth", .custom_name = "",
    .description = "Facebook OAuth tokens are used to authenticate users and provide access to Facebook's API services.",
    .keywords = facebookoauth_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = facebookoauth_scan,
};

int br_facebookoauth_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return facebookoauth_fail(error, "invalid FacebookOAuth detector output");
    *out = NULL;
    if (!facebookoauth_detector.state) {
        facebookoauth_patterns patterns = {0};
        if (br_regex_compile_prefixed(facebookoauth_keywords, 1, "\\b([0-9]{15,18})\\b", &patterns.id, error) != 0 ||
            br_regex_compile_prefixed(facebookoauth_keywords, 1, "\\b([A-Za-z0-9]{32})\\b", &patterns.secret, error) != 0) {
            br_regex_free(patterns.id);
            br_regex_free(patterns.secret);
            return -1;
        }
        facebookoauth_state = patterns;
        facebookoauth_detector.state = &facebookoauth_state;
    }
    *out = &facebookoauth_detector;
    return 0;
}
