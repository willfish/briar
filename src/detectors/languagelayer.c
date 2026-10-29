/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/languagelayer/languagelayer.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int languagelayer_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static bool body_has_needle(br_slice body)
{
    static const char results[] = "results";
    static const char restricted[] =
        "\"info\":\"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption.\"";
    const br_slice needles[] = {
        {(const unsigned char *)results, sizeof(results) - 1},
        {(const unsigned char *)restricted, sizeof(restricted) - 1},
    };
    if (!body.data) return false;
    for (size_t i = 0; i < sizeof(needles) / sizeof(needles[0]); ++i)
        if (br_slice_find(body, needles[i], 0) != SIZE_MAX) return true;
    return false;
}

/* The caller built the raw query URL and checked the key. Timeout 0 selects
 * the SANE profile default. The URL must live through the single release.
 * Source closes only after a successful ReadAll, so a read error leaks that
 * close. An attempted send still releases once here, including send failure
 * and body_error; those branches do not project the body. A successful send
 * with no body_error rejects a NULL data pointer and nonzero length before
 * status or marker search. A valid body is then searched for the exact needles
 * and verifies only for status 200-299 when one matches. No setter. */
static int languagelayer_verify(const br_scan_ctx *ctx, const char *url, int32_t type,
                                br_result *result, char **error)
{
    const br_http_request request = {
        .method = "GET",
        .url = url,
        .profile = BR_HTTP_SANE,
        .timeout_ms = 0,
        .detector_type = type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &transport_error);
    free(transport_error);
    int rc = 0;
    if (send_rc == 0 && !response.body_error) {
        if (!response.body.data && response.body.len)
            rc = languagelayer_fail(error, "invalid LanguageLayer response body");
        else {
            bool needle = body_has_needle(response.body);
            if (response.status >= 200 && response.status < 300 && needle)
                result->verified = true;
        }
    }
    br_http_release(ctx, &response);
    return rc;
}

static int languagelayer_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                              br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return languagelayer_fail(error, "invalid or uninitialized LanguageLayer scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* unique=false keeps duplicates with separate keywords in source order. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        /* TrimSpace is a no-op for this alphabet. Finding failure is fatal
         * before URL construction, the nil-context drop, send, or publication. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = languagelayer_fail(&owned_error, "cannot create LanguageLayer result");
        else if (verify) {
            static const char prefix[] = "https://api.languagelayer.com/languages?access_key=";
            char url[sizeof(prefix) + 32];
            /* Bounded stack URL and key checks run before a nil-context drop.
             * A failed check is fatal. Construction does not allocate. */
            if (key.len != 32 || !key.data)
                rc = languagelayer_fail(&owned_error, "invalid LanguageLayer key");
            else {
                memcpy(url, prefix, sizeof(prefix) - 1);
                memcpy(url + sizeof(prefix) - 1, key.data, 32);
                url[sizeof(url) - 1] = '\0';
                if (!ctx) {
                    /* Constructor drop: no append, send, prepare, or release. */
                } else if (languagelayer_verify(ctx, url, detector->type, &result, &owned_error) != 0)
                    rc = -1;
                else if (br_results_push(out, &result) != 0)
                    rc = languagelayer_fail(&owned_error, "cannot append LanguageLayer result");
            }
        } else if (br_results_push(out, &result) != 0)
            rc = languagelayer_fail(&owned_error, "cannot append LanguageLayer result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const languagelayer_keywords[] = {"languagelayer"};
static br_detector languagelayer_detector = {
    .type = 489,
    .version = 0,
    .name = "LanguageLayer",
    .custom_name = "",
    .description = "LanguageLayer is an API service for language detection. The access key can be used to authenticate and use the API.",
    .keywords = languagelayer_keywords,
    .nkeywords = 1,
    .max_secret_size = -1,
    .start_offset = -1,
    .max_credential_span = -1,
    .scan = languagelayer_scan,
};

int br_languagelayer_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return languagelayer_fail(error, "invalid LanguageLayer detector output");
    *out = NULL;
    if (!languagelayer_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(languagelayer_detector.keywords, languagelayer_detector.nkeywords,
                                      "\\b([a-z0-9]{32})\\b", &regex, error) != 0)
            return -1;
        languagelayer_detector.state = regex;
    }
    *out = &languagelayer_detector;
    return 0;
}
