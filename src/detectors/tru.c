/* SPDX-License-Identifier: AGPL-3.0-only */
/*
 * Tru, from pinned TruffleHog pkg/detectors/tru/tru.go.
 * The upstream constructor is not registered, so this detector stays out of
 * the default set, but the implementation is still required. Every key is
 * paired with every secret. RawV2 is key+secret. Basic auth is key:secret.
 */
#include "captures.h"
#include "detectors.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *const prefix[] = {"tru", NULL};
static const char url[] = "https://eu.api.tru.id/oauth2/v1/token";
static const char body[] = "grant_type=client_credentials";
static br_regex *key_re, *secret_re;

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int verify(const br_scan_ctx *ctx, const char *auth, br_result *result, char **error)
{
    (void)error;
    br_slice payload = {(const unsigned char *)body, sizeof(body) - 1};
    if (!ctx) return 1;
    const br_header headers[] = {
        {"Content-Type", "application/x-www-form-urlencoded"},
        {"Authorization", auth},
    };
    const br_http_request request = {
        .method = "POST", .url = url, .headers = headers, .nheaders = 2, .body = payload,
        .timeout_ms = 5000, .detector_type = 605, .profile = BR_HTTP_SANE,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int rc = br_http_send(ctx, &request, &response, &transport_error);
    if (!rc && response.status >= 200 && response.status < 300) result->verified = true;
    br_http_release(ctx, &response);
    free(transport_error);
    return 0;
}

static int scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify_requested,
                br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !key_re || !secret_re || !out || (!input.data && input.len))
        return fail(error, "invalid Tru scan arguments");
    size_t original = out->len;
    br_captures keys = {0}, secrets = {0};
    char *owned = NULL;
    int rc = 0;
    if (br_captures_find(key_re, input, &keys, false, &owned) ||
        br_captures_find(secret_re, input, &secrets, false, &owned))
        rc = -1;
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        for (size_t s = 0; !rc && s < secrets.len; ++s) {
            const char *key = keys.items[k], *secret = secrets.items[s];
            br_result result = {0};
            br_slice key_s = {(const unsigned char *)key, strlen(key)};
            br_slice secret_s = {(const unsigned char *)secret, strlen(secret)};
            char *auth = NULL;
            int outcome = 0;
            if (br_finding_pair_bytes(&result, detector->type, key_s, "key", secret_s, "secret", (br_slice){0}) != 0)
                rc = fail(&owned, "cannot create Tru finding");
            else if (verify_requested && br_http_basic_auth((br_slice){(const unsigned char *)key, strlen(key)},
                                                             (br_slice){(const unsigned char *)secret, strlen(secret)},
                                                             &auth, &owned) != 0)
                rc = -1;
            else if (verify_requested && (outcome = verify(ctx, auth, &result, &owned)) < 0)
                rc = -1;
            else if (!outcome && br_results_push(out, &result) != 0)
                rc = fail(&owned, "cannot append Tru finding");
            free(auth);
            br_result_clear(&result);
        }
    }
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&secrets);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static br_detector detector = {
    .name = "Tru", .type = 605, .description =
        "Tru is a service that provides APIs for phone number verification and other identity verification services. Tru credentials can be used to access these APIs and perform verification operations.",
    .keywords = (const char *[]){"tru", NULL}, .nkeywords = 1, .scan = scan,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .custom_name = "",
};

int br_tru_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Tru detector output");
    *out = NULL;
    if ((!key_re && br_regex_compile_prefixed(prefix, 1, "\\b([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\\b", &key_re, error) != 0) ||
        (!secret_re && br_regex_compile_prefixed(prefix, 1, "\\b([0-9a-zA-Z.-_]{26})\\b", &secret_re, error) != 0))
        return -1;
    detector.state = key_re;
    *out = &detector;
    return 0;
}
