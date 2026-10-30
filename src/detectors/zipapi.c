/* SPDX-License-Identifier: AGPL-3.0-only */
/*
 * ZipAPI, from pinned TruffleHog pkg/detectors/zipapi/zipapi.go.
 * Unique keys, emails, and passwords form a cartesian product. Only the key
 * is stored. Basic auth is email:password and is built after the request URL.
 * 200 is verified; 401 and 403 are unverified without an error.
 */
#include "captures.h"
#include "detectors.h"
#include "email_pattern.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *const prefix[] = {"zipapi", NULL};
static br_regex *key_re, *email_re, *password_re;

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int verify(const br_scan_ctx *ctx, const char *email, const char *key, const char *password,
                  br_result *result, char **error)
{
    char url[96];
    int n = snprintf(url, sizeof(url), "https://service.zipapi.us/zipcode/90210/?X-API-KEY=%s", key);
    if (n < 0 || (size_t)n >= sizeof(url)) return fail(error, "cannot format ZipAPI URL");
    br_slice secret = {(const unsigned char *)key, strlen(key)};
    if (!ctx) {
        if (br_result_set_verification_error(result, "net/http: nil Context", &secret, 1) != 0)
            return fail(error, "cannot store ZipAPI verification error");
        return 0;
    }
    char *auth = NULL;
    if (br_http_basic_auth((br_slice){(const unsigned char *)email, strlen(email)},
                           (br_slice){(const unsigned char *)password, strlen(password)},
                           &auth, error) != 0)
        return -1;
    const br_header headers[] = {{"Content-Type", "application/json"}, {"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 2,
        .timeout_ms = 5000, .detector_type = 599, .profile = BR_HTTP_SANE,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[64];
    const char *cause = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0)
        cause = transport_error; /* NULL diagnostic stays NULL. */
    else if (response.status == 200) result->verified = true;
    else if (response.status != 401 && response.status != 403) {
        n = snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error))
            rc = fail(error, "cannot format ZipAPI status error");
        else cause = status_error;
    }
    if (!rc && br_result_set_verification_error(result, cause, &secret, 1) != 0)
        rc = fail(error, "cannot store ZipAPI verification error");
    br_http_release(ctx, &response);
    free(transport_error);
    free(auth);
    return rc;
}

static int scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify_requested,
                br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !key_re || !email_re || !password_re || !out || (!input.data && input.len))
        return fail(error, "invalid ZipAPI scan arguments");
    size_t original = out->len;
    br_captures keys = {0}, emails = {0}, passwords = {0};
    char *owned = NULL;
    int rc = 0;
    if (br_captures_find(key_re, input, &keys, true, &owned) ||
        br_captures_find(email_re, input, &emails, true, &owned) ||
        br_captures_find(password_re, input, &passwords, true, &owned))
        rc = -1;
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        for (size_t e = 0; !rc && e < emails.len; ++e) {
            for (size_t p = 0; !rc && p < passwords.len; ++p) {
                br_result result = {0};
                if (br_finding_key(&result, detector->type, keys.items[k], "key") != 0)
                    rc = fail(&owned, "cannot create ZipAPI finding");
                else if (verify_requested &&
                         verify(ctx, emails.items[e], keys.items[k], passwords.items[p],
                                &result, &owned) != 0)
                    rc = -1;
                else if (br_results_push(out, &result) != 0)
                    rc = fail(&owned, "cannot append ZipAPI finding");
                br_result_clear(&result);
            }
        }
    }
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&emails);
    br_captures_clear(&passwords);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static br_detector detector = {
    .name = "ZipAPI", .type = 599, .description =
        "ZipAPI is a service used to retrieve ZIP code information. ZipAPI keys can be used to access and retrieve this information from their API.",
    .keywords = (const char *[]){"zipapi", NULL}, .nkeywords = 1, .scan = scan,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .custom_name = "",
};

int br_zipapi_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid ZipAPI detector output");
    *out = NULL;
    if ((!key_re && br_regex_compile_prefixed(prefix, 1, "\\b([A-Z0-9a-z]{32})\\b", &key_re, error) != 0) ||
        (!email_re && br_regex_compile(br_email_pattern, &email_re, error) != 0) ||
        (!password_re && br_regex_compile_prefixed(prefix, 1, "\\b([a-zA-Z0-9!=@#$%^]{7,})", &password_re, error) != 0))
        return -1;
    detector.state = key_re;
    *out = &detector;
    return 0;
}
