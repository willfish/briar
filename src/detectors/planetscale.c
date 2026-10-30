/* SPDX-License-Identifier: AGPL-3.0-only */
#include "captures.h"

#include <json-c/json.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *const planetscale_keywords[] = {"pscale_tkn_"};
static const char planetscale_url[] = "https://api.planetscale.com/v1/organizations";

typedef struct {
    br_regex *username;
    br_regex *token;
} planetscale_patterns;

typedef struct planetscale_attempt {
    br_http_request request;
    br_http_response response;
    br_header headers[2];
    char *credentials;
    struct planetscale_attempt *previous;
} planetscale_attempt;

static planetscale_patterns planetscale_compiled;

static int planetscale_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static void planetscale_release(const br_scan_ctx *ctx, planetscale_attempt *attempt)
{
    if (!attempt) return;
    br_http_release(ctx, &attempt->response);
    free(attempt->credentials);
    free(attempt);
}

static void planetscale_release_deferred(const br_scan_ctx *ctx, planetscale_attempt *attempt)
{
    while (attempt) {
        planetscale_attempt *previous = attempt->previous;
        planetscale_release(ctx, attempt);
        attempt = previous;
    }
}

static int planetscale_add_part(br_json *parts, const char *name, br_slice value)
{
    if ((!value.data && value.len) || value.len > INT_MAX) return -1;
    br_json *part = json_object_new_string_len(value.data ? (const char *)value.data : "", (int)value.len);
    if (!part) return -1;
    if (json_object_object_add(parts, name, part) != 0) {
        json_object_put(part);
        return -1;
    }
    return 0;
}

static int planetscale_finding(br_result *result, int32_t type, br_slice username, br_slice password)
{
    if (!username.data || !password.data || username.len > SIZE_MAX - password.len - 1) return -1;
    size_t raw_len = username.len + 1 + password.len;
    unsigned char *raw = malloc(raw_len ? raw_len : 1);
    br_json *parts = json_object_new_object();
    if (!raw || !parts) {
        free(raw);
        json_object_put(parts);
        return -1;
    }
    memcpy(raw, username.data, username.len);
    raw[username.len] = ':';
    memcpy(raw + username.len + 1, password.data, password.len);
    result->detector_type = type;
    result->raw.data = raw;
    result->raw.len = raw_len;
    result->secret_parts = parts;
    if (planetscale_add_part(parts, "id", username) != 0 ||
        planetscale_add_part(parts, "token", password) != 0) {
        br_result_clear(result);
        return -1;
    }
    return 0;
}

static planetscale_attempt *planetscale_request(int32_t type, br_slice username, br_slice password)
{
    if (!username.data || !password.data || username.len > SIZE_MAX - password.len - 1) return NULL;
    size_t n = username.len + 1 + password.len;
    planetscale_attempt *attempt = calloc(1, sizeof(*attempt));
    char *credentials = malloc(n + 1);
    if (!attempt || !credentials) {
        free(attempt);
        free(credentials);
        return NULL;
    }
    memcpy(credentials, username.data, username.len);
    credentials[username.len] = ':';
    memcpy(credentials + username.len + 1, password.data, password.len);
    credentials[n] = '\0';
    attempt->credentials = credentials;
    attempt->headers[0] = (br_header){"Authorization", credentials};
    attempt->headers[1] = (br_header){"Accept", "application/json"};
    attempt->request = (br_http_request){
        .method = "GET", .url = planetscale_url, .headers = attempt->headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .detector_type = type,
    };
    return attempt;
}

static int planetscale_status_error(br_result *result, int status, br_slice password)
{
    char message[64];
    int written = snprintf(message, sizeof message, "unexpected status code %d", status);
    if (written < 0 || (size_t)written >= sizeof message) return -1;
    return br_result_set_verification_error(result, message, &password, 1);
}

/* Unprefixed full matches. The outer group is only the group-1 projection.
 * Username is the outer product and token is the inner product, including
 * duplicates and matches farther than the 1024 engine hint. Raw is
 * username:password. The scan-context transport is the injected client.
 * Nil context drops before send. A failed send releases immediately and still
 * appends after the password-only setter. A completed send releases once,
 * scan-wide and LIFO, after the setter and publication. */
static int planetscale_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                             br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    const planetscale_patterns *patterns = detector ? detector->state : NULL;
    if (!detector || !patterns || !patterns->username || !patterns->token || !out ||
        (!input.data && input.len))
        return planetscale_fail(error, "invalid or uninitialized PlanetScale scan");

    size_t original_len = out->len;
    br_captures usernames = {0}, passwords = {0};
    planetscale_attempt *deferred = NULL, *current = NULL;
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->username, input, &usernames, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->token, input, &passwords, false, &owned_error);
    for (size_t u = 0; rc == 0 && u < usernames.len; ++u) {
        br_slice username = br_captures_at(&usernames, u);
        for (size_t p = 0; rc == 0 && p < passwords.len; ++p) {
            br_result result = {0};
            br_slice password = br_captures_at(&passwords, p);
            char *transport_error = NULL;
            if (planetscale_finding(&result, detector->type, username, password) != 0)
                rc = planetscale_fail(&owned_error, "cannot create PlanetScale result");
            else if (!verify) {
                if (br_results_push(out, &result) != 0)
                    rc = planetscale_fail(&owned_error, "cannot append PlanetScale result");
            } else if (!ctx) {
                br_result_clear(&result);
            } else if (!(current = planetscale_request(detector->type, username, password))) {
                rc = planetscale_fail(&owned_error, "cannot create PlanetScale request");
            } else if (br_http_send(ctx, &current->request, &current->response, &transport_error) != 0) {
                planetscale_release(ctx, current);
                current = NULL;
                if (br_result_set_verification_error(&result, transport_error, &password, 1) != 0)
                    rc = planetscale_fail(&owned_error, "cannot set PlanetScale verification error");
                else if (br_results_push(out, &result) != 0)
                    rc = planetscale_fail(&owned_error, "cannot append PlanetScale result");
            } else {
                int status = current->response.status;
                if (status >= 200 && status < 300) result.verified = true;
                else if (status != 401 && planetscale_status_error(&result, status, password) != 0)
                    rc = planetscale_fail(&owned_error, "cannot set PlanetScale verification error");
                if (rc == 0 && br_results_push(out, &result) != 0)
                    rc = planetscale_fail(&owned_error, "cannot append PlanetScale result");
                if (rc == 0) {
                    current->previous = deferred;
                    deferred = current;
                    current = NULL;
                }
            }
            free(transport_error);
            br_result_clear(&result);
        }
    }
    if (current) planetscale_release(ctx, current);
    planetscale_release_deferred(ctx, deferred);
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&usernames);
    br_captures_clear(&passwords);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static br_detector planetscale_detector = {
    .type = 195, .version = 0, .name = "PlanetScale", .custom_name = "",
    .description = "PlanetScale is a database platform. PlanetScale tokens can be used to access and manage database instances.",
    .keywords = planetscale_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = planetscale_scan,
};

int br_planetscale_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return planetscale_fail(error, "invalid PlanetScale detector output");
    *out = NULL;
    if (!planetscale_compiled.username &&
        br_regex_compile("(\\b[a-z0-9]{12}\\b)", &planetscale_compiled.username, error) != 0)
        return -1;
    if (!planetscale_compiled.token &&
        br_regex_compile("(\\bpscale_tkn_[A-Za-z0-9_]{43}\\b)", &planetscale_compiled.token, error) != 0)
        return -1;
    planetscale_detector.state = &planetscale_compiled;
    *out = &planetscale_detector;
    return 0;
}
