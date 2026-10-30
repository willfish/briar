/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/squareapp/squareapp.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include <json-c/json.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *const square_keywords[] = {"sq0i"};
static const char square_sandbox[] = "https://connect.squareupsandbox.com/oauth2/revoke";
static const char square_prod[] = "https://connect.squareup.com/oauth2/revoke";
static const char square_token[] = "fakeTruffleHogAccessTokenForVerification";

typedef struct { br_regex *id; br_regex *secret; } square_patterns;

static int square_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static bool square_sandbox_id(br_slice value)
{
    return value.len >= 8 && !memcmp(value.data, "sandbox-", 8);
}

static int square_store(br_result *result, const char *cause, char **error)
{
    if (br_result_set_verification_error(result, cause, NULL, 0) != 0)
        return square_fail(error, "cannot set SquareApp verification error");
    return 0;
}

static int square_verify(const br_scan_ctx *ctx, const char *endpoint, br_slice id, br_slice secret,
                         br_result *result, char **error)
{
    static const char prefix[] = "{\"access_token\":\"" ;
    static const char middle[] = "\",\"client_id\":\"";
    static const char suffix[] = "\"}";
    /* encoding/json sorts map keys, so access_token precedes client_id.
     * The id class is JSON-safe. Marshal completes before the nil-context error. */
    if (id.len > 58 || secret.len > 65)
        return square_fail(error, "invalid SquareApp capture");
    char body[sizeof(prefix) + sizeof(square_token) + sizeof(middle) + 58 + sizeof(suffix)];
    size_t at = 0;
    memcpy(body + at, prefix, sizeof(prefix) - 1); at += sizeof(prefix) - 1;
    memcpy(body + at, square_token, sizeof(square_token) - 1); at += sizeof(square_token) - 1;
    memcpy(body + at, middle, sizeof(middle) - 1); at += sizeof(middle) - 1;
    memcpy(body + at, id.data, id.len); at += id.len;
    memcpy(body + at, suffix, sizeof(suffix) - 1); at += sizeof(suffix) - 1;
    char authorization[80];
    memcpy(authorization, "Client ", 7);
    memcpy(authorization + 7, secret.data, secret.len);
    authorization[7 + secret.len] = '\0';
    if (!ctx) return square_store(result, "net/http: nil Context", error);
    const br_header headers[] = {
        {"Authorization", authorization},
        {"Content-Type", "application/json"},
    };
    const br_http_request request = {
        .method = "POST", .url = endpoint, .headers = headers, .nheaders = 2,
        .body = {(const unsigned char *)body, at},
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &transport_error);
    char *cause = NULL;
    int rc = 0;
    if (send_rc != 0) {
        if (transport_error && !(cause = strdup(transport_error)))
            rc = square_fail(error, "cannot copy SquareApp transport error");
    }
    else if (response.status == 404) result->verified = true;
    else {
        char status_error[64];
        int n = snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error)) rc = square_fail(error, "cannot format SquareApp status");
        else cause = strdup(status_error);
    }
    if (!rc) rc = square_store(result, cause, error);
    free(cause);
    free(transport_error);
    br_http_release(ctx, &response);
    return rc;
}

static int square_extra(br_result *result, bool verify, bool sandbox, char **error)
{
    result->extra_data = json_object_new_object();
    if (!result->extra_data) return square_fail(error, "cannot create SquareApp metadata");
    if (!verify) return 0;
    br_json *env = json_object_new_string(sandbox ? "Sandbox" : "Production");
    if (!env || json_object_object_add(result->extra_data, "Env", env) != 0) {
        json_object_put(env);
        return square_fail(error, "cannot create SquareApp metadata");
    }
    return 0;
}

static int square_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    const square_patterns *patterns = detector ? detector->state : NULL;
    if (!detector || !patterns || !patterns->id || !patterns->secret || !out || (!input.data && input.len))
        return square_fail(error, "invalid or uninitialized SquareApp scan");
    size_t original_len = out->len;
    br_captures ids = {0}, secrets = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->id, input, &ids, true, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->secret, input, &secrets, true, &owned_error);
    bool *consumed = NULL;
    if (rc == 0 && secrets.len) {
        consumed = calloc(secrets.len, sizeof(*consumed));
        if (!consumed) rc = square_fail(&owned_error, "out of memory pairing SquareApp secrets");
    }
    for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
        br_slice id = br_captures_at(&ids, i);
        bool id_sandbox = square_sandbox_id(id);
        for (size_t s = 0; rc == 0 && s < secrets.len; ++s) {
            br_slice secret = br_captures_at(&secrets, s);
            if (consumed[s] || id_sandbox != square_sandbox_id(secret)) continue;
            br_result result = {0};
            if (br_finding_key_bytes(&result, detector->type, id, "key") != 0)
                rc = square_fail(&owned_error, "cannot create SquareApp result");
            else if (!(result.redacted = strdup(ids.items[i])))
                rc = square_fail(&owned_error, "cannot redact SquareApp id");
            else if (square_extra(&result, verify, id_sandbox, &owned_error) != 0)
                rc = -1;
            else if (verify && square_verify(ctx, id_sandbox ? square_sandbox : square_prod,
                                             id, secret, &result, &owned_error) != 0)
                rc = -1;
            bool verified = rc == 0 && result.verified;
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = square_fail(&owned_error, "cannot append SquareApp result");
            if (rc == 0 && verified) consumed[s] = true;
            br_result_clear(&result);
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    free(consumed);
    br_captures_clear(&ids);
    br_captures_clear(&secrets);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static br_detector square_detector = {
    .type = 25, .version = 0, .name = "SquareApp", .custom_name = "",
    .description = "Square is a financial services and mobile payment company. Square credentials can be used to access and manage payment processing and other financial services.",
    .keywords = square_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = square_scan,
};

int br_squareapp_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return square_fail(error, "invalid SquareApp detector output");
    *out = NULL;
    if (!square_detector.state) {
        square_patterns *patterns = calloc(1, sizeof(*patterns));
        if (!patterns) return square_fail(error, "out of memory compiling SquareApp patterns");
        if (br_regex_compile("((?:sandbox-)?sq0i[a-z]{2}-[0-9A-Za-z_-]{22,43})", &patterns->id, error) != 0 ||
            br_regex_compile("((?:sandbox-)?sq0c[a-z]{2}-[0-9A-Za-z_-]{40,50})", &patterns->secret, error) != 0) {
            br_regex_free(patterns->id);
            free(patterns);
            return -1;
        }
        square_detector.state = patterns;
    }
    *out = &square_detector;
    return 0;
}
