/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/currencycloud/currencycloud.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "email_pattern.h"

#include <json-c/json.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *email; } currencycloud_patterns;

static int currencycloud_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int currencycloud_body(br_slice key, br_slice email, br_bytes *body, char **error)
{
    static const char prefix[] = "{\"login_id\":\"", separator[] = "\",\"api_key\":\"";
    const size_t fixed = sizeof(prefix) - 1 + sizeof(separator) - 1 + 1;
    if (email.len > SIZE_MAX - fixed || key.len > SIZE_MAX - fixed - email.len)
        return currencycloud_fail(error, "CurrencyCloud request body size overflow");
    body->len = fixed + email.len + key.len;
    body->data = malloc(body->len);
    if (!body->data) return currencycloud_fail(error, "cannot allocate CurrencyCloud request body");
    size_t at = 0;
    memcpy(body->data, prefix, sizeof(prefix) - 1); at += sizeof(prefix) - 1;
    memcpy(body->data + at, email.data, email.len); at += email.len;
    memcpy(body->data + at, separator, sizeof(separator) - 1); at += sizeof(separator) - 1;
    memcpy(body->data + at, key.data, key.len); at += key.len;
    /* The source has NO final '}' and performs NO JSON escaping,
     * even for quoted/control-bearing email captures. Preserve the raw bytes. */
    body->data[at] = '"';
    return 0;
}

static int currencycloud_environment(br_result *result, const char *environment, char **error)
{
    result->extra_data = json_object_new_object();
    if (!result->extra_data)
        return currencycloud_fail(error, "cannot create CurrencyCloud extra data");
    br_json *value = json_object_new_string(environment);
    if (!value) return currencycloud_fail(error, "cannot create CurrencyCloud environment");
    if (json_object_object_add(result->extra_data, "environment", value) != 0) {
        json_object_put(value);
        return currencycloud_fail(error, "cannot add CurrencyCloud environment");
    }
    result->verified = true;
    return 0;
}

static int currencycloud_verify(const br_scan_ctx *ctx, br_slice key, br_slice email,
                                 br_result *result, char **error)
{
    static const struct { const char *url, *environment; } environments[] = {
        {"https://devapi.currencycloud.com/v2/authenticate/api", "https://devapi.currencycloud.com"},
        {"https://api.currencycloud.com/v2/authenticate/api", "https://api.currencycloud.com"},
    };
    static const unsigned char token[] = "auth_token";
    br_bytes body = {0};
    /* Payload construction precedes even a nil-context constructor failure.
     * Build ONE complete unbounded body per pair, borrowed through both sends
     * and releases, not another copy/allocation for the second environment. */
    if (currencycloud_body(key, email, &body, error) != 0) return -1;
    int rc = 0;
    for (size_t env = 0; env < sizeof(environments) / sizeof(environments[0]); ++env) {
        if (!ctx) continue; /* Skip only this inner attempt; retain the outer finding. */
        const br_header headers[] = {{"Content-Type", "application/json"}};
        const br_http_request request = {
            .method = "POST", .url = environments[env].url,
            .headers = headers, .nheaders = 1, .body = {body.data, body.len},
            .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
        };
        br_http_response response = {0};
        char *transport_error = NULL;
        /* Suppress the WHOLE combined shared setup/allocation/Do domain. Read
         * errors (even a non-NULL empty cause) also continue to the next env.
         * HTTP status is irrelevant; search complete binary bytes, past NUL. */
        if (br_http_send(ctx, &request, &response, &transport_error) == 0 &&
            !response.body_error &&
            br_slice_find(response.body, (br_slice){token, sizeof(token) - 1}, 0) != SIZE_MAX)
            rc = currencycloud_environment(result, environments[env].environment, error);
        /* Source scan-defers Close BEFORE ReadAll, without draining. ABI1
         * releases eagerly; body lifetime, native POST redirects/full client
         * and global engine/output parity remain partial. */
        br_http_release(ctx, &response);
        free(transport_error);
        if (rc != 0 || result->verified) break; /* Only this pair's env loop. */
    }
    free(body.data);
    return rc == 0 ? 0 : -1;
}

static int currencycloud_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                               br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return currencycloud_fail(error, "invalid or uninitialized CurrencyCloud scan");
    const currencycloud_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->email)
        return currencycloud_fail(error, "uninitialized CurrencyCloud patterns");
    size_t original_len = out->len;
    br_captures keys = {0}, emails = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->email, input, &emails, true, &owned_error);
    /* TrimSpace cannot change either grammar's edges. Keys are occurrences;
     * bare emails are independently byte-unique and case-preserved. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        br_slice key = br_captures_at(&keys, k);
        for (size_t e = 0; rc == 0 && e < emails.len; ++e) {
            br_result result = {0};
            /* Email is required but hidden: only Raw/key SecretParts, including
             * identical NoV projections for different email products. */
            if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
                rc = currencycloud_fail(&owned_error, "cannot create CurrencyCloud result");
            if (rc == 0 && verify && currencycloud_verify(ctx, key, br_captures_at(&emails, e), &result, &owned_error) != 0)
                rc = -1;
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = currencycloud_fail(&owned_error, "cannot append CurrencyCloud result");
            br_result_clear(&result);
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

static currencycloud_patterns currencycloud_compiled;
static const char *const currencycloud_keywords[] = {"currencycloud"};
static const br_detector currencycloud_detector = {
    .type = 382, .version = 0, .name = "CurrencyCloud", .custom_name = "",
    .description = "Currencycloud provides a global payments platform that allows businesses to make payments and manage currency risk. Currencycloud API keys can be used to access and manage these financial services.",
    .keywords = currencycloud_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &currencycloud_compiled, .scan = currencycloud_scan,
};

int br_currencycloud_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return currencycloud_fail(error, "invalid CurrencyCloud detector output");
    *out = NULL;
    if (!currencycloud_compiled.key) {
        currencycloud_patterns compiled = {0};
        if (br_regex_compile_prefixed(currencycloud_keywords, 1, "\\b([0-9a-z]{64})\\b", &compiled.key, error) != 0 ||
            br_regex_compile(br_email_pattern, &compiled.email, error) != 0) {
            br_regex_free(compiled.key);
            br_regex_free(compiled.email);
            return -1;
        }
        currencycloud_compiled = compiled;
    }
    *out = &currencycloud_detector;
    return 0;
}
