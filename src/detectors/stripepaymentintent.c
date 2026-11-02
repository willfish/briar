/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/stripepaymentintent. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"

#include <json-c/json.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static const char *stripe_word(enum json_type kind)
{
    switch (kind) {
    case json_type_boolean: return "bool";
    case json_type_array: return "array";
    case json_type_object: return "object";
    case json_type_string: return "string";
    default: return "number";
    }
}

static char *format_message(const char *prefix, const char *detail)
{
    size_t first = strlen(prefix), second = strlen(detail);
    if (first == SIZE_MAX || second > SIZE_MAX - first - 1) return NULL;
    size_t need = first + second + 1;
    char *message = malloc(need);
    if (message) snprintf(message, need, "%s%s", prefix, detail);
    return message;
}

static int set_error(br_result *result, const char *message, char **error)
{
    /* SetVerificationError receives no secret, so a transport echo is kept. */
    if (br_result_set_verification_error(result, message, NULL, 0) != 0)
        return fail(error, "cannot record Stripe PaymentIntent verification error");
    return 0;
}

static int add_text(br_result *result, const char *name, const char *text, char **error)
{
    if (!result->secret_parts && !(result->secret_parts = json_object_new_object()))
        return fail(error, "cannot create Stripe PaymentIntent result");
    br_json *value = json_object_new_string(text);
    if (!value || json_object_object_add(result->secret_parts, name, value) != 0) {
        json_object_put(value);
        return fail(error, "cannot create Stripe PaymentIntent result");
    }
    return 0;
}

static int make_result(br_result *result, const char *secret, const char *key,
                       const char *key_type, char **error)
{
    size_t secret_len = strlen(secret), key_len = strlen(key);
    if (secret_len > SIZE_MAX - key_len) return fail(error, "cannot create Stripe PaymentIntent result");
    result->detector_type = 1027;
    result->raw.data = malloc(secret_len);
    result->raw_v2.data = malloc(secret_len + key_len);
    if (!result->raw.data || !result->raw_v2.data)
        return fail(error, "cannot create Stripe PaymentIntent result");
    memcpy(result->raw.data, secret, secret_len);
    result->raw.len = secret_len;
    memcpy(result->raw_v2.data, secret, secret_len);
    memcpy(result->raw_v2.data + secret_len, key, key_len);
    result->raw_v2.len = secret_len + key_len;
    if (add_text(result, "client_secret", secret, error) || add_text(result, "key", key, error))
        return -1;
    result->extra_data = json_object_new_object();
    br_json *kind = json_object_new_string(key_type);
    if (!result->extra_data || !kind ||
        json_object_object_add(result->extra_data, "key_type", kind) != 0) {
        json_object_put(kind);
        return fail(error, "cannot create Stripe PaymentIntent metadata");
    }
    return 0;
}

typedef struct {
    char *secret;
    size_t len;
    char *cause;
    int failed;
    int rc;
} stripe_secret;

static int stripe_type_cause_real(br_json *value, char **cause)
{
    char message[96];
    snprintf(message, sizeof(message),
             "json: cannot unmarshal %s into Go struct field .client_secret of type string",
             stripe_word(json_object_get_type(value)));
    *cause = strdup(message);
    return *cause ? 0 : -1;
}

static int (*stripe_type_cause)(br_json *, char **) = stripe_type_cause_real;

static int stripe_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    stripe_secret *out = user;
    if (!br_json_field_name(name, "client_secret")) return 0;
    enum json_type kind = json_object_get_type(value);
    if (kind == json_type_null) return 0; /* null does not clear a prior string */
    if (kind != json_type_string) {
        char *cause = NULL;
        int typed = stripe_type_cause(value, &cause);
        if (typed < 0) { free(cause); out->rc = -1; return -1; }
        if (!out->failed) { out->failed = 1; out->cause = cause; out->rc = 1; }
        else free(cause);
        return 0;
    }
    br_slice text = br_json_text(value);
    if (text.len == SIZE_MAX) { out->rc = -1; return -1; }
    char *copy = malloc(text.len + 1);
    if (!copy) { out->rc = -1; return -1; }
    memcpy(copy, text.data, text.len);
    copy[text.len] = '\0';
    free(out->secret);
    out->secret = copy;
    out->len = text.len;
    return 0;
}

static int client_secret_matches(br_slice body, const char *read_error, const char *expected,
                                 bool *matches, char **cause)
{
    *matches = false;
    br_json *value = NULL;
    size_t end = 0;
    int decoded = br_json_first_document(body, read_error, &value, &end, cause);
    if (decoded < 0 || decoded > 1) { json_object_put(value); return -1; }
    if (decoded == 1) { json_object_put(value); return 1; }
    if (!value || json_object_get_type(value) == json_type_null) {
        json_object_put(value);
        return 0; /* JSON null into the struct is a zero value, not an error. */
    }
    if (json_object_get_type(value) != json_type_object) {
        const char *word = stripe_word(json_object_get_type(value));
        char message[160];
        snprintf(message, sizeof(message),
                 "json: cannot unmarshal %s into Go value of type struct { ClientSecret string \"json:\\\"client_secret\\\"\" }",
                 word);
        json_object_put(value);
        *cause = strdup(message);
        return *cause ? 1 : -1;
    }
    json_object_put(value);
    stripe_secret found = {0};
    int walked = br_json_each_member((br_slice){body.data, end}, stripe_member, &found);
    if (walked != 0 || found.rc < 0) { free(found.secret); free(found.cause); return -1; }
    if (found.rc > 0) { free(found.secret); *cause = found.cause; return 1; }
    size_t expected_len = strlen(expected);
    *matches = found.secret && found.len == expected_len &&
               memcmp(found.secret, expected, expected_len) == 0;
    free(found.secret);
    return 0;
}

static const char *intent_id(const char *secret, size_t *len)
{
    const char *mark = strstr(secret, "_secret_");
    if (!mark) { *len = 0; return secret; }
    *len = (size_t)(mark - secret);
    return secret;
}

static int verify_secret_key(const br_scan_ctx *ctx, const char *secret, const char *key,
                             br_result *result, char **error)
{
    size_t id_len = 0;
    const char *id = intent_id(secret, &id_len);
    if (id_len > SIZE_MAX - sizeof("https://api.stripe.com/v1/payment_intents/"))
        return fail(error, "Stripe PaymentIntent URL is too large");
    char *url = malloc(sizeof("https://api.stripe.com/v1/payment_intents/") + id_len);
    if (!url) return fail(error, "cannot create Stripe PaymentIntent URL");
    memcpy(url, "https://api.stripe.com/v1/payment_intents/", sizeof("https://api.stripe.com/v1/payment_intents/") - 1);
    memcpy(url + sizeof("https://api.stripe.com/v1/payment_intents/") - 1, id, id_len);
    url[sizeof("https://api.stripe.com/v1/payment_intents/") - 1 + id_len] = '\0';
    if (!ctx) { free(url); return set_error(result, "error creating request: net/http: nil Context", error); }
    size_t key_len = strlen(key);
    if (key_len > SIZE_MAX - sizeof("Bearer ")) {
        free(url); return fail(error, "Stripe PaymentIntent authorization is too large");
    }
    size_t auth_size = sizeof("Bearer ") + key_len;
    char *authorization = malloc(auth_size);
    if (!authorization) { free(url); return fail(error, "cannot format Stripe PaymentIntent authorization"); }
    snprintf(authorization, auth_size, "Bearer %s", key);
    const br_header headers[] = {
        {"Authorization", authorization},
        {"Content-Type", "application/x-www-form-urlencoded"},
    };
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = 1027,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &send_error);
    int rc = 0;
    if (sent != 0) {
        if (!send_error) rc = set_error(result, NULL, error);
        else {
            char *message = format_message("request failed: ", send_error);
            rc = message ? set_error(result, message, error) : fail(error, "cannot format Stripe PaymentIntent transport error");
            free(message);
        }
    } else if (response.status == 200) {
        bool matches = false;
        char *cause = NULL;
        int decoded = client_secret_matches(response.body, response.body_error, secret, &matches, &cause);
        if (decoded < 0) rc = fail(error, "cannot decode Stripe PaymentIntent response");
        else if (decoded > 0) {
            char *message = format_message("failed to decode response body: ", cause ? cause : "EOF");
            rc = message ? set_error(result, message, error) : fail(error, "cannot format Stripe PaymentIntent decode error");
            free(message);
        } else result->verified = matches;
        free(cause);
    } else if (response.status != 401 && response.status != 404) {
        char message[64];
        snprintf(message, sizeof(message), "unexpected status code: %d", response.status);
        rc = set_error(result, message, error);
    }
    br_http_release(ctx, &response);
    free(send_error); free(authorization); free(url);
    return rc;
}

static int verify_publishable(const br_scan_ctx *ctx, const char *secret, const char *key,
                              br_result *result, char **error)
{
    size_t id_len = 0;
    const char *id = intent_id(secret, &id_len);
    if (!id_len) return set_error(result, "payment intent ID is required", error);
    size_t need = sizeof("https://api.stripe.com/v1/payment_intents/?key=&client_secret=");
    size_t key_len = strlen(key), secret_len = strlen(secret);
    if (id_len > INT_MAX || id_len > SIZE_MAX - need ||
        key_len > SIZE_MAX - need - id_len || secret_len > SIZE_MAX - need - id_len - key_len)
        return fail(error, "Stripe PaymentIntent URL is too large");
    need += id_len + key_len + secret_len;
    char *url = malloc(need);
    if (!url) return fail(error, "cannot create Stripe PaymentIntent URL");
    snprintf(url, need, "https://api.stripe.com/v1/payment_intents/%.*s?key=%s&client_secret=%s",
             (int)id_len, id, key, secret);
    if (!ctx) { free(url); return set_error(result, "error creating request: net/http: nil Context", error); }
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = 1027,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &send_error);
    int rc = 0;
    if (sent != 0) {
        if (!send_error) rc = set_error(result, NULL, error);
        else {
            char *message = format_message("request failed: ", send_error);
            rc = message ? set_error(result, message, error) : fail(error, "cannot format Stripe PaymentIntent transport error");
            free(message);
        }
    } else if (response.status == 200) {
        bool matches = false;
        char *cause = NULL;
        int decoded = client_secret_matches(response.body, response.body_error, secret, &matches, &cause);
        if (decoded < 0) rc = fail(error, "cannot decode Stripe PaymentIntent response");
        else if (decoded > 0) {
            char *message = format_message("failed to decode response body: ", cause ? cause : "EOF");
            rc = message ? set_error(result, message, error) : fail(error, "cannot format Stripe PaymentIntent decode error");
            free(message);
        } else result->verified = matches;
        free(cause);
    } else if (response.status != 401 && response.status != 404) {
        char message[64];
        snprintf(message, sizeof(message), "unexpected status code: %d", response.status);
        rc = set_error(result, message, error);
    }
    br_http_release(ctx, &response);
    free(send_error); free(url);
    return rc;
}

static int scan_stripe(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Stripe PaymentIntent scan");
    const br_regex *const *patterns = detector->state;
    size_t original_len = out->len;
    /* Go maps are unordered. First-seen order is the stable stand-in. */
    br_captures secrets = {0}, secret_keys = {0}, publishable = {0};
    int rc = br_captures_find(patterns[0], input, &secrets, true, error);
    if (!rc) rc = br_captures_find(patterns[1], input, &secret_keys, true, error);
    if (!rc) rc = br_captures_find(patterns[2], input, &publishable, true, error);
    for (size_t i = 0; rc == 0 && i < secrets.len; ++i) {
        for (size_t j = 0; rc == 0 && j < secret_keys.len; ++j) {
            br_result result = {0};
            if (make_result(&result, secrets.items[i], secret_keys.items[j], "secret", error) != 0)
                rc = -1;
            else if (verify && verify_secret_key(ctx, secrets.items[i], secret_keys.items[j], &result, error) != 0)
                rc = -1;
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = fail(error, "cannot append Stripe PaymentIntent result");
            br_result_clear(&result);
        }
        for (size_t j = 0; rc == 0 && j < publishable.len; ++j) {
            br_result result = {0};
            if (make_result(&result, secrets.items[i], publishable.items[j], "publishable", error) != 0)
                rc = -1;
            else if (verify && verify_publishable(ctx, secrets.items[i], publishable.items[j], &result, error) != 0)
                rc = -1;
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = fail(error, "cannot append Stripe PaymentIntent result");
            br_result_clear(&result);
        }
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&secrets);
    br_captures_clear(&secret_keys);
    br_captures_clear(&publishable);
    return rc == 0 ? 0 : -1;
}

static const char *const stripe_keywords[] = {"_secret_"};
static br_regex *stripe_patterns[3];
static br_detector stripe_detector = {
    .type = 1027, .version = 0, .name = "StripePaymentIntent", .custom_name = "",
    .description = "Stripepaymentintent objects represent a customer's intent to pay and track the lifecycle of a payment. These objects are used to initiate and manage payment flows, including confirmation, authentication, and capture of funds.",
    .keywords = stripe_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .state = stripe_patterns, .scan = scan_stripe,
};

int br_stripepaymentintent_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Stripe PaymentIntent detector output");
    *out = NULL;
    /* A set Scanner.Client and the package default both use the injected transport. */
    if (!stripe_patterns[0] &&
        br_regex_compile("\\b(pi_[a-zA-Z0-9]{24}_secret_[a-zA-Z0-9]{25})\\b", &stripe_patterns[0], error) != 0)
        return -1;
    if (!stripe_patterns[1] &&
        br_regex_compile("\\b([rs]k_live_[a-zA-Z0-9]{20,247})\\b", &stripe_patterns[1], error) != 0)
        return -1;
    if (!stripe_patterns[2] &&
        br_regex_compile("\\b(pk_live_[a-zA-Z0-9]{20,247})\\b", &stripe_patterns[2], error) != 0)
        return -1;
    *out = &stripe_detector;
    return 0;
}
