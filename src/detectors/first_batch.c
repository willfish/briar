/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/{abstract,abuseipdb,abyssale}. */
#include "first_batch.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*key_verifier)(const br_scan_ctx *, const char *, br_result *);

typedef struct {
    const br_detector *detector;
    const br_scan_ctx *ctx;
    br_slice input;
    br_results *out;
    bool verify;
    key_verifier verifier;
    char **error;
} key_matches;

static int scan_error(char **error, const char *message)
{
    if (error) {
        size_t len = strlen(message) + 1;
        *error = malloc(len);
        if (*error) memcpy(*error, message, len);
    }
    return -1;
}

static int verification_error(br_result *result, const char *cause)
{
    br_slice secret = {result->raw.data, result->raw.len};
    return br_result_set_verification_error(result, cause, &secret, 1);
}

static int unexpected_status(br_result *result, int status)
{
    char message[80];
    snprintf(message, sizeof(message), "unexpected HTTP response status %d", status);
    return verification_error(result, message);
}

static int verify_abstract(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char url[160];
    snprintf(url, sizeof(url),
             "https://exchange-rates.abstractapi.com/v1/live/?api_key=%s&base=USD", key);
    const br_header headers[] = {{"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 384,
    };
    br_http_response response = {0};
    char *error = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        rc = verification_error(result, error ? error : "HTTP transport failed");
    } else {
        /* Upstream only inspects status; even a failed body read is irrelevant. */
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401: break;
        default: rc = unexpected_status(result, response.status); break;
        }
    }
    br_http_release(ctx, &response);
    free(error);
    return rc;
}

static bool contains_ip_address(br_slice body)
{
    static const unsigned char needle[] = "ipAddress";
    const size_t len = sizeof(needle) - 1;
    if (body.len < len) return false;
    for (size_t i = 0; i <= body.len - len; ++i) {
        if (memcmp(body.data + i, needle, len) == 0) return true;
    }
    return false;
}

static int verify_abuseipdb(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    const br_header headers[] = {{"Key", key}};
    const br_http_request request = {
        .method = "GET",
        .url = "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 521,
    };
    br_http_response response = {0};
    char *error = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        rc = verification_error(result, error ? error : "HTTP transport failed");
    } else {
        switch (response.status) {
        case 200:
            if (response.body_error) {
                rc = verification_error(result, response.body_error);
            } else {
                /* This intentionally accepts malformed JSON containing these bytes. */
                result->verified = contains_ip_address(response.body);
            }
            break;
        case 401: break;
        default: rc = unexpected_status(result, response.status); break;
        }
    }
    br_http_release(ctx, &response);
    free(error);
    return rc;
}

static int verify_abyssale(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    const br_header headers[] = {{"x-api-key", key}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.abyssale.com/ready",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 239,
    };
    br_http_response response = {0};
    char *error = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        rc = verification_error(result, error ? error : "HTTP transport failed");
    } else {
        switch (response.status) {
        case 200: result->verified = true; break;
        case 403: break;
        default: rc = unexpected_status(result, response.status); break;
        }
    }
    br_http_release(ctx, &response);
    free(error);
    return rc;
}

static int emit_key(void *user, const br_span *groups, size_t ngroups)
{
    key_matches *matches = user;
    if (ngroups < 2 || groups[1].begin == SIZE_MAX ||
        groups[1].end < groups[1].begin || groups[1].end > matches->input.len)
        return scan_error(matches->error, "invalid detector capture");
    size_t len = groups[1].end - groups[1].begin;
    char key[81];
    if (len == 0 || len >= sizeof(key))
        return scan_error(matches->error, "invalid detector capture length");
    /* These three capture alphabets exclude all whitespace: TrimSpace is a no-op. */
    memcpy(key, matches->input.data + groups[1].begin, len);
    key[len] = '\0';

    br_result result = {.detector_type = matches->detector->type};
    result.raw.data = malloc(len);
    result.secret_parts = json_object_new_object();
    br_json *value = json_object_new_string_len(key, (int)len);
    if (!result.raw.data || !result.secret_parts || !value) {
        if (value) json_object_put(value);
        br_result_clear(&result);
        return scan_error(matches->error, "out of memory creating detector result");
    }
    memcpy(result.raw.data, key, len);
    result.raw.len = len;
    if (json_object_object_add(result.secret_parts, "key", value) != 0) {
        json_object_put(value);
        br_result_clear(&result);
        return scan_error(matches->error, "out of memory creating secret parts");
    }
    if (matches->verify && matches->verifier(matches->ctx, key, &result) != 0) {
        br_result_clear(&result);
        return scan_error(matches->error, "out of memory sanitizing verification error");
    }
    if (br_results_push(matches->out, &result) != 0) {
        br_result_clear(&result);
        return scan_error(matches->error, "out of memory appending detector result");
    }
    return 0;
}

static int scan_keys(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error, key_verifier verifier)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return scan_error(error, "invalid or uninitialized detector scan");
    char *match_error = NULL, *regex_error = NULL;
    key_matches matches = {detector, ctx, input, out, verify, verifier, &match_error};
    /* Verification context cancellation/deadlines are handled by br_http_send. */
    int rc = br_regex_each(detector->state, input, emit_key, &matches, &regex_error);
    if (match_error) {
        free(regex_error);
        regex_error = match_error;
    }
    if (error) *error = regex_error;
    else free(regex_error);
    return rc;
}

static int scan_abstract(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    return scan_keys(detector, ctx, verify, input, out, error, verify_abstract);
}

static int scan_abuseipdb(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    return scan_keys(detector, ctx, verify, input, out, error, verify_abuseipdb);
}

static int scan_abyssale(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    return scan_keys(detector, ctx, verify, input, out, error, verify_abyssale);
}

static const char *const abstract_keywords[] = {"abstract"};
static const char *const abuseipdb_keywords[] = {"abuseipdb"};
static const char *const abyssale_keywords[] = {"abyssale"};

static br_detector abstract_detector = {
    .type = 384, .version = 0, .name = "Abstract", .custom_name = "",
    .description = "Abstract API provides various services including exchange rates. The API keys can be used to access these services and retrieve data.",
    .keywords = abstract_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_abstract,
};

static br_detector abuseipdb_detector = {
    .type = 521, .version = 0, .name = "AbuseIPDB", .custom_name = "",
    .description = "AbuseIPDB is a project dedicated to helping combat the spread of hackers, spammers, and abusive activity on the internet. AbuseIPDB API keys can be used to report and check IP addresses for abusive activities.",
    .keywords = abuseipdb_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_abuseipdb,
};

static br_detector abyssale_detector = {
    .type = 239, .version = 0, .name = "Abyssale", .custom_name = "",
    .description = "Abyssale is a service offering various API functionalities for marketing automation and services such as images and ad campaigns. Abyssale API keys can be used to access and interact with this data.",
    .keywords = abyssale_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_abyssale,
};

/* Keep upstream default-list order, with its commented Abstract available directly. */
static const br_detector *const implemented[] = {
    &abyssale_detector, &abstract_detector, &abuseipdb_detector,
};

static int compile_key(br_detector *detector, const char *capture, char **error)
{
    if (detector->state) return 0;
    char *prefix = NULL;
    if (br_prefix_regex(detector->keywords, detector->nkeywords, &prefix) != 0)
        return scan_error(error, "cannot allocate detector prefix pattern");
    size_t len = strlen(prefix) + strlen(capture) + 1;
    char *pattern = malloc(len);
    if (!pattern) {
        free(prefix);
        return scan_error(error, "cannot allocate detector pattern");
    }
    snprintf(pattern, len, "%s%s", prefix, capture);
    br_regex *regex = NULL;
    int rc = br_regex_compile(pattern, &regex, error);
    free(pattern);
    free(prefix);
    if (rc == 0) detector->state = regex;
    return rc;
}

int br_first_batch(const br_detector *const **out, size_t *count, char **error)
{
    if (error) *error = NULL;
    if (out) *out = NULL;
    if (count) *count = 0;
    if (!out || !count) return scan_error(error, "invalid first-batch outputs");
    if (compile_key(&abyssale_detector, "\\b([a-z0-9A-Z]{40})\\b", error) != 0 ||
        compile_key(&abstract_detector, "\\b([0-9a-z]{32})\\b", error) != 0 ||
        compile_key(&abuseipdb_detector, "\\b([a-z0-9]{80})\\b", error) != 0)
        return -1;
    *out = implemented;
    *count = sizeof(implemented) / sizeof(implemented[0]);
    return 0;
}

bool br_first_batch_is_default(const br_detector *detector)
{
    if (!detector || detector->version != 0 ||
        (detector->custom_name && detector->custom_name[0])) return false;
    return detector->type == abyssale_detector.type || detector->type == abuseipdb_detector.type;
}
