/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2,
 * pkg/detectors/azureappconfigconnectionstring/azureappconfigconnectionstring.go. */
#include "detectors.h"
#include "azure_shared_key.h"
#include "findings.h"

#include <json-c/json.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static br_regex *connection_pattern;
static const char content_hash[] = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int textf(char **out, const char *format, ...)
{
    va_list args, copy;
    va_start(args, format); va_copy(copy, args);
    int len = vsnprintf(NULL, 0, format, args);
    va_end(args);
    *out = len < 0 ? NULL : malloc((size_t)len + 1);
    if (*out) vsnprintf(*out, (size_t)len + 1, format, copy);
    va_end(copy);
    return *out ? 0 : -1;
}

static int add_part(br_result *result, const char *name, br_slice text)
{
    if (text.len > INT_MAX) return -1;
    br_json *value = json_object_new_string_len((const char *)text.data, (int)text.len);
    if (!value) return -1;
    if (!json_object_object_add(result->secret_parts, name, value)) return 0;
    json_object_put(value);
    return -1;
}

typedef struct { br_slice input; br_results candidates; char *error; } connection_matches;

static int collect_connection(void *user, const br_span *groups, size_t count)
{
    connection_matches *matches = user;
    if (count < 4) return fail(&matches->error, "invalid Azure App Configuration capture count");
    br_slice captures[4];
    for (size_t i = 0; i < 4; ++i) {
        if (groups[i].begin == SIZE_MAX || groups[i].end <= groups[i].begin || groups[i].end > matches->input.len)
            return fail(&matches->error, "invalid Azure App Configuration capture");
        captures[i] = (br_slice){matches->input.data + groups[i].begin, groups[i].end - groups[i].begin};
    }
    /* Source uniqueness is the WHOLE connection, never the ID or key. Store
     * groups together, rather than producing a Cartesian product of captures. */
    for (size_t i = 0; i < matches->candidates.len; ++i) {
        br_bytes whole = matches->candidates.items[i].raw_v2;
        if (whole.len == captures[0].len && !memcmp(whole.data, captures[0].data, whole.len)) return 0;
    }
    br_result result = {0};
    int rc = br_finding_key_bytes(&result, 1025, captures[2], "id");
    if (!rc) {
        result.raw_v2.data = malloc(captures[0].len);
        if (!result.raw_v2.data) rc = -1;
        else { memcpy(result.raw_v2.data, captures[0].data, captures[0].len); result.raw_v2.len = captures[0].len; }
    }
    if (!rc) rc = add_part(&result, "endpoint", captures[1]);
    if (!rc) rc = add_part(&result, "secret", captures[3]);
    if (!rc) rc = br_results_push(&matches->candidates, &result);
    br_result_clear(&result);
    return rc ? fail(&matches->error, "out of memory collecting Azure App Configuration connection") : 0;
}

static int verify_connection(const br_scan_ctx *ctx, br_result *result)
{
    br_json *endpoint_value = NULL, *id_value = NULL, *secret_value = NULL;
    if (!json_object_object_get_ex(result->secret_parts, "endpoint", &endpoint_value) ||
        !json_object_object_get_ex(result->secret_parts, "id", &id_value) ||
        !json_object_object_get_ex(result->secret_parts, "secret", &secret_value)) return -1;
    const char *endpoint = json_object_get_string(endpoint_value), *id = json_object_get_string(id_value);
    br_slice secret = {(const unsigned char *)json_object_get_string(secret_value), (size_t)json_object_get_string_len(secret_value)};
    br_slice redact = {result->raw_v2.data, result->raw_v2.len};
    br_bytes key = {0};
    size_t bad_offset = SIZE_MAX;
    int decoded = br_azure_base64_std_decode(secret, &key, &bad_offset);
    if (decoded) {
        free(key.data); /* Reject corruption, including a nonempty decoded prefix. */
        if (decoded < 0) return -1;
        char cause[96];
        snprintf(cause, sizeof(cause), "illegal base64 data at input byte %zu", bad_offset);
        /* Both source %w wrappers unwrap to this corrupt-input leaf. */
        return br_result_set_verification_error(result, cause, &redact, 1);
    }
    const char *host = endpoint;
    if (!strncmp(host, "https://", 8)) host += 8;
    if (!strncmp(host, "http://", 7)) host += 7;
    time_t now = time(NULL);
    char date[30], signature[45];
    char *canonical = NULL, *url = NULL, *authorization = NULL;
    int rc = now == (time_t)-1 || br_azure_http_date_utc((int64_t)now, date) ? -1 : 0;
    if (!rc) rc = textf(&canonical, "GET\n/kv?api-version=1.0\n%s;%s;%s", date, host, content_hash);
    if (!rc) rc = br_azure_hmac_sha256_base64((br_slice){key.data, key.len},
                                              (br_slice){(const unsigned char *)canonical, strlen(canonical)}, signature);
    free(key.data); /* Key bytes are opaque; do not reject or strlen an empty/binary key. */
    if (!rc) rc = textf(&authorization, "HMAC-SHA256 Credential=%s&SignedHeaders=date;host;x-ms-content-sha256&Signature=%s", id, signature);
    if (!rc) rc = textf(&url, "%s/kv?api-version=1.0", endpoint);
    if (rc) { free(canonical); free(authorization); free(url); return -1; }
    const br_header headers[] = {
        {"Host", host}, {"Date", date}, {"x-ms-content-sha256", content_hash}, {"Authorization", authorization},
    };
    const br_http_request request = {.method = "GET", .url = url, .headers = headers, .nheaders = 4,
        .profile = BR_HTTP_SANE, .detector_type = 1025};
    /* http.NewRequest ignores the scan context. Retain the injected transport
     * and shared configuration, but discard cancellation and its deadline. */
    br_scan_ctx background = ctx ? *ctx : (br_scan_ctx){0};
    background.cancelled = NULL; background.cancel_user = NULL; background.deadline_monotonic_ms = 0;
    br_http_response response = {0};
    char *send_error = NULL;
    const char *cause = NULL;
    char status_error[80];
    if (br_http_send(&background, &request, &response, &send_error)) cause = send_error ? send_error : "HTTP transport failed";
    else if (response.status == 200) result->verified = true;
    else if (response.status != 401) {
        snprintf(status_error, sizeof(status_error), "got unexpected status code: %d", response.status);
        cause = status_error;
    }
    /* This is error suppression only, not host caching or result suppression.
     * Source supplies ONLY the entire connection for error redaction. */
    if (cause && !strstr(cause, "no such host")) rc = br_result_set_verification_error(result, cause, &redact, 1);
    br_http_release(&background, &response);
    free(send_error); free(canonical); free(authorization); free(url);
    return rc;
}

static int scan_connections(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                              br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !*(br_regex *const *)detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Azure App Configuration scan arguments");
    size_t original_len = out->len;
    connection_matches matches = {.input = input};
    char *regex_error = NULL;
    int rc = br_regex_each(*(br_regex *const *)detector->state, input, collect_connection, &matches, &regex_error);
    if (matches.error) { free(regex_error); regex_error = matches.error; }
    if (error) *error = regex_error;
    else free(regex_error);
    for (size_t i = 0; !rc && i < matches.candidates.len; ++i) {
        br_result *result = &matches.candidates.items[i];
        if (verify) rc = verify_connection(ctx, result);
        if (!rc) rc = br_results_push(out, result);
        if (rc && error && !*error) rc = fail(error, "cannot process Azure App Configuration connection");
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_results_clear(&matches.candidates);
    return rc;
}

static const char *const keywords[] = {".azconfig.io"};
static const br_detector appconfig = {
    .type = 1025, .version = 0, .name = "AzureAppConfigConnectionString", .custom_name = "",
    .description = "Azure App Configuration is a managed service that centralizes application settings and feature flags, enabling dynamic updates without redeploying applications. "
                   "Its connection string, which includes the endpoint URL and an access key, securely connects applications to the configuration store.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &connection_pattern, .scan = scan_connections,
};

int br_azureappconfigconnectionstring_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid AzureAppConfigConnectionString detector output");
    *out = NULL;
    if (!connection_pattern && br_regex_compile("Endpoint=(https://[a-zA-Z0-9-]+\\.azconfig\\.io);Id=([a-zA-Z0-9+/=]+);Secret=([a-zA-Z0-9+/=]+)",
                                                &connection_pattern, error)) return -1;
    *out = &appconfig;
    return 0;
}
