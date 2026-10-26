/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/azure_cosmosdb/{azure_cosmosdb,table}.go. */
#include "detectors.h"
#include "azure_shared_key.h"
#include "captures.h"
#include "findings.h"
#include "host_cache.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct { br_regex *key, *host; } cosmos_patterns;
static br_host_cache invalid_hosts = BR_HOST_CACHE_INIT;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_cosmos(const br_scan_ctx *ctx, const char *host, const char *key,
                          bool table, br_result *result, bool *no_host)
{
    br_bytes decoded = {0};
    size_t bad_offset = SIZE_MAX;
    int rc = br_azure_base64_std_decode((br_slice){(const unsigned char *)key, strlen(key)}, &decoded, &bad_offset);
    if (rc) {
        free(decoded.data);
        if (rc < 0) return -1;
        char message[128];
        snprintf(message, sizeof(message), "failed to decode key: illegal base64 data at input byte %zu", bad_offset);
        return br_result_set_verification_error(result, message, NULL, 0);
    }
    struct timespec now;
    char date[30], canonical[160], signature[45], authorization[192], url[128];
    /* Captured hosts are at most 67 bytes; dates and SHA-256 signatures have
     * fixed lengths. These buffers cover both source signing formats. */
    if (timespec_get(&now, TIME_UTC) != TIME_UTC ||
        br_azure_http_date_utc((int64_t)now.tv_sec, date) != 0) {
        free(decoded.data);
        return -1;
    }
    int n;
    if (table) {
        /* Source TrimPrefix(host, ".table.cosmos.azure.com") is a no-op:
         * the FULL host is the account name in both the signature and auth. */
        n = snprintf(canonical, sizeof(canonical), "%s\n/%s/Tables", date, host);
    } else {
        char lower_date[30];
        for (size_t i = 0; i < sizeof(date); ++i) {
            unsigned char c = (unsigned char)date[i];
            lower_date[i] = (char)(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c);
        }
        n = snprintf(canonical, sizeof(canonical), "get\ndbs\n\n%s\n\n", lower_date);
    }
    if (n < 0 || (size_t)n >= sizeof(canonical) ||
        br_azure_hmac_sha256_base64((br_slice){decoded.data, decoded.len},
            (br_slice){(const unsigned char *)canonical, (size_t)n}, signature) != 0) {
        free(decoded.data);
        return -1;
    }
    free(decoded.data);
    if (table) {
        n = snprintf(authorization, sizeof(authorization), "SharedKeyLite %s:%s", host, signature);
        if (n < 0 || (size_t)n >= sizeof(authorization)) return -1;
    } else {
        const char prefix[] = "type=master&ver=1.0&sig=";
        memcpy(authorization, prefix, sizeof(prefix) - 1);
        char *at = authorization + sizeof(prefix) - 1;
        for (size_t i = 0; signature[i]; ++i) {
            /* QueryEscape applies ONLY to the standard-Base64 signature. */
            const char *escape = signature[i] == '+' ? "%2B" : signature[i] == '/' ? "%2F" :
                                 signature[i] == '=' ? "%3D" : NULL;
            if (escape) { memcpy(at, escape, 3); at += 3; }
            else *at++ = signature[i];
        }
        *at = '\0';
    }
    n = snprintf(url, sizeof(url), "https://%s:443/%s", host, table ? "Tables" : "dbs");
    if (n < 0 || (size_t)n >= sizeof(url)) return -1;
    const br_header headers[] = {
        {"Authorization", authorization}, {"x-ms-date", date},
        {"x-ms-version", table ? "2019-02-02" : "2018-12-31"}, {"Accept", "application/json"},
    };
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = table ? 4 : 3,
        .profile = BR_HTTP_SANE, .detector_type = 971,
    };
    /* Both source verifiers use http.NewRequest, not NewRequestWithContext.
     * Keep the injected transport/configuration, but not scan cancellation. */
    br_scan_ctx background = ctx ? *ctx : (br_scan_ctx){0};
    background.deadline_monotonic_ms = 0;
    background.cancelled = NULL;
    background.cancel_user = NULL;
    br_http_response response = {0};
    char *error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(&background, &request, &response, &error) != 0) {
        if (error && strstr(error, "no such host")) *no_host = true;
        else cause = error ? error : "HTTP transport failed";
    } else if (response.status == 200) result->verified = true;
    else if (response.status != 401 && !(table && response.status == 403)) {
        snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
        cause = status_error;
    }
    /* Source deliberately supplies NO secrets for error redaction. Bodies and
     * deferred drain/close errors are ignored for both database types. */
    rc = cause ? br_result_set_verification_error(result, cause, NULL, 0) : 0;
    br_http_release(&background, &response);
    free(error);
    return rc;
}

static int make_result(br_result *result, int32_t type, const char *key, const char *host)
{
    if (br_finding_pair(result, type, key, "key", host, "account_url") != 0) return -1;
    const char prefix[] = "key: ", middle[] = " account_url: ";
    size_t key_len = strlen(key), host_len = strlen(host);
    size_t len = sizeof(prefix) - 1 + key_len + sizeof(middle) - 1 + host_len;
    unsigned char *raw_v2 = realloc(result->raw_v2.data, len);
    if (!raw_v2) return -1;
    result->raw_v2 = (br_bytes){raw_v2, len};
    memcpy(raw_v2, prefix, sizeof(prefix) - 1);
    memcpy(raw_v2 + sizeof(prefix) - 1, key, key_len);
    memcpy(raw_v2 + sizeof(prefix) - 1 + key_len, middle, sizeof(middle) - 1);
    memcpy(raw_v2 + len - host_len, host, host_len);
    result->extra_data = json_object_new_object();
    return result->extra_data ? 0 : -1;
}

static int set_db_type(br_result *result, bool table)
{
    br_json *value = json_object_new_string(table ? "Table" : "Document");
    if (!value) return -1;
    if (json_object_object_add(result->extra_data, "DB Type", value) == 0) return 0;
    json_object_put(value);
    return -1;
}

static int scan_cosmos(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid AzureCosmosDBKeyIdentifiable scan arguments");
    const cosmos_patterns *compiled = detector->state;
    if (!compiled->key || !compiled->host) return fail(error, "uninitialized Azure Cosmos DB patterns");
    br_captures keys = {0}, hosts = {0};
    int rc = br_captures_find(compiled->key, input, &keys, true, error);
    if (!rc) rc = br_captures_find(compiled->host, input, &hosts, true, error);
    bool *removed = !rc && keys.len && hosts.len ? calloc(hosts.len, sizeof(*removed)) : NULL;
    if (!rc && keys.len && hosts.len && !removed) rc = fail(error, "out of memory tracking Azure Cosmos DB hosts");
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        for (size_t h = 0; !rc && h < hosts.len; ++h) {
            if (removed[h]) continue;
            const char *host = hosts.items[h];
            bool cached = false;
            if (br_host_cache_contains(&invalid_hosts, host, &cached) != 0) {
                rc = fail(error, "wall clock unavailable");
                break;
            }
            if (cached) { removed[h] = true; continue; } /* Source deletes only on Exists. */
            br_result result = {0};
            bool table = strstr(host, ".table.cosmos.azure.com") != NULL, no_host = false;
            if (make_result(&result, detector->type, keys.items[k], host) != 0 ||
                (verify && (verify_cosmos(ctx, host, keys.items[k], table, &result, &no_host) != 0 ||
                            set_db_type(&result, table) != 0))) {
                br_result_clear(&result);
                rc = fail(error, "cannot create Azure Cosmos DB result");
                break;
            }
            if (no_host) {
                br_result_clear(&result);
                if (br_host_cache_add(&invalid_hosts, host) != 0) rc = fail(error, "cannot store invalid Azure Cosmos DB host");
                continue; /* Suppress CURRENT result, but do not yet remove the local host. */
            }
            if (br_results_push(out, &result) != 0) {
                br_result_clear(&result);
                rc = fail(error, "out of memory appending Azure Cosmos DB result");
            }
        }
    }
    free(removed);
    br_captures_clear(&hosts);
    br_captures_clear(&keys);
    return rc;
}

static cosmos_patterns patterns;
static const char *const keywords[] = {".documents.azure.com", ".table.cosmos.azure.com"};
static const br_detector cosmos = {
    .type = 971, .version = 0, .name = "AzureCosmosDBKeyIdentifiable", .custom_name = "",
    .description = "Azure Cosmos DB is a globally distributed, multi-model database service offered by Microsoft. "
                   "CosmosDB keys and connection string are used to connect with Cosmos DB.",
    .keywords = keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .state = &patterns, .scan = scan_cosmos,
};

int br_azure_cosmosdb_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid AzureCosmosDBKeyIdentifiable detector output");
    *out = NULL;
    if (!patterns.key && br_regex_compile("([A-Za-z0-9]{86}==)", &patterns.key, error) != 0) return -1;
    if (!patterns.host && br_regex_compile("([a-z0-9-]{3,44}\\.(?:documents|table\\.cosmos)\\.azure\\.com)",
                                          &patterns.host, error) != 0) return -1;
    *out = &cosmos;
    return 0;
}
