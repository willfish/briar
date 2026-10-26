/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/azure_batch/azurebatch.go. */
#include "detectors.h"
#include "azure_shared_key.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct { br_regex *url, *secret; } batch_patterns;
typedef struct {
    br_slice input;
    br_captures endpoints, accounts;
    char *error;
} batch_urls;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int collect_urls(void *user, const br_span *groups, size_t ngroups)
{
    batch_urls *urls = user;
    if (ngroups < 3 || groups[0].begin == SIZE_MAX || groups[1].begin == SIZE_MAX ||
        groups[0].end <= groups[0].begin || groups[1].end <= groups[1].begin ||
        groups[0].end > urls->input.len || groups[1].end > urls->input.len)
        return fail(&urls->error, "invalid Azure Batch URL capture");
    br_slice endpoint = {urls->input.data + groups[0].begin, groups[0].end - groups[0].begin};
    br_slice account = {urls->input.data + groups[1].begin, groups[1].end - groups[1].begin};
    if (br_captures_push(&urls->endpoints, endpoint, false, &urls->error) != 0) return -1;
    return br_captures_push(&urls->accounts, account, false, &urls->error);
}

static bool ascii_alnum(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
}

static bool supported_endpoint(br_slice endpoint, br_slice account)
{
    /* Extraction remains the greedy source regex. Verification deliberately
     * supports only ordinary ASCII DNS labels: no URL repair, userinfo, ports,
     * escapes, controls, Unicode or normalization behind injected responses. */
    if (endpoint.len <= 8 || endpoint.len > 125 || account.len > 50 ||
        memcmp(endpoint.data, "https://", 8)) return false;
    size_t label = 0;
    unsigned char previous = 0;
    for (size_t i = 8; i < endpoint.len; ++i) {
        unsigned char c = endpoint.data[i];
        if (c == '.') {
            if (!label || previous == '-') return false;
            label = 0;
        } else {
            if (!ascii_alnum(c) && c != '-') return false;
            if (!label && c == '-') return false;
            if (++label > 63) return false;
        }
        previous = c;
    }
    return label && previous != '-';
}

static int verify_batch(const br_scan_ctx *ctx, br_slice endpoint, br_slice account,
                         br_slice encoded_key, br_result *result)
{
    if (!supported_endpoint(endpoint, account))
        return br_result_set_verification_error(result,
            "unsupported: Azure Batch endpoint outside native ASCII DNS subset", NULL, 0);
    char account_name[51], lower_account[51];
    memcpy(account_name, account.data, account.len);
    account_name[account.len] = '\0';
    for (size_t i = 0; i < account.len; ++i) {
        unsigned char c = account.data[i];
        lower_account[i] = (char)(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c);
    }
    lower_account[account.len] = '\0';
    time_t now = time(NULL);
    char date[30];
    if (now == (time_t)-1 || br_azure_http_date_utc((int64_t)now, date) != 0) return -1;
    char to_sign[256], url[256], authorization[128], signature[45];
    int n = snprintf(to_sign, sizeof(to_sign),
        "GET\n\n\n\n\napplication/json\n%s\n\n\n\n\n\n/%s/applications\napi-version:2020-09-01.12.0",
        date, lower_account);
    if (n < 0 || (size_t)n >= sizeof(to_sign)) return -1;
    br_bytes decoded = {0};
    size_t bad_offset = SIZE_MAX;
    int decoded_status = br_azure_base64_std_decode(encoded_key, &decoded, &bad_offset);
    /* Source deliberately ignores corrupt-input errors but signs the decoded
     * prefix, including empty, partial-padded and full 66-byte keys. */
    int rc = decoded_status < 0 ? -1 : br_azure_hmac_sha256_base64(
        (br_slice){decoded.data, decoded.len}, (br_slice){(unsigned char *)to_sign, (size_t)n}, signature);
    free(decoded.data);
    if (rc) return -1;
    n = snprintf(url, sizeof(url), "%.*s/applications?api-version=2020-09-01.12.0",
                 (int)endpoint.len, endpoint.data);
    if (n < 0 || (size_t)n >= sizeof(url)) return -1;
    n = snprintf(authorization, sizeof(authorization), "SharedKey %s:%s", account_name, signature);
    if (n < 0 || (size_t)n >= sizeof(authorization)) return -1;
    const br_header headers[] = {
        {"Content-Type", "application/json"}, {"Authorization", authorization}, {"Date", date},
    };
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 3,
        .profile = BR_HTTP_DETECTOR_PUBLIC, .detector_type = 957,
    };
    br_http_response response = {0};
    char *error = NULL;
    const char *cause = NULL;
    char status_error[384];
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        if (!error || !strstr(error, "no such host")) cause = error ? error : "HTTP transport failed";
    } else {
        switch (response.status) {
        case 200: result->verified = true; break;
        case 403: break;
        default:
            snprintf(status_error, sizeof(status_error), "unexpected status code %d for %s", response.status, url);
            cause = status_error;
            break;
        }
    }
    /* Upstream omits redaction arguments. Never log the unsanitized cause. */
    rc = br_result_set_verification_error(result, cause, NULL, 0);
    br_http_release(ctx, &response);
    free(error);
    return rc;
}

static int scan_batch(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid AzureBatch scan arguments");
    const batch_patterns *compiled = detector->state;
    if (!compiled->url || !compiled->secret) return fail(error, "uninitialized AzureBatch patterns");
    batch_urls urls = {.input = input};
    br_captures secrets = {0};
    char *regex_error = NULL;
    int rc = br_regex_each(compiled->url, input, collect_urls, &urls, &regex_error);
    if (urls.error) { free(regex_error); regex_error = urls.error; }
    if (error) *error = regex_error;
    else free(regex_error);
    if (!rc) rc = br_captures_find(compiled->secret, input, &secrets, false, error);
    for (size_t u = 0; !rc && u < urls.endpoints.len; ++u) {
        br_slice endpoint = br_captures_at(&urls.endpoints, u);
        br_slice account = br_captures_at(&urls.accounts, u);
        for (size_t k = 0; !rc && k < secrets.len; ++k) {
            br_slice key = br_captures_at(&secrets, k);
            br_result result = {0};
            if (br_finding_pair_bytes(&result, detector->type, endpoint, "url", key, "account_key",
                                       (br_slice){0}) != 0) {
                rc = fail(error, "out of memory creating AzureBatch result");
            } else {
                result.redacted = malloc(endpoint.len + 1);
                if (!result.redacted) rc = fail(error, "out of memory copying AzureBatch endpoint");
                else {
                    memcpy(result.redacted, endpoint.data, endpoint.len);
                    result.redacted[endpoint.len] = '\0';
                    if (verify && verify_batch(ctx, endpoint, account, key, &result) != 0)
                        rc = fail(error, "could not sign AzureBatch verification request");
                }
            }
            bool verified = result.verified;
            if (!rc && br_results_push(out, &result) != 0)
                rc = fail(error, "out of memory appending AzureBatch result");
            br_result_clear(&result);
            if (verified) break;
        }
    }
    br_captures_clear(&urls.endpoints);
    br_captures_clear(&urls.accounts);
    br_captures_clear(&secrets);
    return rc;
}

static bool batch_false_positive(const br_detector *detector, const br_result *result, char **reason)
{
    (void)detector;
    (void)result;
    if (reason) *reason = strdup("");
    return false;
}

static batch_patterns patterns;
static const char *const keywords[] = {".batch.azure.com"};
static const br_detector batch = {
    .type = 957, .version = 0, .name = "AzureBatch", .custom_name = "",
    .description = "Azure Batch is a cloud service that provides large-scale parallel and "
                   "high-performance computing (HPC) applications efficiently in the cloud. "
                   "Azure Batch account keys can be used to manage and control access to these resources.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_batch, .false_positive = batch_false_positive,
};

int br_azure_batch_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid AzureBatch detector output");
    *out = NULL;
    if (!patterns.url && br_regex_compile("https://(.{1,50})\\.(.{1,50})\\.batch\\.azure\\.com",
                                          &patterns.url, error) != 0) return -1;
    /* Capture wrapper feeds the shared byte collector without changing matching. */
    if (!patterns.secret && br_regex_compile("([A-Za-z0-9+/=]{88})", &patterns.secret, error) != 0)
        return -1;
    *out = &batch;
    return 0;
}
