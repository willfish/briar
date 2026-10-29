/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/invoiceocean/invoiceocean.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *host; } invoiceocean_patterns;
enum { INVOICEOCEAN_KEY_SIZE = 20 };

static int invoiceocean_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int invoiceocean_verify(const br_scan_ctx *ctx, br_slice key, br_slice host,
                               br_result *result, bool *keep, char **error)
{
    static const char prefix[] = "https://";
    static const char path[] = "/invoices.json?period=this_month&api_token=";
    const size_t fixed = sizeof(prefix) - 1 + sizeof(path) - 1 + INVOICEOCEAN_KEY_SIZE + 1;
    if (host.len > SIZE_MAX - fixed)
        return invoiceocean_fail(error, "InvoiceOcean URL too large");
    char *url = malloc(host.len + fixed);
    if (!url) return invoiceocean_fail(error, "cannot allocate InvoiceOcean URL");
    /* The complete literal URL precedes NewRequestWithContext's nil drop.
     * Both captures are ASCII; no escaping, joining or DNS-label cap applies. */
    size_t at = sizeof(prefix) - 1;
    memcpy(url, prefix, at);
    memcpy(url + at, host.data, host.len); at += host.len;
    memcpy(url + at, path, sizeof(path) - 1); at += sizeof(path) - 1;
    memcpy(url + at, key.data, key.len); at += key.len;
    url[at] = '\0';
    if (!ctx) {
        *keep = false;
        free(url);
        return 0;
    }
    const br_header headers[] = {{"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_DETECTOR_PUBLIC, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Suppress the whole mixed shared setup/Do error domain, not diagnostics.
     * Source ignores every body/read error and never sets verification errors. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Exactly one ordinary release, even after preparation/guard failure.
     * Provider URL, captures and original headers survive release. Synthesized
     * effective request/header-array/UA storage lasts only through send return;
     * eager release does not reproduce source deferred-close timing or leaks. */
    br_http_release(ctx, &response);
    free(send_error);
    free(url);
    return 0;
}

static int invoiceocean_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                             br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return invoiceocean_fail(error, "invalid or uninitialized InvoiceOcean scan");
    const invoiceocean_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->host)
        return invoiceocean_fail(error, "uninitialized InvoiceOcean patterns");
    size_t original_len = out->len;
    br_captures keys = {0}, hosts = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->host, input, &hosts, false, &owned_error);
    /* Independent key-FIRST extraction, then full key-major occurrence products,
     * including duplicates. Hosts are required even in NoV and stay hidden.
     * TrimSpace is a no-op; span1024 belongs to the engine, not this scan. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        br_slice key = br_captures_at(&keys, k);
        for (size_t h = 0; rc == 0 && h < hosts.len; ++h) {
            br_slice host = br_captures_at(&hosts, h);
            br_result result = {0};
            bool keep = true;
            if (key.len != INVOICEOCEAN_KEY_SIZE || !host.len)
                rc = invoiceocean_fail(&owned_error, "invalid InvoiceOcean capture");
            else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
                rc = invoiceocean_fail(&owned_error, "cannot create InvoiceOcean finding");
            if (rc == 0 && verify)
                rc = invoiceocean_verify(ctx, key, host, &result, &keep, &owned_error);
            if (rc == 0 && keep && br_results_push(out, &result) != 0)
                rc = invoiceocean_fail(&owned_error, "cannot append InvoiceOcean finding");
            br_result_clear(&result);
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&hosts);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static invoiceocean_patterns invoiceocean_compiled;
static const char *const invoiceocean_keywords[] = {"invoiceocean"};
static const br_detector invoiceocean_detector = {
    .type = 689, .version = 0, .name = "InvoiceOcean", .custom_name = "",
    .description = "InvoiceOcean is an online invoicing service. InvoiceOcean API tokens can be used to access and manage invoices and other financial data.",
    .keywords = invoiceocean_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &invoiceocean_compiled, .scan = invoiceocean_scan,
};

int br_invoiceocean_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return invoiceocean_fail(error, "invalid InvoiceOcean detector output");
    *out = NULL;
    if (!invoiceocean_compiled.key && br_regex_compile_prefixed(invoiceocean_keywords, 1,
            "\\b([0-9A-Za-z]{20})\\b", &invoiceocean_compiled.key, error) != 0) return -1;
    if (!invoiceocean_compiled.host && br_regex_compile("\\b([0-9a-z]{1,}\\.invoiceocean\\.com)\\b",
            &invoiceocean_compiled.host, error) != 0) return -1;
    *out = &invoiceocean_detector;
    return 0;
}
