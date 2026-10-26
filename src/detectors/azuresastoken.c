/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/azuresastoken/azuresastoken.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "host_cache.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct {
    br_regex *url, *query, *sp, *sv, *sr, *time, *sig, *sip;
} sas_patterns;
typedef struct {
    br_slice input;
    const sas_patterns *patterns;
    br_captures urls, accounts, keys;
    char *error;
} sas_captures;
static br_host_cache invalid_accounts = BR_HOST_CACHE_INIT;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int set_cause(char **cause, const char *message)
{
    *cause = strdup(message);
    return *cause ? 0 : -1;
}

static bool named(br_slice name, const char *expected)
{
    return name.len == strlen(expected) && !memcmp(name.data, expected, name.len);
}

static int found_value(void *user, const br_span *groups, size_t ngroups)
{
    (void)groups; (void)ngroups;
    *(bool *)user = true;
    return 0;
}

static int matches(const br_regex *pattern, br_slice value, bool *found, char **error)
{
    *found = false;
    return br_regex_each(pattern, value, found_value, found, error);
}

static int valid_key(const sas_patterns *patterns, br_slice key, bool *valid, char **error)
{
    br_slice sp = {0}, sv = {0}, sr = {0}, sig = {0}, st = {0}, se = {0}, sip = {0};
    *valid = false;
    static const unsigned char amp[] = "&", equal[] = "=";
    for (size_t at = 0; at < key.len;) {
        size_t end = br_slice_find(key, (br_slice){amp, 1}, at);
        if (end == SIZE_MAX) end = key.len;
        br_slice pair = {key.data + at, end - at};
        size_t eq = br_slice_find(pair, (br_slice){equal, 1}, 0);
        if (eq != SIZE_MAX) {
            br_slice name = {pair.data, eq}, value = {pair.data + eq + 1, pair.len - eq - 1};
            /* Raw map assignment: LAST duplicate wins, even if earlier values
             * were invalid. No unescaping or numeric/date interpretation. */
            if (named(name, "sp")) sp = value;
            else if (named(name, "sv")) sv = value;
            else if (named(name, "sr")) sr = value;
            else if (named(name, "sig")) sig = value;
            else if (named(name, "st")) st = value;
            else if (named(name, "se")) se = value;
            else if (named(name, "sip")) sip = value;
        }
        if (end == key.len) break;
        at = end + 1;
    }
    if (!sp.data || !sv.data || !sr.data || !sig.data || (!st.data && !se.data)) return 0;
    bool found = false;
    int rc = matches(patterns->sp, sp, &found, error);
    if (rc || !found) return rc;
    rc = matches(patterns->sv, sv, &found, error);
    if (rc || !found) return rc;
    rc = matches(patterns->sr, sr, &found, error);
    if (rc || !found) return rc;
    rc = matches(patterns->sig, sig, &found, error);
    if (rc || !found) return rc;
    if (st.data) {
        rc = matches(patterns->time, st, &found, error);
        if (rc || !found) return rc;
    }
    if (se.data) {
        rc = matches(patterns->time, se, &found, error);
        if (rc || !found) return rc;
    }
    if (sip.data) {
        rc = matches(patterns->sip, sip, &found, error);
        if (rc || !found) return rc;
    }
    *valid = true;
    return 0;
}

static int collect_url(void *user, const br_span *groups, size_t ngroups)
{
    sas_captures *captures = user;
    if (ngroups < 2 || groups[0].begin == SIZE_MAX || groups[1].begin == SIZE_MAX ||
        groups[0].end <= groups[0].begin || groups[1].end <= groups[1].begin ||
        groups[0].end > captures->input.len || groups[1].end > captures->input.len)
        return fail(&captures->error, "invalid Azure SAS URL capture");
    br_slice url = {captures->input.data + groups[0].begin, groups[0].end - groups[0].begin};
    br_slice account = {captures->input.data + groups[1].begin, groups[1].end - groups[1].begin};
    size_t before = captures->urls.len;
    int rc = br_captures_push(&captures->urls, url, true, &captures->error);
    if (!rc && captures->urls.len != before)
        rc = br_captures_push(&captures->accounts, account, false, &captures->error);
    return rc;
}

static int collect_key(void *user, const br_span *groups, size_t ngroups)
{
    sas_captures *captures = user;
    if (!ngroups || groups[0].begin == SIZE_MAX || groups[0].end <= groups[0].begin ||
        groups[0].end > captures->input.len)
        return fail(&captures->error, "invalid Azure SAS query capture");
    br_slice key = {captures->input.data + groups[0].begin, groups[0].end - groups[0].begin};
    bool valid = false;
    int rc = valid_key(captures->patterns, key, &valid, &captures->error);
    if (!rc && valid) rc = br_captures_push(&captures->keys, key, true, &captures->error);
    return rc;
}

/* Byte-aware creation policy, BEFORE any C-string URL or HTTP transport.
 * Go first splits '#', then checks controls in the non-fragment prefix. Its
 * RawQuery does not validate '%' escapes. Fragment/non-ASCII/punctuation forms
 * outside this bounded subset remain explicit candidate-level gaps. */
static int request_gate(const br_scan_ctx *ctx, br_slice key, char **cause)
{
    if (!ctx) return set_cause(cause, "net/http: nil Context");
    static const unsigned char hash[] = "#";
    size_t fragment = br_slice_find(key, (br_slice){hash, 1}, 0);
    size_t prefix = fragment == SIZE_MAX ? key.len : fragment;
    for (size_t i = 0; i < prefix; ++i)
        if (key.data[i] < 0x20 || key.data[i] == 0x7f)
            return set_cause(cause, "net/url: invalid control character in URL");
    if (fragment != SIZE_MAX)
        return set_cause(cause, "unsupported: Azure SAS query contains a fragment");
    static const char punctuation[] = "&=:%+/-._~";
    for (size_t i = 0; i < key.len; ++i) {
        unsigned char c = key.data[i];
        bool alnum = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
        if (!alnum && !memchr(punctuation, c, sizeof(punctuation) - 1))
            return set_cause(cause, "unsupported: Azure SAS query outside native ASCII subset");
    }
    return 0;
}

static bool contains(br_slice value, const char *text)
{
    return br_slice_find(value, (br_slice){(const unsigned char *)text, strlen(text)}, 0) != SIZE_MAX;
}

/* Return 0 for a candidate outcome, -1 for resources. DNS is a SEPARATE output,
 * never an integer sentinel that could collide with a positive core error. */
static int verify_sas(const br_scan_ctx *ctx, br_slice url, br_slice key, bool retry,
                       bool *verified, bool *dns, char **cause)
{
    *verified = false; *dns = false; *cause = NULL;
    int rc = request_gate(ctx, key, cause);
    if (rc || *cause) return rc;
    if (key.len > SIZE_MAX - 2 || url.len > SIZE_MAX - key.len - 2) return -1;
    char *request_url = malloc(url.len + key.len + 2);
    if (!request_url) return -1;
    memcpy(request_url, url.data, url.len);
    request_url[url.len] = '?';
    memcpy(request_url + url.len + 1, key.data, key.len);
    request_url[url.len + key.len + 1] = '\0';
    const br_http_request request = {.method = "GET", .url = request_url,
        .profile = BR_HTTP_SANE, .detector_type = 975};
    br_http_response response = {0};
    char *error = NULL;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        if (error && strstr(error, "no such host")) *dns = true;
        else if (error) { *cause = error; error = NULL; }
        else rc = set_cause(cause, "HTTP transport failed");
    } else if (response.body_error) {
        /* ReadAll happens before EVERY status. Never classify its errors as DNS. */
        rc = set_cause(cause, response.body_error);
    } else if (response.status == 200) *verified = true;
    else if (response.status == 403) {
        if (retry && contains(response.body, "Signature did not match")) {
            static const unsigned char suffix[] = "&comp=list&restype=container";
            if (key.len > SIZE_MAX - (sizeof(suffix) - 1)) rc = -1;
            else {
                br_bytes extended = {malloc(key.len + sizeof(suffix) - 1), key.len + sizeof(suffix) - 1};
                if (!extended.data) rc = -1;
                else {
                    memcpy(extended.data, key.data, key.len);
                    memcpy(extended.data + key.len, suffix, sizeof(suffix) - 1);
                    /* Keep the outer response alive until the inner call has
                     * released its response, like the source's deferred Close. */
                    rc = verify_sas(ctx, url, (br_slice){extended.data, extended.len}, false, verified, dns, cause);
                }
                free(extended.data);
            }
        } else if (contains(response.body, "AuthorizationFailure") && contains(key, "&sip="))
            rc = set_cause(cause, "SAS token is restricted to specific IP addresses");
    } else {
        char status_error[80];
        snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        rc = set_cause(cause, status_error);
    }
    br_http_release(ctx, &response);
    free(error);
    free(request_url);
    return rc;
}

static int scan_sas(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Azure SAS scan arguments");
    const sas_patterns *patterns = detector->state;
    if (!patterns->url || !patterns->query || !patterns->sp || !patterns->sv || !patterns->sr ||
        !patterns->time || !patterns->sig || !patterns->sip)
        return fail(error, "uninitialized Azure SAS patterns");
    size_t original_len = out->len;
    sas_captures captures = {.input = input, .patterns = patterns};
    char *regex_error = NULL;
    int rc = br_regex_each(patterns->url, input, collect_url, &captures, &regex_error);
    if (!rc) { free(regex_error); regex_error = NULL; rc = br_regex_each(patterns->query, input, collect_key, &captures, &regex_error); }
    if (captures.error) { free(regex_error); regex_error = captures.error; }
    if (error) *error = regex_error;
    else free(regex_error);
    /* One allowed deterministic map order; no success break or consumption. */
    for (size_t u = 0; !rc && u < captures.urls.len; ++u) {
        for (size_t k = 0; !rc && k < captures.keys.len; ++k) {
            if (verify) {
                bool cached = false;
                if (br_host_cache_contains(&invalid_accounts, captures.accounts.items[u], &cached) != 0) {
                    rc = fail(error, "cannot check Azure SAS account cache"); break;
                }
                if (cached) break;
            }
            br_slice url = br_captures_at(&captures.urls, u), key = br_captures_at(&captures.keys, k);
            br_result result = {0};
            if (br_finding_pair_bytes(&result, detector->type, url, "url", key, "key", (br_slice){0}) != 0)
                rc = fail(error, "cannot create Azure SAS result");
            if (!rc && verify) {
                bool verified = false, dns = false;
                char *cause = NULL;
                int checked = verify_sas(ctx, url, key, true, &verified, &dns, &cause);
                if (checked != 0) rc = fail(error, "out of memory verifying Azure SAS candidate");
                else if (dns) {
                    if (br_host_cache_add(&invalid_accounts, captures.accounts.items[u]) != 0)
                        rc = fail(error, "cannot cache invalid Azure SAS account");
                    free(cause); br_result_clear(&result);
                    break; /* Suppress current candidate and remaining keys for this URL. */
                } else {
                    result.verified = verified;
                    /* Public setter returns +1 on allocation failure. */
                    if (br_result_set_verification_error(&result, cause, &key, 1) != 0)
                        rc = fail(error, "out of memory recording Azure SAS verification error");
                }
                free(cause);
            }
            if (!rc && br_results_push(out, &result) != 0)
                rc = fail(error, "out of memory appending Azure SAS result");
            br_result_clear(&result);
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&captures.urls); br_captures_clear(&captures.accounts); br_captures_clear(&captures.keys);
    return rc ? -1 : 0;
}

static bool sas_false_positive(const br_detector *detector, const br_result *result, char **reason)
{
    (void)detector; (void)result;
    if (reason) *reason = strdup("");
    return false;
}

static sas_patterns patterns;
static const char *const keywords[] = {"azure", ".blob.core.windows.net"};
static const br_detector sas = {
    .type = 975, .version = 0, .name = "AzureSasToken", .custom_name = "",
    .description = "An Azure Shared Access Signature (SAS) token is a time-limited, permission-based URL query string that grants secure, granular access to Azure Storage resources (e.g., blobs, containers, files) without exposing account keys.",
    .keywords = keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_sas, .false_positive = sas_false_positive,
};

int br_azuresastoken_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Azure SAS detector output");
    *out = NULL;
    if (!patterns.url && br_regex_compile("https://([a-zA-Z0-9][a-z0-9_-]{1,22}[a-zA-Z0-9])\\.blob\\.core\\.windows\\.net/[a-z0-9]([a-z0-9-]{1,61}[a-z0-9])?(?:/[a-zA-Z0-9._-]+)*", &patterns.url, error) != 0) return -1;
    /* RE2 ASCII \\s excludes VT; PCRE2 \\s includes it. Keep the substitution LOCAL. */
    if (!patterns.query && br_regex_compile("[a-z]{2,4}=[^&=\\x09\\x0A\\x0C\\x0D\\x20\"'<>]+(?:&[a-z]{2,4}=[^&=\\x09\\x0A\\x0C\\x0D\\x20\"'<>]+)+", &patterns.query, error) != 0) return -1;
    if (!patterns.sp && br_regex_compile("^[racwdli]+$", &patterns.sp, error) != 0) return -1;
    if (!patterns.sv && br_regex_compile("^\\d{4}-\\d{2}-\\d{2}$", &patterns.sv, error) != 0) return -1;
    if (!patterns.sr && br_regex_compile("^[bcfso]$", &patterns.sr, error) != 0) return -1;
    if (!patterns.time && br_regex_compile("^\\d{4}-\\d{2}-\\d{2}T\\d{2}(?::|%3[Aa])\\d{2}(?::|%3[Aa])\\d{2}Z$", &patterns.time, error) != 0) return -1;
    if (!patterns.sig && br_regex_compile("^[a-zA-Z0-9%+/=]{10,}$", &patterns.sig, error) != 0) return -1;
    if (!patterns.sip && br_regex_compile("^\\d{1,3}(?:\\.\\d{1,3}){3}(?:-\\d{1,3}(?:\\.\\d{1,3}){3})?$", &patterns.sip, error) != 0) return -1;
    *out = &sas;
    return 0;
}
