/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/duo/duo.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <inttypes.h>
#include <json-c/json.h>
#include <limits.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct { br_regex *host, *ikey, *skey; } duo_patterns;
typedef struct { bool verified; int status; char *cause; } duo_verdict;
static const char admin_path[] = "/admin/v1/info/summary";
static const char auth_path[] = "/auth/v2/check";

static int duo_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int duo_cause(char **cause, const char *message, char **error)
{
    *cause = strdup(message);
    return *cause ? 0 : duo_fail(error, "cannot create Duo verification cause");
}

/* Private HTTP UTC formatting, not Azure policy or a general Go time layer.
 * CLOCK_REALTIME is read on EVERY attempt, including nil-context constructors
 * and the Auth fallback. Negative epochs (including -1) are valid dates. */
static int duo_date(char date[30], char **error)
{
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0)
        return duo_fail(error, "unsupported: Duo signing clock failure");
    time_t seconds = now.tv_sec;
    struct tm utc;
    if (!gmtime_r(&seconds, &utc)) return duo_fail(error, "unsupported: Duo signing clock range");
    int64_t year = (int64_t)utc.tm_year + 1900;
    if (year < 0 || year > 9999 || utc.tm_mon < 0 || utc.tm_mon > 11 || utc.tm_wday < 0 || utc.tm_wday > 6)
        return duo_fail(error, "unsupported: Duo signing clock range");
    static const char *const days[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    static const char *const months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    int len = snprintf(date, 30, "%s, %02d %s %04" PRId64 " %02d:%02d:%02d GMT",
        days[utc.tm_wday], utc.tm_mday, months[utc.tm_mon], year, utc.tm_hour, utc.tm_min, utc.tm_sec);
    return len == 29 ? 0 : duo_fail(error, "cannot format Duo HTTP date");
}

/* 0 includes ordinary status/constructor/Do errors; -1 is a fatal OWNED native
 * failure, never permission for fallback. Own verdict->cause, if non-NULL. */
static int duo_request(const br_scan_ctx *ctx, br_slice host, br_slice ikey, br_slice skey,
                         const char *path, duo_verdict *verdict, char **error)
{
    char date[30], signature[41], authorization[91];
    unsigned char digest[20], credentials[61];
    _Static_assert(sizeof(credentials) == 20 + 1 + 40, "Duo Basic plaintext must be 61 bytes");
    _Static_assert(sizeof(authorization) == 6 + 84 + 1, "Duo Basic value must be 90 bytes plus NUL");
    char *canonical = NULL, *url = NULL, *send_error = NULL;
    br_http_response response = {0}; bool sent = false;
    int rc = duo_date(date, error);
    if (rc) return -1;
    size_t path_len = strlen(path);
    if (host.len > SIZE_MAX - path_len - 37) return duo_fail(error, "Duo canonical request too large");
    size_t length = host.len + path_len + 36;
    canonical = malloc(length + 1);
    if (!canonical) return duo_fail(error, "cannot allocate Duo canonical request");
    size_t at = 0;
    memcpy(canonical + at, date, 29); at += 29;
    memcpy(canonical + at, "\nGET\n", 5); at += 5;
    memcpy(canonical + at, host.data, host.len); at += host.len;
    canonical[at++] = '\n'; memcpy(canonical + at, path, path_len); at += path_len;
    canonical[at++] = '\n'; canonical[at] = '\0';
    size_t digest_len = 0;
    if (!EVP_Q_mac(NULL, "HMAC", NULL, "SHA1", NULL, skey.data, skey.len,
                   (const unsigned char *)canonical, length, digest, sizeof(digest), &digest_len) || digest_len != 20) {
        rc = duo_fail(error, "cannot sign Duo request"); goto cleanup;
    }
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(digest); ++i) {
        signature[2 * i] = hex[digest[i] >> 4]; signature[2 * i + 1] = hex[digest[i] & 15];
    }
    signature[40] = '\0';
    memcpy(credentials, ikey.data, 20); credentials[20] = ':'; memcpy(credentials + 21, signature, 40);
    memcpy(authorization, "Basic ", 6);
    if (EVP_EncodeBlock((unsigned char *)authorization + 6, credentials, sizeof(credentials)) != 84) {
        rc = duo_fail(error, "cannot encode Duo Basic authorization"); goto cleanup;
    }
    /* The captured host is unbounded. Allocate the complete URL AFTER signing,
     * as the source constructor argument does; never cap it to DNS label limits. */
    if (host.len > SIZE_MAX - path_len - 9) { rc = duo_fail(error, "Duo request URL too large"); goto cleanup; }
    size_t url_len = 8 + host.len + path_len;
    url = malloc(url_len + 1);
    if (!url) { rc = duo_fail(error, "cannot allocate Duo request URL"); goto cleanup; }
    memcpy(url, "https://", 8); memcpy(url + 8, host.data, host.len); memcpy(url + 8 + host.len, path, path_len + 1);
    if (!ctx) {
        /* Date/canonical/HMAC/Base64/URL preparation all precede this ordinary
         * constructor cause. It retains Admin and MUST NOT trigger fallback. */
        rc = duo_cause(&verdict->cause, "net/http: nil Context", error); goto cleanup;
    }
    const br_header headers[] = {{"Authorization", authorization}, {"Date", date}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .detector_type = 1063,
    };
    sent = true;
    if (br_http_send(ctx, &request, &response, &send_error) != 0) {
        /* Combined shared setup/allocation/Do errors are ordinary causes. The
         * ABI error output is owned: MOVE it, rather than clone/strip its text.
         * Source returns status zero on error, even if a response was supplied. */
        verdict->cause = send_error; send_error = NULL;
        if (!verdict->cause) rc = duo_cause(&verdict->cause, "HTTP transport failed", error);
    } else {
        verdict->status = response.status;
        switch (response.status) {
        case 200: case 403: verdict->verified = true; break;
        case 401: break;
        default: {
            char message[64]; int len = snprintf(message, sizeof(message), "unexpected HTTP status %d", response.status);
            rc = len >= 0 && (size_t)len < sizeof(message) ? duo_cause(&verdict->cause, message, error) :
                 duo_fail(error, "cannot format Duo status cause");
            break;
        }
        }
    }
cleanup:
    /* All request bytes remain alive through release. Body/drain/close errors
     * are deliberately ignored. Source drains+closes within EACH verifier, so
     * Admin release completes before the next Auth clock read. Buffered Reader,
     * private/native client and typed transport-chain behavior remain partial. */
    if (sent) br_http_release(ctx, &response);
    free(send_error); free(canonical); free(url);
    return rc ? -1 : 0;
}

static int duo_add(br_json *object, const char *key, br_slice text)
{
    if (text.len > INT_MAX) return -1;
    br_json *value = json_object_new_string_len((const char *)text.data, (int)text.len);
    if (!value) return -1;
    if (json_object_object_add(object, key, value) == 0) return 0;
    json_object_put(value); return -1;
}

static int duo_application(br_result *result, const char *application)
{
    br_slice text = {(const unsigned char *)application, strlen(application)};
    if (duo_add(result->extra_data, "application", text) != 0) return -1;
    return duo_add(result->secret_parts, "application", text);
}

static int duo_finding(br_result *result, br_slice host, br_slice ikey, br_slice skey, char **error)
{
    if (host.len > INT_MAX) return duo_fail(error, "unsupported: Duo host exceeds native JSON string limit");
    if (br_finding_key_bytes(result, 1063, ikey, "ikey") != 0) return duo_fail(error, "cannot create Duo finding");
    if (host.len > SIZE_MAX - 62) return duo_fail(error, "Duo RawV2 too large");
    result->raw_v2.len = host.len + 62;
    result->raw_v2.data = malloc(result->raw_v2.len);
    if (!result->raw_v2.data) return duo_fail(error, "cannot allocate Duo RawV2");
    size_t at = 0;
    memcpy(result->raw_v2.data, host.data, host.len); at += host.len; result->raw_v2.data[at++] = ':';
    memcpy(result->raw_v2.data + at, ikey.data, ikey.len); at += ikey.len; result->raw_v2.data[at++] = ':';
    memcpy(result->raw_v2.data + at, skey.data, skey.len);
    result->extra_data = json_object_new_object();
    if (!result->extra_data || duo_add(result->secret_parts, "host", host) != 0 ||
        duo_add(result->secret_parts, "skey", skey) != 0 || duo_application(result, "Admin API") != 0)
        return duo_fail(error, "cannot create Duo finding metadata");
    return 0;
}

static int duo_verify(const br_scan_ctx *ctx, br_slice host, br_slice ikey, br_slice skey,
                       br_result *result, char **error)
{
    duo_verdict verdict = {0};
    int rc = duo_request(ctx, host, ikey, skey, admin_path, &verdict, error);
    /* Only the ordinary false+nil-error Admin outcome (401) permits Auth.
     * Never infer fallback from response status when there was a send error. */
    if (!rc && !verdict.verified && verdict.cause == NULL) {
        verdict = (duo_verdict){0};
        rc = duo_request(ctx, host, ikey, skey, auth_path, &verdict, error);
        /* The source comment mentions 200, but executable behavior relabels
         * EVERY Auth outcome except 403, including 401 and errors/status zero. */
        if (!rc && verdict.status != 403 && duo_application(result, "Auth API") != 0)
            rc = duo_fail(error, "cannot relabel Duo application");
    }
    if (!rc) {
        const br_slice secrets[] = {host, ikey, skey};
        /* Exactly one setter, in HOST -> IKEY -> SKEY redaction order. A NULL
         * cause is a no-op; positive setter resource failures are still fatal. */
        if (br_result_set_verification_error(result, verdict.cause, secrets, 3) != 0)
            rc = duo_fail(error, "cannot sanitize Duo verification error");
        else result->verified = verdict.verified;
    }
    free(verdict.cause);
    return rc ? -1 : 0;
}

static int duo_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len)) return duo_fail(error, "invalid Duo scan");
    const duo_patterns *patterns = detector->state;
    if (!patterns->host || !patterns->ikey || !patterns->skey) return duo_fail(error, "uninitialized Duo scan");
    size_t original_len = out->len;
    br_captures hosts = {0}, ikeys = {0}, skeys = {0}; char *owned_error = NULL;
    int rc = br_captures_find(patterns->host, input, &hosts, true, &owned_error);
    if (!rc) rc = br_captures_find(patterns->ikey, input, &ikeys, true, &owned_error);
    if (!rc) rc = br_captures_find(patterns->skey, input, &skeys, true, &owned_error);
    /* First-source set iteration is one native order, not randomized Go map
     * parity. Keep HOST-major/IKEY-major/SKEY products and NEVER success-break. */
    for (size_t h = 0; !rc && h < hosts.len; ++h) for (size_t i = 0; !rc && i < ikeys.len; ++i) for (size_t s = 0; !rc && s < skeys.len; ++s) {
        br_slice host = br_captures_at(&hosts, h), ikey = br_captures_at(&ikeys, i), skey = br_captures_at(&skeys, s);
        br_result result = {0};
        rc = duo_finding(&result, host, ikey, skey, &owned_error);
        if (!rc && verify) rc = duo_verify(ctx, host, ikey, skey, &result, &owned_error);
        if (!rc && br_results_push(out, &result) != 0) rc = duo_fail(&owned_error, "cannot append Duo finding");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&hosts); br_captures_clear(&ikeys); br_captures_clear(&skeys);
    if (error) *error = owned_error; else free(owned_error);
    return rc ? -1 : 0;
}

static duo_patterns duo_compiled;
static const char *const duo_keywords[] = {"duosecurity"};
static const br_detector duo_detector = {
    .type = 1063, .version = 0, .name = "Duo", .custom_name = "",
    .description = "Duo is a security platform that provides multi-factor authentication and identity management services.",
    .keywords = duo_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &duo_compiled, .scan = duo_scan,
};

int br_duo_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return duo_fail(error, "invalid Duo detector output");
    *out = NULL;
    if (!duo_compiled.host) {
        br_regex *host = NULL, *ikey = NULL, *skey = NULL;
        static const char *const prefixes[] = {"duo"}; /* NOT the dispatch keyword. */
        int rc = br_regex_compile("\\b([a-z0-9-]{6,}\\.duosecurity\\.com)\\b", &host, error);
        if (!rc) rc = br_regex_compile_prefixed(prefixes, 1, "\\b(DI[A-Z0-9]{18})\\b", &ikey, error);
        if (!rc) rc = br_regex_compile_prefixed(prefixes, 1, "\\b([A-Za-z0-9]{40})\\b", &skey, error);
        if (rc) { br_regex_free(host); br_regex_free(ikey); br_regex_free(skey); return -1; }
        duo_compiled = (duo_patterns){host, ikey, skey};
    }
    *out = &duo_detector;
    return 0;
}
