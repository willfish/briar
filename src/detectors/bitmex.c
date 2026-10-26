/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/bitmex/bitmex.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <inttypes.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct { br_regex *key, *secret; } bitmex_patterns;
typedef struct { br_slice input; br_captures *values; size_t width; char *error; } bitmex_parts;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int collect_part(void *user, const br_span *groups, size_t ngroups)
{
    bitmex_parts *parts = user;
    if (ngroups < 2 || groups[1].begin == SIZE_MAX || groups[1].end <= groups[1].begin ||
        groups[1].end > parts->input.len || groups[1].end - groups[1].begin != parts->width + 2)
        return fail(&parts->error, "invalid Bitmex capture");
    /* Capture includes exactly ONE leading and trailing SPACE/CR/LF. Source
     * TrimSpace removes those two bytes. Keep the regex consuming both. */
    br_slice token = {parts->input.data + groups[1].begin + 1, parts->width};
    return br_captures_push(parts->values, token, false, &parts->error);
}

static int find_parts(const br_regex *pattern, br_slice input, size_t width, br_captures *values, char **error)
{
    bitmex_parts parts = {input, values, width, NULL};
    char *regex_error = NULL;
    int rc = br_regex_each(pattern, input, collect_part, &parts, &regex_error);
    if (parts.error) { free(regex_error); regex_error = parts.error; }
    if (error) *error = regex_error;
    else free(regex_error);
    return rc;
}

static int verify_bitmex(const br_scan_ctx *ctx, const char *key, const char *secret, br_result *result)
{
    time_t now = time(NULL);
    if (now == (time_t)-1) return -1;
    int64_t seconds = (int64_t)now;
    if ((time_t)seconds != now || seconds > INT64_MAX - 5) return -1;
    char expires[32], message[64], signature[65];
    int n = snprintf(expires, sizeof(expires), "%" PRId64, seconds + 5);
    if (n < 0 || (size_t)n >= sizeof(expires)) return -1;
    n = snprintf(message, sizeof(message), "GET/api/v1/user%s", expires);
    if (n < 0 || (size_t)n >= sizeof(message)) return -1;
    unsigned char digest[32];
    size_t digest_len = 0;
    /* EVP_Q_mac returns the output pointer on success, NULL on failure. Sign
     * ASCII secret bytes, not a Base64-decoded key; the payload is EMPTY. */
    if (!EVP_Q_mac(NULL, "HMAC", NULL, "SHA256", NULL, secret, strlen(secret),
                   (const unsigned char *)message, (size_t)n, digest, sizeof(digest), &digest_len) || digest_len != 32)
        return -1;
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(digest); ++i) {
        signature[i * 2] = hex[digest[i] >> 4]; signature[i * 2 + 1] = hex[digest[i] & 15];
    }
    signature[64] = '\0';
    if (!ctx)
        return br_result_set_verification_error(result, "net/http: nil Context", NULL, 0) != 0 ? -1 : 0;
    const br_header headers[] = {{"api-expires", expires}, {"api-key", key}, {"api-signature", signature}};
    /* Empty url.Values{}.Encode() has zero bytes; Go turns its strings.Reader
     * into NoBody. Do not invent Content-Type, Accept or Content-Length. */
    const br_http_request request = {.method = "GET", .url = "https://www.bitmex.com/api/v1/user",
        .headers = headers, .nheaders = 3, .profile = BR_HTTP_SANE, .detector_type = 512};
    br_http_response response = {0};
    char *error = NULL;
    const char *cause = NULL;
    char status_error[80];
    if (br_http_send(ctx, &request, &response, &error) != 0)
        cause = error ? error : "HTTP transport failed";
    else if (response.status == 200) result->verified = true;
    else if (response.status != 401) {
        snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
        cause = status_error;
    }
    /* The source supplies NO secrets to SetVerificationError. Preserve its
     * deliberately UNREDACTED errors, including echoed keys and secrets. */
    int rc = br_result_set_verification_error(result, cause, NULL, 0);
    br_http_release(ctx, &response);
    free(error);
    return rc != 0 ? -1 : 0;
}

static int scan_bitmex(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Bitmex scan arguments");
    const bitmex_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->secret) return fail(error, "uninitialized Bitmex patterns");
    size_t original_len = out->len;
    br_captures keys = {0}, secrets = {0};
    int rc = find_parts(patterns->key, input, 24, &keys, error);
    if (!rc) rc = find_parts(patterns->secret, input, 48, &secrets, error);
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        for (size_t s = 0; !rc && s < secrets.len; ++s) {
            br_result result = {0};
            if (br_finding_pair(&result, detector->type, secrets.items[s], "secret", keys.items[k], "key") != 0)
                rc = fail(error, "out of memory creating Bitmex result");
            else {
                /* Explicit reversed layout: Raw=SECRET, but RawV2=KEY+SECRET,
                 * unlike the default Raw-first order of the finding helper. */
                memcpy(result.raw_v2.data, keys.items[k], 24);
                memcpy(result.raw_v2.data + 24, secrets.items[s], 48);
                if (verify && verify_bitmex(ctx, keys.items[k], secrets.items[s], &result) != 0)
                    rc = fail(error, "could not sign or record Bitmex verification");
            }
            if (!rc && br_results_push(out, &result) != 0)
                rc = fail(error, "out of memory appending Bitmex result");
            br_result_clear(&result);
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys); br_captures_clear(&secrets);
    return rc ? -1 : 0;
}

static bitmex_patterns patterns;
static const char *const keywords[] = {"bitmex"};
static const br_detector bitmex = {
    .type = 512, .version = 0, .name = "Bitmex", .custom_name = "",
    .description = "Bitmex is a cryptocurrency exchange and derivative trading platform. Bitmex API keys can be used to access and trade on the platform programmatically.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_bitmex,
};

int br_bitmex_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Bitmex detector output");
    *out = NULL;
    if (!patterns.key && br_regex_compile_prefixed(keywords, 1, "([ \\r\\n]{1}[0-9a-zA-Z\\-\\_]{24}[ \\r\\n]{1})", &patterns.key, error) != 0) return -1;
    if (!patterns.secret && br_regex_compile_prefixed(keywords, 1, "([ \\r\\n]{1}[0-9a-zA-Z\\-\\_]{48}[ \\r\\n]{1})", &patterns.secret, error) != 0) return -1;
    *out = &bitmex;
    return 0;
}
