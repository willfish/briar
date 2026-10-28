/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/gengo/gengo.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"

#include <inttypes.h>
#include <json-c/json.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef enum { GENGO_FATAL = -1, GENGO_KEEP = 0, GENGO_SKIP = 1 } gengo_outcome;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

typedef struct { br_slice input; br_captures values; char *error; } gengo_captures;

static int collect(void *user, const br_span *groups, size_t count)
{
    gengo_captures *captures = user;
    if (count < 2 || groups[1].begin == SIZE_MAX || groups[1].end > captures->input.len ||
        groups[1].end <= groups[1].begin) return fail(&captures->error, "invalid Gengo capture");
    br_slice value = {captures->input.data + groups[1].begin, groups[1].end - groups[1].begin};
    /* Only ASCII space can lead this grammar, and exactly one SP/CR/LF ends it. */
    if (value.len && value.data[0] == ' ') { ++value.data; --value.len; }
    if (value.len) --value.len;
    if (value.len != 64) return fail(&captures->error, "invalid Gengo credential width");
    return br_captures_push(&captures->values, value, false, &captures->error);
}

typedef struct { bool ok, bad_type; } gengo_response;

static int response_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    gengo_response *response = user;
    if (!br_json_field_name(name, "opstat") || !value) return 0;
    if (!json_object_is_type(value, json_type_string)) response->bad_type = true;
    else {
        br_slice text = br_json_text(value);
        response->ok = text.len == 2 && !memcmp(text.data, "ok", 2);
    }
    return 0;
}

static gengo_outcome decode_response(br_slice body, bool *ok, char **error)
{
    br_json *root = NULL; char *cause = NULL;
    int rc = br_json_document(body, &root, &cause);
    free(cause);
    gengo_outcome outcome = GENGO_KEEP;
    if (rc) outcome = rc == 1 ? GENGO_SKIP : fail(error, "cannot decode Gengo response");
    else if (root && !json_object_is_type(root, json_type_object)) outcome = GENGO_SKIP;
    else if (root) {
        gengo_response response = {0};
        /* Visit duplicates in order: null preserves a string, and a later good
         * value cannot erase an earlier type error. Unknown numbers stay untyped. */
        if (br_json_each_member(body, response_member, &response))
            outcome = fail(error, "cannot project Gengo response");
        else if (response.bad_type) outcome = GENGO_SKIP;
        else *ok = response.ok;
    }
    json_object_put(root);
    return outcome;
}

static gengo_outcome verify_gengo(const br_scan_ctx *ctx, const char *key, const char *secret,
                                   br_result *result, char **error)
{
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now)) return fail(error, "cannot read Gengo signing clock");
    if ((now.tv_sec < 0 && (intmax_t)now.tv_sec < INT64_MIN) ||
        (now.tv_sec >= 0 && (uintmax_t)now.tv_sec > (uintmax_t)INT64_MAX))
        return fail(error, "unsupported: Gengo signing clock range");
    /* Signed int64 decimal is at most 20 bytes; SHA1 hex is exactly 40.
     * All request storage remains live through send AND release. */
    char timestamp[21], signature[41];
    int n = snprintf(timestamp, sizeof(timestamp), "%" PRId64, (int64_t)now.tv_sec);
    if (n < 0 || (size_t)n >= sizeof(timestamp)) return fail(error, "cannot format Gengo timestamp");
    unsigned char digest[20]; size_t written = 0;
    if (!EVP_Q_mac(NULL, "HMAC", NULL, "SHA1", NULL, secret, 64,
                   (const unsigned char *)timestamp, (size_t)n, digest, sizeof(digest), &written) || written != sizeof(digest))
        return fail(error, "cannot sign Gengo request");
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(digest); ++i) {
        signature[i * 2] = hex[digest[i] >> 4]; signature[i * 2 + 1] = hex[digest[i] & 15];
    }
    signature[40] = '\0';
    /* Literal query, NOT url.Values: punctuation in the key stays unescaped. */
    char url[sizeof("https://api.gengo.com/v2/account/me?ts=&api_key=&api_sig=") + 20 + 64 + 40];
    n = snprintf(url, sizeof(url), "https://api.gengo.com/v2/account/me?ts=%s&api_key=%s&api_sig=%s", timestamp, key, signature);
    if (n < 0 || (size_t)n >= sizeof(url)) return fail(error, "cannot construct Gengo URL");
    /* The source clocks, signs, and constructs the URL before nil-context failure. */
    if (!ctx) return GENGO_SKIP;
    const br_header headers[] = {{"Accept", "application/json"}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL;
    gengo_outcome outcome = GENGO_KEEP;
    /* ABI1 mixes Do and adapter setup errors. Every such error is retained,
     * with no verification error, as is ReadAll failure at any status. */
    if (!br_http_send(ctx, &request, &response, &transport_error) && !response.body_error) {
        bool ok = false;
        outcome = decode_response(response.body, &ok, error);
        if (outcome == GENGO_KEEP) result->verified = response.status >= 200 && response.status < 300 && ok;
    }
    br_http_release(ctx, &response);
    free(transport_error);
    return outcome;
}

static int scan_gengo(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len)) return fail(error, "invalid Gengo scan");
    gengo_captures captures = {.input = input}; char *owned_error = NULL;
    size_t original_len = out->len;
    int rc = br_regex_each(detector->state, input, collect, &captures, &owned_error);
    if (captures.error) { free(owned_error); owned_error = captures.error; }
    /* Independent identical regexes give identical occurrence vectors, not
     * sets. Keep KEY-major N squared order, self-products, and duplicates. */
    for (size_t k = 0; !rc && k < captures.values.len; ++k) {
        for (size_t s = 0; !rc && s < captures.values.len; ++s) {
            br_result result = {0}; gengo_outcome outcome = GENGO_KEEP;
            br_slice key = br_captures_at(&captures.values, k), secret = br_captures_at(&captures.values, s);
            if (br_finding_pair_bytes(&result, detector->type, key, "key", secret, "secret", (br_slice){0}))
                outcome = fail(&owned_error, "cannot create Gengo finding");
            else memcpy(result.raw.data, secret.data, secret.len); /* Raw=SECRET, V2=KEY+SECRET. */
            if (outcome == GENGO_KEEP && verify)
                outcome = verify_gengo(ctx, captures.values.items[k], captures.values.items[s], &result, &owned_error);
            if (outcome == GENGO_KEEP && br_results_push(out, &result))
                outcome = fail(&owned_error, "cannot append Gengo finding");
            br_result_clear(&result);
            if (outcome == GENGO_FATAL) rc = -1;
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&captures.values);
    if (error) *error = owned_error; else free(owned_error);
    return rc ? -1 : 0;
}

static br_regex *pattern;
static const char *const keywords[] = {"gengo"};
static br_detector gengo = {
    .type = 426, .version = 0, .name = "Gengo", .custom_name = "",
    .description = "Gengo is a platform for professional human translation services. Gengo API keys can be used to access and manage translation projects and resources.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = scan_gengo,
};

int br_gengo_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Gengo detector output");
    *out = NULL;
    if (!pattern && br_regex_compile_prefixed(keywords, 1,
            "([ ]{0,1}[0-9a-zA-Z\\[\\]\\-\\(\\)\\{\\}|_^@$=~]{64}[ \\r\\n]{1})", &pattern, error)) return -1;
    gengo.state = pattern;
    *out = &gengo;
    return 0;
}
