/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/gemini/gemini.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <inttypes.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct { br_regex *key, *secret; } gemini_patterns;
typedef enum { GEMINI_ABORT = -1, GEMINI_KEEP = 0, GEMINI_SKIP = 1 } gemini_outcome;

static int gemini_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int gemini_nonce(int64_t *nonce, char **error)
{
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now)) return gemini_fail(error, "cannot read Gemini signing clock");
    /* UnixNano is signed int64. Do not emulate Go's undefined out-of-range
     * clock result, or overflow a C intermediate at the negative boundary. */
    const int64_t billion = INT64_C(1000000000);
    if (now.tv_nsec < 0 || now.tv_nsec >= billion ||
        (now.tv_sec < 0 && (intmax_t)now.tv_sec < INT64_MIN / billion - 1) ||
        (now.tv_sec >= 0 && (uintmax_t)now.tv_sec > (uintmax_t)(INT64_MAX / billion)))
        return gemini_fail(error, "unsupported: Gemini signing clock range");
    int64_t seconds = (int64_t)now.tv_sec;
    if ((seconds == INT64_MIN / billion - 1 && now.tv_nsec < billion + INT64_MIN % billion) ||
        (seconds == INT64_MAX / billion && now.tv_nsec > INT64_MAX % billion))
        return gemini_fail(error, "unsupported: Gemini signing clock range");
    *nonce = seconds < 0 ? (seconds + 1) * billion + (now.tv_nsec - billion) : seconds * billion + now.tv_nsec;
    return 0;
}

static gemini_outcome gemini_verify(const br_scan_ctx *ctx, const char *key, const char *secret,
                                     br_result *result, char **error)
{
    /* NewRequestWithContext(POST, fixed URL, &bytes.Buffer{}) is FIRST.
     * This known constructor error skips before clock/JSON/crypto work. */
    if (!ctx) return GEMINI_SKIP;
    int64_t nonce;
    if (gemini_nonce(&nonce, error)) return GEMINI_ABORT;
    enum {
        /* Sorted Go map JSON: fixed ASCII strings + at most 20 int64 bytes.
         * No escaping, generic JSON encoder or heap staging is needed. */
        JSON_CAP = sizeof("{\"account\":\"primary\",\"nonce\":,\"request\":\"/v1/account\"}") + 20,
        PAYLOAD_CAP = 4 * ((JSON_CAP - 1 + 2) / 3) + 1
    };
    char json[JSON_CAP], payload[PAYLOAD_CAP], signature[2 * 48 + 1];
    const char *format = !strncmp(key, "master-", 7) ?
        "{\"account\":\"primary\",\"nonce\":%" PRId64 ",\"request\":\"/v1/account\"}" :
        "{\"nonce\":%" PRId64 ",\"request\":\"/v1/account\"}";
    int length = snprintf(json, sizeof(json), format, nonce);
    if (length < 0 || (size_t)length >= sizeof(json)) {
        gemini_fail(error, "cannot construct Gemini signing JSON"); return GEMINI_ABORT;
    }
    int encoded = EVP_EncodeBlock((unsigned char *)payload, (const unsigned char *)json, length);
    if (encoded != 4 * ((length + 2) / 3)) {
        gemini_fail(error, "cannot encode Gemini payload"); return GEMINI_ABORT;
    }
    unsigned char digest[48]; size_t count = 0;
    if (!EVP_Q_mac(NULL, "HMAC", NULL, "SHA384", NULL, secret, strlen(secret),
                   (const unsigned char *)payload, (size_t)encoded, digest, sizeof(digest), &count) || count != sizeof(digest)) {
        gemini_fail(error, "cannot sign Gemini request"); return GEMINI_ABORT;
    }
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(digest); ++i) {
        signature[i * 2] = hex[digest[i] >> 4]; signature[i * 2 + 1] = hex[digest[i] & 15];
    }
    signature[sizeof(signature) - 1] = '\0';
    /* Literal Header MAP replacement, not Header.Add canonicalization. Shared
     * HTTP appends User-Agent. Distinct map-key order is not wire evidence. */
    const br_header headers[] = {
        {"Content-Type", "text/plain"}, {"Content-Length", "0"},
        {"X-GEMINI-APIKEY", key}, {"X-GEMINI-PAYLOAD", payload},
        {"X-GEMINI-SIGNATURE", signature}, {"Cache-Control", "no-cache"}
    };
    const br_http_request request = {
        .method = "POST", .url = "https://api.gemini.com/v1/account",
        .headers = headers, .nheaders = sizeof(headers) / sizeof(headers[0]),
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL;
    /* Whole mixed setup/allocation/Do error domain retains false findings.
     * Never classify messages or invoke a verification-error setter. */
    if (!br_http_send(ctx, &request, &response, &transport_error))
        result->verified = response.status >= 200 && response.status < 300;
    /* Ignore body/read/close errors. All stack/capture bytes survive release.
     * ABI1 eagerly buffers/releases instead of scan-deferred Close-only.
     * Go NoBody, native POST redirects/wire/client details remain gaps. */
    br_http_release(ctx, &response);
    free(transport_error);
    return GEMINI_KEEP;
}

static int gemini_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return gemini_fail(error, "invalid Gemini scan");
    const gemini_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->secret) return gemini_fail(error, "uninitialized Gemini scan");
    size_t original_len = out->len;
    br_captures keys = {0}, secrets = {0}; char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (!rc) rc = br_captures_find(patterns->secret, input, &secrets, false, &owned_error);
    for (size_t k = 0; !rc && k < keys.len; ++k) for (size_t s = 0; !rc && s < secrets.len; ++s) {
        br_result result = {0}; gemini_outcome outcome = GEMINI_KEEP;
        /* TrimSpace cannot change this grammar. Retain original occurrences,
         * duplicates and EVERY key-major product, without similarity filters. */
        if (br_finding_pair_bytes(&result, detector->type, br_captures_at(&keys, k), "key",
                                   br_captures_at(&secrets, s), "secret", (br_slice){0})) {
            gemini_fail(&owned_error, "cannot create Gemini finding"); outcome = GEMINI_ABORT;
        }
        if (outcome == GEMINI_KEEP && verify) outcome = gemini_verify(ctx, keys.items[k], secrets.items[s], &result, &owned_error);
        if (outcome == GEMINI_KEEP && br_results_push(out, &result)) {
            gemini_fail(&owned_error, "cannot append Gemini finding"); outcome = GEMINI_ABORT;
        }
        br_result_clear(&result);
        if (outcome == GEMINI_ABORT) rc = -1;
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys); br_captures_clear(&secrets);
    if (error) *error = owned_error; else free(owned_error);
    return rc ? -1 : 0;
}

static gemini_patterns gemini_compiled;
static const char *const gemini_keywords[] = {"master-", "account-"};
static const br_detector gemini_detector = {
    .type = 876, .version = 0, .name = "Gemini", .custom_name = "",
    .description = "Gemini is a cryptocurrency exchange platform. API keys can be used to access and manage account details and perform transactions.",
    .keywords = gemini_keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &gemini_compiled, .scan = gemini_scan,
};

int br_gemini_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return gemini_fail(error, "invalid Gemini detector output");
    *out = NULL;
    if (!gemini_compiled.key) {
        br_regex *key = NULL, *secret = NULL;
        int rc = br_regex_compile("\\b((?:master-|account-)[0-9A-Za-z]{20})\\b", &key, error);
        if (!rc) rc = br_regex_compile("([A-Za-z0-9]{27,28})", &secret, error);
        if (rc) { br_regex_free(key); br_regex_free(secret); return -1; }
        gemini_compiled = (gemini_patterns){key, secret};
    }
    *out = &gemini_detector;
    return 0;
}
