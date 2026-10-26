/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/bitfinex. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <inttypes.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int sign_request(const char *secret, char nonce[32], char signature[97], char **error)
{
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now)) return fail(error, "cannot read Bitfinex signing clock");
    /* A bounded nonnegative UnixNano range, not a Go time compatibility layer.
     * Check both the seconds product and nanosecond addition before either can
     * overflow. Negative/out-of-range clocks are explicit scan errors. */
    if (now.tv_sec < 0 || (uintmax_t)now.tv_sec > (uintmax_t)(INT64_MAX / INT64_C(1000000000)) ||
        now.tv_nsec < 0 || now.tv_nsec >= 1000000000L)
        return fail(error, "unsupported: Bitfinex signing clock range");
    int64_t nanos = (int64_t)now.tv_sec * INT64_C(1000000000);
    if ((int64_t)now.tv_nsec > INT64_MAX - nanos)
        return fail(error, "unsupported: Bitfinex signing clock range");
    nanos += (int64_t)now.tv_nsec;
    int n = snprintf(nonce, 32, "%" PRId64, nanos / 1000);
    if (n < 0 || n >= 32) return fail(error, "cannot format Bitfinex signing nonce");
    char canonical[96];
    n = snprintf(canonical, sizeof(canonical), "/api/v2/auth/r/wallets%s{}", nonce);
    if (n < 0 || (size_t)n >= sizeof(canonical)) return fail(error, "cannot construct Bitfinex signing payload");
    unsigned char digest[48]; size_t count = 0;
    /* The 43-byte captured ASCII secret is used unchanged, never decoded. */
    if (!EVP_Q_mac(NULL, "HMAC", NULL, "SHA384", NULL, secret, strlen(secret),
                   (const unsigned char *)canonical, (size_t)n, digest, sizeof(digest), &count) || count != sizeof(digest))
        return fail(error, "cannot sign Bitfinex request");
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(digest); ++i) {
        signature[i * 2] = hex[digest[i] >> 4]; signature[i * 2 + 1] = hex[digest[i] & 15];
    }
    signature[96] = '\0';
    return 0;
}

static int body_diagnostic(br_slice body, char **owned, const char **cause, char **error)
{
    static const char unsupported[] = "unsupported: Bitfinex non-UTF-8 or NUL response body diagnostic";
    static const char prefix[] = "failed to verify Bitfinex API key, error: ";
    *owned = NULL;
    if (body.len && memchr(body.data, 0, body.len)) { *cause = unsupported; return 0; }
    br_slice decoded = {0}; br_bytes storage = {0}; char *decode_error = NULL;
    int rc = br_utf8_decode(body, &decoded, &storage, &decode_error);
    bool invalid_utf8 = storage.data != NULL;
    free(storage.data); free(decode_error);
    if (rc) return fail(error, "cannot validate Bitfinex response diagnostic");
    if (invalid_utf8) { *cause = unsupported; return 0; }
    /* Validation only: preserve original valid Unicode and non-NUL controls,
     * never the PLAIN decoder's normalized bytes. */
    if (body.len > SIZE_MAX - sizeof(prefix)) return fail(error, "Bitfinex response diagnostic too large");
    char *text = malloc(sizeof(prefix) + body.len);
    if (!text) return fail(error, "cannot allocate Bitfinex response diagnostic");
    memcpy(text, prefix, sizeof(prefix) - 1);
    if (body.len) memcpy(text + sizeof(prefix) - 1, body.data, body.len);
    text[sizeof(prefix) - 1 + body.len] = '\0';
    *owned = text; *cause = text;
    return 0;
}

static int set_cause(br_result *result, const char *cause, char **error)
{
    /* Source passes NO secrets: transport/read/body errors stay unredacted. */
    if (br_result_set_verification_error(result, cause, NULL, 0))
        return fail(error, "cannot store Bitfinex verification error");
    return 0;
}

static int verify_bitfinex(const br_scan_ctx *ctx, const char *key, const char *secret, br_result *result, char **error)
{
    char nonce[32], signature[97];
    if (sign_request(secret, nonce, signature, error)) return -1;
    /* Source gets time and signs BEFORE constructing the context-bound request. */
    if (!ctx) return set_cause(result, "net/http: nil Context", error);
    static const unsigned char body[] = "{}";
    const br_header headers[] = {
        {"Content-Type", "application/json"}, {"Accept", "application/json"},
        {"bfx-apikey", key}, {"bfx-signature", signature}, {"bfx-nonce", nonce},
    };
    const br_http_request request = {
        .method = "POST", .url = "https://api.bitfinex.com/v2/auth/r/wallets",
        .headers = headers, .nheaders = 5, .body = {body, 2},
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL, *owned_diagnostic = NULL;
    char status_error[80]; const char *cause = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &transport_error)) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else if (response.status == 200) {
        result->verified = true; /* Ignore all deferred body/drain/close errors. */
    } else if (response.status == 500) {
        if (response.body_error) cause = response.body_error;
        else {
            static const unsigned char digest_invalid[] = "apikey: digest invalid";
            static const unsigned char key_invalid[] = "apikey: invalid";
            /* Binary markers precede NUL/UTF-8 diagnostic guards. */
            if (br_slice_find(response.body, (br_slice){digest_invalid, sizeof(digest_invalid) - 1}, 0) == SIZE_MAX &&
                br_slice_find(response.body, (br_slice){key_invalid, sizeof(key_invalid) - 1}, 0) == SIZE_MAX)
                rc = body_diagnostic(response.body, &owned_diagnostic, &cause, error);
        }
    } else {
        snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        cause = status_error;
    }
    if (!rc) rc = set_cause(result, cause, error);
    /* ABI1 eager release does not establish Go streaming/drain/close timing.
     * Native POST redirect guards are retained; there is no fallback profile. */
    br_http_release(ctx, &response);
    free(transport_error); free(owned_diagnostic);
    return rc ? -1 : 0;
}

static int scan_bitfinex(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Bitfinex scan");
    br_captures values = {0}; char *owned_error = NULL;
    size_t original_len = out->len;
    /* Identical pure patterns produce identical independent unique sets. One
     * vector represents them; every unequal directed pair remains a finding. */
    int rc = br_captures_find(detector->state, input, &values, true, &owned_error);
    for (size_t key = 0; !rc && key < values.len; ++key) {
        for (size_t secret = 0; !rc && secret < values.len; ++secret) {
            if (key == secret) continue;
            br_result result = {0};
            if (br_finding_key_bytes(&result, detector->type, br_captures_at(&values, key), "key"))
                rc = fail(&owned_error, "cannot create Bitfinex result");
            if (!rc && verify) rc = verify_bitfinex(ctx, values.items[key], values.items[secret], &result, &owned_error);
            if (!rc && br_results_push(out, &result)) rc = fail(&owned_error, "cannot append Bitfinex result");
            br_result_clear(&result);
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&values);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"bitfinex"};
static br_detector bitfinex = {
    .type = 56, .version = 0, .name = "Bitfinex", .custom_name = "",
    .description = "Bitfinex is a cryptocurrency exchange offering various trading options. Bitfinex API keys can be used to access and manage trading accounts.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = scan_bitfinex,
};

int br_bitfinex_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Bitfinex detector output");
    *out = NULL;
    if (br_key_pattern_init(&bitfinex, "\\b([A-Za-z0-9_-]{43})\\b", error)) return -1;
    *out = &bitfinex;
    return 0;
}
