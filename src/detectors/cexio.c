/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/cexio/cexio.go. */
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

typedef struct { br_regex *value, *uid; } cexio_patterns;
typedef enum { CEX_ABORT = -1, CEX_KEEP = 0, CEX_SKIP = 1 } cexio_outcome;

static cexio_outcome fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return CEX_ABORT;
}

static int finding(br_result *result, int32_t type, br_slice uid, br_slice key, br_slice secret)
{
    if (br_finding_pair_bytes(result, type, key, "key", secret, "secret", (br_slice){0})) return -1;
    /* Raw remains KEY, but RawV2 omits it: UID+SECRET, without a separator.
     * The owned key+secret buffer is large enough (UID=11, key=24..27).
     * Read separate captures, and shorten the visible length for mixed widths. */
    memcpy(result->raw_v2.data, uid.data, uid.len);
    memcpy(result->raw_v2.data + uid.len, secret.data, secret.len);
    result->raw_v2.len = uid.len + secret.len;
    br_json *part = json_object_new_string_len((const char *)uid.data, (int)uid.len);
    if (!part) return -1;
    if (json_object_object_add(result->secret_parts, "user_id", part)) {
        json_object_put(part);
        return -1;
    }
    return 0;
}

static cexio_outcome sign_request(const char *uid, const char *key, const char *secret,
                                   char nonce[32], char signature[65], char **error)
{
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now)) return fail(error, "cannot read CexIO signing clock");
    /* Unix()*1000 uses WHOLE seconds, ignoring nanoseconds. Check both bounds
     * before conversion/multiplication; zero and representable negative times
     * are supported. Out-of-range Go wraparound is explicitly not emulated. */
    if ((now.tv_sec < 0 && (intmax_t)now.tv_sec < INT64_MIN / INT64_C(1000)) ||
        (now.tv_sec >= 0 && (uintmax_t)now.tv_sec > (uintmax_t)(INT64_MAX / INT64_C(1000))))
        return fail(error, "unsupported: CexIO signing clock range");
    int64_t milliseconds = (int64_t)now.tv_sec * INT64_C(1000);
    int n = snprintf(nonce, 32, "%" PRId64, milliseconds);
    if (n < 0 || n >= 32) return fail(error, "cannot format CexIO signing nonce");
    char message[64]; /* int64 decimal <=20, UID=11, key<=27, plus NUL. */
    n = snprintf(message, sizeof(message), "%s%s%s", nonce, uid, key);
    if (n < 0 || (size_t)n >= sizeof(message)) return fail(error, "cannot construct CexIO signing payload");
    unsigned char digest[32]; size_t count = 0;
    /* Use the captured ASCII secret unchanged, never Base64/hex-decoded. */
    if (!EVP_Q_mac(NULL, "HMAC", NULL, "SHA256", NULL, secret, strlen(secret),
                   (const unsigned char *)message, (size_t)n, digest, sizeof(digest), &count) || count != sizeof(digest))
        return fail(error, "cannot sign CexIO request");
    static const char hex[] = "0123456789ABCDEF";
    for (size_t i = 0; i < sizeof(digest); ++i) {
        signature[i * 2] = hex[digest[i] >> 4]; signature[i * 2 + 1] = hex[digest[i] & 15];
    }
    signature[64] = '\0';
    return CEX_KEEP;
}

static int response_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    bool *bad_type = user;
    /* Response.Error is unused, but its type still gates Unmarshal success.
     * Null is a string no-op. Never clear an earlier duplicate's type error. */
    if (br_json_field_name(name, "error") && value && !json_object_is_type(value, json_type_string)) *bad_type = true;
    return 0;
}

static cexio_outcome accept_response(br_slice body, char **error)
{
    /* Observed native-helper gap: 0xff inside a quoted string is rejected;
     * Go accepts it. For this TYPE-only check, replace only that byte with '?',
     * which is string content but not JSON syntax/whitespace or a valid escape.
     * It cannot turn an unknown name into "error". Error text is unused and
     * never published. Original marker bytes and credentials remain untouched;
     * all other bytes, including controls/NUL/whitespace, are preserved. This
     * is not Unicode repair: PLAIN normalization could wrongly repair controls. */
    unsigned char *storage = NULL; br_slice document = body;
    if (body.len && memchr(body.data, 0xff, body.len)) {
        storage = malloc(body.len);
        if (!storage) return fail(error, "cannot allocate CexIO JSON view");
        for (size_t i = 0; i < body.len; ++i) storage[i] = body.data[i] == 0xff ? '?' : body.data[i];
        document = (br_slice){storage, body.len};
    }
    br_json *root = NULL; char *decode_error = NULL;
    int rc = br_json_document(document, &root, &decode_error);
    free(decode_error); /* Source skips decode errors; no diagnostic is published. */
    if (rc) {
        json_object_put(root); free(storage);
        return rc == 1 ? CEX_SKIP : fail(error, "cannot decode CexIO response");
    }
    cexio_outcome outcome = CEX_KEEP;
    if (root && !json_object_is_type(root, json_type_object)) outcome = CEX_SKIP;
    else if (root) {
        bool bad_type = false;
        /* Ordered visits preserve overwritten type errors. Unknown fields,
         * including huge numbers, are ignored: no blanket float64 conversion. */
        if (br_json_each_member(document, response_member, &bad_type)) outcome = fail(error, "cannot inspect CexIO response");
        else if (bad_type) outcome = CEX_SKIP;
    }
    json_object_put(root); free(storage);
    return outcome;
}

static cexio_outcome verify_cexio(const br_scan_ctx *ctx, const char *uid, const char *key,
                                  const char *secret, br_result *result, char **error)
{
    char nonce[32], signature[65];
    cexio_outcome outcome = sign_request(uid, key, secret, nonce, signature, error);
    if (outcome != CEX_KEEP) return outcome;
    /* Sorted url.Values.Encode(): every value is unreserved under this exact
     * grammar, so checked local formatting needs no new escaping API. */
    char form[160]; /* Maximum 133 bytes plus NUL, including negative int64 nonce. */
    int n = snprintf(form, sizeof(form), "key=%s&nonce=%s&signature=%s", key, nonce, signature);
    if (n < 0 || (size_t)n >= sizeof(form)) return fail(error, "cannot construct CexIO request body");
    /* Source clocks/signs BEFORE the known nil-context constructor failure. */
    if (!ctx) return CEX_SKIP;
    const br_header headers[] = {{"Content-Type", "application/x-www-form-urlencoded"}};
    const br_http_request request = {
        .method = "POST", .url = "https://cex.io/api/balance/", .headers = headers, .nheaders = 1,
        .body = {(const unsigned char *)form, (size_t)n}, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error)) {
        /* ALL Do errors retain false findings. ABI1 also mixes adapter setup
         * and allocation errors here; no text classifier repairs that gap. */
        outcome = CEX_KEEP;
    } else if (response.body_error) outcome = CEX_SKIP; /* ReadAll error wins for EVERY status. */
    else {
        static const unsigned char marker[] = "timestamp";
        bool timestamp = br_slice_find(response.body, (br_slice){marker, sizeof(marker) - 1}, 0) != SIZE_MAX;
        outcome = accept_response(response.body, error);
        if (outcome == CEX_KEEP) result->verified = response.status >= 200 && response.status < 300 && timestamp;
    }
    /* Source scan-defers Close ONLY. ABI1 eagerly buffers/releases per pair;
     * native streaming/close timing and POST redirects remain partial gaps. */
    br_http_release(ctx, &response);
    free(transport_error);
    return outcome;
}

static int scan_cexio(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len)) return fail(error, "invalid CexIO scan");
    const cexio_patterns *compiled = detector->state;
    if (!compiled->value || !compiled->uid) return fail(error, "uninitialized CexIO patterns");
    size_t original_len = out->len;
    br_captures values = {0}, uids = {0}; char *owned_error = NULL;
    /* Identical key/secret regexes produce identical occurrence vectors. Use
     * two indices over one vector, retaining diagonals and ALL duplicates. */
    int rc = br_captures_find(compiled->value, input, &values, false, &owned_error);
    if (!rc) rc = br_captures_find(compiled->uid, input, &uids, false, &owned_error);
    for (size_t u = 0; !rc && u < uids.len; ++u) {
        for (size_t k = 0; !rc && k < values.len; ++k) {
            for (size_t s = 0; !rc && s < values.len; ++s) {
                br_result result = {0}; cexio_outcome outcome = CEX_KEEP;
                if (finding(&result, detector->type, br_captures_at(&uids, u), br_captures_at(&values, k), br_captures_at(&values, s)))
                    outcome = fail(&owned_error, "cannot create CexIO result");
                if (outcome == CEX_KEEP && verify)
                    outcome = verify_cexio(ctx, uids.items[u], values.items[k], values.items[s], &result, &owned_error);
                if (outcome == CEX_KEEP && br_results_push(out, &result)) outcome = fail(&owned_error, "cannot append CexIO result");
                br_result_clear(&result); /* Includes SKIP: later products still run. */
                if (outcome == CEX_ABORT) rc = -1;
            }
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&values); br_captures_clear(&uids);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static cexio_patterns patterns;
static const char *const keywords[] = {"cexio", "cex.io"};
static const br_detector cexio = {
    .type = 739, .version = 0, .name = "CexIO", .custom_name = "",
    .description = "CexIO is a cryptocurrency exchange platform. CexIO API keys can be used to access and manage cryptocurrency accounts and transactions.",
    .keywords = keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_cexio,
};

int br_cexio_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid CexIO detector output");
    *out = NULL;
    if (!patterns.value && br_regex_compile_prefixed(keywords, 2, "\\b([0-9A-Za-z]{24,27})\\b", &patterns.value, error)) return -1;
    if (!patterns.uid && br_regex_compile_prefixed(keywords, 2, "\\b([a-z]{2}[0-9]{9})\\b", &patterns.uid, error)) return -1;
    *out = &cexio;
    return 0;
}
