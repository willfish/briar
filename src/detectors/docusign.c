/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/docusign/docusign.go and common/utils.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *id, *secret; } docusign_patterns;
typedef enum { DOCUSIGN_MISSING, DOCUSIGN_FOUND, DOCUSIGN_TOO_LONG, DOCUSIGN_READ_SHAPE } docusign_body_match;

static int docusign_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int docusign_send_failure(char **error, const char *leaf)
{
    /* go-errors/errors.WrapPrefix preserves the Error() text, not a typed
     * unwrapping/redaction setter. Add precisely one prefix to the flat leaf. */
    static const char prefix[] = "Error making request: ";
    size_t len = strlen(leaf);
    if (len > SIZE_MAX - sizeof(prefix)) return docusign_fail(error, "cannot allocate Docusign send error");
    char *text = malloc(sizeof(prefix) + len);
    if (!text) return docusign_fail(error, "cannot allocate Docusign send error");
    memcpy(text, prefix, sizeof(prefix) - 1);
    memcpy(text + sizeof(prefix) - 1, leaf, len + 1);
    if (error) *error = text;
    else free(text);
    return -1;
}

/* Bounded ScanLines policy, not a general Reader implementation. A token must
 * finish before Contains runs; early matching tokens stop all later reads. */
static docusign_body_match docusign_scan_lines(br_slice body)
{
    static const unsigned char marker[] = "ey", newline[] = "\n";
    const size_t limit = 65536;
    size_t at = 0;
    while (at < body.len) {
        size_t remaining = body.len - at;
        br_slice window = {body.data + at, remaining < limit ? remaining : limit};
        size_t lf = br_slice_find(window, (br_slice){newline, 1}, 0);
        if (lf == SIZE_MAX) {
            if (remaining > limit) return DOCUSIGN_TOO_LONG;
            /* Whether final bytes arrived with EOF/error is absent from ABI1.
             * Guard BOTH found and missing outcomes for this exact boundary. */
            if (remaining == limit) return DOCUSIGN_READ_SHAPE;
        }
        size_t length = lf == SIZE_MAX ? remaining : lf;
        if (length && window.data[length - 1] == '\r') --length; /* Only ONE trailing CR. */
        if (br_slice_find((br_slice){window.data, length}, (br_slice){marker, sizeof(marker) - 1}, 0) != SIZE_MAX)
            return DOCUSIGN_FOUND;
        if (lf == SIZE_MAX) return DOCUSIGN_MISSING;
        at += lf + 1;
    }
    return DOCUSIGN_MISSING;
}

static int docusign_verify(const br_scan_ctx *ctx, br_slice id, br_slice secret,
                           br_result *result, char **error)
{
    char *authorization = NULL;
    if (br_http_basic_auth(id, secret, &authorization, error) != 0) return -1;
    /* 73 input bytes -> 100 Base64 bytes -> 106 auth bytes plus NUL. The owned
     * helper value remains complete through synchronous send AND release. */
    const br_header headers[] = {
        {"Accept", "application/vnd.docusign+json; version=3"},
        {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "POST", .url = "https://account-d.docusign.com/oauth/token?grant_type=client_credentials",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int rc = 0, status = 0;
    bool found = false;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0) {
        /* The WHOLE mixed setup/allocation/Do domain is fatal. Do not classify
         * diagnostic text, strip existing prefixes or redact either credential. */
        rc = docusign_send_failure(error, transport_error ? transport_error : "HTTP transport failed");
    } else {
        status = response.status;
        if (!response.body.data && response.body.len) {
            rc = docusign_fail(error, "unsupported: Docusign invalid response body slice");
        } else {
            docusign_body_match match = docusign_scan_lines(response.body);
            if (match == DOCUSIGN_TOO_LONG) rc = docusign_fail(error, "bufio.Scanner: token too long");
            else if (match == DOCUSIGN_READ_SHAPE)
                rc = docusign_fail(error, "unsupported: Docusign Scanner read shape for a 65536-byte final line");
            else if (match == DOCUSIGN_FOUND) found = true;
            else if (response.body_error != NULL) rc = docusign_fail(error, response.body_error);
        }
    }
    /* Copy every borrowed fatal cause before release. Source closes BEFORE its
     * read-error/status decision; no Result verification-error setter is used. */
    br_http_release(ctx, &response);
    free(transport_error); free(authorization);
    if (rc == 0) result->verified = status >= 200 && status < 300 && found;
    /* Eager buffering cannot reproduce general Scanner/Reader chunk timing.
     * Native POST redirects remain fail-closed; full client/global parity is open. */
    return rc == 0 ? 0 : -1;
}

static int docusign_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return docusign_fail(error, "invalid or uninitialized Docusign scan");
    const docusign_patterns *patterns = detector->state;
    if (!patterns->id || !patterns->secret) return docusign_fail(error, "uninitialized Docusign patterns");
    size_t original_len = out->len;
    br_captures ids = {0}, secrets = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->id, input, &ids, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->secret, input, &secrets, false, &owned_error);
    /* Independent ID-major occurrence products, duplicates and self-pairs.
     * TrimSpace is a no-op; the span hint is not a local pairing restriction. */
    for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
        br_slice id = br_captures_at(&ids, i);
        for (size_t s = 0; rc == 0 && s < secrets.len; ++s) {
            br_result result = {0};
            br_slice secret = br_captures_at(&secrets, s);
            if (br_finding_pair_bytes(&result, detector->type, id, "id", secret, "secret", (br_slice){0}) != 0)
                rc = docusign_fail(&owned_error, "cannot create Docusign result");
            if (rc == 0) {
                result.redacted = strdup(ids.items[i]);
                if (!result.redacted) rc = docusign_fail(&owned_error, "cannot create Docusign Redacted");
            }
            /* Finding and owned Redacted resources precede the known constructor
             * skip. Basic encoding/header preparation happens only AFTER it. */
            if (rc == 0 && (!verify || ctx)) {
                if (verify) rc = docusign_verify(ctx, id, secret, &result, &owned_error);
                if (rc == 0 && br_results_push(out, &result) != 0)
                    rc = docusign_fail(&owned_error, "cannot append Docusign result");
            }
            br_result_clear(&result);
        }
    }
    /* Source fatal send/read returns nil, discarding ALL findings from this
     * invocation. Caller-owned findings must survive both source and own errors. */
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&secrets); br_captures_clear(&ids);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static docusign_patterns docusign_compiled;
static const char *const docusign_keywords[] = {"docusign"};
static const br_detector docusign_detector = {
    .type = 919, .version = 0, .name = "Docusign", .custom_name = "",
    .description = "Docusign is an electronic signature and digital transaction management service. Docusign credentials can be used to access and manage digital transactions and documents.",
    .keywords = docusign_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &docusign_compiled, .scan = docusign_scan,
};

int br_docusign_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return docusign_fail(error, "invalid Docusign detector output");
    *out = NULL;
    static const char uuid[] = "\\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b";
    static const char *const id_prefixes[] = {"integration", "id"}, *const secret_prefixes[] = {"secret"};
    if (!docusign_compiled.id && br_regex_compile_prefixed(id_prefixes, 2, uuid, &docusign_compiled.id, error) != 0) return -1;
    if (!docusign_compiled.secret && br_regex_compile_prefixed(secret_prefixes, 1, uuid, &docusign_compiled.secret, error) != 0) return -1;
    *out = &docusign_detector;
    return 0;
}
