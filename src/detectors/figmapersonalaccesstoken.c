/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, figmapersonalaccesstoken/{,v1/,v2/,v3/}. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int figma_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static char figma_named_escape(unsigned char c)
{
    switch (c) {
    case '\a': return 'a'; case '\b': return 'b'; case '\f': return 'f';
    case '\n': return 'n'; case '\r': return 'r'; case '\t': return 't';
    case '\v': return 'v'; default: return '\0';
    }
}

static int figma_403_cause(br_slice value, char **cause, char **error)
{
    static const char prefix[] = "unexpected 403 response: ";
    static const char hex[] = "0123456789abcdef";
    size_t size = sizeof(prefix) - 1 + 2 + 1;
    *cause = NULL;
    /* ASCII subset of Go strconv.AppendQuote/appendEscapedRune, selected Go
     * e3336a22ad3f0a90bd252c95d8b5544e02674205. Existing Go BSD notices apply.
     * A SLICE preserves NUL; two passes allocate the complete cause once, with
     * no cap/truncation, temporary quote or copy of the decoded string. */
    for (size_t i = 0; i < value.len; ++i) {
        unsigned char c = value.data[i];
        if (c >= 0x80)
            return figma_fail(error, "unsupported: Figma non-ASCII 403 diagnostic requires Go quoting");
        size_t width = c == '"' || c == '\\' || figma_named_escape(c) ? 2 : c < 0x20 || c == 0x7f ? 4 : 1;
        if (size > SIZE_MAX - width) return figma_fail(error, "Figma 403 cause size overflow");
        size += width;
    }
    char *text = malloc(size);
    if (!text) return figma_fail(error, "cannot allocate Figma 403 cause");
    size_t at = sizeof(prefix) - 1;
    memcpy(text, prefix, at); text[at++] = '"';
    for (size_t i = 0; i < value.len; ++i) {
        unsigned char c = value.data[i]; char escape = figma_named_escape(c);
        if (c == '"' || c == '\\' || escape) {
            text[at++] = '\\'; text[at++] = escape ? escape : (char)c;
        } else if (c < 0x20 || c == 0x7f) {
            text[at++] = '\\'; text[at++] = 'x'; text[at++] = hex[c >> 4]; text[at++] = hex[c & 15];
        } else text[at++] = (char)c;
    }
    text[at++] = '"'; text[at] = '\0';
    *cause = text;
    return 0;
}

typedef struct { br_json *err; char *cause; } figma_response;

static int figma_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    figma_response *response = user;
    if (!br_json_field_name(name, "err") || !value) return 0; /* Null string is a no-op. */
    if (json_object_is_type(value, json_type_string)) {
        json_object_put(response->err);
        response->err = json_object_get(value); /* Member values are otherwise borrowed. */
    } else if (!response->cause && br_json_type_cause(value, ".err", "string", &response->cause) != 0) return -1;
    /* Last string wins; FIRST type error stays sticky even after an accepted
     * string. Continue projection so later resource errors remain fatal. */
    return 0;
}

static int figma_403(const br_http_response *response, bool *verified, char **cause, char **error)
{
    figma_response projected = {0};
    br_json *root = NULL;
    size_t end = 0;
    int rc = br_json_first_document(response->body, response->body_error, &root, &end, &projected.cause);
    if (rc == 0 && root) {
        if (json_object_is_type(root, json_type_object))
            rc = br_json_each_member((br_slice){response->body.data, end}, figma_member, &projected);
        else if (br_json_type_cause(root, NULL, "struct { Err string \"json:\\\"err\\\"\" }", &projected.cause) != 0) rc = -1;
    }
    json_object_put(root);
    if (rc < 0) rc = figma_fail(error, "cannot decode Figma 403 response");
    else if (projected.cause) {
        /* Decode's single %w envelope disappears in caller SetVerificationError.
         * Pass this owned ROOT cause, never strip text from injected errors. */
        *cause = projected.cause; projected.cause = NULL; rc = 0;
    } else {
        br_slice message = br_json_text(projected.err);
        static const char invalid[] = "Invalid token", scope[] = "Invalid scope(s):";
        if (message.len == sizeof(invalid) - 1 && !memcmp(message.data, invalid, sizeof(invalid) - 1)) rc = 0;
        else if (message.len >= sizeof(scope) - 1 && !memcmp(message.data, scope, sizeof(scope) - 1)) {
            /* BEFORE any quote guard: Unicode/NUL AFTER this prefix may verify. */
            *verified = true; rc = 0;
        } else rc = figma_403_cause(message, cause, error);
    }
    /* Keep decoded string bytes, including NUL, alive until AFTER quoting. No
     * float64-map check: unknown enormous numbers are ignored by typed decode. */
    json_object_put(projected.err); free(projected.cause);
    return rc == 0 ? 0 : -1;
}

static int figma_verify(const br_scan_ctx *ctx, br_slice token, br_result *result, char **error)
{
    if (!ctx) {
        if (br_result_set_verification_error(result, "net/http: nil Context", &token, 1) != 0)
            return figma_fail(error, "cannot set Figma verification error");
        return 0; /* Constructor error RETAINS the complete finding/version map. */
    }
    const br_header header = {"X-Figma-Token", (const char *)token.data};
    const br_http_request request = {
        .method = "GET", .url = "https://api.figma.com/v1/me", .profile = BR_HTTP_SANE,
        .headers = &header, .nheaders = 1, .detector_type = result->detector_type,
    }; /* Logical http.NoBody; borrow the complete token through send AND release. */
    br_http_response response = {0};
    char *send_error = NULL, *owned_cause = NULL;
    const char *cause = NULL;
    char status_error[80];
    int rc = 0;
    /* Retain the WHOLE mixed shared setup/allocation/Do domain via the setter;
     * do not classify diagnostic text as owned resource failures. */
    if (br_http_send(ctx, &request, &response, &send_error) != 0)
        cause = send_error ? send_error : "HTTP transport failed";
    else if (response.status == 200) result->verified = true; /* Body/read errors ignored. */
    else if (response.status == 403) {
        rc = figma_403(&response, &result->verified, &owned_cause, error); cause = owned_cause;
    } else if (response.status != 401) {
        int n = snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error)) rc = figma_fail(error, "cannot format Figma verification status");
        else cause = status_error;
    }
    /* Quote BEFORE token-only redaction. Copy causes before release/free; NULL
     * is a no-op. Setter +1 and owned decoder/projector/quote failures are fatal. */
    if (rc == 0 && br_result_set_verification_error(result, cause, &token, 1) != 0)
        rc = figma_fail(error, "cannot set Figma verification error");
    /* Source helper drains/closes per verification, not scan end. ABI1 buffers
     * and releases eagerly even on failed sends. Full Unicode diagnostic quoting,
     * JSON/UTF-8/Reader/native client/error-chain/regexp and global parity remain
     * partial; keep native guards unchanged and tests strictly injected/offline. */
    br_http_release(ctx, &response);
    free(send_error); free(owned_cause);
    return rc == 0 ? 0 : -1;
}

static int figma_finding(br_result *result, const br_detector *detector, br_slice token, char **error)
{
    if (br_finding_key_bytes(result, detector->type, token, "token") != 0)
        return figma_fail(error, "cannot create FigmaPersonalAccessToken result");
    result->extra_data = json_object_new_object();
    br_json *version = json_object_new_string(detector->version == 1 ? "1" : detector->version == 2 ? "2" : "3");
    if (!result->extra_data || !version || json_object_object_add(result->extra_data, "version", version) != 0) {
        json_object_put(version);
        return figma_fail(error, "cannot create FigmaPersonalAccessToken version metadata");
    }
    return 0;
}

static int figma_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || detector->version < 1 || detector->version > 3 ||
        !out || (!input.data && input.len)) return figma_fail(error, "invalid or uninitialized FigmaPersonalAccessToken scan");
    size_t original_len = out->len;
    br_captures tokens = {0}; char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &tokens, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < tokens.len; ++i) {
        br_result result = {0};
        /* Original occurrences/duplicates; TrimSpace is a no-op. ALWAYS owned
         * version-string metadata BEFORE verification, including every error. */
        rc = figma_finding(&result, detector, br_captures_at(&tokens, i), &owned_error);
        if (rc == 0 && verify) rc = figma_verify(ctx, br_captures_at(&tokens, i), &result, &owned_error);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = figma_fail(&owned_error, "cannot append FigmaPersonalAccessToken result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&tokens);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const figma_keywords[] = {"figma"}, *const figma_v3_keywords[] = {"figp_"};
static br_detector figma_detectors[] = {
    {.type = 113, .version = 1, .name = "FigmaPersonalAccessToken", .custom_name = "",
     .description = "Figma is a web-based design tool. Personal Access Tokens can be used to access and modify design files and other resources.",
     .keywords = figma_keywords, .nkeywords = 1, .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1, .scan = figma_scan},
    {.type = 113, .version = 2, .name = "FigmaPersonalAccessToken", .custom_name = "",
     .description = "Figma is a collaborative interface design tool. Figma Personal Access Tokens can be used to access and manipulate design files and other resources on behalf of a user.",
     .keywords = figma_keywords, .nkeywords = 1, .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1, .scan = figma_scan},
    {.type = 113, .version = 3, .name = "FigmaPersonalAccessToken", .custom_name = "",
     .description = "Figma is a collaborative interface design tool. Figma Personal Access Tokens can be used to access and manipulate design files and other resources on behalf of a user.",
     .keywords = figma_v3_keywords, .nkeywords = 1, .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1, .scan = figma_scan},
};

static int figma_init(size_t index, const br_detector **out, char **error)
{
    static const char *const patterns[] = {
        "\\b([0-9]{6}-[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\\b",
        "\\b(fig[d|((u|o)(r|h)?)]_[a-z0-9A-Z_-]{40})\\b", /* Preserve source's literal bracket-class bug. */
        "(figp_[a-zA-Z0-9_=-]{40,54})(?:[^a-zA-Z0-9_=-]|\\z)", /* Direct, no left boundary, consumes delimiter. */
    };
    if (error) *error = NULL;
    if (!out) return figma_fail(error, "invalid FigmaPersonalAccessToken detector output");
    *out = NULL;
    br_detector *detector = &figma_detectors[index];
    if (!detector->state) {
        br_regex *pattern = NULL;
        int rc = index == 2 ? br_regex_compile(patterns[index], &pattern, error) :
            br_regex_compile_prefixed(detector->keywords, 1, patterns[index], &pattern, error);
        if (rc != 0) return -1;
        detector->state = pattern;
    }
    *out = detector;
    return 0;
}

int br_figmapersonalaccesstoken_v1_init(const br_detector **out, char **error) { return figma_init(0, out, error); }
int br_figmapersonalaccesstoken_v2_init(const br_detector **out, char **error) { return figma_init(1, out, error); }
int br_figmapersonalaccesstoken_v3_init(const br_detector **out, char **error) { return figma_init(2, out, error); }
