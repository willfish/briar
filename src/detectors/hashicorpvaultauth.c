/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/hashicorpvaultauth. */
#include "detectors.h"
#include "endpoints.h"
#include "findings.h"
#include "../go_unicode.h"
#include "../utf8.h"

#include <json-c/json.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *role, *secret, *url; } approle_patterns;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int put_text(br_json *map, const char *name, br_slice text)
{
    if (text.len > INT_MAX) return -1;
    br_json *value = json_object_new_string_len(text.len ? (const char *)text.data : "", (int)text.len);
    if (!value) return -1;
    if (json_object_object_add(map, name, value) != 0) {
        json_object_put(value);
        return -1;
    }
    return 0;
}

/* The URL match begins with literal http, so only its suffix can be trimmed.
 * Keep original bytes, including NUL and interior VT/Unicode whitespace. */
static br_slice trim_url(br_slice url)
{
    while (url.len) {
        size_t at = url.len - 1;
        while (at && (url.data[at] & 0xc0) == 0x80) --at;
        uint32_t rune;
        size_t width = br_utf8_rune((br_slice){url.data + at, url.len - at}, &rune);
        if (width != url.len - at || !(br_go_unicode_properties(rune) & BR_GO_SPACE)) break;
        url.len = at;
    }
    return url;
}

typedef struct { br_slice input; br_captures *urls; char *error; } url_context;

static int capture_url(void *opaque, const br_span *groups, size_t ngroups)
{
    url_context *context = opaque;
    /* AppRole uses FindAllString, NOT the shared token family's group 1. */
    if (!ngroups || groups[0].begin == SIZE_MAX || groups[0].end <= groups[0].begin ||
        groups[0].end > context->input.len)
        return fail(&context->error, "invalid HashiCorp Vault AppRole URL capture");
    br_slice url = {context->input.data + groups[0].begin, groups[0].end - groups[0].begin};
    return br_captures_push(context->urls, trim_url(url), true, &context->error);
}

static int find_urls(const br_regex *regex, br_slice input, br_captures *urls, char **error)
{
    url_context context = {input, urls, NULL};
    char *regex_error = NULL;
    int rc = br_regex_each(regex, input, capture_url, &context, &regex_error);
    if (context.error) { free(regex_error); regex_error = context.error; }
    if (error) *error = regex_error;
    else free(regex_error);
    return rc;
}

static bool ascii_alnum(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}

/* Provider-local supported request subset, not a Go URL parser. Check full
 * length-bearing bytes AFTER literal assembly and the nil-context branch. */
static bool supported_url(br_slice url)
{
    size_t at;
    if (url.len >= 8 && !memcmp(url.data, "https://", 8)) at = 8;
    else if (url.len >= 7 && !memcmp(url.data, "http://", 7)) at = 7;
    else return false;
    size_t begin = at;
    while (at < url.len && (ascii_alnum(url.data[at]) || url.data[at] == '.' || url.data[at] == '-')) ++at;
    if (at == begin) return false;
    if (at < url.len && url.data[at] == ':') {
        begin = ++at;
        while (at < url.len && url.data[at] >= '0' && url.data[at] <= '9') ++at;
        if (at == begin) return false;
    }
    if (at < url.len && url.data[at] == '/') {
        ++at;
        while (at < url.len && (ascii_alnum(url.data[at]) || url.data[at] == '.' ||
               url.data[at] == '_' || url.data[at] == '~' || url.data[at] == '/' || url.data[at] == '-')) ++at;
    }
    return at == url.len;
}

static int make_payload(br_slice role, br_slice secret, br_bytes *payload, char **error)
{
    static const char first[] = "{\"role_id\":\"", middle[] = "\",\"secret_id\":\"", last[] = "\"}";
    /* Both UUID grammars admit only ASCII hex and hyphens. These fixed strings
     * therefore reproduce json.Marshal's sorted keys and compact escaping
     * exactly, without adding a general JSON encoder. */
    size_t overhead = sizeof(first) - 1 + sizeof(middle) - 1 + sizeof(last) - 1;
    if (role.len > SIZE_MAX - overhead - 1 || secret.len > SIZE_MAX - overhead - 1 - role.len)
        return fail(error, "HashiCorp Vault AppRole JSON payload too large");
    payload->len = overhead + role.len + secret.len;
    payload->data = malloc(payload->len + 1);
    if (!payload->data) return fail(error, "cannot marshal HashiCorp Vault AppRole JSON payload");
    size_t at = sizeof(first) - 1;
    memcpy(payload->data, first, at);
    memcpy(payload->data + at, role.data, role.len); at += role.len;
    memcpy(payload->data + at, middle, sizeof(middle) - 1); at += sizeof(middle) - 1;
    memcpy(payload->data + at, secret.data, secret.len); at += secret.len;
    memcpy(payload->data + at, last, sizeof(last));
    return 0;
}

static int copy_cause(char **cause, const char *message, char **error)
{
    *cause = strdup(message);
    return *cause ? 0 : fail(error, "cannot copy HashiCorp Vault AppRole verification cause");
}

static int verify_match(const br_scan_ctx *ctx, br_slice role, br_slice secret, br_slice endpoint,
                        bool *verified, char **cause, char **error)
{
    static const char suffix[] = "/v1/auth/approle/login";
    br_bytes payload = {0};
    char *url = NULL;
    *verified = false;
    *cause = NULL;
    int rc = make_payload(role, secret, &payload, error);
    if (rc) goto done;
    if (endpoint.len > SIZE_MAX - sizeof(suffix)) {
        rc = fail(error, "HashiCorp Vault AppRole URL too large"); goto done;
    }
    url = malloc(endpoint.len + sizeof(suffix));
    if (!url) { rc = fail(error, "cannot allocate HashiCorp Vault AppRole URL"); goto done; }
    if (endpoint.len) memcpy(url, endpoint.data, endpoint.len);
    memcpy(url + endpoint.len, suffix, sizeof(suffix));
    if (!ctx) {
        rc = copy_cause(cause, "net/http: nil Context", error); goto done;
    }
    if (!supported_url((br_slice){(const unsigned char *)url, endpoint.len + sizeof(suffix) - 1})) {
        rc = fail(error, "unsupported HashiCorp Vault AppRole request URL form"); goto done;
    }
    const br_header headers[] = {{"Content-Type", "application/json"}, {"X-Vault-Namespace", "admin"}};
    const br_http_request request = {
        .method = "POST", .url = url, .headers = headers, .nheaders = 2,
        .body = {payload.data, payload.len}, .profile = BR_HTTP_DETECTOR_PUBLIC,
        .timeout_ms = 10000, .detector_type = 1036,
    };
    br_http_response response = {0};
    bool accepted = false;
    int sent = br_http_send(ctx, &request, &response, cause);
    if (sent) {
        /* Shared setup/Do failures stay ordinary verification causes regardless
         * of wording or sign. Only this module's own failures are fatal. */
        if (!*cause) rc = copy_cause(cause, "HTTP transport failed", error);
    } else {
        free(*cause); *cause = NULL;
        if (response.status == 200) accepted = true;
        else if (response.status == 400 && response.body_error != NULL)
            rc = copy_cause(cause, response.body_error, error);
        else if (response.status != 400 || br_slice_find(response.body,
                     (br_slice){(const unsigned char *)"invalid role or secret ID", sizeof("invalid role or secret ID") - 1}, 0) == SIZE_MAX) {
            char status[80];
            int n = snprintf(status, sizeof(status), "unexpected HTTP response status %d", response.status);
            if (n < 0 || (size_t)n >= sizeof(status)) rc = fail(error, "cannot format HashiCorp Vault AppRole status");
            else rc = copy_cause(cause, status, error);
        }
    }
    /* Drain/close finishes before the caller publishes Verified or invokes the
     * setter. Original URL/JSON/capture storage lives through synchronous release;
     * ordinary shared prepared headers/UA live only through send return. */
    br_http_release(ctx, &response);
    if (!rc) *verified = accepted;
done:
    free(url);
    free(payload.data);
    return rc;
}

static int scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized HashiCorp Vault AppRole scan");
    const approle_patterns *patterns = detector->state;
    br_captures roles = {0}, secrets = {0}, found = {0};
    br_byte_endpoints collected = {0}, urls = {0};
    char *owned_error = NULL;
    size_t original = out->len;
    /* TrimSpace is a no-op for both UUID alphabets. Uniqueness is exact original
     * bytes, not case-folding; deterministic match order represents Go's sets. */
    int rc = br_captures_find(patterns->role, input, &roles, true, &owned_error);
    if (!rc) rc = br_captures_find(patterns->secret, input, &secrets, true, &owned_error);
    if (!rc) rc = find_urls(patterns->url, input, &found, &owned_error);
    if (rc || !roles.len || !secrets.len) goto done;
    rc = br_endpoints_collect_bytes(ctx ? ctx->endpoints : NULL, NULL, &found, &collected, &owned_error);
    for (size_t i = 0; !rc && i < collected.len; ++i)
        rc = br_byte_endpoints_push(&urls, br_byte_endpoints_at(&collected, i), true, &owned_error);
    for (size_t r = 0; !rc && r < roles.len; ++r) {
        br_slice role = br_captures_at(&roles, r);
        for (size_t s = 0; !rc && s < secrets.len; ++s) {
            br_slice secret = br_captures_at(&secrets, s);
            for (size_t u = 0; !rc && u < urls.len; ++u) {
                br_slice endpoint = br_byte_endpoints_at(&urls, u);
                br_result result = {0};
                char *cause = NULL;
                if (br_finding_pair_bytes(&result, 1036, role, "role_id", secret, "secret_id",
                                         (br_slice){(const unsigned char *)":", 1}) != 0)
                    rc = fail(&owned_error, "cannot construct HashiCorp Vault AppRole finding");
                if (!rc) {
                    /* UUIDs are both 36 bytes: Raw is SECRET, RawV2 is ROLE:SECRET. */
                    memcpy(result.raw.data, secret.data, secret.len);
                    result.extra_data = json_object_new_object();
                    if (!result.extra_data || put_text(result.extra_data, "URL", endpoint) != 0)
                        rc = fail(&owned_error, "cannot construct HashiCorp Vault AppRole metadata");
                }
                if (!rc && verify) {
                    bool verified = false;
                    rc = verify_match(ctx, role, secret, endpoint, &verified, &cause, &owned_error);
                    if (!rc) {
                        result.verified = verified;
                        const br_slice redact[] = {role, secret, endpoint};
                        if (br_result_set_verification_error(&result, cause, redact, 3) != 0)
                            rc = fail(&owned_error, "cannot set HashiCorp Vault AppRole verification error");
                    }
                }
                free(cause);
                if (!rc && br_results_push(out, &result) != 0)
                    rc = fail(&owned_error, "cannot append HashiCorp Vault AppRole finding");
                br_result_clear(&result);
            }
        }
    }
done:
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_byte_endpoints_clear(&urls);
    br_byte_endpoints_clear(&collected);
    br_captures_clear(&found);
    br_captures_clear(&secrets);
    br_captures_clear(&roles);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"hashicorp"};
static br_detector approle = {
    .type = 1036, .version = 0, .name = "HashiCorpVaultAuth", .custom_name = "",
    .description = "HashiCorp Vault AppRole authentication method uses role_id and secret_id for machine-to-machine authentication. These credentials can be used to authenticate with Vault and obtain tokens for accessing secrets.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = scan, .validate_endpoints = br_endpoints_validate_configured,
};

int br_hashicorpvaultauth_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid HashiCorp Vault AppRole output");
    *out = NULL;
    if (!approle.state) {
        static approle_patterns compiled;
        approle_patterns patterns = {0};
        const char *const role[] = {"role"}, *const secret[] = {"secret"};
        int rc = br_regex_compile_prefixed(role, 1,
            "\\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b", &patterns.role, error);
        if (!rc) rc = br_regex_compile_prefixed(secret, 1,
            "\\b([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\\b", &patterns.secret, error);
        /* RE2 \\s is [\\t\\n\\f\\r ], NOT PCRE2's VT-inclusive \\s. */
        if (!rc) rc = br_regex_compile("(https?://[^\\x09\\x0a\\x0c\\x0d /]*\\.hashicorp\\.cloud(?::[0-9]+)?)(?:/[^\\x09\\x0a\\x0c\\x0d ]*)?", &patterns.url, error);
        if (rc) {
            br_regex_free(patterns.role); br_regex_free(patterns.secret); br_regex_free(patterns.url);
            return -1;
        }
        compiled = patterns;
        approle.state = &compiled;
    }
    *out = &approle;
    return 0;
}
