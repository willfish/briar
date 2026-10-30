/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/metabase/metabase.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"
#include "../go_url.h"

#include <json-c/json.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *url; } metabase_patterns;
typedef struct {
    br_go_url_parts parts;
    br_bytes user, password, fragment;
} metabase_url;
/* The capture has at most256 authority/fragment bytes after its fixed scheme.
 * Even escaping every decoded byte threefold fits, including fixed path/NUL. */
enum { METABASE_REQUEST_CAP = 8 + 3 * 256 + sizeof("/api/user/current") + 8 };
typedef struct { char text[METABASE_REQUEST_CAP]; size_t len; } metabase_request;

static int metabase_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static void metabase_url_clear(metabase_url *url)
{
    br_go_url_clear(&url->parts);
    free(url->user.data);
    free(url->password.data);
    free(url->fragment.data);
}

static int metabase_parse_url(br_slice original, metabase_url *url, bool *valid, char **error)
{
    *valid = false;
    br_go_url_error ordinary = {0};
    int rc = br_go_url_parse(original, &url->parts, &ordinary, error);
    if (rc != 0 || ordinary.kind != BR_GO_URL_OK) return rc;
    /* url.Parse decodes userinfo and fragment BEFORE finding creation, even
     * for NoV. Keep binary lengths: decoded NUL is reescaped, not rejected. */
    bool component_valid = true;
    if (url->parts.has_user) {
        rc = br_go_url_decode(url->parts.raw_user, false, &url->user, &component_valid, error);
        if (rc != 0 || !component_valid) return rc;
        if (url->parts.has_password) {
            rc = br_go_url_decode(url->parts.raw_password, false, &url->password, &component_valid, error);
            if (rc != 0 || !component_valid) return rc;
        }
    }
    if (url->parts.raw_fragment.len) {
        rc = br_go_url_decode(url->parts.raw_fragment, false, &url->fragment, &component_valid, error);
        if (rc != 0 || !component_valid) return rc;
    }
    /* ParseURLAndStripPathAndParams clears only Path/RawQuery. This actual
     * grammar cannot capture a path/query, hence no RawPath/ForceQuery effect. */
    url->parts.raw_path = (br_slice){0};
    url->parts.raw_query = (br_slice){0};
    *valid = true;
    return 0;
}

static int metabase_append(metabase_request *out, br_slice bytes, bool escape,
                            br_go_url_encoding mode)
{
    static const char hex[] = "0123456789ABCDEF";
    for (size_t i = 0; i < bytes.len; ++i) {
        unsigned char c = bytes.data[i];
        bool literal = !escape || br_go_url_byte_allowed(c, mode);
        size_t n = literal ? 1 : 3;
        if (n > sizeof(out->text) - 1 - out->len) return -1;
        if (literal) out->text[out->len++] = (char)c;
        else {
            out->text[out->len++] = '%';
            out->text[out->len++] = hex[c >> 4];
            out->text[out->len++] = hex[c & 15];
        }
    }
    out->text[out->len] = '\0';
    return 0;
}

static int metabase_url_string(br_slice original, const metabase_url *url,
                                metabase_request *out)
{
    /* Narrow Go URL.String projection for the actual http[s] capture, not a
     * generic URI builder/validator. Userinfo colon and @ remain separators. */
    br_slice scheme = {original.data, original.data[4] == 's' ? 8 : 7};
    if (metabase_append(out, scheme, false, BR_GO_URL_HOST) != 0) return -1;
    if (url->parts.has_user) {
        if (metabase_append(out, (br_slice){url->user.data, url->user.len}, true, BR_GO_URL_USER) != 0) return -1;
        if (url->parts.has_password) {
            if (metabase_append(out, (br_slice){(const unsigned char *)":", 1}, false, BR_GO_URL_USER) != 0 ||
                metabase_append(out, (br_slice){url->password.data, url->password.len}, true, BR_GO_URL_USER) != 0) return -1;
        }
        if (metabase_append(out, (br_slice){(const unsigned char *)"@", 1}, false, BR_GO_URL_USER) != 0) return -1;
    }
    static const unsigned char path[] = "/api/user/current";
    if (metabase_append(out, url->parts.host, true, BR_GO_URL_HOST) != 0 ||
        metabase_append(out, (br_slice){path, sizeof(path) - 1}, false, BR_GO_URL_PATH) != 0) return -1;
    if (url->fragment.len) {
        /* All non-# bytes in this validated ASCII fragment grammar are valid
         * encoded spelling. Another raw # forces ENTIRE-fragment reescaping. */
        bool reescape = memchr(url->parts.raw_fragment.data, '#', url->parts.raw_fragment.len) != NULL;
        br_slice fragment = reescape ? (br_slice){url->fragment.data, url->fragment.len} : url->parts.raw_fragment;
        if (metabase_append(out, (br_slice){(const unsigned char *)"#", 1}, false, BR_GO_URL_FRAGMENT) != 0 ||
            metabase_append(out, fragment, reescape, BR_GO_URL_FRAGMENT) != 0) return -1;
    }
    return 0;
}

static int metabase_verify(const br_scan_ctx *ctx, const br_http_request *request,
                            br_result *result, bool *drop, char **error)
{
    br_http_response response = {0};
    char *send_error = NULL;
    int rc = 0;
    /* Suppress the WHOLE preparation/Do error domain, with no setter. On
     * successful Do, ReadAll precedes EVERY status check; any read error drops. */
    if (br_http_send(ctx, request, &response, &send_error) == 0) {
        if (response.body_error) *drop = true;
        else if (response.status == 200) {
            br_json *document = NULL;
            char *cause = NULL;
            int decoded = br_json_document(response.body, &document, &cause);
            if (decoded == 0) result->verified = true;
            else if (decoded != 1) rc = metabase_fail(error, "cannot validate Metabase JSON body");
            /* json.Valid accepts ANY complete JSON value, with no conversion
             * of original numbers to float64. Helper+1 is ordinary invalid JSON. */
            json_object_put(document);
            free(cause);
        }
    }
    /* Exactly one release per send, before drop/publication, while ALL original
     * request/parsed URL/key/header storage remains live. No prepared retention. */
    br_http_release(ctx, &response);
    free(send_error);
    return rc;
}

static int metabase_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return metabase_fail(error, "invalid or uninitialized Metabase scan");
    const metabase_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->url) return metabase_fail(error, "uninitialized Metabase patterns");
    size_t original_len = out->len;
    br_captures keys = {0}, urls = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    /* ALL URL matches follow ALL keys, even when there are no keys. */
    if (rc == 0) rc = br_captures_find(patterns->url, input, &urls, false, &owned_error);
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        for (size_t u = 0; rc == 0 && u < urls.len; ++u) {
            br_slice key = br_captures_at(&keys, k), original = br_captures_at(&urls, u);
            metabase_url parsed = {0};
            br_result result = {0};
            bool valid = false, drop = false;
            rc = metabase_parse_url(original, &parsed, &valid, &owned_error);
            /* ASCII captures make TrimSpace a no-op. Original URL bytes, not
             * projected URL, supply parts and key+URL RawV2 with NO separator. */
            if (rc == 0 && valid && br_finding_pair_bytes(&result, detector->type, key, "key",
                original, "url", (br_slice){0}) != 0)
                rc = metabase_fail(&owned_error, "cannot create Metabase finding");
            if (rc == 0 && valid && verify) {
                metabase_request projected = {0};
                rc = metabase_url_string(original, &parsed, &projected);
                if (rc == 0 && !ctx) drop = true; /* String BEFORE constructor skip. */
                else if (rc == 0) {
                    const br_header headers[] = {{"X-Metabase-Session", (const char *)key.data}};
                    const br_http_request request = {
                        .method = "GET", .url = projected.text, .headers = headers, .nheaders = 1,
                        .profile = BR_HTTP_DETECTOR_LOCAL, .detector_type = detector->type,
                    };
                    rc = metabase_verify(ctx, &request, &result, &drop, &owned_error);
                }
            }
            if (rc == 0 && valid && !drop && br_results_push(out, &result) != 0)
                rc = metabase_fail(&owned_error, "cannot append Metabase finding");
            br_result_clear(&result);
            metabase_url_clear(&parsed);
        }
    }
    if (rc != 0) {
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
        metabase_fail(&owned_error, "cannot collect or project Metabase credentials");
    }
    br_captures_clear(&keys);
    br_captures_clear(&urls);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static metabase_patterns metabase_compiled;
static const char *const metabase_keywords[] = {"metabase"};
static const br_detector metabase_detector = {
    .type = 950, .version = 0, .name = "Metabase", .custom_name = "",
    .description = "Metabase is an open-source business intelligence tool. Metabase session tokens can be used to access and interact with the Metabase API.",
    .keywords = metabase_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &metabase_compiled, .scan = metabase_scan,
};

int br_metabase_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return metabase_fail(error, "invalid Metabase detector output");
    *out = NULL;
    if (!metabase_compiled.key || !metabase_compiled.url) {
        br_regex *key = NULL, *url = NULL;
        int rc = br_regex_compile_prefixed(metabase_keywords, 1, "\\b([a-zA-Z0-9-]{36})\\b", &key, error);
        if (rc == 0) rc = br_regex_compile_prefixed(metabase_keywords, 1,
            "\\b(https?:\\/\\/[-a-zA-Z0-9@:%._\\+~#=]{7,256})\\b", &url, error);
        if (rc != 0) { br_regex_free(key); br_regex_free(url); return -1; }
        metabase_compiled = (metabase_patterns){key, url};
    }
    *out = &metabase_detector;
    return 0;
}
