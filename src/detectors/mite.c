/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/mite/mite.go.
 * Selected Go URL.String behavior: LICENSES/BSD-3-Clause-Go.txt. */
#include "captures.h"
#include "findings.h"
#include "../go_url.h"

#include <stdlib.h>
#include <string.h>

static int mite_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

typedef struct { br_regex *key, *url; } mite_patterns;
typedef struct {
    br_bytes original, rendered, user, password, path, fragment;
    br_go_url_parts parts;
} mite_target;
typedef struct mite_pending mite_pending;
struct mite_pending {
    mite_pending *next;
    mite_target target;
    br_http_request request;
    br_http_response response;
    br_header headers[3];
    char *authorization;
};

static void mite_target_clear(mite_target *target)
{
    br_go_url_clear(&target->parts);
    free(target->original.data); free(target->rendered.data);
    free(target->user.data); free(target->password.data);
    free(target->path.data); free(target->fragment.data);
    *target = (mite_target){0};
}

static void mite_release(const br_scan_ctx *ctx, mite_pending *pending)
{
    while (pending) {
        mite_pending *next = pending->next;
        br_http_release(ctx, &pending->response);
        mite_target_clear(&pending->target);
        free(pending->authorization);
        free(pending);
        pending = next;
    }
}

/* Only the fixed-https provider target is rendered, not a general URL engine.
 * Go's raw encoded path/fragment exceptions differ from default escaping. */
static bool mite_valid_encoded(br_slice raw, br_go_url_encoding mode)
{
    for (size_t i = 0; i < raw.len; ++i) {
        unsigned char c = raw.data[i];
        if (c && strchr("!$&'()*+,;=:@[]%", c)) continue;
        if (!br_go_url_byte_allowed(c, mode)) return false;
    }
    return true;
}

typedef struct { unsigned char *data; size_t len, capacity; bool overflow; } mite_writer;

static void mite_put(mite_writer *writer, unsigned char c)
{
    if (writer->len == SIZE_MAX || (writer->data && writer->len >= writer->capacity)) {
        writer->overflow = true;
        return;
    }
    if (writer->data) writer->data[writer->len] = c;
    ++writer->len;
}

static void mite_write(mite_writer *writer, br_slice value, bool escape, br_go_url_encoding mode)
{
    static const unsigned char hex[] = "0123456789ABCDEF";
    for (size_t i = 0; i < value.len; ++i) {
        unsigned char c = value.data[i];
        if (!escape || br_go_url_byte_allowed(c, mode)) mite_put(writer, c);
        else { mite_put(writer, '%'); mite_put(writer, hex[c >> 4]); mite_put(writer, hex[c & 15]); }
    }
}

static br_slice mite_bytes(br_bytes value) { return (br_slice){value.data, value.len}; }

static void mite_render(mite_writer *writer, const mite_target *target)
{
    const br_go_url_parts *parts = &target->parts;
    mite_write(writer, (br_slice){(const unsigned char *)"https:", 6}, false, BR_GO_URL_PATH);
    br_slice host = parts->host;
    if (host.len && host.data[host.len - 1] == ':') --host.len; /* NewRequest removeEmptyPort. */
    if (host.len || parts->raw_path.len || parts->has_user) {
        mite_put(writer, '/'); mite_put(writer, '/');
        if (parts->has_user) {
            mite_write(writer, mite_bytes(target->user), true, BR_GO_URL_USER);
            if (parts->has_password) { mite_put(writer, ':'); mite_write(writer, mite_bytes(target->password), true, BR_GO_URL_USER); }
            mite_put(writer, '@');
        }
        mite_write(writer, host, true, BR_GO_URL_HOST);
    }
    if (parts->raw_path.len && parts->raw_path.data[0] != '/' && host.len) mite_put(writer, '/');
    bool raw_path = mite_valid_encoded(parts->raw_path, BR_GO_URL_PATH);
    mite_write(writer, raw_path ? parts->raw_path : mite_bytes(target->path), !raw_path, BR_GO_URL_PATH);
    if (parts->force_query || parts->raw_query.len) {
        mite_put(writer, '?'); mite_write(writer, parts->raw_query, false, BR_GO_URL_PATH);
    }
    if (parts->raw_fragment.len) {
        mite_put(writer, '#');
        bool raw_fragment = mite_valid_encoded(parts->raw_fragment, BR_GO_URL_FRAGMENT);
        mite_write(writer, raw_fragment ? parts->raw_fragment : mite_bytes(target->fragment), !raw_fragment, BR_GO_URL_FRAGMENT);
    }
}

static int mite_decode(br_slice raw, br_bytes *decoded, char **error)
{
    bool valid = false;
    if (br_go_url_decode(raw, false, decoded, &valid, error) != 0) return -1;
    return valid ? 0 : mite_fail(error, "inconsistent parsed Mite URL component");
}

static int mite_target_init(br_slice capture, bool context_present, mite_target *target,
                             bool *keep, char **error)
{
    static const char prefix[] = "https://", suffix[] = "/account.json";
    size_t overhead = sizeof(prefix) - 1 + sizeof(suffix);
    if (capture.len > SIZE_MAX - overhead) return mite_fail(error, "Mite URL too large");
    target->original.data = malloc(overhead + capture.len);
    if (!target->original.data) return mite_fail(error, "cannot construct Mite original URL");
    target->original.len = overhead + capture.len - 1;
    memcpy(target->original.data, prefix, sizeof(prefix) - 1);
    memcpy(target->original.data + sizeof(prefix) - 1, capture.data, capture.len);
    memcpy(target->original.data + sizeof(prefix) - 1 + capture.len, suffix, sizeof(suffix));
    /* Preserve full source bytes, including NUL, before nil constructor handling.
     * The selected NewRequest checks nil context BEFORE url.Parse. */
    if (!context_present) { *keep = false; return 0; }
    br_go_url_error ordinary = {0};
    if (br_go_url_parse(mite_bytes(target->original), &target->parts, &ordinary, error) != 0) return -1;
    if (ordinary.kind != BR_GO_URL_OK) { *keep = false; return 0; }
    if (target->parts.has_user &&
        (mite_decode(target->parts.raw_user, &target->user, error) != 0 ||
         mite_decode(target->parts.raw_password, &target->password, error) != 0)) return -1;
    if (!mite_valid_encoded(target->parts.raw_path, BR_GO_URL_PATH) &&
        mite_decode(target->parts.raw_path, &target->path, error) != 0) return -1;
    if (!mite_valid_encoded(target->parts.raw_fragment, BR_GO_URL_FRAGMENT) &&
        mite_decode(target->parts.raw_fragment, &target->fragment, error) != 0) return -1;
    mite_writer measure = {0}; mite_render(&measure, target);
    if (measure.overflow || measure.len == SIZE_MAX) return mite_fail(error, "Mite rendered URL too large");
    target->rendered.data = malloc(measure.len + 1);
    if (!target->rendered.data) return mite_fail(error, "cannot render Mite URL");
    mite_writer output = {.data = target->rendered.data, .capacity = measure.len};
    mite_render(&output, target);
    if (output.overflow || output.len != measure.len) return mite_fail(error, "inconsistent Mite URL rendering");
    target->rendered.len = output.len; target->rendered.data[output.len] = 0;
    return 0;
}

static int mite_verify(const br_scan_ctx *ctx, br_slice key, br_slice capture, br_result *result,
                        mite_pending **pending, bool *keep, char **error)
{
    mite_target target = {0};
    int rc = mite_target_init(capture, ctx != NULL, &target, keep, error);
    if (rc != 0 || !*keep) { mite_target_clear(&target); return rc; }
    mite_pending *attempt = malloc(sizeof(*attempt));
    if (!attempt) { mite_target_clear(&target); return mite_fail(error, "cannot construct Mite request"); }
    *attempt = (mite_pending){0}; attempt->target = target;
    attempt->headers[0] = (br_header){"Content-Type", "application/json"};
    attempt->headers[1] = (br_header){"X-Miteapikey", (const char *)key.data};
    size_t nheaders = 2;
    if (target.parts.has_user) {
        /* net/http client.send adds implicit Basic auth after provider headers. */
        if (br_http_basic_auth(mite_bytes(target.user), mite_bytes(target.password), &attempt->authorization, error) != 0) {
            mite_target_clear(&attempt->target); free(attempt->authorization); free(attempt); return -1;
        }
        attempt->headers[nheaders++] = (br_header){"Authorization", attempt->authorization};
    }
    attempt->request = (br_http_request){
        .method = "GET", .url = (const char *)target.rendered.data,
        .headers = attempt->headers, .nheaders = nheaders,
        .profile = BR_HTTP_DETECTOR_PUBLIC, .detector_type = result->detector_type,
    };
    char *send_error = NULL;
    if (br_http_send(ctx, &attempt->request, &attempt->response, &send_error) == 0) {
        result->verified = attempt->response.status >= 200 && attempt->response.status < 300;
        attempt->next = *pending; *pending = attempt;
    } else {
        /* Whole mixed shared preparation/Do errors are suppressed, never text
         * classified. Source never calls a verification-error setter. */
        mite_release(ctx, attempt);
    }
    free(send_error);
    return 0;
}

static int mite_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return mite_fail(error, "invalid or uninitialized Mite scan");
    const mite_patterns *patterns = detector->state;
    size_t original_len = out->len;
    br_captures keys = {0}, urls = {0}; mite_pending *pending = NULL;
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->url, input, &urls, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        for (size_t j = 0; rc == 0 && j < urls.len; ++j) {
            br_result result = {0}; bool keep = true;
            if (key.len != 16 || br_finding_key_bytes(&result, detector->type, key, "key") != 0)
                rc = mite_fail(&owned_error, "cannot create Mite result");
            if (rc == 0 && verify) rc = mite_verify(ctx, key, br_captures_at(&urls, j), &result, &pending, &keep, &owned_error);
            if (rc == 0 && keep && br_results_push(out, &result) != 0) rc = mite_fail(&owned_error, "cannot append Mite result");
            br_result_clear(&result);
        }
    }
    /* Successful closes are scan-wide LIFO after publication. All original,
     * parsed/decoded/rendered request values survive release, not ordinary
     * synthesized preparation. Body/read errors do not affect status policy. */
    mite_release(ctx, pending);
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&urls); br_captures_clear(&keys);
    if (error) *error = owned_error; else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const mite_keywords[] = {"mite"};
static mite_patterns mite_compiled;
static br_detector mite_detector = {
    .type = 682, .version = 0, .name = "Mite", .custom_name = "",
    .description = "Mite is a time tracking tool. Mite API keys can be used to access and modify time tracking data.",
    .keywords = mite_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = mite_scan,
};

int br_mite_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return mite_fail(error, "invalid Mite detector output");
    *out = NULL;
    if (!mite_detector.state) {
        mite_patterns patterns = {0};
        if (br_regex_compile_prefixed(mite_keywords, 1, "\\b([0-9a-z]{16})\\b", &patterns.key, error) != 0) return -1;
        if (br_regex_compile("\\b([0-9a-z-]{1,}.mite.yo.lk)\\b", &patterns.url, error) != 0) { br_regex_free(patterns.key); return -1; }
        mite_compiled = patterns; mite_detector.state = &mite_compiled;
    }
    *out = &mite_detector;
    return 0;
}
