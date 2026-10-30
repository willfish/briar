/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/mockaroo/mockaroo.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"
#include "key_scan.h"

#include <json-c/json.h>
#include <stdlib.h>
#include <string.h>

/* Fields are never inspected or published by source. Only final Types length
 * and sticky validity are observable; no borrowed field values need retaining. */
typedef struct { size_t count; bool bad_type; } mockaroo_projection;

static int mockaroo_any(mockaroo_projection *, br_json *, br_slice);

static int mockaroo_any_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)name;
    return mockaroo_any(user, value, encoded);
}

static int mockaroo_any_element(void *user, size_t index, br_json *value, br_slice encoded)
{
    (void)index;
    return mockaroo_any(user, value, encoded);
}

static int mockaroo_any(mockaroo_projection *projected, br_json *value, br_slice encoded)
{
    switch (json_object_get_type(value)) {
    case json_type_object:
        return br_json_each_member(encoded, mockaroo_any_member, projected) == 0 ? 0 : -1;
    case json_type_array:
        return br_json_each_element(encoded, mockaroo_any_element, projected) == 0 ? 0 : -1;
    case json_type_int:
    case json_type_double: {
        /* Check EACH original numeric scalar, including overwritten members.
         * Ordinary overflow is sticky, but later owned failures must be reached. */
        char *cause = NULL;
        int rc = br_json_check_float64_numbers(encoded, &cause);
        free(cause);
        if (rc == 1) { projected->bad_type = true; return 0; }
        return rc == 0 ? 0 : -1;
    }
    default: return 0;
    }
}

static int mockaroo_row_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    mockaroo_projection *projected = user;
    enum json_type kind = json_object_get_type(value);
    if (br_json_field_name(name, "name")) {
        if (kind != json_type_null && kind != json_type_string) projected->bad_type = true;
    } else if (br_json_field_name(name, "type")) {
        return mockaroo_any(projected, value, encoded);
    } else if (br_json_field_name(name, "parameters")) {
        if (kind == json_type_array)
            return br_json_each_element(encoded, mockaroo_any_element, projected) == 0 ? 0 : -1;
        if (kind != json_type_null) projected->bad_type = true;
    }
    /* Unknown fields and wrong-kind typed values skip their children. */
    return 0;
}

static int mockaroo_row(void *user, size_t index, br_json *value, br_slice encoded)
{
    (void)index;
    mockaroo_projection *projected = user;
    if (projected->count == SIZE_MAX) return -1;
    ++projected->count;
    enum json_type kind = json_object_get_type(value);
    if (kind == json_type_object)
        return br_json_each_member(encoded, mockaroo_row_member, projected) == 0 ? 0 : -1;
    if (kind != json_type_null) projected->bad_type = true;
    return 0;
}

static int mockaroo_root_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    mockaroo_projection *projected = user;
    if (!br_json_field_name(name, "types")) return 0;
    switch (json_object_get_type(value)) {
    case json_type_null: projected->count = 0; return 0;
    case json_type_array:
        projected->count = 0;
        return br_json_each_element(encoded, mockaroo_row, projected) == 0 ? 0 : -1;
    default: projected->bad_type = true; return 0;
    }
}

static int mockaroo_decode(const br_http_response *response, bool *verified)
{
    if (!response->body.data && response->body.len) return -1;
    br_json *document = NULL;
    char *cause = NULL;
    size_t end = 0;
    int rc = br_json_first_document(response->body, response->body_error, &document, &end, &cause);
    free(cause);
    if (rc != 0) {
        json_object_put(document);
        return rc == 1 ? 0 : -1; /* Only the decoder's documented +1 is ordinary. */
    }
    mockaroo_projection projected = {0};
    enum json_type kind = json_object_get_type(document);
    if (kind == json_type_object)
        rc = br_json_each_member((br_slice){response->body.data, end}, mockaroo_root_member, &projected);
    else if (kind != json_type_null) projected.bad_type = true;
    if (rc == 0) *verified = !projected.bad_type && projected.count > 0;
    json_object_put(document);
    return rc == 0 ? 0 : -1; /* Projection/callback +1 is fatal, not a decode cause. */
}

typedef struct mockaroo_attempt {
    br_http_request request;
    br_http_response response;
    struct mockaroo_attempt *previous;
    char url[sizeof("https://api.mockaroo.com/api/types?key=") + 8];
} mockaroo_attempt;

static int mockaroo_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static mockaroo_attempt *mockaroo_request(const char *key)
{
    static const char prefix[] = "https://api.mockaroo.com/api/types?key=";
    mockaroo_attempt *attempt = malloc(sizeof(*attempt));
    if (!attempt) return NULL;
    *attempt = (mockaroo_attempt){0};
    memcpy(attempt->url, prefix, sizeof(prefix) - 1);
    memcpy(attempt->url + sizeof(prefix) - 1, key, 8);
    attempt->request = (br_http_request){
        .method = "GET", .url = attempt->url, .profile = BR_HTTP_SANE, .detector_type = 753,
    };
    return attempt;
}

static void mockaroo_release(const br_scan_ctx *ctx, mockaroo_attempt *attempt)
{
    br_http_release(ctx, &attempt->response);
    free(attempt);
}

static int mockaroo_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return mockaroo_fail(error, "invalid or uninitialized Mockaroo scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    mockaroo_attempt *deferred = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = mockaroo_fail(error, "out of memory creating Mockaroo result");
        if (rc == 0 && verify) {
            /* Source evaluates its formatted URL before the nil constructor
             * guard; this reached module allocation cannot become a skip. */
            mockaroo_attempt *attempt = mockaroo_request(keys.items[i]);
            if (!attempt) rc = mockaroo_fail(error, "out of memory creating Mockaroo URL");
            else if (!ctx) { free(attempt); br_result_clear(&result); continue; }
            else {
                char *transport_error = NULL;
                /* The whole mixed shared preparation/Do domain is suppressed. */
                if (br_http_send(ctx, &attempt->request, &attempt->response, &transport_error) == 0) {
                    attempt->previous = deferred;
                    deferred = attempt;
                    if (attempt->response.status >= 200 && attempt->response.status < 300 &&
                        mockaroo_decode(&attempt->response, &result.verified) != 0)
                        rc = mockaroo_fail(error, "cannot decode Mockaroo response");
                } else mockaroo_release(ctx, attempt);
                free(transport_error);
            }
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = mockaroo_fail(error, "out of memory appending Mockaroo result");
        br_result_clear(&result);
    }
    /* Successful Do closes are LIFO after publication, regardless of status
     * or ordinary decode errors. Retain provider originals, not synthesized
     * ordinary HTTP request/header-array/User-Agent preparation storage. */
    while (deferred) {
        mockaroo_attempt *previous = deferred->previous;
        mockaroo_release(ctx, deferred);
        deferred = previous;
    }
    br_captures_clear(&keys);
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    return rc == 0 ? 0 : -1;
}

static const char *const mockaroo_keywords[] = {"mockaroo"};
static br_detector mockaroo_detector = {
    .type = 753, .version = 0, .name = "Mockaroo", .custom_name = "",
    .description = "Mockaroo is a tool for generating realistic data for testing and development. "
                   "Mockaroo API keys can be used to access and generate this data.",
    .keywords = mockaroo_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = mockaroo_scan,
};

int br_mockaroo_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return mockaroo_fail(error, "invalid Mockaroo detector output");
    *out = NULL;
    if (br_key_pattern_init(&mockaroo_detector, "\\b([0-9a-z]{8})\\b", error) != 0) return -1;
    *out = &mockaroo_detector;
    return 0;
}
