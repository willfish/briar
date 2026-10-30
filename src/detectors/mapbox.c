/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/mapbox/mapbox.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } mapbox_patterns;

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static const char url_prefix[] = "https://api.mapbox.com/tokens/v2/";
static const char url_query[] = "?access_token=";

static int scan_mapbox(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized MapBox scan");
    const mapbox_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->id) return fail(error, "uninitialized MapBox detector");

    size_t original_len = out->len;
    br_captures keys = {0}, ids = {0};
    char *owned_error = NULL;
    /* Both FindAll calls run even when verify is set, ctx is NULL, and there
     * are no keys. Any nonzero, including +1, is fatal before a drop. */
    char *key_error = NULL, *id_error = NULL;
    int key_rc = br_captures_find(patterns->key, input, &keys, false, &key_error);
    int id_rc = br_captures_find(patterns->id, input, &ids, false, &id_error);
    int rc = 0;
    if (key_rc != 0) {
        owned_error = key_error;
        free(id_error);
        rc = -1;
    } else if (id_rc != 0) {
        owned_error = id_error;
        free(key_error);
        rc = -1;
    } else {
        free(key_error);
        free(id_error);
    }
    /* Index 11 is the twelfth non-overlapping id, including text inside a key.
     * Fewer than twelve publishes nothing and does not call the constructor.
     * Span 1024 is not applied here. */
    for (size_t k = 0; rc == 0 && ids.len >= 12 && k < keys.len; ++k) {
        br_result result = {0};
        if (br_finding_key(&result, detector->type, keys.items[k], "key") != 0)
            rc = fail(&owned_error, "out of memory creating MapBox result");
        if (rc == 0 && verify) {
            size_t id_len = ids.lengths[11];
            size_t key_len = keys.lengths[k];
            /* Lengths are bounded by the source classes. Assemble on the stack.
             * Do not percent-encode and do not allocate the URL. */
            if (id_len < 4 || id_len > 32 || key_len < 83 || key_len > 243)
                rc = fail(&owned_error, "invalid MapBox capture");
            else {
                char url[sizeof(url_prefix) + 32 + sizeof(url_query) + 243];
                char *cursor = url;
                memcpy(cursor, url_prefix, sizeof(url_prefix) - 1);
                cursor += sizeof(url_prefix) - 1;
                memcpy(cursor, ids.items[11], id_len);
                cursor += id_len;
                memcpy(cursor, url_query, sizeof(url_query) - 1);
                cursor += sizeof(url_query) - 1;
                memcpy(cursor, keys.items[k], key_len);
                cursor[key_len] = '\0';
                if (!ctx) {
                    /* "net/http: nil Context" drops only this candidate. */
                    br_result_clear(&result);
                    continue;
                }
                const br_http_request request = {
                    .method = "GET", .url = url,
                    .profile = BR_HTTP_SANE, .detector_type = 104,
                };
                br_http_response response = {0};
                char *transport_error = NULL;
                /* Any 2xx verifies. The body and its read error are not inspected.
                 * Other statuses and send failures stay unverified with no setter. */
                if (br_http_send(ctx, &request, &response, &transport_error) == 0)
                    result.verified = response.status >= 200 && response.status < 300;
                br_http_release(ctx, &response);
                free(transport_error);
            }
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = fail(&owned_error, "out of memory appending MapBox result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&ids);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static mapbox_patterns patterns;
static const char *const keywords[] = {"mapbox"};
static const br_detector mapbox = {
    .type = 104, .version = 0, .name = "MapBox", .custom_name = "",
    .description = "Mapbox provides location-based services and APIs. "
                   "Mapbox access tokens can be used to interact with these services and modify data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_mapbox,
};

int br_mapbox_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid MapBox detector output");
    *out = NULL;
    if (!patterns.key &&
        br_regex_compile("\\b(sk\\.[a-zA-Z-0-9\\.]{80,240})\\b", &patterns.key, error) != 0)
        return -1;
    if (!patterns.id &&
        br_regex_compile("([a-zA-Z-0-9]{4,32})", &patterns.id, error) != 0)
        return -1;
    *out = &mapbox;
    return 0;
}
