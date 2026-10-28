/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/graphcms/graphcms.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *keys, *ids; } graphcms_state;

static int graphcms_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void graphcms_verify(const br_scan_ctx *ctx, const char *url, br_slice body,
                            br_slice key, br_result *result)
{
    /* Header.Add follows successful construction. Two wildcard runes bound
     * KEY to 1133 bytes: prefix7 + KEY1133 + NUL, without JWT interpretation. */
    br_header headers[2] = {{"Content-Type", "application/graphql"}};
    char authorization[1141];
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, key.len);
    authorization[7 + key.len] = '\0';
    /* ABI1 cannot represent NUL headers. AFTER full assembly and constructor,
     * reproduce the source Do invalid-header outcome in its suppressed domain:
     * false/no setter/zero I/O, never truncated authorization mock success. */
    if (memchr(key.data, '\0', key.len)) return;
    headers[1] = (br_header){"Authorization", authorization};
    const br_http_request request = {
        .method = "POST", .url = url, .headers = headers, .nheaders = 2,
        .body = body, .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Suppress the WHOLE mixed shared setup/allocation/Do error domain. Body
     * bytes and read errors are ignored at every status; no text classifier. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Only original provider values survive through ordinary release, not
     * the adapter's temporary effective request, header array or common UA. */
    br_http_release(ctx, &response);
    free(send_error);
}

static int graphcms_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return graphcms_fail(error, "invalid or uninitialized GraphCMS scan");
    const graphcms_state *state = detector->state;
    br_captures keys = {0}, ids = {0};
    size_t original_len = out->len;
    char *owned_error = NULL;
    int rc = br_captures_find(state->keys, input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(state->ids, input, &ids, false, &owned_error);
    /* TrimSpace cannot change either capture's outer alphabets. Keep original
     * occurrences and duplicates, key-major products, with a required hidden ID.
     * The inherited 1024 span is an engine hint, not a direct key/product cap. */
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        for (size_t j = 0; rc == 0 && j < ids.len; ++j) {
            br_result result = {0};
            if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
                rc = graphcms_fail(&owned_error, "cannot create GraphCMS result");
            if (rc == 0 && verify) {
                static const char prefix[] = "https://api-ap-northeast-1.graphcms.com/v2/";
                static const char suffix[] = "/master";
                static const unsigned char payload[] = "{users {id name}}";
                char url[sizeof(prefix) - 1 + 25 + sizeof(suffix)];
                br_slice id = br_captures_at(&ids, j);
                memcpy(url, prefix, sizeof(prefix) - 1);
                memcpy(url + sizeof(prefix) - 1, id.data, id.len);
                memcpy(url + sizeof(prefix) - 1 + id.len, suffix, sizeof(suffix));
                br_slice body = {payload, sizeof(payload) - 1};
                /* Finding, complete literal URL and body precede the known
                 * nil-context constructor skip; headers follow it. */
                if (!ctx) { br_result_clear(&result); continue; }
                graphcms_verify(ctx, url, body, key, &result);
            }
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = graphcms_fail(&owned_error, "cannot append GraphCMS result");
            br_result_clear(&result);
        }
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&ids);
    if (error) *error = owned_error; else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const graphcms_keywords[] = {"graphcms"};
static graphcms_state graphcms_patterns;
static br_detector graphcms_detector = {
    .type = 223, .version = 0, .name = "GraphCMS", .custom_name = "",
    .description = "GraphCMS, now known as Hygraph, is a CSM software. The GraphCSM API token can enable someone to interact with CMS content.",
    .keywords = graphcms_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = graphcms_scan,
};

int br_graphcms_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return graphcms_fail(error, "invalid GraphCMS detector output");
    *out = NULL;
    if (!graphcms_detector.state) {
        br_regex *keys = NULL, *ids = NULL;
        static const char *const id_keywords[] = {"graph"};
        if (br_regex_compile("\\b(ey[a-zA-Z0-9]{73}.ey[a-zA-Z0-9]{365}.[a-zA-Z0-9_-]{683})\\b", &keys, error) != 0)
            return -1;
        if (br_regex_compile_prefixed(id_keywords, 1, "\\b([a-z0-9]{25})\\b", &ids, error) != 0) {
            br_regex_free(keys);
            return -1;
        }
        graphcms_patterns = (graphcms_state){keys, ids};
        graphcms_detector.state = &graphcms_patterns;
    }
    *out = &graphcms_detector;
    return 0;
}
