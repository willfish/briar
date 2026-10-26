/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/captaindata/v1 and v2. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *project; } captaindata_patterns;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int finding(br_result *result, int32_t type, br_slice project, br_slice key)
{
    /* The helper owns Raw=key, both parts, and a key+project RawV2 buffer.
     * Reorder ONLY that owned buffer, reading the separate capture slices.
     * The total length stays 100 bytes; no aliasing or extra allocation. */
    if (br_finding_pair_bytes(result, type, key, "key", project, "project_id", (br_slice){0})) return -1;
    memcpy(result->raw_v2.data, project.data, project.len);
    memcpy(result->raw_v2.data + project.len, key.data, key.len);
    return 0;
}

static void verify_v1(const br_scan_ctx *ctx, const char *project, const char *key, br_result *result)
{
    /* Both source captures are fixed: project 36 bytes, key 64 bytes. */
    char url[sizeof("https://api.captaindata.co/v2/") + 36];
    snprintf(url, sizeof(url), "https://api.captaindata.co/v2/%s", project);
    const br_header headers[] = {{"x-api-key", key}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL;
    /* Source suppresses ALL Client.Do errors. ABI1 also mixes adapter setup
     * and allocation failures into this domain; do not classify error text. */
    if (!br_http_send(ctx, &request, &response, &transport_error))
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers Close ONLY, without reading/draining. ABI1 may buffer
     * eagerly and releases per request, so native lifecycle parity is partial. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int set_cause(br_result *result, const char *cause)
{
    const br_slice key = {result->raw.data, result->raw.len};
    /* V2 redacts key ONLY, not the project ID or a combined credential. The
     * core setter's positive 1 is a resource failure, never an outcome. */
    return br_result_set_verification_error(result, cause, &key, 1) ? -1 : 0;
}

static int verify_v2(const br_scan_ctx *ctx, const char *project, const char *key, br_result *result)
{
    if (!ctx) return set_cause(result, "net/http: nil Context");
    char auth[sizeof("x-api-key ") + 64];
    snprintf(auth, sizeof(auth), "x-api-key %s", key);
    const br_header headers[] = {{"Authorization", auth}, {"x-project-id", project}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.captaindata.co/v3/workspace",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL;
    char status_error[80]; const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error))
        cause = transport_error ? transport_error : "HTTP transport failed";
    else {
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401: break;
        default:
            snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
            cause = status_error;
            break;
        }
    }
    int rc = set_cause(result, cause);
    /* Source verifier-defers drain/close, ignoring their errors. ABI1 releases
     * eagerly; body/read errors never override the status/Do outcome. */
    br_http_release(ctx, &response);
    free(transport_error);
    return rc ? -1 : 0;
}

static int scan_captaindata(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len) ||
        (detector->version != 1 && detector->version != 2))
        return fail(error, "invalid or uninitialized CaptainData scan");
    const captaindata_patterns *compiled = detector->state;
    if (!compiled->key || !compiled->project) return fail(error, "uninitialized CaptainData patterns");
    br_captures keys = {0}, projects = {0}; char *owned_error = NULL;
    size_t original_len = out->len;
    /* V1 occurrences, V2 independent unique sets. First-seen order in V2 is
     * deterministic and legal: upstream Go map iteration has no fixed order. */
    bool unique = detector->version == 2;
    int rc = br_captures_find(compiled->key, input, &keys, unique, &owned_error);
    if (!rc) rc = br_captures_find(compiled->project, input, &projects, unique, &owned_error);
    for (size_t p = 0; !rc && p < projects.len; ++p) {
        for (size_t k = 0; !rc && k < keys.len; ++k) {
            /* V1's known constructor failure skips this pair. V2 retains it
             * with a key-redacted error. NoV with nil context keeps both. */
            if (verify && detector->version == 1 && !ctx) continue;
            br_result result = {0};
            if (finding(&result, detector->type, br_captures_at(&projects, p), br_captures_at(&keys, k)))
                rc = fail(&owned_error, "cannot create CaptainData result");
            if (!rc && verify) {
                if (detector->version == 1) verify_v1(ctx, projects.items[p], keys.items[k], &result);
                else if (verify_v2(ctx, projects.items[p], keys.items[k], &result))
                    rc = fail(&owned_error, "cannot verify CaptainData candidate");
            }
            if (!rc && br_results_push(out, &result)) rc = fail(&owned_error, "cannot append CaptainData result");
            br_result_clear(&result);
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys); br_captures_clear(&projects);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static captaindata_patterns patterns;
static const char *const keywords[] = {"captaindata"};
static const char description[] = "CaptainData is a service for automating data extraction and processing. The API keys can be used to access and control these automation processes.";
static const br_detector v1 = {
    .type = 708, .version = 1, .name = "CaptainData", .custom_name = "", .description = description,
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_captaindata,
};
static const br_detector v2 = {
    .type = 708, .version = 2, .name = "CaptainData", .custom_name = "", .description = description,
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .state = &patterns, .scan = scan_captaindata,
};

static int init_patterns(char **error)
{
    if (!patterns.key && br_regex_compile_prefixed(keywords, 1, "\\b([0-9a-f]{64})\\b", &patterns.key, error)) return -1;
    if (!patterns.project && br_regex_compile_prefixed(keywords, 1, "\\b([0-9a-f]{8}\\-[0-9a-f]{4}\\-[0-9a-f]{4}\\-[0-9a-f]{4}\\-[0-9a-f]{12})\\b", &patterns.project, error)) return -1;
    return 0;
}

int br_captaindata_v1_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid CaptainData v1 detector output");
    *out = NULL;
    if (init_patterns(error)) return -1;
    *out = &v1;
    return 0;
}

int br_captaindata_v2_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid CaptainData v2 detector output");
    *out = NULL;
    if (init_patterns(error)) return -1;
    *out = &v2;
    return 0;
}
