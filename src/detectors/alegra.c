/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/alegra/alegra.go and
 * pkg/common/patterns.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "email_pattern.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } alegra_patterns;
static alegra_patterns patterns;

typedef struct {
    br_slice input;
    br_captures *ids;
    char *error;
} id_matches;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int collect_id(void *user, const br_span *groups, size_t ngroups)
{
    id_matches *matches = user;
    if (!ngroups || groups[0].begin == SIZE_MAX || groups[0].end <= groups[0].begin ||
        groups[0].end > matches->input.len)
        return fail(&matches->error, "invalid Alegra ID match");
    size_t begin = groups[0].begin, end = groups[0].end;
    /* Upstream takes match[0], then the tail after its LAST literal ASCII space.
     * With no space, the prefix and gap (including NUL) remain part of the ID. */
    for (size_t i = end; i > begin; --i) {
        if (matches->input.data[i - 1] == ' ') {
            begin = i;
            break;
        }
    }
    return br_captures_push(matches->ids,
                            (br_slice){matches->input.data + begin, end - begin},
                            true, &matches->error);
}

static int verify_alegra(const br_scan_ctx *ctx, br_slice token, br_slice id, br_result *result)
{
    /* Upstream suppresses request-creation errors. For this fixed GET URL, the
     * reachable case is NewRequestWithContext rejecting a nil context. */
    if (!ctx) return 0;
    char *auth = NULL;
    if (br_http_basic_auth(id, token, &auth, NULL) != 0) return -1;
    const br_header headers[] = {{"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.alegra.com/api/v1/users/self",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = 375,
    };
    br_http_response response = {0};
    char *error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        cause = error ? error : "HTTP transport failed";
    } else {
        /* The deferred drain/close ignores body errors; only status matters. */
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401: break;
        default:
            snprintf(status_error, sizeof(status_error),
                     "unexpected HTTP response status %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* The ID is not supplied for redaction upstream. */
    int rc = br_result_set_verification_error(result, cause, &token, 1);
    br_http_release(ctx, &response);
    free(error);
    free(auth);
    return rc;
}

static int scan_alegra(const br_detector *detector, const br_scan_ctx *ctx,
                       bool verify, br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid Alegra scan arguments");
    const alegra_patterns *compiled = detector->state;
    if (!compiled->key || !compiled->id)
        return fail(error, "uninitialized Alegra patterns");

    br_captures keys = {0}, ids = {0};
    int rc = br_captures_find(compiled->key, input, &keys, true, error);
    if (!rc) {
        id_matches matches = {input, &ids, NULL};
        char *id_error = NULL;
        rc = br_regex_each(compiled->id, input, collect_id, &matches, &id_error);
        if (matches.error) {
            free(id_error);
            id_error = matches.error;
        }
        if (error) *error = id_error;
        else free(id_error);
    }
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        br_slice token = br_captures_at(&keys, k);
        for (size_t i = 0; !rc && i < ids.len; ++i) {
            br_slice id = br_captures_at(&ids, i);
            br_result result = {0};
            if (br_finding_pair_bytes(&result, detector->type, token, "token", id, "id",
                                      (br_slice){(const unsigned char *)":", 1}) != 0 ||
                (verify && verify_alegra(ctx, token, id, &result) != 0) ||
                br_results_push(out, &result) != 0)
                rc = fail(error, "out of memory creating Alegra result");
            br_result_clear(&result);
        }
    }
    br_captures_clear(&keys);
    br_captures_clear(&ids);
    return rc;
}

static const char *const keywords[] = {"alegra"};
static const br_detector alegra = {
    .type = 375, .version = 0, .name = "Alegra", .custom_name = "",
    .description = "Alegra is a cloud-based accounting software. Alegra API keys can be used to access and modify accounting data and user information.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .state = &patterns, .scan = scan_alegra,
};

int br_alegra_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Alegra detector output");
    *out = NULL;
    if (!patterns.key &&
        br_regex_compile_prefixed(keywords, 1, "\\b([a-z0-9-]{20})\\b", &patterns.key, error) != 0)
        return -1;
    if (!patterns.id &&
        br_regex_compile_prefixed(keywords, 1, br_email_pattern, &patterns.id, error) != 0)
        return -1;
    *out = &alegra;
    return 0;
}
