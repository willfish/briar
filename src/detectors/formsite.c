/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/formsite/formsite.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *server, *user; } formsite_patterns;

static int formsite_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

/* False denotes constructor skip. All mixed shared setup/allocation/Do
 * failures instead retain the original false finding, without setter/classifier. */
static bool formsite_verify(const br_scan_ctx *ctx, br_slice key, br_slice server,
                             br_slice user, br_result *result)
{
    static const char prefix[] = "https://", middle[] = ".formsite.com/api/v2/", suffix[] = "/forms";
    /* Complete ORIGINAL-case URL BEFORE construction. Source server is 3..6
     * ASCII bytes, user exactly 6: no DNS lowercasing/encoder/formatter/heap copy
     * or arbitrary cap/failure seam. The bound includes the longest server. */
    char url[sizeof(prefix) - 1 + 6 + sizeof(middle) - 1 + 6 + sizeof(suffix)];
    _Static_assert(sizeof(url) == 48, "Formsite max URL is 47 bytes plus NUL");
    size_t at = sizeof(prefix) - 1; memcpy(url, prefix, at);
    memcpy(url + at, server.data, server.len); at += server.len;
    memcpy(url + at, middle, sizeof(middle) - 1); at += sizeof(middle) - 1;
    memcpy(url + at, user.data, 6); at += 6; memcpy(url + at, suffix, sizeof(suffix));
    if (!ctx) return false;
    char authorization[40];
    memcpy(authorization, "Bearer ", 7); memcpy(authorization + 7, key.data, 32); authorization[39] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *send_error = NULL;
    /* Whole mixed shared send domain suppresses false/KEPT, never text-classifies
     * as constructor skip. Every 2xx verifies; body/read errors are ignored. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Full URL/auth stay live through synchronous send AND release. Source
     * scan-defers Close; eager buffering/release, full Reader/deferred-close,
     * native URL/client/regexp and global source/engine/output parity remain
     * partial. Keep native/PUBLIC/other guards intact; never live forms checks. */
    br_http_release(ctx, &response);
    free(send_error);
    return true;
}

static int formsite_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return formsite_fail(error, "invalid or uninitialized Formsite scan");
    const formsite_patterns *patterns = detector->state;
    size_t original_len = out->len; br_captures keys = {0}, servers = {0}, users = {0}; char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->server, input, &servers, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->user, input, &users, false, &owned_error);
    /* INDEPENDENT original occurrence collections: fs1234 also matches USER6.
     * Never remove overlapping roles, make sets or impose engine span locally. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        br_slice key = br_captures_at(&keys, k);
        for (size_t s = 0; rc == 0 && s < servers.len; ++s) {
            br_slice server = br_captures_at(&servers, s);
            for (size_t u = 0; rc == 0 && u < users.len; ++u) {
                br_slice user = br_captures_at(&users, u); br_result result = {0}; bool keep = true;
                /* Key-major/server-middle/user-inner, duplicates included. Both
                 * required secondary values stay HIDDEN even when verified.
                 * Finding resources precede complete URL preparation and skip. */
                if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
                    rc = formsite_fail(&owned_error, "cannot create Formsite result");
                if (rc == 0 && verify) keep = formsite_verify(ctx, key, server, user, &result);
                if (rc == 0 && keep && br_results_push(out, &result) != 0)
                    rc = formsite_fail(&owned_error, "cannot append Formsite result");
                br_result_clear(&result); /* No verified break/equality skip/filter/cache. */
            }
        }
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys); br_captures_clear(&servers); br_captures_clear(&users);
    if (error) *error = owned_error; else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const formsite_keywords[] = {"formsite"};
static formsite_patterns formsite_state;
static br_detector formsite_detector = {
    .type = 839, .version = 0, .name = "Formsite", .custom_name = "",
    .description = "Formsite is an online form builder service. Formsite API keys can be used to access and manage forms and data submissions.",
    .keywords = formsite_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024, .scan = formsite_scan,
};

int br_formsite_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return formsite_fail(error, "invalid Formsite detector output");
    *out = NULL;
    if (!formsite_detector.state) {
        br_regex *key = NULL, *server = NULL, *user = NULL;
        if (br_regex_compile_prefixed(formsite_keywords, 1, "\\b([a-zA-Z0-9]{32})\\b", &key, error) != 0) return -1;
        if (br_regex_compile_prefixed(formsite_keywords, 1, "\\b(fs[0-9]{1,4})\\b", &server, error) != 0) { br_regex_free(key); return -1; }
        if (br_regex_compile_prefixed(formsite_keywords, 1, "\\b([a-zA-Z0-9]{6})\\b", &user, error) != 0) { br_regex_free(key); br_regex_free(server); return -1; }
        formsite_state = (formsite_patterns){key, server, user}; formsite_detector.state = &formsite_state;
    }
    *out = &formsite_detector;
    return 0;
}
