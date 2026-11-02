/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/ngc/ngc.go. */
#include "detectors.h"
#include "findings.h"
#include "azure_shared_key.h"

#include <stdlib.h>
#include <string.h>

static const char outer_pattern[] = "\\b([A-Za-z0-9]{84})\\b";
static const char inner_pattern[] =
    "\\b([A-Za-z0-9]{26}:[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12})\\b";

typedef struct {
    br_regex *outer;
    br_regex *inner;
} ngc_state;

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static void rollback(br_results *out, size_t before)
{
    if (!out) return;
    while (out->len > before) br_result_clear(&out->items[--out->len]);
}

typedef struct {
    br_http_response response;
    char *authorization;
} ngc_held;

typedef struct {
    const br_regex *inner;
    const br_scan_ctx *ctx;
    br_slice input;
    br_results *out;
    bool verify;
    char **error;
    ngc_held *held;
    size_t held_len, held_cap;
} ngc_scan;

/* Successful Do stays open until scanner return. The prepared header array is
 * not retained, and authorization is not rebuilt after send. */
static int hold_ngc(ngc_scan *scan, br_http_response response, char *authorization)
{
    if (scan->held_len == scan->held_cap) {
        if (scan->held_cap > SIZE_MAX / sizeof(*scan->held) / 2)
            return fail(scan->error, "cannot retain NGC response");
        size_t cap = scan->held_cap ? scan->held_cap * 2 : 4;
        ngc_held *grown = realloc(scan->held, cap * sizeof(*grown));
        if (!grown) return fail(scan->error, "cannot retain NGC response");
        scan->held = grown;
        scan->held_cap = cap;
    }
    scan->held[scan->held_len++] = (ngc_held){response, authorization};
    return 0;
}

static void drain_ngc(ngc_scan *scan)
{
    while (scan->held_len) {
        ngc_held item = scan->held[--scan->held_len];
        br_http_release(scan->ctx, &item.response);
        free(item.authorization);
    }
    free(scan->held);
    scan->held = NULL;
    scan->held_cap = 0;
}

/* Basic authentication is built before the request. A helper failure is fatal
 * and is not a send. A NULL context drops this finding with no release. */
static int verify_ngc(ngc_scan *scan, br_slice key, br_result *result, bool *keep)
{
    *keep = true;
    static const unsigned char username[] = "$oauthtoken";
    char *authorization = NULL;
    if (br_http_basic_auth((br_slice){username, sizeof(username) - 1}, key, &authorization, scan->error) != 0) {
        free(authorization);
        return -1;
    }
    if (!scan->ctx) {
        free(authorization);
        *keep = false;
        return 0;
    }
    /* Header map is literal. Briar keeps accept; do not send Accept. */
    const br_header headers[] = {{"accept", "*/*"}, {"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://authn.nvidia.com/token?service=ngc",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE, .timeout_ms = 5000,
        .detector_type = 896,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int send_rc = br_http_send(scan->ctx, &request, &response, &send_error);
    free(send_error);
    if (send_rc) {
        br_http_release(scan->ctx, &response);
        free(authorization);
        return 0;
    }
    if (response.status >= 200 && response.status < 300) result->verified = true;
    if (hold_ngc(scan, response, authorization) != 0) {
        br_http_release(scan->ctx, &response);
        free(authorization);
        return -1;
    }
    return 0;
}

static int note_match(void *user, const br_span *groups, size_t ngroups)
{
    (void)groups;
    (void)ngroups;
    *(bool *)user = true;
    return 0;
}

static int on_outer(void *user, const br_span *groups, size_t ngroups)
{
    ngc_scan *scan = user;
    if (ngroups < 2 || groups[1].begin == SIZE_MAX || groups[1].end < groups[1].begin ||
        groups[1].end > scan->input.len)
        return fail(scan->error, "invalid NGC match");
    br_slice encoded = {scan->input.data + groups[1].begin, groups[1].end - groups[1].begin};
    br_bytes prefix = {0};
    size_t bad_offset = SIZE_MAX;
    int decoded = br_azure_base64_std_decode(encoded, &prefix, &bad_offset);
    (void)bad_offset;
    if (decoded < 0) {
        free(prefix.data);
        return fail(scan->error, "cannot decode NGC key");
    }
    /* Return 1 searches the owned prefix. Return 0 searches the full decode.
     * Neither status is published. */
    bool matched = false;
    char *inner_error = NULL;
    int inner_rc = br_regex_each(scan->inner, (br_slice){prefix.data, prefix.len}, note_match, &matched, &inner_error);
    free(prefix.data);
    if (inner_rc) {
        if (scan->error && !*scan->error) *scan->error = inner_error;
        else free(inner_error);
        return -1;
    }
    free(inner_error);
    if (!matched) return 0;
    br_result result = {0};
    if (br_finding_key_bytes(&result, 896, encoded, "key") != 0) {
        br_result_clear(&result);
        return fail(scan->error, "cannot create NGC finding");
    }
    bool keep = true;
    if (scan->verify && verify_ngc(scan, encoded, &result, &keep) != 0) {
        br_result_clear(&result);
        return -1;
    }
    if (!keep) {
        br_result_clear(&result);
        return 0;
    }
    if (br_results_push(scan->out, &result) != 0) {
        br_result_clear(&result);
        return fail(scan->error, "cannot append NGC finding");
    }
    return 0;
}

static int scan_ngc(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                    br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (input.len && !input.data))
        return fail(error, "invalid or uninitialized NGC scan");
    const ngc_state *compiled = detector->state;
    if (!compiled->outer || !compiled->inner)
        return fail(error, "invalid or uninitialized NGC scan");
    size_t before = out->len;
    ngc_scan scan = {
        .inner = compiled->inner, .ctx = ctx, .input = input, .out = out, .verify = verify, .error = error,
    };
    char *regex_error = NULL;
    int rc = br_regex_each(compiled->outer, input, on_outer, &scan, &regex_error);
    drain_ngc(&scan);
    if (rc) {
        if (error && !*error) *error = regex_error;
        else free(regex_error);
        rollback(out, before);
        return -1;
    }
    free(regex_error);
    return 0;
}

static const char *const keywords[] = {"ngc"};
static ngc_state state;
static const br_detector detector = {
    .type = 896, .version = 0, .name = "NGC", .custom_name = "",
    .description = "Nvidia's API for AI related things",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &state, .scan = scan_ngc,
};

int br_ngc_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (out) *out = NULL;
    if (!out) return fail(error, "invalid NGC detector output");
    if (!state.outer && br_regex_compile(outer_pattern, &state.outer, error) != 0) return -1;
    if (!state.inner && br_regex_compile(inner_pattern, &state.inner, error) != 0) return -1;
    *out = &detector;
    return 0;
}
