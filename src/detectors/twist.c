/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/twist/twist.go.
 * Raw is the hex token. Bearer uses oauth2:hex when the full match contains oauth. */
#include "detectors.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { char *token, *full; } twist_hit;
typedef struct { twist_hit *items; size_t len, cap; const unsigned char *data; char *error; } twist_box;

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static char *dup_span(const unsigned char *data, br_span span)
{
    if (span.begin == SIZE_MAX || span.end < span.begin) return NULL;
    size_t n = span.end - span.begin;
    char *copy = malloc(n + 1);
    if (!copy) return NULL;
    memcpy(copy, data + span.begin, n);
    copy[n] = '\0';
    return copy;
}

static int take_twist(void *user, const br_span *groups, size_t ngroups)
{
    twist_box *box = user;
    if (ngroups < 2) return fail(&box->error, "invalid Twist capture");
    if (box->len == box->cap) {
        size_t cap = box->cap ? box->cap * 2 : 4;
        twist_hit *items = realloc(box->items, cap * sizeof(*items));
        if (!items) return fail(&box->error, "cannot retain Twist token");
        box->items = items;
        box->cap = cap;
    }
    twist_hit hit = {dup_span(box->data, groups[1]), dup_span(box->data, groups[0])};
    if (!hit.token || !hit.full) {
        free(hit.token);
        free(hit.full);
        return fail(&box->error, "cannot retain Twist token");
    }
    box->items[box->len++] = hit;
    return 0;
}

static int verify_twist(const br_scan_ctx *ctx, const char *token, const char *full,
                        br_result *result, char **error)
{
    if (!ctx) return 1;
    const char *auth = token;
    char oauth[64];
    if (strstr(full, "oauth")) {
        int n = snprintf(oauth, sizeof(oauth), "oauth2:%s", token);
        if (n < 0 || (size_t)n >= sizeof(oauth)) return fail(error, "cannot format Twist token");
        auth = oauth;
    }
    char authorization[80];
    int n = snprintf(authorization, sizeof(authorization), "Bearer %s", auth);
    if (n < 0 || (size_t)n >= sizeof(authorization)) return fail(error, "cannot format Twist authorization");
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.twist.com/api/v3/users/get_session_user",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    if (!br_http_send(ctx, &request, &response, &transport_error) &&
        response.status >= 200 && response.status < 300)
        result->verified = true;
    br_http_release(ctx, &response);
    free(transport_error);
    return 0;
}

static int scan_twist(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Twist scan");
    size_t original_len = out->len;
    twist_box box = {.data = input.data};
    char *owned_error = NULL;
    int rc = br_regex_each(detector->state, input, take_twist, &box, &owned_error);
    if (box.error) {
        if (!owned_error) owned_error = box.error;
        else free(box.error);
        rc = -1;
    }
    for (size_t i = 0; !rc && i < box.len; ++i) {
        br_result result = {0};
        int outcome = 0;
        if (br_finding_key(&result, detector->type, box.items[i].token, "key") != 0) {
            fail(&owned_error, "cannot create Twist result");
            outcome = -1;
        } else if (verify)
            outcome = verify_twist(ctx, box.items[i].token, box.items[i].full, &result, &owned_error);
        if (outcome == 0 && br_results_push(out, &result) != 0) {
            fail(&owned_error, "cannot append Twist result");
            outcome = -1;
        }
        br_result_clear(&result);
        if (outcome < 0) rc = -1;
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    for (size_t i = 0; i < box.len; ++i) {
        free(box.items[i].token);
        free(box.items[i].full);
    }
    free(box.items);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"twist"};
static br_detector twist = {
    .type = 827, .version = 0, .name = "Twist", .custom_name = "",
    .description = "Twist is a team communication app. Twist access tokens can be used to access and manage Twist accounts and data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_twist,
};

int br_twist_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Twist detector output");
    *out = NULL;
    if (!twist.state && br_key_pattern_init(&twist, "\\b(?:oauth2:)?([0-9a-f]{40})\\b", error) != 0)
        return -1;
    *out = &twist;
    return 0;
}
