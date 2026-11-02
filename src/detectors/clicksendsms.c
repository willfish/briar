/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/clicksendsms/clicksendsms.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "email_pattern.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } clicksendsms_patterns;
typedef struct {
    br_slice input;
    br_span *items;
    size_t len, cap;
    char *error;
} clicksendsms_ids;

static int clicksendsms_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static br_slice clicksendsms_trim_leading(br_slice id)
{
    /* Only the projected prefix can be whitespace: the email grammar ends in
     * a word byte or ']'. Match Go White_Space facts, not a general UTF-8 shim. */
    size_t at = 0;
    while (at < id.len) {
        const unsigned char *s = id.data + at;
        size_t left = id.len - at, width = 0;
        if (s[0] == ' ' || (s[0] >= 0x09 && s[0] <= 0x0d)) width = 1;
        else if (left >= 2 && s[0] == 0xc2 && (s[1] == 0x85 || s[1] == 0xa0)) width = 2;
        else if (left >= 3 &&
                 ((s[0] == 0xe1 && s[1] == 0x9a && s[2] == 0x80) ||
                  (s[0] == 0xe2 && s[1] == 0x80 &&
                   ((s[2] >= 0x80 && s[2] <= 0x8a) || s[2] == 0xa8 || s[2] == 0xa9 || s[2] == 0xaf)) ||
                  (s[0] == 0xe2 && s[1] == 0x81 && s[2] == 0x9f) ||
                  (s[0] == 0xe3 && s[1] == 0x80 && s[2] == 0x80))) width = 3;
        if (!width) break;
        at += width;
    }
    return (br_slice){id.data + at, id.len - at};
}

static int clicksendsms_collect_id(void *user, const br_span *groups, size_t count)
{
    clicksendsms_ids *ids = user;
    if (!count || groups[0].begin == SIZE_MAX || groups[0].end <= groups[0].begin || groups[0].end > ids->input.len)
        return clicksendsms_fail(&ids->error, "invalid ClickSendsms ID match");
    size_t begin = groups[0].begin, end = groups[0].end;
    /* Source projects FULL match zero after its last literal ASCII space, not
     * email capture one. With no space, SMS/gap/NUL bytes remain in the ID. */
    for (size_t i = end; i > begin; --i) {
        if (ids->input.data[i - 1] == ' ') { begin = i; break; }
    }
    br_slice id = clicksendsms_trim_leading((br_slice){ids->input.data + begin, end - begin});
    if (ids->len == ids->cap) {
        if (ids->cap > SIZE_MAX / sizeof(*ids->items) / 2)
            return clicksendsms_fail(&ids->error, "too many ClickSendsms IDs");
        size_t cap = ids->cap ? ids->cap * 2 : 8;
        br_span *items = realloc(ids->items, cap * sizeof(*items));
        if (!items) return clicksendsms_fail(&ids->error, "out of memory collecting ClickSendsms IDs");
        ids->items = items;
        ids->cap = cap;
    }
    /* Borrow projected bytes from this scan's immutable input, without copying
     * unbounded IDs or losing occurrences, embedded NUL or original spelling. */
    ids->items[ids->len++] = (br_span){(size_t)(id.data - ids->input.data), end};
    return 0;
}

static void clicksendsms_send(const br_scan_ctx *ctx, const char *authorization, br_result *result)
{
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://rest.clicksend.com/v3/account",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .detector_type = 209,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* The combined adapter allocation/setup/Do nonzero domain is suppressed.
     * There is no source verification-error setter or error-text classifier. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers close-only. Eager buffering/per-request ABI release
     * remains a lifecycle gap; response bodies and read errors are ignored. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int clicksendsms_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                              br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return clicksendsms_fail(error, "invalid ClickSendsms scan arguments");
    const clicksendsms_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->id)
        return clicksendsms_fail(error, "uninitialized ClickSendsms detector");
    size_t original_len = out->len;
    br_captures keys = {0};
    clicksendsms_ids ids = {.input = input};
    int rc = br_captures_find(patterns->key, input, &keys, false, error);
    if (rc == 0) {
        char *id_error = NULL;
        rc = br_regex_each(patterns->id, input, clicksendsms_collect_id, &ids, &id_error);
        if (ids.error) { free(id_error); id_error = ids.error; }
        if (error) *error = id_error;
        else free(id_error);
    }
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        br_slice key = br_captures_at(&keys, k);
        for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
            br_span span = ids.items[i];
            br_slice id = {input.data + span.begin, span.end - span.begin};
            br_result result = {0};
            if (br_finding_pair_bytes(&result, detector->type, key, "key", id, "id", (br_slice){0}) != 0)
                rc = clicksendsms_fail(error, "out of memory creating ClickSendsms result");
            if (rc == 0 && verify) {
                char *authorization = NULL;
                /* Source builds ID:KEY Base64 BEFORE NewRequestWithContext.
                 * Basic resource failures, even positive +1, are fatal before
                 * the known nil-context constructor skip; NoV never does this. */
                if (br_http_basic_auth(id, key, &authorization, NULL) != 0)
                    rc = clicksendsms_fail(error, "out of memory constructing ClickSendsms Basic authentication");
                else if (!ctx) {
                    free(authorization);
                    br_result_clear(&result);
                    continue;
                } else clicksendsms_send(ctx, authorization, &result);
                free(authorization);
            }
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = clicksendsms_fail(error, "out of memory appending ClickSendsms result");
            br_result_clear(&result);
        }
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    free(ids.items);
    return rc == 0 ? 0 : -1;
}

static clicksendsms_patterns clicksendsms_compiled;
static const char *const clicksendsms_keywords[] = {"clicksendsms"};
static const char *const clicksendsms_id_prefixes[] = {"sms"};
static const br_detector clicksendsms_detector = {
    .type = 209, .version = 0, .name = "ClickSendsms", .custom_name = "",
    .description = "ClickSend is a global leader in business communication solutions, providing a range of services including SMS, email, and voice. "
                   "ClickSend API keys can be used to access and manage these communication services.",
    .keywords = clicksendsms_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &clicksendsms_compiled, .scan = clicksendsms_scan,
};

int br_clicksendsms_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return clicksendsms_fail(error, "invalid ClickSendsms detector output");
    *out = NULL;
    if (!clicksendsms_compiled.key && br_regex_compile(
        "\\b([0-9A-Z]{8}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{12})\\b",
        &clicksendsms_compiled.key, error) != 0) return -1;
    if (!clicksendsms_compiled.id && br_regex_compile_prefixed(clicksendsms_id_prefixes, 1,
        br_email_pattern, &clicksendsms_compiled.id, error) != 0) return -1;
    *out = &clicksendsms_detector;
    return 0;
}
