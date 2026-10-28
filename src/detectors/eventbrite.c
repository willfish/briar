/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/eventbrite/eventbrite.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"
#include "key_scan.h"
#include "../utf8.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_json *extra; char *cause; bool verified; } eventbrite_verdict;

static int eventbrite_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int eventbrite_cause(char **cause, const char *message, char **error)
{
    *cause = strdup(message);
    return *cause ? 0 : eventbrite_fail(error, "cannot create Eventbrite verification cause");
}

static int eventbrite_member(void *state, br_slice key, br_json *value, br_slice encoded)
{
    (void)encoded;
    if (key.len != 4 || memcmp(key.data, "name", 4)) return 0;
    br_json **name = state;
    json_object_put(*name);
    *name = value && json_object_is_type(value, json_type_string) ? json_object_get(value) : NULL;
    /* Generic map assignment: EVERY exact duplicate replaces. Null/non-string
     * clears eligibility; a later string restores it. Empty strings are valid.
     * No folded struct-field matching, sticky type error or C-string key lookup. */
    return 0;
}

/* 0 owned name string, +1 owned ordinary decode cause, -1 fatal owned native
 * failure/unsupported upstream panic. Never turn assertion failure into false. */
static int eventbrite_decode(br_slice body, const char *body_error, br_json **name, char **cause, char **error)
{
    *name = NULL; *cause = NULL;
    br_json *root = NULL; size_t end = 0;
    int rc = br_json_first_document(body, body_error, &root, &end, cause);
    if (rc != 0) {
        json_object_put(root);
        return rc < 0 ? eventbrite_fail(error, "cannot decode Eventbrite response") : 1;
    }
    if (root && !json_object_is_type(root, json_type_object)) {
        /* Root mismatch outranks conversion of numbers within an array, etc. */
        rc = br_json_type_cause(root, NULL, "map[string]interface {}", cause);
        json_object_put(root);
        return rc == 0 ? 1 : eventbrite_fail(error, "cannot create Eventbrite root type cause");
    }
    br_slice document = {body.data, end};
    if (!br_utf8_valid(document)) {
        json_object_put(root);
        return eventbrite_fail(error, "unsupported: Eventbrite invalid UTF-8 in consumed JSON document");
    }
    if (root) {
        /* Check ORIGINAL consumed bytes, not saturated/collapsed json-c values.
         * Even nested/unknown/overwritten numbers undergo Go float64 conversion.
         * Syntax/read and wrong-root errors have ALREADY taken precedence. */
        rc = br_json_check_float64_numbers(document, cause);
        if (!rc && br_json_each_member(document, eventbrite_member, name) != 0) rc = -1;
    }
    json_object_put(root);
    if (rc != 0) {
        json_object_put(*name); *name = NULL;
        return rc < 0 ? eventbrite_fail(error, "cannot project Eventbrite generic response") : 1;
    }
    if (!*name)
        return eventbrite_fail(error, "unsupported upstream panic: Eventbrite name string assertion");
    /* Source response["name"].(string) also panics for root null, missing name,
     * or final null/non-string. A retained empty JSON string is still success. */
    return 0;
}

static void eventbrite_verdict_clear(eventbrite_verdict *verdict)
{
    json_object_put(verdict->extra); free(verdict->cause); *verdict = (eventbrite_verdict){0};
}

static int eventbrite_request(const br_scan_ctx *ctx, br_slice key, eventbrite_verdict *verdict, char **error)
{
    static const char prefix[] = "https://www.eventbriteapi.com/v3/users/me/?token=";
    char url[70];
    _Static_assert(sizeof(prefix) - 1 + 20 + 1 == sizeof(url), "Eventbrite URL must be 69 bytes plus NUL");
    memcpy(url, prefix, sizeof(prefix) - 1); memcpy(url + sizeof(prefix) - 1, key.data, key.len);
    url[sizeof(url) - 1] = '\0'; /* Complete query argument precedes constructor handling. */
    if (!ctx) return eventbrite_cause(&verdict->cause, "net/http: nil Context", error);
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE, .detector_type = 962,
    };
    br_http_response response = {0}; char *transport_error = NULL; br_json *name = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0) {
        /* Combined shared setup/allocation/Do failures remain ordinary causes.
         * The error output is owned: MOVE it, never clone/strip/classify text. */
        verdict->cause = transport_error; transport_error = NULL;
        if (!verdict->cause) rc = eventbrite_cause(&verdict->cause, "HTTP transport failed", error);
    } else if (response.status == 200) {
        int decoded = eventbrite_decode(response.body, response.body_error, &name, &verdict->cause, error);
        if (decoded < 0) rc = -1;
        else if (!decoded) {
            /* Prepare an independently owned pending map BEFORE caller state
             * changes. Retain/transfer the entire string, including empty/NUL. */
            verdict->extra = json_object_new_object();
            if (!verdict->extra || json_object_object_add(verdict->extra, "user name", name) != 0)
                rc = eventbrite_fail(error, "cannot create Eventbrite user metadata");
            else { name = NULL; verdict->verified = true; }
        }
    } else if (response.status != 401 && response.status != 403) {
        char message[64]; int len = snprintf(message, sizeof(message), "unexpected status code: %d", response.status);
        rc = len >= 0 && (size_t)len < sizeof(message) ? eventbrite_cause(&verdict->cause, message, error) :
             eventbrite_fail(error, "cannot format Eventbrite status cause");
    }
    /* Borrowed Reader diagnostics were copied by the decoder; pending strings
     * and transport causes are already owned. The complete stack URL survives
     * BOTH send and release. Source drains+closes within this verifier. Buffered
     * Reader/private-client/error-chain/full JSON/panic/map-order/global parity
     * remain partial; no native HTTP guard is weakened. */
    br_http_release(ctx, &response);
    free(transport_error); json_object_put(name);
    return rc ? -1 : 0;
}

static int eventbrite_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len)) return eventbrite_fail(error, "invalid or uninitialized Eventbrite scan");
    size_t original_len = out->len;
    br_captures keys = {0}; char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, true, &owned_error);
    /* Original byte uniqueness; first-source order is one native traversal,
     * not randomized Go map-order parity. No trimming or case normalization. */
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i); br_result result = {0}; eventbrite_verdict verdict = {0};
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) rc = eventbrite_fail(&owned_error, "cannot create Eventbrite finding");
        /* ALWAYS own the initial empty map, even if verification replaces it. */
        if (!rc && !(result.extra_data = json_object_new_object())) rc = eventbrite_fail(&owned_error, "cannot create Eventbrite empty metadata");
        if (!rc && verify) {
            rc = eventbrite_request(ctx, key, &verdict, &owned_error);
            if (!rc) {
                /* Exact source caller ordering: Verified -> ZERO-secret setter
                 * -> ExtraData replacement. Metadata/cause resources are already
                 * checked; a +1 setter failure aborts BEFORE replacement. */
                result.verified = verdict.verified;
                if (br_result_set_verification_error(&result, verdict.cause, NULL, 0) != 0)
                    rc = eventbrite_fail(&owned_error, "cannot set Eventbrite verification error");
                else {
                    json_object_put(result.extra_data); result.extra_data = verdict.extra; verdict.extra = NULL;
                }
            }
        }
        if (!rc && br_results_push(out, &result) != 0) rc = eventbrite_fail(&owned_error, "cannot append Eventbrite finding");
        eventbrite_verdict_clear(&verdict); br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error; else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const eventbrite_keywords[] = {"eventbrite"};
static br_detector eventbrite_detector = {
    .type = 962, .version = 0, .name = "Eventbrite", .custom_name = "",
    .description = "Eventbrite is an event management and ticketing website. Eventbrite API keys can be used to access and manage event data.",
    .keywords = eventbrite_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = eventbrite_scan,
};

int br_eventbrite_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return eventbrite_fail(error, "invalid Eventbrite detector output");
    *out = NULL;
    if (br_key_pattern_init(&eventbrite_detector, "\\b([0-9A-Z]{20})\\b", error) != 0) return -1;
    *out = &eventbrite_detector;
    return 0;
}
