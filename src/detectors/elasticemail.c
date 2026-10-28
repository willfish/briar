/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/elasticemail/elasticemail.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"

#include <json-c/json.h>
#include <stdlib.h>
#include <string.h>

typedef struct { bool success; char *cause; } elasticemail_response;

static int elasticemail_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int elasticemail_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    elasticemail_response *response = user;
    if (!br_json_field_name(name, "success") || !value) return 0; /* Null bool is a no-op. */
    if (json_object_is_type(value, json_type_boolean)) response->success = json_object_get_boolean(value);
    else if (!response->cause && br_json_type_cause(value, ".success", "bool", &response->cause) != 0) return -1;
    /* Keep the FIRST type error, but continue original-order projection so a
     * later resource failure cannot be mistaken for ordinary parse suppression. */
    return 0;
}

static int elasticemail_decode(br_slice body, bool *success, char **cause)
{
    elasticemail_response response = {0};
    br_json *root = NULL;
    int rc = br_json_document(body, &root, &response.cause);
    if (rc == 0 && root) {
        if (json_object_is_type(root, json_type_object))
            rc = br_json_each_member(body, elasticemail_member, &response);
        else rc = br_json_type_cause(root, NULL, "struct { Success bool \"json:\\\"success\\\"\" }", &response.cause) == 0 ? 1 : -1;
    }
    json_object_put(root);
    if (rc == 0 && response.cause) rc = 1;
    *success = response.success;
    *cause = response.cause;
    /* Whole Unmarshal, not first-document decode or float64-map conversion.
     * Original spans preserve duplicates/null merging and typed folded names;
     * unknown huge numbers are ignored. +1 owns an ordinary cause, -1 is fatal. */
    return rc == 0 ? 0 : rc == 1 && response.cause ? 1 : -1;
}

static int elasticemail_verify(const br_scan_ctx *ctx, br_slice key, br_result *result,
                                bool *keep, char **error)
{
    static const char base[] = "https://api.elasticemail.com/v2/account/profileoverview?apikey=";
    /* Source completes its URL BEFORE construction. Exact 96 ASCII bytes need
     * only this known bound, no heap copy, formatter, encoding or arbitrary cap. */
    char url[sizeof(base) + 96];
    memcpy(url, base, sizeof(base) - 1);
    memcpy(url + sizeof(base) - 1, key.data, 96);
    url[sizeof(base) - 1 + 96] = '\0';
    if (!ctx) { *keep = false; return 0; }
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL, *json_cause = NULL;
    int rc = 0;
    /* Suppress the WHOLE mixed shared setup/allocation/Do domain, without a
     * setter or text classifier. Complete ReadAll precedes decoding at EVERY
     * status; any non-NULL read error, including empty, retains false. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0 && response.body_error == NULL) {
        bool success = false;
        int decoded = elasticemail_decode(response.body, &success, &json_cause);
        if (decoded < 0) rc = elasticemail_fail(error, "cannot decode ElasticEmail verification response");
        else if (decoded == 0) result->verified = success; /* Deliberately NO HTTP status gate. */
    }
    /* Full stack URL lives through synchronous send AND release. Source closes
     * after ReadAll, before Unmarshal; ABI1 releases after projection, even on
     * failure. Full Reader/raw UTF-8/unquoting/client/regexp and global source,
     * engine/output parity remain partial; ordinary causes are suppressed. */
    br_http_release(ctx, &response);
    free(send_error);
    free(json_cause);
    return rc == 0 ? 0 : -1;
}

static int elasticemail_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                              br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return elasticemail_fail(error, "invalid or uninitialized ElasticEmail scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        bool keep = true;
        /* TrimSpace is a no-op. Keep original occurrences/duplicates, without
         * token validation, local filtering or cache. Finding resources precede
         * complete URL preparation and any constructor skip. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = elasticemail_fail(&owned_error, "cannot create ElasticEmail result");
        if (rc == 0 && verify && elasticemail_verify(ctx, key, &result, &keep, &owned_error) != 0) rc = -1;
        if (rc == 0 && keep && br_results_push(out, &result) != 0)
            rc = elasticemail_fail(&owned_error, "cannot append ElasticEmail result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const elasticemail_keywords[] = {"elasticemail"};
static br_detector elasticemail_detector = {
    .type = 112, .version = 0, .name = "ElasticEmail", .custom_name = "",
    .description = "ElasticEmail is an email marketing service. ElasticEmail API keys can be used to send emails, manage contacts, and access other features of the service.",
    .keywords = elasticemail_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = elasticemail_scan,
};

int br_elasticemail_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return elasticemail_fail(error, "invalid ElasticEmail detector output");
    *out = NULL;
    if (!elasticemail_detector.state) {
        /* DISPATCH hint is elasticemail; source EXTRACTION prefix is ONLY elastic. */
        static const char *const extraction_keywords[] = {"elastic"};
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(extraction_keywords, 1, "\\b([A-Za-z0-9_-]{96})\\b", &regex, error) != 0) return -1;
        elasticemail_detector.state = regex;
    }
    *out = &elasticemail_detector;
    return 0;
}
