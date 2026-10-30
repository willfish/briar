/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/lokalisetoken/lokalisetoken.go. */
#include "captures.h"
#include "findings.h"
#include "gcp_json.h"
#include "json.h"

#include <json-c/json.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int lokalise_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int lokalise_cause(char **cause, const char *message, char **error)
{
    *cause = strdup(message);
    return *cause ? 0 : lokalise_fail(error, "cannot allocate LokaliseToken verification cause");
}

typedef struct {
    br_json *ref;
    br_slice text;
    br_bytes repair;
} lokalise_creator;
typedef struct {
    lokalise_creator *items;
    size_t len, cap;
} lokalise_creators;
typedef struct {
    lokalise_creators creators;
    size_t array_len;
    bool invalid;
    char **fatal;
} lokalise_projection;
typedef struct { lokalise_projection *projection; size_t index; } lokalise_project;

static void lokalise_creators_clear(lokalise_creators *creators)
{
    /* Shorter duplicate arrays leave reusable values beyond their new length. */
    for (size_t i = 0; i < creators->cap; ++i) {
        json_object_put(creators->items[i].ref);
        free(creators->items[i].repair.data);
    }
    free(creators->items);
    *creators = (lokalise_creators){0};
}

static int lokalise_slot(lokalise_creators *creators, size_t index, char **error)
{
    if (index < creators->cap) return 0;
    if (index == SIZE_MAX || index + 1 > SIZE_MAX / sizeof(*creators->items))
        return lokalise_fail(error, "too many LokaliseToken project slots");
    size_t cap = creators->cap ? creators->cap * 2 : 8;
    if (cap < creators->cap || cap <= index) cap = index + 1;
    if (cap > SIZE_MAX / sizeof(*creators->items)) cap = index + 1;
    lokalise_creator *items = malloc(cap * sizeof(*items));
    if (!items) return lokalise_fail(error, "cannot allocate LokaliseToken project slots");
    memset(items, 0, cap * sizeof(*items));
    if (creators->cap) memcpy(items, creators->items, creators->cap * sizeof(*items));
    free(creators->items);
    creators->items = items;
    creators->cap = cap;
    return 0;
}

static int lokalise_email_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    lokalise_project *project = user;
    lokalise_projection *projection = project->projection;
    if (!br_json_field_name(name, "created_by_email") || !value) return 0;
    if (!json_object_is_type(value, json_type_string)) {
        projection->invalid = true;
        return 0;
    }
    lokalise_creator next = {0};
    if (br_gcp_json_text(value, &next.text, &next.repair, projection->fatal) != 0) {
        free(next.repair.data);
        return -1;
    }
    next.ref = json_object_get(value); /* Member values are borrowed. */
    lokalise_creator *slot = &projection->creators.items[project->index];
    json_object_put(slot->ref);
    free(slot->repair.data);
    *slot = next;
    return 0;
}

static int lokalise_project_element(void *user, size_t index, br_json *value, br_slice encoded)
{
    lokalise_projection *projection = user;
    if (lokalise_slot(&projection->creators, index, projection->fatal) != 0) return -1;
    projection->array_len = index + 1;
    if (!value) return 0; /* Null value structs preserve reused fields. */
    if (!json_object_is_type(value, json_type_object)) {
        projection->invalid = true;
        return 0;
    }
    lokalise_project project = {projection, index};
    return br_json_each_member(encoded, lokalise_email_member, &project);
}

static int lokalise_projects_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    lokalise_projection *projection = user;
    if (!br_json_field_name(name, "projects")) return 0;
    if (!value) {
        lokalise_creators_clear(&projection->creators);
        return 0;
    }
    if (!json_object_is_type(value, json_type_array)) {
        projection->invalid = true;
        return 0;
    }
    projection->array_len = 0;
    int rc = br_json_each_element(encoded, lokalise_project_element, projection);
    if (rc != 0) return rc;
    projection->creators.len = projection->array_len;
    if (!projection->array_len) lokalise_creators_clear(&projection->creators);
    return 0;
}

static int lokalise_decode(const br_http_response *response, lokalise_creators *creators, char **error)
{
    br_json *root = NULL;
    size_t end = 0;
    char *cause = NULL;
    int rc = br_json_first_document(response->body, response->body_error, &root, &end, &cause);
    free(cause);
    if (rc != 0) {
        json_object_put(root);
        /* Only the decoder's documented +1 is ordinary and suppressed at 200. */
        return rc == 1 ? 0 : lokalise_fail(error, "cannot decode LokaliseToken response");
    }
    lokalise_projection projection = {.fatal = error};
    if (root && !json_object_is_type(root, json_type_object)) projection.invalid = true;
    else if (root && br_json_each_member((br_slice){response->body.data, end}, lokalise_projects_member, &projection) != 0)
        rc = lokalise_fail(error && *error ? NULL : error, "cannot project LokaliseToken response");
    json_object_put(root);
    if (rc == 0 && !projection.invalid) {
        *creators = projection.creators;
        projection.creators = (lokalise_creators){0};
    }
    lokalise_creators_clear(&projection.creators);
    return rc;
}

static int lokalise_verify(const br_scan_ctx *ctx, br_slice key, lokalise_creators *creators,
                            bool *verified, char **cause, char **error)
{
    *verified = false;
    *cause = NULL;
    /* NewRequestWithContext precedes header construction. */
    if (!ctx) return lokalise_cause(cause, "net/http: nil Context", error);
    const br_header header = {"X-Api-Token", (const char *)key.data};
    const br_http_request request = {
        .method = "GET", .url = "https://api.lokalise.com/api2/projects",
        .headers = &header, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = 129,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &send_error) != 0) {
        if (send_error) { *cause = send_error; send_error = NULL; }
        else rc = lokalise_cause(cause, "HTTP transport failed", error);
    } else {
        switch (response.status) {
        case 200:
            rc = lokalise_decode(&response, creators, error);
            if (rc == 0) *verified = true;
            break;
        case 401: case 403: break;
        default: {
            char message[64];
            int n = snprintf(message, sizeof(message), "unexpected status code: %d", response.status);
            if (n < 0 || (size_t)n >= sizeof(message)) rc = lokalise_fail(error, "cannot format LokaliseToken status cause");
            else rc = lokalise_cause(cause, message, error);
            break;
        }
        }
    }
    /* Source helper drains/closes before return. ABI1 releases its buffered
     * response here; retained creator strings and original token survive it,
     * but ordinary synthesized prepared headers/UA do not outlive send. */
    br_http_release(ctx, &response);
    free(send_error);
    return rc;
}

static int lokalise_add_creators(br_result *result, const lokalise_creators *creators, char **error)
{
    size_t len = 0;
    for (size_t i = 0; i < creators->len; ++i) {
        size_t separator = i ? 2 : 0;
        if (len > SIZE_MAX - separator || creators->items[i].text.len > SIZE_MAX - len - separator)
            return lokalise_fail(error, "LokaliseToken creator metadata too large");
        len += separator + creators->items[i].text.len;
    }
    if (len > INT_MAX) return lokalise_fail(error, "LokaliseToken creator metadata exceeds JSON string representation");
    char *joined = malloc(len + 1);
    if (!joined) return lokalise_fail(error, "cannot join LokaliseToken project creators");
    size_t at = 0;
    for (size_t i = 0; i < creators->len; ++i) {
        if (i) { memcpy(joined + at, ", ", 2); at += 2; }
        br_slice text = creators->items[i].text;
        if (text.len) memcpy(joined + at, text.data, text.len);
        at += text.len;
    }
    joined[at] = 0;
    br_json *value = json_object_new_string_len(joined, (int)len);
    free(joined);
    if (!value) return lokalise_fail(error, "cannot create LokaliseToken creator metadata");
    if (json_object_object_add(result->extra_data, "project creators", value) != 0) {
        json_object_put(value);
        return lokalise_fail(error, "cannot insert LokaliseToken creator metadata");
    }
    return 0;
}

static int lokalise_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return lokalise_fail(error, "invalid or uninitialized LokaliseToken scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (key.len != 40 || br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = lokalise_fail(&owned_error, "cannot create LokaliseToken result");
        if (rc == 0) {
            result.extra_data = json_object_new_object();
            if (!result.extra_data) rc = lokalise_fail(&owned_error, "cannot create LokaliseToken extra data");
        }
        if (rc == 0 && verify) {
            bool verified = false;
            char *cause = NULL;
            lokalise_creators creators = {0};
            rc = lokalise_verify(ctx, key, &creators, &verified, &cause, &owned_error);
            if (rc == 0) {
                result.verified = verified;
                if (br_result_set_verification_error(&result, cause, &key, 1) != 0)
                    rc = lokalise_fail(&owned_error, "cannot store LokaliseToken verification error");
            }
            free(cause);
            if (rc == 0 && creators.len) rc = lokalise_add_creators(&result, &creators, &owned_error);
            lokalise_creators_clear(&creators);
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = lokalise_fail(&owned_error, "cannot append LokaliseToken result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const lokalise_keywords[] = {"lokalise"};
static br_detector lokalise_detector = {
    .type = 129, .version = 0, .name = "LokaliseToken", .custom_name = "",
    .description = "Lokalise is a translation management system that helps teams to manage and automate their localization process. Lokalise tokens can be used to access its API and modify project data.",
    .keywords = lokalise_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = lokalise_scan,
};

int br_lokalisetoken_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return lokalise_fail(error, "invalid LokaliseToken detector output");
    *out = NULL;
    if (!lokalise_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(lokalise_keywords, 1, "\\b([a-z0-9]{40})\\b", &regex, error) != 0) return -1;
        lokalise_detector.state = regex;
    }
    *out = &lokalise_detector;
    return 0;
}
