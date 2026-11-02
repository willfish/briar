/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/meraki/meraki.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "gcp_json.h"
#include "json.h"

#include <json-c/json.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_bytes id, name; } meraki_organization;
typedef struct { meraki_organization *items; size_t len, cap; } meraki_organizations;

static int meraki_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void meraki_organizations_clear(meraki_organizations *organizations)
{
    for (size_t i = 0; i < organizations->len; ++i) {
        free(organizations->items[i].id.data);
        free(organizations->items[i].name.data);
    }
    free(organizations->items);
    memset(organizations, 0, sizeof(*organizations));
}

/* Each ordered callback owns only a temporary JSON value. Even retaining the
 * top document cannot retain these strings; repair or copy before returning. */
static int meraki_string(br_json *value, br_bytes *target, char **error)
{
    br_slice text = {0};
    br_bytes repair = {0}, owned = {0};
    if (br_gcp_json_text(value, &text, &repair, error) != 0) {
        free(repair.data);
        return -1;
    }
    if (repair.data) owned = repair;
    else if (text.len) {
        if (text.len == SIZE_MAX) return meraki_fail(error, "Meraki organization string is too large");
        owned.data = malloc(text.len + 1);
        if (!owned.data) return meraki_fail(error, "cannot retain Meraki organization string");
        memcpy(owned.data, text.data, text.len);
        owned.data[text.len] = 0;
        owned.len = text.len;
    }
    free(target->data);
    *target = owned;
    return 0;
}

typedef struct { meraki_organizations *organizations; bool has_error; char *cause; char **error; } meraki_projection;
typedef struct { meraki_projection *projection; meraki_organization *organization; } meraki_fields;

static int meraki_type_cause(meraki_projection *projection, br_json *value,
                              const char *field, const char *expected)
{
    char *cause = NULL;
    if (br_json_type_cause(value, field, expected, &cause) != 0) {
        free(cause);
        return meraki_fail(projection->error, "cannot create Meraki response type cause");
    }
    /* Error presence is independent of nullable diagnostic storage. Preserve
     * even a first NULL cause while still performing later owned operations. */
    if (!projection->has_error) {
        projection->has_error = true;
        projection->cause = cause;
    } else free(cause);
    return 0;
}

static int meraki_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    meraki_fields *fields = user;
    br_bytes *target;
    const char *field;
    if (br_json_field_name(name, "id")) {
        target = &fields->organization->id; field = "merakiOrganizations.id";
    } else if (br_json_field_name(name, "name")) {
        target = &fields->organization->name; field = "merakiOrganizations.name";
    } else return 0;
    if (!value) return 0; /* Scalar null retains the preceding string. */
    if (!json_object_is_type(value, json_type_string))
        return meraki_type_cause(fields->projection, value, field, "string");
    return meraki_string(value, target, fields->projection->error);
}

static int meraki_element(void *user, size_t index, br_json *value, br_slice encoded)
{
    meraki_projection *projection = user;
    meraki_organizations *organizations = projection->organizations;
    if (index != organizations->len) return meraki_fail(projection->error, "invalid Meraki organization index");
    if (organizations->len == organizations->cap) {
        if (organizations->cap > SIZE_MAX / sizeof(*organizations->items) / 2)
            return meraki_fail(projection->error, "too many Meraki organizations");
        size_t cap = organizations->cap ? organizations->cap * 2 : 8;
        meraki_organization *items = realloc(organizations->items, cap * sizeof(*items));
        if (!items) return meraki_fail(projection->error, "cannot stage Meraki organizations");
        organizations->items = items; organizations->cap = cap;
    }
    meraki_organization *organization = &organizations->items[organizations->len++];
    *organization = (meraki_organization){0};
    if (!value) return 0; /* A null array element is a zero struct, not omitted. */
    if (!json_object_is_type(value, json_type_object))
        return meraki_type_cause(projection, value, NULL, "meraki.merakiOrganizations");
    meraki_fields fields = {projection, organization};
    return br_json_each_member(encoded, meraki_member, &fields);
}

static int meraki_decode(br_slice body, const char *read_error, meraki_organizations *organizations,
                          bool *has_error, char **ordinary, char **error)
{
    br_json *document = NULL;
    char *cause = NULL;
    size_t end = 0;
    int parsed = br_json_first_document(body, read_error, &document, &end, &cause), rc = 0;
    bool present = parsed == 1;
    if (parsed != 0 && parsed != 1) {
        rc = meraki_fail(error, "cannot decode Meraki response document");
    } else if (parsed == 0 && document) {
        meraki_projection projection = {.organizations = organizations, .error = error};
        if (!json_object_is_type(document, json_type_array))
            rc = meraki_type_cause(&projection, document, NULL, "[]meraki.merakiOrganizations");
        else if (br_json_each_element((br_slice){body.data, end}, meraki_element, &projection) != 0) {
            if (!error || !*error) meraki_fail(error, "cannot visit Meraki organizations");
            rc = -1;
        }
        if (rc == 0) { present = projection.has_error; cause = projection.cause; }
        else free(projection.cause);
    }
    json_object_put(document);
    if (rc == 0) { *has_error = present; *ordinary = cause; cause = NULL; }
    free(cause);
    return rc;
}

static int meraki_verify(const br_scan_ctx *ctx, br_slice key, meraki_organizations *organizations,
                          bool *verified, bool *has_error, char **ordinary, char **error)
{
    if (!ctx) {
        *has_error = true;
        *ordinary = strdup("net/http: nil Context");
        return *ordinary ? 0 : meraki_fail(error, "cannot copy Meraki constructor cause");
    }
    const br_header headers[] = {{"X-Cisco-Meraki-Api-Key", (const char *)key.data}};
    unsigned char dedup_key[45];
    memcpy(dedup_key, "1000:", 5);
    memcpy(dedup_key + 5, key.data, key.len);
    const br_http_request request = {
        .method = "GET", .url = "https://api.meraki.com/api/v1/organizations",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = 1000, .dedup_key = {dedup_key, sizeof(dedup_key)},
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &send_error), rc = 0;
    if (sent != 0) {
        /* Consume the post-client outcome. Owned dedup buffering/read-error
         * promotion belongs to the client; never infer provenance from text. */
        *has_error = true;
        *ordinary = send_error; send_error = NULL;
    } else if (response.status == 200) {
        rc = meraki_decode(response.body, response.body_error, organizations, has_error, ordinary, error);
        if (rc == 0 && !*has_error) *verified = true;
    } else if (response.status != 401) {
        *has_error = true;
        char status[64];
        int n = snprintf(status, sizeof(status), "unexpected status code: %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status)) rc = meraki_fail(error, "cannot format Meraki status cause");
        else {
            *ordinary = strdup(status);
            if (!*ordinary) rc = meraki_fail(error, "cannot copy Meraki status cause");
        }
    }
    /* Fully stage before release, then outer verdict/setter/metadata/publication.
     * Provider header/key/URL stay live, but ordinary prepared storage does not. */
    br_http_release(ctx, &response);
    free(send_error);
    return rc;
}

static int meraki_metadata(br_result *result, const meraki_organizations *organizations, char **error)
{
    static const char prefix[] = "organization_";
    for (size_t i = 0; i < organizations->len; ++i) {
        const meraki_organization *organization = &organizations->items[i];
        if (organization->id.len > SIZE_MAX - sizeof(prefix))
            return meraki_fail(error, "Meraki organization key is too large");
        size_t length = sizeof(prefix) - 1 + organization->id.len;
        char *key = malloc(length + 1);
        if (!key) return meraki_fail(error, "cannot allocate Meraki organization key");
        memcpy(key, prefix, sizeof(prefix) - 1);
        if (organization->id.len) memcpy(key + sizeof(prefix) - 1, organization->id.data, organization->id.len);
        key[length] = 0;
        /* Only successful full typed decode reaches this shared C-string-key
         * boundary. Preserve the full formatted bytes; never truncate an ID. */
        if (memchr(key, 0, length)) {
            free(key);
            return meraki_fail(error, "unsupported Meraki organization ID with NUL");
        }
        if (organization->name.len > INT_MAX) {
            free(key);
            return meraki_fail(error, "Meraki organization name is too large");
        }
        br_json *name = json_object_new_string_len(organization->name.data ?
                            (const char *)organization->name.data : "", (int)organization->name.len);
        if (!name) {
            free(key);
            return meraki_fail(error, "cannot allocate Meraki organization name");
        }
        int added = json_object_object_add(result->extra_data, key, name);
        free(key);
        if (added != 0) {
            json_object_put(name);
            return meraki_fail(error, "cannot set Meraki organization metadata");
        }
    }
    return 0;
}

static int meraki_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return meraki_fail(error, "invalid or uninitialized Meraki scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, true, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        meraki_organizations organizations = {0};
        char *ordinary = NULL;
        bool verified = false, has_error = false;
        if (key.len != 40) rc = meraki_fail(&owned_error, "invalid Meraki capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = meraki_fail(&owned_error, "cannot create Meraki finding");
        else if (!(result.extra_data = json_object_new_object()))
            rc = meraki_fail(&owned_error, "cannot allocate Meraki extra data");
        if (rc == 0 && verify) {
            rc = meraki_verify(ctx, key, &organizations, &verified, &has_error, &ordinary, &owned_error);
            if (rc == 0) {
                result.verified = verified;
                /* Source passes ZERO secrets: echoed keys remain unredacted. */
                if (has_error && br_result_set_verification_error(&result, ordinary, NULL, 0) != 0)
                    rc = meraki_fail(&owned_error, "cannot set Meraki verification error");
                if (rc == 0 && verified) rc = meraki_metadata(&result, &organizations, &owned_error);
            }
        }
        free(ordinary);
        meraki_organizations_clear(&organizations);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = meraki_fail(&owned_error, "cannot append Meraki finding");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const meraki_keywords[] = {"meraki"};
static br_detector meraki_detector = {
    .type = 1000, .version = 0, .name = "Meraki", .custom_name = "",
    .description = "Cisco Meraki is a cloud-managed IT solution that provides networking, security, and device management through an easy-to-use interface.Meraki APIs make it possible to rapidly deploy and manage networks at scale, build on a platform of intelligent, cloud-connected IT products, and engage with users in powerful new ways.",
    .keywords = meraki_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = meraki_scan,
};

int br_meraki_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return meraki_fail(error, "invalid Meraki detector output");
    *out = NULL;
    if (!meraki_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(meraki_keywords, 1, "([0-9a-f]{40})", &regex, error) != 0) {
            br_regex_free(regex);
            return -1;
        }
        meraki_detector.state = regex;
    }
    *out = &meraki_detector;
    return 0;
}
