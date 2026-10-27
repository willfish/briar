/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/datadogtoken/datadogtoken.go. */
#include "detectors.h"
#include "captures.h"
#include "endpoints.h"
#include "findings.h"
#include "json.h"
#include "../utf8.h"

#include <json-c/json.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *app, *api, *host; } datadog_patterns;

/* Only this provider's response fields. Strings retain visitor-owned JSON
 * references; NULL string references represent the Go zero-value string. */
typedef struct {
    br_json *email, *type, *name, *url;
    bool service_account, verified, disabled;
} datadog_item;
typedef struct {
    datadog_item **items;
    size_t len, initialized;
} datadog_slots;
typedef struct {
    datadog_slots data, included;
    bool bad_type;
} datadog_response;
typedef struct {
    datadog_response *response;
    datadog_slots *slots;
    datadog_item *item;
    bool organization;
} datadog_projection;

static int datadog_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void datadog_item_clear(datadog_item *item)
{
    if (!item) return;
    json_object_put(item->email);
    json_object_put(item->type);
    json_object_put(item->name);
    json_object_put(item->url);
    free(item);
}

static void datadog_slots_clear(datadog_slots *slots)
{
    /* Shortened duplicate arrays retain hidden pointer slots until reset. */
    for (size_t i = 0; i < slots->initialized; ++i) datadog_item_clear(slots->items[i]);
    free(slots->items);
    memset(slots, 0, sizeof(*slots));
}

static void datadog_response_clear(datadog_response *response)
{
    datadog_slots_clear(&response->data);
    datadog_slots_clear(&response->included);
    response->bad_type = false;
}

static void datadog_string(datadog_projection *projection, br_json *value, br_json **field)
{
    if (!value) return; /* null into a string is a no-op, not an empty assignment. */
    if (!json_object_is_type(value, json_type_string)) {
        projection->response->bad_type = true;
        return;
    }
    json_object_put(*field);
    *field = json_object_get(value);
}

static void datadog_boolean(datadog_projection *projection, br_json *value, bool *field)
{
    if (!value) return;
    if (!json_object_is_type(value, json_type_boolean)) {
        projection->response->bad_type = true;
        return;
    }
    *field = json_object_get_boolean(value);
}

static int datadog_attributes(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    datadog_projection *projection = user;
    datadog_item *item = projection->item;
    if (br_json_field_name(name, "disabled")) datadog_boolean(projection, value, &item->disabled);
    else if (projection->organization) {
        if (br_json_field_name(name, "name")) datadog_string(projection, value, &item->name);
        else if (br_json_field_name(name, "url")) datadog_string(projection, value, &item->url);
    } else {
        if (br_json_field_name(name, "email")) datadog_string(projection, value, &item->email);
        else if (br_json_field_name(name, "verified")) datadog_boolean(projection, value, &item->verified);
        else if (br_json_field_name(name, "service_account")) datadog_boolean(projection, value, &item->service_account);
    }
    return 0;
}

static int datadog_item_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    datadog_projection *projection = user;
    if (projection->organization && br_json_field_name(name, "type"))
        datadog_string(projection, value, &projection->item->type);
    else if (br_json_field_name(name, "attributes") && value) {
        if (!json_object_is_type(value, json_type_object)) projection->response->bad_type = true;
        else return br_json_each_member(encoded, datadog_attributes, projection);
    } /* A null value-struct merges nothing; duplicate attribute objects merge. */
    return 0;
}

static int datadog_element(void *user, size_t index, br_json *value, br_slice encoded)
{
    datadog_projection *projection = user;
    if (index >= projection->slots->initialized) return -1;
    datadog_item **slot = &projection->slots->items[index];
    if (!value) {
        datadog_item_clear(*slot);
        *slot = NULL; /* null resets the pointer, including a reused hidden slot. */
        return 0;
    }
    if (!*slot && !(*slot = calloc(1, sizeof(**slot)))) return -1;
    if (!json_object_is_type(value, json_type_object)) {
        projection->response->bad_type = true;
        return 0;
    }
    projection->item = *slot;
    return br_json_each_member(encoded, datadog_item_member, projection);
}

static int datadog_response_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    datadog_response *response = user;
    bool organization = br_json_field_name(name, "included");
    if (!organization && !br_json_field_name(name, "data")) return 0;
    datadog_slots *slots = organization ? &response->included : &response->data;
    if (value && !json_object_is_type(value, json_type_array)) {
        response->bad_type = true;
        return 0;
    }
    size_t len = value ? json_object_array_length(value) : 0;
    if (!len) {
        datadog_slots_clear(slots); /* Both [] and whole-array null discard ALL slots. */
        return 0;
    }
    if (len > slots->initialized) {
        if (len > SIZE_MAX / sizeof(*slots->items)) return -1;
        datadog_item **items = realloc(slots->items, len * sizeof(*items));
        if (!items) return -1;
        memset(items + slots->initialized, 0, (len - slots->initialized) * sizeof(*items));
        slots->items = items;
        slots->initialized = len;
    }
    slots->len = len;
    /* Every nonempty duplicate array starts again at zero, reusing existing
     * nonnull objects. Shortening changes logical length, not initialized slots. */
    datadog_projection projection = {response, slots, NULL, organization};
    return br_json_each_element(encoded, datadog_element, &projection);
}

/* 0 includes root null/{}; 1 is an ordinary, unpublished typed/syntax/read
 * decode error; -1 is our resource/unsupported failure and MUST be fatal. */
static int datadog_decode(br_slice body, const char *body_error, datadog_response *response, char **error)
{
    br_json *root = NULL;
    size_t end = 0;
    char *cause = NULL;
    int rc = br_json_first_document(body, body_error, &root, &end, &cause);
    if (rc == 1 && !br_utf8_valid(body)) {
        /* json-c can reject invalid UTF-8 before reporting a document end.
         * An offset-preserving shadow locates that boundary without a JSON
         * scanner or whole-body rejection. Valid Unicode/NUL bytes are intact;
         * only the consumed ORIGINAL prefix below may trigger the guard. */
        unsigned char *shadow = malloc(body.len ? body.len : 1);
        if (!shadow) {
            json_object_put(root);
            free(cause);
            return datadog_fail(error, "cannot locate DatadogToken JSON document");
        }
        if (body.len) memcpy(shadow, body.data, body.len);
        for (size_t at = 0; at < body.len;) {
            uint32_t rune;
            size_t width = br_utf8_rune((br_slice){body.data + at, body.len - at}, &rune);
            if (width) at += width;
            else shadow[at++] = '?';
        }
        json_object_put(root);
        free(cause);
        rc = br_json_first_document((br_slice){shadow, body.len}, body_error, &root, &end, &cause);
        free(shadow);
    }
    free(cause);
    if (rc < 0) {
        json_object_put(root);
        return datadog_fail(error, "cannot decode DatadogToken response");
    }
    if (rc == 0) {
        br_slice document = {body.data, end};
        /* json-c does not supply Go's invalid-UTF-8 replacement semantics.
         * Guard ONLY the consumed document, never trailing data or valid NULs. */
        if (!br_utf8_valid(document)) {
            json_object_put(root);
            return datadog_fail(error, "unsupported: DatadogToken invalid UTF-8 in consumed JSON document");
        }
        if (root && !json_object_is_type(root, json_type_object)) response->bad_type = true;
        else if (root) rc = br_json_each_member(document, datadog_response_member, response);
    }
    json_object_put(root);
    if (rc < 0) return datadog_fail(error, "cannot project DatadogToken response");
    /* Continue visiting after known type errors so later overwrite cannot erase
     * them, all known fields are checked, and resource failures stay fatal.
     * These diagnostics are never published: allocate no Go-type cause. Unknown
     * huge numbers are ignored; this is NOT a float64-map projection. */
    return rc != 0 || response->bad_type ? 1 : 0;
}

static int datadog_put_text(br_json *object, const char *name, br_slice text)
{
    if (text.len > INT_MAX) return -1;
    br_json *value = json_object_new_string_len(text.data ? (const char *)text.data : "", (int)text.len);
    if (!value) return -1;
    if (json_object_object_add(object, name, value) == 0) return 0;
    json_object_put(value);
    return -1;
}

static int datadog_put_literal(br_json *object, const char *name, const char *text)
{
    return datadog_put_text(object, name, (br_slice){(const unsigned char *)text, strlen(text)});
}

static bool datadog_eligible(const datadog_item *item)
{
    return item->verified && !item->disabled && !item->service_account;
}

static int datadog_metadata(const datadog_response *response, br_result *result, char **error)
{
    if (response->data.len) {
        size_t count = 0, total = 0;
        br_slice selected = {0};
        for (size_t i = 0; i < response->data.len; ++i) {
            datadog_item *item = response->data.items[i];
            if (!item) return datadog_fail(error, "unsupported upstream panic: DatadogToken nil user in Data");
            if (!datadog_eligible(item)) continue;
            br_slice email = br_json_text(item->email);
            if (total > SIZE_MAX - email.len || (count && total + email.len > SIZE_MAX - 2))
                return datadog_fail(error, "DatadogToken user emails too large");
            if (!count) selected = email;
            total += email.len + (count++ ? 2 : 0);
        }
        if (!count) { selected = br_json_text(response->data.items[0]->email); total = selected.len; }
        if (total > INT_MAX) return datadog_fail(error, "DatadogToken user emails too large");
        int rc;
        if (count <= 1) {
            /* All users were checked above. Retained JSON refs keep the single
             * or fallback slice alive until put_text makes the final owned value. */
            rc = datadog_put_text(result->extra_data, "user_emails", selected);
        } else {
            unsigned char *emails = malloc(total);
            if (!emails) return datadog_fail(error, "cannot join DatadogToken user emails");
            size_t at = 0, written = 0;
            for (size_t i = 0; i < response->data.len; ++i) {
                datadog_item *item = response->data.items[i];
                if (!datadog_eligible(item)) continue;
                br_slice email = br_json_text(item->email);
                if (written++) { memcpy(emails + at, ", ", 2); at += 2; }
                if (email.len) memcpy(emails + at, email.data, email.len);
                at += email.len;
            }
            rc = datadog_put_text(result->extra_data, "user_emails", (br_slice){emails, total});
            free(emails);
        }
        if (rc != 0) return datadog_fail(error, "cannot store DatadogToken user emails");
    }
    for (size_t i = 0; i < response->included.len; ++i) {
        datadog_item *item = response->included.items[i];
        if (!item) return datadog_fail(error, "unsupported upstream panic: DatadogToken nil option in Included");
        br_slice type = br_json_text(item->type);
        if (type.len != 4 || memcmp(type.data, "orgs", 4) || item->disabled) continue;
        if (datadog_put_text(result->extra_data, "org_name", br_json_text(item->name)) != 0 ||
            datadog_put_text(result->extra_data, "org_url", br_json_text(item->url)) != 0)
            return datadog_fail(error, "cannot store DatadogToken organization");
        break; /* A later nil option is UNREACHED, not an upstream panic. */
    }
    return 0;
}

static int datadog_attempt(const br_scan_ctx *ctx, const char *api, const char *app, const char *base,
                            datadog_response *decoded, bool *present, bool *verified,
                            char **cause, char **error)
{
    *cause = NULL;
    *present = *verified = false;
    static const char path[] = "/api/v2/users";
    size_t len = strlen(base);
    if (len > SIZE_MAX - sizeof(path)) return datadog_fail(error, "DatadogToken URL too large");
    /* One necessary owned full URL. Literal concatenation preserves empty bases,
     * paths, trailing slashes and query/fragment bytes; no DC normalization. */
    char *url = malloc(len + sizeof(path));
    if (!url) return datadog_fail(error, "cannot create DatadogToken URL");
    memcpy(url, base, len);
    memcpy(url + len, path, sizeof(path));
    int rc = 0;
    if (!ctx) {
        *cause = strdup("net/http: nil Context");
        if (!*cause) rc = datadog_fail(error, "cannot create DatadogToken constructor cause");
    } else {
        const br_header headers[] = {{"Content-Type", "application/json"},
            {"Dd-Api-Key", api}, {"Dd-Application-Key", app}};
        const br_http_request request = {.method = "GET", .url = url,
            .headers = headers, .nheaders = 3, .profile = BR_HTTP_SANE, .detector_type = 39};
        br_http_response response = {0};
        /* The whole shared mixed setup/allocation/Do and body-error domains
         * remain partial. Apply ordinary Do/decode policy, never classify stage
         * by diagnostic text or claim full native resource-failure parity. */
        if (br_http_send(ctx, &request, &response, cause) != 0) {
            if (!*cause && !(*cause = strdup("HTTP transport failed")))
                rc = datadog_fail(error, "cannot create DatadogToken transport cause");
        } else if (response.status == 200) {
            *verified = true;
            int decoded_rc = datadog_decode(response.body, response.body_error, decoded, error);
            if (decoded_rc < 0) rc = -1;
            else *present = decoded_rc == 0; /* root null is PRESENT despite json-c NULL. */
        } else if (response.status != 401 && response.status != 403) {
            char message[80];
            int n = snprintf(message, sizeof(message), "unexpected status code: %d", response.status);
            if (n < 0 || (size_t)n >= sizeof(message))
                rc = datadog_fail(error, "cannot format DatadogToken status cause");
            else if (!(*cause = strdup(message)))
                rc = datadog_fail(error, "cannot create DatadogToken status cause");
        }
        /* Source drains then closes at verifyMatch return. Eager buffering and
         * ABI release cannot establish streaming/drain-close/native parity. */
        br_http_release(ctx, &response);
    }
    free(url); /* Borrowed through BOTH send and release, including failures. */
    return rc;
}

static int datadog_found_urls(br_captures *hosts, char **error)
{
    for (size_t i = 0; i < hosts->len; ++i) {
        size_t len = hosts->lengths[i];
        if (len > SIZE_MAX - sizeof("https://")) return datadog_fail(error, "DatadogToken host too large");
        char *url = malloc(len + sizeof("https://"));
        if (!url) return datadog_fail(error, "cannot prefix DatadogToken host");
        memcpy(url, "https://", 8);
        memcpy(url + 8, hosts->items[i], len + 1);
        free(hosts->items[i]);
        hosts->items[i] = url;
        hosts->lengths[i] = len + 8;
    }
    return 0;
}

static int datadog_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return datadog_fail(error, "invalid or uninitialized DatadogToken scan");
    const datadog_patterns *patterns = detector->state;
    if (!patterns->app || !patterns->api || !patterns->host)
        return datadog_fail(error, "uninitialized DatadogToken patterns");
    size_t original_len = out->len;
    br_captures apps = {0}, apis = {0}, hosts = {0};
    br_endpoint_list endpoints = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->app, input, &apps, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->api, input, &apis, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->host, input, &hosts, true, &owned_error);
    if (rc == 0) rc = datadog_found_urls(&hosts, &owned_error);
    if (rc == 0 && verify && apis.len && apps.len)
        rc = br_endpoints_collect(ctx ? ctx->endpoints : NULL, "https://api.datadoghq.com", &hosts, &endpoints, &owned_error);
    /* Found-map iteration order is unspecified upstream; first-source order
     * here is not a global map-iteration/output parity claim. No credential
     * uniqueness/equality filter, local span restriction or success consumption. */
    for (size_t a = 0; rc == 0 && a < apis.len; ++a) {
        for (size_t p = 0; rc == 0 && p < apps.len; ++p) {
            br_result result = {0};
            br_slice api = br_captures_at(&apis, a), app = br_captures_at(&apps, p);
            if (br_finding_pair_bytes(&result, detector->type, app, "app_key", api, "api_key", (br_slice){0}) != 0)
                rc = datadog_fail(&owned_error, "cannot create DatadogToken result");
            if (rc == 0) {
                result.extra_data = json_object_new_object();
                if (!result.extra_data || datadog_put_literal(result.extra_data, "Type", "Application+APIKey") != 0)
                    rc = datadog_fail(&owned_error, "cannot create DatadogToken Type metadata");
            }
            for (size_t e = 0; rc == 0 && verify && e < endpoints.len; ++e) {
                datadog_response decoded = {0};
                bool present = false, verified = false, stop = false;
                char *cause = NULL;
                rc = datadog_attempt(ctx, apis.items[a], apps.items[p], endpoints.items[e],
                                      &decoded, &present, &verified, &cause, &owned_error);
                if (rc == 0) {
                    result.verified = verified; /* EVERY attempt overwrites verification. */
                    const br_slice secrets[] = {api, app}; /* API THEN APP, exactly. */
                    if (br_result_set_verification_error(&result, cause, secrets, 2) != 0)
                        rc = datadog_fail(&owned_error, "cannot sanitize DatadogToken verification error");
                    /* NULL cause is deliberately STICKY: never clear an earlier error. */
                    if (rc == 0 && datadog_put_literal(result.secret_parts, "endpoint", endpoints.items[e]) != 0)
                        rc = datadog_fail(&owned_error, "cannot store DatadogToken endpoint");
                    if (rc == 0 && verified && present) {
                        rc = datadog_metadata(&decoded, &result, &owned_error);
                        stop = rc == 0;
                    }
                }
                datadog_response_clear(&decoded);
                free(cause);
                if (stop) break; /* {} and root null break, ordinary decode errors do not. */
            }
            if (rc == 0 && br_results_push(out, &result) != 0)
                rc = datadog_fail(&owned_error, "cannot append DatadogToken result");
            br_result_clear(&result);
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_endpoint_list_clear(&endpoints);
    br_captures_clear(&apps);
    br_captures_clear(&apis);
    br_captures_clear(&hosts);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static datadog_patterns datadog_compiled;
static const char *const datadog_keywords[] = {"datadog", "ddog-gov"};
static const char *const datadog_prefixes[] = {"datadog", "dd"};
static const br_detector datadog_detector = {
    .type = 39, .version = 0, .name = "DatadogToken", .custom_name = "",
    .description = "Datadog is a monitoring and security platform for cloud applications. Datadog API and Application keys can be used to access and manage data and configurations within Datadog.",
    .keywords = datadog_keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &datadog_compiled, .scan = datadog_scan,
    .validate_endpoints = br_endpoints_validate_configured,
    .cloud_endpoint = "https://api.datadoghq.com",
};

int br_datadogtoken_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return datadog_fail(error, "invalid DatadogToken detector output");
    *out = NULL;
    if (!datadog_compiled.app && br_regex_compile_prefixed(datadog_prefixes, 2,
        "\\b([a-zA-Z-0-9]{40})\\b", &datadog_compiled.app, error) != 0) return -1;
    if (!datadog_compiled.api && br_regex_compile_prefixed(datadog_prefixes, 2,
        "\\b([a-zA-Z-0-9]{32})\\b", &datadog_compiled.api, error) != 0) return -1;
    if (!datadog_compiled.host && br_regex_compile(
        "\\b(api(?:\\.[a-z0-9-]+)?\\.(?:datadoghq|ddog-gov)\\.(com|eu))\\b", &datadog_compiled.host, error) != 0) return -1;
    *out = &datadog_detector;
    return 0;
}
