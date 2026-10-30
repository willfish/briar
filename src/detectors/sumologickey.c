/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/sumologickey/sumologickey.go.
 * Unique matches keep first-seen order; Go map iteration is unstable.
 * Embedded endpoint setters are reachable but FromData does not consult them. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char cloud_endpoint[] = "api.sumologic.com";
static br_regex *id_re, *key_re, *url_re;
static char **configured;
static size_t nconfigured;
static char *setter_cloud;
static bool use_cloud, use_found;

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

int br_sumologickey_set_configured_endpoints(const char *const *endpoints, size_t count, char **error)
{
    if (error) *error = NULL;
    if (!count) return fail(error, "at least one endpoint required");
    if (!endpoints) return fail(error, "invalid SumoLogicKey endpoints");
    char **next = calloc(count, sizeof(*next));
    if (!next) return fail(error, "cannot store SumoLogicKey endpoints");
    size_t n = 0;
    for (size_t i = 0; i < count; ++i) {
        if (!endpoints[i]) {
            for (size_t j = 0; j < n; ++j) free(next[j]);
            free(next);
            return fail(error, "invalid SumoLogicKey endpoint");
        }
        bool seen = false;
        for (size_t j = 0; j < n; ++j) seen |= !strcmp(next[j], endpoints[i]);
        if (seen) continue;
        next[n] = strdup(endpoints[i]);
        if (!next[n]) {
            for (size_t j = 0; j < n; ++j) free(next[j]);
            free(next);
            return fail(error, "cannot store SumoLogicKey endpoint");
        }
        ++n;
    }
    for (size_t i = 0; i < nconfigured; ++i) free(configured[i]);
    free(configured);
    configured = next;
    nconfigured = n;
    return 0;
}

void br_sumologickey_set_cloud_endpoint(const char *url)
{
    free(setter_cloud);
    setter_cloud = url ? strdup(url) : NULL;
}

void br_sumologickey_use_cloud_endpoint(bool enabled) { use_cloud = enabled; }
void br_sumologickey_use_found_endpoints(bool enabled) { use_found = enabled; }
size_t br_sumologickey_configured_count(void) { return nconfigured; }
const char *br_sumologickey_configured_at(size_t index)
{
    return index < nconfigured ? configured[index] : NULL;
}

typedef struct { char **items; size_t len, cap; } strings;

static void strings_clear(strings *values)
{
    if (!values) return;
    for (size_t i = 0; i < values->len; ++i) free(values->items[i]);
    free(values->items);
    *values = (strings){0};
}

static int strings_add(strings *values, const char *text, size_t len, char **error)
{
    for (size_t i = 0; i < values->len; ++i)
        if (strlen(values->items[i]) == len && !memcmp(values->items[i], text, len)) return 0;
    if (values->len == values->cap) {
        size_t cap = values->cap ? values->cap * 2 : 4;
        char **items = realloc(values->items, cap * sizeof(*items));
        if (!items) return fail(error, "cannot retain SumoLogicKey match");
        values->items = items;
        values->cap = cap;
    }
    char *copy = malloc(len + 1);
    if (!copy) return fail(error, "cannot retain SumoLogicKey match");
    memcpy(copy, text, len);
    copy[len] = '\0';
    values->items[values->len++] = copy;
    return 0;
}

typedef struct { strings *out; const unsigned char *data; int group; char *error; } collect_box;

static int take_group(void *user, const br_span *groups, size_t ngroups)
{
    collect_box *box = user;
    if ((size_t)box->group >= ngroups || groups[box->group].begin == SIZE_MAX ||
        groups[box->group].end < groups[box->group].begin)
        return fail(&box->error, "invalid SumoLogicKey capture");
    return strings_add(box->out, (const char *)box->data + groups[box->group].begin,
                       groups[box->group].end - groups[box->group].begin, &box->error);
}

static int collect(const br_regex *re, br_slice input, int group, strings *out, char **error)
{
    collect_box box = {out, input.data, group, NULL};
    int rc = br_regex_each(re, input, take_group, &box, error);
    if (box.error) {
        if (error && !*error) *error = box.error;
        else free(box.error);
        return -1;
    }
    return rc;
}

static int raw_v2(br_result *result, const char *id, const char *key, const char *endpoint, char **error)
{
    if (!id || !*id) return 0;
    size_t n = sizeof("{\"accessId\":\"\",\"accessKey\":\"\"}") + strlen(id) + strlen(key);
    if (endpoint && *endpoint) n += sizeof(",\"url\":\"\"") + strlen(endpoint);
    char *text = malloc(n);
    if (!text) return fail(error, "cannot format SumoLogicKey raw value");
    size_t at = 0;
    int wrote = snprintf(text, n, "{\"accessId\":\"%s\",\"accessKey\":\"%s\"", id, key);
    if (wrote < 0 || (size_t)wrote >= n) {
        free(text);
        return fail(error, "cannot format SumoLogicKey raw value");
    }
    at = (size_t)wrote;
    if (endpoint && *endpoint) {
        wrote = snprintf(text + at, n - at, ",\"url\":\"%s\"", endpoint);
        if (wrote < 0 || (size_t)wrote >= n - at) {
            free(text);
            return fail(error, "cannot format SumoLogicKey raw value");
        }
        at += (size_t)wrote;
    }
    if (at + 1 >= n) {
        free(text);
        return fail(error, "cannot format SumoLogicKey raw value");
    }
    text[at++] = '}';
    text[at] = '\0';
    result->raw_v2.data = (unsigned char *)text;
    result->raw_v2.len = at;
    return 0;
}

static int try_verify(const br_scan_ctx *ctx, const char *endpoint, const char *id, const char *key,
                      bool *verified, char **error)
{
    *verified = false;
    char url[160];
    int n = snprintf(url, sizeof(url), "https://%s/api/v1/users", endpoint);
    if (n < 0 || (size_t)n >= sizeof(url)) return fail(error, "cannot format SumoLogicKey URL");
    if (!ctx) return 0;
    char *authorization = NULL;
    if (br_http_basic_auth((br_slice){(const unsigned char *)id, strlen(id)},
                           (br_slice){(const unsigned char *)key, strlen(key)},
                           &authorization, error) != 0)
        return -1;
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .timeout_ms = 5000, .detector_type = 123,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int rc = br_http_send(ctx, &request, &response, &transport_error);
    /* Non-200 outcomes, including 401 and transport errors, are discarded. */
    if (!rc && response.status == 200) *verified = true;
    br_http_release(ctx, &response);
    free(transport_error);
    free(authorization);
    return 0;
}

static int finish_result(br_result *result, const char *id, const char *key, const char *endpoint,
                         bool verified, char **error)
{
    if (br_finding_key(result, 123, key, "key") != 0) return fail(error, "cannot create SumoLogicKey result");
    result->verified = verified;
    if (raw_v2(result, id, key, endpoint, error) != 0) return -1;
    if (!(result->extra_data = json_object_new_object())) return fail(error, "cannot create SumoLogicKey metadata");
    br_json *guide = json_object_new_string("https://howtorotate.com/docs/tutorials/sumologic/");
    if (!guide || json_object_object_add(result->extra_data, "rotation_guide", guide) != 0) {
        json_object_put(guide);
        return fail(error, "cannot create SumoLogicKey metadata");
    }
    return 0;
}

static int scan_sumo(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                     br_slice input, br_results *out, char **error)
{
    (void)detector;
    (void)setter_cloud;
    (void)use_cloud;
    (void)use_found;
    if (error) *error = NULL;
    if (!id_re || !key_re || !url_re || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized SumoLogicKey scan");
    size_t original_len = out->len;
    strings ids = {0}, keys = {0}, endpoints = {0};
    char *owned_error = NULL;
    int rc = collect(id_re, input, 1, &ids, &owned_error);
    if (!rc) rc = collect(key_re, input, 1, &keys, &owned_error);
    if (!rc) rc = collect(url_re, input, 0, &endpoints, &owned_error);
    if (!rc && !endpoints.len) rc = strings_add(&endpoints, cloud_endpoint, sizeof(cloud_endpoint) - 1, &owned_error);
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        const char *chosen_id = NULL, *chosen_endpoint = NULL;
        bool verified = false;
        for (size_t i = 0; !rc && verify && i < ids.len; ++i) {
            for (size_t e = 0; !rc && e < endpoints.len; ++e) {
                bool ok = false;
                if (try_verify(ctx, endpoints.items[e], ids.items[i], keys.items[k], &ok, &owned_error) != 0)
                    rc = -1;
                else if (ok) {
                    verified = true;
                    chosen_id = ids.items[i];
                    chosen_endpoint = endpoints.items[e];
                }
            }
        }
        if (!verified) {
            chosen_id = ids.len == 1 ? ids.items[0] : NULL;
            chosen_endpoint = ids.len && endpoints.len == 1 && strcmp(endpoints.items[0], cloud_endpoint)
                ? endpoints.items[0] : NULL;
        }
        br_result result = {0};
        if (!rc && (finish_result(&result, chosen_id, keys.items[k], chosen_endpoint, verified, &owned_error) != 0 ||
                    br_results_push(out, &result) != 0)) {
            if (!owned_error) fail(&owned_error, "cannot append SumoLogicKey result");
            br_result_clear(&result);
            rc = -1;
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    strings_clear(&ids);
    strings_clear(&keys);
    strings_clear(&endpoints);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"sumo", "accessId", "accessKey"};
static br_detector sumo = {
    .type = 123, .version = 0, .name = "SumoLogicKey", .custom_name = "",
    .description = "Sumo Logic is a cloud-based machine data analytics service. Sumo Logic keys can be used to access and manage data within the Sumo Logic platform.",
    .keywords = keywords, .nkeywords = 3,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = scan_sumo, .cloud_endpoint = cloud_endpoint,
};

int br_sumologickey_init(const br_detector **out, char **error)
{
    static const char *const id_prefix[] = {"sumo", "accessId"};
    static const char *const key_prefix[] = {"sumo", "accessKey"};
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid SumoLogicKey detector output");
    *out = NULL;
    if (!id_re && br_regex_compile_prefixed(id_prefix, 2, "\\b(su[A-Za-z0-9]{12})\\b", &id_re, error) != 0)
        return -1;
    if (!key_re && br_regex_compile_prefixed(key_prefix, 2, "\\b([A-Za-z0-9]{64})\\b", &key_re, error) != 0)
        return -1;
    if (!url_re && br_regex_compile("(?i)api\\.(?:au|ca|de|eu|fed|jp|kr|in|us2)\\.sumologic\\.com", &url_re, error) != 0)
        return -1;
    sumo.state = key_re;
    *out = &sumo;
    return 0;
}
