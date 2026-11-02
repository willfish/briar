/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/opsgenie/opsgenie.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"
#include "json.h"
#include <json-c/json.h>

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *const opsgenie_keywords[] = {"opsgenie"};
static const char opsgenie_url[] = "https://api.opsgenie.com/v2/account";
static const char opsgenie_alert[] = "opsgenie.com/alert/detail/";
static const char opsgenie_data_type[] =
    "struct { Name string \"json:\\\"name\\\"\"; UserCount int \"json:\\\"userCount\\\"\"; "
    "Plan struct { Name string \"json:\\\"name\\\"\" } \"json:\\\"plan\\\"\" }";
static const char opsgenie_plan_type[] = "struct { Name string \"json:\\\"name\\\"\" }";

static int opsgenie_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static bool opsgenie_contains(br_slice haystack, const char *needle)
{
    size_t n = strlen(needle);
    if (n > haystack.len) return false;
    for (size_t i = 0; i + n <= haystack.len; ++i)
        if (!memcmp(haystack.data + i, needle, n)) return true;
    return false;
}

typedef struct {
    br_slice input;
    br_captures *keys;
    char *error;
} opsgenie_collect;

static int opsgenie_collect_match(void *user, const br_span *groups, size_t ngroups)
{
    opsgenie_collect *collect = user;
    if (ngroups < 2 || groups[0].begin == SIZE_MAX || groups[1].begin == SIZE_MAX ||
        groups[0].end < groups[0].begin || groups[1].end <= groups[1].begin ||
        groups[0].end > collect->input.len || groups[1].end > collect->input.len)
        return opsgenie_fail(&collect->error, "invalid Opsgenie capture");
    br_slice full = {collect->input.data + groups[0].begin, groups[0].end - groups[0].begin};
    br_slice key = {collect->input.data + groups[1].begin, groups[1].end - groups[1].begin};
    /* Alert-detail URLs are skipped before entropy and uniqueness. ASCII class. */
    if (opsgenie_contains(full, opsgenie_alert) || br_ascii_shannon_entropy(key) < 3) return 0;
    return br_captures_push(collect->keys, key, true, &collect->error);
}

static bool json_space(unsigned char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

typedef struct {
    char *name;
    char *plan;
    char *cause;
    size_t name_len, plan_len;
    bool ordinary;
} opsgenie_account;

static int copy_text(char **slot, size_t *len, br_slice text)
{
    if (text.len == SIZE_MAX) return -1;
    char *copy = malloc(text.len + 1);
    if (!copy) return -1;
    if (text.len) memcpy(copy, text.data, text.len);
    copy[text.len] = '\0';
    free(*slot);
    *slot = copy;
    if (len) *len = text.len;
    return 0;
}

static int type_error(opsgenie_account *account, br_json *value, const char *field, const char *expected)
{
    char *next = NULL;
    int rc = br_json_type_cause(value, field, expected, &next);
    if (rc != 0) { free(next); return rc; }
    if (!account->ordinary) {
        account->ordinary = true;
        account->cause = next;
    } else free(next);
    return 0;
}

static int take_string(opsgenie_account *account, br_json *value, char **slot, size_t *len,
                       const char *field)
{
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_string))
        return type_error(account, value, field, "string");
    return copy_text(slot, len, br_json_text(value));
}

static int take_int(opsgenie_account *account, br_json *value, br_slice encoded, const char *field)
{
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    size_t begin = 0, end = encoded.len;
    while (begin < end && json_space(encoded.data[begin])) ++begin;
    while (end > begin && json_space(encoded.data[end - 1])) --end;
    bool integer = begin < end;
    size_t digits = begin < end && encoded.data[begin] == '-' ? begin + 1 : begin;
    if (digits >= end) integer = false;
    for (size_t i = digits; integer && i < end; ++i)
        integer = encoded.data[i] >= '0' && encoded.data[i] <= '9';
    if (integer) {
        char token[32];
        if (end - begin < sizeof(token)) {
            memcpy(token, encoded.data + begin, end - begin);
            token[end - begin] = '\0';
            errno = 0;
            char *stopped = NULL;
            (void)strtoll(token, &stopped, 10);
            integer = !errno && stopped && *stopped == '\0';
        } else integer = false;
    }
    if (integer) return 0;
    if (!json_object_is_type(value, json_type_int) && !json_object_is_type(value, json_type_double))
        return type_error(account, value, field, "int");
    static const char prefix[] = "json: cannot unmarshal number ";
    size_t token_len = end - begin, field_len = strlen(field);
    size_t fixed = sizeof(prefix) + sizeof(" into Go struct field  of type int") - 1;
    if (token_len > SIZE_MAX - fixed || field_len > SIZE_MAX - fixed - token_len) return -1;
    size_t size = fixed + token_len + field_len;
    char *message = malloc(size);
    if (!message) return -1;
    memcpy(message, prefix, sizeof(prefix) - 1);
    memcpy(message + sizeof(prefix) - 1, encoded.data + begin, token_len);
    size_t at = sizeof(prefix) - 1 + token_len;
    int n = snprintf(message + at, size - at, " into Go struct field %s of type int", field);
    if (n < 0 || (size_t)n >= size - at) { free(message); return -1; }
    if (account->ordinary) { free(message); return 0; }
    account->ordinary = true;
    account->cause = message;
    return 0;
}

static int opsgenie_plan(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    opsgenie_account *account = user;
    if (!br_json_field_name(name, "name")) return 0;
    int rc = take_string(account, value, &account->plan, &account->plan_len, ".data.plan.name");
    return rc;
}

static int opsgenie_data(void *user, br_slice name, br_json *value, br_slice encoded)
{
    opsgenie_account *account = user;
    if (br_json_field_name(name, "name"))
        return take_string(account, value, &account->name, &account->name_len, ".data.name");
    if (br_json_field_name(name, "usercount"))
        return take_int(account, value, encoded, ".data.userCount");
    if (!br_json_field_name(name, "plan")) return 0;
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_object))
        return type_error(account, value, ".data.plan", opsgenie_plan_type);
    return br_json_each_member(encoded, opsgenie_plan, account);
}

static int opsgenie_root(void *user, br_slice name, br_json *value, br_slice encoded)
{
    opsgenie_account *account = user;
    if (!br_json_field_name(name, "data")) return 0;
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_object))
        return type_error(account, value, "accountResponse.data", opsgenie_data_type);
    return br_json_each_member(encoded, opsgenie_data, account);
}

static int opsgenie_decode(br_slice body, opsgenie_account *account)
{
    memset(account, 0, sizeof(*account));
    bool blank = true;
    for (size_t i = 0; i < body.len; ++i)
        if (!json_space(body.data[i])) { blank = false; break; }
    /* Decoder.Decode reports EOF. Unmarshal's end-of-input text is not used. */
    if (blank) {
        account->ordinary = true;
        account->cause = strdup("EOF");
        return account->cause ? 1 : -1;
    }
    br_json *root = NULL;
    size_t end = 0;
    int rc = br_json_first_document(body, NULL, &root, &end, &account->cause);
    if (rc < 0 || rc > 1) { json_object_put(root); return -1; }
    if (rc == 1) { json_object_put(root); account->ordinary = true; return 1; }
    if (json_object_is_type(root, json_type_null)) { json_object_put(root); return 0; }
    if (!json_object_is_type(root, json_type_object)) {
        rc = type_error(account, root, NULL, "opsgenie.accountResponse");
        json_object_put(root);
        return rc == 0 ? 1 : -1;
    }
    json_object_put(root);
    rc = br_json_each_member((br_slice){body.data, end}, opsgenie_root, account);
    if (rc != 0) return -1;
    return account->ordinary ? 1 : 0;
}

static int opsgenie_extra(br_result *result, const opsgenie_account *account, char **error)
{
    if (account->name_len > INT_MAX || account->plan_len > INT_MAX)
        return opsgenie_fail(error, "cannot create Opsgenie metadata");
    result->extra_data = json_object_new_object();
    br_json *account_text = json_object_new_string_len(account->name ? account->name : "", (int)account->name_len);
    br_json *plan_text = json_object_new_string_len(account->plan ? account->plan : "", (int)account->plan_len);
    if (!result->extra_data || !account_text || !plan_text ||
        json_object_object_add(result->extra_data, "account", account_text) != 0 ||
        json_object_object_add(result->extra_data, "plan", plan_text) != 0) {
        json_object_put(account_text);
        json_object_put(plan_text);
        return opsgenie_fail(error, "cannot create Opsgenie metadata");
    }
    return 0;
}

static int opsgenie_verify(const br_scan_ctx *ctx, const char *key, br_result *result, char **error)
{
    char authorization[48];
    memcpy(authorization, "GenieKey ", 9);
    memcpy(authorization + 9, key, 36);
    authorization[45] = '\0';
    br_slice secret = {(const unsigned char *)key, 36};
    if (!ctx)
        return br_result_set_verification_error(result, "net/http: nil Context", &secret, 1) == 0 ? 0 :
               opsgenie_fail(error, "cannot set Opsgenie verification error");
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = opsgenie_url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &transport_error);
    char *cause = NULL;
    bool error_present = false;
    opsgenie_account account = {0};
    int rc = 0;
    if (send_rc != 0) {
        error_present = true;
        cause = transport_error;
    }
    else if (response.status == 200) {
        rc = opsgenie_decode(response.body, &account);
        if (rc == 0) {
            result->verified = true;
            rc = opsgenie_extra(result, &account, error);
        } else if (rc > 0) {
            error_present = true;
            cause = account.cause;
            account.cause = NULL;
            rc = 0;
        }
    } else if (response.status == 403) result->verified = true;
    else if (response.status != 401) {
        char status_error[64];
        int n = snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error)) rc = opsgenie_fail(error, "cannot format Opsgenie status");
        else {
            cause = strdup(status_error);
            error_present = cause != NULL;
        }
        if (!rc && !cause) rc = -1;
    }
    if (!rc && error_present && br_result_set_verification_error(result, cause, &secret, 1) != 0)
        rc = -1;
    if (cause != transport_error) free(cause);
    free(transport_error);
    free(account.name);
    free(account.plan);
    free(account.cause);
    br_http_release(ctx, &response);
    return rc < 0 ? -1 : 0;
}

static int opsgenie_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return opsgenie_fail(error, "invalid or uninitialized Opsgenie scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    opsgenie_collect collect = {input, &keys, NULL};
    char *regex_error = NULL;
    int rc = br_regex_each(detector->state, input, opsgenie_collect_match, &collect, &regex_error);
    char *owned_error = collect.error ? collect.error : regex_error;
    if (collect.error) free(regex_error);
    if (rc != 0 && !owned_error) rc = opsgenie_fail(&owned_error, "cannot scan Opsgenie input");
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        if (key.len != 36)
            rc = opsgenie_fail(&owned_error, "invalid Opsgenie capture");
        else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = opsgenie_fail(&owned_error, "cannot create Opsgenie result");
        else if (verify)
            rc = opsgenie_verify(ctx, keys.items[i], &result, &owned_error);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = opsgenie_fail(&owned_error, "cannot append Opsgenie result");
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static br_detector opsgenie_detector = {
    .type = 875, .version = 0, .name = "Opsgenie", .custom_name = "",
    .description = "Opsgenie is an alerting and incident management platform. Opsgenie API keys can be used to interact with the Opsgenie API to manage alerts and incidents.",
    .keywords = opsgenie_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = opsgenie_scan,
};

int br_opsgenie_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return opsgenie_fail(error, "invalid Opsgenie detector output");
    *out = NULL;
    if (br_key_pattern_init(&opsgenie_detector,
                            "\\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b",
                            error) != 0)
        return -1;
    *out = &opsgenie_detector;
    return 0;
}
