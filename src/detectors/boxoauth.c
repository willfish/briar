/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/boxoauth. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <json-c/json.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *id, *secret, *subject, *label; } box_patterns;

#define MAX_SUBJECT_CANDIDATES 5
static const char unknown_client[] = "unauthorized_client: cannot verify incomplete Box credentials without an enterprise, user, or subject id found nearby";

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

typedef struct { br_slice input; bool strong; } label_context;

static int last_label(void *user, const br_span *groups, size_t ngroups)
{
    label_context *c = user;
    if (!ngroups || groups[0].end > c->input.len) return -1;
    br_slice label = {c->input.data + groups[0].begin, groups[0].end - groups[0].begin};
    /* enterprise[_id] and box_subject are strong; all other labels weak. */
    c->strong = label.len == 10 || label.len == 13 || label.len == 11;
    return 0;
}

typedef struct {
    br_slice input;
    const br_regex *label;
    br_captures all, strong;
    char *error;
} subject_context;

static int collect_subject(void *user, const br_span *groups, size_t ngroups)
{
    subject_context *c = user;
    if (ngroups < 2 || groups[1].begin == SIZE_MAX || groups[1].end > c->input.len)
        return fail(&c->error, "invalid BoxOauth subject capture");
    br_slice value = {c->input.data + groups[1].begin, groups[1].end - groups[1].begin};
    label_context label = {{c->input.data + groups[0].begin, groups[1].begin - groups[0].begin}, false};
    int rc = br_regex_each(c->label, label.input, last_label, &label, &c->error);
    if (!rc) rc = br_captures_push(&c->all, value, true, &c->error);
    if (!rc && label.strong) rc = br_captures_push(&c->strong, value, true, &c->error);
    return rc;
}

static int rank_subjects(const box_patterns *patterns, br_slice input, br_captures *out, char **error)
{
    subject_context c = {.input = input, .label = patterns->label};
    char *regex_error = NULL;
    int rc = br_regex_each(patterns->subject, input, collect_subject, &c, &regex_error);
    /* Preserve first occurrence within each group, including weak IDs later
     * promoted by a strong label. Never sort numeric strings lexically. */
    for (int group = 0; !rc && group < 2; ++group) {
        for (size_t i = 0; !rc && i < c.all.len; ++i) {
            br_slice value = br_captures_at(&c.all, i);
            bool strong = false;
            for (size_t j = 0; j < c.strong.len; ++j) {
                br_slice candidate = br_captures_at(&c.strong, j);
                if (value.len == candidate.len && !memcmp(value.data, candidate.data, value.len)) { strong = true; break; }
            }
            if (strong == (group == 0)) rc = br_captures_push(out, value, true, &c.error);
        }
    }
    br_captures_clear(&c.all);
    br_captures_clear(&c.strong);
    if (c.error) { free(regex_error); regex_error = c.error; }
    if (error) *error = regex_error;
    else free(regex_error);
    return rc;
}

static int verify_match(const br_scan_ctx *ctx, br_slice id, br_slice secret,
                         br_result *result, bool *probe_subjects, char **error)
{
    const char *cause = NULL;
    if (!ctx) {
        if (br_result_set_verification_error(result, "net/http: nil Context", &id, 1))
            return fail(error, "cannot store BoxOauth verification error");
        return 0;
    }
    char payload[160];
    int n = snprintf(payload, sizeof(payload),
        "grant_type=client_credentials&client_id=%.*s&client_secret=%.*s",
        (int)id.len, (const char *)id.data, (int)secret.len, (const char *)secret.data);
    if (n < 0 || (size_t)n >= sizeof(payload)) return fail(error, "cannot construct BoxOauth payload");
    /* Source assigns this lowercase map key directly; subject probes use Set. */
    const br_header headers[] = {{"content-type", "application/x-www-form-urlencoded"}};
    const br_http_request request = {
        .method = "POST", .url = "https://api.box.com/oauth2/token",
        .headers = headers, .nheaders = 1, .body = {(const unsigned char *)payload, (size_t)n},
        .profile = BR_HTTP_SANE, .detector_type = 1003,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80];
    if (br_http_send(ctx, &request, &response, &transport_error)) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else if (response.status == 400) {
        if (response.body_error) cause = response.body_error;
        else {
            struct json_tokener *tok = json_tokener_new();
            if (!tok) { br_http_release(ctx, &response); return fail(error, "cannot allocate BoxOauth error parser"); }
            json_tokener_set_flags(tok, JSON_TOKENER_STRICT);
            br_json *body = response.body.len <= INT_MAX ?
                json_tokener_parse_ex(tok, response.body.data ? (const char *)response.body.data : "", (int)response.body.len) : NULL;
            br_json *code = NULL;
            bool parsed = body && json_tokener_get_error(tok) == json_tokener_success &&
                          json_object_is_type(body, json_type_object);
            size_t end = json_tokener_get_parse_end(tok);
            for (size_t i = end; parsed && i < response.body.len; ++i) {
                unsigned char c = response.body.data[i];
                if (c != ' ' && c != '\t' && c != '\r' && c != '\n') parsed = false;
            }
            bool has_code = parsed && json_object_object_get_ex(body, "error", &code);
            if (!parsed || (has_code && !json_object_is_type(code, json_type_string)))
                cause = "failed to decode token error response";
            else if (has_code && json_object_get_string_len(code) == (int)sizeof("unauthorized_client") - 1 &&
                     !memcmp(json_object_get_string(code), "unauthorized_client", sizeof("unauthorized_client") - 1)) {
                cause = unknown_client;
                *probe_subjects = true;
            } else if (!(has_code && json_object_get_string_len(code) == (int)sizeof("invalid_client") - 1 &&
                         !memcmp(json_object_get_string(code), "invalid_client", sizeof("invalid_client") - 1)))
                cause = "unexpected token error"; /* Never echo arbitrary response text. */
            json_object_put(body);
            json_tokener_free(tok);
        }
    } else {
        snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        cause = status_error;
    }
    const br_slice credentials[] = {id, secret};
    int rc = br_result_set_verification_error(result, cause, credentials, 2);
    br_http_release(ctx, &response); /* Must finish BEFORE subject token probes. */
    free(transport_error);
    return rc ? fail(error, "cannot store BoxOauth verification error") : 0;
}

static bool verify_subject_id(const br_scan_ctx *ctx, br_slice id, br_slice secret, br_slice subject)
{
    static const char *const types[] = {"enterprise", "user"};
    for (size_t t = 0; t < 2; ++t) {
        /* Source suppresses constructor errors as well as every Client.Do error. */
        if (!ctx) continue;
        char payload[256];
        int n = snprintf(payload, sizeof(payload),
            "grant_type=client_credentials&client_id=%.*s&client_secret=%.*s&box_subject_type=%s&box_subject_id=%.*s",
            (int)id.len, (const char *)id.data, (int)secret.len, (const char *)secret.data,
            types[t], (int)subject.len, (const char *)subject.data);
        /* Captures are bounded ASCII (32/32/20), so this is only a safe guard. */
        if (n < 0 || (size_t)n >= sizeof(payload)) continue;
        const br_header headers[] = {{"Content-Type", "application/x-www-form-urlencoded"}};
        const br_http_request request = {
            .method = "POST", .url = "https://api.box.com/oauth2/token",
            .headers = headers, .nheaders = 1, .body = {(const unsigned char *)payload, (size_t)n},
            .profile = BR_HTTP_SANE, .detector_type = 1003,
        };
        br_http_response response = {0};
        char *transport_error = NULL;
        int rc = br_http_send(ctx, &request, &response, &transport_error);
        int status = response.status;
        br_http_release(ctx, &response); /* Source closes even a successful probe before returning. */
        free(transport_error);
        if (!rc && status == 200) return true; /* Ignore body/drain/close errors. */
    }
    return false;
}

static int add_subject(br_result *result, br_slice subject, char **error)
{
    br_json *value = json_object_new_string_len((const char *)subject.data, (int)subject.len);
    if (!value) return fail(error, "cannot allocate BoxOauth subject ID");
    if (json_object_object_add(result->secret_parts, "subject_id", value)) {
        json_object_put(value);
        return fail(error, "cannot store BoxOauth subject ID");
    }
    return 0;
}

static int scan_boxoauth(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized BoxOauth scan");
    const box_patterns *patterns = detector->state;
    if (!patterns->id || !patterns->secret || !patterns->subject || !patterns->label)
        return fail(error, "uninitialized BoxOauth patterns");
    br_captures ids = {0}, secrets = {0}, subjects = {0};
    char *owned_error = NULL;
    size_t original_len = out->len;
    int rc = br_captures_find(patterns->id, input, &ids, true, &owned_error);
    if (!rc) rc = br_captures_find(patterns->secret, input, &secrets, true, &owned_error);
    if (!rc) rc = rank_subjects(patterns, input, &subjects, &owned_error);
    /* Source maps are unordered; first-seen traversal is one allowed order.
     * Secrets are never consumed globally: each later ID can reuse them. */
    for (size_t i = 0; !rc && i < ids.len; ++i) {
        br_slice id = br_captures_at(&ids, i);
        for (size_t s = 0; !rc && s < secrets.len; ++s) {
            br_slice secret = br_captures_at(&secrets, s);
            if (id.len == secret.len && !memcmp(id.data, secret.data, id.len)) continue;
            br_result result = {0};
            if (br_finding_pair_bytes(&result, detector->type, id, "client_id", secret, "client_secret", (br_slice){0}))
                rc = fail(&owned_error, "cannot create BoxOauth result");
            bool probe_subjects = false;
            if (!rc && verify) rc = verify_match(ctx, id, secret, &result, &probe_subjects, &owned_error);
            if (!rc && probe_subjects) {
                size_t tried = subjects.len < MAX_SUBJECT_CANDIDATES ? subjects.len : MAX_SUBJECT_CANDIDATES;
                for (size_t sub = 0; sub < tried; ++sub) {
                    br_slice subject = br_captures_at(&subjects, sub);
                    if (verify_subject_id(ctx, id, secret, subject)) {
                        rc = add_subject(&result, subject, &owned_error);
                        if (!rc) {
                            free(result.verification_error);
                            result.verification_error = NULL;
                            result.verified = true;
                        }
                        break;
                    }
                }
                if (!rc && !result.verified && subjects.len) {
                    char message[384];
                    if (subjects.len > tried)
                        snprintf(message, sizeof(message), "%s; no nearby subject ID was accepted (tried %zu of %zu subject ID candidates)", unknown_client, tried, subjects.len);
                    else
                        snprintf(message, sizeof(message), "%s; no nearby subject ID was accepted", unknown_client);
                    const br_slice credentials[] = {id, secret};
                    if (br_result_set_verification_error(&result, message, credentials, 2))
                        rc = fail(&owned_error, "cannot store BoxOauth verification error");
                }
            }
            bool verified = result.verified;
            if (!rc && br_results_push(out, &result)) rc = fail(&owned_error, "cannot append BoxOauth result");
            br_result_clear(&result);
            if (verified) break; /* Only a successful subject ends the secret loop. */
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&ids);
    br_captures_clear(&secrets);
    br_captures_clear(&subjects);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static box_patterns patterns;
static const char *const keywords[] = {"box"};
static const br_detector boxoauth = {
    .type = 1003, .version = 0, .name = "BoxOauth", .custom_name = "",
    .description = "Box is a service offering various service for secure collaboration, content "
                   "management, and workflow. Box Oauth credentials can be used to access and interact with this data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .state = &patterns, .scan = scan_boxoauth,
};

int br_boxoauth_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid BoxOauth detector output");
    *out = NULL;
    static const char *const id_prefixes[] = {"id"};
    static const char *const secret_prefixes[] = {"secret"};
    static const char *const subject_prefixes[] = {"enterprise", "enterprise_id", "user", "user_id", "subject", "box_subject"};
    if (!patterns.id && br_regex_compile_prefixed(id_prefixes, 1, "\\b([a-zA-Z0-9]{32})\\b", &patterns.id, error)) return -1;
    if (!patterns.secret && br_regex_compile_prefixed(secret_prefixes, 1, "\\b([a-zA-Z0-9]{32})\\b", &patterns.secret, error)) return -1;
    if (!patterns.subject && br_regex_compile_prefixed(subject_prefixes, 6, "\\b([0-9]{6,20})\\b", &patterns.subject, error)) return -1;
    if (!patterns.label && br_regex_compile("(?i)enterprise_id|enterprise|box_subject|user_id|user|subject", &patterns.label, error)) return -1;
    *out = &boxoauth;
    return 0;
}
