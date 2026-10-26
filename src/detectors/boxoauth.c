/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/boxoauth. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *id, *secret, *subject; } box_patterns;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void sort_subjects(br_captures *subjects)
{
    /* ASCII decimal strings sort lexically, not numerically. Swap lengths too;
     * leading zeros and the byte-aware capture ownership remain unchanged. */
    for (size_t i = 1; i < subjects->len; ++i) {
        size_t j = i;
        while (j && strcmp(subjects->items[j - 1], subjects->items[j]) > 0) {
            char *text = subjects->items[j - 1];
            size_t len = subjects->lengths[j - 1];
            subjects->items[j - 1] = subjects->items[j];
            subjects->lengths[j - 1] = subjects->lengths[j];
            subjects->items[j] = text;
            subjects->lengths[j] = len;
            --j;
        }
    }
}

static int verify_match(const br_scan_ctx *ctx, br_slice id, br_slice secret,
                         br_result *result, char **error)
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
            static const unsigned char valid[] = "unauthorized_client";
            static const unsigned char invalid[] = "invalid_client";
            /* Source uses byte substrings, in this priority, not JSON fields. */
            if (br_slice_find(response.body, (br_slice){valid, sizeof(valid) - 1}, 0) != SIZE_MAX)
                result->verified = true;
            else if (br_slice_find(response.body, (br_slice){invalid, sizeof(invalid) - 1}, 0) == SIZE_MAX)
                cause = "response body missing expected keyword";
        }
    } else {
        snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        cause = status_error;
    }
    /* Only the client ID is supplied upstream; the secret remains unredacted. */
    int rc = br_result_set_verification_error(result, cause, &id, 1);
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
    if (!patterns->id || !patterns->secret || !patterns->subject)
        return fail(error, "uninitialized BoxOauth patterns");
    br_captures ids = {0}, secrets = {0}, subjects = {0};
    char *owned_error = NULL;
    size_t original_len = out->len;
    int rc = br_captures_find(patterns->id, input, &ids, true, &owned_error);
    if (!rc) rc = br_captures_find(patterns->secret, input, &secrets, true, &owned_error);
    if (!rc) rc = br_captures_find(patterns->subject, input, &subjects, true, &owned_error);
    if (!rc) sort_subjects(&subjects);
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
            if (!rc && verify) rc = verify_match(ctx, id, secret, &result, &owned_error);
            if (!rc && result.verified) {
                for (size_t sub = 0; sub < subjects.len; ++sub) {
                    br_slice subject = br_captures_at(&subjects, sub);
                    if (verify_subject_id(ctx, id, secret, subject)) {
                        rc = add_subject(&result, subject, &owned_error);
                        break;
                    }
                }
            }
            bool verified = result.verified;
            if (!rc && br_results_push(out, &result)) rc = fail(&owned_error, "cannot append BoxOauth result");
            br_result_clear(&result);
            if (verified) break; /* Inner secret loop ONLY, even if every subject failed. */
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
    *out = &boxoauth;
    return 0;
}
