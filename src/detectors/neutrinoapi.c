/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/neutrinoapi/neutrinoapi.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char neutrino_body[] =
    "--BriarNeutrinoBoundary\r\n"
    "Content-Disposition: form-data; name=\"url\"\r\n"
    "\r\n"
    "https://google.com\r\n"
    "--BriarNeutrinoBoundary--\r\n";
static const char neutrino_content_type[] =
    "multipart/form-data; boundary=BriarNeutrinoBoundary";

/* Same-TU tests inject these. Production leaves them zero. Field and copy
 * failures are the source continue domain; allocation is not. */
static int neutrino_field_fail;
static int neutrino_copy_fail;
static int neutrino_alloc_fail;

static int neutrino_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

/* 0 continue, 1 drop this product, -1 allocation fatal. */
static int form_step(int *flag, char **error)
{
    int rc = *flag;
    *flag = 0;
    if (!rc) return 0;
    if (rc < 0) return neutrino_fail(error, "cannot allocate NeutrinoApi request body");
    return 1;
}

static int build_body(unsigned char **body, size_t *len, char **error)
{
    int step = form_step(&neutrino_field_fail, error);
    if (step) return step;
    step = form_step(&neutrino_copy_fail, error);
    if (step) return step;
    /* Source ignores writer.Close. Still include its closing boundary, and do
     * not turn that write into a product drop. */
    if (neutrino_alloc_fail) {
        neutrino_alloc_fail = 0;
        return neutrino_fail(error, "cannot allocate NeutrinoApi request body");
    }
    unsigned char *owned = malloc(sizeof(neutrino_body) - 1);
    if (!owned) return neutrino_fail(error, "cannot allocate NeutrinoApi request body");
    memcpy(owned, neutrino_body, sizeof(neutrino_body) - 1);
    *body = owned;
    *len = sizeof(neutrino_body) - 1;
    return 0;
}

static int neutrino_verify(const br_scan_ctx *ctx, br_slice key, br_slice id,
                           br_result *result, char **error)
{
    unsigned char *body = NULL;
    size_t body_len = 0;
    int built = build_body(&body, &body_len, error);
    if (built) return built;
    /* NewRequestWithContext fails only for a nil context. That is a drop. */
    if (!ctx) {
        free(body);
        return 1;
    }
    char url[160];
    int url_len = snprintf(url, sizeof(url),
                           "https://neutrinoapi.net/url-info?user-id=%.*s&api-key=%.*s",
                           (int)id.len, id.data, (int)key.len, key.data);
    if (url_len < 0 || (size_t)url_len >= sizeof(url)) {
        free(body);
        return neutrino_fail(error, "cannot allocate NeutrinoApi request body");
    }
    const br_header headers[] = {{"Content-Type", neutrino_content_type}};
    const br_http_request request = {
        .method = "POST",
        .url = url,
        .headers = headers,
        .nheaders = 1,
        .body = {body, body_len},
        .profile = BR_HTTP_SANE,
        .timeout_ms = 0,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &send_error);
    /* One release for every attempted send, including a Do failure. Source
     * never reads the body, so body_error does not change the status rule. */
    bool verified = send_rc == 0 && response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(body);
    free(send_error);
    result->verified = verified;
    return 0;
}

typedef struct { br_regex *key, *id; } neutrino_patterns;
static neutrino_patterns neutrino_state;

static int neutrino_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    const neutrino_patterns *state = detector ? detector->state : NULL;
    if (!state || !state->key || !state->id || !out || (!input.data && input.len))
        return neutrino_fail(error, "invalid or uninitialized NeutrinoApi scan");
    size_t original = out->len;
    char *owned = NULL;
    br_captures keys = {0}, ids = {0};
    int rc = br_captures_find(state->key, input, &keys, false, &owned);
    if (!rc) rc = br_captures_find(state->id, input, &ids, false, &owned);
    if (rc && !owned) neutrino_fail(&owned, "cannot scan NeutrinoApi matches");
    /* Key order, then id order. No uniqueness map. The id is not published. */
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        for (size_t i = 0; !rc && i < ids.len; ++i) {
            br_result result = {0};
            br_slice key = br_captures_at(&keys, k);
            br_slice id = br_captures_at(&ids, i);
            if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
                rc = neutrino_fail(&owned, "cannot create NeutrinoApi result");
                break;
            }
            if (verify) {
                int outcome = neutrino_verify(ctx, key, id, &result, &owned);
                if (outcome < 0) {
                    br_result_clear(&result);
                    rc = -1;
                    break;
                }
                if (outcome > 0) {
                    br_result_clear(&result);
                    continue;
                }
            }
            if (br_results_push(out, &result) != 0)
                rc = neutrino_fail(&owned, "cannot append NeutrinoApi result");
            br_result_clear(&result);
        }
    }
    if (rc)
        while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&ids);
    if (error) *error = owned;
    else free(owned);
    return rc == 0 ? 0 : -1;
}

static const char *const neutrino_keywords[] = {"neutrinoapi"};
static const br_detector neutrino_detector = {
    .type = 623,
    .version = 0,
    .name = "NeutrinoApi",
    .custom_name = "",
    .description = "Neutrino API provides a variety of services including data tools, security tools, and more. Neutrino API keys can be used to access these services.",
    .keywords = neutrino_keywords,
    .nkeywords = 1,
    .max_secret_size = -1,
    .start_offset = -1,
    .max_credential_span = 1024,
    .state = &neutrino_state,
    .scan = neutrino_scan,
};

int br_neutrinoapi_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return neutrino_fail(error, "invalid NeutrinoApi detector output");
    *out = NULL;
    if (!neutrino_state.key &&
        br_regex_compile_prefixed(neutrino_keywords, 1, "\\b([a-zA-Z0-9]{48})\\b",
                                  &neutrino_state.key, error) != 0)
        return -1;
    if (!neutrino_state.id &&
        br_regex_compile_prefixed(neutrino_keywords, 1, "\\b([a-zA-Z0-9]{6,24})\\b",
                                  &neutrino_state.id, error) != 0) {
        br_regex_free(neutrino_state.key);
        neutrino_state.key = NULL;
        return -1;
    }
    *out = &neutrino_detector;
    return 0;
}
