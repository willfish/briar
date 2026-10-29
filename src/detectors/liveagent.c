/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/liveagent/liveagent.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"

#include <json-c/json.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *domain; } liveagent_state;
typedef struct {
    char *message;
    size_t len;
    char *cause;
    bool ordinary_error;
} liveagent_message;

static int liveagent_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static const char liveagent_privilege[] = "You do not have sufficient privileges";

/* Unknown members stay ignored. JSON null is a no-op, including after a valid
 * duplicate string. Ordinary error presence is a flag, not a non-NULL cause.
 * Every reached non-null non-string calls the type helper. The first ordinary
 * diagnostic is kept, even when that diagnostic is NULL; later diagnostics are
 * freed. A helper nonzero, including +1 after a saved error, is fatal. Later
 * strings are still copied and cannot clear the error. */
static int read_message(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    liveagent_message *message = user;
    if (!br_json_field_name(name, "message")) return 0;
    if (!value || json_object_is_type(value, json_type_null)) return 0;
    if (!json_object_is_type(value, json_type_string)) {
        char *typed = NULL;
        if (br_json_type_cause(value, "response.message", "string", &typed) != 0) {
            free(typed);
            return -1;
        }
        if (!message->ordinary_error) {
            message->ordinary_error = true;
            message->cause = typed;
        } else free(typed);
        return 0;
    }
    br_slice text = br_json_text(value);
    char *copy = malloc(text.len + 1);
    if (!copy) return -1;
    if (text.len) memcpy(copy, text.data, text.len);
    copy[text.len] = '\0';
    free(message->message);
    message->message = copy;
    message->len = text.len;
    return 0;
}

/* 1 drops after a checked setter. -2 is setter +1. */
static int call_setter(br_result *result, const char *cause, br_slice key)
{
    /* NULL cause is a checked no-op. Setter +1 is fatal even when the result
     * would be dropped. Do not invent a fallback cause. */
    int stored = br_result_set_verification_error(result, cause, &key, 1);
    return stored == 0 ? 1 : -2;
}

/* 0 keeps the pair, 1 skips it after a checked setter, -1 is fatal. The
 * successful response is already scan-deferred before this decision. */
static int decode_forbidden(const br_http_response *response, br_slice key, br_result *result)
{
    br_json *root = NULL;
    size_t end = 0;
    char *cause = NULL;
    int rc = br_json_first_document(response->body, response->body_error, &root, &end, &cause);
    if (rc < 0 || rc > 1) {
        /* Only exactly +1 is an ordinary document error. +2 and resource
         * failure are fatal and must not become a NULL-setter drop. */
        json_object_put(root);
        free(cause);
        return -1;
    }
    if (rc == 1) {
        json_object_put(root);
        int drop = call_setter(result, cause, key);
        free(cause);
        return drop;
    }
    /* Root null decodes a zero response. It is not a liveagent.response error. */
    if (!root) return 0;
    if (!json_object_is_type(root, json_type_object)) {
        if (br_json_type_cause(root, NULL, "liveagent.response", &cause) != 0) {
            json_object_put(root);
            return -1;
        }
        json_object_put(root);
        int drop = call_setter(result, cause, key);
        free(cause);
        return drop;
    }
    liveagent_message message = {0};
    int visit = br_json_each_member((br_slice){response->body.data, end}, read_message, &message);
    json_object_put(root);
    if (visit != 0) {
        free(message.message);
        free(message.cause);
        return -1;
    }
    if (message.ordinary_error) {
        int drop = call_setter(result, message.cause, key);
        free(message.cause);
        free(message.message);
        return drop;
    }
    result->verified = message.message && message.len == sizeof(liveagent_privilege) - 1 &&
        memcmp(message.message, liveagent_privilege, sizeof(liveagent_privilege) - 1) == 0;
    free(message.message);
    return 0;
}

/* Successful Do closes are scan-deferred, including a 403 whose decode later
 * drops the candidate. The stack header array dies at send return. */
typedef struct liveagent_pending liveagent_pending;
struct liveagent_pending {
    liveagent_pending *next;
    br_http_response response;
    char *url;
};

static int liveagent_retain(liveagent_pending **pending, const br_http_response *response, char *url)
{
    liveagent_pending *item = malloc(sizeof(*item));
    if (!item) return -1;
    item->next = *pending;
    item->response = *response;
    item->url = url;
    *pending = item;
    return 0;
}

static void liveagent_release_held(const br_scan_ctx *ctx, liveagent_pending *pending)
{
    while (pending) {
        liveagent_pending *next = pending->next;
        br_http_release(ctx, &pending->response);
        free(pending->url);
        free(pending);
        pending = next;
    }
}

/* Finding and ExtraData already exist. The complete URL is owned before the
 * nil-context drop. Header construction follows a successful constructor.
 * 1 drops this pair. 0 publishes it. -1 is fatal. */
static int liveagent_verify(const br_scan_ctx *ctx, const char *key, br_slice key_bytes,
                            br_slice domain, br_result *result, liveagent_pending **pending,
                            char **error)
{
    if (domain.len > SIZE_MAX - sizeof("/api/v3/agents"))
        return liveagent_fail(error, "LiveAgent URL too long");
    char *url = malloc(domain.len + sizeof("/api/v3/agents"));
    if (!url) return liveagent_fail(error, "cannot allocate LiveAgent URL");
    memcpy(url, domain.data, domain.len);
    memcpy(url + domain.len, "/api/v3/agents", sizeof("/api/v3/agents"));
    if (!ctx) {
        free(url);
        return 1;
    }
    /* Source Header.Add("apikey") canonicalizes to Apikey. Do not change shared
     * HTTP normalization. The value is the raw capture, which outlives release. */
    const br_header headers[] = {{"Apikey", key}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_DETECTOR_PUBLIC, .timeout_ms = 0,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int send_rc = br_http_send(ctx, &request, &response, &send_error);
    free(send_error);
    if (send_rc != 0) {
        br_http_release(ctx, &response);
        free(url);
        return 0;
    }
    if (liveagent_retain(pending, &response, url) != 0) {
        br_http_release(ctx, &response);
        free(url);
        return liveagent_fail(error, "cannot retain LiveAgent response for release");
    }
    /* 2xx does not read the body, so body_error cannot suppress it. Other
     * statuses except 403 do not decode or call a setter. */
    if (response.status >= 200 && response.status < 300) {
        result->verified = true;
        return 0;
    }
    if (response.status != 403) return 0;
    int decoded = decode_forbidden(&response, key_bytes, result);
    if (decoded == -2) return liveagent_fail(error, "cannot record LiveAgent verification error");
    if (decoded < 0) return liveagent_fail(error, "cannot decode LiveAgent response");
    return decoded;
}

static int add_domain(br_result *result, br_slice domain)
{
    if (domain.len > INT_MAX) return -1;
    result->extra_data = json_object_new_object();
    if (!result->extra_data) return -1;
    br_json *value = json_object_new_string_len((const char *)domain.data, (int)domain.len);
    if (!value) return -1;
    if (json_object_object_add(result->extra_data, "domain", value) == 0) return 0;
    json_object_put(value);
    return -1;
}

static int liveagent_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    const liveagent_state *state = detector ? detector->state : NULL;
    if (!detector || !state || !state->key || !state->domain || !out || (!input.data && input.len))
        return liveagent_fail(error, "invalid or uninitialized LiveAgent scan");
    size_t original_len = out->len;
    br_captures domains = {0}, keys = {0};
    liveagent_pending *pending = NULL;
    char *owned_error = NULL;
    int rc = br_captures_find(state->domain, input, &domains, false, &owned_error);
    if (rc == 0) rc = br_captures_find(state->key, input, &keys, false, &owned_error);
    /* max_credential_span is an engine hint, not a scan cap. Empty side yields nothing. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        for (size_t d = 0; rc == 0 && d < domains.len; ++d) {
            br_result result = {0};
            br_slice key = br_captures_at(&keys, k);
            br_slice domain = br_captures_at(&domains, d);
            bool keep = true;
            /* TrimSpace is a no-op. Finding and ExtraData precede URL assembly. */
            if (key.len != 32)
                rc = liveagent_fail(&owned_error, "invalid LiveAgent capture");
            else if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
                rc = liveagent_fail(&owned_error, "cannot create LiveAgent result");
            else if (add_domain(&result, domain) != 0)
                rc = liveagent_fail(&owned_error, "cannot store LiveAgent domain");
            else if (verify) {
                int verdict = liveagent_verify(ctx, keys.items[k], key, domain, &result,
                                                &pending, &owned_error);
                if (verdict < 0) rc = -1;
                else keep = verdict == 0;
            }
            if (rc == 0 && keep && br_results_push(out, &result) != 0)
                rc = liveagent_fail(&owned_error, "cannot append LiveAgent result");
            br_result_clear(&result);
        }
    }
    /* Successful responses close after verdict and publication, last success
     * first. Fatal paths drain the same list once, then roll back only this
     * invocation. Captures still own the raw key bytes used as header values. */
    liveagent_release_held(ctx, pending);
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&domains);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const liveagent_keywords[] = {"liveagent", "ladesk"};
static const char *const liveagent_key_prefixes[] = {"liveagent", "apikey"};
static br_detector liveagent_detector = {
    .type = 165, .version = 0, .name = "LiveAgent", .custom_name = "",
    .description = "LiveAgent is a help desk software that provides a customer service platform. The API key allows access to various functionalities of the LiveAgent service.",
    .keywords = liveagent_keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = liveagent_scan,
};

int br_liveagent_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return liveagent_fail(error, "invalid LiveAgent detector output");
    *out = NULL;
    if (!liveagent_detector.state) {
        liveagent_state *state = calloc(1, sizeof(*state));
        if (!state) return liveagent_fail(error, "cannot allocate LiveAgent patterns");
        if (br_regex_compile_prefixed(liveagent_key_prefixes, 2, "\\b([a-zA-Z0-9]{32})\\b",
                                      &state->key, error) != 0) {
            free(state);
            return -1;
        }
        if (br_regex_compile("\\b(https?://[A-Za-z0-9-]+\\.ladesk\\.com)\\b", &state->domain, error) != 0) {
            br_regex_free(state->key);
            free(state);
            return -1;
        }
        liveagent_detector.state = state;
    }
    *out = &liveagent_detector;
    return 0;
}
