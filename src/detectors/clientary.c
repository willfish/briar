/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/clientary/clientary.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } clientary_patterns;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int set_cause(br_result *result, const char *cause)
{
    const br_slice key = {result->raw.data, result->raw.len};
    return br_result_set_verification_error(result, cause, &key, 1) ? -1 : 0;
}

static int rebranding(br_result *result)
{
    br_json *text = json_object_new_string("https://www.clientary.com/articles/a-new-brand/");
    if (!text) return -1;
    /* Preserve the pinned source's TYPO, not "Rebranding Docs". */
    if (json_object_object_add(result->extra_data, "Rebrading Docs", text)) { json_object_put(text); return -1; }
    return 0;
}

static int verify_clientary(const br_scan_ctx *ctx, const char *id, br_slice key,
                            br_result *result, bool *remove_id)
{
    *remove_id = false;
    /* Source suppresses the known nil-context constructor failure, retaining
     * false/nil. Construction precedes Basic preparation. */
    if (!ctx) return 0;
    char url[96]; /* Captured ID <=25 ASCII bytes, without DNS validation. */
    snprintf(url, sizeof(url), "https://%s.clientary.com/api/v2/invoices", id);
    char *authorization = NULL;
    if (br_http_basic_auth(key, key, &authorization, NULL)) { free(authorization); return -1; }
    const br_header headers[] = {{"Authorization", authorization}, {"Accept", "application/json"}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL;
    char status_error[80]; const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error))
        cause = transport_error ? transport_error : "HTTP transport failed";
    else {
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401: case 403: break;
        case 404:
            /* Private SENTINEL IDENTITY, not error text or a positive return
             * code. Ignore body/read errors even here. */
            *remove_id = true;
            break;
        default:
            snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* Copy API-key-redacted causes BEFORE release. Setter +1 is resource -1,
     * never the account-not-found outcome. No body/drain/close error is used. */
    int rc = set_cause(result, cause);
    br_http_release(ctx, &response);
    free(transport_error); free(authorization);
    /* Source verifier-defers drain/close. ABI1 eager buffering/release and
     * http.NoBody identity/native client configuration remain parity gaps. */
    return rc ? -1 : 0;
}

static int scan_clientary(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len)) return fail(error, "invalid Clientary scan");
    const clientary_patterns *compiled = detector->state;
    if (!compiled->key || !compiled->id) return fail(error, "uninitialized Clientary patterns");
    br_captures ids = {0}, keys = {0}; char *owned_error = NULL;
    size_t original_len = out->len;
    int rc = br_captures_find(compiled->id, input, &ids, true, &owned_error);
    if (!rc) rc = br_captures_find(compiled->key, input, &keys, true, &owned_error);
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        for (size_t i = 0; !rc && i < ids.len; ++i) {
            if (!ids.items[i]) continue; /* Invocation-local deletion, not a host cache. */
            br_slice key = br_captures_at(&keys, k), id = br_captures_at(&ids, i);
            if (key.len == id.len && !memcmp(key.data, id.data, key.len)) continue;
            br_result result = {0}; bool remove_id = false;
            static const unsigned char colon[] = ":";
            if (br_finding_pair_bytes(&result, detector->type, key, "key", id, "id", (br_slice){colon, 1}) ||
                !(result.extra_data = json_object_new_object()))
                rc = fail(&owned_error, "cannot create Clientary result");
            if (!rc && verify) {
                int checked = verify_clientary(ctx, ids.items[i], key, &result, &remove_id);
                /* Resource failures take precedence over suppression/deletion. */
                if (checked) rc = fail(&owned_error, "cannot verify Clientary candidate");
                else if (remove_id) {
                    free(ids.items[i]); ids.items[i] = NULL; ids.lengths[i] = 0;
                } else if (result.verified && rebranding(&result))
                    rc = fail(&owned_error, "cannot attach Clientary rebranding metadata");
            }
            if (!rc && !remove_id && br_results_push(out, &result)) rc = fail(&owned_error, "cannot append Clientary result");
            br_result_clear(&result); /* 404 discards only this candidate; prior findings stay. */
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&ids); br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static clientary_patterns patterns;
static const char *const keywords[] = {"ronin", "clientary"};
static const br_detector clientary = {
    .type = 307, .version = 0, .name = "Clientary", .custom_name = "",
    .description = "Clientary is a one software app to manage Clients, Invoices, Projects, Proposals, Estimates, Hours, Payments, Contractors and Staff. Clientary keys can be used to access and manage invoices and other resources.",
    .keywords = keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_clientary,
};

int br_clientary_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Clientary detector output");
    *out = NULL;
    if (!patterns.id && br_regex_compile_prefixed(keywords, 2, "\\b([0-9Aa-zA-Z-]{4,25})\\b", &patterns.id, error)) return -1;
    if (!patterns.key && br_regex_compile_prefixed(keywords, 2, "\\b([0-9a-zA-Z]{24,26})\\b", &patterns.key, error)) return -1;
    *out = &clientary;
    return 0;
}
