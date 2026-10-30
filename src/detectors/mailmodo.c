/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/mailmodo/mailmodo.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static const char mailmodo_url[] = "https://api.mailmodo.com/api/v1/campaigns?type=CONTACT_LIST";

static int mailmodo_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int send_mailmodo(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    /* Header.Add canonicalizes the source spelling mmApiKey. Content-Type stays first.
     * Built only after NewRequestWithContext succeeds. */
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"Mmapikey", key},
    };
    const br_http_request request = {
        .method = "GET", .url = mailmodo_url, .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    /* Any 2xx verifies. Do not read the body. Never call the setter. */
    if (br_http_send(ctx, &request, &response, &send_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(send_error);
    return 0;
}

static int scan_mailmodo(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return mailmodo_fail(error, "invalid or uninitialized Mailmodo scan");
    br_captures keys = {0};
    char *owned_error = NULL;
    size_t original_len = out->len;
    /* FindAll runs before a constructor drop, including a nil context.
     * Any nonzero, including +1, is fatal before that drop. */
    int capture_rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    int rc = capture_rc == 0 ? 0 : -1;
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        int finding_rc = br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key");
        if (finding_rc != 0)
            rc = mailmodo_fail(&owned_error, "out of memory creating detector result");
        else if (verify && !ctx) {
            /* NewRequestWithContext(nil) drops only this candidate. No headers, send, or release. */
            br_result_clear(&result);
            continue;
        } else if (verify && send_mailmodo(ctx, keys.items[i], &result) != 0)
            rc = mailmodo_fail(&owned_error, "cannot verify Mailmodo candidate");
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = mailmodo_fail(&owned_error, "out of memory appending detector result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const mailmodo_keywords[] = {"mailmodo"};
static br_detector mailmodo_detector = {
    .type = 157, .version = 0, .name = "Mailmodo", .custom_name = "",
    .description = "Mailmodo is a platform for creating and sending interactive emails. Mailmodo API keys can be used to access and manage email campaigns and contacts.",
    .keywords = mailmodo_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_mailmodo,
};

int br_mailmodo_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return mailmodo_fail(error, "invalid Mailmodo detector output");
    *out = NULL;
    if (br_key_pattern_init(&mailmodo_detector,
            "\\b([A-Z0-9]{7}-[A-Z0-9]{7}-[A-Z0-9]{7}-[A-Z0-9]{7})\\b", error) != 0)
        return -1;
    *out = &mailmodo_detector;
    return 0;
}
