/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/teamworkcrm/teamworkcrm.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_teamworkcrm(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    char auth[96];
    int n = snprintf(auth, sizeof(auth), "Bearer %s", key);
    if (n < 0 || (size_t)n >= sizeof(auth)) return -1;
    if (!ctx) return 1;
    const br_header headers[] = {{"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = "https://example.teamwork.com/crm/api/v2/users.json",
        .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *error = NULL;
    if (br_http_send(ctx, &request, &response, &error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    br_http_release(ctx, &response);
    free(error);
    return 0;
}

static int scan_teamworkcrm(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized TeamworkCRM scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        /* Capture includes one required trailing space, CR, or LF. TrimSpace
         * removes it; the rest of this alphabet has no Unicode space. */
        size_t len = keys.lengths[i];
        if (!len) continue;
        char saved = keys.items[i][len - 1];
        if (saved == ' ' || saved == '\r' || saved == '\n') keys.items[i][len - 1] = '\0';
        br_result result = {0};
        if (br_finding_key(&result, detector->type, keys.items[i], "key") != 0)
            rc = fail(error, "out of memory creating TeamworkCRM result");
        else if (verify) {
            int checked = verify_teamworkcrm(ctx, keys.items[i], &result);
            if (checked < 0) rc = fail(error, "cannot construct TeamworkCRM Authorization header");
            else if (checked > 0) { br_result_clear(&result); keys.items[i][len - 1] = saved; continue; }
        }
        if (!rc && br_results_push(out, &result) != 0)
            rc = fail(error, "out of memory appending TeamworkCRM result");
        br_result_clear(&result);
        keys.items[i][len - 1] = saved;
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"teamwork", "teamworkcrm"};
static br_detector teamworkcrm = {
    .type = 628, .version = 0, .name = "TeamworkCRM", .custom_name = "",
    .description = "TeamworkCRM is a customer relationship management tool that helps teams manage their sales pipeline and customer interactions. TeamworkCRM tokens can be used to access and manage CRM data and functionalities.",
    .keywords = keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_teamworkcrm,
};

int br_teamworkcrm_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid TeamworkCRM detector output");
    *out = NULL;
    if (br_key_pattern_init(&teamworkcrm, "\\b(tkn\\.v1_[0-9A-Za-z]{71}=[ \\r\\n])", error) != 0)
        return -1;
    *out = &teamworkcrm;
    return 0;
}
