/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/reallysimplesystems/reallysimplesystems.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "json.h"
#include "key_scan.h"

#include <json-c/json.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_reallysimplesystems(const br_scan_ctx *ctx, const char *key, size_t key_len,
                                       br_result *result, bool *skip)
{
    char authorization[1166];
    int n = snprintf(authorization, sizeof(authorization), "Bearer %s", key);
    if (n < 0 || (size_t)n >= sizeof(authorization) || (size_t)n != key_len + 7) return -1;
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = "https://apiv4.reallysimplesystems.com/accounts",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE, .detector_type = 276,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int rc = 0;
    /* Do errors are suppressed. A body-read error continues without a result.
     * Only a 2xx body that json.Valid accepts is verified; other statuses are silent. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0) {
        if (response.body_error) *skip = true;
        else if (response.status >= 200 && response.status < 300) {
            br_json *document = NULL;
            char *cause = NULL;
            int parsed = br_json_document(response.body, &document, &cause);
            json_object_put(document);
            free(cause);
            /* json.Valid: exact +1 is ordinary invalid JSON. Other nonzero is fatal.
             * Success, including JSON null, verifies. */
            if (parsed == 0) result->verified = true;
            else if (parsed != 1) rc = -1;
        }
    }
    br_http_release(ctx, &response);
    free(transport_error);
    return rc;
}

static int scan_reallysimplesystems(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                                    br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid ReallySimpleSystems scan");
    br_captures keys = {0};
    char *owned = NULL;
    size_t original = out->len;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        bool skip = false;
        if (key.len < 1074 || key.len > 1158) rc = fail(&owned, "invalid ReallySimpleSystems capture");
        else if (br_finding_key_bytes(&result, 276, key, "key") != 0)
            rc = fail(&owned, "cannot create ReallySimpleSystems result");
        else if (verify) {
            /* Fixed URL is complete before NewRequestWithContext rejects nil. */
            if (!ctx) skip = true;
            else if (verify_reallysimplesystems(ctx, keys.items[i], key.len, &result, &skip) != 0)
                rc = fail(&owned, "cannot validate ReallySimpleSystems response");
        }
        if (!rc && !skip && br_results_push(out, &result) != 0)
            rc = fail(&owned, "cannot append ReallySimpleSystems result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"reallysimplesystems"};
static br_detector reallysimplesystems = {
    .type = 276, .version = 0, .name = "ReallySimpleSystems", .custom_name = "",
    .description = "ReallySimpleSystems is a CRM system. The detected credentials can be used to "
                   "access and manage customer relationship data and workflows within the "
                   "ReallySimpleSystems platform.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_reallysimplesystems,
};

int br_reallysimplesystems_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid ReallySimpleSystems detector output");
    *out = NULL;
    if (!reallysimplesystems.state &&
        br_regex_compile("\\b(ey[a-zA-Z0-9-._]{153}.ey[a-zA-Z0-9-._]{916,1000})\\b",
                         (br_regex **)&reallysimplesystems.state, error) != 0)
        return -1;
    *out = &reallysimplesystems;
    return 0;
}
