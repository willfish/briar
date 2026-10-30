/* SPDX-License-Identifier: AGPL-3.0-only */
/*
 * Plivo, from pinned TruffleHog pkg/detectors/plivo/plivo.go.
 * Every key match is paired with every id match. Raw is the key, RawV2 is
 * key+id, and the redacted value is the raw id. Basic auth is id:key.
 */
#include "captures.h"
#include "detectors.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *const prefix[] = {"plivo", NULL};
static br_regex *key_re, *id_re;

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int verify(const br_scan_ctx *ctx, const char *id, const char *auth, br_result *result, char **error)
{
    char url[72];
    int n = snprintf(url, sizeof(url), "https://api.plivo.com/v1/Account/%s/Number/", id);
    if (n < 0 || (size_t)n >= sizeof(url)) return fail(error, "cannot format Plivo URL");
    if (!ctx) return 1;
    const br_header headers[] = {{"Accept", "application/json"}, {"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 2,
        .timeout_ms = 5000, .detector_type = 80, .profile = BR_HTTP_SANE,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int rc = br_http_send(ctx, &request, &response, &transport_error);
    if (!rc && response.status >= 200 && response.status < 300) result->verified = true;
    br_http_release(ctx, &response);
    free(transport_error);
    return 0;
}

static int scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify_requested,
                br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !key_re || !id_re || !out || (!input.data && input.len))
        return fail(error, "invalid Plivo scan arguments");
    size_t original = out->len;
    br_captures keys = {0}, ids = {0};
    char *owned = NULL;
    int rc = 0;
    if (br_captures_find(key_re, input, &keys, false, &owned) ||
        br_captures_find(id_re, input, &ids, false, &owned))
        rc = -1;
    for (size_t k = 0; !rc && k < keys.len; ++k) {
        for (size_t i = 0; !rc && i < ids.len; ++i) {
            const char *key = keys.items[k], *id = ids.items[i];
            br_result result = {0};
            br_slice key_s = {(const unsigned char *)key, strlen(key)};
            br_slice id_s = {(const unsigned char *)id, strlen(id)};
            char *auth = NULL;
            int outcome = 0;
            if (br_finding_pair_bytes(&result, detector->type, key_s, "key", id_s, "id", (br_slice){0}) != 0 ||
                !(result.redacted = strdup(id)))
                rc = fail(&owned, "cannot create Plivo finding");
            else if (br_http_basic_auth((br_slice){(const unsigned char *)id, strlen(id)},
                                         (br_slice){(const unsigned char *)key, strlen(key)},
                                         &auth, &owned) != 0)
                rc = -1;
            else if (verify_requested && (outcome = verify(ctx, id, auth, &result, &owned)) < 0)
                rc = -1;
            else if (!outcome && br_results_push(out, &result) != 0)
                rc = fail(&owned, "cannot append Plivo finding");
            free(auth);
            br_result_clear(&result);
        }
    }
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&ids);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static br_detector detector = {
    .name = "Plivo", .type = 80, .description =
        "Plivo is a cloud-based communications platform that provides API services for voice and messaging. Plivo credentials can be used to access and manage these services.",
    .keywords = (const char *[]){"plivo", NULL}, .nkeywords = 1, .scan = scan,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .custom_name = "",
};

int br_plivo_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Plivo detector output");
    *out = NULL;
    if ((!key_re && br_regex_compile_prefixed(prefix, 1, "\\b([A-Za-z0-9_-]{40})\\b", &key_re, error) != 0) ||
        (!id_re && br_regex_compile_prefixed(prefix, 1, "\\b([A-Z]{20})\\b", &id_re, error) != 0))
        return -1;
    detector.state = key_re;
    *out = &detector;
    return 0;
}
