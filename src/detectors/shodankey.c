/* SPDX-License-Identifier: AGPL-3.0-only */
/*
 * ShodanKey, from pinned TruffleHog pkg/detectors/shodankey/shodankey.go.
 * A 2xx body must unmarshal as JSON into the plan struct. Nil context and
 * transport errors still publish an unverified result.
 */
#include "captures.h"
#include "detectors.h"
#include "findings.h"
#include "key_scan.h"

#include <json-c/json.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

/* encoding/json.Unmarshal into a struct accepts an object or null and
 * trailing whitespace. json-c reports JSON null as a NULL object and needs a
 * following byte before an exact literal is complete, so copy and append one. */
static int json_struct_ok(br_slice body)
{
    if (!body.data || !body.len || body.len > INT_MAX - 1) return 0;
    char *copy = malloc(body.len + 1);
    struct json_tokener *tok = json_tokener_new();
    if (!copy || !tok) { free(copy); json_tokener_free(tok); return -1; }
    memcpy(copy, body.data, body.len);
    copy[body.len] = ' ';
    json_object *obj = json_tokener_parse_ex(tok, copy, (int)body.len + 1);
    enum json_tokener_error err = json_tokener_get_error(tok);
    size_t end = json_tokener_get_parse_end(tok);
    json_tokener_free(tok);
    free(copy);
    if (err != json_tokener_success) { json_object_put(obj); return 0; }
    bool ok = !obj || json_object_get_type(obj) == json_type_object;
    json_object_put(obj);
    if (!ok) return 0;
    for (size_t i = end < body.len ? end : body.len; i < body.len; ++i) {
        unsigned char c = body.data[i];
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r') return 0;
    }
    return 1;
}

static int verify(const br_scan_ctx *ctx, const char *key, br_result *result, char **error)
{
    char url[80];
    int n = snprintf(url, sizeof(url), "https://api.shodan.io/api-info?key=%s", key);
    if (n < 0 || (size_t)n >= sizeof(url)) return fail(error, "cannot format ShodanKey URL");
    if (!ctx) return 0;
    const br_http_request request = {
        .method = "GET", .url = url, .timeout_ms = 5000, .detector_type = 88, .profile = BR_HTTP_SANE,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &transport_error);
    if (!sent && !response.body_error && response.status >= 200 && response.status < 300) {
        int ok = json_struct_ok(response.body);
        if (ok < 0) {
            br_http_release(ctx, &response);
            free(transport_error);
            return fail(error, "cannot parse ShodanKey response");
        }
        result->verified = ok == 1;
    }
    br_http_release(ctx, &response);
    free(transport_error);
    return 0;
}

static int scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify_requested,
                br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid ShodanKey scan arguments");
    size_t original = out->len;
    br_captures found = {0};
    char *owned = NULL;
    int rc = br_captures_find(detector->state, input, &found, false, &owned);
    if (rc) rc = -1;
    for (size_t i = 0; !rc && i < found.len; ++i) {
        br_result result = {0};
        if (br_finding_key(&result, detector->type, found.items[i], "key") != 0)
            rc = fail(&owned, "cannot create ShodanKey finding");
        else if (verify_requested && verify(ctx, found.items[i], &result, &owned) != 0)
            rc = -1;
        else if (br_results_push(out, &result) != 0)
            rc = fail(&owned, "cannot append ShodanKey finding");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&found);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static br_detector detector = {
    .name = "ShodanKey", .type = 88, .description =
        "Shodan is a search engine for Internet-connected devices. Shodan API keys can be used to query the Shodan database for information on these devices.",
    .keywords = (const char *[]){"shodan", NULL}, .nkeywords = 1, .scan = scan,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .custom_name = "",
};

int br_shodankey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid ShodanKey detector output");
    *out = NULL;
    if (!detector.state && br_key_pattern_init(&detector, "\\b([a-zA-Z0-9]{32})\\b", error) != 0)
        return -1;
    *out = &detector;
    return 0;
}
