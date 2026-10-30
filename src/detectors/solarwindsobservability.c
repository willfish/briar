/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/solarwindsobservability/solarwindsobservability.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int put_text(br_json *object, const char *name, const char *value)
{
    br_json *text = json_object_new_string(value);
    if (!text || json_object_object_add(object, name, text) != 0) {
        json_object_put(text);
        return -1;
    }
    return 0;
}

static int verify_solarwinds(const br_scan_ctx *ctx, const char *token, bool *verified,
                             char **region, char **cause)
{
    static const char *const regions[] = {"na-01", "na-02", "eu-01", "ap-01"};
    char *last = NULL;
    *verified = false;
    *region = NULL;
    *cause = NULL;
    for (size_t i = 0; i < sizeof(regions) / sizeof(regions[0]); ++i) {
        char url[64];
        int n = snprintf(url, sizeof(url), "https://api.%s.cloud.solarwinds.com/v1/metrics", regions[i]);
        if (n != 49) { free(last); return -1; }
        /* Each regional URL is complete before that iteration's nil-context drop. */
        if (!ctx) {
            free(last);
            if (!(last = strdup("net/http: nil Context"))) return -1;
            continue;
        }
        char authorization[80];
        if (snprintf(authorization, sizeof(authorization), "Bearer %s", token) != 78) {
            free(last);
            return -1;
        }
        const br_header headers[] = {{"Authorization", authorization}};
        const br_http_request request = {
            .method = "GET", .url = url, .headers = headers, .nheaders = 1,
            .profile = BR_HTTP_SANE, .detector_type = 1069,
        };
        br_http_response response = {0};
        char *transport_error = NULL;
        int sent = br_http_send(ctx, &request, &response, &transport_error);
        if (sent != 0) {
            free(last);
            /* Known send failure. A NULL diagnostic is not an allocation failure
             * and must not become invented fallback text. */
            last = transport_error;
            transport_error = NULL;
            br_http_release(ctx, &response);
            continue;
        }
        if (response.status == 200) {
            free(last);
            *verified = true;
            *region = strdup(regions[i]);
            br_http_release(ctx, &response);
            free(transport_error);
            return *region ? 0 : -1;
        }
        if (response.status != 401) {
            char status_error[128];
            snprintf(status_error, sizeof(status_error),
                     "unexpected HTTP response status %d from region %s", response.status, regions[i]);
            free(last);
            last = strdup(status_error);
            br_http_release(ctx, &response);
            free(transport_error);
            if (!last) return -1;
            continue;
        }
        br_http_release(ctx, &response);
        free(transport_error);
    }
    *cause = last;
    return 0;
}

static int scan_solarwinds(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid SolarWindsObservability scan");
    br_captures keys = {0};
    char *owned = NULL;
    size_t original = out->len;
    int rc = br_captures_find(detector->state, input, &keys, false, &owned);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_slice key = br_captures_at(&keys, i);
        br_result result = {0};
        if (key.len != 71) rc = fail(&owned, "invalid SolarWindsObservability capture");
        else if (br_finding_key_bytes(&result, 1069, key, "key") != 0)
            rc = fail(&owned, "cannot create SolarWindsObservability result");
        else if (verify) {
            bool verified = false;
            char *region = NULL, *cause = NULL;
            if (verify_solarwinds(ctx, keys.items[i], &verified, &region, &cause) != 0)
                rc = fail(&owned, "cannot verify SolarWindsObservability token");
            else if (br_result_set_verification_error(&result, cause, &key, 1) != 0)
                rc = fail(&owned, "cannot record SolarWindsObservability verification error");
            else if (region &&
                     (put_text(result.secret_parts, "region", region) != 0 ||
                      !(result.extra_data = json_object_new_object()) ||
                      put_text(result.extra_data, "region", region) != 0))
                rc = fail(&owned, "cannot record SolarWindsObservability region");
            result.verified = !rc && verified;
            free(region);
            free(cause);
        }
        if (!rc && br_results_push(out, &result) != 0)
            rc = fail(&owned, "cannot append SolarWindsObservability result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"solarwinds"};
static br_detector solarwinds = {
    .type = 1069, .version = 0, .name = "SolarWindsObservability", .custom_name = "",
    .description = "SolarWinds Observability is a cloud-based SaaS observability platform "
                   "(successor to AppOptics). Its API tokens can be used to access and manage "
                   "monitoring data and configurations.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_solarwinds,
};

int br_solarwindsobservability_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid SolarWindsObservability detector output");
    *out = NULL;
    if (!solarwinds.state) {
        static const char *const prefixes[] = {"solarwinds"};
        br_regex *compiled = NULL;
        if (br_regex_compile_prefixed(prefixes, 1, "\\b([0-9a-zA-Z_-]{71})\\b", &compiled, error) != 0)
            return -1;
        solarwinds.state = compiled;
    }
    *out = &solarwinds;
    return 0;
}
