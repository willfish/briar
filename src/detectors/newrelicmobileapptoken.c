/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/newrelicmobileapptoken/newrelicmobileapptoken.go. */
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

/* Mandatory, including a nil cause. No secrets: redact nothing. */
static int set_cause(br_result *result, const char *cause, char **error)
{
    if (br_result_set_verification_error(result, cause, NULL, 0) != 0)
        return fail(error, "cannot record NewRelicMobileAppToken verification error");
    return 0;
}

static int add_string(br_json *object, const char *name, const char *value)
{
    br_json *part = json_object_new_string(value);
    if (!part) return -1;
    if (json_object_object_add(object, name, part) != 0) {
        json_object_put(part);
        return -1;
    }
    return 0;
}

/* Region is chosen before verify, including when verification is off. */
static int annotate(br_result *result, br_slice key, char **error)
{
    if (!key.data || key.len < 8) return fail(error, "cannot allocate NewRelicMobileAppToken redaction");
    char shown[12];
    memcpy(shown, key.data, 8);
    memcpy(shown + 8, "...", 4);
    result->redacted = strdup(shown);
    if (!result->redacted) return fail(error, "cannot allocate NewRelicMobileAppToken redaction");
    const char *region = key.len >= 6 && !memcmp(key.data, "eu01xx", 6) ? "eu" : "us";
    result->extra_data = json_object_new_object();
    if (!result->extra_data) return fail(error, "cannot create NewRelicMobileAppToken metadata");
    if (add_string(result->secret_parts, "region", region) != 0 ||
        add_string(result->extra_data, "region", region) != 0)
        return fail(error, "cannot record NewRelicMobileAppToken region");
    return 0;
}

static int wrap_cause(const char *prefix, const char *detail, char **out)
{
    size_t prefix_len = strlen(prefix);
    size_t detail_len = strlen(detail);
    if (detail_len > SIZE_MAX - prefix_len - 1) return -1;
    char *text = malloc(prefix_len + detail_len + 1);
    if (!text) return -1;
    memcpy(text, prefix, prefix_len);
    memcpy(text + prefix_len, detail, detail_len + 1);
    *out = text;
    return 0;
}

static int verify_token(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    /* Constructor failure is retained. Do not send or release. */
    if (!ctx)
        return set_cause(result, "error constructing request: net/http: nil Context", error);
    if (key.len != 47) return fail(error, "cannot verify NewRelicMobileAppToken key");
    bool eu = !memcmp(key.data, "eu01xx", 6);
    char api_key[48];
    memcpy(api_key, key.data, 47);
    api_key[47] = '\0';
    const br_header headers[] = {
        {"Content-Type", "application/json"},
        {"X-App-License-Key", api_key},
    };
    const br_http_request request = {
        .method = "POST",
        .url = eu ? "https://mobile-collector.eu01.nr-data.net/mobile/v5/connect"
                  : "https://mobile-collector.newrelic.com/mobile/v5/connect",
        .headers = headers,
        .nheaders = 2,
        .profile = BR_HTTP_SANE,
        .timeout_ms = 0,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    int sent = br_http_send(ctx, &request, &response, &send_error);
    int status = response.status;
    const char *cause = NULL;
    char *owned = NULL;
    char status_text[64];
    int rc = 0;
    /* A missing transport cause stays NULL. Do not invent diagnostic text. */
    if (sent != 0) {
        if (send_error && wrap_cause("error making request: ", send_error, &owned) != 0)
            rc = fail(error, "cannot record NewRelicMobileAppToken verification error");
        else if (send_error) cause = owned;
    } else if (status != 400 && status != 401) {
        /* Source builds this error before the deferred close. */
        int n = snprintf(status_text, sizeof(status_text), "unexpected status code: %d", status);
        if (n < 0 || (size_t)n >= sizeof(status_text))
            rc = fail(error, "cannot format NewRelicMobileAppToken verification status");
        else cause = status_text;
    }
    /* Release once while the original key bytes are still alive. */
    br_http_release(ctx, &response);
    if (rc != 0) {
        free(owned);
        free(send_error);
        return rc; /* No verdict and no setter. The scan rolls this invocation back. */
    }
    if (sent == 0 && status == 400) result->verified = true;
    /* 400 and 401 still reach the setter with a nil cause. */
    rc = set_cause(result, cause, error);
    free(owned);
    free(send_error);
    return rc;
}

static int scan_token(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized NewRelicMobileAppToken scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    char *owned_error = NULL;
    /* Keyword is an engine hint. Keep every match, including duplicates. */
    int rc = br_captures_find(detector->state, input, &keys, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0) {
            fail(&owned_error, "cannot create NewRelicMobileAppToken finding");
            rc = -1;
        } else if (annotate(&result, key, &owned_error) != 0) {
            rc = -1;
        } else if (verify && verify_token(ctx, key, &result, &owned_error) != 0) {
            rc = -1;
        } else if (br_results_push(out, &result) != 0) {
            fail(&owned_error, "cannot append NewRelicMobileAppToken finding");
            rc = -1;
        }
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const keywords[] = {"-nrma"};
static br_detector token = {
    .type = 1068,
    .version = 0,
    .name = "NewRelicMobileAppToken",
    .custom_name = "",
    .description = "A New Relic Mobile App Token is an authentication key used to send mobile application telemetry data (such as performance metrics, crashes, and events) from iOS and Android apps to New Relic for monitoring and analysis. It is specific to each mobile app and ensures secure data ingestion.",
    .keywords = keywords,
    .nkeywords = 1,
    .max_secret_size = -1,
    .start_offset = -1,
    .max_credential_span = -1,
    .scan = scan_token,
};

int br_newrelicmobileapptoken_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid NewRelicMobileAppToken detector output");
    *out = NULL;
    if (!token.state) {
        br_regex *regex = NULL;
        if (br_regex_compile("\\b((AA[0-9a-f]{40}|eu01xx[0-9a-f]{36})-NRMA)\\b", &regex, error) != 0)
            return -1;
        token.state = regex;
    }
    *out = &token;
    return 0;
}
