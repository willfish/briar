/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/logzio/logzio.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct logzio_attempt {
    br_http_request request;
    br_http_response response;
    br_header headers[2];
    struct logzio_attempt *previous;
} logzio_attempt;

static int logzio_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static logzio_attempt *logzio_request(const char *key)
{
    logzio_attempt *attempt = malloc(sizeof(*attempt));
    if (!attempt) return NULL;
    *attempt = (logzio_attempt){0};
    /* Go Header.Add canonicalizes the source literal X-API-TOKEN. */
    attempt->headers[0] = (br_header){"X-Api-Token", key};
    attempt->headers[1] = (br_header){"Content-Type", "application/json; charset=utf-8"};
    attempt->request = (br_http_request){
        .method = "GET", .url = "https://api.logz.io/v2/whoami",
        .headers = attempt->headers, .nheaders = 2, .profile = BR_HTTP_SANE, .detector_type = 961,
    };
    return attempt;
}

static void logzio_release(const br_scan_ctx *ctx, logzio_attempt *attempt)
{
    br_http_release(ctx, &attempt->response);
    free(attempt);
}

static int logzio_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return logzio_fail(error, "invalid or uninitialized LogzIO scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    logzio_attempt *deferred = NULL;
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        br_result result = {0};
        br_slice key = br_captures_at(&keys, i);
        /* TrimSpace is a no-op for the lowercase-alphanumeric UUID grammar. */
        if (br_finding_key_bytes(&result, detector->type, key, "key") != 0)
            rc = logzio_fail(error, "out of memory creating LogzIO result");
        if (rc == 0 && verify && !ctx) {
            /* Fixed-URL constructor failure precedes provider headers, but
             * cannot hide a reached finding/map failure. */
            br_result_clear(&result);
            continue;
        }
        if (rc == 0 && verify) {
            logzio_attempt *attempt = logzio_request(keys.items[i]);
            if (!attempt) rc = logzio_fail(error, "out of memory creating LogzIO request");
            else {
                char *transport_error = NULL;
                int send_rc = br_http_send(ctx, &attempt->request, &attempt->response, &transport_error);
                bool set_error = send_rc != 0;
                const char *cause = transport_error;
                char status_error[80];
                if (send_rc == 0) {
                    attempt->previous = deferred;
                    deferred = attempt;
                    if (attempt->response.status >= 200 && attempt->response.status < 300)
                        result.verified = true;
                    else if (attempt->response.status != 401) {
                        int n = snprintf(status_error, sizeof(status_error),
                                         "unexpected HTTP response status %d", attempt->response.status);
                        if (n < 0 || (size_t)n >= sizeof(status_error))
                            rc = logzio_fail(error, "cannot format LogzIO HTTP status");
                        else { cause = status_error; set_error = true; }
                    }
                }
                /* The setter is conditional, including on the entire mixed
                 * shared preparation/Do error domain. Keep the original cause;
                 * even its NULL no-op remains a checked owned helper call. */
                if (rc == 0 && set_error && br_result_set_verification_error(&result, cause, &key, 1) != 0)
                    rc = logzio_fail(error, "cannot set LogzIO verification error");
                if (send_rc != 0) logzio_release(ctx, attempt);
                free(transport_error);
            }
        }
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = logzio_fail(error, "out of memory appending LogzIO result");
        br_result_clear(&result);
    }
    /* Successful closes are LIFO after setter/publication, also on fatal exits.
     * Only provider request/header/key storage survives, never prepared HTTP. */
    while (deferred) {
        logzio_attempt *previous = deferred->previous;
        logzio_release(ctx, deferred);
        deferred = previous;
    }
    br_captures_clear(&keys);
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    return rc == 0 ? 0 : -1;
}

static const char *const logzio_keywords[] = {"logz"};
static br_detector logzio_detector = {
    .type = 961, .version = 0, .name = "LogzIO", .custom_name = "",
    .description = "Logz.io is a cloud observability platform for log analysis and monitoring. "
                   "Logz.io API tokens can be used to access and manage log data.",
    .keywords = logzio_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = logzio_scan,
};

int br_logzio_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return logzio_fail(error, "invalid LogzIO detector output");
    *out = NULL;
    if (br_key_pattern_init(&logzio_detector,
        "\\b([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\\b", error) != 0) return -1;
    *out = &logzio_detector;
    return 0;
}
