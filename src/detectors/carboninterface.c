/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/carboninterface/carboninterface.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int carboninterface_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void carboninterface_verify(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    static const unsigned char payload[] =
        "{\"type\":\"flight\",\"passengers\":2,\"legs\":[{\"departure_airport\":\"sfo\",\"destination_airport\":\"yyz\"},"
        "{\"departure_airport\":\"yyz\",\"destination_airport\":\"sfo\"}]}";
    static const char prefix[] = "Bearer ";
    char auth[sizeof(prefix) + 21];
    memcpy(auth, prefix, sizeof(prefix) - 1);
    memcpy(auth + sizeof(prefix) - 1, key, 22); /* Exactly 21 ASCII bytes plus NUL. */
    const br_header headers[] = {{"Authorization", auth}, {"Content-Type", "application/json"}};
    const br_http_request request = {
        .method = "POST", .url = "https://www.carboninterface.com/api/v1/estimates",
        .headers = headers, .nheaders = 2, .body = {payload, sizeof(payload) - 1},
        .profile = BR_HTTP_SANE, .detector_type = 578,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* ALL source Client.Do errors are suppressed. ABI1's unified nonzero send
     * domain also conflates adapter allocation/setup errors, an explicit partial
     * gap. No text classification; native POST redirects stay fail-closed and
     * their unsupported diagnostic is suppressed like other send failures. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Source scan-defers Close only, without draining. ABI1 eagerly releases
     * per request and may already have buffered the body. Body errors ignored. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int carboninterface_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                                br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return carboninterface_fail(error, "invalid or uninitialized CarbonInterface scan");
    size_t original_len = out->len;
    br_captures keys = {0};
    int rc = br_captures_find(detector->state, input, &keys, false, error);
    for (size_t i = 0; rc == 0 && i < keys.len; ++i) {
        /* Fixed method/URL and ASCII keys leave nil context as the reachable
         * request-construction failure: source skips rather than appends. */
        if (verify && !ctx) continue;
        br_result result = {0};
        /* TrimSpace changes nothing in the captured ASCII alphabet. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&keys, i), "key") != 0)
            rc = carboninterface_fail(error, "out of memory creating CarbonInterface result");
        else if (verify) carboninterface_verify(ctx, keys.items[i], &result);
        if (rc == 0 && br_results_push(out, &result) != 0)
            rc = carboninterface_fail(error, "out of memory appending CarbonInterface result");
        br_result_clear(&result);
    }
    if (rc != 0) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    return rc == 0 ? 0 : -1;
}

static const char *const carboninterface_keywords[] = {"carboninterface"};
static br_detector carboninterface_detector = {
    .type = 578, .version = 0, .name = "CarbonInterface", .custom_name = "",
    .description = "CarbonInterface provides an API for estimating carbon emissions for various activities. "
                   "The API keys can be used to access and utilize this service.",
    .keywords = carboninterface_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = carboninterface_scan,
};

int br_carboninterface_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return carboninterface_fail(error, "invalid CarbonInterface detector output");
    *out = NULL;
    if (br_key_pattern_init(&carboninterface_detector, "\\b([a-zA-Z0-9]{21})\\b", error) != 0) return -1;
    *out = &carboninterface_detector;
    return 0;
}
