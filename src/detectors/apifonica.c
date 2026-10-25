/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/apifonica/apifonica.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_apifonica(const br_scan_ctx *ctx, br_slice key,
                            br_slice token, br_result *result)
{
    char *auth = NULL;
    if (br_http_basic_auth(key, token, &auth, NULL) != 0) return -1;
    const br_header headers[] = {
        {"Content-Type", "application/json"}, {"Authorization", auth},
    };
    const br_http_request request = {
        .method = "GET", .url = "https://api.apifonica.com/v2/accounts",
        .headers = headers, .nheaders = 2,
        .profile = BR_HTTP_SANE, .detector_type = 484,
    };
    br_http_response response = {0};
    char *error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        cause = error ? error : "HTTP transport failed";
    } else {
        /* Upstream ignores errors from its deferred body drain and close. */
        switch (response.status) {
        case 200: result->verified = true; break;
        case 401:
        case 403: break;
        default:
            snprintf(status_error, sizeof(status_error),
                     "unexpected status code: %d", response.status);
            cause = status_error;
            break;
        }
    }
    /* Upstream supplies neither key nor token to SetVerificationError. */
    int rc = br_result_set_verification_error(result, cause, NULL, 0);
    br_http_release(ctx, &response);
    free(error);
    free(auth);
    return rc;
}

static int scan_apifonica(const br_detector *detector, const br_scan_ctx *ctx,
                          bool verify, br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid ApiFonica scan arguments");

    /* Upstream uses keyPat for BOTH unique sets. Keep the full Cartesian
     * product, including equality, using one collection of unique captures. */
    br_captures values = {0};
    int rc = br_captures_find(detector->state, input, &values, true, error);
    for (size_t k = 0; !rc && k < values.len; ++k) {
        br_slice key = br_captures_at(&values, k);
        for (size_t t = 0; !rc && t < values.len; ++t) {
            br_slice token = br_captures_at(&values, t);
            br_result result = {0};
            /* The token affects verification only: upstream emits neither its
             * SecretPart nor RawV2. Same-key findings repeat for each token. */
            if (br_finding_key(&result, detector->type, values.items[k], "key") != 0 ||
                (verify && verify_apifonica(ctx, key, token, &result) != 0) ||
                br_results_push(out, &result) != 0)
                rc = fail(error, "out of memory creating ApiFonica result");
            br_result_clear(&result);
        }
    }
    br_captures_clear(&values);
    return rc;
}

static const char *const keywords[] = {"apifonica"};
static br_detector apifonica = {
    .type = 484, .version = 0, .name = "ApiFonica", .custom_name = "",
    .description = "Apifonica is a cloud communication platform that provides APIs for messaging, voice, and other communication services. Apifonica keys can be used to access and manage these services.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_apifonica,
};

int br_apifonica_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid ApiFonica detector output");
    *out = NULL;
    if (!apifonica.state) {
        br_regex *regex = NULL;
        if (br_regex_compile_prefixed(keywords, 1,
                "\\b([0-9a-z]{11}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\\b",
                &regex, error) != 0)
            return -1;
        apifonica.state = regex;
    }
    *out = &apifonica;
    return 0;
}
