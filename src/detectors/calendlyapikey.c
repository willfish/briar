/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/calendlyapikey. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "key_scan.h"

#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int verify_calendly(const br_scan_ctx *ctx, br_slice token, br_result *result, char **error)
{
    static const char bearer[] = "Bearer ";
    /* The signature capture is unbounded. Keep the complete original token,
     * without a fixed header buffer, Base64/JWT parsing or a new length cap. */
    if (token.len > SIZE_MAX - sizeof(bearer)) return fail(error, "CalendlyApiKey Authorization header too large");
    char *auth = malloc(sizeof(bearer) + token.len);
    if (!auth) return fail(error, "cannot allocate CalendlyApiKey Authorization header");
    memcpy(auth, bearer, sizeof(bearer) - 1);
    if (token.len) memcpy(auth + sizeof(bearer) - 1, token.data, token.len);
    auth[sizeof(bearer) - 1 + token.len] = '\0';
    const br_header headers[] = {{"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.calendly.com/users/me",
        .headers = headers, .nheaders = 1, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL;
    /* All Client.Do errors are suppressed. ABI1 also mixes adapter setup and
     * allocation errors into this nonzero domain: that classification gap is
     * explicit, not repaired by inspecting error text or inventing an API. */
    if (!br_http_send(ctx, &request, &response, &transport_error))
        result->verified = response.status >= 200 && response.status < 300;
    /* Source defers Close ONLY until FromData returns. ABI1 may have buffered
     * the body already and releases per request; no provider drain is added. */
    br_http_release(ctx, &response);
    free(transport_error); free(auth);
    return 0; /* Never set a verification error, including for non-2xx. */
}

static int scan_calendly(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized CalendlyApiKey scan");
    br_captures tokens = {0}; char *owned_error = NULL;
    size_t original_len = out->len;
    int rc = br_captures_find(detector->state, input, &tokens, false, &owned_error);
    for (size_t i = 0; !rc && i < tokens.len; ++i) {
        /* Fixed method/URL and ASCII tokens leave nil context as the known
         * constructor failure. Source continues WITHOUT this finding. Do not
         * confuse later Client.Do/adapter errors with this specific branch. */
        if (verify && !ctx) continue;
        br_result result = {0};
        br_slice token = br_captures_at(&tokens, i);
        /* TrimSpace is a no-op for this capture's ASCII alphabet and periods. */
        if (br_finding_key_bytes(&result, detector->type, token, "key"))
            rc = fail(&owned_error, "cannot create CalendlyApiKey result");
        if (!rc && verify) rc = verify_calendly(ctx, token, &result, &owned_error);
        if (!rc && br_results_push(out, &result)) rc = fail(&owned_error, "cannot append CalendlyApiKey result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&tokens);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"calendly"};
static br_detector calendly = {
    .type = 44, .version = 0, .name = "CalendlyApiKey", .custom_name = "",
    .description = "Calendly is an online scheduling tool that allows users to schedule meetings and appointments. Calendly API keys can be used to access and manage Calendly accounts and data.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_calendly,
};

int br_calendlyapikey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid CalendlyApiKey detector output");
    *out = NULL;
    /* eyJ is exact-case, periods are literal, bounds exclude each eyJ prefix,
     * and the final + is deliberately unbounded with source word backtracking. */
    if (br_key_pattern_init(&calendly, "\\b(eyJ[A-Za-z0-9-_]{100,300}\\.eyJ[A-Za-z0-9-_]{100,300}\\.[A-Za-z0-9-_]+)\\b", error)) return -1;
    *out = &calendly;
    return 0;
}
