/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/portainer/portainer.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "../go_url.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static void rollback(br_results *out, size_t before)
{
    while (out && out->len > before) br_result_clear(&out->items[--out->len]);
}

static int append_slice(br_bytes *out, br_slice s)
{
    if (!s.len) return 0;
    if (out->len == SIZE_MAX || s.len > SIZE_MAX - out->len - 1) return -1;
    unsigned char *data = realloc(out->data, out->len + s.len + 1);
    if (!data) return -1;
    out->data = data;
    memcpy(data + out->len, s.data, s.len);
    out->len += s.len;
    data[out->len] = '\0';
    return 0;
}

static int append_text(br_bytes *out, const char *text)
{
    return append_slice(out, (br_slice){(const unsigned char *)text, strlen(text)});
}

static int escape_bytes(br_slice in, br_go_url_encoding mode, br_bytes *out)
{
    *out = (br_bytes){0};
    for (size_t i = 0; i < in.len; ++i) {
        unsigned char c = in.data[i];
        if (br_go_url_byte_allowed(c, mode)) {
            if (append_slice(out, (br_slice){&c, 1}) != 0) return -1;
        } else {
            char hex[4];
            snprintf(hex, sizeof(hex), "%%%02X", c);
            if (append_text(out, hex) != 0) return -1;
        }
    }
    return 0;
}

/* Parse, clear path and query, then set /api/endpoints. Invalid URLs skip.
 * The rebuilt string is complete before a nil-context drop. */
static int portainer_url(br_slice endpoint, char **url, bool *valid, char **error)
{
    *url = NULL;
    *valid = false;
    br_go_url_parts parts = {0};
    br_go_url_error rejection = {0};
    char *fatal = NULL;
    int rc = br_go_url_parse(endpoint, &parts, &rejection, &fatal);
    if (rc < 0) {
        br_go_url_clear(&parts);
        if (error && !*error) *error = fatal;
        else free(fatal);
        return -1;
    }
    free(fatal);
    if (rejection.kind != BR_GO_URL_OK) {
        br_go_url_clear(&parts);
        return 0;
    }
    const char *scheme = endpoint.len >= 8 && !memcmp(endpoint.data, "https://", 8) ? "https" : "http";
    br_bytes built = {0};
    br_bytes user = {0}, password = {0}, fragment = {0};
    bool user_ok = true, pass_ok = true, frag_ok = true;
    if (parts.has_user) {
        if (br_go_url_decode(parts.raw_user, false, &user, &user_ok, error) != 0 ||
            (parts.has_password && br_go_url_decode(parts.raw_password, false, &password, &pass_ok, error) != 0)) {
            br_go_url_clear(&parts); free(user.data); free(password.data);
            return -1;
        }
    }
    if (parts.raw_fragment.len &&
        br_go_url_decode(parts.raw_fragment, false, &fragment, &frag_ok, error) != 0) {
        br_go_url_clear(&parts); free(user.data); free(password.data);
        return -1;
    }
    if (!user_ok || !pass_ok || !frag_ok) {
        br_go_url_clear(&parts); free(user.data); free(password.data); free(fragment.data);
        return 0;
    }
    br_bytes esc_user = {0}, esc_pass = {0}, esc_frag = {0};
    int built_rc = 0;
    if (append_text(&built, scheme) != 0 || append_text(&built, "://") != 0) built_rc = -1;
    if (!built_rc && parts.has_user) {
        if (escape_bytes((br_slice){user.data, user.len}, BR_GO_URL_USER, &esc_user) != 0) built_rc = -1;
        else if (append_slice(&built, (br_slice){esc_user.data, esc_user.len}) != 0) built_rc = -1;
        else if (parts.has_password) {
            if (escape_bytes((br_slice){password.data, password.len}, BR_GO_URL_USER, &esc_pass) != 0 ||
                append_text(&built, ":") != 0 ||
                append_slice(&built, (br_slice){esc_pass.data, esc_pass.len}) != 0) built_rc = -1;
        }
        if (!built_rc && append_text(&built, "@") != 0) built_rc = -1;
    }
    if (!built_rc && append_slice(&built, parts.host) != 0) built_rc = -1;
    if (!built_rc && append_text(&built, "/api/endpoints") != 0) built_rc = -1;
    if (!built_rc && parts.raw_fragment.len) {
        if (escape_bytes((br_slice){fragment.data, fragment.len}, BR_GO_URL_FRAGMENT, &esc_frag) != 0 ||
            append_text(&built, "#") != 0 ||
            append_slice(&built, (br_slice){esc_frag.data, esc_frag.len}) != 0) built_rc = -1;
    }
    br_go_url_clear(&parts);
    free(user.data); free(password.data); free(fragment.data);
    free(esc_user.data); free(esc_pass.data); free(esc_frag.data);
    if (built_rc) { free(built.data); return fail(error, "cannot format Portainer URL"); }
    *url = (char *)built.data;
    *valid = true;
    return 0;
}

static int verify_portainer(const br_scan_ctx *ctx, br_slice token, const char *url,
                            br_result *result, char **error)
{
    if (!ctx) return 1;
    if (token.len > SIZE_MAX - 8) return fail(error, "Portainer authorization is too large");
    char *auth = malloc(7 + token.len + 1);
    if (!auth) return fail(error, "cannot format Portainer authorization");
    memcpy(auth, "Bearer ", 7);
    memcpy(auth + 7, token.data, token.len);
    auth[7 + token.len] = '\0';
    const br_header headers[] = {{"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_DETECTOR_LOCAL, .timeout_ms = 10000, .detector_type = 942,
    };
    br_http_response response = {0};
    char *send_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    bool error_present = false;
    int rc = 0;
    if (br_http_send(ctx, &request, &response, &send_error) != 0) {
        error_present = true;
        cause = send_error;
    } else if (response.status >= 200 && response.status < 300) {
        result->verified = true;
    } else if (response.status != 401 && response.status != 403) {
        int n = snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error)) rc = fail(error, "cannot format Portainer status");
        else {
            error_present = true;
            cause = status_error;
        }
    }
    br_http_release(ctx, &response);
    if (!rc && error_present && br_result_set_verification_error(result, cause, &token, 1) != 0)
        rc = -1;
    free(send_error);
    free(auth);
    return rc;
}

typedef struct { br_regex *token, *endpoint; } portainer_state;

static int scan_portainer(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    portainer_state *state = detector ? (portainer_state *)detector->state : NULL;
    if (!detector || !state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Portainer scan");
    size_t before = out->len;
    br_captures tokens = {0}, endpoints = {0};
    char *owned = NULL;
    int rc = br_captures_find(state->token, input, &tokens, false, &owned);
    if (!rc) rc = br_captures_find(state->endpoint, input, &endpoints, false, &owned);
    for (size_t i = 0; !rc && i < tokens.len; ++i) {
        for (size_t j = 0; !rc && j < endpoints.len; ++j) {
            br_slice token = br_captures_at(&tokens, i);
            br_slice endpoint = br_captures_at(&endpoints, j);
            char *url = NULL;
            bool valid = false;
            rc = portainer_url(endpoint, &url, &valid, &owned);
            if (rc) { free(url); break; }
            if (!valid) { free(url); continue; }
            br_result result = {0};
            if (br_finding_pair_bytes(&result, detector->type, token, "key", endpoint, "url", (br_slice){0}) != 0)
                rc = fail(&owned, "cannot create Portainer finding");
            else if (verify && !ctx) {
                free(url);
                br_result_clear(&result);
                continue;
            } else if (verify && verify_portainer(ctx, token, url, &result, &owned) != 0) {
                rc = -1;
            }
            free(url);
            if (!rc && br_results_push(out, &result) != 0)
                rc = fail(&owned, "cannot append Portainer finding");
            br_result_clear(&result);
        }
    }
    if (rc) rollback(out, before);
    br_captures_clear(&tokens);
    br_captures_clear(&endpoints);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"portainer"};
static br_detector portainer = {
    .type = 942, .version = 0, .name = "Portainer", .custom_name = "",
    .description = "Portainer is a management UI for Docker, Docker Swarm, Kubernetes, and Azure ACI. Portainer API tokens can be used to access and control these environments.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .scan = scan_portainer,
};

int br_portainer_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Portainer detector output");
    *out = NULL;
    if (portainer.state) { *out = &portainer; return 0; }
    portainer_state *state = calloc(1, sizeof(*state));
    if (!state) return fail(error, "cannot allocate Portainer patterns");
    if (br_regex_compile_prefixed(keywords, 1,
            "\\b(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\\.[0-9A-Za-z]{50,310}\\.[0-9A-Z-a-z\\-_]{43})\\b",
            &state->token, error) != 0 ||
        br_regex_compile_prefixed(keywords, 1, "\\b(https?:\\/\\/\\S+(:[0-9]{4,5})?)\\b",
                                  &state->endpoint, error) != 0) {
        free(state);
        return -1;
    }
    portainer.state = state;
    *out = &portainer;
    return 0;
}
