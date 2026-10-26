/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/bitbucketapppassword. */
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

typedef struct { br_regex *patterns[3]; } app_patterns;
typedef struct {
    br_slice input;
    br_captures usernames, passwords;
    char *error;
} credentials;

static int remember(void *user, const br_span *groups, size_t ngroups)
{
    credentials *found = user;
    /* All three named source patterns use username=1 and password=2. */
    if (ngroups < 3) return fail(&found->error, "invalid Bitbucket App Password captures");
    for (size_t i = 1; i <= 2; ++i)
        if (groups[i].begin == SIZE_MAX || groups[i].end <= groups[i].begin || groups[i].end > found->input.len)
            return fail(&found->error, "invalid Bitbucket App Password capture");
    br_slice username = {found->input.data + groups[1].begin, groups[1].end - groups[1].begin};
    br_slice password = {found->input.data + groups[2].begin, groups[2].end - groups[2].begin};
    for (size_t i = 0; i < found->usernames.len; ++i) {
        if (found->usernames.lengths[i] != username.len || memcmp(found->usernames.items[i], username.data, username.len)) continue;
        if (password.len == SIZE_MAX) return fail(&found->error, "Bitbucket App Password capture too large");
        char *replacement = malloc(password.len + 1);
        if (!replacement) return fail(&found->error, "cannot replace Bitbucket App Password capture");
        memcpy(replacement, password.data, password.len); replacement[password.len] = '\0';
        free(found->passwords.items[i]);
        found->passwords.items[i] = replacement; found->passwords.lengths[i] = password.len;
        return 0; /* Case-sensitive username map, last write wins. */
    }
    if (br_captures_push(&found->usernames, username, false, &found->error) ||
        br_captures_push(&found->passwords, password, false, &found->error)) return -1;
    return 0;
}

static int set_cause(br_result *result, const char *cause, br_slice username, br_slice password)
{
    /* Keep the source's sequential replacement order, even when parts overlap. */
    const br_slice secrets[] = {username, password};
    return br_result_set_verification_error(result, cause, secrets, 2) ? -1 : 0;
}

static int verify_credential(const br_scan_ctx *ctx, br_slice username, br_slice password, br_result *result)
{
    if (!ctx) return set_cause(result, "net/http: nil Context", username, password);
    char *auth = NULL, *auth_error = NULL;
    if (br_http_basic_auth(username, password, &auth, &auth_error)) {
        free(auth); free(auth_error);
        return -1; /* Core helpers also use positive 1 for resource failures. */
    }
    const br_header headers[] = {{"Accept", "application/json"}, {"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = "https://api.bitbucket.org/2.0/user",
        .headers = headers, .nheaders = 2, .profile = BR_HTTP_SANE,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    char status_error[80];
    const char *cause = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error)) {
        cause = transport_error ? transport_error : "HTTP transport failed";
    } else {
        switch (response.status) {
        case 200: case 403: result->verified = true; break;
        case 401: break;
        default:
            snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
            cause = status_error;
            break;
        }
    }
    int rc = cause ? set_cause(result, cause, username, password) : 0;
    /* Body/drain/close errors are ignored. ABI1 eager release does not establish
     * native Go deferred streaming/drain/close timing parity. */
    br_http_release(ctx, &response);
    free(transport_error); free(auth_error); free(auth);
    return rc ? -1 : 0;
}

static int scan_app_password(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                             br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Bitbucket App Password scan");
    const app_patterns *compiled = detector->state;
    for (size_t p = 0; p < 3; ++p)
        if (!compiled->patterns[p]) return fail(error, "uninitialized Bitbucket App Password pattern");
    credentials found = {.input = input};
    size_t original_len = out->len;
    char *owned_error = NULL;
    int rc = 0;
    /* Entire P1 pass, then entire P2 pass, then entire P3 pass: never an
     * input-sorted union, unique credential pairs or Cartesian product. */
    for (size_t p = 0; !rc && p < 3; ++p)
        rc = br_regex_each(compiled->patterns[p], input, remember, &found, &owned_error);
    if (found.error) { free(owned_error); owned_error = found.error; }
    static const unsigned char colon[] = ":";
    for (size_t i = 0; !rc && i < found.usernames.len; ++i) {
        br_slice username = br_captures_at(&found.usernames, i), password = br_captures_at(&found.passwords, i);
        br_result result = {0};
        if (br_finding_pair_bytes(&result, detector->type, username, "username", password, "password", (br_slice){colon, 1}))
            rc = fail(&owned_error, "cannot create Bitbucket App Password result");
        if (!rc) {
            free(result.raw.data);
            result.raw = result.raw_v2; result.raw_v2 = (br_bytes){0};
            /* Source Raw is username:password. Do not set primary_secret or
             * offsets to locate a password when assembled Raw is absent. */
            if (verify && verify_credential(ctx, username, password, &result))
                rc = fail(&owned_error, "cannot verify Bitbucket App Password candidate");
        }
        if (!rc && br_results_push(out, &result)) rc = fail(&owned_error, "cannot append Bitbucket App Password result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&found.usernames); br_captures_clear(&found.passwords);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static app_patterns compiled;
static const char *const keywords[] = {"bitbucket", "ATBB"};
static const br_detector app_password = {
    .type = 1029, .version = 0, .name = "BitbucketAppPassword", .custom_name = "",
    .description = "Bitbucket is a Git repository hosting service by Atlassian. Bitbucket App Passwords are used to authenticate to the Bitbucket API.",
    .keywords = keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .state = &compiled, .scan = scan_app_password,
};

int br_bitbucketapppassword_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Bitbucket App Password detector output");
    *out = NULL;
    static const char *const patterns[] = {
        "(?:^|[^A-Za-z0-9-_])(?P<username>[A-Za-z0-9-_]{1,30}):(?P<password>ATBB[A-Za-z0-9_=.-]+)\\b",
        "https://(?P<username>[A-Za-z0-9-_]{1,30}):(?P<password>ATBB[A-Za-z0-9_=.-]+)@bitbucket\\.org",
        /* Go stdlib regexp's ASCII \\s excludes VT. Keep this local; PCRE's
         * \\s is broader. Invalid UTF-8 RuneError/barrier parity is a gap. */
        "\"(?P<username>[A-Za-z0-9-_]{1,30})\",[\\t\\n\\f\\r ]*\"(?P<password>ATBB[A-Za-z0-9_=.-]+)\"",
    };
    for (size_t p = 0; p < 3; ++p)
        if (!compiled.patterns[p] && br_regex_compile(patterns[p], &compiled.patterns[p], error)) return -1;
    *out = &app_password;
    return 0;
}
