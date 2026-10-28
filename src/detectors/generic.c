/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/generic/generic.go. */
#include "detectors.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static const char *const keywords[] = {"pass", "token", "cred", "secret", "key"};
static const char *const exclude_patterns[] = {
    "[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}",
    "[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}",
    "[A-Z]{2,6}\\-[0-9]{2,6}",
    "#[a-fA-F0-9]{6}\\b",
    "\\b[A-Fa-f0-9]{64}\\b",
    "https?:\\/\\/(www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}\\b([-a-zA-Z0-9()@:%_\\+.~#?&//=]*)",
    "\\b([/]{0,1}([\\w]+[/])+[\\w\\.]*)\\b",
    "([0-9A-F]{2}[:-]){5}([0-9A-F]{2})",
    "\\d{4}[-/]{1}([0]\\d|1[0-2])[-/]{1}([0-2]\\d|3[01])",
    "[v|\\-]\\d\\.\\d",
    "\\d\\.\\d\\.\\d-",
    "[\\d]{1,3}\\.[\\d]{1,3}\\.[\\d]{1,3}\\.[\\d]{1,3}",
    "[A-Fa-f0-9x]{2}:[A-Fa-f0-9x]{2}:[A-Fa-f0-9x]{2}",
    "[\\w]+\\([\\w, ]+\\)",
};

typedef struct {
    br_regex *key;
    br_regex *exclude[sizeof(exclude_patterns) / sizeof(exclude_patterns[0])];
    size_t nexclude;
} generic_state;

typedef struct {
    const generic_state *state;
    br_slice input;
    br_results *out;
    char *error;
} generic_matches;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int first_match(void *user, const br_span *groups, size_t ngroups)
{
    (void)groups;
    (void)ngroups;
    *(bool *)user = true;
    return 1;
}

/* br_regex_each uses positive callback returns for early stop as well as
 * resource errors. Only the callback's own positive stop is a match. */
static int excluded(const generic_state *state, br_slice token, char **error)
{
    for (size_t i = 0; i < state->nexclude; ++i) {
        bool found = false;
        char *detail = NULL;
        int rc = br_regex_each(state->exclude[i], token, first_match, &found, &detail);
        /* The iterator allocates a diagnostic even for callback stops;
         * failure of that allocation must not become an ordinary drop. */
        if (rc != 0 && !(rc == 1 && found && detail)) {
            if (error) *error = detail;
            else free(detail);
            return -1;
        }
        free(detail);
        if (found) return 1;
    }
    return 0;
}

/* Captures contain printable ASCII only. StdEncoding is padded, but its
 * default (non-strict) decoder accepts nonzero unused padding bits. No
 * decoded bytes are needed, and CR/LF cannot occur in these captures. */
static bool standard_base64(br_slice token)
{
    if (token.len % 4) return false;
    size_t end = token.len;
    if (end && token.data[end - 1] == '=') --end;
    if (end && token.data[end - 1] == '=') --end;
    for (size_t i = 0; i < end; ++i) {
        unsigned char c = token.data[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '+' || c == '/')) return false;
    }
    return true;
}

static bool containment(unsigned char c)
{
    return c && strchr("`\" '.,)(][}{", c) != NULL;
}

static int emit_generic(void *user, const br_span *groups, size_t ngroups)
{
    generic_matches *matches = user;
    if (ngroups < 2 || groups[1].begin == SIZE_MAX ||
        groups[1].end <= groups[1].begin || groups[1].end > matches->input.len)
        return fail(&matches->error, "invalid Generic capture");
    br_slice token = {matches->input.data + groups[1].begin,
                      groups[1].end - groups[1].begin};
    int rc = excluded(matches->state, token, &matches->error);
    if (rc < 0) return -1;
    if (rc > 0) return 0;
    while (token.len && containment(token.data[0])) {
        ++token.data;
        --token.len;
    }
    while (token.len && containment(token.data[token.len - 1])) --token.len;
    if (standard_base64(token)) return 0;

    br_result result = {0};
    if (br_finding_key_bytes(&result, 7, token, "key") != 0)
        return fail(&matches->error, "out of memory creating Generic result");
    if (br_results_push(matches->out, &result) != 0) {
        br_result_clear(&result);
        return fail(&matches->error, "cannot append Generic result");
    }
    return 0;
}

static int scan_generic(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    (void)ctx;
    (void)verify;
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Generic scan");
    const generic_state *state = detector->state;
    if (!state->key) return fail(error, "uninitialized Generic pattern");
    size_t original_len = out->len;
    generic_matches matches = {state, input, out, NULL};
    char *detail = NULL;
    int rc = br_regex_each(state->key, input, emit_generic, &matches, &detail);
    if (matches.error) {
        free(detail);
        detail = matches.error;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    if (error) *error = detail;
    else free(detail);
    return rc == 0 ? 0 : -1;
}

static const br_detector descriptor = {
    .type = 7, .version = 0, .name = "Generic", .custom_name = "",
    .description = "Generic secret key that may provide access to sensitive data or systems.",
    .keywords = keywords, .nkeywords = sizeof(keywords) / sizeof(keywords[0]),
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_generic,
};
static generic_state zero_state, new_state;
static br_detector zero_detector, new_detector;

static int init_generic(br_detector *detector, generic_state *state, bool with_exclusions,
                        const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Generic detector output");
    *out = NULL;
    if (!state->key) {
        generic_state pending = {0};
        if (br_regex_compile_prefixed(keywords, sizeof(keywords) / sizeof(keywords[0]),
                                      "(\\b[\\x21-\\x7e]{16,64}\\b)", &pending.key, error) != 0)
            return -1;
        if (with_exclusions) {
            for (size_t i = 0; i < sizeof(exclude_patterns) / sizeof(exclude_patterns[0]); ++i) {
                if (br_regex_compile(exclude_patterns[i], &pending.exclude[i], error) != 0) {
                    for (size_t j = 0; j < pending.nexclude; ++j) br_regex_free(pending.exclude[j]);
                    br_regex_free(pending.key);
                    return -1;
                }
                ++pending.nexclude;
            }
        }
        *state = pending;
        *detector = descriptor;
        detector->state = state;
    }
    *out = detector;
    return 0;
}

int br_generic_init(const br_detector **out, char **error)
{
    return init_generic(&zero_detector, &zero_state, false, out, error);
}

int br_generic_new_init(const br_detector **out, char **error)
{
    return init_generic(&new_detector, &new_state, true, out, error);
}
