/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/couchbase/couchbase.go
 * and pkg/common/patterns.go. */
#include "briar.h"
#include "captures.h"
#include "../go_unicode.h"
#include "../utf8.h"

#include <json-c/json.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *host, *username, *password; } couchbase_patterns;

static int couchbase_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static bool couchbase_cutset(unsigned char c)
{
    return c == '"' || c == '\'' || c == ' ' || c == ')' || c == ',' || c == ';';
}

static int couchbase_trim(br_slice value, br_slice *trimmed, char **error)
{
    size_t begin = 0, end;
    while (begin < value.len) {
        uint32_t rune;
        size_t width = br_utf8_rune((br_slice){value.data + begin, value.len - begin}, &rune);
        if (!width) return couchbase_fail(error, "cannot decode Couchbase capture");
        if (!(br_go_unicode_properties(rune) & BR_GO_SPACE)) break;
        begin += width;
    }
    end = begin;
    for (size_t at = begin; at < value.len;) {
        uint32_t rune;
        size_t width = br_utf8_rune((br_slice){value.data + at, value.len - at}, &rune);
        if (!width) return couchbase_fail(error, "cannot decode Couchbase capture");
        at += width;
        if (!(br_go_unicode_properties(rune) & BR_GO_SPACE)) end = at;
    }
    /* Matches applies TrimSpace once, THEN this ASCII cutset. In particular,
     * removing quotes must not trigger another Unicode whitespace trim. */
    while (begin < end && couchbase_cutset(value.data[begin])) ++begin;
    while (end > begin && couchbase_cutset(value.data[end - 1])) --end;
    *trimmed = (br_slice){value.data + begin, end - begin};
    return 0;
}

static int couchbase_normalize(br_captures *values, bool hosts, bool *empty, char **error)
{
    static const char scheme[] = "couchbases://";
    const size_t prefix = sizeof(scheme) - 1;
    size_t kept = 0;
    for (size_t i = 0; i < values->len; ++i) {
        size_t len = values->lengths[i];
        if (hosts) {
            if (len > SIZE_MAX - prefix - 1)
                return couchbase_fail(error, "Couchbase connection string size overflow");
            char *expanded = realloc(values->items[i], prefix + len + 1);
            if (!expanded) return couchbase_fail(error, "cannot normalize Couchbase host");
            values->items[i] = expanded;
            memmove(expanded + prefix, expanded, len);
            memcpy(expanded, scheme, prefix);
            len += prefix;
        } else {
            br_slice trimmed;
            if (couchbase_trim(br_captures_at(values, i), &trimmed, error) != 0) return -1;
            len = trimmed.len;
            memmove(values->items[i], trimmed.data, len);
        }
        values->items[i][len] = '\0';
        values->lengths[i] = len;
        bool duplicate = false;
        for (size_t j = 0; j < kept; ++j) {
            if (values->lengths[j] == len && !memcmp(values->items[j], values->items[i], len)) {
                duplicate = true;
                break;
            }
        }
        /* br_captures stores nonempty values; a separate set member preserves
         * usernames which become empty AFTER the source's 4-rune capture. */
        if (!len || duplicate) {
            if (!len && empty) *empty = true;
            free(values->items[i]);
            values->items[i] = NULL;
            values->lengths[i] = 0;
        } else {
            if (kept != i) {
                values->items[kept] = values->items[i];
                values->lengths[kept] = len;
                values->items[i] = NULL;
                values->lengths[i] = 0;
            }
            ++kept;
        }
    }
    values->len = kept;
    return 0;
}

static int couchbase_password_valid(br_slice password, bool *valid, char **error)
{
    unsigned found = 0;
    for (size_t at = 0; at < password.len;) {
        uint32_t rune;
        size_t width = br_utf8_rune((br_slice){password.data + at, password.len - at}, &rune);
        if (!width) return couchbase_fail(error, "cannot decode Couchbase password");
        unsigned flags = br_go_unicode_properties(rune);
        if (flags & BR_GO_LOWER) found |= 1u;
        else if (flags & BR_GO_UPPER) found |= 2u;
        else if (flags & BR_GO_NUMBER) found |= 4u;
        else if (flags & (BR_GO_PUNCT | BR_GO_SYMBOL)) found |= 8u;
        at += width;
    }
    *valid = found == 15u;
    return 0;
}

static int couchbase_add_part(br_result *result, const char *name, br_slice value, char **error)
{
    /* json-c's length parameter is int; fail explicitly rather than truncate. */
    if (value.len > INT_MAX)
        return couchbase_fail(error, "Couchbase secret part exceeds native JSON string size");
    br_json *part = json_object_new_string_len((const char *)value.data, (int)value.len);
    if (!part) return couchbase_fail(error, "cannot create Couchbase secret part");
    if (json_object_object_add(result->secret_parts, name, part) != 0) {
        json_object_put(part);
        return couchbase_fail(error, "cannot add Couchbase secret part");
    }
    return 0;
}

static int couchbase_result(br_result *result, int32_t type, br_slice host,
                            br_slice username, br_slice password, bool verify, char **error)
{
    if (password.len > SIZE_MAX - username.len)
        return couchbase_fail(error, "Couchbase raw size overflow");
    size_t len = username.len + password.len;
    if (len > SIZE_MAX - 2 || host.len > SIZE_MAX - len - 2)
        return couchbase_fail(error, "Couchbase raw size overflow");
    len += 2 + host.len;
    result->detector_type = type;
    result->raw.data = malloc(len);
    if (!result->raw.data) return couchbase_fail(error, "cannot create Couchbase raw");
    result->raw.len = len;
    size_t at = 0;
    memcpy(result->raw.data, username.data, username.len); at += username.len;
    result->raw.data[at++] = ':';
    memcpy(result->raw.data + at, password.data, password.len); at += password.len;
    result->raw.data[at++] = '@';
    memcpy(result->raw.data + at, host.data, host.len);
    result->secret_parts = json_object_new_object();
    if (!result->secret_parts) return couchbase_fail(error, "cannot create Couchbase secret parts");
    if (couchbase_add_part(result, "host", host, error) != 0 ||
        couchbase_add_part(result, "username", username, error) != 0 ||
        couchbase_add_part(result, "password", password, error) != 0) return -1;
    if (verify) {
        /* HTTP cannot represent gocb v2.11.0's wan-development profile,
         * Connect and 5s Ping (any service endpoint OK). No substitute probe.
         * Source ignores ctx and passes NO redaction arguments to its setter. */
        if (br_result_set_verification_error(result,
                "unsupported: Couchbase native SDK verification is not implemented", NULL, 0) != 0)
            return couchbase_fail(error, "cannot set Couchbase verification error");
        result->primary_secret.data = malloc(host.len);
        if (!result->primary_secret.data)
            return couchbase_fail(error, "cannot create Couchbase primary secret");
        memcpy(result->primary_secret.data, host.data, host.len);
        result->primary_secret.len = host.len;
    }
    return 0;
}

static int couchbase_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                          br_slice input, br_results *out, char **error)
{
    (void)ctx; /* verifyCouchBase does not take the FromData context. */
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return couchbase_fail(error, "invalid or uninitialized Couchbase scan");
    /* UsernameRegexCheck/PasswordRegexCheck use Go stdlib regexp, unlike the
     * host's go-re2 pattern. Its invalid-byte RuneError behavior is not ported;
     * do not return partial findings or normalize through the PLAIN decoder. */
    if (!br_utf8_valid(input))
        return couchbase_fail(error, "unsupported: Couchbase extraction of invalid UTF-8 input is not implemented");
    const couchbase_patterns *patterns = detector->state;
    if (!patterns->host || !patterns->username || !patterns->password)
        return couchbase_fail(error, "uninitialized Couchbase patterns");
    size_t original_len = out->len;
    br_captures hosts = {0}, usernames = {0}, passwords = {0};
    bool empty_username = false;
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->host, input, &hosts, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->username, input, &usernames, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->password, input, &passwords, false, &owned_error);
    if (rc == 0) rc = couchbase_normalize(&hosts, true, NULL, &owned_error);
    if (rc == 0) rc = couchbase_normalize(&usernames, false, &empty_username, &owned_error);
    if (rc == 0) rc = couchbase_normalize(&passwords, false, NULL, &owned_error);
    size_t nusers = usernames.len;
    if (rc == 0 && empty_username) {
        if (nusers == SIZE_MAX) rc = couchbase_fail(&owned_error, "too many Couchbase usernames");
        else ++nusers;
    }
    for (size_t h = 0; rc == 0 && h < hosts.len; ++h) {
        br_slice host = br_captures_at(&hosts, h);
        for (size_t u = 0; rc == 0 && u < nusers; ++u) {
            br_slice username = u < usernames.len ? br_captures_at(&usernames, u) :
                (br_slice){(const unsigned char *)"", 0};
            for (size_t p = 0; rc == 0 && p < passwords.len; ++p) {
                br_slice password = br_captures_at(&passwords, p);
                bool valid = false;
                rc = couchbase_password_valid(password, &valid, &owned_error);
                if (rc != 0 || !valid) continue;
                br_result result = {0};
                rc = couchbase_result(&result, detector->type, host, username, password, verify, &owned_error);
                if (rc == 0 && br_results_push(out, &result) != 0)
                    rc = couchbase_fail(&owned_error, "cannot append Couchbase result");
                br_result_clear(&result);
            }
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&hosts);
    br_captures_clear(&usernames);
    br_captures_clear(&passwords);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static couchbase_patterns couchbase_compiled;
static const char *const couchbase_keywords[] = {"couchbase://", "couchbases://"};
static const br_detector couchbase_detector = {
    .type = 920, .version = 0, .name = "Couchbase", .custom_name = "",
    .description = "Couchbase is a distributed NoSQL cloud database. Couchbase credentials can be used to access and modify data within the Couchbase database.",
    .keywords = couchbase_keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &couchbase_compiled, .scan = couchbase_scan,
};

int br_couchbase_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return couchbase_fail(error, "invalid Couchbase detector output");
    *out = NULL;
    if (!couchbase_compiled.host) {
        couchbase_patterns compiled = {0};
        /* Preserve Go stdlib's SimpleFold for keyword letters explicitly (s
         * also folds to long-s), without PCRE's newer Unicode caseless tables.
         * Go \\s is EXACTLY HT/LF/FF/CR/SPACE, not VT. The source's %+v inserts
         * its exclusions unchanged: \\+ escapes '+', not a literal backslash.
         * Keep alternation order, lazy prefix, greedy rune captures, and only
         * the username's trailing ASCII word boundary. */
        if (br_regex_compile("\\b(cb\\.[a-z0-9]+\\.cloud\\.couchbase\\.com)\\b", &compiled.host, error) != 0 ||
            br_regex_compile(
                "(?:[uU][sS\\x{017F}][eE][rR]|[uU][sS\\x{017F}][rR])"
                "[^\\x09\\x0a\\x0c\\x0d ]{0,40}?[:=\\x09\\x0a\\x0c\\x0d ]{1,3}[ '\"=]{0,1}"
                "([^:?()/+=\\x09\\x0a\\x0c\\x0d ]{4,40})\\b", &compiled.username, error) != 0 ||
            br_regex_compile(
                "(?:[pP][aA][sS\\x{017F}][sS\\x{017F}]|[pP][aA][sS\\x{017F}][sS\\x{017F}][wW][oO][rR][dD])"
                "[^\\x09\\x0a\\x0c\\x0d ]{0,40}?[:=\\x09\\x0a\\x0c\\x0d ]{1,3}[ '\"=]{0,1}"
                "([^:^<>;.*&|\\x{00a3}\\x09\\x0a\\x0c\\x0d ]{4,40})", &compiled.password, error) != 0) {
            br_regex_free(compiled.host);
            br_regex_free(compiled.username);
            br_regex_free(compiled.password);
            return -1;
        }
        couchbase_compiled = compiled;
    }
    *out = &couchbase_detector;
    return 0;
}
