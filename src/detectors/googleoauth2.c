/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2 googleoauth2/googleoauth2_access_token.go.
 * Selected Go string/time behavior: LICENSES/BSD-3-Clause-Go.txt. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "gcp_json.h"
#include "json.h"

#include <json-c/json.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int oauth_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

typedef struct { br_json *ref; br_slice text; br_bytes repair; } oauth_string;
typedef struct {
    oauth_string fields[5];
    bool bad_request;
    char *cause;
    char **fatal;
} oauth_record;
static const char *const oauth_tags[] = {"exp", "scope", "email", "email_verified", "access_type"};
static const char *const oauth_paths[] = {"tokenInfo.exp", "tokenInfo.scope", "tokenInfo.email", "tokenInfo.email_verified", "tokenInfo.access_type"};

static void oauth_string_clear(oauth_string *s)
{
    json_object_put(s->ref); free(s->repair.data); *s = (oauth_string){0};
}
static void oauth_record_clear(oauth_record *r)
{
    for (size_t i = 0; i < 5; ++i) oauth_string_clear(&r->fields[i]);
    free(r->cause);
}
static int oauth_member(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)encoded;
    oauth_record *r = user;
    size_t count = r->bad_request ? 1 : 5;
    for (size_t i = 0; i < count; ++i) {
        if (!br_json_field_name(name, r->bad_request ? "error_description" : oauth_tags[i])) continue;
        if (!value) return 0; /* null does not overwrite an earlier string. */
        if (!json_object_is_type(value, json_type_string)) {
            if (!r->cause && br_json_type_cause(value, r->bad_request ? "errorInfo.error_description" : oauth_paths[i], "string", &r->cause))
                return oauth_fail(r->fatal, "cannot allocate GoogleOauth2 type cause");
            return 0; /* First type error sticks, but subsequent members decode. */
        }
        oauth_string next = {0};
        if (br_gcp_json_text(value, &next.text, &next.repair, r->fatal)) {
            free(next.repair.data); return -1;
        }
        next.ref = json_object_get(value); /* Ordered-visitor values are ephemeral. */
        oauth_string_clear(&r->fields[i]); r->fields[i] = next;
        return 0;
    }
    return 0;
}
static int oauth_decode(const br_http_response *response, oauth_record *r, char **error)
{
    br_json *root = NULL; size_t end = 0;
    int rc = br_json_first_document(response->body, response->body_error, &root, &end, &r->cause);
    if (rc < 0) { json_object_put(root); return oauth_fail(error, "cannot decode GoogleOauth2 response"); }
    if (rc) { json_object_put(root); return 1; }
    if (root && !json_object_is_type(root, json_type_object)) {
        rc = br_json_type_cause(root, NULL, r->bad_request ? "googleoauth2.errorInfo" : "googleoauth2.tokenInfo", &r->cause);
        json_object_put(root);
        return rc ? oauth_fail(error, "cannot allocate GoogleOauth2 root type cause") : 1;
    }
    r->fatal = error;
    rc = root ? br_json_each_member((br_slice){response->body.data, end}, oauth_member, r) : 0;
    json_object_put(root);
    if (rc) return oauth_fail(error && *error ? NULL : error, "cannot project GoogleOauth2 response");
    return r->cause ? 1 : 0;
}

/* ParseInt(base=10, bitSize=64): no whitespace, underscores or C-string truncation. */
static bool oauth_expiry(br_slice text, int64_t *out)
{
    size_t i = 0; bool negative = false;
    if (text.len && (text.data[0] == '+' || text.data[0] == '-')) negative = text.data[i++] == '-';
    if (i == text.len) return false;
    uint64_t n = 0, limit = (uint64_t)INT64_MAX + negative;
    for (; i < text.len; ++i) {
        unsigned char c = text.data[i];
        if (c < '0' || c > '9') return false;
        unsigned d = c - '0';
        if (n > (limit - d) / 10) return false;
        n = n * 10 + d;
    }
    *out = negative ? (n == (uint64_t)INT64_MAX + 1 ? INT64_MIN : -(int64_t)n) : (int64_t)n;
    return true;
}
static int oauth_time(int64_t seconds, char output[30], char **error)
{
    /* Go Unix selects Local. This is only the explicitly stable UTC subset,
     * not libc localtime equivalence, and never mutates process timezone state. */
    const char *tz = getenv("TZ");
    if (!tz || (*tz && strcmp(tz, "UTC")))
        return oauth_fail(error, "unsupported: GoogleOauth2 expiry requires explicit stable TZ=UTC or empty TZ");
    if (seconds < INT64_C(-62135596800) || seconds > INT64_C(253402300799))
        return oauth_fail(error, "unsupported: GoogleOauth2 expiry outside calendar years 0001..9999");
    time_t stamp = (time_t)seconds;
    if (((time_t)-1 > 0 && seconds < 0) || (int64_t)stamp != seconds)
        return oauth_fail(error, "unsupported: GoogleOauth2 expiry time_t representation");
    struct tm t;
    if (!gmtime_r(&stamp, &t) || t.tm_year < -1899 || t.tm_year > 8099 ||
        t.tm_mon < 0 || t.tm_mon > 11 || t.tm_mday < 1 || t.tm_mday > 31 ||
        t.tm_hour < 0 || t.tm_hour > 23 || t.tm_min < 0 || t.tm_min > 59 || t.tm_sec < 0 || t.tm_sec > 59)
        return oauth_fail(error, "unsupported: GoogleOauth2 expiry calendar representation");
    if (snprintf(output, 30, "%04d-%02d-%02d %02d:%02d:%02d +0000 UTC", t.tm_year + 1900,
                 t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec) != 29)
        return oauth_fail(error, "unsupported: GoogleOauth2 expiry output representation");
    return 0;
}
static int oauth_extra_add(br_json *extra, const char *name, br_slice text, char **error)
{
    if (text.len > INT_MAX) return oauth_fail(error, "GoogleOauth2 metadata exceeds JSON string representation");
    br_json *value = json_object_new_string_len(text.data ? (const char *)text.data : "", (int)text.len);
    if (!value) return oauth_fail(error, "cannot allocate GoogleOauth2 metadata string");
    if (json_object_object_add(extra, name, value)) {
        json_object_put(value); return oauth_fail(error, "cannot insert GoogleOauth2 metadata");
    }
    return 0;
}
static int oauth_metadata(oauth_record *record, br_json **out, char **error)
{
    static const char *const names[] = {"google_email", "email_verified", "scope", "access_type"};
    static const size_t indices[] = {2, 3, 1, 4};
    *out = json_object_new_object();
    if (!*out) return oauth_fail(error, "cannot allocate GoogleOauth2 metadata");
    for (size_t i = 0; i < 4; ++i)
        if (oauth_extra_add(*out, names[i], record->fields[indices[i]].text, error)) return -1;
    int64_t expiry;
    if (oauth_expiry(record->fields[0].text, &expiry)) {
        char text[30];
        if (oauth_time(expiry, text, error)) return -1;
        if (oauth_extra_add(*out, "expires_at", (br_slice){(const unsigned char *)text, 29}, error)) return -1;
    }
    return 0;
}
static int oauth_description_cause(br_slice description, const char *url, char **cause, char **error)
{
    static const char prefix[] = "unexpected error description '", middle[] = "' for ";
    /* A final description NUL cannot pass ABI1's error setter. Type errors win. */
    if (description.len && memchr(description.data, 0, description.len))
        return oauth_fail(error, "unsupported: GoogleOauth2 error description contains NUL");
    size_t u = strlen(url), fixed = sizeof(prefix) - 1 + sizeof(middle);
    if (description.len > SIZE_MAX - fixed || u > SIZE_MAX - fixed - description.len)
        return oauth_fail(error, "GoogleOauth2 error cause size overflow");
    *cause = malloc(fixed + description.len + u);
    if (!*cause) return oauth_fail(error, "cannot allocate GoogleOauth2 description cause");
    size_t at = sizeof(prefix) - 1;
    memcpy(*cause, prefix, at);
    if (description.len) memcpy(*cause + at, description.data, description.len);
    at += description.len;
    memcpy(*cause + at, middle, sizeof(middle) - 1); at += sizeof(middle) - 1;
    memcpy(*cause + at, url, u + 1);
    return 0;
}
static int oauth_verify(const br_scan_ctx *ctx, br_slice key, br_result *result, char **error)
{
    static const char prefix[] = "https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=";
    if (key.len > SIZE_MAX - sizeof(prefix)) return oauth_fail(error, "GoogleOauth2 URL size overflow");
    char *url = malloc(sizeof(prefix) + key.len);
    if (!url) return oauth_fail(error, "cannot allocate GoogleOauth2 URL");
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, key.data, key.len); url[sizeof(prefix) - 1 + key.len] = 0;
    int rc = 0; char *cause = NULL; br_json *extra = NULL; bool verified = false;
    if (!ctx) {
        cause = strdup("net/http: nil Context");
        if (!cause) rc = oauth_fail(error, "cannot allocate GoogleOauth2 constructor cause");
    } else {
        const br_http_request request = {.method = "GET", .url = url, .profile = BR_HTTP_SANE, .detector_type = 69};
        br_http_response response = {0};
        int sent = br_http_send(ctx, &request, &response, &cause);
        if (!sent) {
            free(cause); cause = NULL;
            if (response.status == 200 || response.status == 400) {
                oauth_record record = {.bad_request = response.status == 400};
                int decoded = oauth_decode(&response, &record, error);
                if (decoded < 0) rc = -1;
                else if (decoded) { cause = record.cause; record.cause = NULL; }
                else if (response.status == 200) {
                    rc = oauth_metadata(&record, &extra, error);
                    if (!rc) verified = true;
                } else {
                    br_slice text = record.fields[0].text;
                    if (text.len != 13 || memcmp(text.data, "Invalid Value", 13))
                        rc = oauth_description_cause(text, url, &cause, error);
                }
                oauth_record_clear(&record);
            } else {
                char number[32]; int n = snprintf(number, sizeof(number), "%d", response.status);
                static const char p[] = "unexpected response ", m[] = " for ";
                size_t u = strlen(url), fixed = sizeof(p) - 1 + sizeof(m);
                if (n < 0 || (size_t)n >= sizeof(number) || u > SIZE_MAX - fixed - (size_t)n)
                    rc = oauth_fail(error, "GoogleOauth2 status cause size overflow");
                else {
                    cause = malloc(fixed + (size_t)n + u);
                    if (!cause) rc = oauth_fail(error, "cannot allocate GoogleOauth2 status cause");
                    else {
                        size_t at = sizeof(p) - 1; memcpy(cause, p, at);
                        memcpy(cause + at, number, (size_t)n); at += (size_t)n;
                        memcpy(cause + at, m, sizeof(m) - 1); at += sizeof(m) - 1;
                        memcpy(cause + at, url, u + 1);
                    }
                }
            }
        }
        /* Ordinary ABI1 synthesized headers/UA end at send; only our URL is
         * retained here. Release once even on shared preparation/Do failures. */
        br_http_release(ctx, &response);
    }
    if (!rc) {
        result->verified = verified;
        json_object_put(result->extra_data); result->extra_data = extra; extra = NULL;
        /* Source setter unwraps the known decode envelope. Causes above are
         * already underlying causes; arbitrary injected text is never stripped. */
        if (br_result_set_verification_error(result, cause, NULL, 0))
            rc = oauth_fail(error, "cannot set GoogleOauth2 verification error");
    }
    json_object_put(extra); free(cause); free(url);
    return rc;
}
static int oauth_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return oauth_fail(error, "invalid or uninitialized GoogleOauth2 scan");
    size_t original = out->len; br_captures keys = {0}; char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &keys, true, &owned_error);
    for (size_t i = 0; !rc && i < keys.len; ++i) {
        br_result result = {0}; br_slice key = br_captures_at(&keys, i);
        if (br_finding_key_bytes(&result, detector->type, key, "key"))
            rc = oauth_fail(&owned_error, "cannot create GoogleOauth2 result");
        if (!rc && verify) rc = oauth_verify(ctx, key, &result, &owned_error);
        if (!rc && br_results_push(out, &result)) rc = oauth_fail(&owned_error, "cannot append GoogleOauth2 result");
        br_result_clear(&result);
    }
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    if (error) *error = owned_error; else free(owned_error);
    return rc ? -1 : 0;
}
static const char *const oauth_keywords[] = {"ya29."};
static br_detector oauth_detector = {
    .type = 69, .version = 0, .name = "GoogleOauth2", .custom_name = "",
    .description = "Google OAuth 2.0 tokens are used for authenticating and authorizing access to Google APIs and services.",
    .keywords = oauth_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1, .scan = oauth_scan,
};
int br_googleoauth2_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return oauth_fail(error, "invalid GoogleOauth2 detector output");
    *out = NULL;
    if (!oauth_detector.state) {
        br_regex *regex = NULL;
        if (br_regex_compile("\\b(ya29\\.(?i:[a-z0-9_-]{10,}))(?:[^a-z0-9_-]|\\z)", &regex, error)) return -1;
        oauth_detector.state = regex;
    }
    *out = &oauth_detector;
    return 0;
}
