/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, MicrosoftTeamsWebhook v1/v2. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "gcp_oauth.h"
#include "../go_url.h"
#include "../go_unicode.h"
#include "../utf8.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Wrapped constructor/Do errors retain explicit ownership/provenance. The
 * source setter unwraps these nodes and stores the leaf, never guessed text. */
typedef struct { br_bytes leaf, wrapped; } teams_error;
typedef struct { bool verified; teams_error error; } teams_verdict;
static const unsigned char teams_payload_v1[] = "{'text':''}";
static const unsigned char teams_payload_v2[] = "{\"text\":\"\"}";
_Static_assert(sizeof(teams_payload_v1) == 12 && sizeof(teams_payload_v2) == 12, "source payload lengths");

static int teams_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int teams_concat(const char *prefix, br_slice value, br_bytes *out, char **error)
{
    size_t n = strlen(prefix);
    if ((!value.data && value.len) || n == SIZE_MAX || value.len > SIZE_MAX - n - 1)
        return teams_fail(error, "Microsoft Teams cause is too large or invalid");
    out->data = malloc(n + value.len + 1);
    if (!out->data) return teams_fail(error, "cannot allocate Microsoft Teams cause");
    memcpy(out->data, prefix, n);
    if (value.len) memcpy(out->data + n, value.data, value.len);
    out->len = n + value.len; out->data[out->len] = 0;
    return 0;
}

static int teams_leaf(const char *message, teams_error *out, char **error)
{
    return teams_concat("", (br_slice){(const unsigned char *)message, strlen(message)}, &out->leaf, error);
}

static int teams_wrap(teams_error *out, const char *prefix, char **error)
{
    return teams_concat(prefix, (br_slice){out->leaf.data, out->leaf.len}, &out->wrapped, error);
}

static void teams_error_clear(teams_error *error)
{
    free(error->leaf.data); free(error->wrapped.data);
}

/* This fixed negated query class uses RE2 2024-07-02 Add_80_10ffff,
 * whose bytecode accepts E0/F0 overlong, ED surrogate and F4 above-max units.
 * It is deliberately NOT strict UTF8 decoding or an unrestricted byte class. */
static size_t teams_query_unit(br_slice rest)
{
    if (!rest.len) return 0;
    unsigned char c = rest.data[0];
    if (c < 128) return c == 9 || c == 10 || c == 12 || c == 13 || c == 32 ||
        c == 34 || c == 39 || c == 60 || c == 62 ? 0 : 1;
    size_t width = c >= 0xc2 && c <= 0xdf ? 2 : c >= 0xe0 && c <= 0xef ? 3 :
        c >= 0xf0 && c <= 0xf4 ? 4 : 0;
    if (!width || rest.len < width) return 0;
    for (size_t i = 1; i < width; ++i) if (rest.data[i] < 0x80 || rest.data[i] > 0xbf) return 0;
    return width;
}

typedef struct {
    br_slice input;
    br_captures *raw;
    size_t consumed_end;
    char *error;
} teams_query_matches;

static int teams_query_match(void *user, const br_span *groups, size_t count)
{
    teams_query_matches *matches = user;
    if (!count || groups[0].begin == SIZE_MAX || groups[0].begin > groups[0].end || groups[0].end > matches->input.len)
        return teams_fail(&matches->error, "invalid Microsoft Teams base match");
    if (groups[0].begin < matches->consumed_end) return 0;
    size_t end = groups[0].end;
    for (;;) {
        size_t width = teams_query_unit((br_slice){matches->input.data + end, matches->input.len - end});
        if (!width) break;
        end += width;
    }
    if (end == groups[0].end) return 0; /* Failed query1+ consumes no full URL. */
    /* Source FindAll advances by the FULL UNTRIMMED match, even if signature
     * filtering later rejects it. A nested base is not another occurrence. */
    matches->consumed_end = end;
    return br_captures_push(matches->raw,
        (br_slice){matches->input.data + groups[0].begin, end - groups[0].begin}, false, &matches->error);
}

static int teams_collect_v2(const br_regex *base, br_slice input, br_captures *raw, char **error)
{
    teams_query_matches matches = {.input = input, .raw = raw};
    char *regex_error = NULL;
    int rc = br_regex_each(base, input, teams_query_match, &matches, &regex_error);
    if (matches.error) { free(regex_error); regex_error = matches.error; }
    if (error) *error = regex_error; else free(regex_error);
    return rc;
}

static bool teams_has_sig(br_slice raw)
{
    /* MatchString over the ENTIRE raw URL, including fragment. Only a matching
     * prefix of the value is required; no query decoding or normalization. */
    for (size_t i = 0; i < raw.len; ++i) {
        if (raw.len - i < 6 || (raw.data[i] != '?' && raw.data[i] != '&') || memcmp(raw.data + i + 1, "sig=", 4)) continue;
        unsigned char c = raw.data[i + 5];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '_' || c == '-') return true;
    }
    return false;
}

static br_slice teams_trim(br_slice raw)
{
    /* This grammar starts with https, so only trailing space is reachable.
     * Invalid UTF8 has width0: consume ONE ORIGINAL byte as nonspace. */
    size_t last = 0;
    for (size_t at = 0; at < raw.len;) {
        uint32_t rune = 0;
        size_t width = br_utf8_rune((br_slice){raw.data + at, raw.len - at}, &rune);
        bool space = width && (br_go_unicode_properties(rune) & BR_GO_SPACE);
        at += width ? width : 1;
        if (!space) last = at;
    }
    return (br_slice){raw.data, last};
}

static int teams_put(br_json *object, const char *name, const char *value)
{
    br_json *string = json_object_new_string(value);
    if (!string) return -1;
    if (json_object_object_add(object, name, string) != 0) { json_object_put(string); return -1; }
    return 0;
}

static int teams_extra(br_result *result, int version)
{
    result->extra_data = json_object_new_object();
    if (!result->extra_data) return -1;
    if (version == 1 && teams_put(result->extra_data, "rotation_guide", "https://howtorotate.com/docs/tutorials/microsoftteams/") != 0) return -1;
    return teams_put(result->extra_data, "version", version == 1 ? "1" : "2");
}

static int teams_constructor_cause(br_go_url_error ordinary, teams_error *out, char **error)
{
    if (ordinary.kind == BR_GO_URL_CONTROL)
        return teams_leaf("net/url: invalid control character in URL", out, error);
    if (ordinary.kind != BR_GO_URL_ESCAPE)
        return teams_fail(error, "unsupported: Microsoft Teams URL rejection outside source grammar");
    size_t quoted = 0;
    int rc = br_gcp_oauth_quote(ordinary.detail, NULL, 0, &quoted, error);
    static const char prefix[] = "invalid URL escape ";
    if (rc != 0) return rc;
    if (quoted > SIZE_MAX - sizeof(prefix)) return teams_fail(error, "Microsoft Teams URL cause is too large");
    out->leaf.data = malloc(sizeof(prefix) + quoted);
    if (!out->leaf.data) return teams_fail(error, "cannot allocate Microsoft Teams URL cause");
    memcpy(out->leaf.data, prefix, sizeof(prefix) - 1);
    size_t written = 0;
    rc = br_gcp_oauth_quote(ordinary.detail, out->leaf.data + sizeof(prefix) - 1, quoted, &written, error);
    if (rc != 0) return rc;
    out->leaf.len = sizeof(prefix) - 1 + written; out->leaf.data[out->leaf.len] = 0;
    return 0;
}

static bool teams_fragment_encoded(br_slice raw)
{
    for (size_t i = 0; i < raw.len; ++i) {
        unsigned char c = raw.data[i];
        if (c && strchr("!$&'()*+,;=:@[]%", c)) continue;
        if (!br_go_url_byte_allowed(c, BR_GO_URL_FRAGMENT)) return false;
    }
    return true;
}

static int teams_project(br_slice original, const br_go_url_parts *parsed,
                           br_bytes *projected, const char **request_url, char **error)
{
    *request_url = (const char *)original.data;
    const unsigned char *hash = memchr(original.data, '#', original.len);
    if (!hash) return 0;
    size_t prefix_len = (size_t)(hash - original.data);
    br_bytes decoded = {0}; bool valid = false;
    int rc = br_go_url_decode(parsed->raw_fragment, false, &decoded, &valid, error);
    if (rc == 0 && !valid) rc = teams_fail(error, "invalid already-parsed Microsoft Teams fragment");
    bool keep_raw = rc == 0 && teams_fragment_encoded(parsed->raw_fragment);
    if (rc == 0 && decoded.len && keep_raw) { free(decoded.data); return 0; }
    /* Only fragment can change in the strict v2 grammar. Preserve the complete
     * original RawQuery, including plus/percent/Unicode/invalid original bytes. */
    size_t n = prefix_len;
    if (rc == 0 && decoded.len) {
        if (n >= SIZE_MAX - 1) rc = -1;
        else ++n;
        for (size_t i = 0; rc == 0 && i < decoded.len; ++i) {
            size_t width = br_go_url_byte_allowed(decoded.data[i], BR_GO_URL_FRAGMENT) ? 1 : 3;
            if (width > SIZE_MAX - n - 1) rc = -1;
            else n += width;
        }
    }
    if (rc == 0 && (n == SIZE_MAX || !(projected->data = malloc(n + 1)))) rc = -1;
    if (rc == 0) {
        memcpy(projected->data, original.data, prefix_len); size_t at = prefix_len;
        static const char hex[] = "0123456789ABCDEF";
        if (decoded.len) projected->data[at++] = '#';
        for (size_t i = 0; i < decoded.len; ++i) {
            unsigned char c = decoded.data[i];
            if (br_go_url_byte_allowed(c, BR_GO_URL_FRAGMENT)) projected->data[at++] = c;
            else { projected->data[at++] = '%'; projected->data[at++] = (unsigned char)hex[c >> 4]; projected->data[at++] = (unsigned char)hex[c & 15]; }
        }
        projected->len = at; projected->data[at] = 0; *request_url = (const char *)projected->data;
    }
    free(decoded.data);
    if (rc != 0) teams_fail(error, "cannot project Microsoft Teams fragment");
    return rc;
}

static int teams_status_cause(int status, int version, teams_error *out, char **error)
{
    char message[80];
    int n = snprintf(message, sizeof(message), version == 1 ? "unexpected HTTP response status: %d" : "unexpected HTTP response status %d", status);
    if (n < 0 || (size_t)n >= sizeof(message)) return teams_fail(error, "cannot format Microsoft Teams status");
    return teams_leaf(message, out, error);
}

static int teams_verify(const br_scan_ctx *ctx, int version, br_slice secret,
                         teams_verdict *verdict, char **error)
{
    /* Reader/payload construction precedes nil-context/URL constructor errors. */
    br_slice payload = {version == 1 ? teams_payload_v1 : teams_payload_v2, 11};
    br_go_url_parts parsed = {0}; br_go_url_error ordinary = {0};
    br_bytes projected = {0}; const char *url = (const char *)secret.data;
    int rc = 0;
    if (!ctx) rc = teams_leaf("net/http: nil Context", &verdict->error, error);
    else {
        rc = br_go_url_parse(secret, &parsed, &ordinary, error);
        if (rc == 0 && ordinary.kind != BR_GO_URL_OK) rc = teams_constructor_cause(ordinary, &verdict->error, error);
        else if (rc == 0 && version == 2) rc = teams_project(secret, &parsed, &projected, &url, error);
    }
    if (rc == 0 && verdict->error.leaf.data && version == 2)
        rc = teams_wrap(&verdict->error, "failed to create request: ", error);
    if (rc == 0 && !verdict->error.leaf.data) {
        const br_header headers[] = {{"Content-Type", "application/json"}};
        const br_http_request request = {
            .method = "POST", .url = url, .headers = headers, .nheaders = 1, .body = payload,
            .profile = BR_HTTP_DETECTOR_PUBLIC, .detector_type = 114,
        };
        br_http_response response = {0}; char *send_error = NULL;
        if (br_http_send(ctx, &request, &response, &send_error) != 0) {
            /* ABI transport causes are leaf inputs. Never infer provenance or
             * strip prefixes from arbitrary preparation/Do diagnostic text. */
            rc = teams_leaf(send_error ? send_error : "HTTP transport failed", &verdict->error, error);
            if (rc == 0 && version == 2) rc = teams_wrap(&verdict->error, "failed to make request: ", error);
        } else if (version == 1) {
            if (response.body_error) rc = teams_leaf(response.body_error, &verdict->error, error);
            else if (response.status == 400) {
                static const unsigned char marker[] = "Text is required";
                if (!response.body.data && response.body.len) rc = teams_fail(error, "invalid Microsoft Teams response body");
                else if (br_slice_find(response.body, (br_slice){marker, sizeof(marker) - 1}, 0) != SIZE_MAX) verdict->verified = true;
                else rc = teams_concat("unexpected response body: ", response.body, &verdict->error.leaf, error);
            } else if (response.status < 200 || response.status >= 500) rc = teams_status_cause(response.status, version, &verdict->error, error);
        } else if (response.status == 202) verdict->verified = true;
        else if (response.status != 400 && response.status != 401) rc = teams_status_cause(response.status, version, &verdict->error, error);
        /* V2 drain/read errors are ignored; v1 ReadAll/cause construction is
         * complete. Helper Close/release precedes outer Verified/setter/push. */
        br_http_release(ctx, &response);
        free(send_error);
    }
    free(projected.data);
    br_go_url_clear(&parsed);
    return rc;
}

static int teams_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len) ||
        (detector->version != 1 && detector->version != 2)) return teams_fail(error, "invalid Microsoft Teams scan");
    size_t original_len = out->len;
    br_captures raw = {0}, unique = {0}; char *owned_error = NULL;
    int rc = detector->version == 1 ? br_captures_find(detector->state, input, &raw, false, &owned_error) :
        teams_collect_v2(detector->state, input, &raw, &owned_error);
    if (detector->version == 2) {
        for (size_t i = 0; rc == 0 && i < raw.len; ++i) {
            br_slice value = br_captures_at(&raw, i);
            if (teams_has_sig(value)) rc = br_captures_push(&unique, teams_trim(value), true, &owned_error);
        }
    }
    const br_captures *secrets = detector->version == 1 ? &raw : &unique;
    for (size_t i = 0; rc == 0 && i < secrets->len; ++i) {
        br_slice secret = br_captures_at(secrets, i);
        br_result result = {0}; teams_verdict verdict = {0};
        rc = br_finding_key_bytes(&result, detector->type, secret, "key");
        if (rc == 0) rc = teams_extra(&result, detector->version);
        if (rc == 0 && verify) {
            rc = teams_verify(ctx, detector->version, secret, &verdict, &owned_error);
            if (rc == 0) {
                result.verified = verdict.verified;
                /* The COMPLETE binary v1 message already exists and release
                 * already ran. ABI1 cannot store an embedded-NUL error string;
                 * this is an explicit fatal representation boundary, not drop. */
                if (verdict.error.leaf.data && memchr(verdict.error.leaf.data, 0, verdict.error.leaf.len))
                    rc = teams_fail(&owned_error, "unsupported: Microsoft Teams binary verification error needs byte-length storage");
                else if (br_result_set_verification_error(&result, (const char *)verdict.error.leaf.data, &secret, 1) != 0)
                    rc = teams_fail(&owned_error, "cannot set Microsoft Teams verification error");
            }
        }
        if (rc == 0 && br_results_push(out, &result) != 0) rc = teams_fail(&owned_error, "cannot append Microsoft Teams finding");
        teams_error_clear(&verdict.error);
        br_result_clear(&result);
    }
    if (rc != 0) {
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
        teams_fail(&owned_error, "cannot collect or construct Microsoft Teams finding");
    }
    br_captures_clear(&raw); br_captures_clear(&unique);
    if (error) *error = owned_error; else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static bool teams_false_positive(const br_detector *detector, const br_result *result, char **reason)
{
    (void)detector; (void)result;
    if (reason) *reason = NULL;
    return false;
}

static const char *const teams_keywords_v1[] = {"webhook.office.com"};
static const char *const teams_keywords_v2[] = {"environment.api.powerplatform.com"};
static br_detector teams_versions[] = {
    {.type = 114, .version = 1, .name = "MicrosoftTeamsWebhook", .custom_name = "",
     .description = "Microsoft Teams Webhooks allow external services to communicate with Teams channels by sending messages to a unique URL.",
     .keywords = teams_keywords_v1, .nkeywords = 1, .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024, .scan = teams_scan},
    {.type = 114, .version = 2, .name = "MicrosoftTeamsWebhook", .custom_name = "",
     .description = "Microsoft Teams Webhooks (Power Automate) allow external services to communicate with Teams channels by sending messages to a unique Power Automate workflow URL.",
     .keywords = teams_keywords_v2, .nkeywords = 1, .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1, .scan = teams_scan, .false_positive = teams_false_positive},
};
static const char *const teams_patterns[] = {
    "(https:\\/\\/[a-zA-Z-0-9]+\\.webhook\\.office\\.com\\/webhookb2\\/[a-zA-Z-0-9]{8}-[a-zA-Z-0-9]{4}-[a-zA-Z-0-9]{4}-[a-zA-Z-0-9]{4}-[a-zA-Z-0-9]{12}\\@[a-zA-Z-0-9]{8}-[a-zA-Z-0-9]{4}-[a-zA-Z-0-9]{4}-[a-zA-Z-0-9]{4}-[a-zA-Z-0-9]{12}\\/IncomingWebhook\\/[a-zA-Z-0-9]{32}\\/[a-zA-Z-0-9]{8}-[a-zA-Z-0-9]{4}-[a-zA-Z-0-9]{4}-[a-zA-Z-0-9]{4}-[a-zA-Z-0-9]{12})",
    "(https://[a-z0-9]+\\.\\d+\\.environment\\.api\\.powerplatform\\.com(?::\\d+)?/powerautomate/automations/direct/workflows/[a-f0-9]{32}/triggers/manual/paths/invoke\\?)",
};
static int teams_init(size_t index, const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return teams_fail(error, "invalid Microsoft Teams detector output");
    *out = NULL; br_detector *detector = &teams_versions[index];
    if (!detector->state) {
        br_regex *pattern = NULL;
        if (br_regex_compile(teams_patterns[index], &pattern, error) != 0) { br_regex_free(pattern); return -1; }
        detector->state = pattern;
    }
    *out = detector; return 0;
}
int br_microsoftteamswebhook_v1_init(const br_detector **out, char **error) { return teams_init(0, out, error); }
int br_microsoftteamswebhook_v2_init(const br_detector **out, char **error) { return teams_init(1, out, error); }
