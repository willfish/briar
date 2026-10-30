/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/redis/redis.go.
 * Verification cannot dial Redis: this tree has no Redis client and must not
 * call endpoints. An unverified result follows the failed-ping branch, so a
 * password starting with '$' is still skipped. */
#include "detectors.h"
#include "../go_url.h"

#include <json-c/json.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *uri, *azure; } redis_patterns;

static int redis_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static bool only_asterisks(br_slice password)
{
    for (size_t i = 0; i < password.len; ++i)
        if (password.data[i] != '*') return false;
    return true;
}

static bool ascii_space(unsigned char value)
{
    return value == ' ' || value == '\t' || value == '\n' || value == '\v' ||
           value == '\f' || value == '\r';
}

static int add_field(br_json *object, const char *name, br_slice value)
{
    if (!object || value.len > INT_MAX) return -1;
    br_json *part = json_object_new_string_len(value.data ? (const char *)value.data : "",
                                              (int)value.len);
    if (!part) return -1;
    if (json_object_object_add(object, name, part) != 0) {
        json_object_put(part);
        return -1;
    }
    return 0;
}

static int redact(br_slice raw, br_slice password, char **out, char **error)
{
    if (!password.len || !raw.data) return redis_fail(error, "invalid Redis redaction");
    size_t count = 0;
    for (size_t i = 0; i + password.len <= raw.len; ) {
        if (!memcmp(raw.data + i, password.data, password.len)) {
            ++count;
            i += password.len;
        } else ++i;
    }
    size_t out_len = raw.len;
    if (password.len > 7) {
        size_t unit = password.len - 7;
        if (count > raw.len / unit) return redis_fail(error, "Redis redaction is too large");
        out_len = raw.len - count * unit;
    } else if (password.len < 7) {
        size_t unit = 7 - password.len;
        if (count > (SIZE_MAX - raw.len) / unit) return redis_fail(error, "Redis redaction is too large");
        out_len = raw.len + count * unit;
    }
    char *text = malloc(out_len + 1);
    if (!text) return redis_fail(error, "out of memory redacting Redis secret");
    size_t written = 0;
    for (size_t i = 0; i < raw.len; ) {
        if (i + password.len <= raw.len && !memcmp(raw.data + i, password.data, password.len)) {
            memcpy(text + written, "*******", 7);
            written += 7;
            i += password.len;
        } else text[written++] = (char)raw.data[i++];
    }
    size_t start = 0, end = written;
    while (start < end && ascii_space((unsigned char)text[start])) ++start;
    while (end > start && ascii_space((unsigned char)text[end - 1])) --end;
    size_t kept = end - start;
    if (start) memmove(text, text + start, kept);
    text[kept] = '\0';
    *out = text;
    return 0;
}

static int consider(br_results *out, br_slice raw, br_slice password, bool owned_raw,
                    char **error)
{
    br_bytes owned = {0};
    if (owned_raw) {
        owned.data = malloc(raw.len + 1);
        if (!owned.data) return redis_fail(error, "out of memory copying Redis URL");
        if (raw.len) memcpy(owned.data, raw.data, raw.len);
        owned.data[raw.len] = '\0';
        owned.len = raw.len;
        raw = (br_slice){owned.data, owned.len};
    }
    int rc = 0;
    br_go_url_parts parts = {0};
    br_go_url_error ordinary = {0};
    br_bytes username = {0};
    br_result result = {0};
    if (only_asterisks(password)) goto done;
    if (br_go_url_parse(raw, &parts, &ordinary, error) != 0) {
        rc = -1;
        goto done;
    }
    if (ordinary.kind != BR_GO_URL_OK || !parts.has_password) goto done;
    if (parts.has_user && parts.raw_user.len) {
        bool valid = false;
        if (br_go_url_decode(parts.raw_user, false, &username, &valid, error) != 0) {
            rc = -1;
            goto done;
        }
        if (!valid) goto done;
    }
    /* Verification would ping Redis. Without a client it stays unverified, so
     * the source still drops passwords that look like variables. */
    if (password.len && password.data[0] == '$') goto done;
    if (redact(raw, password, &result.redacted, error) != 0) {
        rc = -1;
        goto done;
    }
    result.detector_type = 900;
    result.raw.data = malloc(raw.len ? raw.len : 1);
    result.secret_parts = json_object_new_object();
    result.extra_data = json_object_new_object();
    if (!result.raw.data || !result.secret_parts || !result.extra_data) {
        rc = redis_fail(error, "out of memory creating Redis result");
        goto done;
    }
    if (raw.len) memcpy(result.raw.data, raw.data, raw.len);
    result.raw.len = raw.len;
    if (add_field(result.secret_parts, "host", parts.host) != 0 ||
        add_field(result.secret_parts, "password", password) != 0 ||
        (parts.host.len && add_field(result.extra_data, "host", parts.host) != 0) ||
        (username.len && add_field(result.extra_data, "username",
                                   (br_slice){username.data, username.len}) != 0)) {
        rc = redis_fail(error, "out of memory creating Redis metadata");
        goto done;
    }
    if (br_results_push(out, &result) != 0)
        rc = redis_fail(error, "out of memory appending Redis result");
done:
    if (rc) br_result_clear(&result);
    br_go_url_clear(&parts);
    free(username.data);
    free(owned.data);
    return rc;
}

typedef struct {
    br_slice input;
    br_results *out;
    char **error;
    bool azure;
} redis_walk;

static br_slice at(br_slice input, br_span span)
{
    return (br_slice){input.data + span.begin, span.end - span.begin};
}

static bool usable(br_span span, size_t len)
{
    return span.begin != SIZE_MAX && span.end > span.begin && span.end <= len;
}

static int on_match(void *user, const br_span *groups, size_t ngroups)
{
    redis_walk *walk = user;
    if (walk->azure) {
        if (ngroups < 3 || !usable(groups[1], walk->input.len) || !usable(groups[2], walk->input.len))
            return redis_fail(walk->error, "invalid Redis capture");
        br_slice host = at(walk->input, groups[1]);
        br_slice password = at(walk->input, groups[2]);
        const char prefix[] = "rediss://:";
        if (password.len > SIZE_MAX - (sizeof(prefix) - 1) - 1 - host.len)
            return redis_fail(walk->error, "Redis URL is too large");
        size_t len = (sizeof(prefix) - 1) + password.len + 1 + host.len;
        unsigned char *url = malloc(len);
        if (!url) return redis_fail(walk->error, "out of memory building Redis URL");
        memcpy(url, prefix, sizeof(prefix) - 1);
        memcpy(url + sizeof(prefix) - 1, password.data, password.len);
        url[sizeof(prefix) - 1 + password.len] = '@';
        memcpy(url + sizeof(prefix) + password.len, host.data, host.len);
        int rc = consider(walk->out, (br_slice){url, len}, password, true, walk->error);
        free(url);
        return rc;
    }
    if (ngroups < 2 || !usable(groups[0], walk->input.len) || !usable(groups[1], walk->input.len))
        return redis_fail(walk->error, "invalid Redis capture");
    return consider(walk->out, at(walk->input, groups[0]), at(walk->input, groups[1]),
                    false, walk->error);
}

static int redis_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    (void)ctx;
    (void)verify;
    if (error) *error = NULL;
    redis_patterns *patterns = detector ? (redis_patterns *)detector->state : NULL;
    if (!detector || !patterns || !patterns->uri || !patterns->azure || !out ||
        (!input.data && input.len))
        return redis_fail(error, "invalid or uninitialized Redis scan");
    size_t original = out->len;
    char *owned = NULL;
    redis_walk walk = {input, out, &owned, true};
    /* Azure matches are published before URI matches, matching the source loops. */
    int rc = br_regex_each(patterns->azure, input, on_match, &walk, NULL);
    walk.azure = false;
    if (!rc) rc = br_regex_each(patterns->uri, input, on_match, &walk, NULL);
    if (rc && !owned) owned = strdup("Redis scan failed");
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const redis_keywords[] = {"redis"};
static redis_patterns redis_state;
static br_detector redis_detector = {
    .type = 900, .version = 0, .name = "Redis", .custom_name = "",
    .description = "Redis is an in-memory data structure store, used as a database, cache, and message broker. Redis credentials can be used to access and manipulate stored data.",
    .keywords = redis_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1,
    /* Scanner embeds DefaultMultiPartCredentialProvider. */
    .max_credential_span = 1024,
    .scan = redis_scan, .state = &redis_state,
};

int br_redis_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return redis_fail(error, "invalid Redis detector output");
    *out = NULL;
    if (!redis_state.uri &&
        br_regex_compile("\\bredi[s]{1,2}://[\\S]{3,50}:([\\S]{3,50})@[-.%\\w\\/:]+\\b",
                         &redis_state.uri, error) != 0)
        return -1;
    if (!redis_state.azure &&
        br_regex_compile("\\b([\\w\\d.-]{1,100}\\.redis\\.cache\\.windows\\.net:6380),password=([^,]{44}),ssl=True,abortConnect=False\\b",
                         &redis_state.azure, error) != 0) {
        br_regex_free(redis_state.uri);
        redis_state.uri = NULL;
        return -1;
    }
    *out = &redis_detector;
    return 0;
}
