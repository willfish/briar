/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/pusherchannelkey/pusherchannelkey.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct { br_regex *app, *key, *secret; } pusher_patterns;

static const char payload[] =
    "{\"channels\":[\"my-channel\"],\"data\":\"{\\\"message\\\":\\\"hello world\\\"}\",\"name\":\"my_event\"}";

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int compile_prefixed(const char *keyword, const char *rest, br_regex **out, char **error)
{
    const char *keywords[] = {keyword};
    char *prefix = NULL;
    if (br_prefix_regex(keywords, 1, &prefix) != 0)
        return fail(error, "cannot allocate PusherChannelKey prefix");
    size_t first = strlen(prefix), second = strlen(rest);
    if (first == SIZE_MAX || second > SIZE_MAX - first - 1) {
        free(prefix); return fail(error, "PusherChannelKey pattern is too large");
    }
    char *pattern = malloc(first + second + 1);
    if (!pattern) {
        free(prefix);
        return fail(error, "cannot allocate PusherChannelKey pattern");
    }
    memcpy(pattern, prefix, first);
    memcpy(pattern + first, rest, second + 1);
    int rc = br_regex_compile(pattern, out, error);
    free(pattern);
    free(prefix);
    return rc;
}

static void hex_lower(const unsigned char *in, size_t n, char *out)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i) {
        out[i * 2] = digits[in[i] >> 4];
        out[i * 2 + 1] = digits[in[i] & 15];
    }
    out[n * 2] = '\0';
}

static int pusher_verify(const br_scan_ctx *ctx, br_result *result, br_slice app, br_slice key,
                         br_slice secret, char **error)
{
    unsigned char md5[16], mac[32];
    size_t count = 0;
    char hash[33], signature[65], timestamp[32], query[160], to_sign[256], url[320];
    char status_error[64];
    const char *cause = NULL;
    if (sizeof(payload) - 1 != 84) return fail(error, "PusherChannelKey payload drifted");
    if (!EVP_Q_digest(NULL, "MD5", NULL, payload, sizeof(payload) - 1, md5, &count) || count != 16)
        return fail(error, "cannot hash PusherChannelKey body");
    hex_lower(md5, 16, hash);
    time_t now = time(NULL);
    if (now < 0) return fail(error, "cannot read PusherChannelKey timestamp");
    int ts_n = snprintf(timestamp, sizeof(timestamp), "%lld", (long long)now);
    if (ts_n < 0 || (size_t)ts_n >= sizeof(timestamp))
        return fail(error, "cannot format PusherChannelKey timestamp");
    /* url.Values.Encode sorts keys and QueryUnescape is a no-op for this grammar. */
    int qn = snprintf(query, sizeof(query), "auth_key=%.*s&auth_timestamp=%s&auth_version=1.0&body_md5=%s",
                      (int)key.len, key.data, timestamp, hash);
    int sign_n = snprintf(to_sign, sizeof(to_sign), "POST\n/apps/%.*s/events\n%s",
                          (int)app.len, app.data, query);
    if (qn < 0 || sign_n < 0 || (size_t)qn >= sizeof(query) || (size_t)sign_n >= sizeof(to_sign))
        return fail(error, "cannot build PusherChannelKey signature input");
    count = 0;
    if (!EVP_Q_mac(NULL, "HMAC", NULL, "SHA256", NULL, secret.data, secret.len,
                   (const unsigned char *)to_sign, (size_t)sign_n, mac, sizeof(mac), &count) ||
        count != 32)
        return fail(error, "cannot sign PusherChannelKey request");
    hex_lower(mac, 32, signature);
    int url_n = snprintf(url, sizeof(url),
                         "https://api-ap1.pusher.com/apps/%.*s/events?auth_key=%.*s&auth_signature=%s&auth_timestamp=%s&auth_version=1.0&body_md5=%s",
                         (int)app.len, app.data, (int)key.len, key.data, signature, timestamp, hash);
    if (url_n < 0 || (size_t)url_n >= sizeof(url))
        return fail(error, "cannot build PusherChannelKey URL");
    /* Body, signature and URL exist before NewRequestWithContext. Its error is not redacted. */
    if (!ctx) cause = "net/http: nil Context";
    else {
        const br_header headers[] = {{"Content-Type", "application/json"}};
        const br_http_request request = {
            .method = "POST", .url = url, .headers = headers, .nheaders = 1,
            .body = {(const unsigned char *)payload, sizeof(payload) - 1},
            .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
        };
        br_http_response response = {0};
        char *send_error = NULL;
        if (br_http_send(ctx, &request, &response, &send_error) == 0) {
            if (response.status == 200) result->verified = true;
            else if (response.status != 401 && response.status != 403) {
                snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
                cause = status_error;
            }
        }
        /* A transport error is discarded, matching the source's nil error return. */
        free(send_error);
        br_http_release(ctx, &response);
    }
    return br_result_set_verification_error(result, cause, NULL, 0) == 0 ? 0 : fail(error, "cannot set PusherChannelKey verification error");
}

static int scan_pusher(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized PusherChannelKey scan");
    const pusher_patterns *patterns = detector->state;
    size_t original_len = out->len;
    br_captures apps = {0}, keys = {0}, secrets = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->app, input, &apps, true, &owned_error);
    if (!rc) rc = br_captures_find(patterns->key, input, &keys, true, &owned_error);
    if (!rc) rc = br_captures_find(patterns->secret, input, &secrets, true, &owned_error);
    /* Each source loop ranges a uniqueness map. First-seen order is one permitted traversal. */
    for (size_t a = 0; !rc && a < apps.len; ++a) {
        for (size_t k = 0; !rc && k < keys.len; ++k) {
            for (size_t s = 0; !rc && s < secrets.len; ++s) {
                br_result result = {0};
                br_slice app = br_captures_at(&apps, a);
                br_slice key = br_captures_at(&keys, k);
                br_slice secret = br_captures_at(&secrets, s);
                if (br_finding_pair_bytes(&result, detector->type, app, "app", key, "key",
                                          (br_slice){0}) != 0)
                    rc = fail(&owned_error, "cannot create PusherChannelKey result");
                if (!rc && verify)
                    rc = pusher_verify(ctx, &result, app, key, secret, &owned_error);
                if (!rc && br_results_push(out, &result) != 0)
                    rc = fail(&owned_error, "cannot append PusherChannelKey result");
                br_result_clear(&result);
            }
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&apps);
    br_captures_clear(&keys);
    br_captures_clear(&secrets);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static pusher_patterns patterns;
static const char *const keywords[] = {"pusher"};
static br_detector pusher = {
    .type = 84, .version = 0, .name = "PusherChannelKey", .custom_name = "",
    .description = "Pusher is a service for adding real-time functionality to web and mobile apps. Pusher Channel keys can be used to authenticate and send messages to channels.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1,
    /* Scanner embeds DefaultMultiPartCredentialProvider. */
    .max_credential_span = 1024,
    .state = &patterns, .scan = scan_pusher,
};

int br_pusherchannelkey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid PusherChannelKey detector output");
    *out = NULL;
    if (!patterns.app && compile_prefixed("pusher", "\\b([0-9]{7})\\b", &patterns.app, error) != 0)
        return -1;
    if (!patterns.key && compile_prefixed("key", "\\b([a-z0-9]{20})\\b", &patterns.key, error) != 0)
        return -1;
    if (!patterns.secret && compile_prefixed("pusher", "\\b([a-z0-9]{20})\\b", &patterns.secret, error) != 0)
        return -1;
    *out = &pusher;
    return 0;
}
