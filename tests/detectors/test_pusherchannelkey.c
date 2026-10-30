/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

#include <openssl/evp.h>

int br_pusherchannelkey_init(const br_detector **out, char **error);

static const char app[] = "1234567";
static const char key[] = "abcdefghij0123456789";
static const char secret[] = "abcdefghij0123456780";
static const char payload[] =
    "{\"channels\":[\"my-channel\"],\"data\":\"{\\\"message\\\":\\\"hello world\\\"}\",\"name\":\"my_event\"}";

static void hex_lower(const unsigned char *in, size_t n, char *out)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i) {
        out[i * 2] = digits[in[i] >> 4];
        out[i * 2 + 1] = digits[in[i] & 15];
    }
    out[n * 2] = '\0';
}

static int inspect(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                   br_http_response *response, char **error)
{
    (void)ctx; (void)error;
    test_http *http = user;
    http->calls++;
    unsigned char md5[16], mac[32];
    size_t count = 0;
    char hash[33], signature[65], expect[320];
    CHECK(request->body.len == 84 && !memcmp(request->body.data, payload, 84));
    CHECK(EVP_Q_digest(NULL, "MD5", NULL, payload, 84, md5, &count) && count == 16);
    hex_lower(md5, 16, hash);
    CHECK(!strcmp(hash, "63c099b602fc2c0b504f73208aa77bbe"));
    const char *ts = strstr(request->url, "auth_timestamp=");
    CHECK(ts);
    ts += strlen("auth_timestamp=");
    char timestamp[32];
    size_t ts_len = strcspn(ts, "&");
    CHECK(ts_len < sizeof(timestamp));
    memcpy(timestamp, ts, ts_len);
    timestamp[ts_len] = '\0';
    char to_sign[256];
    int n = snprintf(to_sign, sizeof(to_sign),
                     "POST\n/apps/%s/events\nauth_key=%s&auth_timestamp=%s&auth_version=1.0&body_md5=%s",
                     app, key, timestamp, hash);
    CHECK(EVP_Q_mac(NULL, "HMAC", NULL, "SHA256", NULL, secret, strlen(secret),
                    (const unsigned char *)to_sign, (size_t)n, mac, sizeof(mac), &count) && count == 32);
    hex_lower(mac, 32, signature);
    snprintf(expect, sizeof(expect),
             "https://api-ap1.pusher.com/apps/%s/events?auth_key=%s&auth_signature=%s&auth_timestamp=%s&auth_version=1.0&body_md5=%s",
             app, key, signature, timestamp, hash);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, expect));
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].value, "application/json"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 84);
    *response = http->response;
    return http->send_rc;
}

static void release(void *user, br_http_response *response)
{
    ((test_http *)user)->releases++;
    memset(response, 0, sizeof(*response));
}

int main(void)
{
    const br_detector *d = NULL;
    CHECK(br_pusherchannelkey_init(&d, NULL) == 0);
    CHECK(d->type == 84 && !strcmp(d->name, "PusherChannelKey") && d->nkeywords == 1 &&
          d->max_credential_span == 1024);
    char gap[48];
    memset(gap, 'x', 41);
    gap[41] = '\0';
    char text[256];
    snprintf(text, sizeof(text), "pusher %s pusher %s %skey %s pusher %s", app, secret, gap, key, app);
    br_results results = {0};
    CHECK(d->scan(d, NULL, false, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 1);
    CHECK(results.items[0].raw.len == 7 && !memcmp(results.items[0].raw.data, app, 7));
    CHECK(results.items[0].raw_v2.len == 27 && !memcmp(results.items[0].raw_v2.data, app, 7));
    CHECK(!memcmp(results.items[0].raw_v2.data + 7, key, 20));
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(results.items[0].secret_parts, "key", &part));
    CHECK(!strcmp(json_object_get_string(part), key));
    CHECK(!json_object_object_get_ex(results.items[0].secret_parts, "secret", &part));
    br_results_clear(&results);
    int statuses[] = {200, 401, 403, 500};
    const char *errors[] = {NULL, NULL, NULL, "unexpected status code: 500"};
    for (size_t i = 0; i < 4; ++i) {
        test_http http = {.response = {.status = statuses[i]}};
        br_transport transport = {.user = &http, .send = inspect, .release = release};
        br_scan_ctx ctx = {.transport = &transport};
        CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
        CHECK(results.len == 1 && results.items[0].verified == (statuses[i] == 200) && http.releases == 1);
        if (errors[i]) CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, errors[i]));
        else CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
    }
    test_http failed = {.send_rc = -1, .send_error = "dial tcp: connection refused"};
    br_transport transport = {.user = &failed, .send = inspect, .release = release};
    br_scan_ctx ctx = {.transport = &transport};
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)text, strlen(text)}, &results, NULL) == 0);
    CHECK(results.len == 1 && results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&results);
    return test_finish("pusherchannelkey");
}
