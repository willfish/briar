/* SPDX-License-Identifier: AGPL-3.0-only */
#include "briar.h"

#include <curl/curl.h>
#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return 1;
}

static int64_t now_ms(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) return -1;
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static const char *interrupted(const br_scan_ctx *ctx)
{
    if (!ctx) return NULL;
    if (ctx->cancelled && ctx->cancelled(ctx->cancel_user)) return "context canceled";
    if (ctx->deadline_monotonic_ms) {
        int64_t now = now_ms();
        if (now < 0) return "monotonic clock unavailable";
        if (now >= ctx->deadline_monotonic_ms) return "context deadline exceeded";
    }
    return NULL;
}

static bool header_valid(const br_header *h)
{
    if (!h->name || !*h->name || !h->value) return false;
    for (const unsigned char *p = (const unsigned char *)h->name; *p; ++p)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || strchr("!#$%&'*+-.^_`|~", *p))) return false;
    for (const unsigned char *p = (const unsigned char *)h->value; *p; ++p)
        if (*p == '\r' || *p == '\n' || (*p < 0x20 && *p != '\t') || *p == 0x7f) return false;
    return true;
}

int br_http_send(const br_scan_ctx *ctx, const br_http_request *request,
                 br_http_response *response, char **error)
{
    if (error) *error = NULL;
    if (response) memset(response, 0, sizeof(*response));
    if (!ctx || !request || !response) return fail(error, "invalid HTTP arguments");
    if (!ctx->transport || !ctx->transport->send || !ctx->transport->release)
        return fail(error, "HTTP transport not installed");
    if (request->profile != BR_HTTP_SANE && request->profile != BR_HTTP_DETECTOR_LOCAL &&
        request->profile != BR_HTTP_DETECTOR_PUBLIC)
        return fail(error, "unsupported HTTP client profile");
    if (request->dedup_key.len) return fail(error, "unsupported HTTP request coalescing");
    if (!request->method || !*request->method || !request->url ||
        (request->nheaders && !request->headers) || (!request->body.data && request->body.len))
        return fail(error, "invalid HTTP request");
    br_header method = { request->method, "" };
    if (!header_valid(&method)) return fail(error, "invalid HTTP method");
    for (size_t i = 0; i < request->nheaders; ++i)
        if (!header_valid(&request->headers[i])) return fail(error, "invalid HTTP header");
    const char *stop = interrupted(ctx);
    if (stop) return fail(error, stop);
    if (request->nheaders >= SIZE_MAX / sizeof(br_header) - 1)
        return fail(error, "too many HTTP headers");
    br_header *headers = malloc((request->nheaders + 1) * sizeof(*headers));
    if (!headers) return fail(error, "out of memory constructing HTTP headers");
    char *agent = NULL;
    if (ctx->user_agent && *ctx->user_agent) {
        size_t n = strlen(ctx->user_agent);
        if (n > SIZE_MAX - sizeof("TruffleHog ")) {
            free(headers);
            return fail(error, "HTTP user agent too long");
        }
        agent = malloc(sizeof("TruffleHog ") + n);
        if (agent) snprintf(agent, sizeof("TruffleHog ") + n, "TruffleHog %s", ctx->user_agent);
    } else agent = strdup("TruffleHog");
    if (!agent) {
        free(headers);
        return fail(error, "out of memory constructing HTTP user agent");
    }
    if (request->nheaders) memcpy(headers, request->headers, request->nheaders * sizeof(*headers));
    headers[request->nheaders] = (br_header){ "User-Agent", agent };
    if (!header_valid(&headers[request->nheaders])) {
        free(agent);
        free(headers);
        return fail(error, "invalid HTTP user agent");
    }
    br_http_request effective = *request;
    effective.headers = headers;
    ++effective.nheaders;
    if (!effective.timeout_ms)
        effective.timeout_ms = request->profile == BR_HTTP_SANE ? 5000 : 10000;
    if (ctx->deadline_monotonic_ms) {
        int64_t now = now_ms();
        int64_t remaining = now < 0 ? 0 : ctx->deadline_monotonic_ms - now;
        if (remaining <= 0) {
            free(agent);
            free(headers);
            return fail(error, "context deadline exceeded");
        }
        if (remaining < effective.timeout_ms) effective.timeout_ms = (uint32_t)remaining;
    }
    int rc = ctx->transport->send(ctx->transport->user, ctx, &effective, response, error);
    free(agent);
    free(headers);
    if (rc && error && !*error) *error = strdup("HTTP transport failed");
    return rc;
}

void br_http_release(const br_scan_ctx *ctx, br_http_response *response)
{
    if (!response) return;
    if (ctx && ctx->transport && ctx->transport->release)
        ctx->transport->release(ctx->transport->user, response);
    memset(response, 0, sizeof(*response));
}

/* The runtime adapter is private. Curl regression tests run against isolated local fixtures. */
typedef struct {
    br_http_response *response;
    bool headers_complete;
    const char *failure;
    size_t header_bytes;
} curl_response;

static void curl_release(void *user, br_http_response *r)
{
    (void)user;
    for (size_t i = 0; i < r->nheaders; ++i) {
        free((char *)r->headers[i].name);
        free((char *)r->headers[i].value);
    }
    free((void *)r->headers);
    free((void *)r->body.data);
    free((void *)r->body_error);
    memset(r, 0, sizeof(*r));
}

static size_t receive_header(char *data, size_t size, size_t count, void *user)
{
    curl_response *cr = user;
    br_http_response *r = cr->response;
    if (size && count > SIZE_MAX / size) return 0;
    size_t n = size * count;
    if (n > 65536 || cr->header_bytes > 65536 - n) {
        cr->failure = "unsupported: HTTP headers exceed 64 KiB";
        return 0;
    }
    cr->header_bytes += n;
    if (n >= 5 && !memcmp(data, "HTTP/", 5)) {
        curl_release(NULL, r); /* Drop prior informational headers; curl suppresses CONNECT headers. */
        cr->headers_complete = false;
        const char *space = memchr(data, ' ', n);
        if (space && (size_t)(space - data) + 4 <= n)
            r->status = (space[1] - '0') * 100 + (space[2] - '0') * 10 + space[3] - '0';
        return n;
    }
    if ((n == 2 && data[0] == '\r' && data[1] == '\n') || (n == 1 && data[0] == '\n')) {
        cr->headers_complete = r->status >= 200;
        return n;
    }
    if (cr->headers_complete) return n; /* Trailers are not response headers. */
    const char *colon = memchr(data, ':', n);
    if (!colon) return n;
    size_t key_len = (size_t)(colon - data), start = key_len + 1, end = n;
    while (start < end && (data[start] == ' ' || data[start] == '\t')) ++start;
    while (end > start && strchr(" \t\r\n", data[end - 1])) --end;
    char *key = strndup(data, key_len), *value = strndup(data + start, end - start);
    if (!key || !value) {
        free(key); free(value);
        cr->failure = "out of memory reading HTTP headers";
        return 0;
    }
    br_header *headers = realloc((void *)r->headers, (r->nheaders + 1) * sizeof(*headers));
    if (!headers) {
        free(key); free(value);
        cr->failure = "out of memory reading HTTP headers";
        return 0;
    }
    headers[r->nheaders++] = (br_header){ key, value };
    r->headers = headers;
    return n;
}

static size_t receive_body(char *data, size_t size, size_t count, void *user)
{
    curl_response *cr = user;
    br_http_response *r = cr->response;
    if (size && count > SIZE_MAX / size) return 0;
    size_t n = size * count;
    if (n > 8 * 1024 * 1024 || r->body.len > 8 * 1024 * 1024 - n) {
        cr->failure = "unsupported: HTTP body exceeds 8 MiB";
        return 0;
    }
    if (!n) return 0;
    unsigned char *body = realloc((void *)r->body.data, r->body.len + n);
    if (!body) {
        cr->failure = "out of memory reading HTTP body";
        return 0;
    }
    memcpy(body + r->body.len, data, n);
    r->body.data = body;
    r->body.len += n;
    return n;
}

static bool redirect_status(int status)
{
    return status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
}

static int curl_send(void *user, const br_scan_ctx *ctx, const br_http_request *req,
                     br_http_response *response, char **error)
{
    (void)user;
    /* Injected transports implement the requested profile. Never route a profile
     * requiring no redirects or DNS/IP policy through this incomplete adapter. */
    if (req->profile != BR_HTTP_SANE)
        return fail(error, "unsupported: native curl HTTP client profile");
    if (strcmp(req->method, "GET") || req->body.len)
        return fail(error, "unsupported: curl adapter currently supports bodyless GET only");
    struct curl_slist *headers = NULL;
    /* net/http does not add curl's default Accept header. */
    headers = curl_slist_append(headers, "Accept:");
    if (!headers) return fail(error, "out of memory constructing curl headers");
    for (size_t i = 0; i < req->nheaders; ++i) {
        size_t a = strlen(req->headers[i].name), b = strlen(req->headers[i].value);
        if (a > SIZE_MAX - b - 3) goto memory_error;
        char *line = malloc(a + b + 3);
        if (!line) goto memory_error;
        if (b) snprintf(line, a + b + 3, "%s: %s", req->headers[i].name, req->headers[i].value);
        else snprintf(line, a + b + 3, "%s;", req->headers[i].name);
        struct curl_slist *next = curl_slist_append(headers, line);
        free(line);
        if (!next) goto memory_error;
        headers = next;
    }
    char *url = strdup(req->url);
    if (!url) goto memory_error;
    int rc = 1;
    int64_t started = now_ms();
    if (started < 0) { free(url); curl_slist_free_all(headers); return fail(error, "monotonic clock unavailable"); }
    int64_t total_end = started + req->timeout_ms;
    for (unsigned redirects = 0; ; ++redirects) {
        CURL *easy = curl_easy_init();
        CURLM *multi = curl_multi_init();
        curl_response cr = { .response = response };
        const char *failure = NULL;
        bool added = false;
        if (!easy || !multi) failure = "out of memory initializing curl";
        int64_t hop_start = now_ms();
        if (hop_start < 0) failure = "monotonic clock unavailable";
        if (!failure && hop_start >= total_end) failure = "context deadline exceeded";
#define SET(option, value) do { if (!failure && curl_easy_setopt(easy, option, value) != CURLE_OK) failure = "unsupported curl option"; } while (0)
        SET(CURLOPT_URL, url);
        SET(CURLOPT_PATH_AS_IS, 1L);
        SET(CURLOPT_PROTOCOLS_STR, "http,https");
        SET(CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
        SET(CURLOPT_HTTPHEADER, headers);
        SET(CURLOPT_ACCEPT_ENCODING, "gzip");
        SET(CURLOPT_NOSIGNAL, 1L);
        SET(CURLOPT_TIMEOUT_MS, (long)(total_end - hop_start));
        SET(CURLOPT_CONNECTTIMEOUT_MS, 5000L);
        SET(CURLOPT_WRITEFUNCTION, receive_body);
        SET(CURLOPT_WRITEDATA, &cr);
        SET(CURLOPT_HEADERFUNCTION, receive_header);
        SET(CURLOPT_HEADERDATA, &cr);
        /* A proxy's CONNECT 200 is not an origin response, even if TLS then fails. */
        SET(CURLOPT_SUPPRESS_CONNECT_HEADERS, 1L);
#undef SET
        if (!failure) {
            if (curl_multi_add_handle(multi, easy) != CURLM_OK) failure = "curl multi add failed";
            else added = true;
        }
        CURLcode outcome = CURLE_OK;
        while (!failure) {
            failure = interrupted(ctx);
            int64_t now = now_ms();
            curl_off_t connected = 0, tls = 0;
            curl_easy_getinfo(easy, CURLINFO_CONNECT_TIME_T, &connected);
            curl_easy_getinfo(easy, CURLINFO_APPCONNECT_TIME_T, &tls);
            if (now < 0) failure = "monotonic clock unavailable";
            else if (now >= total_end) failure = "context deadline exceeded";
            else if (!connected && now - hop_start >= 2000) failure = "dial timeout";
            else if (connected && !tls && !strncasecmp(url, "https://", 8) &&
                     now - hop_start - connected / 1000 >= 3000) failure = "TLS handshake timeout";
            if (failure) break;
            int running = 0;
            if (curl_multi_perform(multi, &running) != CURLM_OK) { failure = "curl multi perform failed"; break; }
            if (!running) {
                int queued = 0;
                CURLMsg *msg;
                bool done = false;
                while ((msg = curl_multi_info_read(multi, &queued))) {
                    if (msg->msg == CURLMSG_DONE) { outcome = msg->data.result; done = true; }
                }
                if (!done) failure = "curl completed without a response";
                break;
            }
            int activity = 0;
            if (curl_multi_poll(multi, NULL, 0, 25, &activity) != CURLM_OK)
                failure = "curl multi poll failed";
        }
        if (!failure && outcome != CURLE_OK)
            failure = cr.failure ? cr.failure : curl_easy_strerror(outcome);
        char *next_url = NULL;
        if (!failure && redirect_status(response->status)) {
            char *location = NULL;
            curl_easy_getinfo(easy, CURLINFO_REDIRECT_URL, &location);
            if (location) {
                if (redirects >= 9) failure = "stopped after 10 redirects";
                else {
                    /* Go strips sensitive headers across hosts. That generic case is not ported yet. */
                    for (size_t i = 0; i < req->nheaders; ++i)
                        if (!strcasecmp(req->headers[i].name, "Authorization") ||
                            !strcasecmp(req->headers[i].name, "Cookie") ||
                            !strcasecmp(req->headers[i].name, "WWW-Authenticate"))
                            failure = "unsupported: redirects with sensitive HTTP headers";
                    if (!failure) {
                        next_url = strdup(location);
                        if (!next_url) failure = "out of memory following redirect";
                    }
                }
            }
        }
        if (failure) {
            /* Body errors remain separate so status-only detectors ignore them. */
            if (cr.headers_complete && !redirect_status(response->status)) {
                response->body_error = strdup(failure);
                if (response->body_error) rc = 0;
                else fail(error, "out of memory storing HTTP body error");
            } else fail(error, failure);
        } else rc = 0;
        if (added) curl_multi_remove_handle(multi, easy);
        if (easy) curl_easy_cleanup(easy);
        if (multi) curl_multi_cleanup(multi);
        if (failure || !next_url) break;
        curl_release(NULL, response);
        free(url);
        url = next_url;
        rc = 1;
    }
    free(url);
    curl_slist_free_all(headers);
    return rc;
memory_error:
    curl_slist_free_all(headers);
    return fail(error, "out of memory constructing curl request");
}

/* Private runtime entry point, deliberately not an ABI revision 1 addition. */
const br_transport *br_curl_transport_init(char **error)
{
    static const br_transport transport = { NULL, curl_send, curl_release };
    if (error) *error = NULL;
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        fail(error, "curl global initialization failed");
        return NULL;
    }
    return &transport;
}
