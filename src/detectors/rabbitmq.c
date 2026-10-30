/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/rabbitmq/rabbitmq.go.
 * Verification dials AMQP, not HTTP. The custom dialer is a 10s plain TCP dial
 * for both amqp and amqps, matching the overridden amqp.Dial callback. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "../go_url.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static int fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static bool contains_ci(const char *text, const char *needle)
{
    size_t n = strlen(needle);
    for (size_t i = 0; text[i]; ++i) {
        size_t j = 0;
        for (; j < n; ++j) {
            unsigned char a = (unsigned char)text[i + j], b = (unsigned char)needle[j];
            if (!a) return false;
            if (a >= 'A' && a <= 'Z') a = (unsigned char)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z') b = (unsigned char)(b - 'A' + 'a');
            if (a != b) break;
        }
        if (j == n) return true;
    }
    return false;
}

static bool determinate_auth(const char *text)
{
    return text && ((contains_ci(text, "403") && contains_ci(text, "access_refused")) ||
        contains_ci(text, "username or password not allowed"));
}

static const char *errno_text(int code)
{
    switch (code) {
    case ENETUNREACH: return "network is unreachable";
    case EHOSTUNREACH: return "no route to host";
    case ECONNREFUSED: return "connection refused";
    case ETIMEDOUT: return "connection timed out";
    case ECONNRESET: return "connection reset by peer";
    default: return strerror(code);
    }
}

static int dial_numeric(const char *host, const char *port, int *fd, char **cause)
{
    struct in_addr ipv4;
    if (inet_pton(AF_INET, host, &ipv4) != 1) return 0;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return fail(cause, "cannot open RabbitMQ socket");
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr = ipv4};
    address.sin_port = htons((uint16_t)atoi(port));
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) { close(sock); return fail(cause, "cannot set RabbitMQ dial mode"); }
    int connected = connect(sock, (struct sockaddr *)&address, sizeof(address));
    int connect_errno = 0;
    if (connected != 0 && errno == EINPROGRESS) {
        struct pollfd ready = {.fd = sock, .events = POLLOUT};
        int polled = poll(&ready, 1, 10000);
        if (polled > 0) {
            socklen_t len = sizeof(connect_errno);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &connect_errno, &len);
        } else connect_errno = polled == 0 ? ETIMEDOUT : errno;
    } else if (connected != 0) connect_errno = errno;
    if (connect_errno) {
        close(sock);
        const char *why = errno_text(connect_errno);
        int n = snprintf(NULL, 0, "dial tcp %s:%s: connect: %s", host, port, why);
        char *buffer = n < 0 ? NULL : malloc((size_t)n + 1);
        if (!buffer) return -1;
        snprintf(buffer, (size_t)n + 1, "dial tcp %s:%s: connect: %s", host, port, why);
        *cause = buffer;
        return 1;
    }
    fcntl(sock, F_SETFL, flags);
    struct timeval timeout = {.tv_sec = 10};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    *fd = sock;
    return 2;
}

static int dial_tcp(const char *host, const char *port, int *fd, char **cause)
{
    int numeric = dial_numeric(host, port, fd, cause);
    if (numeric != 0) return numeric < 0 ? -1 : numeric == 1 ? 1 : 0;
    struct addrinfo hints = {.ai_socktype = SOCK_STREAM, .ai_family = AF_UNSPEC};
    struct addrinfo *info = NULL;
    int lookup = getaddrinfo(host, port, &hints, &info);
    if (lookup != 0) {
        const char *why = lookup == EAI_NONAME || lookup == EAI_AGAIN ? "no such host" : gai_strerror(lookup);
        int n = snprintf(NULL, 0, "dial tcp: lookup %s: %s", host, why);
        char *buffer = n < 0 ? NULL : malloc((size_t)n + 1);
        if (!buffer) return -1;
        snprintf(buffer, (size_t)n + 1, "dial tcp: lookup %s: %s", host, why);
        *cause = buffer;
        return 1;
    }
    int sock = -1;
    int connect_errno = EHOSTUNREACH;
    char address[64] = {0};
    for (struct addrinfo *item = info; item; item = item->ai_next) {
        sock = socket(item->ai_family, item->ai_socktype, item->ai_protocol);
        if (sock < 0) { connect_errno = errno; continue; }
        int flags = fcntl(sock, F_GETFL, 0);
        if (flags < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
            connect_errno = errno;
            close(sock);
            sock = -1;
            continue;
        }
        if (item->ai_family == AF_INET) {
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &((struct sockaddr_in *)item->ai_addr)->sin_addr, ip, sizeof(ip));
            snprintf(address, sizeof(address), "%s:%s", ip, port);
        } else if (item->ai_family == AF_INET6) {
            char ip[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)item->ai_addr)->sin6_addr, ip, sizeof(ip));
            snprintf(address, sizeof(address), "[%s]:%s", ip, port);
        }
        int connected = connect(sock, item->ai_addr, item->ai_addrlen);
        if (connected == 0 || errno == EINPROGRESS) {
            struct pollfd ready = {.fd = sock, .events = POLLOUT};
            int polled = poll(&ready, 1, 10000);
            if (polled > 0) {
                int so = 0;
                socklen_t len = sizeof(so);
                getsockopt(sock, SOL_SOCKET, SO_ERROR, &so, &len);
                if (!so) { fcntl(sock, F_SETFL, flags); break; }
                connect_errno = so;
            } else connect_errno = polled == 0 ? ETIMEDOUT : errno;
        } else connect_errno = errno;
        close(sock);
        sock = -1;
    }
    freeaddrinfo(info);
    if (sock < 0) {
        const char *why = errno_text(connect_errno);
        const char *where = address[0] ? address : host;
        int n = snprintf(NULL, 0, "dial tcp %s: connect: %s", where, why);
        char *buffer = n < 0 ? NULL : malloc((size_t)n + 1);
        if (!buffer) return -1;
        snprintf(buffer, (size_t)n + 1, "dial tcp %s: connect: %s", where, why);
        *cause = buffer;
        return 1;
    }
    struct timeval timeout = {.tv_sec = 10};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    *fd = sock;
    return 0;
}

static int write_all(int fd, const unsigned char *data, size_t len)
{
    size_t at = 0;
    while (at < len) {
        ssize_t n = write(fd, data + at, len - at);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        at += (size_t)n;
    }
    return 0;
}

static int read_full(int fd, unsigned char *data, size_t len)
{
    size_t at = 0;
    while (at < len) {
        ssize_t n = read(fd, data + at, len - at);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        at += (size_t)n;
    }
    return 0;
}

static int put_shortstr(unsigned char *out, size_t cap, size_t *at, const char *text)
{
    size_t n = strlen(text);
    if (n > 255 || *at + 1 + n > cap) return -1;
    out[(*at)++] = (unsigned char)n;
    memcpy(out + *at, text, n);
    *at += n;
    return 0;
}

static int put_u16(unsigned char *out, size_t *at, unsigned value)
{
    out[(*at)++] = (unsigned char)(value >> 8);
    out[(*at)++] = (unsigned char)value;
    return 0;
}

static int put_u32(unsigned char *out, size_t *at, unsigned value)
{
    out[(*at)++] = (unsigned char)(value >> 24);
    out[(*at)++] = (unsigned char)(value >> 16);
    out[(*at)++] = (unsigned char)(value >> 8);
    out[(*at)++] = (unsigned char)value;
    return 0;
}

static int send_method(int fd, unsigned class_id, unsigned method_id, const unsigned char *args, size_t args_len)
{
    unsigned char frame[512];
    if (args_len > sizeof(frame) - 8) return -1;
    size_t payload = 4 + args_len;
    frame[0] = 1;
    frame[1] = frame[2] = 0;
    frame[3] = (unsigned char)(payload >> 24);
    frame[4] = (unsigned char)(payload >> 16);
    frame[5] = (unsigned char)(payload >> 8);
    frame[6] = (unsigned char)payload;
    frame[7] = (unsigned char)(class_id >> 8);
    frame[8] = (unsigned char)class_id;
    frame[9] = (unsigned char)(method_id >> 8);
    frame[10] = (unsigned char)method_id;
    if (args_len) memcpy(frame + 11, args, args_len);
    frame[11 + args_len] = 0xCE;
    return write_all(fd, frame, 12 + args_len);
}

static int read_method(int fd, unsigned *class_id, unsigned *method_id, unsigned char *args, size_t cap, size_t *args_len)
{
    unsigned char header[7];
    if (read_full(fd, header, 7) != 0) return -1;
    if (header[0] != 1) return -1;
    size_t payload = ((size_t)header[3] << 24) | ((size_t)header[4] << 16) | ((size_t)header[5] << 8) | header[6];
    if (payload < 4 || payload > 65536) return -1;
    unsigned char *body = malloc(payload);
    unsigned char end = 0;
    if (!body || read_full(fd, body, payload) != 0 || read_full(fd, &end, 1) != 0 || end != 0xCE) {
        free(body);
        return -1;
    }
    *class_id = ((unsigned)body[0] << 8) | body[1];
    *method_id = ((unsigned)body[2] << 8) | body[3];
    *args_len = payload - 4;
    if (*args_len > cap) { free(body); return -1; }
    memcpy(args, body + 4, *args_len);
    free(body);
    return 0;
}

static int handshake(int fd, const char *user, const char *password, const char *vhost, char **cause)
{
    static const unsigned char header[] = {'A', 'M', 'Q', 'P', 0, 0, 9, 1};
    if (write_all(fd, header, sizeof(header)) != 0) return fail(cause, "read tcp: connection reset by peer");
    unsigned class_id = 0, method_id = 0;
    unsigned char args[1024];
    size_t args_len = 0;
    if (read_method(fd, &class_id, &method_id, args, sizeof(args), &args_len) != 0)
        return fail(cause, "EOF");
    if (class_id == 10 && method_id == 50 && args_len >= 3) {
        unsigned code = ((unsigned)args[0] << 8) | args[1];
        unsigned text_len = args[2];
        char text[256] = {0};
        if (text_len < sizeof(text) && 3u + text_len <= args_len) memcpy(text, args + 3, text_len);
        char buffer[320];
        snprintf(buffer, sizeof(buffer), "Exception (%u) Reason: \"%s\"", code, text);
        *cause = strdup(buffer);
        return *cause ? 1 : -1;
    }
    unsigned char start[256];
    size_t at = 0;
    put_u32(start, &at, 0);
    if (put_shortstr(start, sizeof(start), &at, "PLAIN") != 0) return fail(cause, "AMQP credential too large");
    size_t user_len = strlen(user), pass_len = strlen(password);
    if (at + 4 + user_len + pass_len + 2 > sizeof(start)) return fail(cause, "AMQP credential too large");
    put_u32(start, &at, (unsigned)(user_len + pass_len + 2));
    start[at++] = 0;
    memcpy(start + at, user, user_len);
    at += user_len;
    start[at++] = 0;
    memcpy(start + at, password, pass_len);
    at += pass_len;
    if (put_shortstr(start, sizeof(start), &at, "en_US") != 0 || send_method(fd, 10, 11, start, at) != 0)
        return fail(cause, "EOF");
    if (read_method(fd, &class_id, &method_id, args, sizeof(args), &args_len) != 0)
        return fail(cause, "EOF");
    if (class_id == 10 && method_id == 50 && args_len >= 3) {
        unsigned code = ((unsigned)args[0] << 8) | args[1];
        unsigned text_len = args[2];
        char text[256] = {0};
        if (text_len < sizeof(text) && 3u + text_len <= args_len) memcpy(text, args + 3, text_len);
        char buffer[320];
        snprintf(buffer, sizeof(buffer), "Exception (%u) Reason: \"%s\"", code, text);
        *cause = strdup(buffer);
        return *cause ? 1 : -1;
    }
    unsigned char tune[8];
    size_t tune_at = 0;
    put_u16(tune, &tune_at, 0);
    put_u32(tune, &tune_at, 131072);
    put_u16(tune, &tune_at, 0);
    unsigned char open[256];
    size_t open_at = 0;
    if (send_method(fd, 10, 31, tune, tune_at) != 0 ||
        put_shortstr(open, sizeof(open), &open_at, vhost) != 0 ||
        put_shortstr(open, sizeof(open), &open_at, "") != 0)
        return fail(cause, "EOF");
    open[open_at++] = 0;
    if (send_method(fd, 10, 40, open, open_at) != 0 ||
        read_method(fd, &class_id, &method_id, args, sizeof(args), &args_len) != 0)
        return fail(cause, "EOF");
    if (class_id == 10 && method_id == 41) return 0;
    if (class_id == 10 && method_id == 50 && args_len >= 3) {
        unsigned code = ((unsigned)args[0] << 8) | args[1];
        unsigned text_len = args[2];
        char text[256] = {0};
        if (text_len < sizeof(text) && 3u + text_len <= args_len) memcpy(text, args + 3, text_len);
        char buffer[320];
        snprintf(buffer, sizeof(buffer), "Exception (%u) Reason: \"%s\"", code, text);
        *cause = strdup(buffer);
        return *cause ? 1 : -1;
    }
    return fail(cause, "unexpected AMQP method");
}

static int verify_rabbit(const char *url, const char *user, const char *password, const char *host,
                         const char *port, const char *vhost, bool *verified, char **cause)
{
    int fd = -1;
    int dialed = dial_tcp(host, port, &fd, cause);
    if (dialed != 0) return dialed < 0 ? -1 : 0;
    int shook = handshake(fd, user, password, vhost, cause);
    close(fd);
    if (shook == 0) *verified = true;
    (void)url;
    return shook < 0 ? -1 : 0;
}

static bool skipped_host(br_slice url)
{
    static const char *const terms[] = {"127.0.0.1", "localhost", "contoso.com", "example.com"};
    for (size_t i = 0; i < 4; ++i)
        if (br_slice_find(url, (br_slice){(const unsigned char *)terms[i], strlen(terms[i])}, 0) != SIZE_MAX)
            return true;
    return false;
}

static bool only_asterisks(const char *password)
{
    if (!password[0]) return true;
    for (const char *p = password; *p; ++p) if (*p != '*') return false;
    return true;
}

static int split_host(br_slice host, char *name, size_t name_cap, char *port, size_t port_cap, const char *fallback)
{
    const char *text = (const char *)host.data;
    const char *colon = NULL;
    if (host.len && text[0] == '[') {
        const char *end = memchr(text, ']', host.len);
        if (end && (size_t)(end - text) + 1 < host.len && end[1] == ':') colon = end + 1;
    } else colon = memchr(text, ':', host.len);
    size_t name_len = colon ? (size_t)(colon - text) : host.len;
    if (!name_len || name_len >= name_cap) return -1;
    memcpy(name, text, name_len);
    name[name_len] = 0;
    if (!colon) {
        snprintf(port, port_cap, "%s", fallback);
        return 0;
    }
    size_t port_len = host.len - (size_t)(colon + 1 - text);
    if (!port_len || port_len >= port_cap) return -1;
    memcpy(port, colon + 1, port_len);
    port[port_len] = 0;
    return 0;
}

typedef struct { char *url, *password; } rabbit_pair;
typedef struct { rabbit_pair *items; size_t len, cap; char *error; const unsigned char *data; } rabbit_bag;

static int collect_rabbit(void *user, const br_span *groups, size_t ngroups)
{
    rabbit_bag *bag = user;
    if (ngroups < 2 || groups[0].begin == SIZE_MAX || groups[1].begin == SIZE_MAX) return 0;
    size_t url_len = groups[0].end - groups[0].begin, pass_len = groups[1].end - groups[1].begin;
    for (size_t i = 0; i < bag->len; ++i)
        if (strlen(bag->items[i].url) == url_len && !memcmp(bag->items[i].url, bag->data + groups[0].begin, url_len))
            return 0;
    if (bag->len == bag->cap) {
        size_t cap = bag->cap ? bag->cap * 2 : 4;
        rabbit_pair *grown = realloc(bag->items, cap * sizeof(*grown));
        if (!grown) return fail(&bag->error, "out of memory collecting RabbitMQ URLs");
        bag->items = grown;
        bag->cap = cap;
    }
    char *url = malloc(url_len + 1), *password = malloc(pass_len + 1);
    if (!url || !password) { free(url); free(password); return fail(&bag->error, "out of memory copying RabbitMQ URL"); }
    memcpy(url, bag->data + groups[0].begin, url_len);
    memcpy(password, bag->data + groups[1].begin, pass_len);
    url[url_len] = password[pass_len] = 0;
    bag->items[bag->len++] = (rabbit_pair){url, password};
    return 0;
}

static int scan_rabbit(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    (void)ctx; /* The source dial ignores context and uses a fixed 10s timeout. */
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized RabbitMQ scan");
    size_t original_len = out->len;
    rabbit_bag bag = {.data = input.data ? input.data : (const unsigned char *)""};
    char *owned = NULL;
    int rc = br_regex_each(detector->state, input, collect_rabbit, &bag, &owned);
    if (!rc && bag.error) { free(owned); owned = bag.error; bag.error = NULL; rc = -1; }
    for (size_t i = 0; !rc && i < bag.len; ++i) {
        br_slice url = {(const unsigned char *)bag.items[i].url, strlen(bag.items[i].url)};
        const char *captured = bag.items[i].password;
        if (skipped_host(url)) continue;
        br_go_url_parts parts = {0};
        br_go_url_error ordinary = {0};
        br_bytes password = {0};
        bool valid = false;
        int parsed = br_go_url_parse(url, &parts, &ordinary, &owned);
        if (parsed != 0) { rc = -1; br_go_url_clear(&parts); break; }
        if (ordinary.kind != BR_GO_URL_OK || !parts.has_password) {
            br_go_url_clear(&parts);
            continue;
        }
        if (br_go_url_decode(parts.raw_password, false, &password, &valid, &owned) != 0) {
            rc = -1;
            br_go_url_clear(&parts);
            free(password.data);
            break;
        }
        if (!valid || !password.data || password.len >= 64) { br_go_url_clear(&parts); free(password.data); continue; }
        char decoded[64];
        memcpy(decoded, password.data, password.len);
        decoded[password.len] = 0;
        if (only_asterisks(captured)) {
            br_go_url_clear(&parts);
            free(password.data);
            continue;
        }
        char host[256], port[16], vhost[256], user[128];
        const char *scheme_port = url.len >= 8 && !memcmp(url.data, "amqps://", 8) ? "5671" : "5672";
        if (split_host(parts.host, host, sizeof(host), port, sizeof(port), scheme_port) != 0) {
            br_go_url_clear(&parts);
            free(password.data);
            continue;
        }
        user[0] = 0;
        if (parts.has_user && parts.raw_user.len < sizeof(user)) {
            memcpy(user, parts.raw_user.data, parts.raw_user.len);
            user[parts.raw_user.len] = 0;
        }
        const char *vhost_text = "/";
        if (parts.raw_path.len > 1 && parts.raw_path.len < sizeof(vhost)) {
            memcpy(vhost, parts.raw_path.data + 1, parts.raw_path.len - 1);
            vhost[parts.raw_path.len - 1] = 0;
            vhost_text = vhost;
        }
        char *redacted = malloc(url.len + 8);
        br_result result = {0};
        if (!redacted || br_finding_key(&result, 903, bag.items[i].url, "key") != 0) {
            free(redacted);
            rc = fail(&owned, "out of memory creating RabbitMQ result");
        } else {
            memcpy(redacted, url.data, url.len);
            redacted[url.len] = 0;
            for (char *cursor = redacted; (cursor = strstr(cursor, captured)); ) {
                size_t pass_len = strlen(captured), rest = strlen(cursor + pass_len);
                memmove(cursor + 8, cursor + pass_len, rest + 1);
                memcpy(cursor, "********", 8);
                cursor += 8;
            }
            result.redacted = redacted;
            bool verified = false;
            char *cause = NULL;
            if (verify && verify_rabbit(bag.items[i].url, user, decoded, host, port, vhost_text, &verified, &cause) != 0)
                rc = fail(&owned, cause ? cause : "cannot verify RabbitMQ candidate");
            result.verified = verified;
            if (!rc && cause && !determinate_auth(cause)) {
                br_slice secret = {result.raw.data, result.raw.len};
                if (br_result_set_verification_error(&result, cause, &secret, 1) != 0)
                    rc = fail(&owned, "out of memory recording RabbitMQ verification error");
            }
            free(cause);
            if (!rc && !result.verified && captured[0] == '$') {
                br_result_clear(&result);
                br_go_url_clear(&parts);
                free(password.data);
                continue;
            }
            if (!rc && br_results_push(out, &result) != 0)
                rc = fail(&owned, "out of memory appending RabbitMQ result");
        }
        br_result_clear(&result);
        br_go_url_clear(&parts);
        free(password.data);
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    for (size_t i = 0; i < bag.len; ++i) { free(bag.items[i].url); free(bag.items[i].password); }
    free(bag.items);
    free(bag.error);
    if (error) *error = owned;
    else free(owned);
    return rc ? -1 : 0;
}

static const char *const keywords[] = {"amqp"};
static br_detector rabbitmq = {
    .type = 903, .version = 0, .name = "RabbitMQ", .custom_name = "",
    .description = "RabbitMQ is an open-source message broker software that originally implemented the Advanced Message Queuing Protocol (AMQP). RabbitMQ credentials can be used to access and manage message queues.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = scan_rabbit,
};

int br_rabbitmq_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid RabbitMQ detector output");
    *out = NULL;
    br_regex *pattern = NULL;
    if (br_regex_compile("\\b(?:amqps?):\\/\\/[\\S]{3,50}:([\\S]{3,50})@[-.%\\w\\/:]+\\b", &pattern, error) != 0)
        return -1;
    rabbitmq.state = pattern;
    *out = &rabbitmq;
    return 0;
}
