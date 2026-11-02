/* SPDX-License-Identifier: AGPL-3.0-only */
/* TruffleHog v3.97.2 pkg/detectors/ftp/ftp.go; jlaffaye/ftp v0.2.0
 * (ISC); selected Go 1.26.7 net/url, textproto and bufio (BSD-3-Clause).
 * The URL byte permissions below derive from the 2025 Go encoding table.
 * See the committed NOTICE and LICENSES for the original notices. */
#include "detectors.h"
#include "findings.h"
#include "ftp_private.h"

#include <arpa/inet.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct { unsigned char *data; size_t len, cap; } ftp_buf;
typedef enum { FTP_NONE, FTP_IO, FTP_MESSAGE, FTP_REPLY, FTP_SHORT, FTP_BAD_CODE } ftp_kind;
typedef struct { ftp_kind kind; int code; ftp_buf text; } ftp_cause;
enum { FTP_USERINFO_BYTES = 101 };
typedef struct {
    /* Regex's two 50-rune fields plus ':' and validUserinfo's ASCII check
     * bound actual userinfo to 101 bytes. Percent decoding only shrinks it.
     * Stack-owned byte storage, not C strings or redundant heap staging. */
    unsigned char user[FTP_USERINFO_BYTES], password[FTP_USERINFO_BYTES];
    size_t user_len, password_len;
    ftp_buf host, raw;
} ftp_url;
typedef struct { br_bytes url, password; } ftp_match;
typedef struct { ftp_match *items; size_t len, cap; br_slice input; char *error; } ftp_matches;
typedef struct {
    const br_ftp_state *state; br_ftp_conn conn;
    unsigned char input[4096]; size_t pos, len;
    bool eof, writer_failed; ftp_cause pending;
} ftp_session;
typedef struct { int code; bool more; br_slice message; ftp_kind bad; } ftp_code;

static br_slice ftp_slice(const ftp_buf *b) { return (br_slice){b->data, b->len}; }
static br_slice ftp_user(const ftp_url *u) { return (br_slice){u->user, u->user_len}; }
static br_slice ftp_password(const ftp_url *u) { return (br_slice){u->password, u->password_len}; }
static br_slice ftp_bytes(br_bytes b) { return (br_slice){b.data, b.len}; }
static br_slice ftp_text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }
static int ftp_fail(char **error, const char *message)
{
    if (error) { free(*error); *error = strdup(message); }
    return -1;
}
static void ftp_clear(ftp_buf *b) { free(b->data); *b = (ftp_buf){0}; }
static int ftp_add(ftp_buf *b, const void *data, size_t n, char **error)
{
    if ((!data && n) || n > SIZE_MAX - b->len - 1) return ftp_fail(error, "FTP value is too large");
    size_t need = b->len + n + 1;
    if (need > b->cap) {
        size_t cap = b->cap ? b->cap : 64;
        while (cap < need) { if (cap > SIZE_MAX / 2) { cap = need; break; } cap *= 2; }
        void *p = realloc(b->data, cap);
        if (!p) return ftp_fail(error, "cannot allocate FTP value");
        b->data = p; b->cap = cap;
    }
    if (n) memcpy(b->data + b->len, data, n);
    b->len += n; b->data[b->len] = 0; return 0;
}
static int ftp_char(ftp_buf *b, unsigned char c, char **error) { return ftp_add(b, &c, 1, error); }
static void ftp_cause_clear(ftp_cause *c) { ftp_clear(&c->text); *c = (ftp_cause){0}; }
static int ftp_cause_set(ftp_cause *c, ftp_kind kind, br_slice text, char **error)
{
    ftp_cause_clear(c); c->kind = kind;
    return ftp_add(&c->text, text.data, text.len, error);
}
static void ftp_cause_move(ftp_cause *out, ftp_cause *in)
{
    ftp_cause_clear(out); *out = *in; *in = (ftp_cause){0};
}
static void ftp_io_cause(ftp_cause *out, br_bytes *owned)
{
    ftp_cause_clear(out); out->kind = FTP_IO;
    out->text = (ftp_buf){owned->data, owned->len, owned->len}; *owned = (br_bytes){0};
}
static bool ftp_same(br_slice s, const char *literal)
{
    size_t n = strlen(literal); return s.len == n && (!n || !memcmp(s.data, literal, n));
}
static size_t ftp_index(br_slice s, unsigned char c)
{
    const unsigned char *p = s.len ? memchr(s.data, c, s.len) : NULL;
    return p ? (size_t)(p - s.data) : SIZE_MAX;
}
static br_slice ftp_sub(br_slice s, size_t begin, size_t end)
{
    return (br_slice){s.data ? s.data + begin : NULL, end - begin};
}
static int ftp_hex(unsigned char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
/* Exact relevant columns of Go 1.26.7's encoding_table.go, NOT curl URL rules. */
enum { FTP_PATH = 1, FTP_HOST = 4, FTP_ZONE = 8, FTP_USER = 16, FTP_FRAGMENT = 64 };
static unsigned int ftp_permissions(unsigned char c)
{
    const unsigned int all = FTP_PATH | FTP_HOST | FTP_ZONE | FTP_USER | FTP_FRAGMENT;
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) return all;
    switch (c) {
    case '$': case '&': case '+': case ',': case ';': case '=': case '-': case '.': case '_': case '~': return all;
    case '!': case '(': case ')': case '*': return FTP_FRAGMENT | FTP_ZONE | FTP_HOST;
    case '"': case '\'': case '<': case '>': case '[': case ']': return FTP_ZONE | FTP_HOST;
    case '/': case '@': return FTP_FRAGMENT | FTP_PATH;
    case ':': return FTP_FRAGMENT | FTP_ZONE | FTP_HOST | FTP_PATH;
    case '?': return FTP_FRAGMENT;
    default: return 0;
    }
}
/* +1 ordinary URL parse rejection, -1 owned allocation failure. */
static int ftp_unescape(br_slice s, unsigned int mode, ftp_buf *out, char **error)
{
    for (size_t i = 0; i < s.len; ++i) {
        unsigned char c = s.data[i];
        if (c == '%') {
            if (s.len - i < 3 || ftp_hex(s.data[i+1]) < 0 || ftp_hex(s.data[i+2]) < 0) return 1;
            unsigned char value = (unsigned char)(ftp_hex(s.data[i+1]) * 16 + ftp_hex(s.data[i+2]));
            bool percent = s.data[i+1] == '2' && s.data[i+2] == '5';
            if (mode == FTP_HOST && value < 128 && !percent) return 1;
            if (mode == FTP_ZONE && !percent && value != ' ' && !(ftp_permissions(value) & FTP_HOST)) return 1;
            c = value; i += 2;
        } else if ((mode == FTP_HOST || mode == FTP_ZONE) && c < 128 && !(ftp_permissions(c) & mode)) return 1;
        if (ftp_char(out, c, error)) return -1;
    }
    return 0;
}
static int ftp_escape(br_slice s, unsigned int mode, ftp_buf *out, char **error)
{
    static const unsigned char hex[] = "0123456789ABCDEF";
    for (size_t i = 0; i < s.len; ++i) {
        unsigned char c = s.data[i];
        if (ftp_permissions(c) & mode) { if (ftp_char(out, c, error)) return -1; }
        else { unsigned char esc[] = {'%', hex[c >> 4], hex[c & 15]}; if (ftp_add(out, esc, 3, error)) return -1; }
    }
    return 0;
}
static bool ftp_valid_encoded(br_slice s, unsigned int mode)
{
    for (size_t i = 0; i < s.len; ++i)
        if (!s.data[i] || (!strchr("!$&'()*+,;=:@[]%", s.data[i]) && !(ftp_permissions(s.data[i]) & mode))) return false;
    return true;
}
static bool ftp_port(br_slice s)
{
    if (!s.len) return true;
    if (s.data[0] != ':') return false;
    for (size_t i = 1; i < s.len; ++i) if (s.data[i] < '0' || s.data[i] > '9') return false;
    return true;
}
static int ftp_host(br_slice raw, ftp_buf *host, char **error)
{
    size_t open = ftp_index(raw, '[');
    if (open != SIZE_MAX) {
        /* Go checks LAST '[' and LAST ']'. Multiple '[' cannot be an IP literal. */
        size_t last_open = open, close = SIZE_MAX;
        for (size_t i = open + 1; i < raw.len; ++i) if (raw.data[i] == '[') last_open = i;
        if (last_open != 0) return 1;
        for (size_t i = 1; i < raw.len; ++i) if (raw.data[i] == ']') close = i;
        if (close == SIZE_MAX || !ftp_port(ftp_sub(raw, close + 1, raw.len))) return 1;
        br_slice inside = ftp_sub(raw, 1, close); ftp_buf decoded = {0};
        size_t zone = br_slice_find(inside, ftp_text("%25"), 0);
        int rc = ftp_unescape(ftp_sub(inside, 0, zone == SIZE_MAX ? inside.len : zone), FTP_HOST, &decoded, error);
        if (!rc && zone != SIZE_MAX) rc = ftp_unescape(ftp_sub(inside, zone, inside.len), FTP_ZONE, &decoded, error);
        if (!rc) {
            size_t pct = ftp_index(ftp_slice(&decoded), '%');
            if (pct != SIZE_MAX && pct + 1 == decoded.len) rc = 1;
            size_t n = pct == SIZE_MAX ? decoded.len : pct;
            unsigned char address[16]; char ip[INET6_ADDRSTRLEN];
            /* IPv6 textual GRAMMAR bounds the base to 45 bytes, excluding its
             * independently retained zone. This is not a DNS/provider cap.
             * Literal validation never resolves or opens a socket. */
            if (n >= sizeof(ip)) rc = 1;
            else {
                if (n) memcpy(ip, decoded.data, n);
                ip[n] = 0;
                if (memchr(ip, 0, n) || inet_pton(AF_INET6, ip, address) != 1) rc = 1;
            }
        }
        if (!rc && (ftp_char(host, '[', error) || ftp_add(host, decoded.data, decoded.len, error) ||
                    ftp_char(host, ']', error) || ftp_add(host, raw.data + close + 1, raw.len - close - 1, error))) rc = -1;
        ftp_clear(&decoded); return rc;
    }
    size_t colon = SIZE_MAX;
    for (size_t i = 0; i < raw.len; ++i) if (raw.data[i] == ':') colon = i;
    /* FTP keeps Go's historical last-colon rule, NOT HTTP's strict-colon mode. */
    if (colon != SIZE_MAX && !ftp_port(ftp_sub(raw, colon, raw.len))) return 1;
    return ftp_unescape(raw, FTP_HOST, host, error);
}
static bool ftp_path_valid(br_slice path)
{
    /* Go's path-mode unescape rejects only malformed percent triplets here;
     * the decoded Path is cleared before String, so retain no redundant copy. */
    for (size_t i = 0; i < path.len; ++i) if (path.data[i] == '%') {
        if (path.len - i < 3 || ftp_hex(path.data[i+1]) < 0 || ftp_hex(path.data[i+2]) < 0) return false;
        i += 2;
    }
    return true;
}
static int ftp_decode_user(br_slice raw, unsigned char out[FTP_USERINFO_BYTES], size_t *used)
{
    *used = 0;
    for (size_t i = 0; i < raw.len; ++i) {
        unsigned char c = raw.data[i];
        if (c == '%') {
            if (raw.len - i < 3 || ftp_hex(raw.data[i+1]) < 0 || ftp_hex(raw.data[i+2]) < 0) return 1;
            c = (unsigned char)(ftp_hex(raw.data[i+1]) * 16 + ftp_hex(raw.data[i+2])); i += 2;
        }
        out[(*used)++] = c; /* Literal '+' stays '+', including decoded NUL. */
    }
    return 0;
}
static void ftp_url_clear(ftp_url *u)
{
    ftp_clear(&u->host); ftp_clear(&u->raw);
    memset(u, 0, sizeof(*u));
}
static int ftp_project(br_slice full, ftp_url *u, char **error)
{
    if (full.len < 6 || memcmp(full.data, "ftp://", 6)) return 1;
    /* Go Parse cuts #fragment BEFORE parse's C0/DEL check. Raw fragment
     * controls, including NUL, are decoded and percent-escaped by String. */
    size_t hash = ftp_index(full, '#');
    br_slice before_frag = ftp_sub(full, 0, hash == SIZE_MAX ? full.len : hash);
    for (size_t i = 0; i < before_frag.len; ++i) if (before_frag.data[i] < 32 || before_frag.data[i] == 127) return 1;
    br_slice frag = hash == SIZE_MAX ? (br_slice){0} : ftp_sub(full, hash + 1, full.len);
    size_t query_at = ftp_index(before_frag, '?');
    br_slice before_query = ftp_sub(before_frag, 0, query_at == SIZE_MAX ? before_frag.len : query_at);
    br_slice query = query_at == SIZE_MAX ? (br_slice){0} : ftp_sub(before_frag, query_at + 1, before_frag.len);
    size_t end = before_query.len;
    for (size_t i = 6; i < end; ++i) if (full.data[i] == '/') { end = i; break; }
    br_slice authority = ftp_sub(full, 6, end); size_t at = SIZE_MAX;
    for (size_t i = 0; i < authority.len; ++i) if (authority.data[i] == '@') at = i;
    int rc = ftp_host(at == SIZE_MAX ? authority : ftp_sub(authority, at + 1, authority.len), &u->host, error);
    if (rc) return rc;
    if (at == SIZE_MAX) return 1;
    br_slice info = ftp_sub(authority, 0, at);
    for (size_t i = 0; i < info.len; ++i) {
        unsigned char c = info.data[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              (c && strchr("-._:~!$&'()*+,;=%@", c)))) return 1;
    }
    size_t colon = ftp_index(info, ':'); if (colon == SIZE_MAX) return 1;
    rc = ftp_decode_user(ftp_sub(info, 0, colon), u->user, &u->user_len);
    if (!rc) rc = ftp_decode_user(ftp_sub(info, colon + 1, info.len), u->password, &u->password_len);
    if (rc) return rc;
    /* Parse validates Path even though the separately serialized copy clears it. */
    ftp_buf fragment = {0};
    rc = ftp_path_valid(ftp_sub(before_query, end, before_query.len)) ? 0 : 1;
    if (!rc) rc = ftp_unescape(frag, FTP_FRAGMENT, &fragment, error);
    if (!rc && ftp_same(ftp_user(u), "anonymous")) { ftp_clear(&fragment); return 1; }
    if (!rc && (ftp_add(&u->raw, "ftp://", 6, error) || ftp_escape(ftp_user(u), FTP_USER, &u->raw, error) ||
                ftp_char(&u->raw, ':', error) || ftp_escape(ftp_password(u), FTP_USER, &u->raw, error) ||
                ftp_char(&u->raw, '@', error) || ftp_escape(ftp_slice(&u->host), FTP_HOST, &u->raw, error))) rc = -1;
    if (!rc && query_at != SIZE_MAX && (ftp_char(&u->raw, '?', error) || ftp_add(&u->raw, query.data, query.len, error))) rc = -1;
    if (!rc && fragment.len) {
        if (ftp_char(&u->raw, '#', error)) rc = -1;
        else if (ftp_valid_encoded(frag, FTP_FRAGMENT)) rc = ftp_add(&u->raw, frag.data, frag.len, error);
        else rc = ftp_escape(ftp_slice(&fragment), FTP_FRAGMENT, &u->raw, error);
    }
    ftp_clear(&fragment); return rc;
}
/* Go strings.TrimSpace/Unicode White_Space, only the required literal encodings. */
static size_t ftp_space(br_slice s)
{
    if (!s.len) return 0;
    unsigned char c = s.data[0];
    if (c == ' ' || (c >= 9 && c <= 13)) return 1;
    if (s.len >= 2 && c == 0xc2 && (s.data[1] == 0x85 || s.data[1] == 0xa0)) return 2;
    if (s.len >= 3 && ((c == 0xe1 && s.data[1] == 0x9a && s.data[2] == 0x80) ||
        (c == 0xe2 && s.data[1] == 0x80 && (s.data[2] >= 0x80 && s.data[2] <= 0x8a)) ||
        (c == 0xe2 && s.data[1] == 0x80 && (s.data[2] == 0xa8 || s.data[2] == 0xa9 || s.data[2] == 0xaf)) ||
        (c == 0xe2 && s.data[1] == 0x81 && s.data[2] == 0x9f) ||
        (c == 0xe3 && s.data[1] == 0x80 && s.data[2] == 0x80))) return 3;
    return 0;
}
static br_slice ftp_trim(br_slice s)
{
    size_t n;
    while ((n = ftp_space(s)) != 0) s = ftp_sub(s, n, s.len);
    for (;;) {
        bool cut = false;
        for (n = 1; n <= 3 && n <= s.len; ++n)
            if (ftp_space(ftp_sub(s, s.len - n, s.len)) == n) { s.len -= n; cut = true; break; }
        if (!cut) return s;
    }
}
static int ftp_replace(br_slice input, br_slice secret, const char *replacement, ftp_buf *out, char **error)
{
    size_t at = 0;
    if (secret.len) for (;;) {
        size_t next = br_slice_find(input, secret, at); if (next == SIZE_MAX) break;
        if (ftp_add(out, input.data + at, next - at, error) || ftp_add(out, replacement, strlen(replacement), error)) return -1;
        at = next + secret.len;
    }
    return ftp_add(out, input.data ? input.data + at : NULL, input.len - at, error);
}
static int ftp_timeout(const br_ftp_state *state, const br_scan_ctx *ctx, int64_t *timeout, char **error)
{
    if (state->timeout_ns > 0) { *timeout = state->timeout_ns; return 0; }
    if (!ctx) return ftp_fail(error, "unsupported upstream panic: FTP nil context Deadline");
    if (!ctx->deadline_monotonic_ms) { *timeout = INT64_C(5000000000); return 0; }
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) || now.tv_sec < 0 || now.tv_sec > INT64_MAX / INT64_C(1000000000))
        return ftp_fail(error, "cannot obtain FTP monotonic time");
    int64_t d = ctx->deadline_monotonic_ms;
    if (d > INT64_MAX / INT64_C(1000000) || d < INT64_MIN / INT64_C(1000000))
        return ftp_fail(error, "unsupported: FTP deadline cannot be represented in nanoseconds");
    int64_t deadline = d * INT64_C(1000000), current = (int64_t)now.tv_sec * INT64_C(1000000000);
    if (current > INT64_MAX - now.tv_nsec) return ftp_fail(error, "unsupported: FTP clock range");
    current += now.tv_nsec;
    if (deadline < INT64_MIN + current) return ftp_fail(error, "unsupported: FTP remaining timeout range");
    *timeout = deadline - current; return 0;
}
static int ftp_io_valid(int rc, br_bytes cause, char **error)
{
    if ((!cause.data && cause.len) || (rc != 0 && rc != 1 && rc != -1))
        return ftp_fail(error, "invalid FTP I/O callback result");
    return rc < 0 ? ftp_fail(error, "FTP I/O resource failure") : 0;
}
static int ftp_line(ftp_session *s, ftp_buf *line, ftp_cause *cause, char **error)
{
    for (;;) {
        while (s->pos < s->len) {
            unsigned char c = s->input[s->pos++];
            if (c == '\n') {
                if (line->len && line->data[line->len-1] == '\r') --line->len;
                if (line->data) line->data[line->len] = 0;
                return 0;
            }
            if (ftp_char(line, c, error)) return -1;
        }
        if (s->pending.kind != FTP_NONE || s->eof) {
            /* bufio.ReadLine yields an unterminated final fragment first and
             * defers its pending ordinary error/EOF until the following read. */
            if (line->len) return 0;
            if (s->pending.kind != FTP_NONE) ftp_cause_move(cause, &s->pending);
            else if (ftp_cause_set(cause, FTP_IO, ftp_text("EOF"), error)) return -1;
            return 1;
        }
        s->pos = s->len = 0; br_bytes owned = {0}; size_t n = 0;
        int rc = s->state->io->read(s->state->user, s->conn, s->input, sizeof(s->input), &n, &owned);
        if (ftp_io_valid(rc, owned, error) || n > sizeof(s->input)) {
            free(owned.data); if (n > sizeof(s->input)) ftp_fail(error, "invalid FTP read length"); return -1;
        }
        s->len = n;
        if (rc) ftp_io_cause(&s->pending, &owned);
        else if (!n) s->eof = true;
        free(owned.data);
    }
}
static ftp_code ftp_code_line(br_slice line)
{
    ftp_code out = {0};
    if (line.len < 4 || (line.data[3] != ' ' && line.data[3] != '-')) { out.bad = FTP_SHORT; return out; }
    out.more = line.data[3] == '-';
    for (size_t i = 0; i < 3; ++i) {
        if (line.data[i] < '0' || line.data[i] > '9') { out.code = 0; out.bad = FTP_BAD_CODE; return out; }
        out.code = out.code * 10 + line.data[i] - '0';
    }
    if (out.code < 100) { out.bad = FTP_BAD_CODE; return out; }
    out.message = ftp_sub(line, 4, line.len); return out;
}
static int ftp_response(ftp_session *s, int expected, int *code, ftp_buf *message, ftp_cause *cause, char **error)
{
    ftp_buf line = {0}; int rc = ftp_line(s, &line, cause, error);
    if (rc) { ftp_clear(&line); return rc; }
    ftp_code initial = ftp_code_line(ftp_slice(&line)); *code = initial.code;
    bool failed = initial.bad != FTP_NONE || (expected > 0 && initial.code != expected);
    ftp_cause saved = {0};
    if (failed) {
        saved.kind = initial.bad ? initial.bad : FTP_REPLY; saved.code = initial.code;
        br_slice detail = initial.bad ? ftp_slice(&line) : initial.message;
        if (ftp_add(&saved.text, detail.data, detail.len, error)) rc = -1;
    }
    if (!rc && ftp_add(message, initial.message.data, initial.message.len, error)) rc = -1;
    bool more = initial.more;
    while (!rc && more) {
        ftp_clear(&line); rc = ftp_line(s, &line, cause, error);
        if (rc) break; /* Reader error overrides any initial reply/protocol error. */
        ftp_code next = ftp_code_line(ftp_slice(&line)); br_slice part;
        if (next.bad || next.code != initial.code) {
            part = ftp_slice(&line);
            while (part.len && (part.data[part.len-1] == '\r' || part.data[part.len-1] == '\n')) --part.len;
            more = true;
        } else { part = next.message; more = next.more; }
        if (ftp_char(message, '\n', error) || ftp_add(message, part.data, part.len, error)) rc = -1;
    }
    if (!rc && failed) {
        if (initial.more && message->len) {
            ftp_cause_clear(&saved); saved.kind = FTP_REPLY; saved.code = initial.code;
            if (ftp_add(&saved.text, message->data, message->len, error)) rc = -1;
        }
        if (!rc) { ftp_cause_move(cause, &saved); rc = 1; }
    }
    ftp_clear(&line); ftp_cause_clear(&saved); return rc;
}
static int ftp_write(ftp_session *s, br_slice frame, ftp_cause *cause, char **error)
{
    if (s->writer_failed) return 1; /* QUIT cannot bypass bufio's sticky error. */
    br_bytes owned = {0}; size_t n = 0;
    int rc = s->state->io->write(s->state->user, s->conn, frame, &n, &owned);
    if (ftp_io_valid(rc, owned, error) || n > frame.len) {
        s->writer_failed = true;
        free(owned.data); if (n > frame.len) ftp_fail(error, "invalid FTP write length"); return -1;
    }
    if (rc || n < frame.len) {
        s->writer_failed = true;
        if (cause) {
            if (rc) ftp_io_cause(cause, &owned);
            else if (ftp_cause_set(cause, FTP_IO, ftp_text("short write"), error)) { free(owned.data); return -1; }
        }
        free(owned.data); return 1;
    }
    free(owned.data); return 0;
}
static int ftp_exchange(ftp_session *s, const char *verb, const br_slice *arg, int expected,
                        int *code, ftp_buf *message, ftp_cause *cause, char **error)
{
    if (arg && (ftp_index(*arg, '\r') != SIZE_MAX || ftp_index(*arg, '\n') != SIZE_MAX))
        return ftp_fail(error, "unsupported: FTP credential CR/LF command injection");
    /* Fixed commands already include CRLF and are BORROWED. USER/PASS use
     * grammar-bounded storage: the two 50-rune regex fields plus ':' contain
     * at most 101 ASCII userinfo bytes after validUserinfo; decoding shrinks.
     * No formatter, redundant heap staging or artificial failure/cap seam. */
    unsigned char frame[5 + FTP_USERINFO_BYTES + 2]; br_slice command = ftp_text(verb);
    if (arg) {
        memcpy(frame, verb, 5);
        if (arg->len) memcpy(frame + 5, arg->data, arg->len);
        memcpy(frame + 5 + arg->len, "\r\n", 2);
        command = (br_slice){frame, 5 + arg->len + 2};
    }
    int rc = ftp_write(s, command, cause, error);
    if (!rc) rc = ftp_response(s, expected, code, message, cause, error);
    return rc;
}
static bool ftp_utf8_feature(br_slice message)
{
    size_t at = 0;
    while (at <= message.len) {
        size_t end = at; while (end < message.len && message.data[end] != '\n') ++end;
        br_slice line = ftp_sub(message, at, end);
        if (line.len && line.data[0] == ' ') {
            line = ftp_trim(line); size_t space = ftp_index(line, ' ');
            if (ftp_same(ftp_sub(line, 0, space == SIZE_MAX ? line.len : space), "UTF8")) return true;
        }
        if (end == message.len) break;
        at = end + 1;
    }
    return false;
}
static int ftp_verify(const br_ftp_state *state, const br_scan_ctx *ctx, const ftp_url *url,
                      ftp_cause *cause, char **error)
{
    int64_t timeout; int rc = ftp_timeout(state, ctx, &timeout, error); if (rc) return rc;
    if (!state->io) return ftp_cause_set(cause, FTP_IO, ftp_text("unsupported: native FTP verification"), error) ? -1 : 1;
    const br_ftp_io *io = state->io;
    if (!io->dial || !io->deadline_after || !io->read || !io->write || !io->close)
        return ftp_fail(error, "invalid FTP I/O configuration: all five callbacks are required");
    ftp_buf address = {0}, message = {0}; ftp_session session = {.state = state}; br_bytes owned = {0};
    if (ftp_add(&address, url->host.data, url->host.len, error) ||
        (ftp_index(ftp_slice(&url->host), ':') == SIZE_MAX && ftp_add(&address, ":21", 3, error))) { ftp_clear(&address); return -1; }
    rc = io->dial(state->user, ftp_slice(&address), timeout, &session.conn, &owned); ftp_clear(&address);
    if (ftp_io_valid(rc, owned, error)) rc = -1;
    if (rc) { if (rc > 0) ftp_io_cause(cause, &owned); goto close_only; }
    free(owned.data); owned = (br_bytes){0};
    if (!session.conn.handle) { rc = ftp_fail(error, "unsupported upstream panic: FTP nil connection"); goto close_only; }
    rc = io->deadline_after(state->user, session.conn, timeout, &owned);
    if (ftp_io_valid(rc, owned, error)) rc = -1;
    if (rc) { if (rc > 0) ftp_io_cause(cause, &owned); goto close_only; }
    free(owned.data); owned = (br_bytes){0};
    if (!session.conn.tcp) { rc = ftp_fail(error, "unsupported upstream panic: FTP RemoteAddr is not TCP"); goto close_only; }
    int code = 0;
    rc = ftp_response(&session, 220, &code, &message, cause, error); ftp_clear(&message);
    if (rc) goto quit;
    br_slice user = ftp_user(url), password = ftp_password(url);
    rc = ftp_exchange(&session, "USER ", &user, -1, &code, &message, cause, error);
    if (rc) goto quit;
    if (code == 331) {
        ftp_clear(&message); rc = ftp_exchange(&session, "PASS ", &password, 230, &code, &message, cause, error);
        if (rc) goto quit;
    } else if (code != 230) { rc = ftp_cause_set(cause, FTP_MESSAGE, ftp_slice(&message), error) ? -1 : 1; goto quit; }
    ftp_clear(&message); rc = ftp_exchange(&session, "FEAT\r\n", NULL, -1, &code, &message, cause, error);
    if (rc) goto quit;
    bool utf8 = code == 211 && ftp_utf8_feature(ftp_slice(&message));
    ftp_clear(&message); rc = ftp_exchange(&session, "TYPE I\r\n", NULL, 200, &code, &message, cause, error);
    if (rc) goto quit;
    if (utf8) {
        ftp_clear(&message); rc = ftp_exchange(&session, "OPTS UTF8 ON\r\n", NULL, -1, &code, &message, cause, error);
        if (rc) goto quit;
        if (code != 200 && code != 202 && code != 501 && code != 504)
            rc = ftp_cause_set(cause, FTP_MESSAGE, ftp_slice(&message), error) ? -1 : 1;
    }
quit:
    /* Dial banner errors and every Login exit attempt QUIT through the SAME
     * writer, never read 221. Ordinary cleanup errors cannot replace outcome;
     * genuine callback/resource failure is fatal even during cleanup. */
    if (ftp_write(&session, ftp_text("QUIT\r\n"), NULL, error) < 0) rc = -1;
close_only:
    free(owned.data); ftp_clear(&message); ftp_cause_clear(&session.pending);
    if (session.conn.handle) io->close(state->user, session.conn);
    return rc;
}
/* Go 1.26.7 %q for ASCII diagnostic lines. Narrow unsupported boundary only
 * when a protocol error actually REQUIRES non-ASCII Go quoting; ordinary
 * messages, successful replies and ignored lines remain arbitrary bytes. */
static int ftp_quote(br_slice line, ftp_buf *out, char **error)
{
    static const char hex[] = "0123456789abcdef";
    if (ftp_char(out, '"', error)) return -1;
    for (size_t i = 0; i < line.len; ++i) {
        unsigned char c = line.data[i]; const char *esc = NULL;
        switch (c) {
        case '\a': esc = "\\a"; break; case '\b': esc = "\\b"; break;
        case '\f': esc = "\\f"; break; case '\n': esc = "\\n"; break;
        case '\r': esc = "\\r"; break; case '\t': esc = "\\t"; break;
        case '\v': esc = "\\v"; break; case '\\': esc = "\\\\"; break; case '"': esc = "\\\""; break;
        default: break;
        }
        if (c >= 128) return ftp_fail(error, "unsupported: FTP non-ASCII Go protocol diagnostic quoting");
        if (esc) { if (ftp_add(out, esc, 2, error)) return -1; }
        else if (c < 32 || c == 127) { char x[] = {'\\', 'x', hex[c >> 4], hex[c & 15]}; if (ftp_add(out, x, 4, error)) return -1; }
        else if (ftp_char(out, c, error)) return -1;
    }
    return ftp_char(out, '"', error);
}
static int ftp_publish_error(br_result *result, const ftp_cause *cause, br_slice captured, char **error)
{
    if (cause->kind == FTP_REPLY && cause->code == 530) return 0;
    if (cause->kind == FTP_NONE)
        return br_result_set_verification_error(result, NULL, &captured, 1) == 0 ? 0 : ftp_fail(error, "cannot sanitize FTP verification error");
    ftp_buf text = {0}, sanitized = {0}; int rc = 0;
    if (cause->kind == FTP_REPLY) {
        char code[16]; int n = snprintf(code, sizeof(code), "%03d ", cause->code);
        if (n < 0 || (size_t)n >= sizeof(code)) rc = ftp_fail(error, "cannot format FTP reply error");
        else rc = ftp_add(&text, code, (size_t)n, error);
    } else if (cause->kind == FTP_SHORT || cause->kind == FTP_BAD_CODE) {
        const char *prefix = cause->kind == FTP_SHORT ? "short response: " : "invalid response code: ";
        if (ftp_add(&text, prefix, strlen(prefix), error) || ftp_quote(ftp_slice(&cause->text), &text, error)) rc = -1;
    }
    if (!rc && cause->kind != FTP_SHORT && cause->kind != FTP_BAD_CODE)
        rc = ftp_add(&text, cause->text.data, cause->text.len, error);
    if (!rc) rc = ftp_replace(ftp_slice(&text), captured, "[REDACTED]", &sanitized, error);
    /* Required quoting and captured-password redaction precede the ABI1 NUL
     * boundary. Typed determinate 530 never reaches it. Never truncate bytes. */
    if (!rc && ftp_index(ftp_slice(&sanitized), 0) != SIZE_MAX)
        rc = ftp_fail(error, "unsupported: FTP published verification error contains embedded NUL");
    if (!rc && br_result_set_verification_error(result, (const char *)sanitized.data, NULL, 0) != 0)
        rc = ftp_fail(error, "cannot sanitize FTP verification error");
    ftp_clear(&text); ftp_clear(&sanitized); return rc;
}
static int ftp_collect(void *user, const br_span *groups, size_t n)
{
    ftp_matches *m = user;
    if (n < 2 || groups[0].begin == SIZE_MAX || groups[1].begin == SIZE_MAX ||
        groups[0].end > m->input.len || groups[1].end > m->input.len ||
        groups[0].end <= groups[0].begin || groups[1].end <= groups[1].begin)
        return ftp_fail(&m->error, "invalid FTP capture");
    if (m->len == m->cap) {
        if (m->cap > SIZE_MAX / sizeof(*m->items) / 2) return ftp_fail(&m->error, "too many FTP captures");
        size_t cap = m->cap ? m->cap * 2 : 8;
        void *p = realloc(m->items, cap * sizeof(*m->items));
        if (!p) return ftp_fail(&m->error, "cannot allocate FTP captures");
        m->items = p; m->cap = cap;
    }
    ftp_match item = {0};
    item.url.len = groups[0].end - groups[0].begin; item.password.len = groups[1].end - groups[1].begin;
    item.url.data = malloc(item.url.len); item.password.data = malloc(item.password.len);
    if (!item.url.data || !item.password.data) { free(item.url.data); free(item.password.data); return ftp_fail(&m->error, "cannot copy FTP captures"); }
    memcpy(item.url.data, m->input.data + groups[0].begin, item.url.len);
    memcpy(item.password.data, m->input.data + groups[1].begin, item.password.len);
    m->items[m->len++] = item; return 0;
}
static int ftp_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                    br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len)) return ftp_fail(error, "invalid FTP scan");
    const br_ftp_state *state = detector->state;
    if (!state->regex) return ftp_fail(error, "uninitialized FTP scan");
    size_t original = out->len; ftp_matches matches = {.input = input}; char *owned = NULL;
    int rc = br_regex_each(state->regex, input, ftp_collect, &matches, &owned);
    if (matches.error) { free(owned); owned = matches.error; matches.error = NULL; }
    for (size_t i = 0; !rc && i < matches.len; ++i) {
        ftp_match *match = &matches.items[i]; br_slice captured = ftp_bytes(match->password);
        bool stars = true; for (size_t j = 0; j < captured.len; ++j) if (captured.data[j] != '*') stars = false;
        if (stars) continue;
        ftp_url url = {0}; br_result result = {0}; ftp_cause cause = {0}; ftp_buf redacted = {0};
        int parsed = ftp_project(ftp_bytes(match->url), &url, &owned);
        if (parsed < 0) rc = -1;
        else if (!parsed && !ftp_same(ftp_user(&url), "anonymous")) {
            if (br_finding_key_bytes(&result, detector->type, ftp_slice(&url.raw), "key") != 0)
                rc = ftp_fail(&owned, "cannot create FTP finding");
            if (!rc && ftp_replace(ftp_slice(&url.raw), captured, "********", &redacted, &owned)) rc = -1;
            if (!rc) {
                br_slice trimmed = ftp_trim(ftp_slice(&redacted));
                result.redacted = malloc(trimmed.len + 1);
                if (!result.redacted) rc = ftp_fail(&owned, "cannot create FTP Redacted value");
                else { if (trimmed.len) memcpy(result.redacted, trimmed.data, trimmed.len); result.redacted[trimmed.len] = 0; }
            }
            if (!rc && verify) {
                int verified = ftp_verify(state, ctx, &url, &cause, &owned);
                if (verified < 0) rc = -1;
                else { result.verified = verified == 0; rc = ftp_publish_error(&result, &cause, captured, &owned); }
            }
            /* Required owned work precedes the source unverified/NoV $ drop. */
            if (!rc && !(!result.verified && captured.len && captured.data[0] == '$') && br_results_push(out, &result) != 0)
                rc = ftp_fail(&owned, "cannot append FTP finding");
        }
        ftp_url_clear(&url); ftp_cause_clear(&cause); ftp_clear(&redacted); br_result_clear(&result);
    }
    if (rc) while (out->len > original) br_result_clear(&out->items[--out->len]);
    for (size_t i = 0; i < matches.len; ++i) { free(matches.items[i].url.data); free(matches.items[i].password.data); }
    free(matches.items); free(matches.error);
    if (error) *error = owned; else free(owned);
    return rc ? -1 : 0;
}
static bool ftp_false_positive(const br_detector *detector, const br_result *result, char **reason)
{
    (void)detector; if (reason) *reason = NULL;
    if (!result) return false;
    static const char *const terms[] = {"@ftp.freebsd.org"};
    return br_known_false_positive((br_slice){result->raw.data, result->raw.len}, terms, 1, false, reason);
}
static br_ftp_state ftp_state;
static const char *const ftp_keywords[] = {"ftp://"};
static const br_detector ftp_detector = {
    .type = 899, .version = 0, .name = "FTP", .custom_name = "",
    .description = "FTP is a protocol for reading and writing files. An FTP password can be used to read and sometimes write files.",
    .keywords = ftp_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .state = &ftp_state, .scan = ftp_scan, .false_positive = ftp_false_positive,
};
int br_ftp_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return ftp_fail(error, "invalid FTP detector output");
    *out = NULL;
    /* RE2 nonwhitespace excludes HT/LF/FF/CR/SP, NOT VT. Keep greedy group 0
     * and separately captured password: it need not be parsed URL credentials. */
    if (!ftp_state.regex && br_regex_compile("\\bftp://[^\\t\\n\\f\\r ]{3,50}:([^\\t\\n\\f\\r ]{3,50})@[-.%\\w/:]+\\b", &ftp_state.regex, error) != 0) return -1;
    *out = &ftp_detector; return 0;
}
/* Deliberately no native resolver/socket/FTP calls. Native verification remains
 * an explicit unsupported cause. Scripted private I/O validates this C provider,
 * not a full Go oracle, native runtime, global engine or output-parity claim. */
