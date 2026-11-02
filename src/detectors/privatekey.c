/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/privatekey. SSH and the
 * retryable fingerprint client never dial. Certificate JSON is parsed only
 * after an injected send succeeds. */
#include "detectors.h"
#include "findings.h"
#include "json.h"
#include "privatekey_wordlist.inc"

#include <json-c/json.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int pk_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static int pk_replace(br_bytes *buf, const char *needle, const char *repl)
{
    size_t nlen = strlen(needle), rlen = strlen(repl);
    if (!nlen) return 0;
    size_t count = 0;
    for (size_t i = 0; i <= buf->len && nlen <= buf->len - i;) {
        if (!memcmp(buf->data + i, needle, nlen)) {
            ++count;
            i += nlen;
        } else ++i;
    }
    if (!count) return 0;
    if (buf->len == SIZE_MAX ||
        (rlen > nlen && count > (SIZE_MAX - buf->len - 1) / (rlen - nlen))) return -1;
    size_t next = rlen > nlen ? buf->len + count * (rlen - nlen) :
                               buf->len - count * (nlen - rlen);
    unsigned char *out = malloc(next + 1);
    if (!out) return -1;
    size_t n = 0;
    for (size_t i = 0; i < buf->len;) {
        if (nlen <= buf->len - i && !memcmp(buf->data + i, needle, nlen)) {
            if (rlen) memcpy(out + n, repl, rlen);
            n += rlen;
            i += nlen;
        } else out[n++] = buf->data[i++];
    }
    out[n] = '\0';
    free(buf->data);
    buf->data = out;
    buf->len = n;
    return 0;
}

static bool pk_space(unsigned char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}

static int pk_normalize(br_slice input, br_bytes *out, char **error)
{
    *out = (br_bytes){0};
    if (input.len == SIZE_MAX) return pk_fail(error, "private key is too large");
    out->data = malloc(input.len + 1);
    if (!out->data) return pk_fail(error, "cannot normalize private key");
    if (input.len) memcpy(out->data, input.data, input.len);
    out->data[input.len] = '\0';
    out->len = input.len;
    const char *const steps[][2] = {
        {"\"", ""}, {"'", ""}, {"\t", ""}, {"\\t", ""}, {"\\\\t", ""},
        {"\\n", "\n"}, {"\\\\r\\\\n", "\n"}, {"\\r\\n", "\n"}, {"\r\n", "\n"},
        {"\\\\r", "\n"}, {"\r", "\n"}, {"\\r", "\n"}, {"\\\\n", "\n"},
        {"\\n\\n", "\n"}, {"\n\n", "\n"}, {"\\\\", "\n"},
    };
    for (size_t i = 0; i < sizeof(steps) / sizeof(steps[0]); ++i)
        if (pk_replace(out, steps[i][0], steps[i][1]) != 0) {
            free(out->data);
            *out = (br_bytes){0};
            return pk_fail(error, "cannot normalize private key");
        }
    size_t lines = 1;
    for (size_t i = 0; i < out->len; ++i) if (out->data[i] == '\n') ++lines;
    if (lines > SIZE_MAX - out->len - 1) {
        free(out->data); *out = (br_bytes){0};
        return pk_fail(error, "normalized private key is too large");
    }
    br_bytes cleaned = {0};
    cleaned.data = malloc(out->len + lines + 1);
    if (!cleaned.data) {
        free(out->data);
        *out = (br_bytes){0};
        return pk_fail(error, "cannot normalize private key");
    }
    for (size_t i = 0; i < out->len || (i == 0 && !out->len);) {
        size_t start = i, end = i;
        while (end < out->len && out->data[end] != '\n') ++end;
        size_t left = start, right = end;
        while (left < right && pk_space(out->data[left])) ++left;
        while (right > left && pk_space(out->data[right - 1])) --right;
        if (right > left) {
            memcpy(cleaned.data + cleaned.len, out->data + left, right - left);
            cleaned.len += right - left;
        }
        cleaned.data[cleaned.len++] = '\n';
        if (end >= out->len) break;
        i = end + 1;
        if (i == out->len) {
            /* A trailing newline produces the empty final split element. */
            cleaned.data[cleaned.len++] = '\n';
            break;
        }
    }
    cleaned.data[cleaned.len] = '\0';
    free(out->data);
    *out = cleaned;
    return 0;
}

static int pk_b64(int c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int pk_decode_b64(br_slice text, br_bytes *out, bool *valid)
{
    *out = (br_bytes){0};
    *valid = false;
    if (text.len == SIZE_MAX) return -1;
    out->data = malloc(text.len + 1);
    if (!out->data) return -1;
    unsigned value = 0;
    int bits = 0;
    for (size_t i = 0; i < text.len; ++i) {
        unsigned char c = text.data[i];
        if (c == '=' || pk_space(c)) continue;
        int digit = pk_b64(c);
        if (digit < 0) {
            free(out->data);
            *out = (br_bytes){0};
            return 0;
        }
        value = (value << 6) | (unsigned)digit;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out->data[out->len++] = (unsigned char)((value >> bits) & 0xff);
        }
    }
    out->data[out->len] = '\0';
    *valid = true;
    return 0;
}

static int pk_openssh_encrypted(br_slice token, bool *encrypted)
{
    *encrypted = false;
    const char *begin = "-----BEGIN OPENSSH PRIVATE KEY-----";
    const char *end = "-----END OPENSSH PRIVATE KEY-----";
    br_slice body = {0};
    for (size_t i = 0; i + strlen(begin) <= token.len; ++i) {
        if (memcmp(token.data + i, begin, strlen(begin))) continue;
        size_t start = i + strlen(begin);
        for (size_t j = start; j + strlen(end) <= token.len; ++j) {
            if (!memcmp(token.data + j, end, strlen(end))) {
                body = (br_slice){token.data + start, j - start};
                break;
            }
        }
        break;
    }
    if (!body.data) return 0;
    br_bytes decoded = {0};
    bool valid = false;
    if (pk_decode_b64(body, &decoded, &valid) != 0) return -1;
    if (!valid) return 0; /* Malformed input is not an encrypted key. */
    static const char magic[] = "openssh-key-v1";
    if (decoded.len >= sizeof(magic) && !memcmp(decoded.data, magic, sizeof(magic) - 1) &&
        decoded.data[sizeof(magic) - 1] == 0 && decoded.len >= sizeof(magic) + 4) {
        size_t at = sizeof(magic);
        unsigned n = ((unsigned)decoded.data[at] << 24) | ((unsigned)decoded.data[at + 1] << 16) |
                     ((unsigned)decoded.data[at + 2] << 8) | decoded.data[at + 3];
        at += 4;
        if (n <= decoded.len - at)
            *encrypted = !(n == 4 && !memcmp(decoded.data + at, "none", 4));
    }
    free(decoded.data);
    return 0;
}

static int pk_pem_encrypted(br_slice token, bool *encrypted)
{
    *encrypted = false;
    const char *marker = "ENCRYPTED";
    for (size_t i = 0; i + 9 <= token.len; ++i) {
        if (!memcmp(token.data + i, marker, 9)) {
            *encrypted = true;
            return 0;
        }
    }
    return pk_openssh_encrypted(token, encrypted);
}

static int pk_password(char *buf, int size, int rwflag, void *user)
{
    (void)rwflag;
    const char *password = user ? user : "";
    size_t n = strlen(password);
    if (n > (size_t)size) n = (size_t)size;
    if (n) memcpy(buf, password, n);
    return (int)n;
}

static int pk_read(br_slice token, const char *password, EVP_PKEY **key, char **error)
{
    *key = NULL;
    if (token.len > INT_MAX) return pk_fail(error, "unsupported: private key exceeds native length interface");
    BIO *bio = BIO_new_mem_buf(token.data, (int)token.len);
    if (!bio) return pk_fail(error, "cannot read private key");
    ERR_clear_error();
    *key = PEM_read_bio_PrivateKey(bio, NULL, pk_password, (void *)(password ? password : ""));
    unsigned long code = ERR_peek_error();
    bool oom = false;
    while ((code = ERR_get_error()))
        if (ERR_GET_REASON(code) == ERR_R_MALLOC_FAILURE) oom = true;
    BIO_free(bio);
    if (oom) {
        EVP_PKEY_free(*key);
        *key = NULL;
        return pk_fail(error, "cannot allocate private key");
    }
    return 0;
}

static int pk_crack(br_slice token, EVP_PKEY **key, char **passphrase, char **error)
{
    *key = NULL;
    *passphrase = NULL;
    const char *cursor = privatekey_wordlist;
    while (*cursor) {
        const char *nl = strchr(cursor, '\n');
        size_t n = nl ? (size_t)(nl - cursor) : strlen(cursor);
        char *word = malloc(n + 1);
        if (!word) return pk_fail(error, "cannot crack private key");
        if (n) memcpy(word, cursor, n);
        word[n] = '\0';
        int rc = pk_read(token, word, key, error);
        if (rc != 0) {
            free(word);
            return -1;
        }
        if (*key) {
            *passphrase = word;
            return 0;
        }
        free(word);
        if (!nl) break;
        cursor = nl + 1;
    }
    return 0; /* Ordinary exhaustion: no key, not an owned-operation failure. */
}

static int pk_fingerprint(EVP_PKEY *key, char **hex, char **error)
{
    *hex = NULL;
    int kind = EVP_PKEY_base_id(key);
    if (kind != EVP_PKEY_RSA && kind != EVP_PKEY_EC && kind != EVP_PKEY_ED25519)
        return pk_fail(error, "unsupported: private key public-key type");
    unsigned char *der = NULL;
    int n = i2d_PUBKEY(key, &der);
    if (n < 0 || !der) return pk_fail(error, "cannot fingerprint private key");
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    if (EVP_Digest(der, (size_t)n, digest, &digest_len, EVP_sha1(), NULL) != 1 || digest_len != 20) {
        OPENSSL_free(der);
        return pk_fail(error, "cannot fingerprint private key");
    }
    OPENSSL_free(der);
    *hex = malloc(digest_len * 2 + 1);
    if (!*hex) return pk_fail(error, "cannot fingerprint private key");
    static const char digits[] = "0123456789abcdef";
    for (unsigned i = 0; i < digest_len; ++i) {
        (*hex)[i * 2] = digits[digest[i] >> 4];
        (*hex)[i * 2 + 1] = digits[digest[i] & 0xf];
    }
    (*hex)[digest_len * 2] = '\0';
    return 0;
}

static int pk_extra_put(br_json *object, const char *name, const char *value)
{
    br_json *part = json_object_new_string(value);
    if (!part || json_object_object_add(object, name, part) != 0) {
        json_object_put(part);
        return -1;
    }
    return 0;
}

static time_t pk_timegm(const struct tm *tm)
{
    int64_t year = tm->tm_year + 1900;
    unsigned month = (unsigned)tm->tm_mon + 1;
    year -= month <= 2;
    int64_t era = (year >= 0 ? year : year - 399) / 400;
    unsigned yoe = (unsigned)(year - era * 400);
    unsigned doy = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + (unsigned)tm->tm_mday - 1;
    unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return (time_t)((era * 146097 + (int64_t)doe - 719468) * 86400 +
                    tm->tm_hour * 3600 + tm->tm_min * 60 + tm->tm_sec);
}

static bool pk_expired(const char *timestamp)
{
    int year, month, day, hour, minute, second, zone_hour = 0, zone_minute = 0;
    char zone = 'Z';
    if (sscanf(timestamp, "%d-%d-%dT%d:%d:%d%c%d:%d", &year, &month, &day, &hour, &minute,
               &second, &zone, &zone_hour, &zone_minute) < 6)
        return true;
    struct tm parsed = {0};
    parsed.tm_year = year - 1900;
    parsed.tm_mon = month - 1;
    parsed.tm_mday = day;
    parsed.tm_hour = hour;
    parsed.tm_min = minute;
    parsed.tm_sec = second;
    time_t when = pk_timegm(&parsed);
    if (when == (time_t)-1) return true;
    if (zone == '+') when -= zone_hour * 3600 + zone_minute * 60;
    if (zone == '-') when += zone_hour * 3600 + zone_minute * 60;
    return time(NULL) > when;
}

typedef struct {
    char **urls;
    size_t len, cap;
    bool include_expired;
    char *error;
} pk_certs;

static int pk_cert(void *user, size_t index, br_json *value, br_slice encoded)
{
    (void)index;
    (void)value;
    pk_certs *certs = user;
    br_json *object = NULL;
    char *cause = NULL;
    if (br_json_document(encoded, &object, &cause) != 0) {
        pk_fail(&certs->error, cause ? cause : "cannot decode private-key certificate");
        free(cause);
        json_object_put(object);
        return -1;
    }
    free(cause);
    br_json *fingerprint = NULL, *expiration = NULL;
    json_object_object_get_ex(object, "CertificateFingerprint", &fingerprint);
    json_object_object_get_ex(object, "ExpirationTimestamp", &expiration);
    const char *fp = fingerprint && json_object_is_type(fingerprint, json_type_string)
                         ? json_object_get_string(fingerprint) : NULL;
    const char *when = expiration && json_object_is_type(expiration, json_type_string)
                           ? json_object_get_string(expiration) : NULL;
    bool skip = !fp || !*fp || (!certs->include_expired && (!when || pk_expired(when)));
    for (size_t i = 0; fp && i < certs->len; ++i)
        if (!strcmp(certs->urls[i] + strlen("https://crt.sh/?q="), fp)) skip = true;
    if (!skip) {
        size_t fp_len = strlen(fp);
        if (fp_len > SIZE_MAX - sizeof("https://crt.sh/?q=")) {
            json_object_put(object); return pk_fail(&certs->error, "certificate URL is too large");
        }
        size_t url_len = sizeof("https://crt.sh/?q=") + fp_len;
        char *url = malloc(url_len);
        if (!url) {
            json_object_put(object);
            return pk_fail(&certs->error, "cannot store certificate URL");
        }
        memcpy(url, "https://crt.sh/?q=", sizeof("https://crt.sh/?q=") - 1);
        memcpy(url + sizeof("https://crt.sh/?q=") - 1, fp, strlen(fp) + 1);
        if (certs->len == certs->cap) {
            if (certs->cap > SIZE_MAX / sizeof(*certs->urls) / 2) {
                free(url); json_object_put(object);
                return pk_fail(&certs->error, "too many certificate URLs");
            }
            size_t cap = certs->cap ? certs->cap * 2 : 4;
            char **urls = realloc(certs->urls, cap * sizeof(*urls));
            if (!urls) {
                free(url);
                json_object_put(object);
                return pk_fail(&certs->error, "cannot store certificate URL");
            }
            certs->urls = urls;
            certs->cap = cap;
        }
        certs->urls[certs->len++] = url;
    }
    json_object_put(object);
    return 0;
}

static int pk_members(void *user, br_slice name, br_json *value, br_slice encoded)
{
    (void)value;
    if (!br_json_field_name(name, "certificateresults")) return 0;
    return br_json_each_element(encoded, pk_cert, user);
}

__attribute__((weak)) int br_privatekey_json_document(br_slice body, br_json **out, char **cause)
{
    return br_json_document(body, out, cause);
}

static int pk_lookup(const br_scan_ctx *ctx, const char *fingerprint, char **urls, char **cause, char **error)
{
    *urls = NULL;
    *cause = NULL;
    char url[160];
    int written = snprintf(url, sizeof(url), "https://keychecker.trufflesecurity.com/fingerprint/%s", fingerprint);
    if (written < 0 || (size_t)written >= sizeof(url))
        return pk_fail(error, "cannot build private-key fingerprint URL");
    if (!ctx) {
        *cause = strdup("net/http: nil Context");
        return *cause ? 0 : pk_fail(error, "cannot record private-key verification error");
    }
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_RETRYABLE, .detector_type = 15,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    if (br_http_send(ctx, &request, &response, &transport_error) != 0) {
        /* A failed send is a known ordinary error even when the diagnostic is NULL. */
        *cause = transport_error;
        br_http_release(ctx, &response);
        return 0;
    }
    if (response.body_error) {
        *cause = strdup(response.body_error);
        br_http_release(ctx, &response);
        return *cause ? 0 : pk_fail(error, "cannot record private-key body error");
    }
    br_json *document = NULL;
    char *json_error = NULL;
    int decoded = br_privatekey_json_document(response.body, &document, &json_error);
    if (decoded == 1) {
        *cause = json_error;
        json_object_put(document);
        br_http_release(ctx, &response);
        return 0;
    }
    if (decoded != 0) {
        free(json_error);
        json_object_put(document);
        br_http_release(ctx, &response);
        return pk_fail(error, "cannot decode private-key fingerprint response");
    }
    pk_certs certs = {0};
    char *visit_error = NULL;
    int rc = br_json_each_member(response.body, pk_members, &certs);
    if (certs.error) {
        free(visit_error);
        visit_error = certs.error;
        rc = -1;
    }
    json_object_put(document);
    br_http_release(ctx, &response);
    if (rc != 0) {
        for (size_t i = 0; i < certs.len; ++i) free(certs.urls[i]);
        free(certs.urls);
        pk_fail(error, visit_error ? visit_error : "cannot read private-key certificates");
        free(visit_error);
        return -1;
    }
    free(visit_error);
    if (certs.len) {
        size_t total = 0;
        for (size_t i = 0; i < certs.len; ++i) {
            size_t len = strlen(certs.urls[i]), sep = i ? 2 : 0;
            if (total > SIZE_MAX - sep - 1 || len > SIZE_MAX - sep - 1 - total) {
                for (size_t j = 0; j < certs.len; ++j) free(certs.urls[j]);
                free(certs.urls); return pk_fail(error, "certificate URLs are too large");
            }
            total += len + sep;
        }
        *urls = malloc(total + 1);
        if (!*urls) {
            for (size_t i = 0; i < certs.len; ++i) free(certs.urls[i]);
            free(certs.urls);
            return pk_fail(error, "cannot store certificate URLs");
        }
        size_t n = 0;
        for (size_t i = 0; i < certs.len; ++i) {
            if (i) {
                memcpy(*urls + n, ", ", 2);
                n += 2;
            }
            size_t len = strlen(certs.urls[i]);
            memcpy(*urls + n, certs.urls[i], len);
            n += len;
            free(certs.urls[i]);
        }
        (*urls)[n] = '\0';
    }
    free(certs.urls);
    return 0;
}

static int pk_join(char **out, const char *a, const char *b, const char *c)
{
    const char *parts[] = {a, b, c};
    size_t n = 0, count = 0;
    for (size_t i = 0; i < 3; ++i) if (parts[i]) {
        size_t len = strlen(parts[i]), sep = count ? 2 : 0;
        if (n > SIZE_MAX - sizeof("verification failures: ") - sep ||
            len > SIZE_MAX - sizeof("verification failures: ") - sep - n) return -1;
        n += len + sep;
        ++count;
    }
    if (!count) {
        *out = NULL;
        return 0;
    }
    char *joined = malloc(sizeof("verification failures: ") + n);
    if (!joined) return -1;
    size_t at = 0;
    memcpy(joined, "verification failures: ", sizeof("verification failures: ") - 1);
    at = sizeof("verification failures: ") - 1;
    count = 0;
    for (size_t i = 0; i < 3; ++i) if (parts[i]) {
        if (count) {
            memcpy(joined + at, ", ", 2);
            at += 2;
        }
        size_t len = strlen(parts[i]);
        memcpy(joined + at, parts[i], len);
        at += len;
        ++count;
    }
    joined[at] = '\0';
    *out = joined;
    return 0;
}

static int pk_verify(const br_scan_ctx *ctx, br_slice token, const char *fingerprint,
                     br_result *result, char **error)
{
    char *urls = NULL, *cert_error = NULL, *github_error = NULL, *gitlab_error = NULL;
    char *github_user = NULL, *gitlab_user = NULL;
    if (pk_lookup(ctx, fingerprint, &urls, &cert_error, error) != 0) return -1;
    /* SSH host verification is not implemented. Do not dial GitHub or GitLab. */
    github_error = strdup("unsupported: SSH verification is not available");
    gitlab_error = strdup("unsupported: SSH verification is not available");
    if (!github_error || !gitlab_error) {
        free(urls);
        free(cert_error);
        free(github_error);
        free(gitlab_error);
        return pk_fail(error, "cannot record SSH verification");
    }
    if (urls) {
        result->verified = true;
        if (pk_extra_put(result->extra_data, "certificate_urls", urls) != 0) {
            free(urls);
            free(cert_error);
            free(github_error);
            free(gitlab_error);
            return pk_fail(error, "cannot store certificate URLs");
        }
    } else {
        json_object_put(result->extra_data);
        result->extra_data = NULL;
    }
    /* A present GitHub username is omitted when it is the known distributed key. */
    if (github_user && strcmp(github_user, "aaron1234567890123") && result->extra_data &&
        pk_extra_put(result->extra_data, "github_user", github_user) != 0) {
        free(urls);
        free(cert_error);
        free(github_error);
        free(gitlab_error);
        free(github_user);
        free(gitlab_user);
        return pk_fail(error, "cannot store GitHub user");
    }
    if (gitlab_user && result->extra_data &&
        pk_extra_put(result->extra_data, "gitlab_user", gitlab_user) != 0) {
        free(urls);
        free(cert_error);
        free(github_error);
        free(gitlab_error);
        free(github_user);
        free(gitlab_user);
        return pk_fail(error, "cannot store GitLab user");
    }
    char *joined = NULL;
    if (pk_join(&joined, cert_error, github_error, gitlab_error) != 0) {
        free(urls);
        free(cert_error);
        free(github_error);
        free(gitlab_error);
        free(github_user);
        free(gitlab_user);
        return pk_fail(error, "cannot combine private-key verification errors");
    }
    int rc = 0;
    if (joined && br_result_set_verification_error(result, joined, &token, 1) != 0)
        rc = pk_fail(error, "cannot set private-key verification error");
    free(joined);
    free(urls);
    free(cert_error);
    free(github_error);
    free(gitlab_error);
    free(github_user);
    free(gitlab_user);
    return rc;
}

typedef struct {
    const br_detector *detector;
    const br_scan_ctx *ctx;
    br_slice input;
    br_results *out;
    bool verify;
    char *error;
} pk_matches;

static int pk_emit(void *user, const br_span *groups, size_t ngroups)
{
    pk_matches *matches = user;
    if (!ngroups || groups[0].begin == SIZE_MAX || groups[0].end < groups[0].begin ||
        groups[0].end > matches->input.len)
        return pk_fail(&matches->error, "invalid private-key capture");
    br_slice match = {matches->input.data + groups[0].begin, groups[0].end - groups[0].begin};
    br_bytes token = {0};
    if (pk_normalize(match, &token, &matches->error) != 0) return -1;
    if (token.len < 64) {
        free(token.data);
        return 0;
    }
    br_result result = {0};
    br_slice normalized = {token.data, token.len};
    int rc = 0;
    if (br_finding_key_bytes(&result, matches->detector->type, normalized, "token") != 0) {
        pk_fail(&matches->error, "cannot create private-key result");
        rc = -1;
    } else if (!(result.redacted = strndup((const char *)token.data, 64)) ||
               !(result.extra_data = json_object_new_object()) ||
               !(result.primary_secret.data = malloc(match.len ? match.len : 1))) {
        pk_fail(&matches->error, "cannot create private-key result");
        rc = -1;
    } else {
        if (match.len) memcpy(result.primary_secret.data, match.data, match.len);
        result.primary_secret.len = match.len;
        EVP_PKEY *key = NULL;
        char *passphrase = NULL;
        bool encrypted = false;
        int reading = pk_read(normalized, NULL, &key, &matches->error);
        if (reading == 0 && !key) reading = pk_pem_encrypted(normalized, &encrypted);
        if (reading != 0) {
            rc = pk_fail(&matches->error, "cannot inspect private-key encryption");
        } else if (!key && encrypted) {
            if (pk_extra_put(result.extra_data, "encrypted", "true") != 0) {
                pk_fail(&matches->error, "cannot store private-key encryption flag");
                rc = -1;
            } else if (pk_crack(normalized, &key, &passphrase, &matches->error) != 0) {
                rc = -1;
            } else if (!key) {
                br_slice secret = {token.data, token.len};
                if (br_result_set_verification_error(&result, "unable to crack encryption", &secret, 1) != 0) {
                    pk_fail(&matches->error, "cannot set private-key verification error");
                    rc = -1;
                } else if (br_results_push(matches->out, &result) != 0) {
                    pk_fail(&matches->error, "cannot append private-key result");
                    rc = -1;
                }
                free(matches->error);
                matches->error = NULL;
                EVP_PKEY_free(key);
                free(passphrase);
                free(token.data);
                br_result_clear(&result);
                return rc;
            } else if (passphrase && *passphrase &&
                       pk_extra_put(result.extra_data, "cracked_encryption_passphrase", "true") != 0) {
                pk_fail(&matches->error, "cannot store cracked passphrase flag");
                rc = -1;
            }
        } else if (!key) {
            EVP_PKEY_free(key);
            free(token.data);
            br_result_clear(&result);
            return 0;
        }
        char *fingerprint = NULL;
        if (!rc && pk_fingerprint(key, &fingerprint, &matches->error) != 0) rc = -1;
        if (!rc && matches->verify &&
            pk_verify(matches->ctx, normalized, fingerprint, &result, &matches->error) != 0)
            rc = -1;
        if (!rc && br_results_push(matches->out, &result) != 0) {
            pk_fail(&matches->error, "cannot append private-key result");
            rc = -1;
        }
        free(fingerprint);
        EVP_PKEY_free(key);
        free(passphrase);
        (void)encrypted;
    }
    free(token.data);
    br_result_clear(&result);
    return rc;
}

static int pk_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                   br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return pk_fail(error, "invalid or uninitialized PrivateKey scan");
    size_t original_len = out->len;
    pk_matches matches = {detector, ctx, input, out, verify, NULL};
    char *regex_error = NULL;
    int rc = br_regex_each(detector->state, input, pk_emit, &matches, &regex_error);
    if (matches.error) {
        free(regex_error);
        regex_error = matches.error;
        rc = -1;
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    if (error) *error = regex_error;
    else free(regex_error);
    return rc == 0 ? 0 : -1;
}

static bool pk_never_false_positive(const br_detector *detector, const br_result *result, char **reason)
{
    (void)detector;
    (void)result;
    if (reason) *reason = strdup("");
    return false;
}

static const char *const pk_keywords[] = {"private key"};
static br_detector pk_detector = {
    .type = 15, .version = 0, .name = "PrivateKey", .custom_name = "",
    .description = "Private keys are used for securely connecting and authenticating to various systems and services. Exposure of private keys can lead to unauthorized access and data breaches.",
    .keywords = pk_keywords, .nkeywords = 1,
    .max_secret_size = 4096, .start_offset = -1, .max_credential_span = -1,
    .scan = pk_scan, .false_positive = pk_never_false_positive,
};

int br_privatekey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return pk_fail(error, "invalid PrivateKey detector output");
    *out = NULL;
    if (!pk_detector.state &&
        br_regex_compile("(?i)-----[ \\t\\n\\f\\r]*?BEGIN[ A-Z0-9_-]*?PRIVATE KEY[ \\t\\n\\f\\r]*?-----(?s:.)*?----[ \\t\\n\\f\\r]*?END[ A-Z0-9_-]*? PRIVATE KEY[ \\t\\n\\f\\r]*?-----",
                         (br_regex **)&pk_detector.state, error) != 0)
        return -1;
    *out = &pk_detector;
    return 0;
}
