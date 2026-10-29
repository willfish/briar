/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#include <stdarg.h>

#define br_result_set_verification_error langfuse_real_setter
#define br_results_push langfuse_real_push
#include "../../src/result.c"
#undef br_result_set_verification_error
#undef br_results_push

int br_langfuse_init(const br_detector **out, char **error);

/* A named-test inclusion seam makes impossible formatter returns observable
 * without interposing Nix's fortified snprintf. Existing cases keep the
 * library factory, which remains the only production export. */
static int checked_snprintf(char *, size_t, const char *, ...);
static int langfuse_seam_send(const br_scan_ctx *, const br_http_request *, br_http_response *, char **);
#define snprintf checked_snprintf
#define br_http_send langfuse_seam_send
#define br_langfuse_init observed_langfuse_init
#include "../../src/detectors/langfuse.c"
#undef snprintf
#undef br_http_send
#undef br_langfuse_init

static char pka[43], pkb[43], ska[43], skb[43];
static const char description[] =
    "Langfuse is a platform for building and scaling AI applications. Langfuse API keys can be used to access these services.";
static const char url[] = "https://cloud.langfuse.com/api/public/projects";
static size_t fail_size, fail_after, fail_key_after, fail_push_after, fail_setter_after, setter_calls, basic_allocations;
static bool track_basic, format_before_release, setter_saw_null, null_send_cause;
static int fail_format;
static size_t setters_before_format, seen_secret_count, null_send_setters_before;
static test_http *null_send_http;
static char seen_secret[43];
static size_t seen_secret_len;
static const char *seam_auth, *seam_pub, *seam_sec;

void *malloc(size_t size)
{
    if (track_basic && size == 123) ++basic_allocations;
    if (fail_after && size == fail_size && --fail_after == 0) return NULL;
    return calloc(1, size);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_key_after && --fail_key_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

int br_result_set_verification_error(br_result *r, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    setter_saw_null = cause == NULL;
    seen_secret_count = count;
    seen_secret_len = 0;
    if (count == 1 && secrets && secrets[0].data && secrets[0].len < sizeof(seen_secret)) {
        memcpy(seen_secret, secrets[0].data, secrets[0].len);
        seen_secret[secrets[0].len] = '\0';
        seen_secret_len = secrets[0].len;
    }
    if (fail_setter_after && --fail_setter_after == 0) {
        if (null_send_cause) {
            CHECK(null_send_http && null_send_http->releases == 1);
            CHECK(setter_calls == null_send_setters_before + 1);
        }
        return 1;
    }
    return langfuse_real_setter(r, cause, secrets, count);
}

int br_results_push(br_results *out, br_result *owned)
{
    if (fail_push_after && --fail_push_after == 0) return 1;
    return langfuse_real_push(out, owned);
}

static void fill_key(char *out, const char *prefix, char fill)
{
    const int groups[] = {8, 4, 4, 4, 12};
    memcpy(out, prefix, 6);
    size_t at = 6;
    for (size_t i = 0; i < sizeof(groups) / sizeof(groups[0]); ++i) {
        if (i) out[at++] = '-';
        memset(out + at, fill, (size_t)groups[i]);
        at += (size_t)groups[i];
    }
    out[at] = '\0';
}

static size_t add_key(char *buf, size_t cap, size_t at, const char *key)
{
    int n = snprintf(buf + at, cap - at, "langfuse %s ", key);
    CHECK(n == 52 && (size_t)n < cap - at);
    return at + (size_t)n;
}

static void result_is(const br_result *result, const char *secret, bool verified, const char *cause)
{
    test_key_result(result, 1021, secret, "key");
    CHECK(result->raw.len == 42 && result->verified == verified);
    CHECK(cause ? result->verification_error && !strcmp(result->verification_error, cause) : !result->verification_error);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 42);
    CHECK(!json_object_object_get_ex(result->secret_parts, "public", &part));
    CHECK(!json_object_object_get_ex(result->secret_parts, "id", &part));
    CHECK(!result->raw_v2.data);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    fill_key(pka, "pk-lf-", 'a');
    fill_key(pkb, "pk-lf-", 'b');
    fill_key(ska, "sk-lf-", 'c');
    fill_key(skb, "sk-lf-", 'd');
    CHECK(BR_ABI_REVISION == 1 && strlen(pka) == 42 && strlen(ska) == 42);
    CHECK(br_langfuse_init(NULL, &error) == -1 && error);
    CHECK(!strcmp(error, "invalid Langfuse detector output"));
    free(error);
    error = NULL;
    CHECK(br_langfuse_init(NULL, NULL) == -1);
    CHECK(br_langfuse_init(&d, &error) == 0 && d && !error);
    CHECK(br_langfuse_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 1021 && d->version == 0 && !strcmp(d->name, "Langfuse") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, description));
    CHECK(d->nkeywords == 2 && !strcmp(d->keywords[0], "pk-lf-") && !strcmp(d->keywords[1], "sk-lf-"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void expect_none(const br_detector *d, const void *text, size_t len)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    size_t before = setter_calls;
    br_results out = test_scan(d, &ctx, false, text, len);
    CHECK(!out.len && !http.calls && !http.releases && setter_calls == before);
    br_results_clear(&out);
}

static void extraction(const br_detector *d)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    char input[400];
    size_t n = add_key(input, sizeof(input), 0, pkb);
    n = add_key(input, sizeof(input), n, pka);
    n = add_key(input, sizeof(input), n, skb);
    n = add_key(input, sizeof(input), n, ska);
    n = add_key(input, sizeof(input), n, pkb);
    n = add_key(input, sizeof(input), n, skb);
    br_results out = test_scan(d, &ctx, false, input, n);
    CHECK(out.len == 4 && !http.calls && !http.releases && !setter_calls);
    result_is(&out.items[0], skb, false, NULL);
    result_is(&out.items[1], ska, false, NULL);
    result_is(&out.items[2], skb, false, NULL);
    result_is(&out.items[3], ska, false, NULL);
    CHECK(memcmp(out.items[0].raw.data, pkb, 42) != 0);
    br_results_clear(&out);

    n = add_key(input, sizeof(input), 0, pka);
    expect_none(d, input, n);
    n = add_key(input, sizeof(input), 0, ska);
    expect_none(d, input, n);
    n = snprintf(input, sizeof(input), "%s %s", pka, ska);
    expect_none(d, input, (size_t)n);
    expect_none(d, "langfuse", 8);

    n = snprintf(input, sizeof(input), "LangFuse %s LangFuse %s", pka, ska);
    out = test_scan(d, &ctx, false, input, n);
    CHECK(out.len == 1);
    result_is(&out.items[0], ska, false, NULL);
    br_results_clear(&out);

    char upper[43];
    memcpy(upper, pka, 43);
    upper[6] = 'A';
    n = add_key(input, sizeof(input), 0, upper);
    n = add_key(input, sizeof(input), n, ska);
    expect_none(d, input, n);
    n = snprintf(input, sizeof(input), "langfuse%s langfuse %s", pka, ska);
    expect_none(d, input, n);

    memcpy(input, "langfuse", 8);
    memset(input + 8, '.', 40);
    memcpy(input + 48, pka, 42);
    memcpy(input + 90, " langfuse ", 10);
    memcpy(input + 100, ska, 42);
    out = test_scan(d, &ctx, false, input, 142);
    CHECK(out.len == 1);
    result_is(&out.items[0], ska, false, NULL);
    br_results_clear(&out);
    memset(input + 8, '.', 41);
    memcpy(input + 49, pka, 42);
    memcpy(input + 91, " langfuse ", 10);
    memcpy(input + 101, ska, 42);
    out = test_scan(d, &ctx, false, input, 143);
    CHECK(!out.len);
    br_results_clear(&out);
    CHECK(!http.calls && !http.releases && !setter_calls);
}

static int b64_value(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static void expect_basic(const char *header, const char *pub, const char *sec)
{
    CHECK(header && !strncmp(header, "Basic ", 6) && strlen(header) == 122);
    CHECK(strncmp(header, "Bearer ", 7) != 0);
    unsigned char decoded[85];
    size_t out = 0;
    for (int i = 0; i < 29; ++i) {
        int a = b64_value(header[6 + i * 4]);
        int b = b64_value(header[7 + i * 4]);
        char cch = header[8 + i * 4], dch = header[9 + i * 4];
        int c = cch == '=' ? 0 : b64_value(cch);
        int d = dch == '=' ? 0 : b64_value(dch);
        CHECK(a >= 0 && b >= 0 && c >= 0 && d >= 0 && out < sizeof(decoded));
        decoded[out++] = (unsigned char)((a << 2) | (b >> 4));
        if (cch != '=') decoded[out++] = (unsigned char)((b << 4) | (c >> 2));
        if (dch != '=') decoded[out++] = (unsigned char)((c << 6) | d);
    }
    CHECK(out == 85 && !memcmp(decoded, pub, 42) && decoded[42] == ':' && !memcmp(decoded + 43, sec, 42));
}

typedef struct {
    const char *pub[4];
    const char *sec[4];
    const char *borrowed_url, *borrowed_auth;
    int status, send_rc;
    const char *send_error, *body_error;
    bool status_set[4];
    int statuses[4];
} script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user;
    const char *pub = s->pub[http->calls - 1];
    const char *sec = s->sec[http->calls - 1];
    CHECK(ctx && http->calls == http->releases + 1 && pub && sec);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, url) && !strchr(request->url, '?'));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 1021);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    expect_basic(request->headers[0].value, pub, sec);
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, "TruffleHog langfuse-offline"));
    s->borrowed_url = request->url;
    s->borrowed_auth = request->headers[0].value;
    static const unsigned char body[] = {0xff, 0, '{'};
    int status = s->status_set[http->calls - 1] ? s->statuses[http->calls - 1] : s->status;
    http->response = (br_http_response){
        .status = status, .body = {body, sizeof(body)}, .body_error = s->body_error,
    };
    http->send_rc = s->send_rc;
    http->send_error = s->send_error;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user;
    script *s = http->user;
    /* The later attempt formats before this release and has not called the setter. */
    if (format_before_release && http->releases == 1)
        CHECK(!fail_format && setter_calls == setters_before_format);
    if (null_send_cause)
        CHECK(setter_calls == null_send_setters_before);
    if (seam_auth) {
        expect_basic(seam_auth, seam_pub, seam_sec);
        seam_auth = NULL;
    }
    if (s->borrowed_auth) {
        CHECK(!strcmp(s->borrowed_url, url));
        expect_basic(s->borrowed_auth, s->pub[http->releases], s->sec[http->releases]);
        s->borrowed_url = s->borrowed_auth = NULL;
    }
    test_http_release(user, response);
}

static bool cancelled(void *unused)
{
    (void)unused;
    return true;
}

static void verification(const br_detector *d)
{
    script s = {.pub = {pka}, .sec = {ska}, .status = 200};
    test_http http = {.inspect = inspect, .user = &s};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "langfuse-offline"};
    char input[160];
    size_t n = add_key(input, sizeof(input), 0, pka);
    n = add_key(input, sizeof(input), n, ska);
    size_t before = setter_calls;
    s.body_error = "ignored read failure";
    br_results out = test_scan(d, &ctx, true, input, n);
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !s.borrowed_auth);
    CHECK(setter_calls == before);
    result_is(&out.items[0], ska, true, NULL);
    br_results_clear(&out);

    s.status = 401;
    s.body_error = "ignored read failure";
    http.calls = http.releases = 0;
    before = setter_calls;
    out = test_scan(d, &ctx, true, input, n);
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && setter_calls == before);
    result_is(&out.items[0], ska, false, NULL);
    br_results_clear(&out);

    const int other[] = {0, 403, 500};
    for (size_t i = 0; i < sizeof(other) / sizeof(other[0]); ++i) {
        s.status = other[i];
        s.body_error = "ignored read failure";
        s.send_rc = 0;
        s.send_error = NULL;
        http.calls = http.releases = 0;
        before = setter_calls;
        out = test_scan(d, &ctx, true, input, n);
        char cause[64];
        CHECK(snprintf(cause, sizeof(cause), "unexpected HTTP response status %d", other[i]) > 0);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && setter_calls == before + 1);
        result_is(&out.items[0], ska, false, cause);
        CHECK(strcmp(out.items[0].verification_error, "ignored read failure") != 0);
        CHECK(seen_secret_len == 42 && !strcmp(seen_secret, pka));
        br_results_clear(&out);
    }

    char rejected[120];
    CHECK(snprintf(rejected, sizeof(rejected), "rejected %s %s", pka, ska) == 94);
    s.status = 200;
    s.send_rc = -1;
    s.send_error = rejected;
    s.body_error = "ignored";
    http.calls = http.releases = 0;
    out = test_scan(d, &ctx, true, input, n);
    char redacted[80];
    CHECK(snprintf(redacted, sizeof(redacted), "rejected [REDACTED] %s", ska) > 0);
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
    result_is(&out.items[0], ska, false, redacted);
    CHECK(!strstr(out.items[0].verification_error, pka));
    CHECK(strstr(out.items[0].verification_error, ska) != NULL);
    CHECK(!strcmp(seen_secret, pka));
    br_results_clear(&out);

    br_scan_ctx stopped = {.transport = &transport, .user_agent = "langfuse-offline", .cancelled = cancelled};
    s.send_rc = 0;
    s.send_error = NULL;
    s.body_error = NULL;
    http.calls = http.releases = 0;
    before = setter_calls;
    out = test_scan(d, &stopped, true, input, n);
    CHECK(out.len == 1 && !http.calls && http.releases == 1 && setter_calls == before + 1);
    result_is(&out.items[0], ska, false, "context canceled");
    br_results_clear(&out);

    track_basic = true;
    before = basic_allocations;
    size_t setters = setter_calls;
    http.calls = http.releases = 0;
    char wide[280];
    size_t w = add_key(wide, sizeof(wide), 0, pkb);
    w = add_key(wide, sizeof(wide), w, pka);
    w = add_key(wide, sizeof(wide), w, skb);
    w = add_key(wide, sizeof(wide), w, ska);
    out = test_scan(d, NULL, true, wide, w);
    CHECK(out.len == 4 && !http.calls && !http.releases && basic_allocations == before);
    CHECK(setter_calls == setters + 4);
    result_is(&out.items[0], skb, false, "net/http: nil Context");
    result_is(&out.items[1], ska, false, "net/http: nil Context");
    result_is(&out.items[2], skb, false, "net/http: nil Context");
    result_is(&out.items[3], ska, false, "net/http: nil Context");
    CHECK(!strcmp(seen_secret, pka));
    br_results_clear(&out);

    s.pub[0] = pkb;
    s.pub[1] = pkb;
    s.pub[2] = pka;
    s.pub[3] = pka;
    s.sec[0] = skb;
    s.sec[1] = ska;
    s.sec[2] = skb;
    s.sec[3] = ska;
    s.status = 200;
    s.send_rc = 0;
    s.send_error = NULL;
    http.calls = http.releases = 0;
    before = setter_calls;
    size_t auths = basic_allocations;
    out = test_scan(d, &ctx, true, wide, w);
    CHECK(out.len == 4 && http.calls == 4 && http.releases == 4 && !s.borrowed_auth);
    CHECK(setter_calls == before && basic_allocations == auths + 4);
    result_is(&out.items[0], skb, true, NULL);
    result_is(&out.items[1], ska, true, NULL);
    result_is(&out.items[2], skb, true, NULL);
    result_is(&out.items[3], ska, true, NULL);
    br_results_clear(&out);
}

static void prior_unchanged(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && out->items[0].raw.data == prior->raw.data);
    CHECK(out->items[0].secret_parts == prior->secret_parts);
    CHECK(out->items[0].verification_error == prior->verification_error);
    CHECK(out->items[0].verified && !strcmp(out->items[0].verification_error, "caller-owned"));
    CHECK(out->items[0].raw.len == 5 && !memcmp(out->items[0].raw.data, "prior", 5));
}

static void owned_failures(const br_detector *d)
{
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error);
    br_results out = {0};
    CHECK(br_results_push(&out, &prior) == 0);
    prior = out.items[0];
    char input[160];
    size_t n = add_key(input, sizeof(input), 0, pka);
    n = add_key(input, sizeof(input), n, ska);
    n = add_key(input, sizeof(input), n, skb);
    br_slice data = {(const unsigned char *)input, (size_t)n};
    script s = {.pub = {pka, pka}, .sec = {ska, skb}, .status = 200};
    test_http http = {.inspect = inspect, .user = &s};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "langfuse-offline"};
    char *error = NULL;

    fail_key_after = 1;
    size_t before = basic_allocations, setters = setter_calls;
    CHECK(d->scan(d, NULL, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create Langfuse finding") && !fail_key_after);
    free(error);
    error = NULL;
    CHECK(!http.calls && !http.releases && basic_allocations == before && setter_calls == setters);
    prior_unchanged(&out, &prior);

    fail_setter_after = 1;
    CHECK(d->scan(d, NULL, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot record Langfuse verification error") && !fail_setter_after);
    free(error);
    error = NULL;
    CHECK(!http.calls && !http.releases && basic_allocations == before);
    prior_unchanged(&out, &prior);

    fail_size = 123;
    fail_after = 1;
    http.calls = http.releases = 0;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "out of memory constructing Basic authentication") && !fail_after);
    free(error);
    error = NULL;
    CHECK(!http.calls && !http.releases && basic_allocations == before + 1);
    prior_unchanged(&out, &prior);

    fail_size = 123;
    fail_after = 2;
    http.calls = http.releases = 0;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "out of memory constructing Basic authentication") && !fail_after);
    free(error);
    error = NULL;
    CHECK(http.calls == 1 && http.releases == 1 && !s.borrowed_auth);
    CHECK(basic_allocations == before + 1 + 2);
    prior_unchanged(&out, &prior);

    fail_setter_after = 2;
    s.status = 500;
    http.calls = http.releases = 0;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot record Langfuse verification error") && !fail_setter_after);
    free(error);
    error = NULL;
    CHECK(http.calls == 2 && http.releases == 2 && !s.borrowed_auth);
    prior_unchanged(&out, &prior);

    fail_push_after = 1;
    http.calls = http.releases = 0;
    CHECK(d->scan(d, &ctx, false, data, &out, NULL) == -1 && !fail_push_after);
    CHECK(!http.calls && !http.releases);
    prior_unchanged(&out, &prior);
    CHECK(d->scan(NULL, NULL, false, (br_slice){0}, NULL, NULL) == -1);
    br_results_clear(&out);
    CHECK(!fail_after && !fail_key_after && !fail_setter_after && !fail_push_after);
}

static int langfuse_seam_send(const br_scan_ctx *ctx, const br_http_request *request,
                              br_http_response *response, char **error)
{
    if (!null_send_cause) return br_http_send(ctx, request, response, error);
    /* Bypass the shared helper, which would invent "HTTP transport failed". */
    seam_auth = request && request->nheaders ? request->headers[0].value : NULL;
    if (response) memset(response, 0, sizeof(*response));
    if (error) *error = NULL;
    return -1;
}

static int checked_snprintf(char *out, size_t n, const char *format, ...)
{
    if (fail_format && format && !strcmp(format, "unexpected HTTP response status %d")) {
        int rc = fail_format;
        fail_format = 0;
        return rc;
    }
    va_list args;
    va_start(args, format);
    int rc = vsnprintf(out, n, format, args);
    va_end(args);
    return rc;
}

static void format_failures(void)
{
    const br_detector *observed = NULL, *library = NULL;
    char *error = NULL;
    CHECK(observed_langfuse_init(&observed, &error) == 0 && observed && !error);
    CHECK(br_langfuse_init(&library, NULL) == 0 && library && library != observed);
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error);
    br_results out = {0};
    CHECK(br_results_push(&out, &prior) == 0);
    prior = out.items[0];
    char input[220];
    size_t n = add_key(input, sizeof(input), 0, pka);
    n = add_key(input, sizeof(input), n, ska);
    n = add_key(input, sizeof(input), n, skb);
    br_slice data = {(const unsigned char *)input, (size_t)n};
    script s = {.pub = {pka, pka}, .sec = {ska, skb}, .status = 200, .body_error = "ignored read failure"};
    s.status_set[1] = true;
    s.statuses[1] = 500;
    test_http http = {.inspect = inspect, .user = &s};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "langfuse-offline"};
    const int format_errors[] = {-1, 64};
    format_before_release = true;
    for (size_t i = 0; i < sizeof(format_errors) / sizeof(format_errors[0]); ++i) {
        http.calls = http.releases = 0;
        s.borrowed_url = s.borrowed_auth = NULL;
        setters_before_format = setter_calls;
        fail_format = format_errors[i];
        CHECK(observed->scan(observed, &ctx, true, data, &out, &error) == -1);
        CHECK(error && !strcmp(error, "cannot format Langfuse verification status") && !fail_format);
        CHECK(http.calls == 2 && http.releases == 2 && !s.borrowed_auth);
        CHECK(setter_calls == setters_before_format);
        prior_unchanged(&out, &prior);
        free(error);
        error = NULL;
    }
    format_before_release = false;
    br_results_clear(&out);
}

static void null_send_cause_reaches_setter(void)
{
    const br_detector *observed = NULL, *library = NULL;
    char *error = NULL;
    CHECK(observed_langfuse_init(&observed, &error) == 0 && observed && !error);
    CHECK(br_langfuse_init(&library, NULL) == 0 && library && library != observed);
    char input[160];
    size_t n = add_key(input, sizeof(input), 0, pka);
    n = add_key(input, sizeof(input), n, ska);
    script s = {.pub = {pka}, .sec = {ska}};
    test_http http = {.user = &s};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "langfuse-offline"};
    null_send_cause = true;
    null_send_http = &http;
    seam_pub = pka;
    seam_sec = ska;
    null_send_setters_before = setter_calls;
    size_t setters = setter_calls;
    br_results out = test_scan(observed, &ctx, true, input, n);
    CHECK(out.len == 1 && !http.calls && http.releases == 1 && !seam_auth);
    CHECK(setter_calls == setters + 1 && setter_saw_null && seen_secret_count == 1);
    CHECK(seen_secret_len == 42 && !strcmp(seen_secret, pka));
    result_is(&out.items[0], ska, false, NULL);
    br_results_clear(&out);

    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error);
    CHECK(br_results_push(&out, &prior) == 0);
    prior = out.items[0];
    http.calls = http.releases = 0;
    seam_pub = pka;
    seam_sec = ska;
    null_send_setters_before = setter_calls;
    setters = setter_calls;
    fail_setter_after = 1;
    CHECK(observed->scan(observed, &ctx, true, (br_slice){(const unsigned char *)input, n}, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot record Langfuse verification error") && !fail_setter_after);
    CHECK(!http.calls && http.releases == 1 && !seam_auth);
    CHECK(setter_calls == setters + 1 && setter_saw_null && seen_secret_count == 1);
    CHECK(seen_secret_len == 42 && !strcmp(seen_secret, pka));
    prior_unchanged(&out, &prior);
    free(error);
    null_send_cause = false;
    null_send_http = NULL;
    br_results_clear(&out);
}

int main(void)
{
    const br_detector *d = descriptor();
    extraction(d);
    verification(d);
    owned_failures(d);
    format_failures();
    null_send_cause_reaches_setter();
    return test_finish("Langfuse");
}
