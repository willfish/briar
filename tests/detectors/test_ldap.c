/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/findings.h"
#include "../../src/detectors/captures.h"
#include "../../src/detectors/ldap_private.h"
#include "../support/detector_test.h"
#include <stdarg.h>

static int ldap_test_snprintf(char *buf, size_t n, const char *fmt, ...);
static int ldap_test_url(br_slice input, br_bytes *out, bool *accepted, char **fatal);
static int ldap_test_captures(const br_regex *regex, br_slice input, br_captures *out,
                              bool unique, char **error);
#define snprintf ldap_test_snprintf
#define br_ldap_url_string ldap_test_url
#define br_captures_find ldap_test_captures
#include "../../src/detectors/ldap.c"
#undef snprintf
#undef br_ldap_url_string
#undef br_captures_find

static int snprintf_calls, snprintf_fail_at, snprintf_fail_rc;
static int url_fail_remaining;
static size_t url_calls, password_finds, captures_finds;
static const br_regex *password_regex;
static int part_fail_after;

static int ldap_test_snprintf(char *buf, size_t n, const char *fmt, ...)
{
    ++snprintf_calls;
    if (snprintf_fail_at && snprintf_calls == snprintf_fail_at) {
        snprintf_fail_at = 0;
        if (snprintf_fail_rc < 0) return -1;
        return n > 2147483646u ? 2147483647 : (int)n;
    }
    va_list ap;
    va_start(ap, fmt);
    int wrote = vsnprintf(buf, n, fmt, ap);
    va_end(ap);
    return wrote;
}

static int ldap_test_url(br_slice input, br_bytes *out, bool *accepted, char **fatal)
{
    ++url_calls;
    if (url_fail_remaining && --url_fail_remaining == 0) {
        if (out) *out = (br_bytes){0};
        if (accepted) *accepted = false;
        if (fatal) *fatal = strdup("injected URL projection failure");
        return 1;
    }
    return br_ldap_url_string(input, out, accepted, fatal);
}

static int ldap_test_captures(const br_regex *regex, br_slice input, br_captures *out,
                              bool unique, char **error)
{
    ++captures_finds;
    if (password_regex && regex == password_regex) ++password_finds;
    return br_captures_find(regex, input, out, unique, error);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (part_fail_after && --part_fail_after == 0) return -1;
    return json_object_object_add_ex(object, name, value, 0);
}

static const char user[] = "abcd";
static const char other_user[] = "wxyz";
static const char pass[] = "pqrs";
static const char other_pass[] = "wxyz";

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(br_ldap_init(NULL, &error) == -1 && error);
    CHECK(!strcmp(error, "invalid LDAP detector output"));
    free(error);
    error = NULL;
    CHECK(br_ldap_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_ldap_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 901 && detector->version == 0 && !strcmp(detector->name, "LDAP"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
                  "LDAP (Lightweight Directory Access Protocol) is an open, vendor-neutral, industry standard application protocol for accessing and maintaining distributed directory information services over an Internet Protocol (IP) network."));
    CHECK(detector->nkeywords == 2 && detector->keywords);
    CHECK(!strcmp(detector->keywords[0], "ldaps://") && !strcmp(detector->keywords[1], "ldap://"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1);
    CHECK(detector->max_credential_span == 1024 && detector->state && detector->scan);
    CHECK(!detector->false_positive && !detector->clean && !detector->clean_always);
    CHECK(!((const br_ldap_state *)detector->state)->io);
    return detector;
}

static void expect_secret(const br_result *result, const char *url, const char *username, const char *password)
{
    char raw[256];
    int n = snprintf(raw, sizeof(raw), "%s\t%s\t%s", url, username, password);
    CHECK(n > 0 && (size_t)n < sizeof(raw));
    CHECK(result->detector_type == 901 && !result->detector_name);
    CHECK(result->raw.len == (size_t)n && !memcmp(result->raw.data, raw, result->raw.len));
    CHECK(!result->raw_v2.data && !result->raw_v2.len && !result->extra_data && !result->structured_data);
    CHECK(!result->redacted && !result->verification_from_cache);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 3);
    const char *names[] = {"url", "username", "password"};
    const char *values[] = {url, username, password};
    for (size_t i = 0; i < 3; ++i) {
        br_json *part = NULL;
        CHECK(json_object_object_get_ex(result->secret_parts, names[i], &part));
        CHECK(json_object_is_type(part, json_type_string));
        CHECK((size_t)json_object_get_string_len(part) == strlen(values[i]));
        CHECK(!memcmp(json_object_get_string(part), values[i], strlen(values[i])));
    }
}

static br_results nov(const br_detector *detector, const char *input)
{
    return test_scan(detector, NULL, false, input, strlen(input));
}

static void products(const br_detector *detector)
{
    br_results out = nov(detector, "LDAP://127.0.0.1 user \"abcd\" pass \"pqrs\"");
    CHECK(out.len == 1 && !out.items[0].verified && !out.items[0].verification_error);
    expect_secret(&out.items[0], "ldap://127.0.0.1", user, pass);
    br_results_clear(&out);

    out = nov(detector, "ldap://Host bind 'wxyz' PASS \"pqrs\"");
    CHECK(out.len == 1);
    expect_secret(&out.items[0], "ldap://Host", other_user, pass);
    br_results_clear(&out);

    out = nov(detector, "ldap://127.0.0.1 ldap://10.0.0.2 user \"abcd\" user \"wxyz\" pass \"pqrs\" pass \"wxyz\"");
    CHECK(out.len == 8);
    const char *urls[] = {"ldap://127.0.0.1", "ldap://10.0.0.2"};
    const char *users[] = {user, other_user};
    const char *passes[] = {pass, other_pass};
    size_t at = 0;
    for (size_t u = 0; u < 2; ++u)
        for (size_t i = 0; i < 2; ++i)
            for (size_t j = 0; j < 2; ++j)
                expect_secret(&out.items[at++], urls[u], users[i], passes[j]);
    br_results_clear(&out);

    out = nov(detector, "ldap://127.0.0.1 ldap://127.0.0.1 user \"abcd\" pass \"pqrs\"");
    CHECK(out.len == 2);
    expect_secret(&out.items[0], "ldap://127.0.0.1", user, pass);
    expect_secret(&out.items[1], "ldap://127.0.0.1", user, pass);
    br_results_clear(&out);

    out = nov(detector, "ldap://127.0.0.1 user \"abcd\"");
    CHECK(out.len == 0);
    br_results_clear(&out);
    out = nov(detector, "user \"abcd\" pass \"pqrs\"");
    CHECK(out.len == 0);
    br_results_clear(&out);
    out = nov(detector, "ldap://127.0.0.1 pass \"pqrs\"");
    CHECK(out.len == 0);
    br_results_clear(&out);
    out = nov(detector, "ldap://127.0.0.1 user \"abc\" pass \"1234\"");
    CHECK(out.len == 0);
    br_results_clear(&out);

    char vt[] = "ldap://host/a\vname user \"abcd\" pass \"pqrs\"";
    out = nov(detector, vt);
    CHECK(out.len == 0);
    br_results_clear(&out);
    out = nov(detector, "ldaps://[fe80:4049:92ff:fe44:4bd1]:5060 ldap://127.0.0.1 user \"abcd\" pass \"pqrs\"");
    CHECK(out.len == 1);
    expect_secret(&out.items[0], "ldap://127.0.0.1", user, pass);
    br_results_clear(&out);
}

static void iad(const br_detector *detector)
{
    br_results out = nov(detector, "OpenDSObject(\"ldaps://www\",\"ABC\",\"XYZ\",1)");
    CHECK(out.len == 1 && !out.items[0].verified && !out.items[0].verification_error);
    expect_secret(&out.items[0], "ldaps://www", "ABC", "XYZ");
    br_results_clear(&out);

    out = nov(detector, "OpenDSObject(\"ldaps://www\", \"ABC\", \"XYZ\", 1)");
    CHECK(out.len == 1);
    expect_secret(&out.items[0], "ldaps://www", "ABC", "XYZ");
    br_results_clear(&out);

    out = nov(detector, "OpenDSObject(\"LDAPS://WWW\",\"ABC\",\"XYZ\",1)");
    CHECK(out.len == 1);
    expect_secret(&out.items[0], "ldaps://WWW", "ABC", "XYZ");
    br_results_clear(&out);

    out = nov(detector, "ldap://127.0.0.1 user \"abcd\" pass \"pqrs\" OpenDSObject(\"ldaps://www\",\"ABC\",\"XYZ\",1)");
    CHECK(out.len == 3);
    expect_secret(&out.items[0], "ldap://127.0.0.1", user, pass);
    /* The URI grammar is greedy through the IAD arguments; IAD capture stops at the quote. */
    expect_secret(&out.items[1], "ldaps://www\",\"ABC\",\"XYZ\",1", user, pass);
    expect_secret(&out.items[2], "ldaps://www", "ABC", "XYZ");
    br_results_clear(&out);

    out = nov(detector, "ldaps://[fe80:4049:92ff:fe44:4bd1]:5060 OpenDSObject(\"ldaps://www\",\"ABC\",\"XYZ\",1)");
    CHECK(out.len == 1);
    expect_secret(&out.items[0], "ldaps://www", "ABC", "XYZ");
    br_results_clear(&out);
}

enum { STEP_DIAL = 1, STEP_BIND, STEP_STARTTLS };
typedef struct {
    int kind, rc, presence;
    bool op, deadline, canceled, tls, insecure, null_ctx, null_handle, embed_nul;
    const char *text, *fatal, *url, *user, *pass;
} step;
typedef struct {
    const step *steps;
    size_t count, at, closes;
    bool open;
    const br_scan_ctx *ctx;
} script;

static void fill_error(const step *st, br_ldap_error *ordinary, char **fatal)
{
    *ordinary = (br_ldap_error){
        .presence = st->presence ? BR_LDAP_ERR_OTHER : BR_LDAP_ERR_NONE,
        .has_op_error = st->op, .is_deadline = st->deadline, .is_canceled = st->canceled,
    };
    if (st->embed_nul) {
        ordinary->innermost.data = malloc(3);
        CHECK(ordinary->innermost.data);
        memcpy(ordinary->innermost.data, "a\0b", 3);
        ordinary->innermost.len = 3;
    } else if (st->text) {
        ordinary->innermost.data = (unsigned char *)strdup(st->text);
        CHECK(ordinary->innermost.data);
        ordinary->innermost.len = strlen(st->text);
    }
    *fatal = st->fatal ? strdup(st->fatal) : NULL;
    CHECK(!st->fatal || *fatal);
}

static int dial_cb(void *user, br_slice url, bool tls, bool insecure, const br_scan_ctx *ctx,
                   int64_t timeout, void **handle, br_ldap_error *ordinary, char **fatal)
{
    script *s = user;
    CHECK(s->at < s->count && s->steps[s->at].kind == STEP_DIAL && !s->open);
    const step *st = &s->steps[s->at++];
    CHECK(timeout == INT64_C(5000000000) && tls == st->tls && insecure == st->insecure);
    CHECK(st->url && url.len == strlen(st->url) && !memcmp(url.data, st->url, url.len));
    CHECK(st->null_ctx ? !ctx : ctx == s->ctx);
    *handle = NULL;
    fill_error(st, ordinary, fatal);
    if (st->rc == 0 && st->presence == 0 && !st->null_handle) {
        *handle = s;
        s->open = true;
    }
    return st->rc;
}

static int bind_cb(void *user, void *handle, const br_scan_ctx *ctx, br_slice username,
                   br_slice password, br_ldap_error *ordinary, char **fatal)
{
    script *s = user;
    CHECK(s->at < s->count && s->steps[s->at].kind == STEP_BIND);
    const step *st = &s->steps[s->at++];
    CHECK(s->open && handle == s);
    CHECK(st->null_ctx ? !ctx : ctx == s->ctx);
    CHECK(st->user && username.len == strlen(st->user) && !memcmp(username.data, st->user, username.len));
    CHECK(st->pass && password.len == strlen(st->pass) && !memcmp(password.data, st->pass, password.len));
    fill_error(st, ordinary, fatal);
    return st->rc;
}

static int starttls_cb(void *user, void *handle, bool insecure, br_ldap_error *ordinary, char **fatal)
{
    script *s = user;
    CHECK(s->at < s->count && s->steps[s->at].kind == STEP_STARTTLS);
    const step *st = &s->steps[s->at++];
    CHECK(s->open && handle == s && insecure);
    fill_error(st, ordinary, fatal);
    return st->rc;
}

static void close_cb(void *user, void *handle)
{
    script *s = user;
    CHECK(s->open && handle == s);
    s->open = false;
    ++s->closes;
}

static const br_ldap_io io = {
    .dial = dial_cb, .bind = bind_cb, .starttls = starttls_cb, .close = close_cb,
};

static br_results run_bound(const br_detector *base, script *steps, const br_scan_ctx *ctx,
                            const char *input, char **error)
{
    br_ldap_binding *binding = NULL;
    CHECK(br_ldap_binding_init(base, &io, steps, &binding, error) == 0 && binding && !*error);
    CHECK(!((const br_ldap_state *)base->state)->io);
    const br_detector *bound = br_ldap_binding_detector(binding);
    steps->ctx = ctx;
    br_results out = {0};
    int rc = bound->scan(bound, ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, error);
    if (rc) fprintf(stderr, "scan error: %s\n", error && *error ? *error : "(null)");
    br_ldap_binding_destroy(binding);
    CHECK(rc == 0 && error && !*error && steps->at == steps->count && !steps->open);
    return out;
}

static void routing(const br_detector *detector)
{
    br_scan_ctx ctx = {.deadline_monotonic_ms = 42};
    const step query[] = {
        {.kind = STEP_DIAL, .url = "ldap:?query", .user = user, .pass = pass},
        {.kind = STEP_BIND, .url = "ldap:?query", .user = user, .pass = pass},
    };
    script steps = {.steps = query, .count = 2};
    char *error = NULL;
    br_results out = run_bound(detector, &steps, &ctx, "LDAP://?query user \"abcd\" pass \"pqrs\"", &error);
    CHECK(out.len == 1 && out.items[0].verified && !out.items[0].verification_error && steps.closes == 1);
    expect_secret(&out.items[0], "ldap:?query", user, pass);
    br_results_clear(&out);

    const step fragment[] = {
        {.kind = STEP_DIAL, .tls = true, .insecure = true, .url = "ldaps:#fragment", .user = user, .pass = pass},
        {.kind = STEP_BIND, .url = "ldaps:#fragment", .user = user, .pass = pass},
    };
    steps = (script){.steps = fragment, .count = 2};
    out = run_bound(detector, &steps, &ctx, "LDAPS://#fragment user \"abcd\" pass \"pqrs\"", &error);
    CHECK(out.len == 1 && out.items[0].verified && steps.closes == 1);
    expect_secret(&out.items[0], "ldaps:#fragment", user, pass);
    br_results_clear(&out);

    br_scan_ctx zero = {0};
    const step plain[] = {
        {.kind = STEP_DIAL, .url = "ldap://127.0.0.1", .user = user, .pass = pass},
        {.kind = STEP_BIND, .url = "ldap://127.0.0.1", .user = user, .pass = pass},
    };
    steps = (script){.steps = plain, .count = 2};
    out = run_bound(detector, &steps, &zero, "ldap://127.0.0.1 user \"abcd\" pass \"pqrs\"", &error);
    CHECK(out.len == 1 && out.items[0].verified && !out.items[0].verification_error && steps.closes == 1);
    expect_secret(&out.items[0], "ldap://127.0.0.1", user, pass);
    br_results_clear(&out);
}

static br_result prior_result(void)
{
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    prior.extra_data = json_object_new_object();
    CHECK(prior.verification_error && prior.extra_data);
    return prior;
}

static void nil_io(const br_detector *detector)
{
    br_result prior = prior_result();
    br_results out = {0};
    CHECK(br_results_push(&out, &prior) == 0);
    unsigned char *raw = out.items[0].raw.data;
    char *saved = out.items[0].verification_error;
    char *error = NULL;
    br_scan_ctx zero = {0};
    const char *input = "ldap://127.0.0.1 user \"abcd\" pass \"pqrs\"";
    CHECK(detector->scan(detector, &zero, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == -1);
    CHECK(error && !strncmp(error, "unsupported: LDAP verification", 31));
    CHECK(out.len == 1 && out.items[0].raw.data == raw && out.items[0].verification_error == saved);
    CHECK(out.items[0].verified && !((const br_ldap_state *)detector->state)->io);
    free(error);
    error = NULL;
    CHECK(detector->scan(detector, &zero, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, NULL) == -1);
    CHECK(out.len == 1);
    br_results_clear(&out);
}

static void outcomes(const br_detector *detector)
{
    br_scan_ctx ctx = {.deadline_monotonic_ms = 7};
    char *error = NULL;
    const char *input = "ldaps://127.0.0.1 user \"abcd\" pass \"pqrs\"";
    const step empty_indeterminate[] = {
        {.kind = STEP_DIAL, .tls = true, .insecure = true, .url = "ldaps://127.0.0.1"},
        {.kind = STEP_BIND, .presence = 1, .canceled = true, .text = "", .user = user, .pass = pass},
    };
    script steps = {.steps = empty_indeterminate, .count = 2};
    br_results out = run_bound(detector, &steps, &ctx, input, &error);
    CHECK(!error && out.len == 1 && !out.items[0].verified && steps.closes == 1);
    CHECK(out.items[0].verification_error && !*out.items[0].verification_error);
    br_results_clear(&out);

    const char *ldap_input = "ldap://127.0.0.1 user \"abcd\" pass \"pqrs\"";
    const step determinate[] = {
        {.kind = STEP_DIAL, .presence = 1, .text = "", .url = "ldap://127.0.0.1"},
    };
    steps = (script){.steps = determinate, .count = 1};
    out = run_bound(detector, &steps, &ctx, ldap_input, &error);
    CHECK(!error && out.len == 1 && !out.items[0].verified && !out.items[0].verification_error && !steps.closes);
    br_results_clear(&out);

    const step redacted[] = {
        {.kind = STEP_DIAL, .presence = 1, .op = true, .text = "dial pqrs failed", .url = "ldap://127.0.0.1"},
    };
    steps = (script){.steps = redacted, .count = 1};
    out = run_bound(detector, &steps, &ctx, ldap_input, &error);
    CHECK(!out.items[0].verified && out.items[0].verification_error);
    CHECK(!strcmp(out.items[0].verification_error, "dial [REDACTED] failed"));
    CHECK(!strstr(out.items[0].verification_error, pass));
    br_results_clear(&out);

    const step starttls[] = {
        {.kind = STEP_DIAL, .url = "ldap://127.0.0.1"},
        {.kind = STEP_BIND, .presence = 1, .canceled = true, .text = "FIRST-BIND", .user = user, .pass = pass},
        {.kind = STEP_STARTTLS, .presence = 1, .deadline = true, .text = "tls-down"},
    };
    steps = (script){.steps = starttls, .count = 3};
    out = run_bound(detector, &steps, &ctx, ldap_input, &error);
    CHECK(!out.items[0].verified && steps.closes == 1);
    CHECK(!strcmp(out.items[0].verification_error, "tls-down"));
    br_results_clear(&out);

    const step second[] = {
        {.kind = STEP_DIAL, .url = "ldap://127.0.0.1"},
        {.kind = STEP_BIND, .presence = 1, .text = "discard-me", .user = user, .pass = pass},
        {.kind = STEP_STARTTLS},
        {.kind = STEP_BIND, .user = user, .pass = pass},
    };
    steps = (script){.steps = second, .count = 4};
    out = run_bound(detector, &steps, &ctx, ldap_input, &error);
    CHECK(out.items[0].verified && !out.items[0].verification_error && steps.closes == 1);
    br_results_clear(&out);
}

static void fatal_paths(const br_detector *detector)
{
    br_scan_ctx ctx = {.deadline_monotonic_ms = 9};
    char *error = NULL;
    const char *input = "ldap://127.0.0.1 user \"abcd\" pass \"pqrs\"";
    br_result prior = prior_result();
    br_results out = {0};
    CHECK(br_results_push(&out, &prior) == 0);
    unsigned char *raw = out.items[0].raw.data;
    char *saved = out.items[0].verification_error;
    const step bind_fatal[] = {
        {.kind = STEP_DIAL, .url = "ldap://127.0.0.1"},
        {.kind = STEP_BIND, .rc = 1, .text = "x", .fatal = "boom", .user = user, .pass = pass},
    };
    script steps = {.steps = bind_fatal, .count = 2, .ctx = &ctx};
    br_ldap_binding *binding = NULL;
    CHECK(br_ldap_binding_init(detector, &io, &steps, &binding, &error) == 0 && !error);
    const br_detector *bound = br_ldap_binding_detector(binding);
    CHECK(bound->scan(bound, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == -1);
    CHECK(error && !strcmp(error, "LDAP bind failed") && steps.closes == 1 && !steps.open && steps.at == 2);
    CHECK(out.len == 1 && out.items[0].raw.data == raw && out.items[0].verification_error == saved);
    free(error);
    error = NULL;
    br_ldap_binding_destroy(binding);

    const step dial_fatal[] = {{.kind = STEP_DIAL, .rc = 1, .fatal = "nope", .url = "ldap://127.0.0.1"}};
    steps = (script){.steps = dial_fatal, .count = 1, .ctx = &ctx};
    CHECK(br_ldap_binding_init(detector, &io, &steps, &binding, &error) == 0 && !error);
    bound = br_ldap_binding_detector(binding);
    CHECK(bound->scan(bound, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == -1);
    CHECK(error && !strcmp(error, "LDAP dial failed") && !steps.closes && !steps.open && steps.at == 1);
    CHECK(out.len == 1 && out.items[0].verification_error == saved);
    free(error);
    error = NULL;
    br_ldap_binding_destroy(binding);

    const step nul[] = {
        {.kind = STEP_DIAL, .presence = 1, .op = true, .embed_nul = true, .url = "ldap://127.0.0.1"},
    };
    steps = (script){.steps = nul, .count = 1, .ctx = &ctx};
    CHECK(br_ldap_binding_init(detector, &io, &steps, &binding, &error) == 0 && !error);
    bound = br_ldap_binding_detector(binding);
    CHECK(bound->scan(bound, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == -1);
    CHECK(error && !strncmp(error, "unsupported:", 12) && !steps.closes);
    CHECK(out.len == 1 && out.items[0].raw.data == raw);
    free(error);
    br_ldap_binding_destroy(binding);
    br_results_clear(&out);

    const char *two = "ldap://127.0.0.1 ldap://10.0.0.2 user \"abcd\" pass \"pqrs\"";
    const step rollback[] = {
        {.kind = STEP_DIAL, .url = "ldap://127.0.0.1"},
        {.kind = STEP_BIND, .user = user, .pass = pass},
        {.kind = STEP_DIAL, .url = "ldap://10.0.0.2"},
        {.kind = STEP_BIND, .rc = 1, .fatal = "boom", .user = user, .pass = pass},
    };
    prior = prior_result();
    out = (br_results){0};
    CHECK(br_results_push(&out, &prior) == 0);
    raw = out.items[0].raw.data;
    saved = out.items[0].verification_error;
    steps = (script){.steps = rollback, .count = 4, .ctx = &ctx};
    error = NULL;
    CHECK(br_ldap_binding_init(detector, &io, &steps, &binding, &error) == 0 && !error);
    bound = br_ldap_binding_detector(binding);
    CHECK(bound->scan(bound, &ctx, true, (br_slice){(const unsigned char *)two, strlen(two)}, &out, &error) == -1);
    CHECK(error && !strcmp(error, "LDAP bind failed") && steps.closes == 2 && !steps.open);
    CHECK(out.len == 1 && out.items[0].raw.data == raw && out.items[0].verification_error == saved);
    free(error);
    br_ldap_binding_destroy(binding);
    br_results_clear(&out);
}

static void reset_counts(void)
{
    url_calls = password_finds = captures_finds = 0;
    url_fail_remaining = snprintf_fail_at = part_fail_after = 0;
}

static void stage_order(const br_detector *detector)
{
    password_regex = ((const br_ldap_state *)detector->state)->password;
    char *error = NULL;
    br_results out = {0};
    reset_counts();
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)"", 0}, &out, &error) == 0);
    CHECK(!error && !out.len && !url_calls && !captures_finds);

    reset_counts();
    const char *nomatch = "user \"abcd\" pass \"pqrs\"";
    CHECK(detector->scan(detector, NULL, true,
                         (br_slice){(const unsigned char *)nomatch, strlen(nomatch)}, &out, &error) == 0);
    CHECK(!error && !out.len && !url_calls && !captures_finds);

    reset_counts();
    char rejected[] = "ldap://host/a\vname user \"abcd\" pass \"pqrs\"";
    CHECK(detector->scan(detector, NULL, true,
                         (br_slice){(const unsigned char *)rejected, sizeof(rejected) - 1}, &out, &error) == 0);
    CHECK(!error && !out.len && url_calls == 1 && !captures_finds && !password_finds);

    reset_counts();
    const char *no_user = "ldap://127.0.0.1 pass \"pqrs\"";
    CHECK(detector->scan(detector, NULL, true,
                         (br_slice){(const unsigned char *)no_user, strlen(no_user)}, &out, &error) == 0);
    CHECK(!error && !out.len && url_calls == 1 && captures_finds == 1 && !password_finds);

    reset_counts();
    out = nov(detector, "ldap://127.0.0.1 user \"abcd\" pass \"pqrs\"");
    CHECK(out.len == 1 && url_calls == 1 && captures_finds == 2 && password_finds == 1);
    br_results_clear(&out);

    reset_counts();
    out = nov(detector, "ldap://127.0.0.1 user \"abcd\" user \"wxyz\" pass \"pqrs\"");
    CHECK(out.len == 2 && password_finds == 2 && captures_finds == 3);
    br_results_clear(&out);

    reset_counts();
    char mixed[] = "ldap://host/a\vname ldap://127.0.0.1 user \"abcd\" pass \"pqrs\"";
    out = nov(detector, mixed);
    CHECK(out.len == 1 && url_calls == 2 && captures_finds == 2 && password_finds == 1);
    expect_secret(&out.items[0], "ldap://127.0.0.1", user, pass);
    br_results_clear(&out);

    reset_counts();
    out = nov(detector, "OpenDSObject(\"ldaps://www\",\"ABC\",\"XYZ\",1)");
    /* The URI grammar also matches ldaps://www, then a missing username skips passwords. */
    CHECK(out.len == 1 && url_calls == 2 && captures_finds == 1 && !password_finds);
    br_results_clear(&out);
}

static void dial_boundary(const br_detector *detector)
{
    br_scan_ctx zero = {0};
    char *error = NULL;
    const char *input = "ldap://127.0.0.1 user \"abcd\" pass \"pqrs\"";
    const char *ldaps = "ldaps://127.0.0.1 user \"abcd\" pass \"pqrs\"";
    const char *mixed = "ldap://127.0.0.1 user \"abcd\" pass \"pqrs\" OpenDSObject(\"ldaps://www\",\"ABC\",\"XYZ\",1)";
    script steps = {0};
    br_ldap_binding *binding = NULL;
    CHECK(br_ldap_binding_init(detector, &io, &steps, &binding, &error) == 0 && !error);
    const br_detector *bound = br_ldap_binding_detector(binding);
    br_results out = {0};
    CHECK(bound->scan(bound, NULL, false, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == 0);
    CHECK(!error && out.len == 1 && !steps.at && !steps.closes);
    br_results_clear(&out);
    br_ldap_binding_destroy(binding);

    steps = (script){0};
    error = NULL;
    CHECK(br_ldap_binding_init(detector, &io, &steps, &binding, &error) == 0 && !error);
    bound = br_ldap_binding_detector(binding);
    CHECK(bound->scan(bound, NULL, true, (br_slice){(const unsigned char *)"", 0}, &out, &error) == 0);
    CHECK(!error && !out.len && !steps.at && !steps.closes);
    br_ldap_binding_destroy(binding);

    const char *no_user = "ldap://127.0.0.1 pass \"pqrs\"";
    steps = (script){0};
    error = NULL;
    CHECK(br_ldap_binding_init(detector, &io, &steps, &binding, &error) == 0 && !error);
    bound = br_ldap_binding_detector(binding);
    CHECK(bound->scan(bound, NULL, true, (br_slice){(const unsigned char *)no_user, strlen(no_user)}, &out, &error) == 0);
    CHECK(!error && !out.len && !steps.at && !steps.closes);
    br_ldap_binding_destroy(binding);

    char rejected[] = "ldap://host/a\vname user \"abcd\" pass \"pqrs\"";
    steps = (script){0};
    error = NULL;
    CHECK(br_ldap_binding_init(detector, &io, &steps, &binding, &error) == 0 && !error);
    bound = br_ldap_binding_detector(binding);
    CHECK(bound->scan(bound, NULL, true,
                      (br_slice){(const unsigned char *)rejected, sizeof(rejected) - 1}, &out, &error) == 0);
    CHECK(!error && !out.len && !steps.at && !steps.closes);
    br_ldap_binding_destroy(binding);

    br_result prior = prior_result();
    CHECK(br_results_push(&out, &prior) == 0);
    unsigned char *raw = out.items[0].raw.data;
    char *saved = out.items[0].verification_error;
    steps = (script){0};
    error = NULL;
    CHECK(br_ldap_binding_init(detector, &io, &steps, &binding, &error) == 0 && !error);
    bound = br_ldap_binding_detector(binding);
    CHECK(bound->scan(bound, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == -1);
    CHECK(error && !strcmp(error, "unsupported upstream panic: LDAP nil context"));
    CHECK(!steps.at && !steps.closes && out.len == 1 && out.items[0].raw.data == raw);
    CHECK(out.items[0].verification_error == saved);
    free(error);
    br_ldap_binding_destroy(binding);

    steps = (script){0};
    error = NULL;
    CHECK(br_ldap_binding_init(detector, &io, &steps, &binding, &error) == 0 && !error);
    bound = br_ldap_binding_detector(binding);
    CHECK(bound->scan(bound, NULL, true, (br_slice){(const unsigned char *)ldaps, strlen(ldaps)}, &out, &error) == -1);
    CHECK(error && !strcmp(error, "unsupported upstream panic: LDAP nil context"));
    CHECK(!steps.at && !steps.closes && out.len == 1 && out.items[0].verification_error == saved);
    free(error);
    br_ldap_binding_destroy(binding);

    const char *default_inputs[] = {input, ldaps};
    for (size_t i = 0; i < 2; ++i) {
        error = NULL;
        CHECK(detector->scan(detector, NULL, true,
                             (br_slice){(const unsigned char *)default_inputs[i], strlen(default_inputs[i])},
                             &out, &error) == -1);
        CHECK(error && !strcmp(error, "unsupported upstream panic: LDAP nil context"));
        CHECK(!((const br_ldap_state *)detector->state)->io);
        CHECK(out.len == 1 && out.items[0].raw.data == raw && out.items[0].verification_error == saved);
        free(error);
        error = NULL;
        CHECK(detector->scan(detector, &zero, true,
                             (br_slice){(const unsigned char *)default_inputs[i], strlen(default_inputs[i])},
                             &out, &error) == -1);
        CHECK(error && !strcmp(error, "unsupported: LDAP verification"));
        CHECK(out.len == 1 && out.items[0].raw.data == raw && out.items[0].verification_error == saved);
        free(error);
    }

    part_fail_after = 1;
    error = NULL;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create LDAP result") && !part_fail_after);
    CHECK(out.len == 1 && out.items[0].raw.data == raw && out.items[0].verification_error == saved);
    free(error);

    const step null_handle[] = {{.kind = STEP_DIAL, .null_handle = true, .url = "ldap://127.0.0.1"}};
    steps = (script){.steps = null_handle, .count = 1, .ctx = &zero};
    error = NULL;
    CHECK(br_ldap_binding_init(detector, &io, &steps, &binding, &error) == 0 && !error);
    bound = br_ldap_binding_detector(binding);
    CHECK(bound->scan(bound, &zero, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == -1);
    CHECK(error && !strcmp(error, "unsupported: LDAP NULL dial handle"));
    CHECK(steps.at == 1 && !steps.closes && !steps.open && out.len == 1 && out.items[0].raw.data == raw);
    free(error);
    br_ldap_binding_destroy(binding);

    const step setter[] = {
        {.kind = STEP_DIAL, .tls = true, .insecure = true, .url = "ldaps://127.0.0.1"},
        {.kind = STEP_BIND, .presence = 1, .op = true, .embed_nul = true, .user = user, .pass = pass},
    };
    steps = (script){.steps = setter, .count = 2, .ctx = &zero};
    error = NULL;
    CHECK(br_ldap_binding_init(detector, &io, &steps, &binding, &error) == 0 && !error);
    bound = br_ldap_binding_detector(binding);
    CHECK(bound->scan(bound, &zero, true, (br_slice){(const unsigned char *)ldaps, strlen(ldaps)}, &out, &error) == -1);
    CHECK(error && !strcmp(error, "unsupported: LDAP verification error contains embedded NUL"));
    CHECK(steps.closes == 1 && !steps.open && steps.at == 2 && out.len == 1);
    free(error);
    br_ldap_binding_destroy(binding);

    const step uri_fatal[] = {{.kind = STEP_DIAL, .rc = 1, .fatal = "nope", .url = "ldap://127.0.0.1"}};
    steps = (script){.steps = uri_fatal, .count = 1, .ctx = &zero};
    error = NULL;
    CHECK(br_ldap_binding_init(detector, &io, &steps, &binding, &error) == 0 && !error);
    bound = br_ldap_binding_detector(binding);
    CHECK(bound->scan(bound, &zero, true, (br_slice){(const unsigned char *)mixed, strlen(mixed)}, &out, &error) == -1);
    CHECK(error && !strcmp(error, "LDAP dial failed") && steps.at == 1 && !steps.closes && !steps.open);
    CHECK(out.len == 1 && out.items[0].raw.data == raw && out.items[0].verification_error == saved);
    free(error);
    br_ldap_binding_destroy(binding);

    reset_counts();
    url_fail_remaining = 1;
    steps = (script){.ctx = &zero};
    error = NULL;
    CHECK(br_ldap_binding_init(detector, &io, &steps, &binding, &error) == 0 && !error);
    bound = br_ldap_binding_detector(binding);
    CHECK(bound->scan(bound, &zero, true, (br_slice){(const unsigned char *)mixed, strlen(mixed)}, &out, &error) == -1);
    CHECK(error && !strcmp(error, "injected URL projection failure"));
    CHECK(!steps.at && !steps.closes && url_calls == 1 && !captures_finds && !password_finds);
    CHECK(out.len == 1 && out.items[0].raw.data == raw && out.items[0].verification_error == saved);
    free(error);
    br_ldap_binding_destroy(binding);
    br_results_clear(&out);
    reset_counts();
}

static void unknown_scheme_format(void)
{
    br_slice url = {(const unsigned char *)"other:rest", 10};
    char *error = NULL;
    snprintf_calls = 0;
    snprintf_fail_at = 0;
    CHECK(unknown_scheme(url, &error) == 0 && !error && snprintf_calls == 2);

    snprintf_calls = 0;
    snprintf_fail_at = 1;
    snprintf_fail_rc = -1;
    CHECK(unknown_scheme(url, &error) == -1 && snprintf_calls == 1);
    CHECK(error && !strcmp(error, "cannot format LDAP scheme error"));
    CHECK(!strstr(error, "unknown ldap scheme"));
    free(error);

    snprintf_calls = 0;
    snprintf_fail_at = 2;
    snprintf_fail_rc = -1;
    error = NULL;
    CHECK(unknown_scheme(url, &error) == -1 && snprintf_calls == 2);
    CHECK(error && !strcmp(error, "cannot format LDAP scheme error"));
    CHECK(!strstr(error, "other"));
    free(error);

    snprintf_calls = 0;
    snprintf_fail_at = 2;
    snprintf_fail_rc = 1;
    error = NULL;
    CHECK(unknown_scheme(url, &error) == -1 && snprintf_calls == 2);
    CHECK(error && !strcmp(error, "cannot format LDAP scheme error"));
    free(error);

    snprintf_calls = 0;
    snprintf_fail_at = 2;
    snprintf_fail_rc = -1;
    CHECK(unknown_scheme(url, NULL) == -1 && snprintf_calls == 2);
    snprintf_fail_at = 0;
}

int main(void)
{
    br_result result = {0};
    unsigned char text[] = "synthetic";
    br_ldap_error oversized = {.presence = BR_LDAP_ERR_OTHER, .has_op_error = true,
                              .innermost = {text, SIZE_MAX}};
    char *error = NULL;
    CHECK(classify(&result, &oversized, (br_slice){0}, &error) == -1 && error);
    CHECK(!result.verification_error && !result.verified);
    free(error);
    const br_detector *detector = descriptor();
    products(detector);
    iad(detector);
    routing(detector);
    nil_io(detector);
    outcomes(detector);
    fatal_paths(detector);
    stage_order(detector);
    dial_boundary(detector);
    unknown_scheme_format();
    return test_finish("LDAP");
}
