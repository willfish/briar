/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static const char key[] = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCdEf";
static const char other[] = "zYxWvUtSrQpOnMlKjIhGfEdCbA9876543210-_zYxWvU";
static const char form_prefix[] = "apikey=";
static const char form_suffix[] = "&grant_type=urn%3Aibm%3Aparams%3Aoauth%3Agrant-type%3Aapikey";
static size_t fail_size, fail_after, failed_allocations, fail_part_after;
static bool fail_agent;
static br_slice borrowed_body;
static const char *borrowed_type, *borrowed_auth, *expected_key;

/* Reuse the named-test allocation seam to distinguish fatal provider-owned
 * work from the shared preparation failures this source deliberately ignores. */
void *malloc(size_t size)
{
    if (size == fail_size && fail_after && --fail_after == 0) {
        ++failed_allocations;
        return NULL;
    }
    return calloc(1, size);
}

char *strdup(const char *s)
{
    if (fail_agent && !strcmp(s, "TruffleHog")) {
        fail_agent = false;
        ++failed_allocations;
        return NULL;
    }
    size_t size = strlen(s) + 1;
    char *copy = malloc(size);
    if (copy) memcpy(copy, s, size);
    return copy;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) return 7;
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 44 && strlen(other) == 44);
    CHECK(br_ibmclouduserkey_init(NULL, &error) == -1 && error);
    CHECK(!strcmp(error, "invalid IBM Cloud user-key detector output"));
    free(error);
    CHECK(br_ibmclouduserkey_init(NULL, NULL) == -1);
    CHECK(br_ibmclouduserkey_init(&d, &error) == 0 && d && !error);
    CHECK(br_ibmclouduserkey_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 73 && d->version == 0 && !strcmp(d->name, "IbmCloudUserKey"));
    CHECK(d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "IBM Cloud is a suite of cloud computing services from IBM that offers both platform as a service (PaaS) and infrastructure as a service (IaaS). IBM Cloud API keys can be used to access and manage IBM Cloud services and resources."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "ibm"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d; /* Direct disabled-detector evidence, not CLI selection evidence. */
}

static void check_result(const br_result *result, const char *value, bool verified)
{
    test_key_result(result, 73, value, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static void extract_case(const br_detector *d, const void *input, size_t len, const char *value)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input, len);
    CHECK(out.len == (value ? 1u : 0u) && !http.calls && !http.releases);
    if (value) check_result(&out.items[0], value, false);
    br_results_clear(&out);
}

static void extraction(const br_detector *d)
{
    char input[300], changed[46];
    const char *formats[] = {
        "ibm '%s'", "IBM=-%s-", "prefixIbMsuffix\r\n%s", "ibm\r%s", "ibm\n%s", "ibm \t%s\t ",
    };
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        snprintf(input, sizeof(input), formats[i], key);
        extract_case(d, input, strlen(input), key);
    }
    const char *missing[] = {"%s", "i bm %s", "%s ibm", "ibm%s", "ibm _%s", "ibm %s_", "ibm %sA"};
    for (size_t i = 0; i < sizeof(missing) / sizeof(missing[0]); ++i) {
        snprintf(input, sizeof(input), missing[i], key);
        extract_case(d, input, strlen(input), NULL);
    }
    const char invalid[] = {'/', ' ', ':', '.'};
    for (size_t i = 0; i < sizeof(invalid); ++i) {
        memcpy(changed, key, sizeof(key)); changed[15] = invalid[i];
        snprintf(input, sizeof(input), "ibm %s", changed);
        extract_case(d, input, strlen(input), NULL);
    }
    memcpy(changed, key, sizeof(key)); changed[43] = '\0';
    snprintf(input, sizeof(input), "ibm %s", changed);
    extract_case(d, input, strlen(input), NULL);
    memset(changed, 'Z', 44); changed[44] = '\0';
    snprintf(input, sizeof(input), "ibm %s", changed);
    extract_case(d, input, strlen(input), changed); /* No entropy/hex/randomness filter. */
    changed[44] = 'Z'; changed[45] = '\0';
    snprintf(input, sizeof(input), "ibm %s", changed);
    extract_case(d, input, strlen(input), NULL);
    memcpy(changed, key, sizeof(key)); changed[0] = changed[43] = '_';
    snprintf(input, sizeof(input), "ibm %s", changed);
    extract_case(d, input, strlen(input), changed);
    memcpy(changed, key, sizeof(key)); changed[0] = '-';
    snprintf(input, sizeof(input), "ibm %s", changed);
    extract_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "ibmX%s", changed);
    extract_case(d, input, strlen(input), changed);
    memcpy(changed, key, sizeof(key)); changed[43] = '-';
    snprintf(input, sizeof(input), "ibm %s", changed);
    extract_case(d, input, strlen(input), NULL);
    snprintf(input, sizeof(input), "ibm %sX", changed);
    extract_case(d, input, strlen(input), changed); /* A word boundary is not a whole-token check. */
    changed[0] = '-';
    snprintf(input, sizeof(input), "ibmX%sY", changed);
    extract_case(d, input, strlen(input), changed);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "ibm", 3); memset(input + 3, ':', gap); memcpy(input + 3 + gap, key, 44);
        extract_case(d, input, 47 + gap, gap == 40 ? key : NULL);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 3 + 4 * i, "💡", 4);
        memcpy(input + 3 + 4 * gap, key, 44);
        extract_case(d, input, 47 + 4 * gap, gap == 40 ? key : NULL);
    }
    memcpy(input, "ibm\0:", 5); memcpy(input + 5, key, 44);
    extract_case(d, input, 49, key);
    snprintf(input, sizeof(input), "ibm %s %s", key, other);
    extract_case(d, input, strlen(input), key); /* Consumed prefixes are not reused. */
    extract_case(d, NULL, 0, NULL);
}

typedef struct {
    const char *const *keys;
    size_t count;
    const br_scan_ctx *ctx;
    const char *agent;
    const br_http_response *responses;
} expected;

static void check_form(br_slice body, const char *value)
{
    char full[sizeof(form_prefix) - 1 + 44 + sizeof(form_suffix)];
    int n = snprintf(full, sizeof(full), "%s%s%s", form_prefix, value, form_suffix);
    CHECK(n > 0 && (size_t)n == sizeof(full) - 1);
    CHECK(body.data && body.len == (size_t)n && !memcmp(body.data, full, body.len));
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected *e = http->user;
    size_t at = http->calls - 1;
    CHECK(at < e->count && ctx == e->ctx && http->releases == at && !borrowed_body.data);
    CHECK(request->detector_type == 73 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://iam.cloud.ibm.com/identity/token"));
    expected_key = e->keys[at];
    check_form(request->body, expected_key);
    CHECK(!request->dedup_key.data && !request->dedup_key.len && request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/x-www-form-urlencoded"));
    CHECK(!strcmp(request->headers[1].name, "Authorization") && !strcmp(request->headers[1].value, "Basic Yng6Yng="));
    CHECK(!strcmp(request->headers[2].name, "User-Agent") && !strcmp(request->headers[2].value, e->agent));
    /* Only original body/header values survive ordinary release. Never borrow
     * the synthesized request, header array or User-Agent beyond send return. */
    borrowed_body = request->body;
    borrowed_type = request->headers[0].value;
    borrowed_auth = request->headers[1].value;
    if (e->responses) http->response = e->responses[at];
}

static void release_response(void *user, br_http_response *response)
{
    if (borrowed_body.data) {
        check_form(borrowed_body, expected_key);
        CHECK(!strcmp(borrowed_type, "application/x-www-form-urlencoded"));
        CHECK(!strcmp(borrowed_auth, "Basic Yng6Yng="));
    } else CHECK(!response->status && !response->body.data && !response->body.len && !response->body_error);
    borrowed_body = (br_slice){0};
    borrowed_type = borrowed_auth = expected_key = NULL;
    test_http_release(user, response);
}

static void occurrences_and_constructor_order(const br_detector *d)
{
    char input[160];
    snprintf(input, sizeof(input), "ibm %s\nibm %s\nibm %s", key, other, key);
    const char *keys[] = {key, other, key};
    const br_http_response responses[] = {{.status = 200}, {.status = 299, .body_error = "ignored"}, {.status = 300}};
    expected e = {.keys = keys, .count = 3, .agent = "TruffleHog ibm-offline", .responses = responses};
    test_http http = {.inspect = inspect_request, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "ibm-offline"}; e.ctx = &ctx;
    for (int verify = 0; verify < 2; ++verify) {
        br_results out = test_scan(d, &ctx, verify, input, strlen(input));
        CHECK(out.len == 3 && http.calls == (verify ? 3u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 3; ++i) check_result(&out.items[i], keys[i], verify && i < 2);
        CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
        br_results_clear(&out);
    }
    br_results out = test_scan(d, NULL, true, input, strlen(input));
    CHECK(!out.len && http.calls == 3 && http.releases == 3);
    br_results_clear(&out);
    out = test_scan(d, NULL, false, input, strlen(input));
    CHECK(out.len == 3 && http.calls == 3 && http.releases == 3);
    for (size_t i = 0; i < 3; ++i) check_result(&out.items[i], keys[i], false);
    br_results_clear(&out);
}

static bool fail_headers(void *user) { (void)user; fail_size = 3 * sizeof(br_header); fail_after = 1; return false; }
static bool arm_agent(void *user) { (void)user; fail_agent = true; return false; }
static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void status_send_and_setup(const br_detector *d)
{
    char input[50]; snprintf(input, sizeof(input), "ibm %s", key);
    const char *keys[] = {key};
    expected e = {.keys = keys, .count = 1, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_transport no_send = {&http, NULL, release_response};
    br_scan_ctx ctx = {.transport = &transport}; e.ctx = &ctx;
    static const unsigned char binary[] = {0xff, 0, '{', '!', '}'};
    const struct { int status; const char *read_error; bool verified; } cases[] = {
        {199, NULL, false}, {200, "read failed", true}, {201, NULL, true}, {204, NULL, true},
        {299, "", true}, {300, NULL, false}, {302, "read failed", false}, {401, NULL, false},
        {403, NULL, false}, {500, "read failed", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = 0;
        http.response = (br_http_response){.status = cases[i].status, .body_error = cases[i].read_error,
            .body = cases[i].status == 204 ? (br_slice){0} : (br_slice){binary, sizeof(binary)}};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        check_result(&out.items[0], key, cases[i].verified);
        br_results_clear(&out);
    }
    const struct { int rc; const char *cause; } failures[] = {
        {1, "timeout"}, {-7, "cannot construct IBM Cloud user-key form"},
        {1, "cannot create IBM Cloud user-key result"}, {-1, NULL}, {1, key},
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        http.calls = http.releases = 0; http.send_rc = failures[i].rc; http.send_error = failures[i].cause;
        http.response = (br_http_response){.status = 200, .body = {binary, sizeof(binary)}, .body_error = "ignored"};
        br_results out = test_scan(d, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        check_result(&out.items[0], key, false);
        br_results_clear(&out);
    }
    size_t cancellations = 0;
    br_scan_ctx contexts[] = {
        {0}, {.transport = &transport, .cancelled = fail_headers},
        {.transport = &transport, .cancelled = arm_agent},
        {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1},
        {.transport = &transport, .user_agent = "bad\r\nagent"}, {.transport = &no_send},
    };
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        size_t before = failed_allocations; http.calls = http.releases = 0;
        br_results out = test_scan(d, &contexts[i], true, input, strlen(input));
        CHECK(out.len == 1 && !http.calls && http.releases == (i ? 1u : 0u));
        CHECK(!fail_after && !fail_agent && failed_allocations == before + (i == 1 || i == 2 ? 1u : 0u));
        check_result(&out.items[0], key, false);
        br_results_clear(&out);
    }
    CHECK(cancellations == 1);
}

static void check_prior(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && !memcmp(&out->items[0], prior, sizeof(*prior)));
    CHECK(prior->raw.len == 5 && !memcmp(prior->raw.data, "prior", 5));
    CHECK(prior->verified && !strcmp(prior->verification_error, "caller-owned"));
}

static void owned_failures_and_rollback(const br_detector *d)
{
    char input[110]; snprintf(input, sizeof(input), "ibm %s\nibm %s", key, other);
    const char *keys[] = {key, other};
    expected e = {.keys = keys, .count = 2, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &e, .send_rc = -7, .send_error = "synthetic Do failure"};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport}; e.ctx = &ctx;
    br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0];
    char *error = NULL;
    const size_t form_size = sizeof(form_prefix) - 1 + 44 + sizeof(form_suffix);
    for (size_t failure = 0; failure < 5; ++failure) {
        if (failure == 0) { fail_size = 2 * sizeof(br_span); fail_after = 1; } /* Positive regex resource failure. */
        if (failure == 1) { fail_size = 45; fail_after = 2; } /* All captures precede verification. */
        if (failure == 2) { fail_size = 44; fail_after = 2; } /* Second finding Raw. */
        if (failure == 3) fail_part_after = 2; /* Positive secret-part insertion failure. */
        /* Regex scratch uses this same size once before the two forms. */
        if (failure == 4) { fail_size = form_size; fail_after = 3; } /* Second form assembly. */
        size_t before = failed_allocations;
        CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == -1 && error);
        CHECK(!fail_after && !fail_part_after && http.calls == (failure >= 2 ? 1u : 0u) && http.releases == http.calls);
        CHECK(failed_allocations == before + (failure == 3 ? 0u : 1u));
        if (failure == 4) CHECK(!strcmp(error, "cannot construct IBM Cloud user-key form"));
        check_prior(&out, &prior);
        free(error); error = NULL; http.calls = http.releases = 0;
    }
    /* Owned form/finding failures must win before the nil-constructor drop. */
    fail_size = form_size; fail_after = 2;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == -1 && error);
    CHECK(!strcmp(error, "cannot construct IBM Cloud user-key form") && !fail_after);
    check_prior(&out, &prior); free(error); error = NULL;
    fail_part_after = 1;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == -1 && error);
    CHECK(!strcmp(error, "cannot create IBM Cloud user-key result") && !fail_part_after);
    check_prior(&out, &prior); free(error); error = NULL;
    /* A positive push failure is fatal even after successful verification. */
    size_t cap = out.cap; out.cap = 0; http.send_rc = 0; http.send_error = NULL;
    http.response = (br_http_response){.status = 204, .body_error = "ignored"};
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &out, &error) == -1 && error);
    out.cap = cap;
    CHECK(!strcmp(error, "cannot append IBM Cloud user-key result") && http.calls == 1 && http.releases == 1);
    check_prior(&out, &prior); free(error);
    fail_size = 44; fail_after = 1;
    CHECK(d->scan(d, &ctx, false, (br_slice){(const unsigned char *)input, strlen(input)}, &out, NULL) == -1 && !fail_after);
    check_prior(&out, &prior);
    br_results_clear(&out);
}

int main(void)
{
    const br_detector *d = descriptor();
    extraction(d);
    occurrences_and_constructor_order(d);
    status_send_and_setup(d);
    owned_failures_and_rollback(d);
    CHECK(!fail_after && !fail_part_after && !fail_agent && !borrowed_body.data);
    CHECK(!borrowed_type && !borrowed_auth && !expected_key);
    return test_finish("IbmCloudUserKey");
}
