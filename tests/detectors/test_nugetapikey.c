/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int br_nugetapikey_init(const br_detector **out, char **error);

static char key1[47], key2[47];
static const char url[] = "https://www.nuget.org/api/v2/package";
static const char header_name[] = "X-Nuget-Apikey";
static size_t fail_size, fail_after, fail_part_after, fail_next_malloc, setter_calls, sized_allocs;
static bool fail_growth;
static const size_t key_size = 47;

static void *hook_realloc(void *p, size_t n)
{
    if (fail_growth) { fail_growth = false; return NULL; }
    return realloc(p, n);
}
#define realloc hook_realloc
#define br_result_set_verification_error nuget_real_setter
#include "../../src/result.c"
#undef br_result_set_verification_error
#undef realloc

void *malloc(size_t n)
{
    if (fail_next_malloc && --fail_next_malloc == 0) return NULL;
    if (fail_after && n == fail_size && --fail_after == 0) return NULL;
    if (n == key_size) ++sized_allocs;
    return calloc(1, n);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && !strcmp(name, "key") && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    (void)result; (void)cause; (void)secrets; (void)count;
    ++setter_calls;
    return nuget_real_setter(result, cause, secrets, count);
}

static void make_key(char *out, size_t shift)
{
    test_secret(out, 46, shift);
    CHECK(strlen(out) == 46);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_nugetapikey_init(NULL, &error) == -1 && error);
    free(error); error = NULL;
    CHECK(br_nugetapikey_init(NULL, NULL) == -1);
    fail_size = sizeof("(?i:nuget)(?s:.){0,40}?");
    fail_after = 1;
    CHECK(br_nugetapikey_init(&d, &error) == -1 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern"));
    free(error); error = NULL;
    CHECK(br_nugetapikey_init(&d, &error) == 0 && d && !error);
    CHECK(br_nugetapikey_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 916 && d->version == 0 && !strcmp(d->name, "NuGetApiKey"));
    CHECK(d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "NuGet is a package manager for .NET. NuGet API keys can be used to publish and manage packages in the NuGet repository."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "nuget"));
    CHECK(strcmp(d->keywords[0], "nugetapikey"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive);
    CHECK(!d->validate_endpoints && !d->cloud_endpoint);
    return d;
}

static void check_result(const br_result *r, const char *key, bool verified)
{
    test_key_result(r, 916, key, "key");
    CHECK(r->raw.len == 46 && r->verified == verified && !r->extra_data && !r->verification_error);
}

static void expect_n(const br_detector *d, const void *text, size_t n, size_t count, const char *key)
{
    br_results r = test_scan(d, NULL, false, text, n);
    CHECK(r.len == count && !setter_calls);
    for (size_t i = 0; i < count; ++i) check_result(&r.items[i], key, false);
    br_results_clear(&r);
}

static void grammar(const br_detector *d)
{
    char input[220], changed[47], near[100], far[110];
    int n = snprintf(input, sizeof(input), "nuget %s", key1);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 1, key1);
    n = snprintf(input, sizeof(input), "NUGET %s", key1);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 1, key1);
    n = snprintf(input, sizeof(input), "nuget %s nuget %s", key1, key1);
    CHECK(n > 0);
    br_results both = test_scan(d, NULL, false, input, (size_t)n);
    CHECK(both.len == 2 && !setter_calls);
    check_result(&both.items[0], key1, false);
    check_result(&both.items[1], key1, false);
    CHECK(both.items[0].raw.data != both.items[1].raw.data);
    br_results_clear(&both);
    expect_n(d, key1, 46, 0, NULL);
    n = snprintf(input, sizeof(input), "apikey %s", key1);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 0, NULL);
    n = snprintf(input, sizeof(input), "nugetapikey-only %s", key1);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 1, key1);
    memcpy(near, "nuget", 5);
    memset(near + 5, '.', 40);
    memcpy(near + 45, key1, 46);
    expect_n(d, near, 91, 1, key1);
    memcpy(far, "nuget", 5);
    memset(far + 5, '.', 41);
    memcpy(far + 46, key1, 46);
    expect_n(d, far, 92, 0, NULL);
    memcpy(changed, key1, 47); changed[10] = 'A';
    n = snprintf(input, sizeof(input), "nuget %s", changed);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 0, NULL);
    memcpy(changed, key1, 45); changed[45] = '\0';
    n = snprintf(input, sizeof(input), "nuget %s.", changed);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 0, NULL);
    n = snprintf(input, sizeof(input), "nuget %sa", key1);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 0, NULL);
    n = snprintf(input, sizeof(input), "nuget %s.", key1);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 1, key1);
    n = snprintf(input, sizeof(input), "xnuget %s", key1);
    CHECK(n > 0); expect_n(d, input, (size_t)n, 1, key1);
    expect_n(d, "nuget", 5, 0, NULL);
    expect_n(d, NULL, 0, 0, NULL);
}

typedef struct {
    const char *const *keys;
    size_t count;
    const char *live[3];
    br_header markers[3];
    int statuses[3];
    const char *body_errors[3];
    int send_rc[3];
    const char *send_errors[3];
    size_t released_ids[3];
    size_t release_lengths[3];
    size_t sends_at_release[3];
    const br_scan_ctx *ctx;
    br_results *out;
    bool fail_retain;
} expected;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected *e = http->user;
    size_t at = http->calls - 1;
    CHECK(at < e->count && ctx == e->ctx && request->headers);
    size_t failed = 0;
    for (size_t i = 0; i < at; ++i) {
        if (!e->live[i]) { ++failed; continue; }
        CHECK(e->live[i] != request->headers[1].value && !strcmp(e->live[i], e->keys[i]));
    }
    CHECK(http->releases == failed);
    CHECK(!strcmp(request->method, "PUT") && request->url && !strcmp(request->url, url));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 916);
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Length"));
    CHECK(!strcmp(request->headers[0].value, "0"));
    CHECK(!strcmp(request->headers[1].name, header_name));
    CHECK(strcmp(request->headers[1].name, "X-NuGet-ApiKey"));
    CHECK(!strcmp(request->headers[1].value, e->keys[at]));
    CHECK(!strcmp(request->headers[2].name, "User-Agent"));
    CHECK(!strcmp(request->headers[2].value, "TruffleHog nuget-offline"));
    e->live[at] = request->headers[1].value;
    e->markers[at] = (br_header){"synthetic-attempt", e->keys[at]};
    http->response = (br_http_response){
        .status = e->statuses[at], .headers = &e->markers[at], .nheaders = 1,
        .body_error = e->body_errors[at],
    };
    http->send_rc = e->send_rc[at];
    http->send_error = e->send_errors[at];
    if (e->fail_retain && at == 1) fail_next_malloc = 1;
}

static void release_response(void *user, br_http_response *response)
{
    test_http *http = user;
    expected *e = http->user;
    if (http->calls) {
        size_t id = 0;
        while (id < e->count && response->headers != &e->markers[id]) ++id;
        CHECK(id < e->count && e->out && e->live[id] && !strcmp(e->live[id], e->keys[id]));
        e->live[id] = NULL;
        e->released_ids[http->releases] = id;
        e->release_lengths[http->releases] = e->out->len;
        e->sends_at_release[http->releases] = http->calls;
    } else {
        CHECK(response && !response->headers && e->out);
        e->release_lengths[http->releases] = e->out->len;
        e->sends_at_release[http->releases] = 0;
    }
    test_http_release(user, response);
}

static void check_prior(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && out->items[0].raw.data == prior->raw.data);
    CHECK(out->items[0].verified && out->items[0].detector_type == 777);
    CHECK(out->items[0].raw.len == 5 && !memcmp(out->items[0].raw.data, "prior", 5));
    CHECK(out->items[0].verification_error == prior->verification_error);
    CHECK(!strcmp(out->items[0].verification_error, "caller-owned"));
}

static br_results scan_ok(const br_detector *d, const br_scan_ctx *ctx, const void *data,
                          size_t n, expected *e)
{
    br_results out = {0};
    e->out = &out;
    char *error = NULL;
    int rc = d->scan(d, ctx, true, (br_slice){data, n}, &out, &error);
    if (error) fprintf(stderr, "scan error: %s\n", error);
    CHECK(rc == 0 && !error && !setter_calls);
    return out;
}

static void verification(const br_detector *d)
{
    char input[80];
    int n = snprintf(input, sizeof(input), "nuget %s", key1);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    const char *keys[] = {key1};
    expected e = {.keys = keys, .count = 1};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "nuget-offline"};
    e.ctx = &ctx;
    const struct { int status, rc; const char *body_error; bool verified; } cases[] = {
        {400, 0, NULL, true},
        {400, 0, "", true},
        {400, 0, "synthetic read failure", true},
        {200, 0, NULL, false},
        {201, 0, "read", false},
        {299, 0, "", false},
        {399, 0, NULL, false},
        {401, 0, NULL, false},
        {404, 0, "read", false},
        {0, 0, NULL, false},
        {400, 4, "read", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = setter_calls = 0;
        memset(e.live, 0, sizeof(e.live));
        e.statuses[0] = cases[i].status;
        e.body_errors[0] = cases[i].body_error;
        e.send_rc[0] = cases[i].rc;
        e.send_errors[0] = cases[i].rc ? "synthetic send error" : NULL;
        br_results r = scan_ok(d, &ctx, input, (size_t)n, &e);
        CHECK(r.len == 1 && http.calls == 1 && http.releases == 1 && !e.live[0] && !setter_calls);
        CHECK(e.sends_at_release[0] == 1 && e.released_ids[0] == 0);
        CHECK(e.release_lengths[0] == (cases[i].rc == 0 ? 1u : 0u));
        check_result(&r.items[0], key1, cases[i].verified);
        br_results_clear(&r);
    }
    http.calls = http.releases = setter_calls = 0;
    memset(e.live, 0, sizeof(e.live));
    br_transport no_send = {.user = &http, .release = release_response};
    br_scan_ctx missing = {.transport = &no_send, .user_agent = "nuget-offline"};
    br_results unpublished = scan_ok(d, &missing, input, (size_t)n, &e);
    CHECK(unpublished.len == 1 && !http.calls && http.releases == 1 && !e.live[0] && !setter_calls);
    CHECK(e.release_lengths[0] == 0 && e.sends_at_release[0] == 0);
    check_result(&unpublished.items[0], key1, false);
    br_results_clear(&unpublished);
}

static void order_and_nil(const br_detector *d)
{
    char input[160];
    int n = snprintf(input, sizeof(input), "nuget %s nuget %s", key1, key2);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    const char *keys[] = {key1, key2};
    expected e = {.keys = keys, .count = 2, .statuses = {400, 400}};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "nuget-offline"};
    e.ctx = &ctx;
    setter_calls = 0;
    br_results r = scan_ok(d, &ctx, input, (size_t)n, &e);
    CHECK(r.len == 2 && http.calls == 2 && http.releases == 2 && !setter_calls);
    for (size_t i = 0; i < 2; ++i) {
        CHECK(!e.live[i] && e.released_ids[i] == 1 - i);
        CHECK(e.release_lengths[i] == 2 && e.sends_at_release[i] == 2);
    }
    check_result(&r.items[0], key1, true);
    check_result(&r.items[1], key2, true);
    CHECK(r.items[0].raw.data != r.items[1].raw.data);
    br_results_clear(&r);

    expected mixed_e = {.keys = keys, .count = 2, .statuses = {400, 200}, .send_rc = {5, 0}};
    test_http mixed_http = {.inspect = inspect, .user = &mixed_e};
    br_transport mixed_transport = {&mixed_http, test_http_send, release_response};
    br_scan_ctx mixed_ctx = {.transport = &mixed_transport, .user_agent = "nuget-offline"};
    mixed_e.ctx = &mixed_ctx;
    setter_calls = 0;
    br_results mixed = scan_ok(d, &mixed_ctx, input, (size_t)n, &mixed_e);
    CHECK(mixed.len == 2 && mixed_http.calls == 2 && mixed_http.releases == 2 && !setter_calls);
    CHECK(mixed_e.released_ids[0] == 0 && mixed_e.release_lengths[0] == 0 && mixed_e.sends_at_release[0] == 1);
    CHECK(mixed_e.released_ids[1] == 1 && mixed_e.release_lengths[1] == 2 && mixed_e.sends_at_release[1] == 2);
    check_result(&mixed.items[0], key1, false);
    check_result(&mixed.items[1], key2, false);
    br_results_clear(&mixed);

    char one[80];
    int one_n = snprintf(one, sizeof(one), "nuget %s", key1);
    CHECK(one_n > 0);
    size_t before = sized_allocs;
    br_results quiet = test_scan(d, NULL, false, one, (size_t)one_n);
    size_t baseline = sized_allocs - before;
    CHECK(quiet.len == 1 && baseline);
    br_results_clear(&quiet);

    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error);
    br_results kept = {0};
    CHECK(br_results_push(&kept, &prior) == 0);
    prior = kept.items[0];
    char *error = NULL;
    size_t calls = http.calls, releases = http.releases;
    setter_calls = 0;
    before = sized_allocs;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)one, (size_t)one_n}, &kept, &error) == 0 && !error);
    CHECK(sized_allocs - before == baseline && !setter_calls);
    CHECK(http.calls == calls && http.releases == releases);
    check_prior(&kept, &prior);

    fail_size = key_size;
    fail_after = baseline + 1;
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)one, (size_t)one_n}, &kept, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate NuGetApiKey key"));
    CHECK(http.calls == calls && http.releases == releases && !setter_calls);
    check_prior(&kept, &prior);
    free(error);
    br_results_clear(&kept);
}

static void owned_failures(const br_detector *d)
{
    char input[160];
    int n = snprintf(input, sizeof(input), "nuget %s nuget %s", key1, key2);
    CHECK(n > 0 && (size_t)n < sizeof(input));
    const char *keys[] = {key1, key2};
    expected e = {.keys = keys, .count = 2, .statuses = {400, 400}};
    test_http http = {.inspect = inspect, .user = &e};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "nuget-offline"};
    e.ctx = &ctx;
    br_slice data = {(const unsigned char *)input, (size_t)n};
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error);
    br_results out = {0};
    CHECK(br_results_push(&out, &prior) == 0);
    prior = out.items[0];
    e.out = &out;
    char *error = NULL;
    setter_calls = 0;

    fail_size = key_size; fail_after = 1;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_after);
    CHECK(!strcmp(error, "out of memory copying detector capture"));
    CHECK(!http.calls && !http.releases && !setter_calls && !e.live[0]);
    check_prior(&out, &prior);
    free(error); error = NULL;

    fail_part_after = 2;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_part_after);
    CHECK(!strcmp(error, "cannot create NuGetApiKey result"));
    CHECK(http.calls == 1 && http.releases == 1 && !setter_calls && !e.live[0]);
    CHECK(e.released_ids[0] == 0 && e.release_lengths[0] == 2 && e.sends_at_release[0] == 1);
    check_prior(&out, &prior);
    free(error); error = NULL;
    http.calls = http.releases = 0;
    memset(e.live, 0, sizeof(e.live));

    size_t cap = out.cap;
    out.cap = 2;
    fail_growth = true;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_growth);
    CHECK(!strcmp(error, "cannot append NuGetApiKey result"));
    CHECK(http.calls == 2 && http.releases == 2 && !setter_calls);
    CHECK(e.released_ids[0] == 1 && e.released_ids[1] == 0);
    CHECK(e.release_lengths[0] == 2 && e.release_lengths[1] == 2);
    check_prior(&out, &prior);
    out.cap = cap;
    free(error); error = NULL;
    http.calls = http.releases = 0;
    memset(e.live, 0, sizeof(e.live));

    e.fail_retain = true;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !fail_next_malloc);
    CHECK(!strcmp(error, "cannot retain NuGetApiKey response for release"));
    CHECK(http.calls == 2 && http.releases == 2 && !setter_calls);
    CHECK(e.released_ids[0] == 1 && e.released_ids[1] == 0);
    CHECK(e.release_lengths[0] == 2 && e.release_lengths[1] == 2);
    check_prior(&out, &prior);
    free(error);
    br_results_clear(&out);
}

int main(void)
{
    make_key(key1, 0);
    make_key(key2, 11);
    const br_detector *d = descriptor();
    grammar(d);
    verification(d);
    order_and_nil(d);
    owned_failures(d);
    CHECK(!fail_after && !fail_part_after && !fail_growth && !fail_next_malloc && !setter_calls);
    return test_finish("NuGetApiKey");
}
