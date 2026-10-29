/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#define KEY_A "Ab3=Ef5+Gh7/Jk9=Lm2+Np4/Qr6=St8+Uv0/Wx1=Yz3+"
#define KEY_B "9zY8xW7vU6tS5rQ4pO3nM2lK1jI0hG9fE8dC7bA6=Z5+"
#define WORD44 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
#define EQUAL44 "============================================"
#define PLUS44 "++++++++++++++++++++++++++++++++++++++++++++"
#define SLASH44 "////////////////////////////////////////////"

static size_t fail_size, fail_after, failed_allocations, fail_part_after;
static bool fail_agent;
static const char *borrowed_key, *borrowed_url, *expected_key;

/* Exercise existing native allocation/JSON boundaries, not replacement helpers. */
void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++failed_allocations; return NULL; }
    return calloc(1, size);
}
char *strdup(const char *s)
{
    if (fail_agent && !strcmp(s, "TruffleHog")) { fail_agent = false; ++failed_allocations; return NULL; }
    size_t n = strlen(s) + 1; char *copy = malloc(n); if (copy) memcpy(copy, s, n); return copy;
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) return 7;
    return json_object_object_add_ex(object, name, value, 0);
}

static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(KEY_A) == 44 && strlen(KEY_B) == 44);
    CHECK(strlen(WORD44) == 44 && strlen(EQUAL44) == 44 && strlen(PLUS44) == 44 && strlen(SLASH44) == 44);
    CHECK(br_instabot_init(NULL, &error) != 0 && error); free(error); error = NULL;
    CHECK(br_instabot_init(NULL, NULL) != 0);
    fail_size = sizeof("(?i:instabot)(?s:.){0,40}?"); fail_after = 1;
    CHECK(br_instabot_init(&d, &error) != 0 && !d && error && !fail_after);
    CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    CHECK(br_instabot_init(&d, &error) == 0 && d && !error);
    CHECK(br_instabot_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 856 && d->version == 0 && !strcmp(d->name, "Instabot") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Instabot is a service that provides automated social media interactions. Instabot API keys can be used to access and interact with the service programmatically."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "instabot"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void result(const br_result *r, const char *key, bool verified)
{
    test_key_result(r, 856, key, "key");
    CHECK(r->raw.len == 44 && r->verified == verified && !r->verification_error);
    br_json *part = NULL; CHECK(json_object_object_get_ex(r->secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 44);
}
static void extract(const br_detector *d, const void *input, size_t len, const char *key)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(d, &ctx, false, input, len);
    CHECK(out.len == (key ? 1u : 0u) && !http.calls && !http.releases);
    if (key) result(&out.items[0], key, false);
    br_results_clear(&out);
}
static void extraction(const br_detector *d)
{
    const struct { const char *input, *key; } cases[] = {
        {"iNsTaBoT " KEY_A, KEY_A}, {"prefixINSTABOTsuffix::" KEY_B, KEY_B},
        {"instabot\r\n" KEY_A, KEY_A}, {"instabot \t" KEY_A "\r\n", KEY_A},
        {"instabot -" KEY_A, KEY_A}, {"instabot _" KEY_A, NULL},
        {"instabot " KEY_A "more", KEY_A}, {"instabot " WORD44 "_a", WORD44},
        {"instabot " WORD44 "A", WORD44}, {"instabot " KEY_A " " KEY_B, KEY_A},
        {"instabot " EQUAL44, NULL}, {"instabot" EQUAL44, EQUAL44},
        {"instabot" PLUS44, PLUS44}, {"instabot" SLASH44, SLASH44},
        {"instabot " WORD44, WORD44}, {KEY_A, NULL}, {KEY_A " instabot", NULL},
        {"instab0t " KEY_A, NULL},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
        extract(d, cases[i].input, strlen(cases[i].input), cases[i].key);
    char input[250], changed[45];
    memcpy(changed, KEY_A, sizeof(changed)); changed[43] = '\0';
    int n = snprintf(input, sizeof(input), "instabot %s", changed); CHECK(n > 0);
    extract(d, input, (size_t)n, NULL);
    memcpy(changed, KEY_A, sizeof(changed)); changed[20] = '-';
    n = snprintf(input, sizeof(input), "instabot %s", changed); CHECK(n > 0);
    extract(d, input, (size_t)n, NULL);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "instabot", 8); memset(input + 8, ':', gap); memcpy(input + 8 + gap, KEY_A, 44);
        extract(d, input, 8 + gap + 44, gap == 40 ? KEY_A : NULL);
        input[9] = '\r'; input[10] = '\n'; input[11] = '\0';
        extract(d, input, 8 + gap + 44, gap == 40 ? KEY_A : NULL);
        memcpy(input, "instabot", 8);
        for (size_t i = 0; i < gap; ++i) memcpy(input + 8 + 4 * i, "💡", 4);
        memcpy(input + 8 + 4 * gap, KEY_A, 44);
        extract(d, input, 8 + 4 * gap + 44, gap == 40 ? KEY_A : NULL);
    }
    extract(d, NULL, 0, NULL);
}

typedef struct { const char *const *keys; size_t count; const br_scan_ctx *ctx; const char *agent; } expected;
static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected *e = http->user; size_t at = http->calls - 1;
    CHECK(at < e->count && ctx == e->ctx && http->releases == at && !borrowed_key);
    CHECK(request->detector_type == 856 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.instabot.io/v1"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "X-Instabot-Api-Key"));
    expected_key = e->keys[at]; CHECK(!strcmp(request->headers[0].value, expected_key));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, e->agent));
    /* Retain provider originals only, never effective request/header-array/UA. */
    borrowed_key = request->headers[0].value; borrowed_url = request->url;
}
static void release_response(void *user, br_http_response *response)
{
    if (borrowed_key) {
        CHECK(!strcmp(borrowed_key, expected_key));
        CHECK(!strcmp(borrowed_url, "https://api.instabot.io/v1"));
    } else CHECK(!response->status && !response->body.data && !response->body.len && !response->body_error);
    borrowed_key = borrowed_url = expected_key = NULL;
    test_http_release(user, response);
}
static void occurrences_and_requests(const br_detector *d)
{
    const char input[] = "instabot " KEY_A "\ninstabot " KEY_B "\ninstabot " KEY_A;
    const char *sequence[] = {KEY_A, KEY_B, KEY_A};
    expected e = {.keys = sequence, .count = 3, .agent = "TruffleHog instabot-offline"};
    test_http http = {.inspect = inspect_request, .user = &e, .response = {.status = 204, .body_error = "ignored"}};
    br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "instabot-offline"}; e.ctx = &ctx;
    for (size_t pass = 0; pass < 2; ++pass) {
        br_results out = test_scan(d, &ctx, pass != 0, input, sizeof(input) - 1);
        CHECK(out.len == 3 && http.calls == (pass ? 3u : 0u) && http.releases == http.calls);
        for (size_t i = 0; i < 3; ++i) result(&out.items[i], sequence[i], pass != 0);
        CHECK(out.items[0].raw.data != out.items[2].raw.data && out.items[0].secret_parts != out.items[2].secret_parts);
        br_results_clear(&out);
    }
    const char *contextual[] = {EQUAL44, PLUS44, SLASH44};
    e.count = 1; e.keys = contextual;
    for (size_t i = 0; i < 3; ++i) {
        char input_context[60]; int n = snprintf(input_context, sizeof(input_context), "instabot%s", contextual[i]); CHECK(n > 0);
        e.keys = contextual + i; http.calls = http.releases = 0;
        br_results out = test_scan(d, &ctx, true, input_context, (size_t)n);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1); result(&out.items[0], contextual[i], true); br_results_clear(&out);
    }
    br_results out = test_scan(d, NULL, true, input, sizeof(input) - 1); CHECK(!out.len); br_results_clear(&out);
    out = test_scan(d, NULL, false, input, sizeof(input) - 1); CHECK(out.len == 3);
    for (size_t i = 0; i < 3; ++i) result(&out.items[i], sequence[i], false);
    br_results_clear(&out);
}
static bool arm_headers(void *user) { (void)user; fail_size = 2 * sizeof(br_header); fail_after = 1; return false; }
static bool arm_agent(void *user) { (void)user; fail_agent = true; return false; }
static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static void verification_outcomes(const br_detector *d)
{
    const char input[] = "instabot " KEY_A; const char *keys[] = {KEY_A};
    expected e = {.keys = keys, .count = 1, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &e};
    br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport}; e.ctx = &ctx;
    const int statuses[] = {0, 199, 200, 201, 204, 206, 299, 300, 401, 403, 429, 500};
    static const unsigned char body[] = {0, 0xff, '{'};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        http.calls = http.releases = 0;
        http.response = (br_http_response){.status = statuses[i], .body = {body, sizeof(body)}, .body_error = i % 2 ? "ignored" : ""};
        br_results out = test_scan(d, &ctx, true, input, sizeof(input) - 1);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1);
        result(&out.items[0], KEY_A, statuses[i] >= 200 && statuses[i] < 300); br_results_clear(&out);
    }
    const struct { int rc; const char *cause; } failures[] = {
        {1, "timeout"}, {-7, "cannot create Instabot result"}, {1, "out of memory constructing HTTP headers"},
        {-1, NULL}, {7, KEY_A}, {1, ""},
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        http.calls = http.releases = 0; http.send_rc = failures[i].rc; http.send_error = failures[i].cause;
        http.response = i == 3 ? (br_http_response){0} : (br_http_response){.status = 200, .body_error = "ignored"};
        br_results out = test_scan(d, &ctx, true, input, sizeof(input) - 1);
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1); result(&out.items[0], KEY_A, false); br_results_clear(&out);
    }
    size_t cancellations = 0; br_transport no_send = {&http, NULL, release_response};
    br_scan_ctx contexts[] = {
        {0}, {.transport = &no_send}, {.transport = &transport, .cancelled = arm_headers},
        {.transport = &transport, .cancelled = arm_agent},
        {.transport = &transport, .cancelled = cancelled, .cancel_user = &cancellations},
        {.transport = &transport, .deadline_monotonic_ms = 1}, {.transport = &transport, .user_agent = "bad\r\nagent"},
    };
    for (size_t i = 0; i < sizeof(contexts) / sizeof(contexts[0]); ++i) {
        size_t before = failed_allocations; http.calls = http.releases = 0;
        br_results out = test_scan(d, &contexts[i], true, input, sizeof(input) - 1);
        CHECK(out.len == 1 && !http.calls && http.releases == (i ? 1u : 0u));
        CHECK(!fail_after && !fail_agent && failed_allocations == before + (i == 2 || i == 3 ? 1u : 0u));
        result(&out.items[0], KEY_A, false); br_results_clear(&out);
    }
    CHECK(cancellations == 1);
}
static void check_prior(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && !memcmp(&out->items[0], prior, sizeof(*prior)));
    CHECK(prior->raw.len == 5 && !memcmp(prior->raw.data, "prior", 5) && !strcmp(prior->verification_error, "caller-owned"));
}
static void owned_failures_and_rollback(const br_detector *d)
{
    const char input[] = "instabot " KEY_A "\ninstabot " KEY_B; const char *keys[] = {KEY_A, KEY_B};
    expected e = {.keys = keys, .count = 2, .agent = "TruffleHog"};
    test_http http = {.inspect = inspect_request, .user = &e, .send_rc = -7, .send_error = "synthetic Do failure"};
    br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport}; e.ctx = &ctx;
    br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results out = {0}; CHECK(br_results_push(&out, &prior) == 0); prior = out.items[0]; char *error = NULL;
    for (size_t failure = 0; failure < 3; ++failure) {
        if (failure == 0) { fail_size = 45; fail_after = 2; } /* Collect all captures before verification. */
        if (failure == 1) { fail_size = 44; fail_after = 2; } /* Second finding after first suppressed Do. */
        if (failure == 2) fail_part_after = 2; /* Positive JSON insertion failure. */
        CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)input, sizeof(input) - 1}, &out, &error) != 0 && error);
        CHECK(!fail_after && !fail_part_after && http.calls == (failure ? 1u : 0u) && http.releases == http.calls && !borrowed_key);
        check_prior(&out, &prior); free(error); error = NULL; http.calls = http.releases = 0;
    }
    /* Owned finding failure must precede the nil-constructor ordinary drop. */
    fail_size = 44; fail_after = 1;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, sizeof(input) - 1}, &out, &error) != 0 && error && !fail_after);
    check_prior(&out, &prior); free(error); error = NULL;
    fail_part_after = 1;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, sizeof(input) - 1}, &out, NULL) != 0 && !fail_part_after);
    check_prior(&out, &prior);
    /* Shared push's positive failure is fatal after both success and suppressed Do. */
    for (size_t pass = 0; pass < 2; ++pass) {
        http.send_rc = pass ? 7 : 0; http.send_error = pass ? "cannot create Instabot result" : NULL;
        http.response = (br_http_response){.status = 200}; size_t cap = out.cap; out.cap = 0;
        CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)input, sizeof(input) - 1}, &out, &error) != 0 && error && !strcmp(error, "cannot append Instabot result"));
        out.cap = cap; CHECK(http.calls == 1 && http.releases == 1); check_prior(&out, &prior);
        free(error); error = NULL; http.calls = http.releases = 0;
    }
    br_results_clear(&out);
}
int main(void)
{
    const br_detector *d = descriptor(); extraction(d); occurrences_and_requests(d);
    verification_outcomes(d); owned_failures_and_rollback(d);
    CHECK(!fail_after && !fail_part_after && !fail_agent && !borrowed_key && !borrowed_url && !expected_key);
    return test_finish("Instabot");
}
