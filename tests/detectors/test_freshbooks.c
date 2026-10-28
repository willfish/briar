/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char key[65], other[65]; /* Synthetic lowercase alnum, not merely hex. */
static br_bytes normal_uri, alternate_uri, large_uri;
static const char prefix[] = "https://auth.freshbooks.com/oauth/authorize?client_id=", middle[] = "&redirect_uri=", suffix[] = "&response_type=code";
static const char unsupported[] = "unsupported: Freshbooks embedded NUL in URL fragment";
static size_t fail_size, fail_after, failed_allocations, fail_part_after, fail_duplicate_after, fail_raw_after_release;
static const char *fail_duplicate, *last_url;
static size_t url_size, url_attempts;

/* Real native resource boundaries; no URI formatter/normalization/cap seam. */
void *malloc(size_t size)
{
    bool url = url_size && size == url_size;
    if (url) { ++url_attempts; last_url = NULL; }
    if (fail_after && size == fail_size && --fail_after == 0) { ++failed_allocations; return NULL; }
    void *value = calloc(1, size);
    if (url) last_url = value;
    return value;
}
char *strdup(const char *value)
{
    if (fail_duplicate_after && fail_duplicate && !strcmp(value, fail_duplicate) && --fail_duplicate_after == 0) {
        ++failed_allocations; return NULL;
    }
    size_t size = strlen(value) + 1; char *copy = malloc(size);
    if (copy) memcpy(copy, value, size);
    return copy;
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}
#define TEXT(value) ((br_slice){(const unsigned char *)(value), sizeof(value) - 1})
static br_slice text(const char *value) { return (br_slice){(const unsigned char *)value, strlen(value)}; }
static br_slice view(br_bytes value) { return (br_slice){value.data, value.len}; }
static br_bytes uri(br_slice first, br_slice second, size_t count)
{
    br_bytes value = {.len = 14 + first.len + count + second.len}; value.data = malloc(value.len + 1); CHECK(value.data);
    memcpy(value.data, "https://www", 11); size_t at = 11;
    memcpy(value.data + at, first.data, first.len); at += first.len;
    for (size_t i = 0; i < count; ++i) value.data[at++] = (unsigned char)"MiX9_-"[i % 6];
    memcpy(value.data + at, second.data, second.len); at += second.len;
    memcpy(value.data + at, "com", 4); CHECK(at + 3 == value.len); return value;
}
static br_bytes input_for(const char *candidate, br_slice address)
{
    br_bytes input = {.len = 11 + strlen(candidate) + 12 + address.len + 1}; input.data = malloc(input.len + 1); CHECK(input.data);
    size_t at = 0; memcpy(input.data + at, "freshbooks ", 11); at += 11;
    memcpy(input.data + at, candidate, strlen(candidate)); at += strlen(candidate);
    memcpy(input.data + at, "\nfreshbooks ", 12); at += 12;
    memcpy(input.data + at, address.data, address.len); at += address.len;
    input.data[at++] = '\n'; input.data[at] = '\0'; CHECK(at == input.len); return input;
}
static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(key) == 64 && strlen(other) == 64 && normal_uri.len == 20 && alternate_uri.len == 20);
    CHECK(br_freshbooks_init(NULL, &error) == -1 && error); free(error); error = NULL;
    for (size_t at = 1; at <= 2; ++at) {
        fail_size = sizeof("(?i:freshbooks)(?s:.){0,40}?"); fail_after = at;
        CHECK(br_freshbooks_init(&d, &error) == -1 && !d && error && !fail_after);
        CHECK(!strcmp(error, "cannot allocate detector prefix pattern")); free(error); error = NULL;
    }
    CHECK(br_freshbooks_init(&d, &error) == 0 && d && !error);
    CHECK(br_freshbooks_init(&again, &error) == 0 && again == d && !error);
    CHECK(d->type == 681 && d->version == 0 && !strcmp(d->name, "Freshbooks") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "FreshBooks is an accounting software package developed and marketed by 2ndSite Inc. FreshBooks API keys can be used to access and modify accounting data and perform other operations."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "freshbooks"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void result(const br_result *r, const char *expected, bool verified)
{
    test_key_result(r, 681, expected, "key"); CHECK(r->raw.len == 64 && r->verified == verified && !r->verification_error);
    br_json *part = NULL; CHECK(json_object_object_get_ex(r->secret_parts, "key", &part)); CHECK(json_object_get_string_len(part) == 64);
}
static void extraction(const br_detector *d)
{
    br_bytes input = input_for(key, view(normal_uri)); br_results out = test_scan(d, NULL, false, input.data, input.len); CHECK(out.len == 1);
    result(&out.items[0], key, false); br_results_clear(&out); free(input.data);
    char only[96]; snprintf(only, sizeof(only), "freshbooks %s", key); out = test_scan(d, NULL, false, only, strlen(only)); CHECK(!out.len); br_results_clear(&out);
    input = input_for("", view(normal_uri)); out = test_scan(d, NULL, false, input.data, input.len); CHECK(!out.len); br_results_clear(&out); free(input.data);
    char changed[66]; memcpy(changed, key, sizeof(key)); changed[10] = 'A';
    input = input_for(changed, view(normal_uri)); out = test_scan(d, NULL, false, input.data, input.len); CHECK(!out.len); br_results_clear(&out); free(input.data);
    memcpy(changed, key, sizeof(key)); changed[63] = '\0';
    input = input_for(changed, view(normal_uri)); out = test_scan(d, NULL, false, input.data, input.len); CHECK(!out.len); br_results_clear(&out); free(input.data);
    br_bytes newline_uri = uri(TEXT("\n"), TEXT("."), 4); input = input_for(key, view(newline_uri));
    out = test_scan(d, NULL, false, input.data, input.len); CHECK(!out.len); br_results_clear(&out); free(input.data); free(newline_uri.data);
    input = input_for(key, view(normal_uri)); memcpy(input.data, "FrEsHbOoKs", 10); memcpy(input.data + 76, "FRESHBOOKS", 10);
    out = test_scan(d, NULL, false, input.data, input.len); CHECK(out.len == 1); result(&out.items[0], key, false); br_results_clear(&out); free(input.data);
    input = input_for(key, view(normal_uri)); input.data[87] = 'H'; /* Literal https is not keyword-case-folded. */
    out = test_scan(d, NULL, false, input.data, input.len); CHECK(!out.len); br_results_clear(&out); free(input.data);
}

typedef struct { const char *key; br_slice uri; int status, rc; br_slice body; const char *read_error, *send_error; } reply;
typedef struct { const reply *rows; size_t count, urls; const br_scan_ctx *ctx; bool suffix; const char *borrowed_url; } script;
static void check_url(const char *url, const reply *row)
{
    CHECK(strlen(url) == row->uri.len + 151 && !memcmp(url, prefix, sizeof(prefix) - 1));
    CHECK(!memcmp(url + 54, row->key, 64) && !memcmp(url + 118, middle, sizeof(middle) - 1));
    CHECK(!memcmp(url + 132, row->uri.data, row->uri.len));
    CHECK(!memcmp(url + 132 + row->uri.len, suffix, sizeof(suffix))); /* No encoding, normalization, query repair or truncation. */
}
static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *s = http->user; size_t at = http->calls - 1;
    CHECK(at < s->count && ctx == s->ctx && http->releases == at); const reply *row = &s->rows[at];
    CHECK(request->url == last_url && url_attempts == s->urls + http->calls);
    CHECK(request->detector_type == 681 && request->profile == BR_HTTP_DETECTOR_PUBLIC && request->timeout_ms == 10000);
    CHECK(!strcmp(request->method, "GET")); check_url(request->url, row);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent") && !strcmp(request->headers[0].value, s->suffix ? "TruffleHog freshbooks-offline" : "TruffleHog"));
    s->borrowed_url = request->url;
    http->response = (br_http_response){.status = row->status, .body = row->body, .body_error = row->read_error};
    http->send_rc = row->rc; http->send_error = row->send_error;
}
static void release_response(void *user, br_http_response *response)
{
    test_http *http = user; script *s = http->user; CHECK(s->borrowed_url && s->borrowed_url == last_url);
    check_url(s->borrowed_url, &s->rows[http->calls - 1]); s->borrowed_url = NULL; test_http_release(user, response);
    if (fail_raw_after_release == http->calls) { fail_raw_after_release = 0; fail_size = 64; fail_after = 1; }
}
static br_results run(const br_detector *d, br_slice input, bool verify, script *s, size_t uri_size, size_t allocations)
{
    test_http http = {.inspect = inspect_request, .user = s}; br_transport transport = {&http, test_http_send, release_response};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = s->suffix ? "freshbooks-offline" : NULL}; s->ctx = &ctx;
    url_size = uri_size + 152; s->urls = url_attempts;
    br_results out = test_scan(d, &ctx, verify, input.data, input.len);
    CHECK(http.calls == s->count && http.releases == http.calls && !s->borrowed_url && url_attempts == s->urls + allocations);
    url_size = 0; last_url = NULL; return out;
}
static void verify_one(const br_detector *d, reply row, size_t kept, bool verified)
{
    if (!row.key) row.key = key;
    if (!row.uri.data) row.uri = view(normal_uri);
    br_bytes input = input_for(row.key, row.uri); script s = {.rows = &row, .count = 1};
    br_results out = run(d, view(input), true, &s, row.uri.len, 1); CHECK(out.len == kept);
    if (kept) result(&out.items[0], row.key, verified);
    br_results_clear(&out); free(input.data);
}
static void occurrence_products(const br_detector *d)
{
    unsigned char input[2600]; int n = snprintf((char *)input, sizeof(input), "freshbooks %s\nFRESHBOOKS %s\nfreshbooks %s\n", key, other, key); CHECK(n > 0);
    size_t at = (size_t)n; memset(input + at, ' ', 2048); at += 2048;
    CHECK(snprintf((char *)input + at, sizeof(input) - at, "freshbooks %s\nFrEsHbOoKs %s\nfreshbooks %s", normal_uri.data, alternate_uri.data, normal_uri.data) > 0);
    br_slice data = text((char *)input); const char *keys[] = {key, other, key}; br_slice uris[] = {view(normal_uri), view(alternate_uri), view(normal_uri)};
    script none = {0}; br_results out = run(d, data, false, &none, normal_uri.len, 0); CHECK(out.len == 9);
    for (size_t i = 0; i < 9; ++i) result(&out.items[i], keys[i / 3], false);
    br_results_clear(&out);
    reply rows[9]; for (size_t i = 0; i < 9; ++i) rows[i] = (reply){.key = keys[i / 3], .uri = uris[i % 3], .status = 200, .body = TEXT("\0\xff{ Log In to FreshBooks ")};
    rows[1].status = 401; rows[1].read_error = ""; rows[2].status = 201;
    rows[3].rc = 1; rows[3].send_error = "cannot allocate Freshbooks URL"; rows[3].read_error = "";
    rows[4].body = TEXT("no marker"); rows[5].status = 500; rows[7].status = 299;
    script s = {.rows = rows, .count = 9, .suffix = true}; out = run(d, data, true, &s, normal_uri.len, 9); CHECK(out.len == 8);
    const size_t order[] = {0, 2, 3, 4, 5, 6, 7, 8};
    for (size_t i = 0; i < 8; ++i) result(&out.items[i], rows[order[i]].key, order[i] != 3 && order[i] != 4 && order[i] != 5);
    br_results_clear(&out);
}
static void constructor_guards(const br_detector *d)
{
    const br_slice first[] = {TEXT("\0"), TEXT("."), TEXT("\x7f"), TEXT("#")};
    const br_slice second[] = {TEXT("."), TEXT("\r"), TEXT("."), TEXT("%")};
    for (size_t i = 0; i < 4; ++i) {
        br_bytes address = uri(first[i], second[i], 4), input = input_for(key, view(address)); script none = {0};
        url_size = address.len + 152; fail_size = url_size; fail_after = 1; size_t before = url_attempts;
        br_results out = test_scan(d, NULL, false, input.data, input.len); CHECK(out.len == 1 && fail_after == 1 && url_attempts == before);
        fail_after = 0; url_size = 0; result(&out.items[0], key, false); br_results_clear(&out);
        out = run(d, view(input), true, &none, address.len, 1); CHECK(!out.len); br_results_clear(&out);
        free(input.data); free(address.data);
    }
    const br_slice accepted_first[] = {TEXT("%"), TEXT(" "), TEXT("\xe2\x98\x83"), TEXT("#")};
    const br_slice accepted_second[] = {TEXT("."), TEXT("."), TEXT("."), TEXT("\r")};
    for (size_t i = 0; i < 4; ++i) {
        br_bytes address = uri(accepted_first[i], accepted_second[i], 4);
        verify_one(d, (reply){.uri = view(address), .status = 200, .body = TEXT("Log In to FreshBooks")}, 1, true); free(address.data);
    }
    br_bytes address = uri(TEXT("#"), TEXT("\0"), 4), input = input_for(key, view(address));
    url_size = address.len + 152; fail_size = url_size; fail_after = 1; size_t before = url_attempts;
    br_results out = test_scan(d, NULL, false, input.data, input.len); CHECK(out.len == 1 && fail_after == 1 && url_attempts == before); br_results_clear(&out); fail_after = 0;
    out = test_scan(d, NULL, true, input.data, input.len); CHECK(!out.len && url_attempts == before + 1); br_results_clear(&out); /* nil ctx PRECEDES unsupported fragment NUL. */
    url_size = 0; last_url = NULL; free(input.data); free(address.data);
    verify_one(d, (reply){.uri = view(large_uri), .status = 200, .body = TEXT("Log In to FreshBooks")}, 1, true); /* Unbounded URI middle, no 1024 local cap. */
}
static void read_and_send_contracts(const br_detector *d)
{
    const int statuses[] = {200, 201, 204, 299, 401, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i)
        verify_one(d, (reply){.status = statuses[i], .body = TEXT("\0\xff{{Log In to FreshBooks\0after")}, 1, statuses[i] >= 200 && statuses[i] < 300);
    verify_one(d, (reply){.status = 200, .body = TEXT("log In to FreshBooks")}, 1, false);
    verify_one(d, (reply){.status = 200, .body = TEXT("Log In to Fresh Books")}, 1, false);
    const int reads[] = {200, 401, 500};
    for (size_t i = 0; i < 3; ++i)
        verify_one(d, (reply){.status = reads[i], .body = TEXT("Log In to FreshBooks"), .read_error = i == 1 ? "" : "synthetic read error"}, 0, false);
    const char *causes[] = {"cannot allocate Freshbooks URL", "out of memory constructing HTTP headers", "", NULL};
    for (size_t i = 0; i < 4; ++i)
        verify_one(d, (reply){.status = 200, .body = TEXT("Log In to FreshBooks"), .read_error = "", .rc = i % 2 ? -7 : 1, .send_error = causes[i]}, 1, false);
}
static bool fail_headers(void *user) { (void)user; fail_size = sizeof(br_header); fail_after = 1; return false; }
static void shared_send_domain(const br_detector *d)
{
    br_bytes input = input_for(key, view(normal_uri));
    for (int mode = 0; mode < 2; ++mode) {
        test_http http = {0}; br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode ? &transport : NULL, .cancelled = mode ? fail_headers : NULL};
        size_t before = failed_allocations, urls = url_attempts; url_size = normal_uri.len + 152;
        br_results out = test_scan(d, &ctx, true, input.data, input.len);
        CHECK(out.len == 1 && !http.calls && http.releases == (size_t)mode && url_attempts == urls + 1);
        CHECK(!fail_after && failed_allocations == before + (size_t)mode); result(&out.items[0], key, false); br_results_clear(&out);
        url_size = 0; last_url = NULL;
    }
    free(input.data);
}
static void prior_result(br_results *out)
{
    br_result prior = {0}; CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true; prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error && br_results_push(out, &prior) == 0);
}
static void check_prior(const br_results *out, const br_result *prior)
{
    CHECK(out->len == 1 && out->items[0].detector_type == 777 && out->items[0].verified);
    CHECK(out->items[0].raw.data == prior->raw.data && out->items[0].raw.len == 5 && !memcmp(out->items[0].raw.data, "prior", 5));
    CHECK(out->items[0].secret_parts == prior->secret_parts && out->items[0].verification_error == prior->verification_error && !strcmp(prior->verification_error, "caller-owned"));
}
static void resource_failures(const br_detector *d)
{
    char input[320]; snprintf(input, sizeof(input), "freshbooks %s\nfreshbooks %s\nfreshbooks %s", key, normal_uri.data, alternate_uri.data); br_slice data = text(input);
    reply rows[] = {{.key = key, .uri = view(normal_uri), .status = 200, .body = TEXT("Log In to FreshBooks")},
        {.key = key, .uri = view(alternate_uri), .status = 200, .rc = 1, .read_error = "", .send_error = "out of memory in Do"},
        {.key = key, .uri = view(normal_uri), .status = 200}};
    script s = {.rows = rows, .count = 3}; test_http http = {.inspect = inspect_request, .user = &s};
    br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport}; s.ctx = &ctx;
    br_results out = {0}; prior_result(&out); br_result saved = out.items[0]; char *error = NULL; url_size = normal_uri.len + 152;
    for (int failure = 0; failure < 6; ++failure) {
        s.urls = url_attempts;
        if (failure == 0) { fail_size = 2 * sizeof(br_span); fail_after = 2; } /* +1 scratch failure in URI's independent search. */
        if (failure == 1) { fail_size = 65; fail_after = 1; }
        if (failure == 2) { fail_size = normal_uri.len + 1; fail_after = 2; }
        if (failure == 3) fail_raw_after_release = 1;
        if (failure == 4) fail_part_after = 2;
        if (failure == 5) { fail_size = url_size; fail_after = 2; }
        CHECK(d->scan(d, &ctx, failure != 0, data, &out, &error) == -1);
        const char *message = failure == 0 ? "out of memory iterating regex" : failure <= 2 ? "out of memory copying detector capture" : failure == 5 ? "cannot allocate Freshbooks URL" : "cannot create Freshbooks result";
        CHECK(error && !strcmp(error, message) && !fail_after && !fail_part_after && !fail_raw_after_release);
        CHECK(http.calls == (failure >= 3 ? 1u : 0u) && http.releases == http.calls && !s.borrowed_url);
        CHECK(url_attempts == s.urls + (failure == 5 ? 2u : failure >= 3 ? 1u : 0u));
        check_prior(&out, &saved); free(error); error = NULL; http.calls = http.releases = 0;
    }
    /* Finding resources precede nil-context URL preparation/skip, too. */
    s.urls = url_attempts; fail_part_after = 2;
    CHECK(d->scan(d, NULL, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot create Freshbooks result") && !fail_part_after);
    CHECK(url_attempts == s.urls + 1); check_prior(&out, &saved); free(error); error = NULL;
    /* URL allocation outranks BOTH nil context and a known malformed query. */
    br_bytes bad = uri(TEXT("\0"), TEXT("."), 4), bad_input = input_for(key, view(bad));
    for (int nil_ctx = 0; nil_ctx < 2; ++nil_ctx) {
        s.urls = url_attempts; fail_size = url_size; fail_after = 1;
        CHECK(d->scan(d, nil_ctx ? NULL : &ctx, true, view(bad_input), &out, &error) == -1 && error && !strcmp(error, "cannot allocate Freshbooks URL") && !fail_after);
        CHECK(url_attempts == s.urls + 1 && !http.calls && !http.releases); check_prior(&out, &saved); free(error); error = NULL;
    }
    free(bad_input.data); free(bad.data);
    br_bytes fragment = uri(TEXT("#"), TEXT("\0"), 4);
    /* Replace URI two with fragment-NUL, after one kept result. */
    int n = snprintf(input, sizeof(input), "freshbooks %s\nfreshbooks %s\nfreshbooks ", key, normal_uri.data); CHECK(n > 0);
    memcpy(input + n, fragment.data, fragment.len); data = (br_slice){(const unsigned char *)input, (size_t)n + fragment.len};
    for (int oom_cause = 0; oom_cause < 2; ++oom_cause) {
        s.urls = url_attempts; if (oom_cause) { fail_duplicate = unsupported; fail_duplicate_after = 1; }
        CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1);
        CHECK(oom_cause ? !error && !fail_duplicate_after : error && !strcmp(error, unsupported));
        CHECK(http.calls == 1 && http.releases == 1 && url_attempts == s.urls + 2); check_prior(&out, &saved);
        free(error); error = NULL; http.calls = http.releases = 0;
    }
    free(fragment.data);
    /* A read DROP cannot swallow a later owned failure or preserve earlier new findings. */
    snprintf(input, sizeof(input), "freshbooks %s\nfreshbooks %s\nfreshbooks %s\nfreshbooks %s", key, normal_uri.data, alternate_uri.data, normal_uri.data); data = text(input);
    rows[1].rc = 0; rows[1].send_error = NULL; rows[1].read_error = ""; fail_raw_after_release = 2; s.urls = url_attempts;
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot create Freshbooks result") && !fail_after && !fail_raw_after_release);
    CHECK(http.calls == 2 && http.releases == 2 && url_attempts == s.urls + 2); check_prior(&out, &saved); free(error); error = NULL; http.calls = http.releases = 0;
    size_t cap = out.cap; out.cap = 0; s.urls = url_attempts; /* Actual +1 append guard. */
    CHECK(d->scan(d, &ctx, true, data, &out, &error) == -1 && error && !strcmp(error, "cannot append Freshbooks result"));
    out.cap = cap; CHECK(http.calls == 1 && http.releases == 1 && url_attempts == s.urls + 1); check_prior(&out, &saved);
    free(error); br_results_clear(&out); url_size = 0; last_url = NULL;
}

int main(void)
{
    test_secret(key, 64, 0); test_secret(other, 64, 11); key[0] = 'g'; other[13] = 'z';
    normal_uri = uri(TEXT("."), TEXT("."), 4); alternate_uri = uri(TEXT("/"), TEXT("."), 4); large_uri = uri(TEXT("."), TEXT("."), 65537);
    const br_detector *d = descriptor();
    extraction(d); occurrence_products(d); constructor_guards(d); read_and_send_contracts(d); shared_send_domain(d); resource_failures(d);
    CHECK(!fail_after && !fail_part_after && !fail_duplicate_after && !fail_raw_after_release && !url_size);
    free(normal_uri.data); free(alternate_uri.data); free(large_uri.data); return test_finish("Freshbooks");
}
