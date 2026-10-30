/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

extern int br_paperform_init(const br_detector **out, char **error);

static const char sample[] =
    "NvBbE5vYVPhidc-tiZ7E6DvP.z4bAQj29KEZOCv_XEl1pIn.Y1q8JoeGNoSelGj.db1iQpLM0fsype86LD.Vk.p6yweF5A2MlfxXDrEd7nz2SBExnTpp4QRN94pBAeulPLLtzqTz--y_UuF1g6cjE_.kuW_u5He0QkBdLMkyAgSx94N3Csj9LY37XOmUp9IIi9LXpTvZGa8oywp6JuMfhzwg5OCEvdp9mx.UyfQcnnJtYzzP5dItmwfEC-KJIvjvS8LF2NU2w2japQHtnAJqBAn3_EP-FN78wHnDEWANANT0cfor6kDqyKraO0Y-26PdB6xBjm3_VpU.8hnKIyoKdLQ6S.HZwr5rx0Bx76zXTCBv4uEzhtDFcDqVPN8ZG_kE90P..ldReG0jU4w3YA2jbaOgi6i-8llYWGoCiFFBm3Od-zLOEDYL2BlGsUFRUkiEMjytCVDqcIOdfPT7GQcd3wdmort6FFv8SbCu95f2gBCcM.5.ZmMxIOybubMGmiRunYM8-pSaVvXfBQSkM2Eygh15tkKCDHf8X3InAkPh7HQn13mP5y1gFRLsVAUWb-91PeHASP6hluUEdsX3uLQ9OJFenKrk.0zS9Goy08bfttd4h4Jtb2JV8vbJ8-3Wb4AJWqf0eUALMxOChB3sSBKW37s4vDb1NKOnoqOeoYQUBijqRGu9YLKIAimwo7Uvl0CuD7bWNrERweBqNVWjfGhlE8Yvvklm5YhCk5XY02pOa3IjMf_TDKhbTr8bh_20SXevnDk80XKg_3mWbhuieL23kx835AokAg9JpEkgydBBqo8nzQg23R5xJzKRT64kgb5GBlzuM9Oxh7pXsmzlYf";
static const char questioned[] =
    "NvBbE5vYVPhidc?tiZ7E6DvP.z4bAQj29KEZOCv_XEl1pIn.Y1q8JoeGNoSelGj.db1iQpLM0fsype86LD.Vk.p6yweF5A2MlfxXDrEd7nz2SBExnTpp4QRN94pBAeulPLLtzqTz--y_UuF1g6cjE_.kuW_u5He0QkBdLMkyAgSx94N3Csj9LY37XOmUp9IIi9LXpTvZGa8oywp6JuMfhzwg5OCEvdp9mx.UyfQcnnJtYzzP5dItmwfEC-KJIvjvS8LF2NU2w2japQHtnAJqBAn3_EP-FN78wHnDEWANANT0cfor6kDqyKraO0Y-26PdB6xBjm3_VpU.8hnKIyoKdLQ6S.HZwr5rx0Bx76zXTCBv4uEzhtDFcDqVPN8ZG_kE90P..ldReG0jU4w3YA2jbaOgi6i-8llYWGoCiFFBm3Od-zLOEDYL2BlGsUFRUkiEMjytCVDqcIOdfPT7GQcd3wdmort6FFv8SbCu95f2gBCcM.5.ZmMxIOybubMGmiRunYM8-pSaVvXfBQSkM2Eygh15tkKCDHf8X3InAkPh7HQn13mP5y1gFRLsVAUWb-91PeHASP6hluUEdsX3uLQ9OJFenKrk.0zS9Goy08bfttd4h4Jtb2JV8vbJ8-3Wb4AJWqf0eUALMxOChB3sSBKW37s4vDb1NKOnoqOeoYQUBijqRGu9YLKIAimwo7Uvl0CuD7bWNrERweBqNVWjfGhlE8Yvvklm5YhCk5XY02pOa3IjMf_TDKhbTr8bh_20SXevnDk80XKg_3mWbhuieL23kx835AokAg9JpEkgydBBqo8nzQg23R5xJzKRT64kgb5GBlzuM9Oxh7pXsmzlYf";
static size_t fail_size, fail_after, fail_part_after;

void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) return NULL;
    return calloc(1, size);
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static char *fill_key(size_t n)
{
    char *key = malloc(n + 1);
    CHECK(key);
    memset(key, 'a', n);
    if (n >= 4) {
        key[1] = '-';
        key[2] = '.';
        key[3] = '_';
    }
    key[n] = '\0';
    return key;
}

static char *join3(const char *a, const char *b, const char *c, size_t *len)
{
    size_t na = strlen(a), nb = strlen(b), nc = c ? strlen(c) : 0;
    char *out = malloc(na + nb + nc + 1);
    CHECK(out);
    memcpy(out, a, na);
    memcpy(out + na, b, nb);
    if (nc) memcpy(out + na + nb, c, nc);
    out[na + nb + nc] = '\0';
    if (len) *len = na + nb + nc;
    return out;
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1 && strlen(sample) == 850 && strlen(questioned) == 850);
    CHECK(strchr(sample, '-') && strchr(sample, '.') && strchr(sample, '_') && !strchr(sample, '?'));
    CHECK(br_paperform_init(NULL, &error) == -1 && error);
    CHECK(!strcmp(error, "invalid Paperform detector output"));
    free(error); error = NULL;
    CHECK(br_paperform_init(NULL, NULL) == -1);
    CHECK(br_paperform_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_paperform_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 791 && detector->version == 0 && !strcmp(detector->name, "Paperform"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "An API for building and creating forms. API keys could be used to read proprietary or not public form data"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "paperform"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 791, expected, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

static void extraction_case(const br_detector *detector, const void *input, size_t len,
                            const char *const *expected, size_t count)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, false, input, len);
    CHECK(out.len == count && !http.calls && !http.releases);
    for (size_t i = 0; i < count; ++i) check_result(&out.items[i], expected[i], false);
    br_results_clear(&out);
    out = test_scan(detector, NULL, false, input, len);
    CHECK(out.len == count);
    for (size_t i = 0; i < count; ++i) check_result(&out.items[i], expected[i], false);
    br_results_clear(&out);
}

static void extraction(const br_detector *detector)
{
    const char *one[] = {sample}, *same[] = {sample, sample};
    const char *prefixes[] = {"paperform token = '", "PAPERFORM=", "prepaperformsuffix:", "paperform\r\n"};
    const char *tails[] = {"'", "", "", ""};
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); ++i) {
        size_t len = 0;
        char *input = join3(prefixes[i], sample, tails[i], &len);
        extraction_case(detector, input, len, one, 1);
        free(input);
    }
    for (int gap = 40; gap <= 41; ++gap) {
        char spaces[42];
        memset(spaces, ' ', (size_t)gap);
        spaces[gap] = '\0';
        size_t len = 0;
        char *input = join3("paperform", spaces, sample, &len);
        extraction_case(detector, input, len, gap == 40 ? one : NULL, gap == 40 ? 1u : 0u);
        free(input);
    }
    const size_t lengths[] = {849, 850, 1000, 1001};
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
        /* Hyphen and dot are non-word, so an over-long token can still bound a shorter match. */
        char *key = fill_key(lengths[i]);
        if (lengths[i] == 849 || lengths[i] == 1001) memset(key, 'a', lengths[i]);
        size_t len = 0;
        char *input = join3("paperform ", key, NULL, &len);
        int matches = lengths[i] == 850 || lengths[i] == 1000;
        const char *expected[] = {key};
        extraction_case(detector, input, len, matches ? expected : NULL, matches ? 1u : 0u);
        free(input);
        free(key);
    }
    size_t len = 0;
    char *input = join3("paperform = '", questioned, "'", &len);
    extraction_case(detector, input, len, NULL, 0);
    free(input);
    /* One paperform prefix is consumed. This is not a uniqueness filter. */
    input = join3("paperform token = '", sample, "' | '", &len);
    char *dup = join3(input, sample, "'", &len);
    free(input);
    extraction_case(detector, dup, len, one, 1);
    free(dup);
    input = join3("paperform ", sample, " paperform ", &len);
    dup = join3(input, sample, NULL, &len);
    free(input);
    extraction_case(detector, dup, len, same, 2);
    free(dup);
    input = join3("paperform keyword is not close to the real key in the data\n = '", sample, "'", &len);
    extraction_case(detector, input, len, NULL, 0);
    free(input);
    extraction_case(detector, "", 0, NULL, 0);
    extraction_case(detector, NULL, 0, NULL, 0);
}

typedef struct { const char *key; int status, send_rc; const char *send_error, *body_error; } reply;
typedef struct { const reply *rows; size_t count; const br_scan_ctx *ctx; } script;

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user;
    size_t at = http->calls - 1;
    CHECK(at < steps->count && ctx == steps->ctx && http->releases == at);
    const reply *row = &steps->rows[at];
    size_t key_len = strlen(row->key);
    CHECK(request->detector_type == 791 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.paperform.co/v1/forms"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    CHECK(strlen(request->headers[0].value) == 7 + key_len);
    CHECK(!memcmp(request->headers[0].value, "Bearer ", 7));
    CHECK(!memcmp(request->headers[0].value + 7, row->key, key_len));
    CHECK(strncmp(request->headers[0].value, "Token ", 6) != 0);
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog"));
    static const unsigned char junk[] = {0, 0xff, 'n', 'o', 't', ' ', 'J', 'S', 'O', 'N'};
    http->response = (br_http_response){.status = row->status, .body = {junk, sizeof(junk)},
        .body_error = row->body_error};
    http->send_rc = row->send_rc;
    http->send_error = row->send_error;
}

static br_results run(const br_detector *detector, const void *input, size_t len, script *steps)
{
    test_http http = {.inspect = inspect_request, .user = steps};
    br_transport transport = {&http, test_http_send, test_http_release};
    br_scan_ctx ctx = {.transport = &transport};
    steps->ctx = &ctx;
    br_results out = test_scan(detector, &ctx, true, input, len);
    CHECK(http.calls == steps->count && http.releases == http.calls);
    return out;
}

static void verification(const br_detector *detector)
{
    size_t one_len = 0, both_len = 0, long_len = 0;
    char *one = join3("paperform ", sample, NULL, &one_len);
    char *mid = join3("paperform ", sample, " paperform ", &both_len);
    char *both = join3(mid, sample, NULL, &both_len);
    free(mid);
    char *long_key = fill_key(1000);
    char *long_input = join3("paperform ", long_key, NULL, &long_len);
    const int statuses[] = {199, 200, 201, 204, 299, 300, 401, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        reply row = {.key = sample, .status = statuses[i], .body_error = i % 2 ? "synthetic read failure" : ""};
        script steps = {.rows = &row, .count = 1};
        br_results out = run(detector, one, one_len, &steps);
        CHECK(out.len == 1);
        check_result(&out.items[0], sample, statuses[i] >= 200 && statuses[i] < 300);
        br_results_clear(&out);
    }
    const reply rows[] = {
        {sample, 200, 0, NULL, "ignored"},
        {sample, 401, 0, NULL, "synthetic read failure"},
    };
    script steps = {.rows = rows, .count = 2};
    br_results out = run(detector, both, both_len, &steps);
    CHECK(out.len == 2);
    check_result(&out.items[0], sample, true);
    check_result(&out.items[1], sample, false);
    br_results_clear(&out);
    reply failed = {.key = sample, .status = 200, .send_rc = 1, .send_error = "context deadline exceeded",
        .body_error = "synthetic read failure"};
    script fail_steps = {.rows = &failed, .count = 1};
    out = run(detector, one, one_len, &fail_steps);
    CHECK(out.len == 1);
    check_result(&out.items[0], sample, false);
    br_results_clear(&out);
    reply full = {.key = long_key, .status = 200};
    script full_steps = {.rows = &full, .count = 1};
    out = run(detector, long_input, long_len, &full_steps);
    CHECK(out.len == 1 && out.items[0].raw.len == 1000);
    check_result(&out.items[0], long_key, true);
    br_results_clear(&out);
    out = test_scan(detector, NULL, true, one, one_len);
    CHECK(out.len == 0);
    br_results_clear(&out);
    out = test_scan(detector, NULL, true, both, both_len);
    CHECK(out.len == 0);
    br_results_clear(&out);
    out = test_scan(detector, NULL, false, one, one_len);
    CHECK(out.len == 1);
    check_result(&out.items[0], sample, false);
    br_results_clear(&out);
    free(one);
    free(both);
    free(long_key);
    free(long_input);
}

static bool cancelled(void *user) { (void)user; return true; }

static void shared_send(const br_detector *detector)
{
    size_t len = 0;
    char *mid = join3("paperform ", sample, " paperform ", &len);
    char *input = join3(mid, sample, NULL, &len);
    free(mid);
    for (int mode = 0; mode < 4; ++mode) {
        test_http http = {0};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = mode == 0 ? NULL : &transport,
            .cancelled = mode == 1 ? cancelled : NULL,
            .deadline_monotonic_ms = mode == 2 ? 1 : 0,
            .user_agent = mode == 3 ? "invalid\r\nagent" : NULL};
        br_results out = test_scan(detector, &ctx, true, input, len);
        CHECK(out.len == 2 && !http.calls && http.releases == (mode == 0 ? 0u : 2u));
        check_result(&out.items[0], sample, false);
        check_result(&out.items[1], sample, false);
        CHECK(!out.items[0].verification_error && !out.items[1].verification_error);
        br_results_clear(&out);
    }
    free(input);
}

static void preserve_prior(const br_results *out, unsigned char *raw, char *saved, br_json *parts)
{
    CHECK(out->len == 1 && out->items[0].detector_type == 777 && out->items[0].verified);
    CHECK(out->items[0].raw.data == raw && out->items[0].raw.len == 5 && !memcmp(raw, "prior", 5));
    CHECK(out->items[0].verification_error == saved && !strcmp(saved, "caller-owned"));
    CHECK(out->items[0].secret_parts == parts);
}

static void owned_failures(const br_detector *detector)
{
    size_t n = 0;
    char *input = join3("paperform ", sample, NULL, &n);
    br_slice data = {(const unsigned char *)input, n};
    br_result prior = {0};
    br_results out = {0};
    char *error = NULL;
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verified = true;
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error && br_results_push(&out, &prior) == 0);
    unsigned char *raw = out.items[0].raw.data;
    char *saved = out.items[0].verification_error;
    br_json *parts = out.items[0].secret_parts;
    test_http http = {0};

    CHECK(detector->scan(detector, NULL, true, data, &out, &error) == 0 && !error);
    CHECK(!http.calls && !http.releases);
    preserve_prior(&out, raw, saved, parts);

    fail_size = 2 * sizeof(br_span);
    fail_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &out, &error) != 0 && error && !fail_after);
    CHECK(!strcmp(error, "out of memory iterating regex") && !http.calls && !http.releases);
    free(error); error = NULL;
    preserve_prior(&out, raw, saved, parts);

    fail_part_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &out, &error) != 0 && error && !fail_part_after);
    CHECK(!strcmp(error, "out of memory creating detector result") && !http.calls && !http.releases);
    free(error); error = NULL;
    preserve_prior(&out, raw, saved, parts);

    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    reply row = {.key = sample, .status = 200};
    script steps = {.rows = &row, .count = 1, .ctx = &ctx};
    http.inspect = inspect_request;
    http.user = &steps;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == 0 && !error);
    CHECK(http.calls == 1 && http.releases == 1 && out.len == 2);
    check_result(&out.items[1], sample, true);
    br_result_clear(&out.items[1]);
    out.len = 1;
    preserve_prior(&out, raw, saved, parts);

    http.calls = http.releases = 0;
    size_t cap = out.cap;
    out.cap = 0;
    CHECK(detector->scan(detector, &ctx, true, data, &out, &error) == -1 && error);
    CHECK(!strcmp(error, "out of memory appending detector result") && http.calls == 1 && http.releases == 1);
    out.cap = cap;
    free(error);
    preserve_prior(&out, raw, saved, parts);
    br_results_clear(&out);
    free(input);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    shared_send(detector);
    owned_failures(detector);
    return test_finish("Paperform");
}
