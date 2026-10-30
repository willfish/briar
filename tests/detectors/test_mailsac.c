/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"
#include "../../src/detectors/findings.h"

extern int br_mailsac_init(const br_detector **out, char **error);

/* Test-local seams only. Production regex, findings and HTTP stay linked. */
#define br_results_push mailsac_real_push
#define br_result_set_verification_error mailsac_real_setter
#include "../../src/result.c"
#undef br_results_push
#undef br_result_set_verification_error

static size_t fail_size, fail_after, fail_part_after, fail_push_after, setter_calls;

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

int br_results_push(br_results *out, br_result *owned)
{
    if (fail_push_after && --fail_push_after == 0) return 1;
    return mailsac_real_push(out, owned);
}

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return mailsac_real_setter(result, cause, secrets, count);
}

static const char description[] =
    "Mailsac is a disposable email service used for testing and temporary email purposes. "
    "Mailsac API keys can be used to access and manage email addresses and messages.";

static void key_of(char *out, size_t alnum, size_t shift)
{
    static const char alphabet[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    out[0] = 'k';
    out[1] = '_';
    for (size_t i = 0; i < alnum; ++i) out[2 + i] = alphabet[(i + shift) % 62];
    out[2 + alnum] = '\0';
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const char *const *keys = http->user;
    const char *key = keys[http->calls - 1];
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://mailsac.com/api/addresses"));
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 481);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Mailsac-Key"));
    CHECK(!strcmp(request->headers[1].value, key));
    CHECK(!strcmp(request->headers[2].name, "User-Agent"));
    CHECK(!strcmp(request->headers[2].value, "TruffleHog"));
}

static const br_detector *test_descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_mailsac_init(NULL, &error) != 0);
    CHECK(error && !strcmp(error, "invalid Mailsac detector output"));
    free(error);
    CHECK(br_mailsac_init(&detector, &error) == 0 && !error);
    const br_detector *again = NULL;
    CHECK(br_mailsac_init(&again, &error) == 0 && again == detector && !error);
    CHECK(!strcmp(detector->name, "Mailsac") && detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, description));
    CHECK(detector->type == 481 && detector->version == 0);
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "mailsac"));
    CHECK(detector->max_credential_span == -1 && detector->max_secret_size == -1);
    CHECK(detector->start_offset == -1 && detector->state && detector->scan);
    return detector;
}

static void add_spaces(char *out, size_t cap, size_t count)
{
    size_t used = strlen(out);
    CHECK(used + count < cap);
    memset(out + used, ' ', count);
    out[used + count] = '\0';
}

static void test_extraction(const br_detector *detector)
{
    char exact[39], longer[40], huge[203], short_key[38], first[39], second[39], input[512];
    key_of(exact, 36, 1);
    key_of(longer, 37, 2);
    key_of(huge, 200, 3);
    key_of(short_key, 35, 4);
    key_of(first, 36, 5);
    key_of(second, 36, 6);

    snprintf(input, sizeof(input), "mailsac %s tail", exact);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    test_key_result(&out.items[0], 481, exact, "key");
    CHECK(!out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);

    snprintf(input, sizeof(input), "MAILSAC %s mailsac %s", longer, huge);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 2);
    test_key_result(&out.items[0], 481, longer, "key");
    test_key_result(&out.items[1], 481, huge, "key");
    CHECK(out.items[1].raw.len == 202);
    br_results_clear(&out);

    snprintf(input, sizeof(input), "mailsac %s mailsac %s", first, first);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 2);
    test_key_result(&out.items[0], 481, first, "key");
    test_key_result(&out.items[1], 481, first, "key");
    br_results_clear(&out);

    snprintf(input, sizeof(input), "mailsac %s mailsac %s", first, second);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 2);
    test_key_result(&out.items[0], 481, first, "key");
    test_key_result(&out.items[1], 481, second, "key");
    br_results_clear(&out);

    input[0] = '\0';
    CHECK(strlen("mailsac") + 40 + strlen(exact) + 1 < sizeof(input));
    memcpy(input, "mailsac", 8);
    add_spaces(input, sizeof(input), 40);
    strcat(input, exact);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    test_key_result(&out.items[0], 481, exact, "key");
    br_results_clear(&out);

    snprintf(input, sizeof(input), "%s", exact);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "mailsac %s", short_key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "mailsac%s", exact);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    input[0] = '\0';
    memcpy(input, "mailsac", 8);
    add_spaces(input, sizeof(input), 41);
    strcat(input, exact);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    char upper[39];
    key_of(upper, 36, 8);
    upper[0] = 'K';
    snprintf(input, sizeof(input), "mailsac %s", upper);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
}

static void test_verification(const br_detector *detector)
{
    char key[39], other[39], huge[203], input[512];
    key_of(key, 36, 9);
    key_of(other, 36, 10);
    key_of(huge, 200, 11);
    snprintf(input, sizeof(input), "mailsac %s mailsac %s", key, huge);
    const char *keys[] = {key, huge};
    const unsigned char unread[] = {'{', 'n', 'o', 't'};
    test_http http = {
        .response = {.status = 200, .body = {unread, sizeof(unread)}, .body_error = "body must not be read"},
        .inspect = inspect_request, .user = keys,
    };
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 2 && http.calls == 2 && http.releases == 2);
    test_key_result(&out.items[0], 481, key, "key");
    test_key_result(&out.items[1], 481, huge, "key");
    CHECK(out.items[0].verified && out.items[1].verified);
    CHECK(!out.items[0].verification_error && !out.items[1].verification_error);
    br_results_clear(&out);

    snprintf(input, sizeof(input), "mailsac %s", key);
    const char *only[] = {key};
    const int statuses[] = {204, 299, 199, 300, 401, 500};
    const bool verified[] = {true, true, false, false, false, false};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        test_http one = {
            .response = {.status = statuses[i], .body = {unread, sizeof(unread)},
                         .body_error = "ignored"},
            .inspect = inspect_request, .user = only,
        };
        br_transport one_transport = test_transport(&one);
        br_scan_ctx one_ctx = {.transport = &one_transport};
        out = test_scan(detector, &one_ctx, true, input, strlen(input));
        CHECK(out.len == 1 && one.calls == 1 && one.releases == 1);
        test_key_result(&out.items[0], 481, key, "key");
        CHECK(out.items[0].verified == verified[i] && !out.items[0].verification_error);
        br_results_clear(&out);
    }

    test_http failed = {
        .response = {.status = 200, .body = {(const unsigned char *)"Invalid key", 11}},
        .send_rc = 1, .send_error = "transport failed with key",
        .inspect = inspect_request, .user = only,
    };
    br_transport failed_transport = test_transport(&failed);
    br_scan_ctx failed_ctx = {.transport = &failed_transport};
    out = test_scan(detector, &failed_ctx, true, input, strlen(input));
    CHECK(out.len == 1 && failed.calls == 1 && failed.releases == 1);
    test_key_result(&out.items[0], 481, key, "key");
    CHECK(!out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);

    snprintf(input, sizeof(input), "mailsac %s mailsac %s", key, other);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 2 && !out.items[0].verified);
    br_results_clear(&out);

    br_results prior = {0};
    br_result kept = {0};
    CHECK(br_finding_key(&kept, 777, "prior", "key") == 0 && br_results_push(&prior, &kept) == 0);
    char *error = NULL;
    CHECK(detector->scan(detector, NULL, true,
                         (br_slice){(const unsigned char *)input, strlen(input)}, &prior, &error) == 0);
    CHECK(!error && prior.len == 1 && prior.items[0].raw.len == 5 && !memcmp(prior.items[0].raw.data, "prior", 5));
    br_results_clear(&prior);
}

static void keep_prior(br_results *results, br_result *sentinel, unsigned char **raw, char **cause)
{
    memset(sentinel, 0, sizeof(*sentinel));
    sentinel->detector_type = 12345;
    sentinel->verified = true;
    sentinel->raw.data = malloc(4);
    CHECK(sentinel->raw.data);
    memcpy(sentinel->raw.data, "keep", 4);
    sentinel->raw.len = 4;
    sentinel->verification_error = strdup("caller-owned");
    CHECK(sentinel->verification_error);
    *raw = sentinel->raw.data;
    *cause = sentinel->verification_error;
    CHECK(br_results_push(results, sentinel) == 0);
}

static void prior_unchanged(const br_results *results, unsigned char *raw, char *cause)
{
    CHECK(results->len == 1 && results->items[0].detector_type == 12345 && results->items[0].verified);
    CHECK(results->items[0].raw.data == raw && results->items[0].raw.len == 4 && !memcmp(raw, "keep", 4));
    CHECK(results->items[0].verification_error == cause && !strcmp(cause, "caller-owned"));
}

/* These fail an archived verify && !ctx return: that path never captures or
 * creates a finding, so an injected +1 cannot be observed. */
static void test_nil_context(const br_detector *detector)
{
    char key[39], input[64];
    key_of(key, 36, 12);
    snprintf(input, sizeof(input), "mailsac %s", key);
    br_slice slice = {(const unsigned char *)input, strlen(input)};
    const char *messages[] = {
        "out of memory iterating regex",
        "out of memory creating Mailsac result",
    };
    for (int mode = 0; mode < 2; ++mode) {
        br_result sentinel = {0};
        unsigned char *raw = NULL;
        char *cause = NULL;
        br_results results = {0};
        keep_prior(&results, &sentinel, &raw, &cause);
        test_http http = {.response = {.status = 200}};
        if (mode == 0) {
            fail_size = 2 * sizeof(br_span);
            fail_after = 1;
        } else fail_part_after = 1;
        char *error = NULL;
        int rc = detector->scan(detector, NULL, true, slice, &results, &error);
        CHECK(rc != 0 && error && !strcmp(error, messages[mode]));
        CHECK(!fail_after && !fail_part_after);
        CHECK(!http.calls && !http.releases);
        prior_unchanged(&results, raw, cause);
        free(error);
        br_results_clear(&results);
    }

    br_result sentinel = {0};
    unsigned char *raw = NULL;
    char *cause = NULL;
    br_results results = {0};
    keep_prior(&results, &sentinel, &raw, &cause);
    test_http http = {.response = {.status = 200}};
    char *error = NULL;
    CHECK(detector->scan(detector, NULL, true, slice, &results, &error) == 0 && !error);
    CHECK(!http.calls && !http.releases);
    prior_unchanged(&results, raw, cause);
    br_results_clear(&results);

    char long_key[80], long_input[96];
    key_of(long_key, 70, 13);
    CHECK(strlen(long_key) == 72);
    snprintf(long_input, sizeof(long_input), "mailsac %s", long_key);
    const char *keys[] = {long_key};
    http = (test_http){.response = {.status = 200}, .inspect = inspect_request, .user = keys};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, long_input, strlen(long_input));
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    test_key_result(&results.items[0], 481, long_key, "key");
    CHECK(results.items[0].raw.len == 72 && results.items[0].verified);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = test_descriptor();
    test_extraction(detector);
    test_verification(detector);
    test_nil_context(detector);
    CHECK(!setter_calls);
    return test_finish("Mailsac");
}
