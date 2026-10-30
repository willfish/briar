/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"
#include "../../src/detectors/findings.h"

extern int br_mapbox_init(const br_detector **out, char **error);

/* Test-local seams only. Production regex, findings and HTTP stay linked. */
#define br_results_push mapbox_real_push
#define br_result_set_verification_error mapbox_real_setter
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
    return mapbox_real_push(out, owned);
}

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return mapbox_real_setter(result, cause, secrets, count);
}

static const char description[] =
    "Mapbox provides location-based services and APIs. "
    "Mapbox access tokens can be used to interact with these services and modify data.";

typedef struct {
    const char *id;
    const char *const *keys;
} mapbox_expect;

static void key_ending(char *out, char last)
{
    memcpy(out, "sk.", 3);
    memset(out + 3, '.', 79);
    out[82] = last;
    out[83] = '\0';
}

static void key_with_id(char *out, const char *id4)
{
    memcpy(out, "sk.", 3);
    memcpy(out + 3, id4, 4);
    memset(out + 7, '.', 75);
    out[82] = 'b';
    out[83] = '\0';
}

static void id_at(char out[5], size_t n)
{
    snprintf(out, 5, "q%03zu", n);
}

static size_t add_text(char *out, size_t used, size_t cap, const char *text, char separator)
{
    size_t n = strlen(text);
    int separate = separator && used;
    CHECK(used + (separate ? 1 : 0) + n < cap);
    if (separate) out[used++] = separator;
    memcpy(out + used, text, n);
    used += n;
    out[used] = '\0';
    return used;
}

static size_t add_ids(char *out, size_t used, size_t cap, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        char id[5];
        id_at(id, i);
        used = add_text(out, used, cap, id, '_');
    }
    return used;
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const mapbox_expect *expect = http->user;
    const char *key = expect->keys[http->calls - 1];
    char url[400];
    snprintf(url, sizeof(url), "https://api.mapbox.com/tokens/v2/%s?access_token=%s", expect->id, key);
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, url));
    CHECK(!strstr(request->url, "%"));
    CHECK(request->nheaders == 1);
    CHECK(!strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, "TruffleHog"));
    CHECK(!request->body.data && !request->body.len);
    CHECK(!request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 104);
}

static const br_detector *test_descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_mapbox_init(NULL, &error) != 0);
    CHECK(error && !strcmp(error, "invalid MapBox detector output"));
    free(error);
    CHECK(br_mapbox_init(&detector, &error) == 0 && !error);
    const br_detector *again = NULL;
    CHECK(br_mapbox_init(&again, &error) == 0 && again == detector && !error);
    CHECK(!strcmp(detector->name, "MapBox") && detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, description));
    CHECK(detector->type == 104 && detector->version == 0);
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "mapbox"));
    CHECK(detector->max_credential_span == 1024 && detector->max_secret_size == -1);
    CHECK(detector->start_offset == -1 && detector->state && detector->scan);
    return detector;
}

static void test_extraction(const br_detector *detector)
{
    char key[84], other[84], inside[84], input[512];
    key_ending(key, 'a');
    key_ending(other, 'c');
    key_with_id(inside, "wxyz");

    size_t used = add_ids(input, 0, sizeof(input), 11);
    used = add_text(input, used, sizeof(input), key, ' ');
    br_results out = test_scan(detector, NULL, false, input, used);
    CHECK(!out.len);
    br_results_clear(&out);

    used = add_ids(input, 0, sizeof(input), 12);
    used = add_text(input, used, sizeof(input), key, ' ');
    out = test_scan(detector, NULL, false, input, used);
    CHECK(out.len == 1);
    test_key_result(&out.items[0], 104, key, "key");
    CHECK(!out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);

    used = add_ids(input, 0, sizeof(input), 11);
    used = add_text(input, used, sizeof(input), inside, ' ');
    out = test_scan(detector, NULL, false, input, used);
    CHECK(out.len == 1);
    test_key_result(&out.items[0], 104, inside, "key");
    br_results_clear(&out);

    used = add_ids(input, 0, sizeof(input), 9);
    used = add_text(input, used, sizeof(input), "abcd.efgh_ijkl", ' ');
    used = add_text(input, used, sizeof(input), key, ' ');
    out = test_scan(detector, NULL, false, input, used);
    CHECK(out.len == 1);
    test_key_result(&out.items[0], 104, key, "key");
    br_results_clear(&out);

    used = add_ids(input, 0, sizeof(input), 11);
    used = add_text(input, used, sizeof(input), "ijkl-mnop", ' ');
    used = add_text(input, used, sizeof(input), key, ' ');
    out = test_scan(detector, NULL, false, input, used);
    CHECK(out.len == 1);
    test_key_result(&out.items[0], 104, key, "key");
    br_results_clear(&out);

    used = add_text(input, 0, sizeof(input), "mapbox", 0);
    used = add_ids(input, used, sizeof(input), 11);
    used = add_text(input, used, sizeof(input), key, ' ');
    used = add_text(input, used, sizeof(input), other, ' ');
    out = test_scan(detector, NULL, false, input, used);
    CHECK(out.len == 2);
    test_key_result(&out.items[0], 104, key, "key");
    test_key_result(&out.items[1], 104, other, "key");
    br_results_clear(&out);

    used = add_ids(input, 0, sizeof(input), 12);
    used = add_text(input, used, sizeof(input), key, ' ');
    used = add_text(input, used, sizeof(input), key, ' ');
    out = test_scan(detector, NULL, false, input, used);
    CHECK(out.len == 2);
    test_key_result(&out.items[0], 104, key, "key");
    test_key_result(&out.items[1], 104, key, "key");
    br_results_clear(&out);

    char short_key[83];
    memcpy(short_key, "sk.", 3);
    memset(short_key + 3, '.', 78);
    short_key[81] = 'a';
    short_key[82] = '\0';
    used = add_ids(input, 0, sizeof(input), 12);
    used = add_text(input, used, sizeof(input), short_key, ' ');
    out = test_scan(detector, NULL, false, input, used);
    CHECK(!out.len);
    br_results_clear(&out);

    char glued[96];
    glued[0] = 'x';
    key_ending(glued + 1, 'a');
    used = add_ids(input, 0, sizeof(input), 12);
    used = add_text(input, used, sizeof(input), glued, ' ');
    out = test_scan(detector, NULL, false, input, used);
    CHECK(!out.len);
    br_results_clear(&out);

    static char far_input[1400];
    key_ending(far_input, 'a');
    memset(far_input + 83, '.', 1100);
    far_input[83 + 1100] = '\0';
    used = add_ids(far_input, 83 + 1100, sizeof(far_input), 12);
    out = test_scan(detector, NULL, false, far_input, used);
    CHECK(out.len == 1);
    test_key_result(&out.items[0], 104, key, "key");
    br_results_clear(&out);
}

static void test_verification(const br_detector *detector)
{
    char key[84], other[84], inside[84], input[512];
    key_ending(key, 'a');
    key_ending(other, 'c');
    key_with_id(inside, "wxyz");
    const unsigned char unread[] = {'{', 'n', 'o', 't'};

    size_t used = add_ids(input, 0, sizeof(input), 11);
    used = add_text(input, used, sizeof(input), key, ' ');
    test_http silent = {.response = {.status = 200}, .inspect = inspect_request};
    br_transport silent_transport = test_transport(&silent);
    br_scan_ctx silent_ctx = {.transport = &silent_transport};
    br_results out = test_scan(detector, &silent_ctx, true, input, used);
    CHECK(!out.len && silent.calls == 0 && silent.releases == 0);
    br_results_clear(&out);

    used = add_ids(input, 0, sizeof(input), 12);
    used = add_text(input, used, sizeof(input), key, ' ');
    used = add_text(input, used, sizeof(input), other, ' ');
    const char *both[] = {key, other};
    mapbox_expect twelfth = {.id = "q011", .keys = both};
    test_http http = {
        .response = {.status = 200, .body = {unread, sizeof(unread)}, .body_error = "body must not be read"},
        .inspect = inspect_request, .user = &twelfth,
    };
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    out = test_scan(detector, &ctx, true, input, used);
    CHECK(out.len == 2 && http.calls == 2 && http.releases == 2);
    test_key_result(&out.items[0], 104, key, "key");
    test_key_result(&out.items[1], 104, other, "key");
    CHECK(out.items[0].verified && out.items[1].verified);
    CHECK(!out.items[0].verification_error && !out.items[1].verification_error);
    br_results_clear(&out);

    used = add_ids(input, 0, sizeof(input), 13);
    used = add_text(input, used, sizeof(input), key, ' ');
    const char *only[] = {key};
    mapbox_expect still_twelfth = {.id = "q011", .keys = only};
    test_http extra = {
        .response = {.status = 200, .body = {unread, sizeof(unread)}, .body_error = "ignored"},
        .inspect = inspect_request, .user = &still_twelfth,
    };
    br_transport extra_transport = test_transport(&extra);
    br_scan_ctx extra_ctx = {.transport = &extra_transport};
    out = test_scan(detector, &extra_ctx, true, input, used);
    CHECK(out.len == 1 && extra.calls == 1 && extra.releases == 1);
    test_key_result(&out.items[0], 104, key, "key");
    CHECK(out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);

    used = add_ids(input, 0, sizeof(input), 11);
    used = add_text(input, used, sizeof(input), inside, ' ');
    const char *inside_keys[] = {inside};
    mapbox_expect inside_id = {.id = "wxyz", .keys = inside_keys};
    test_http inside_http = {
        .response = {.status = 204, .body = {unread, sizeof(unread)}, .body_error = "ignored"},
        .inspect = inspect_request, .user = &inside_id,
    };
    br_transport inside_transport = test_transport(&inside_http);
    br_scan_ctx inside_ctx = {.transport = &inside_transport};
    out = test_scan(detector, &inside_ctx, true, input, used);
    CHECK(out.len == 1 && inside_http.calls == 1 && inside_http.releases == 1);
    test_key_result(&out.items[0], 104, inside, "key");
    CHECK(out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);

    used = add_ids(input, 0, sizeof(input), 9);
    used = add_text(input, used, sizeof(input), "abcd.efgh_ijkl", ' ');
    used = add_text(input, used, sizeof(input), key, ' ');
    mapbox_expect split = {.id = "ijkl", .keys = only};
    test_http split_http = {
        .response = {.status = 299}, .inspect = inspect_request, .user = &split,
    };
    br_transport split_transport = test_transport(&split_http);
    br_scan_ctx split_ctx = {.transport = &split_transport};
    out = test_scan(detector, &split_ctx, true, input, used);
    CHECK(out.len == 1 && split_http.calls == 1);
    CHECK(out.items[0].verified);
    br_results_clear(&out);

    used = add_ids(input, 0, sizeof(input), 11);
    used = add_text(input, used, sizeof(input), "ijkl-mnop", ' ');
    used = add_text(input, used, sizeof(input), key, ' ');
    mapbox_expect hyphen = {.id = "ijkl-mnop", .keys = only};
    test_http hyphen_http = {
        .response = {.status = 200}, .inspect = inspect_request, .user = &hyphen,
    };
    br_transport hyphen_transport = test_transport(&hyphen_http);
    br_scan_ctx hyphen_ctx = {.transport = &hyphen_transport};
    out = test_scan(detector, &hyphen_ctx, true, input, used);
    CHECK(out.len == 1 && hyphen_http.calls == 1);
    CHECK(out.items[0].verified);
    br_results_clear(&out);

    used = add_ids(input, 0, sizeof(input), 12);
    used = add_text(input, used, sizeof(input), key, ' ');
    const int statuses[] = {199, 300, 401, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        test_http status_http = {
            .response = {.status = statuses[i], .body = {unread, sizeof(unread)}, .body_error = "ignored"},
            .inspect = inspect_request, .user = &still_twelfth,
        };
        br_transport status_transport = test_transport(&status_http);
        br_scan_ctx status_ctx = {.transport = &status_transport};
        out = test_scan(detector, &status_ctx, true, input, used);
        CHECK(out.len == 1 && status_http.calls == 1 && status_http.releases == 1);
        test_key_result(&out.items[0], 104, key, "key");
        CHECK(!out.items[0].verified && !out.items[0].verification_error);
        br_results_clear(&out);
    }

    test_http failed = {
        .response = {.status = 200, .body = {(const unsigned char *)"bad", 3}},
        .send_rc = 1, .send_error = "transport failed with key",
        .inspect = inspect_request, .user = &still_twelfth,
    };
    br_transport failed_transport = test_transport(&failed);
    br_scan_ctx failed_ctx = {.transport = &failed_transport};
    out = test_scan(detector, &failed_ctx, true, input, used);
    CHECK(out.len == 1 && failed.calls == 1 && failed.releases == 1);
    test_key_result(&out.items[0], 104, key, "key");
    CHECK(!out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);

    br_results prior = {0};
    br_result kept = {0};
    CHECK(br_finding_key(&kept, 777, "prior", "key") == 0 && br_results_push(&prior, &kept) == 0);
    char *error = NULL;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, used},
                         &prior, &error) == 0);
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
    const char *none = "mapbox";
    br_slice empty = {(const unsigned char *)none, strlen(none)};
    for (int capture = 0; capture < 2; ++capture) {
        br_result sentinel = {0};
        unsigned char *raw = NULL;
        char *cause = NULL;
        br_results results = {0};
        keep_prior(&results, &sentinel, &raw, &cause);
        test_http http = {0};
        fail_size = 2 * sizeof(br_span);
        fail_after = (size_t)capture + 1; /* 1 is the key FindAll; 2 is the id FindAll. */
        char *error = NULL;
        int rc = detector->scan(detector, NULL, true, empty, &results, &error);
        CHECK(rc != 0 && error && !strcmp(error, "out of memory iterating regex"));
        CHECK(!fail_after && !http.calls && !http.releases);
        prior_unchanged(&results, raw, cause);
        free(error);
        br_results_clear(&results);
    }

    char key[84], input[256];
    key_ending(key, 'd');
    size_t used = add_ids(input, 0, sizeof(input), 12);
    used = add_text(input, used, sizeof(input), key, ' ');
    br_slice slice = {(const unsigned char *)input, used};
    br_result sentinel = {0};
    unsigned char *raw = NULL;
    char *cause = NULL;
    br_results results = {0};
    keep_prior(&results, &sentinel, &raw, &cause);
    test_http http = {.response = {.status = 200}};
    fail_part_after = 1;
    char *error = NULL;
    int rc = detector->scan(detector, NULL, true, slice, &results, &error);
    CHECK(rc != 0 && error && !strcmp(error, "out of memory creating MapBox result"));
    CHECK(!fail_part_after && !http.calls && !http.releases);
    prior_unchanged(&results, raw, cause);
    free(error);
    br_results_clear(&results);

    sentinel = (br_result){0};
    raw = NULL;
    cause = NULL;
    results = (br_results){0};
    keep_prior(&results, &sentinel, &raw, &cause);
    http = (test_http){.response = {.status = 200}};
    error = NULL;
    CHECK(detector->scan(detector, NULL, true, slice, &results, &error) == 0 && !error);
    CHECK(!http.calls && !http.releases);
    prior_unchanged(&results, raw, cause);
    br_results_clear(&results);

    const char *keys[] = {key};
    mapbox_expect twelfth = {.id = "q011", .keys = keys};
    http = (test_http){.response = {.status = 200}, .inspect = inspect_request, .user = &twelfth};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    results = test_scan(detector, &ctx, true, input, used);
    CHECK(results.len == 1 && http.calls == 1 && http.releases == 1);
    test_key_result(&results.items[0], 104, key, "key");
    CHECK(results.items[0].verified);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = test_descriptor();
    test_extraction(detector);
    test_verification(detector);
    test_nil_context(detector);
    CHECK(!setter_calls);
    return test_finish("MapBox");
}
