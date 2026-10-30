/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"
#include "../../src/detectors/findings.h"

extern int br_maxmindlicense_v1_init(const br_detector **out, char **error);
extern int br_maxmindlicense_v2_init(const br_detector **out, char **error);

/* Test-local seams only. Production regex, findings and HTTP stay linked. */
#define br_results_push maxmind_real_push
#define br_result_set_verification_error maxmind_real_setter
#include "../../src/result.c"
#undef br_results_push
#undef br_result_set_verification_error

static size_t fail_size, fail_after, fail_part_after, fail_extra_after, fail_push_after, setter_calls;
static int fail_setter;
static const char *fail_strdup_text;

void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) return NULL;
    return calloc(1, size);
}

char *strdup(const char *text)
{
    if (fail_strdup_text && !strcmp(text, fail_strdup_text)) {
        fail_strdup_text = NULL;
        return NULL;
    }
    size_t len = strlen(text);
    char *copy = malloc(len + 1);
    if (!copy) return NULL;
    memcpy(copy, text, len + 1);
    return copy;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && name && !strcmp(name, "key") && --fail_part_after == 0) return 1;
    if (fail_extra_after && name && !strcmp(name, "rotation_guide") && --fail_extra_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

int br_results_push(br_results *out, br_result *owned)
{
    if (fail_push_after && --fail_push_after == 0) return 1;
    return maxmind_real_push(out, owned);
}

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    if (fail_setter) {
        fail_setter = 0;
        return 1;
    }
    return maxmind_real_setter(result, cause, secrets, count);
}

static const char v1_description[] =
    "MaxMind provides IP intelligence through their GeoIP service which can be used to determine geographical location and other information about an IP address.";
static const char v2_description[] =
    "MaxMind provides IP intelligence through its GeoIP databases and services. "
    "MaxMind license keys are used to access these services and databases.";
static const char guide[] = "https://howtorotate.com/docs/tutorials/maxmind/";

typedef struct { const char *id, *key; } v1_pair;

static void v1_key(char out[17], char mark)
{
    for (int i = 0; i < 16; ++i) out[i] = (char)('A' + (i + (mark - 'A')) % 26);
    out[16] = '\0';
}

static void v2_key(char out[41], char mark)
{
    for (int i = 0; i < 6; ++i) out[i] = mark;
    out[6] = '_';
    for (int i = 0; i < 29; ++i) out[7 + i] = (char)('a' + (i + (mark - 'A')) % 26);
    memcpy(out + 36, "_mmk", 5);
}

static void check_key(const br_result *result, const char *key)
{
    CHECK(result->detector_type == 96);
    CHECK(result->raw.len == strlen(key) && !memcmp(result->raw.data, key, strlen(key)));
    CHECK(!result->raw_v2.data && !result->raw_v2.len && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 1);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(json_object_is_type(part, json_type_string));
    CHECK(!strcmp(json_object_get_string(part), key));
}

static void check_extra(const br_result *result, const char *version, const char *redacted)
{
    CHECK(result->extra_data && json_object_object_length(result->extra_data) == 2);
    br_json *guide_value = NULL, *version_value = NULL;
    CHECK(json_object_object_get_ex(result->extra_data, "rotation_guide", &guide_value));
    CHECK(json_object_object_get_ex(result->extra_data, "version", &version_value));
    CHECK(json_object_is_type(guide_value, json_type_string));
    CHECK(json_object_is_type(version_value, json_type_string));
    CHECK(!strcmp(json_object_get_string(guide_value), guide));
    CHECK(!strcmp(json_object_get_string(version_value), version));
    if (redacted) CHECK(result->redacted && !strcmp(result->redacted, redacted));
    else CHECK(!result->redacted);
}

static void inspect_v1(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const v1_pair *pair = &((const v1_pair *)http->user)[http->calls - 1];
    char *authorization = NULL, *error = NULL;
    CHECK(br_http_basic_auth((br_slice){(const unsigned char *)pair->id, strlen(pair->id)},
                             (br_slice){(const unsigned char *)pair->key, strlen(pair->key)},
                             &authorization, &error) == 0 && !error);
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://geoip.maxmind.com/geoip/v2.1/country/8.8.8.8"));
    CHECK(!request->body.data && !request->body.len);
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 96 && !request->dedup_key.data);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Authorization"));
    CHECK(!strcmp(request->headers[0].value, authorization));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, "TruffleHog"));
    free(authorization);
}

static void inspect_v2(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const char *key = ((const char *const *)http->user)[http->calls - 1];
    char body[64];
    snprintf(body, sizeof(body), "license_key=%s", key);
    CHECK(ctx && ctx->transport && ctx->transport->user == http);
    CHECK(!strcmp(request->method, "POST"));
    CHECK(!strcmp(request->url, "https://secret-scanning.maxmind.com/secrets/validate-license-key"));
    CHECK(request->body.len == strlen(body) && !memcmp(request->body.data, body, request->body.len));
    CHECK(!memchr(request->body.data, '%', request->body.len));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(request->detector_type == 96 && !request->dedup_key.data);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Content-Type"));
    CHECK(!strcmp(request->headers[0].value, "application/x-www-form-urlencoded"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
    CHECK(!strcmp(request->headers[1].value, "TruffleHog"));
}

static const br_detector *v1_descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_maxmindlicense_v1_init(NULL, &error) != 0);
    CHECK(error && !strcmp(error, "invalid MaxMindLicense v1 detector output"));
    free(error);
    CHECK(br_maxmindlicense_v1_init(&detector, &error) == 0 && !error);
    const br_detector *again = NULL;
    CHECK(br_maxmindlicense_v1_init(&again, &error) == 0 && again == detector && !error);
    CHECK(!strcmp(detector->name, "MaxMindLicense") && detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, v1_description));
    CHECK(detector->type == 96 && detector->version == 1);
    CHECK(detector->nkeywords == 2 && !strcmp(detector->keywords[0], "maxmind"));
    CHECK(!strcmp(detector->keywords[1], "geoip"));
    CHECK(detector->max_credential_span == 1024 && detector->max_secret_size == -1);
    CHECK(detector->start_offset == -1 && detector->state && detector->scan);
    return detector;
}

static const br_detector *v2_descriptor(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_maxmindlicense_v2_init(NULL, &error) != 0);
    CHECK(error && !strcmp(error, "invalid MaxMindLicense v2 detector output"));
    free(error);
    CHECK(br_maxmindlicense_v2_init(&detector, &error) == 0 && !error);
    const br_detector *again = NULL;
    CHECK(br_maxmindlicense_v2_init(&again, &error) == 0 && again == detector && !error);
    CHECK(!strcmp(detector->name, "MaxMindLicense") && detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, v2_description));
    CHECK(detector->type == 96 && detector->version == 2);
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "_mmk"));
    CHECK(detector->max_credential_span == -1 && detector->max_secret_size == -1);
    CHECK(detector->start_offset == -1 && detector->state && detector->scan);
    return detector;
}

static void test_v1_extraction(const br_detector *detector)
{
    char first[17], second[17], input[256], far[1400];
    v1_key(first, 'A');
    v1_key(second, 'B');

    snprintf(input, sizeof(input), "maxmind %s maxmind %s geoip 1234567 geoip 89", first, second);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 4);
    check_key(&out.items[0], first);
    check_extra(&out.items[0], "1", "1234567");
    check_key(&out.items[1], first);
    check_extra(&out.items[1], "1", "89");
    check_key(&out.items[2], second);
    check_extra(&out.items[2], "1", "1234567");
    check_key(&out.items[3], second);
    check_extra(&out.items[3], "1", "89");
    CHECK(!out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);

    snprintf(input, sizeof(input), "GEOIP %s MAXMIND 12", first);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    check_key(&out.items[0], first);
    check_extra(&out.items[0], "1", "12");
    br_results_clear(&out);

    snprintf(input, sizeof(input), "maxmind %s maxmind %s geoip 99", first, first);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 2);
    check_key(&out.items[0], first);
    check_key(&out.items[1], first);
    br_results_clear(&out);

    snprintf(input, sizeof(input), "maxmind 1234567890123456");
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "maxmind 1234567890123456 geoip 99");
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    check_key(&out.items[0], "1234567890123456");
    check_extra(&out.items[0], "1", "99");
    br_results_clear(&out);

    input[0] = '\0';
    memcpy(input, "maxmind", 8);
    memset(input + 7, ' ', 40);
    input[47] = '\0';
    strcat(input, first);
    strcat(input, " geoip 42");
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    check_key(&out.items[0], first);
    br_results_clear(&out);
    input[0] = '\0';
    memcpy(input, "maxmind", 8);
    memset(input + 7, ' ', 41);
    input[48] = '\0';
    strcat(input, first);
    strcat(input, " geoip 42");
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);

    snprintf(input, sizeof(input), "maxmind%s geoip 12", first);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "maxmind %s geoip12", first);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "maxmind %s geoip 1", first);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "maxmind %s geoip 12345678", first);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);

    memcpy(far, "maxmind ", 8);
    memcpy(far + 8, first, 16);
    memset(far + 24, '.', 1100);
    memcpy(far + 1124, " geoip 1234567", 15);
    out = test_scan(detector, NULL, false, far, 1124 + 14);
    CHECK(out.len == 1);
    check_key(&out.items[0], first);
    check_extra(&out.items[0], "1", "1234567");
    br_results_clear(&out);
}

static void test_v1_verification(const br_detector *detector)
{
    char first[17], second[17], input[192];
    v1_key(first, 'C');
    v1_key(second, 'D');
    snprintf(input, sizeof(input), "maxmind %s maxmind %s geoip 1234567 geoip 89", first, second);
    v1_pair pairs[] = {
        {"1234567", first}, {"89", first}, {"1234567", second}, {"89", second},
    };
    const unsigned char unread[] = {'{', 'n', 'o'};
    test_http http = {
        .response = {.status = 200, .body = {unread, sizeof(unread)}, .body_error = "body must not be read"},
        .inspect = inspect_v1, .user = pairs,
    };
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 4 && http.calls == 4 && http.releases == 4);
    CHECK(out.items[0].verified && out.items[3].verified);
    CHECK(!out.items[0].verification_error && !strcmp(out.items[0].redacted, "1234567"));
    CHECK(!strcmp(out.items[3].redacted, "89"));
    br_results_clear(&out);

    snprintf(input, sizeof(input), "maxmind %s geoip 42", first);
    v1_pair one[] = {{"42", first}};
    const int statuses[] = {204, 299, 199, 300, 401, 500};
    const bool verified[] = {true, true, false, false, false, false};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        test_http status_http = {
            .response = {.status = statuses[i], .body = {unread, sizeof(unread)}, .body_error = "ignored"},
            .inspect = inspect_v1, .user = one,
        };
        br_transport status_transport = test_transport(&status_http);
        br_scan_ctx status_ctx = {.transport = &status_transport};
        out = test_scan(detector, &status_ctx, true, input, strlen(input));
        CHECK(out.len == 1 && status_http.calls == 1 && status_http.releases == 1);
        CHECK(out.items[0].verified == verified[i] && !out.items[0].verification_error);
        check_extra(&out.items[0], "1", "42");
        br_results_clear(&out);
    }

    test_http failed = {
        .response = {.status = 200}, .send_rc = 1, .send_error = "transport failed with key",
        .inspect = inspect_v1, .user = one,
    };
    br_transport failed_transport = test_transport(&failed);
    br_scan_ctx failed_ctx = {.transport = &failed_transport};
    out = test_scan(detector, &failed_ctx, true, input, strlen(input));
    CHECK(out.len == 1 && failed.calls == 1 && failed.releases == 1);
    CHECK(!out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);

    snprintf(input, sizeof(input), "maxmind %s", first);
    test_http none = {.response = {.status = 200}, .inspect = inspect_v1};
    br_transport none_transport = test_transport(&none);
    br_scan_ctx none_ctx = {.transport = &none_transport};
    out = test_scan(detector, &none_ctx, true, input, strlen(input));
    CHECK(!out.len && none.calls == 0 && none.releases == 0);
    br_results_clear(&out);

    br_results prior = {0};
    br_result kept = {0};
    CHECK(br_finding_key(&kept, 777, "prior", "key") == 0 && br_results_push(&prior, &kept) == 0);
    char *error = NULL;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)},
                         &prior, &error) == 0);
    CHECK(!error && prior.len == 1 && prior.items[0].raw.len == 5);
    br_results_clear(&prior);
}

static void test_v2_extraction(const br_detector *detector)
{
    char first[41], second[41], input[192];
    v2_key(first, 'A');
    v2_key(second, 'B');
    snprintf(input, sizeof(input), "%s %s %s", first, second, first);
    br_results out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 2);
    check_key(&out.items[0], first);
    check_extra(&out.items[0], "2", NULL);
    check_key(&out.items[1], second);
    check_extra(&out.items[1], "2", NULL);
    CHECK(!out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);

    snprintf(input, sizeof(input), "prefix %s tail", first);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(out.len == 1);
    check_key(&out.items[0], first);
    br_results_clear(&out);
    snprintf(input, sizeof(input), "%s", "_mmk");
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
    char short_key[40];
    memcpy(short_key, first, 39);
    short_key[5] = 'x';
    short_key[39] = '\0';
    snprintf(input, sizeof(input), "%s", short_key);
    out = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!out.len);
    br_results_clear(&out);
}

static void test_v2_verification(const br_detector *detector)
{
    char first[41], second[41], input[128];
    v2_key(first, 'C');
    v2_key(second, 'D');
    snprintf(input, sizeof(input), "%s %s %s", first, second, first);
    const char *keys[] = {first, second};
    const unsigned char unread[] = {'n', 'o'};
    test_http http = {
        .response = {.status = 204, .body = {unread, sizeof(unread)}, .body_error = "body read failed"},
        .inspect = inspect_v2, .user = (void *)keys,
    };
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 2 && http.calls == 2 && http.releases == 2);
    CHECK(out.items[0].verified && out.items[1].verified);
    CHECK(!out.items[0].verification_error && !out.items[1].verification_error);
    check_extra(&out.items[0], "2", NULL);
    br_results_clear(&out);

    snprintf(input, sizeof(input), "%s", first);
    const char *only[] = {first};
    test_http denied = {
        .response = {.status = 401, .body_error = "ignored"},
        .inspect = inspect_v2, .user = (void *)only,
    };
    br_transport denied_transport = test_transport(&denied);
    br_scan_ctx denied_ctx = {.transport = &denied_transport};
    out = test_scan(detector, &denied_ctx, true, input, strlen(input));
    CHECK(out.len == 1 && denied.calls == 1 && denied.releases == 1);
    CHECK(!out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);

    const int statuses[] = {200, 199, 299, 400, 500};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        char message[64];
        snprintf(message, sizeof(message), "unexpected status code: %d", statuses[i]);
        test_http status_http = {
            .response = {.status = statuses[i], .body_error = "body read failed"},
            .inspect = inspect_v2, .user = (void *)only,
        };
        br_transport status_transport = test_transport(&status_http);
        br_scan_ctx status_ctx = {.transport = &status_transport};
        out = test_scan(detector, &status_ctx, true, input, strlen(input));
        CHECK(out.len == 1 && status_http.calls == 1 && status_http.releases == 1);
        CHECK(!out.items[0].verified);
        CHECK(out.items[0].verification_error && !strcmp(out.items[0].verification_error, message));
        CHECK(!strstr(out.items[0].verification_error, "body read failed"));
        check_extra(&out.items[0], "2", NULL);
        br_results_clear(&out);
    }

    char send_error[80];
    snprintf(send_error, sizeof(send_error), "transport failed %s", first);
    test_http failed = {
        .response = {.status = 204, .body_error = "must not decide"},
        .send_rc = 1, .send_error = send_error,
        .inspect = inspect_v2, .user = (void *)only,
    };
    br_transport failed_transport = test_transport(&failed);
    br_scan_ctx failed_ctx = {.transport = &failed_transport};
    out = test_scan(detector, &failed_ctx, true, input, strlen(input));
    CHECK(out.len == 1 && failed.calls == 1 && failed.releases == 1);
    CHECK(!out.items[0].verified);
    CHECK(out.items[0].verification_error && !strcmp(out.items[0].verification_error, "transport failed [REDACTED]"));
    CHECK(!strstr(out.items[0].verification_error, first));
    br_results_clear(&out);

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
static void test_nil_context(const br_detector *v1, const br_detector *v2)
{
    const char *none = "maxmind";
    br_slice empty = {(const unsigned char *)none, strlen(none)};
    for (int capture = 0; capture < 2; ++capture) {
        br_result sentinel = {0};
        unsigned char *raw = NULL;
        char *cause = NULL;
        br_results results = {0};
        keep_prior(&results, &sentinel, &raw, &cause);
        test_http http = {0};
        size_t setters = setter_calls;
        fail_size = 2 * sizeof(br_span);
        fail_after = (size_t)capture + 1; /* 1 is the key FindAll; 2 is the id FindAll. */
        char *error = NULL;
        int rc = v1->scan(v1, NULL, true, empty, &results, &error);
        CHECK(rc != 0 && error && !strcmp(error, "out of memory iterating regex"));
        CHECK(!fail_after && !http.calls && !http.releases && setter_calls == setters);
        prior_unchanged(&results, raw, cause);
        free(error);
        br_results_clear(&results);
    }

    char key[17], input[64];
    v1_key(key, 'E');
    snprintf(input, sizeof(input), "maxmind %s geoip 42", key);
    br_slice slice = {(const unsigned char *)input, strlen(input)};
    const char *v1_messages[] = {
        "out of memory creating MaxMindLicense v1 result",
        "out of memory copying MaxMindLicense account id",
        "cannot store MaxMindLicense metadata",
    };
    for (int mode = 0; mode < 3; ++mode) {
        br_result sentinel = {0};
        unsigned char *raw = NULL;
        char *cause = NULL;
        br_results results = {0};
        keep_prior(&results, &sentinel, &raw, &cause);
        test_http http = {.response = {.status = 200}};
        size_t setters = setter_calls;
        if (mode == 0) fail_part_after = 1;
        else if (mode == 1) fail_strdup_text = "42";
        else fail_extra_after = 1;
        char *error = NULL;
        int rc = v1->scan(v1, NULL, true, slice, &results, &error);
        CHECK(rc != 0 && error && !strcmp(error, v1_messages[mode]));
        CHECK(!fail_part_after && !fail_strdup_text && !fail_extra_after);
        CHECK(!http.calls && !http.releases && setter_calls == setters);
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
    size_t setters = setter_calls;
    char *error = NULL;
    CHECK(v1->scan(v1, NULL, true, slice, &results, &error) == 0 && !error);
    CHECK(!http.calls && !http.releases && setter_calls == setters);
    prior_unchanged(&results, raw, cause);
    br_results_clear(&results);

    const char *no_key = "_mmk";
    br_slice missing = {(const unsigned char *)no_key, strlen(no_key)};
    sentinel = (br_result){0};
    raw = NULL;
    cause = NULL;
    results = (br_results){0};
    keep_prior(&results, &sentinel, &raw, &cause);
    http = (test_http){0};
    setters = setter_calls;
    fail_size = 2 * sizeof(br_span);
    fail_after = 1;
    error = NULL;
    int rc = v2->scan(v2, NULL, true, missing, &results, &error);
    CHECK(rc != 0 && error && !strcmp(error, "out of memory iterating regex"));
    CHECK(!fail_after && !http.calls && !http.releases && setter_calls == setters);
    prior_unchanged(&results, raw, cause);
    free(error);
    br_results_clear(&results);

    char license[41];
    v2_key(license, 'E');
    snprintf(input, sizeof(input), "%s", license);
    slice = (br_slice){(const unsigned char *)input, strlen(input)};
    const char *v2_messages[] = {
        "out of memory creating MaxMindLicense v2 result",
        "cannot store MaxMindLicense metadata",
        "out of memory sanitizing verification error",
    };
    for (int mode = 0; mode < 3; ++mode) {
        sentinel = (br_result){0};
        raw = NULL;
        cause = NULL;
        results = (br_results){0};
        keep_prior(&results, &sentinel, &raw, &cause);
        http = (test_http){.response = {.status = 204}};
        setters = setter_calls;
        if (mode == 0) fail_part_after = 1;
        else if (mode == 1) fail_extra_after = 1;
        else fail_setter = 1;
        error = NULL;
        rc = v2->scan(v2, NULL, true, slice, &results, &error);
        CHECK(rc != 0 && error && !strcmp(error, v2_messages[mode]));
        CHECK(!fail_part_after && !fail_extra_after && !fail_setter);
        CHECK(!http.calls && !http.releases);
        if (mode == 2) CHECK(setter_calls == setters + 1);
        else CHECK(setter_calls == setters);
        prior_unchanged(&results, raw, cause);
        free(error);
        br_results_clear(&results);
    }

    sentinel = (br_result){0};
    raw = NULL;
    cause = NULL;
    results = (br_results){0};
    keep_prior(&results, &sentinel, &raw, &cause);
    http = (test_http){.response = {.status = 204}};
    setters = setter_calls;
    error = NULL;
    CHECK(v2->scan(v2, NULL, true, slice, &results, &error) == 0 && !error);
    CHECK(!http.calls && !http.releases && setter_calls == setters + 1);
    CHECK(results.len == 2 && results.items[0].raw.data == raw);
    CHECK(!results.items[1].verified && !results.items[1].redacted);
    CHECK(results.items[1].verification_error &&
          !strcmp(results.items[1].verification_error, "net/http: nil Context"));
    check_key(&results.items[1], license);
    check_extra(&results.items[1], "2", NULL);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *v1 = v1_descriptor();
    const br_detector *v2 = v2_descriptor();
    test_v1_extraction(v1);
    test_v1_verification(v1);
    test_v2_extraction(v2);
    test_v2_verification(v2);
    test_nil_context(v1, v2);
    return test_finish("MaxMindLicense");
}
