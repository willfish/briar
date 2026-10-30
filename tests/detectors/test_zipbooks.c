/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

static const char email[] = "hi@ex.co";
static const char other_email[] = "a@ex.co";
static const char password[] = "passw0rd";
static const char second[] = "secondok";
static const char body_text[] = "{\"email\": \"hi@ex.co\", \"password\": \"passw0rd\"}";

static int setter_rc, setter_calls;
static int setter_cause_null;
static char setter_cause[96];
static size_t setter_nsecrets, setter_secret_len;
static char setter_secret[64];
static const unsigned char *live_body;
static size_t live_len;

static int (*real_set)(br_result *, const char *, const br_slice *, size_t) = br_result_set_verification_error;

static int observe_set(br_result *result, const char *cause, const br_slice *secrets, size_t nsecrets)
{
    ++setter_calls;
    setter_cause_null = !cause;
    snprintf(setter_cause, sizeof(setter_cause), "%s", cause ? cause : "");
    setter_nsecrets = nsecrets;
    setter_secret_len = 0;
    if (nsecrets == 1 && secrets && secrets[0].data && secrets[0].len < sizeof(setter_secret)) {
        memcpy(setter_secret, secrets[0].data, secrets[0].len);
        setter_secret_len = secrets[0].len;
    }
    if (setter_rc) return setter_rc;
    return real_set(result, cause, secrets, nsecrets);
}

#define br_result_set_verification_error observe_set
#include "../../src/detectors/zipbooks.c"
#undef br_result_set_verification_error

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    CHECK(!strcmp(request->method, "POST") && !strcmp(request->url, "https://api.zipbooks.com/v2/auth/login"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 600);
    CHECK(request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog zipbooks-offline"));
    CHECK(request->body.len == strlen(body_text) && !memcmp(request->body.data, body_text, strlen(body_text)));
    live_body = request->body.data;
    live_len = request->body.len;
}

static void release_body(void *user, br_http_response *response)
{
    CHECK(live_body && live_len == strlen(body_text) && !memcmp(live_body, body_text, live_len));
    live_body = NULL;
    test_http_release(user, response);
}

static void expect_email(const br_result *result, const char *want)
{
    CHECK(result->raw.len == strlen(want) && !memcmp(result->raw.data, want, strlen(want)));
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part));
    CHECK(!strcmp(json_object_get_string(part), want));
    CHECK(!json_object_object_get_ex(result->secret_parts, "email", NULL));
    CHECK(!json_object_object_get_ex(result->secret_parts, "password", NULL));
}

static void reset_setter(void)
{
    setter_rc = 0;
    setter_calls = 0;
    setter_cause_null = 0;
    setter_cause[0] = '\0';
    setter_nsecrets = 99;
    setter_secret_len = 0;
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_zipbooks_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 600 && !strcmp(detector->name, "ZipBooks"));
    CHECK(detector->max_credential_span == 1024 && detector->nkeywords == 1);
    CHECK(!strcmp(detector->keywords[0], "zipbooks"));
    CHECK(!strcmp(detector->description,
        "ZipBooks is an accounting software service that allows businesses to manage their finances online. The credentials can be used to access and manage financial data."));
    CHECK(br_zipbooks_init(NULL, &error) != 0 && error); free(error);

    char input[192];
    snprintf(input, sizeof(input), "%s password %s", email, password);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    expect_email(&results.items[0], email);
    br_results_clear(&results);

    snprintf(input, sizeof(input), "%s %s password %s password %s", email, email, password, second);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    expect_email(&results.items[0], email);
    expect_email(&results.items[1], email);
    br_results_clear(&results);

    snprintf(input, sizeof(input), "%s %s password %s password %s", email, other_email, password, second);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 4);
    expect_email(&results.items[0], email);
    expect_email(&results.items[1], email);
    expect_email(&results.items[2], other_email);
    expect_email(&results.items[3], other_email);
    br_results_clear(&results);

    snprintf(input, sizeof(input), "%s", email);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "zipbooks %s", password);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "%s password passw0r", email);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "%s passwordX%s", email, password);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "%s zipbooks %*s %s", email, 41, "", password);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);

    snprintf(input, sizeof(input), "%s password %s zipbooks", email, password);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    expect_email(&results.items[0], email);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "zipbooks %s password %s", email, password);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    expect_email(&results.items[0], email);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "zipbooks %s%*s password %s", email, 41, "", password);
    test_http http = {.response = {.status = 200}, .inspect = inspect};
    br_transport transport = {&http, test_http_send, release_body};
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "zipbooks-offline"};
    reset_setter();
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
    CHECK(http.calls == 1 && http.releases == 1 && !live_body);
    CHECK(setter_calls == 1 && setter_cause_null && setter_nsecrets == 1 && setter_secret_len == strlen(email));
    CHECK(!memcmp(setter_secret, email, strlen(email)));
    br_results_clear(&results);

    http.response.status = 401; http.calls = http.releases = 0;
    reset_setter();
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    CHECK(setter_calls == 1 && setter_cause_null && http.releases == 1);
    br_results_clear(&results);

    http.response.status = 404; http.calls = http.releases = 0;
    reset_setter();
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    CHECK(setter_calls == 1 && setter_cause_null);
    br_results_clear(&results);

    http.response.status = 403; http.calls = http.releases = 0;
    reset_setter();
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && setter_calls == 1 && !setter_cause_null);
    CHECK(!strcmp(setter_cause, "unexpected status code: 403"));
    CHECK(!strcmp(results.items[0].verification_error, "unexpected status code: 403"));
    br_results_clear(&results);

    char echoed[96];
    snprintf(echoed, sizeof(echoed), "dial %s %s", email, password);
    http.response.status = 200; http.send_rc = 1; http.send_error = echoed; http.calls = http.releases = 0;
    reset_setter();
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && setter_calls == 1 && setter_nsecrets == 1);
    CHECK(strstr(results.items[0].verification_error, "[REDACTED]") && !strstr(results.items[0].verification_error, email));
    CHECK(strstr(results.items[0].verification_error, password));
    br_results_clear(&results);

    http.send_rc = 0;
    http.send_error = NULL;

    reset_setter();
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    CHECK(!strcmp(results.items[0].verification_error, "net/http: nil Context"));
    CHECK(setter_calls == 1 && !setter_cause_null && !strcmp(setter_cause, "net/http: nil Context"));
    CHECK(setter_nsecrets == 1 && setter_secret_len == strlen(email));
    br_results_clear(&results);

    br_result sentinel = {.detector_type = 777, .verified = true};
    sentinel.raw.data = malloc(5); CHECK(sentinel.raw.data);
    memcpy(sentinel.raw.data, "prior", 5); sentinel.raw.len = 5;
    results = (br_results){0};
    CHECK(br_results_push(&results, &sentinel) == 0);
    setter_rc = 1;
    reset_setter();
    setter_rc = 1;
    error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) != 0);
    CHECK(results.len == 1 && results.items[0].detector_type == 777 && results.items[0].raw.len == 5);
    CHECK(!memcmp(results.items[0].raw.data, "prior", 5));
    CHECK(setter_calls == 1);
    free(error);
    br_results_clear(&results);
    setter_rc = 0;
    return test_finish("ZipBooks");
}
