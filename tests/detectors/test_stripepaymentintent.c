/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/json.h"
#include "../support/detector_test.h"

static int force_json;
static int (*real_first_document)(br_slice, const char *, br_json **, size_t *, char **) = br_json_first_document;
static int first_hook(br_slice body, const char *read_error, br_json **out, size_t *end, char **cause)
{
    if (force_json) { *out = NULL; if (end) *end = 0; *cause = NULL; return force_json; }
    return real_first_document(body, read_error, out, end, cause);
}
#define br_json_first_document first_hook
#include "../../src/detectors/stripepaymentintent.c"
#undef br_json_first_document

static int stripe_type_calls, stripe_type_fatal_after;
static int stripe_type_hook(br_json *value, char **cause)
{
    ++stripe_type_calls;
    if (stripe_type_fatal_after && stripe_type_calls >= stripe_type_fatal_after) {
        if (cause) *cause = NULL;
        return -1;
    }
    return stripe_type_cause_real(value, cause);
}

static const char secret[] = "pi_3MtwBwLkdIwHu7ix28a3tqPa_secret_YrKJUKribcBjcG8HVhf123456";
static const char sk[] = "sk_live_0123456789abcdefghij";
static const char rk[] = "rk_live_0123456789abcdefghij";
static const char pk[] = "pk_live_0123456789abcdefghij";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    int mode = http->user ? *(int *)http->user : 0;
    bool publishable = mode == 1 || (mode == 2 && http->calls > 1);
    CHECK(request->timeout_ms == 5000 && !strcmp(request->method, "GET"));
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 1027 && !request->body.len);
    CHECK(!ctx->cancelled && !strcmp(ctx->user_agent, "stripe-offline"));
    if (!publishable) {
        char url[80];
        snprintf(url, sizeof(url), "https://api.stripe.com/v1/payment_intents/%.27s", secret);
        char *authorization = malloc(sizeof("Bearer ") + strlen(sk));
        CHECK(authorization);
        sprintf(authorization, "Bearer %s", mode == 3 ? rk : sk);
        CHECK(!strcmp(request->url, url) && request->nheaders == 3);
        CHECK(!strcmp(request->headers[0].name, "Authorization") && !strcmp(request->headers[0].value, authorization));
        CHECK(!strcmp(request->headers[1].name, "Content-Type") &&
              !strcmp(request->headers[1].value, "application/x-www-form-urlencoded"));
        CHECK(!strcmp(request->headers[2].name, "User-Agent") &&
              !strcmp(request->headers[2].value, "TruffleHog stripe-offline"));
        free(authorization);
    } else {
        char url[220];
        snprintf(url, sizeof(url),
                 "https://api.stripe.com/v1/payment_intents/%.27s?key=%s&client_secret=%s", secret, pk, secret);
        CHECK(!strcmp(request->url, url) && request->nheaders == 1);
        CHECK(!strcmp(request->headers[0].name, "User-Agent"));
    }
}

static void check_pair(const br_result *result, const char *key, const char *kind)
{
    CHECK(result->detector_type == 1027 && !result->verified && !result->verification_error);
    CHECK(result->raw.len == strlen(secret) && !memcmp(result->raw.data, secret, strlen(secret)));
    CHECK(result->raw_v2.len == strlen(secret) + strlen(key));
    CHECK(!memcmp(result->raw_v2.data, secret, strlen(secret)));
    CHECK(!memcmp(result->raw_v2.data + strlen(secret), key, strlen(key)));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "client_secret", &part) &&
          !strcmp(json_object_get_string(part), secret));
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) &&
          !strcmp(json_object_get_string(part), key));
    CHECK(result->extra_data && json_object_object_get_ex(result->extra_data, "key_type", &part) &&
          !strcmp(json_object_get_string(part), kind));
    CHECK(!result->redacted && !result->primary_secret.data);
}

int main(void)
{
    CHECK(strlen(secret) == 27 + 8 + 25 && strlen(sk) == 28 && strlen(pk) == 28);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_stripepaymentintent_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 1027 && !strcmp(detector->name, "StripePaymentIntent"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "_secret_"));
    CHECK(detector->max_credential_span == -1);
    CHECK(br_stripepaymentintent_init(NULL, &error) != 0 && error); free(error);
    char input[320];
    snprintf(input, sizeof(input), "%s %s", secret, sk);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1); check_pair(&results.items[0], sk, "secret");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "%s %s", secret, pk);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1); check_pair(&results.items[0], pk, "publishable");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "%s %s %s", secret, sk, pk);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    check_pair(&results.items[0], sk, "secret");
    check_pair(&results.items[1], pk, "publishable");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "%s %s", secret, rk);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1); check_pair(&results.items[0], rk, "secret");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "%s %s %s", secret, secret, sk);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1); br_results_clear(&results);
    snprintf(input, sizeof(input), "%s", secret);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "sk_live_0123456789abcdefghi %s", secret);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);

    char body[160];
    snprintf(body, sizeof(body), "{\"client_secret\":\"%s\"}", secret);
    int mode = 0;
    test_http http = {.response = {.status = 200, .body = {(const unsigned char *)body, strlen(body)}},
                      .inspect = inspect, .user = &mode};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "stripe-offline"};
    snprintf(input, sizeof(input), "%s %s", secret, sk);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1 && http.releases == 1);
    br_results_clear(&results);
    static const char mismatch[] = "{\"client_secret\":\"other\"}";
    http.response.body = (br_slice){(const unsigned char *)mismatch, sizeof(mismatch) - 1};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.body = (br_slice){(const unsigned char *)"null", 4};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.body = (br_slice){(const unsigned char *)"\"nope\"", 6};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !strcmp(results.items[0].verification_error,
          "failed to decode response body: json: cannot unmarshal string into Go value of type struct { ClientSecret string \"json:\\\"client_secret\\\"\" }"));
    br_results_clear(&results);
    static const char number_field[] = "{\"client_secret\":1}";
    http.response.body = (br_slice){(const unsigned char *)number_field, sizeof(number_field) - 1};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !strcmp(results.items[0].verification_error,
          "failed to decode response body: json: cannot unmarshal number into Go struct field .client_secret of type string"));
    br_results_clear(&results);
    static const char overwritten[] = "{\"client_secret\":1,\"client_secret\":true}";
    http.response.body = (br_slice){(const unsigned char *)overwritten, sizeof(overwritten) - 1};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !strcmp(results.items[0].verification_error,
          "failed to decode response body: json: cannot unmarshal number into Go struct field .client_secret of type string"));
    br_results_clear(&results);
    char kept_secret[160];
    snprintf(kept_secret, sizeof(kept_secret), "{\"client_secret\":\"%s\",\"client_secret\":null}", secret);
    http.response.body = (br_slice){(const unsigned char *)kept_secret, strlen(kept_secret)};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    char nul_secret[180];
    snprintf(nul_secret, sizeof(nul_secret), "{\"client_secret\":\"%s\\u0000extra\"}", secret);
    http.response.body = (br_slice){(const unsigned char *)nul_secret, strlen(nul_secret)};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    stripe_type_cause = stripe_type_hook;
    stripe_type_calls = 0; stripe_type_fatal_after = 2;
    http.response.body = (br_slice){(const unsigned char *)overwritten, sizeof(overwritten) - 1};
    char *typed_error = NULL;
    br_results typed_failed = {0};
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)},
                         &typed_failed, &typed_error) != 0);
    CHECK(!typed_failed.len && stripe_type_calls >= 2);
    free(typed_error);
    br_results_clear(&typed_failed);
    stripe_type_cause = stripe_type_cause_real;
    stripe_type_calls = stripe_type_fatal_after = 0;
    http.response.body = (br_slice){0};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !strcmp(results.items[0].verification_error, "failed to decode response body: EOF"));
    br_results_clear(&results);
    http.response.status = 401; http.response.body = (br_slice){(const unsigned char *)body, strlen(body)};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.status = 404; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.status = 403; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !strcmp(results.items[0].verification_error, "unexpected status code: 403"));
    br_results_clear(&results);
    http.response.status = 200; http.send_rc = 1; http.send_error = "dial sk_live_echo";
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !strcmp(results.items[0].verification_error, "request failed: dial sk_live_echo"));
    br_results_clear(&results);
    http.send_rc = 0; http.send_error = NULL; mode = 1; http.calls = http.releases = 0;
    snprintf(input, sizeof(input), "%s %s", secret, pk);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && !strcmp(results.items[0].verification_error, "error creating request: net/http: nil Context"));
    br_results_clear(&results);
    force_json = 2;
    char *scan_error = NULL;
    br_results failed = {0};
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &failed, &scan_error) != 0);
    CHECK(!failed.len);
    free(scan_error);
    br_results_clear(&failed);
    return test_finish("StripePaymentIntent");
}
