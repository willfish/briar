/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
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
#include "../../src/detectors/shopify.c"
#undef br_json_first_document

static const char key[] = "shpat_0123456789abcdef0123456789abcdef";
static const char other[] = "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";
static const char domain[] = "acme.myshopify.com";
static const char domain2[] = "beta.myshopify.com";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://acme.myshopify.com/admin/oauth/access_scopes.json"));
    CHECK(request->profile == BR_HTTP_DETECTOR_PUBLIC && request->timeout_ms == 10000);
    CHECK(request->detector_type == 902 && request->nheaders == 2);
    CHECK(!strcmp(request->headers[0].name, "X-Shopify-Access-Token") && !strcmp(request->headers[0].value, key));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, "TruffleHog shopify-offline"));
}

static void check_pair(const br_result *result, const char *api, const char *store)
{
    CHECK(result->detector_type == 902 && !result->verified && !result->verification_error);
    CHECK(result->raw.len == strlen(api) + strlen(store));
    CHECK(!memcmp(result->raw.data, api, strlen(api)));
    CHECK(!memcmp(result->raw.data + strlen(api), store, strlen(store)));
    CHECK(result->redacted && !strcmp(result->redacted, store));
    CHECK(result->primary_secret.len == strlen(api) && !memcmp(result->primary_secret.data, api, strlen(api)));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && !strcmp(json_object_get_string(part), api));
    CHECK(json_object_object_get_ex(result->secret_parts, "store_url", &part) && !strcmp(json_object_get_string(part), store));
    CHECK(!result->raw_v2.data && !result->extra_data);
}

int main(void)
{
    CHECK(strlen(key) == 38 && strlen(other) == 38);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_shopify_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 902 && !strcmp(detector->name, "Shopify"));
    CHECK(detector->nkeywords == 2 && !strcmp(detector->keywords[0], "shppa_") && !strcmp(detector->keywords[1], "shpat_"));
    CHECK(detector->max_credential_span == 1024 && detector->false_positive);
    char *reason = (char *)"untouched";
    CHECK(!detector->false_positive(detector, NULL, &reason) && !reason);
    CHECK(!strcmp(detector->description,
        "An ecommerce platform, API keys can be used to access customer data"));
    CHECK(br_shopify_init(NULL, &error) != 0 && error); free(error);
    char input[256];
    snprintf(input, sizeof(input), "%s %s", key, domain);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1); check_pair(&results.items[0], key, domain);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "%s %s %s %s", key, other, domain, domain2);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 4);
    check_pair(&results.items[0], key, domain);
    check_pair(&results.items[1], key, domain2);
    check_pair(&results.items[2], other, domain);
    check_pair(&results.items[3], other, domain2);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "%s prefixacme.myshopify.com", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1 && !strcmp(results.items[0].redacted, "prefixacme.myshopify.com"));
    br_results_clear(&results);
    const char *body = "{\"access_scopes\":[{\"handle\":\"read_orders\"},{\"handle\":\"write_orders\"}]}";
    test_http http = {.response = {.status = 200, .body = {(const unsigned char *)body, strlen(body)}}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "shopify-offline"};
    snprintf(input, sizeof(input), "%s %s", key, domain);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && http.calls == 1 && http.releases == 1);
    br_json *scopes = NULL;
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "access_scopes", &scopes));
    CHECK(!strcmp(json_object_get_string(scopes), "read_orders,write_orders"));
    br_results_clear(&results);
    http.response.status = 401; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].extra_data);
    br_results_clear(&results);
    http.response.status = 200;
    http.response.body = (br_slice){(const unsigned char *)"not-json", 8};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].extra_data && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.body = (br_slice){(const unsigned char *)"{\"access_scopes\":[null]}", 24};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified);
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "access_scopes", &scopes));
    CHECK(!strcmp(json_object_get_string(scopes), ""));
    br_results_clear(&results);
    http.send_rc = 1; http.send_error = "dial shopify"; http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    force_json = 2;
    http.send_rc = 0; http.send_error = NULL; http.response.status = 200;
    http.response.body = (br_slice){(const unsigned char *)"{}", 2};
    char *scan_error = NULL;
    br_results failed = {0};
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &failed, &scan_error) != 0);
    CHECK(!failed.len);
    free(scan_error);
    br_results_clear(&failed);

    force_json = 0;
    http.send_rc = 0; http.send_error = NULL; http.response.status = 200;
    const char *sticky = "{\"access_scopes\":3,\"access_scopes\":[{\"handle\":\"read_products\"}]}";
    http.response.body = (br_slice){(const unsigned char *)sticky, strlen(sticky)};
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].extra_data &&
          !results.items[0].verification_error);
    br_results_clear(&results);

    const char *typed = "{\"access_scopes\":[{\"handle\":1,\"handle\":\"read_products\"}]}";
    http.response.body = (br_slice){(const unsigned char *)typed, strlen(typed)};
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 9, "kept", "key") == 0);
    br_results kept = {0};
    CHECK(br_results_push(&kept, &prior) == 0);
    scan_error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)},
                         &kept, &scan_error) == 0 && !scan_error);
    CHECK(kept.len == 2 && kept.items[0].detector_type == 9 && !kept.items[1].verified &&
          !kept.items[1].extra_data && !kept.items[1].verification_error);
    br_results_clear(&kept);
    br_result_clear(&prior);

    const char *preserved = "{\"access_scopes\":[{\"handle\":\"read_products\",\"handle\":null}]}";
    http.response.body = (br_slice){(const unsigned char *)preserved, strlen(preserved)};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.items[0].verified);
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "access_scopes", &scopes));
    CHECK(!strcmp(json_object_get_string(scopes), "read_products"));
    br_results_clear(&results);

    const char *reused =
        "{\"access_scopes\":[{\"handle\":\"read_products\"},{\"handle\":\"write_orders\"}],"
        "\"access_scopes\":[{\"handle\":\"keep\"}],"
        "\"access_scopes\":[{},{}]}";
    http.response.body = (br_slice){(const unsigned char *)reused, strlen(reused)};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.items[0].verified);
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "access_scopes", &scopes));
    CHECK(!strcmp(json_object_get_string(scopes), "keep,write_orders"));
    br_results_clear(&results);

    const char *fresh =
        "{\"access_scopes\":[{\"handle\":\"read_products\"}],\"access_scopes\":[],\"access_scopes\":[{}]}";
    http.response.body = (br_slice){(const unsigned char *)fresh, strlen(fresh)};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.items[0].verified);
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "access_scopes", &scopes));
    CHECK(!strcmp(json_object_get_string(scopes), ""));
    br_results_clear(&results);

    const char nul_body[] = "{\"access_scopes\":[{\"handle\":\"a\\u0000b\"},{\"handle\":\"c\"}]}";
    http.response.body = (br_slice){(const unsigned char *)nul_body, sizeof(nul_body) - 1};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.items[0].verified);
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "access_scopes", &scopes));
    const char joined[] = {'a', '\0', 'b', ',', 'c'};
    CHECK((size_t)json_object_get_string_len(scopes) == sizeof(joined));
    CHECK(!memcmp(json_object_get_string(scopes), joined, sizeof(joined)));
    br_results_clear(&results);

    http.response.body = (br_slice){(const unsigned char *)"null", 4};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.items[0].verified && !results.items[0].verification_error);
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "access_scopes", &scopes));
    CHECK(!strcmp(json_object_get_string(scopes), ""));
    br_results_clear(&results);
    return test_finish("Shopify");
}
