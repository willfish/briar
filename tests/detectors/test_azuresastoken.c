/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

#define BYTES(s) ((br_slice){(const unsigned char *)(s), sizeof(s) - 1})
static const char url[] = "https://example.blob.core.windows.net/container/blob.txt";
static const char token[] = "sp=r&sv=2024-01-02&sr=c&st=2024-01-02T03:04:05Z&sig=abcdefghij";
static const char alternate[] = "sig=KLMNOPQRST&sr=b&sv=2025-02-03&se=2025-02-04T03%3A04%3a05Z&sp=rcwl";
static const char control_error[] = "net/url: invalid control character in URL";
static const char fragment_error[] = "unsupported: Azure SAS query contains a fragment";
static const char ascii_error[] = "unsupported: Azure SAS query outside native ASCII subset";
static const char retry_suffix[] = "&comp=list&restype=container";
static unsigned fail_503_dup;

/* One targeted core +1 allocation failure, not a transport/DNS sentinel.
 * The first matching copy belongs to the provider; the second is the setter. */
char *strdup(const char *text)
{
    if (fail_503_dup && !strcmp(text, "unexpected HTTP response status 503") && !--fail_503_dup) return NULL;
    size_t n = strlen(text) + 1;
    char *copy = malloc(n);
    if (copy) memcpy(copy, text, n);
    return copy;
}

static br_slice text(const char *value)
{
    return (br_slice){(const unsigned char *)value, strlen(value)};
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_azuresastoken_init(NULL, &error) != 0 && error);
    free(error); error = NULL;
    CHECK(!br_azuresastoken_init(&detector, &error) && detector && !error);
    CHECK(!br_azuresastoken_init(&again, NULL) && again == detector);
    CHECK(detector->type == 975 && detector->version == 0 && !strcmp(detector->name, "AzureSasToken"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
        "An Azure Shared Access Signature (SAS) token is a time-limited, permission-based URL query string that grants secure, granular access to Azure Storage resources (e.g., blobs, containers, files) without exposing account keys."));
    CHECK(detector->nkeywords == 2 && !strcmp(detector->keywords[0], "azure") && !strcmp(detector->keywords[1], ".blob.core.windows.net"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->scan && detector->state && detector->false_positive && !detector->clean && !detector->clean_always);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    char *reason = NULL;
    CHECK(!detector->false_positive(detector, NULL, &reason) && reason && !*reason);
    free(reason);
    CHECK(!detector->false_positive(detector, NULL, NULL));
    return detector;
}

static void check_part(br_json *parts, const char *name, br_slice bytes)
{
    br_json *value = NULL;
    CHECK(json_object_object_get_ex(parts, name, &value) && json_object_is_type(value, json_type_string));
    CHECK((size_t)json_object_get_string_len(value) == bytes.len);
    CHECK(!memcmp(json_object_get_string(value), bytes.data, bytes.len));
}

static void check_result(const br_detector *detector, const br_result *result, const char *endpoint,
                          br_slice key, bool verified, const char *error)
{
    size_t n = strlen(endpoint);
    CHECK(result->detector_type == 975 && !result->detector_name);
    CHECK(result->raw.len == n && !memcmp(result->raw.data, endpoint, n));
    CHECK(result->raw_v2.data && result->raw_v2.len == n + key.len);
    CHECK(!memcmp(result->raw_v2.data, endpoint, n));
    CHECK(!memcmp(result->raw_v2.data + n, key.data, key.len)); /* NO separator. */
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    check_part(result->secret_parts, "url", text(endpoint));
    check_part(result->secret_parts, "key", key);
    CHECK(result->verified == verified);
    if (error) CHECK(result->verification_error && !strcmp(result->verification_error, error));
    else CHECK(!result->verification_error);
    CHECK(!result->redacted && !result->extra_data && !result->structured_data && !result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset_set && !result->chunk_offset);
    char *reason = NULL;
    CHECK(!detector->false_positive(detector, result, &reason) && reason && !*reason);
    free(reason);
}

static br_bytes input_for(const char *endpoint, br_slice key)
{
    size_t n = strlen(endpoint);
    br_bytes input = {malloc(n + key.len + 1), n + key.len + 1};
    CHECK(input.data);
    memcpy(input.data, endpoint, n); input.data[n] = '\n';
    memcpy(input.data + n + 1, key.data, key.len);
    return input;
}

static br_results scan_one(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                            const char *endpoint, br_slice key)
{
    br_bytes input = input_for(endpoint, key);
    br_results results = test_scan(detector, ctx, verify, input.data, input.len);
    free(input.data);
    return results;
}

static void expect_extract(const br_detector *detector, const char *endpoint, br_slice input_key,
                             const char *expected_url, br_slice expected_key)
{
    test_http http = {0}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = scan_one(detector, &ctx, false, endpoint, input_key);
    CHECK(results.len == (expected_url ? 1 : 0) && !http.calls && !http.releases);
    if (expected_url) check_result(detector, &results.items[0], expected_url, expected_key, false, NULL);
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    const struct { const char *query; bool valid; } cases[] = {
        {token, true}, {alternate, true},
        {"sp=rr&sv=9999-99-99&sr=o&st=0000-00-00T99:99:99Z&sip=999.999.999.999-000.000.000.000&sig=%%%%%+++++", true},
        {"sp=x&sp=r&sv=2024-01-02&sr=c&st=2024-01-02T03:04:05Z&sig=abcdefghij", true},
        {"sp=r&sv=2024-01-02&sr=c&st=bad&st=2024-01-02T03%3a04%3A05Z&sig=abcdefghij", true},
        {"sp=r&sv=2024-01-02&sr=c&se=2024-01-02T03:04:05Z&sig=abcdefghij", true},
        {"sp=r&sv=2024-01-02&sr=c&st=2024-01-02T03:04:05Z&sig=abcdefghij&spr=https&zz=a%GG+/-._~:9", true},
        {"sv=2024-01-02&sr=c&st=2024-01-02T03:04:05Z&sig=abcdefghij", false},
        {"sp=r&sr=c&st=2024-01-02T03:04:05Z&sig=abcdefghij", false},
        {"sp=r&sv=2024-01-02&st=2024-01-02T03:04:05Z&sig=abcdefghij", false},
        {"sp=r&sv=2024-01-02&sr=c&st=2024-01-02T03:04:05Z", false},
        {"sp=r&sv=2024-01-02&sr=c&sig=abcdefghij", false},
        {"sp=r&sv=2024%2D01%2D02&sr=c&st=2024-01-02T03:04:05Z&sig=abcdefghij", false},
        {"sp=r&sv=2024-01-02&sr=q&st=2024-01-02T03:04:05Z&sig=abcdefghij", false},
        {"sp=r&sv=2024-01-02&sr=c&st=2024-01-02T03:04:05Z&sig=abcdefghi", false},
        {"sp=r&sv=2024-01-02&sr=c&st=2024-01-02T03:04:05Z&sig=abcdefghij&sp=x", false},
        {"sp=r&sv=2024-01-02&sr=c&st=2024-01-02T03:04:05Z&sig=abcdefghij&se=bad", false},
        {"sp=r&sv=2024-01-02&sr=c&st=bad&se=2024-01-02T03:04:05Z&sig=abcdefghij", false},
        {"sp=r&sv=2024-01-02&sr=c&st=2024-01-02T03:04:05Z&sig=abcdefghij&sip=168.1.6", false},
        {"sp=r&sv=2024-01-02&sr=c&st=2024-01-02T03:04:05Z&sig=abcdefghij&sip=bad&sip=168.1.6.50", true},
        {"comp=list&restype=container&maxresults=100", false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
        expect_extract(detector, url, text(cases[i].query), cases[i].valid ? url : NULL, text(cases[i].query));
    char query[256];
    snprintf(query, sizeof(query), "sas=%s", token);
    expect_extract(detector, url, text(query), url, text(token));
    snprintf(query, sizeof(query), "%s==", token);
    expect_extract(detector, url, text(query), url, text(token)); /* Raw padding truncates at literal '='. */
    const struct { const char *input, *expected; } urls[] = {
        {"https://A_b.blob.core.windows.net/a/../Blob_.txt", "https://A_b.blob.core.windows.net/a/../Blob_.txt"},
        {"prefixhttps://abc.blob.core.windows.net/ab/leaf", "https://abc.blob.core.windows.net/a"},
        {"https://abc.blob.core.windows.net/abc-", "https://abc.blob.core.windows.net/abc"},
        {"https://aBc.blob.core.windows.net/container", NULL},
        {"https://ab.blob.core.windows.net/container", NULL},
        {"HTTPS://abc.blob.core.windows.net/container", NULL},
        {"https://abc.BLOB.core.windows.net/container", NULL},
        {"https://abc.blob.core.windows.net/Container", NULL},
    };
    for (size_t i = 0; i < sizeof(urls) / sizeof(urls[0]); ++i)
        expect_extract(detector, urls[i].input, text(token), urls[i].expected, text(token));
}

typedef struct { const char *endpoint; br_slice key; } expected_request;
typedef struct { const expected_request *items; size_t len; } expected_requests;

static void check_request(const br_scan_ctx *ctx, const br_http_request *request, const expected_request *expected)
{
    CHECK(ctx && ctx->transport && !strcmp(request->method, "GET"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 975);
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 1 && !strcmp(request->headers[0].name, "User-Agent"));
    CHECK(!strcmp(request->headers[0].value, "TruffleHog sas-test"));
    size_t n = strlen(expected->endpoint), len = n + 1 + expected->key.len;
    CHECK(strlen(request->url) == len);
    CHECK(!memcmp(request->url, expected->endpoint, n) && request->url[n] == '?');
    CHECK(!memcmp(request->url + n + 1, expected->key.data, expected->key.len));
}

static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    const expected_requests *expected = http->user;
    CHECK(http->calls && http->calls <= expected->len);
    CHECK(http->releases + 1 == http->calls);
    check_request(ctx, request, &expected->items[http->calls - 1]);
}

static void verify_case(const br_detector *detector, const char *endpoint, br_slice key,
                         test_http *http, bool verified, const char *error)
{
    expected_request item = {endpoint, key}; expected_requests requests = {&item, 1};
    http->calls = http->releases = 0; http->inspect = inspect_request; http->user = &requests;
    br_transport transport = test_transport(http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "sas-test"};
    br_results results = scan_one(detector, &ctx, true, endpoint, key);
    CHECK(results.len == 1 && http->calls == 1 && http->releases == 1);
    check_result(detector, &results.items[0], endpoint, key, verified, error);
    br_results_clear(&results);
}

static void status_and_errors(const br_detector *detector)
{
    static const unsigned char body[] = "ignored\0body";
    const int statuses[] = {200, 403, 401, 201, 500};
    for (size_t i = 0; i < 5; ++i) {
        char error[80]; snprintf(error, sizeof(error), "unexpected HTTP response status %d", statuses[i]);
        test_http http = {.response = {.status = statuses[i], .body = {body, sizeof(body) - 1}}};
        verify_case(detector, url, text(token), &http, i == 0, i < 2 ? NULL : error);
    }
    const int read_status[] = {200, 403, 401, 503};
    for (size_t i = 0; i < 4; ++i) {
        test_http http = {.response = {.status = read_status[i], .body = BYTES("Signature did not match"), .body_error = "read failed"}};
        verify_case(detector, url, text(token), &http, false, "read failed");
    }
    test_http http = {.response = {.status = 200}, .send_rc = 1, .send_error = "No such host"};
    verify_case(detector, url, text(token), &http, false, "No such host");
    http.send_error = NULL;
    verify_case(detector, url, text(token), &http, false, "HTTP transport failed");
    char cause[512], redacted[256];
    snprintf(cause, sizeof(cause), "url=%s key=%s again=%s", url, token, token);
    snprintf(redacted, sizeof(redacted), "url=%s key=[REDACTED] again=[REDACTED]", url);
    http = (test_http){.response = {.status = 200, .body_error = cause}};
    verify_case(detector, url, text(token), &http, false, redacted); /* KEY ONLY, not the URL. */
    http.response.body_error = "no such host";
    verify_case(detector, url, text(token), &http, false, "no such host");
    verify_case(detector, url, text(token), &http, false, "no such host"); /* ReadAll does not populate DNS cache. */
    char ip_key[256]; snprintf(ip_key, sizeof(ip_key), "%s&sip=168.1.6.50", token);
    http = (test_http){.response = {.status = 403, .body = BYTES("AuthorizationFailure")}};
    verify_case(detector, url, text(ip_key), &http, false, "SAS token is restricted to specific IP addresses");
    snprintf(ip_key, sizeof(ip_key), "sip=168.1.6.50&%s", token);
    verify_case(detector, url, text(ip_key), &http, false, NULL);
    http.response.body = BYTES("authorizationfailure");
    snprintf(ip_key, sizeof(ip_key), "%s&sip=168.1.6.50", token);
    verify_case(detector, url, text(ip_key), &http, false, NULL);
}

static br_bytes append(br_slice key, br_slice suffix)
{
    br_bytes out = {malloc(key.len + suffix.len), key.len + suffix.len}; CHECK(out.data);
    memcpy(out.data, key.data, key.len); memcpy(out.data + key.len, suffix.data, suffix.len);
    return out;
}

static void byte_gate(const br_detector *detector)
{
    static const unsigned char nul_x[] = "&zz=\0x", nul_y[] = "&zz=\0y", vt[] = "&zz=\vx";
    static const unsigned char fragment[] = "&zz=prefix#\0\v\177";
    br_bytes x = append(text(token), (br_slice){nul_x, sizeof(nul_x) - 1});
    br_bytes y = append(text(token), (br_slice){nul_y, sizeof(nul_y) - 1});
    br_bytes vertical = append(text(token), (br_slice){vt, sizeof(vt) - 1});
    br_bytes frag = append(text(token), (br_slice){fragment, sizeof(fragment) - 1});
    const br_slice keys[] = {{x.data, x.len}, {y.data, y.len}, {x.data, x.len}, {vertical.data, vertical.len}, {frag.data, frag.len}, BYTES(token)};
    size_t size = strlen(url) + 1;
    for (size_t i = 0; i < 6; ++i) size += keys[i].len + 1;
    unsigned char *input = malloc(size); CHECK(input);
    size_t at = strlen(url); memcpy(input, url, at); input[at++] = '\n';
    for (size_t i = 0; i < 6; ++i) { memcpy(input + at, keys[i].data, keys[i].len); at += keys[i].len; input[at++] = '\n'; }
    CHECK(at == size);
    expected_request item = {url, text(token)}; expected_requests requests = {&item, 1};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &requests};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "sas-test"};
    const size_t unique[] = {0, 1, 3, 4, 5};
    for (int verify = 0; verify <= 1; ++verify) {
        br_results results = test_scan(detector, &ctx, verify, input, size);
        CHECK(results.len == 5 && http.calls == (verify ? 1 : 0) && http.releases == http.calls);
        for (size_t i = 0; i < 5; ++i) {
            const char *error = !verify || i == 4 ? NULL : i == 3 ? fragment_error : control_error;
            check_result(detector, &results.items[i], url, keys[unique[i]], verify && i == 4, error);
        }
        br_results_clear(&results);
    } /* Full bytes beyond NUL distinguish keys; unsafe candidates never stop the good pair. */
    const struct { const char *suffix, *error; } cases[] = {
        {"&zz=\177", control_error}, {"&zz=\0#tail", control_error},
        {"&zz=#%GG", fragment_error}, {"&zz=π", ascii_error}, {"&zz=a;b", ascii_error},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        br_slice suffix = i == 1 ? BYTES("&zz=\0#tail") : text(cases[i].suffix);
        br_bytes value = append(text(token), suffix);
        expect_extract(detector, url, (br_slice){value.data, value.len}, url, (br_slice){value.data, value.len});
        http.calls = http.releases = 0;
        br_results results = scan_one(detector, &ctx, true, url, (br_slice){value.data, value.len});
        CHECK(results.len == 1 && !http.calls && !http.releases);
        check_result(detector, &results.items[0], url, (br_slice){value.data, value.len}, false, cases[i].error);
        br_results_clear(&results); free(value.data);
    }
    br_results results = scan_one(detector, NULL, true, url, (br_slice){x.data, x.len});
    CHECK(results.len == 1);
    check_result(detector, &results.items[0], url, (br_slice){x.data, x.len}, false, "net/http: nil Context");
    br_results_clear(&results);
    free(input); free(x.data); free(y.data); free(vertical.data); free(frag.data);
    br_bytes supported = append(text(token), BYTES("&zz=a%GG+/-._~:9"));
    http = (test_http){.response = {.status = 200}};
    verify_case(detector, url, (br_slice){supported.data, supported.len}, &http, true, NULL);
    free(supported.data);
}

typedef struct {
    const char *endpoint;
    br_slice key, extended;
    int inner_status;
    br_slice inner_body;
    const char *inner_error;
    size_t sent, released;
} retry_http;
static const br_header outer_tag[] = {{"test", "outer"}}, inner_tag[] = {{"test", "inner"}};

static int send_retry(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                        br_http_response *response, char **error)
{
    retry_http *http = user; ++http->sent;
    CHECK(http->sent <= 2 && http->released == 0); /* Outer MUST still be held at inner send. */
    expected_request expected = {http->endpoint, http->sent == 1 ? http->key : http->extended};
    check_request(ctx, request, &expected);
    *error = NULL;
    *response = http->sent == 1 ?
        (br_http_response){.status = 403, .headers = outer_tag, .nheaders = 1,
            .body = BYTES("Signature did not match\0AuthorizationFailure")} :
        (br_http_response){.status = http->inner_status, .headers = inner_tag, .nheaders = 1,
            .body = http->inner_body, .body_error = http->inner_error};
    return 0;
}

static void release_retry(void *user, br_http_response *response)
{
    retry_http *http = user;
    CHECK(http->sent == 2);
    CHECK(response->headers == (http->released == 0 ? inner_tag : outer_tag));
    ++http->released;
}

static void recursion(const br_detector *detector)
{
    char value[256]; snprintf(value, sizeof(value), "%s&comp=existing&sip=168.1.6.50", token);
    br_bytes extended = append(text(value), text(retry_suffix));
    char nested_error[512], nested_redacted[256];
    snprintf(nested_error, sizeof(nested_error), "nested url=%s?%s%s", url, value, retry_suffix);
    snprintf(nested_redacted, sizeof(nested_redacted), "nested url=%s?[REDACTED]%s", url, retry_suffix);
    const struct { int status; br_slice body; const char *read_error, *error; bool verified; } cases[] = {
        {200, {0}, NULL, NULL, true},
        {403, BYTES("Signature did not match"), NULL, NULL, false},
        {403, BYTES("Signature did not match AuthorizationFailure"), NULL, "SAS token is restricted to specific IP addresses", false},
        {200, {0}, "inner read failed", "inner read failed", false},
        {200, {0}, nested_error, nested_redacted, false}, /* Redact ORIGINAL key, retain retry tail. */
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        retry_http http = {.endpoint = url, .key = text(value), .extended = {extended.data, extended.len},
            .inner_status = cases[i].status, .inner_body = cases[i].body, .inner_error = cases[i].read_error};
        br_transport transport = {&http, send_retry, release_retry};
        br_scan_ctx ctx = {.transport = &transport, .user_agent = "sas-test"};
        br_results results = scan_one(detector, &ctx, true, url, text(value));
        CHECK(results.len == 1 && http.sent == 2 && http.released == 2);
        check_result(detector, &results.items[0], url, text(value), cases[i].verified, cases[i].error);
        br_results_clear(&results);
    }
    free(extended.data);
}

static void products_and_cache(const br_detector *detector)
{
    const char first[] = "https://Cache_a.blob.core.windows.net/alpha";
    const char same[] = "https://Cache_a.blob.core.windows.net/bravo";
    const char lower[] = "https://cache_a.blob.core.windows.net/charlie";
    char input[768];
    snprintf(input, sizeof(input), "%s\n%s\n%s\n%s\n%s\n%s\n%s", first, same, lower, first, token, alternate, token);
    const char *urls[] = {first, same, lower}; const char *keys[] = {token, alternate};
    expected_request all[6];
    for (size_t u = 0; u < 3; ++u) for (size_t k = 0; k < 2; ++k) all[u * 2 + k] = (expected_request){urls[u], text(keys[k])};
    expected_requests expected = {all, 6};
    test_http http = {.response = {.status = 200}, .inspect = inspect_request, .user = &expected};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .user_agent = "sas-test"};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 6 && http.calls == 6 && http.releases == 6);
    for (size_t i = 0; i < 6; ++i) check_result(detector, &results.items[i], all[i].endpoint, all[i].key, true, NULL);
    br_results_clear(&results);
    expected_request dns[] = {{first, text(token)}, {lower, text(token)}};
    expected = (expected_requests){dns, 2};
    http = (test_http){.send_rc = 1, .send_error = "lookup synthetic: no such host", .inspect = inspect_request, .user = &expected};
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.len && http.calls == 2 && http.releases == 2);
    br_results_clear(&results); /* Same account/different path suppressed; different CASE still attempted. */
    http.calls = http.releases = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.len && !http.calls && !http.releases);
    br_results_clear(&results);
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 6 && !http.calls && !http.releases);
    for (size_t i = 0; i < 6; ++i) check_result(detector, &results.items[i], all[i].endpoint, all[i].key, false, NULL);
    br_results_clear(&results);
}

static bool cancelled(void *user) { (void)user; return true; }

static void context_and_resource(const br_detector *detector)
{
    test_http http = {.response = {.status = 200}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .cancelled = cancelled};
    br_results results = scan_one(detector, &ctx, true, url, text(token));
    CHECK(results.len == 1 && !http.calls && http.releases == 1);
    check_result(detector, &results.items[0], url, text(token), false, "context canceled");
    br_results_clear(&results);
    const char fresh[] = "https://setteroom.blob.core.windows.net/container";
    br_bytes input = input_for(fresh, text(token));
    expected_request item = {fresh, text(token)}; expected_requests expected = {&item, 1};
    http = (test_http){.response = {.status = 503}, .inspect = inspect_request, .user = &expected};
    ctx = (br_scan_ctx){.transport = &transport, .user_agent = "sas-test"};
    char *error = NULL;
    fail_503_dup = 2;
    int rc = detector->scan(detector, &ctx, true, (br_slice){input.data, input.len}, &results, &error);
    CHECK(rc == -1 && error && !strcmp(error, "out of memory recording Azure SAS verification error"));
    CHECK(!fail_503_dup && !results.len && http.calls == 1 && http.releases == 1);
    free(error); br_results_clear(&results); free(input.data);
    http = (test_http){.response = {.status = 503}};
    verify_case(detector, fresh, text(token), &http, false, "unexpected HTTP response status 503");
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    status_and_errors(detector);
    byte_gate(detector);
    recursion(detector);
    products_and_cache(detector);
    context_and_resource(detector);
    return test_finish("AzureSasToken");
}
