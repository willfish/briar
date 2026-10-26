/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/aws_common.h"
#include "../support/detector_test.h"
#include <inttypes.h>
#include <strings.h>
#include <time.h>

/* Only the clock is interposed. All credentials are generated synthetic text,
 * and every scan uses the injected transport below, never a native client. */
static time_t fixed_time = 1704164645;
int clock_gettime(clockid_t clock, struct timespec *out)
{
    *out = (struct timespec){clock == CLOCK_MONOTONIC ? 1000 : fixed_time, 0};
    return 0;
}

static char id1[21], id2[21], secret1[41], secret2[41], token1[132], token2[132];
static const char endpoint[] = "https://sts.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15";
static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char identity[] = "{\"GetCallerIdentityResponse\":{\"GetCallerIdentityResult\":{\"Account\":\"999999999999\",\"Arn\":\"synthetic-arn\",\"UserId\":\"synthetic-user\"},\"ResponseMetadata\":{\"RequestId\":\"unused\"}}}";
static const char expired[] = "{\"Error\":{\"Code\":\"eXpIrEdToKeN\",\"Message\":\"synthetic denial\"}}";

static void make_token(char *out, size_t len, unsigned shift, const char *marker, size_t padding)
{
    CHECK(len >= strlen(marker) && padding <= 4);
    for (size_t i = 0; i < len; ++i) out[i] = alphabet[(i * 17 + shift) % 64];
    memcpy(out, marker, strlen(marker));
    memset(out + len, '=', padding);
    out[len + padding] = '\0';
}

static void make_id(char out[21], uint64_t account, unsigned seed)
{
    static const char base32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    CHECK(account < (UINT64_C(1) << 40));
    for (unsigned attempt = 0; attempt < 256; ++attempt) {
        unsigned char raw[10];
        uint64_t first = UINT64_C(0x800000000000) | (account << 7) | ((seed + attempt) & 127);
        for (size_t i = 0; i < 6; ++i) raw[i] = (unsigned char)(first >> (8 * (5 - i)));
        for (size_t i = 6; i < 10; ++i) raw[i] = (unsigned char)((seed + attempt) * 37 + i * 53);
        memcpy(out, "ASIA", 4);
        unsigned buffer = 0, bits = 0;
        size_t at = 4;
        for (size_t i = 0; i < sizeof(raw); ++i) {
            buffer = (buffer << 8) | raw[i]; bits += 8;
            while (bits >= 5) { bits -= 5; out[at++] = base32[(buffer >> bits) & 31]; }
            buffer &= (1u << bits) - 1;
        }
        out[20] = '\0';
        if (br_ascii_shannon_entropy((br_slice){(const unsigned char *)out, 20}) >= 3.0) return;
    }
    CHECK(!"cannot construct synthetic ID");
}

static void check_text(br_json *object, const char *name, const char *expected)
{
    br_json *value = NULL;
    CHECK(json_object_object_get_ex(object, name, &value));
    CHECK(json_object_is_type(value, json_type_string));
    CHECK((size_t)json_object_get_string_len(value) == strlen(expected));
    CHECK(!memcmp(json_object_get_string(value), expected, strlen(expected)));
}

static void check_result(const br_result *result, const char *id, const char *secret, const char *token)
{
    CHECK(result->detector_type == 959 && !result->detector_name);
    CHECK(result->raw.len == 20 && !memcmp(result->raw.data, id, 20));
    CHECK(result->raw_v2.len == 62 + strlen(token));
    CHECK(!memcmp(result->raw_v2.data, id, 20) && result->raw_v2.data[20] == ':');
    CHECK(!memcmp(result->raw_v2.data + 21, secret, 40) && result->raw_v2.data[61] == ':');
    CHECK(!memcmp(result->raw_v2.data + 62, token, strlen(token)));
    CHECK(result->redacted && !strcmp(result->redacted, id));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 3);
    check_text(result->secret_parts, "access_key_id", id);
    check_text(result->secret_parts, "secret_access_key", secret);
    check_text(result->secret_parts, "session_token", token);
    CHECK(result->extra_data && !json_object_object_get_ex(result->extra_data, "resource_type", NULL));
    CHECK(!json_object_object_get_ex(result->extra_data, "is_canary", NULL));
    CHECK(!json_object_object_get_ex(result->extra_data, "message", NULL));
    CHECK(!result->structured_data && !result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static const br_detector *init(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_aws_session_keys_init(NULL, &error) != 0 && error);
    CHECK(!strcmp(error, "invalid AWS session key detector output"));
    free(error); error = NULL;
    CHECK(!br_aws_session_keys_init(&detector, &error) && !error && detector);
    CHECK(!br_aws_session_keys_init(&again, &error) && !error && again == detector);
    CHECK(detector->type == 959 && detector->version == 0);
    CHECK(!strcmp(detector->name, "AWSSessionKey") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. "
        "API keys for AWS can have varying amount of access to these services depending on the IAM policy attached. AWS Session Tokens are short-lived keys."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "ASIA"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 2048);
    CHECK(detector->state && detector->scan && detector->clean == br_aws_clean && detector->clean_always);
    CHECK(!detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

typedef struct {
    br_http_response steps[16];
    br_header tags[16];
    const char *errors[16];
    size_t count, calls, releases, order[16];
    bool released[16], hold_first;
    const char *expected_token, *signature, *date;
    const br_json *options;
    char ids[16][21];
} fake_http;

static const char *header(const br_http_request *request, const char *name)
{
    for (size_t i = 0; i < request->nheaders; ++i)
        if (!strcasecmp(request->headers[i].name, name)) return request->headers[i].value;
    return NULL;
}

static int send_fake(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                       br_http_response *response, char **error)
{
    fake_http *fake = user;
    size_t at = fake->calls++;
    CHECK(ctx && at < fake->count && at < 16);
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 959 && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, endpoint));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.len);
    CHECK(request->nheaders == 5 && !strcmp(header(request, "Accept"), "application/json"));
    CHECK(!strcmp(header(request, "User-Agent"), "TruffleHog"));
    CHECK(!header(request, "Amz-Sdk-Invocation-Id") && !header(request, "Amz-Sdk-Request"));
    CHECK(!header(request, "X-Amz-Content-Sha256") && !header(request, "Content-Type") && !header(request, "Content-Length"));
    const char *token = header(request, "x-amz-security-token");
    const char *auth = header(request, "Authorization");
    const char *date = header(request, "x-amz-date");
    CHECK(token && strlen(token) >= 100 && auth && date);
    CHECK(!strcmp(date, fake->date ? fake->date : "20240102T030405Z"));
    CHECK(strstr(auth, "SignedHeaders=host;x-amz-date;x-amz-security-token, Signature="));
    const char *credential = strstr(auth, "Credential=");
    CHECK(credential && strlen(credential) > 31);
    memcpy(fake->ids[at], credential + 11, 20); fake->ids[at][20] = '\0';
    if (fake->expected_token) CHECK(!strcmp(token, fake->expected_token));
    if (fake->signature) CHECK(!strcmp(auth + strlen(auth) - 64, fake->signature));
    if (fake->hold_first && at == 1) CHECK(fake->releases == 0 && !fake->released[0]);
    *response = fake->steps[at];
    response->headers = &fake->tags[at]; response->nheaders = 1;
    *error = fake->errors[at] ? strdup(fake->errors[at]) : NULL;
    CHECK(!fake->errors[at] || *error);
    return fake->errors[at] ? -1 : 0;
}

static void release_fake(void *user, br_http_response *response)
{
    fake_http *fake = user;
    size_t at = 0;
    while (at < fake->calls && response->headers != &fake->tags[at]) ++at;
    CHECK(at < fake->calls && !fake->released[at]);
    fake->released[at] = true;
    fake->order[fake->releases++] = at;
}

static br_http_response response(int status, const char *body)
{
    return (br_http_response){.status = status, .body = {(const unsigned char *)body, strlen(body)}};
}

static br_results scan(const br_detector *detector, const char *input, bool verify, fake_http *fake)
{
    br_transport transport = {fake, send_fake, release_fake};
    br_scan_ctx ctx = {.transport = &transport, .options = fake->options};
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(fake->calls == fake->count && fake->releases == fake->calls);
    return results;
}

static void extraction(const br_detector *detector)
{
    char input[4096], token[160];
    snprintf(input, sizeof(input), "%s\n%s \n%s", id1, secret1, token1);
    fake_http fake = {0};
    br_results results = scan(detector, input, false, &fake);
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    check_result(&results.items[0], id1, secret1, token1);
    CHECK(json_object_object_length(results.items[0].extra_data) == 1);
    check_text(results.items[0].extra_data, "account", "123456789012");
    br_results_clear(&results);

    snprintf(input, sizeof(input), "%s\n%s \n%s\n%s\n%s \n%s", id1, secret1, token1, id1, secret1, token1);
    results = scan(detector, input, false, &fake);
    CHECK(results.len == 1); br_results_clear(&results);
    const char *missing[] = {"", id1, secret1, token1};
    for (size_t i = 0; i < 4; ++i) {
        results = scan(detector, missing[i], false, &fake);
        CHECK(!results.len); br_results_clear(&results);
    }
    for (size_t padding = 0; padding <= 4; ++padding) {
        make_token(token, 100, 13, "YXdz", padding);
        snprintf(input, sizeof(input), "%s\n%s \n=%s", id1, secret1, token);
        results = scan(detector, input, false, &fake);
        CHECK(results.len == (padding <= 3 ? 1u : 0u));
        if (results.len) check_result(&results.items[0], id1, secret1, token);
        br_results_clear(&results);
    }
    make_token(token, 99, 13, "YXdz", 0);
    snprintf(input, sizeof(input), "%s\n%s \n%s", id1, secret1, token);
    results = scan(detector, input, false, &fake); CHECK(!results.len); br_results_clear(&results);
    make_token(token, 101, 19, "Jb3JpZ2luX2Vj", 3); /* Not structurally validated Base64. */
    snprintf(input, sizeof(input), "%s\n%s \n%s", id1, secret1, token);
    results = scan(detector, input, false, &fake); CHECK(results.len == 1); br_results_clear(&results);
    make_token(token, 128, 7, "", 0);
    snprintf(input, sizeof(input), "%s\n%s \n%s", id1, secret1, token);
    results = scan(detector, input, false, &fake); CHECK(!results.len); br_results_clear(&results);
    make_token(token, 128, 7, "YXdz", 0); memcpy(token + 16, secret1, 40);
    snprintf(input, sizeof(input), "%s\n%s \n%s", id1, secret1, token);
    results = scan(detector, input, false, &fake); CHECK(!results.len); br_results_clear(&results);
    memset(token, 'A', 128); memcpy(token, "YXdz", 4); token[128] = '\0';
    snprintf(input, sizeof(input), "%s\n%s \n%s", id1, secret1, token);
    results = scan(detector, input, false, &fake); CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "ASIAAAAAAAAAAAAAAAAA\n%s \n%s", secret1, token1);
    results = scan(detector, input, false, &fake); CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "%s\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA \n%s", id1, token1);
    results = scan(detector, input, false, &fake); CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "%s\n0123456789abcdef0123456789abcdef01234567 \n%s", id1, token1);
    results = scan(detector, input, false, &fake); CHECK(!results.len); br_results_clear(&results);
    const char *bad_ids[] = {"asiaABCDEFGHIJKLMNOP", "AKIAABCDEFGHIJKLMNOP", "XASIAABCDEFGHIJKLMNOP", "ASIAABCDEFGHIJKLMNOP_"};
    for (size_t i = 0; i < sizeof(bad_ids) / sizeof(bad_ids[0]); ++i) {
        snprintf(input, sizeof(input), "%s\n%s \n%s", bad_ids[i], secret1, token1);
        results = scan(detector, input, false, &fake); CHECK(!results.len); br_results_clear(&results);
    }
    /* A consumed separator cannot also start the next token match. */
    snprintf(input, sizeof(input), "%s\n%s \n%s!%s", id1, secret1, token1, token2);
    results = scan(detector, input, false, &fake); CHECK(results.len == 1); br_results_clear(&results);
    snprintf(input, sizeof(input), "%s\n%s \n%s!!%s", id1, secret1, token1, token2);
    results = scan(detector, input, false, &fake); CHECK(results.len == 2); br_results_clear(&results);

    /* Only the six URL substitutions. '+' is not turned into a space and
     * encoded percent signs are not recursively decoded. */
    char escaped_secret[128], escaped_token[512];
    const char *values[] = {secret2, token2};
    char *outputs[] = {escaped_secret, escaped_token};
    for (size_t which = 0; which < 2; ++which) {
        size_t at = 0;
        for (size_t i = 0; values[which][i]; ++i) {
            char c = values[which][i];
            const char *code = c == '+' ? (i & 1 ? "%2b" : "%2B") : c == '/' ? (i & 1 ? "%2f" : "%2F") : c == '=' ? (i & 1 ? "%3d" : "%3D") : NULL;
            if (code) { memcpy(outputs[which] + at, code, 3); at += 3; }
            else outputs[which][at++] = c;
        }
        outputs[which][at] = '\0';
    }
    snprintf(input, sizeof(input), "%s\n%s \n%s", id1, escaped_secret, escaped_token);
    results = scan(detector, input, false, &fake); CHECK(results.len == 1);
    check_result(&results.items[0], id1, secret2, token2); br_results_clear(&results);
    snprintf(input, sizeof(input), "%s\n%s \n%s", "ASIAIJKLMNOPQRSTUVWX", secret1, token1);
    results = scan(detector, input, false, &fake); CHECK(results.len == 1);
    CHECK(!json_object_object_length(results.items[0].extra_data)); br_results_clear(&results);
    char canary_id[21]; make_id(canary_id, UINT64_C(52310077262), 25);
    snprintf(input, sizeof(input), "%s\n%s \n%s", canary_id, secret1, token1);
    results = scan(detector, input, false, &fake); CHECK(results.len == 1);
    check_result(&results.items[0], canary_id, secret1, token1);
    CHECK(json_object_object_length(results.items[0].extra_data) == 1); br_results_clear(&results);
}

static void products_and_cleaning(const br_detector *detector)
{
    char input[2048];
    snprintf(input, sizeof(input), "%s\n%s\n%s \n%s \n%s \n%s", id1, id2, secret1, secret2, token1, token2);
    fake_http fake = {0};
    br_results results = scan(detector, input, false, &fake);
    CHECK(results.len == 8);
    size_t at = 0;
    const char *ids[] = {id1, id2}, *secrets[] = {secret1, secret2}, *tokens[] = {token1, token2};
    for (size_t i = 0; i < 2; ++i) for (size_t s = 0; s < 2; ++s) for (size_t t = 0; t < 2; ++t)
        check_result(&results.items[at++], ids[i], secrets[s], tokens[t]);
    detector->clean(detector, &results, false); CHECK(results.len == 8);
    results.items[0].verified = results.items[1].verified = results.items[7].verified = true;
    detector->clean(detector, &results, true); CHECK(results.len == 2);
    check_result(&results.items[0], id1, secret1, token2);
    check_result(&results.items[1], id2, secret2, token2);
    br_results_clear(&results);
}

static void options(const br_detector *detector)
{
    char input[2048], setting[512];
    snprintf(input, sizeof(input), "%s\n%s \n%s", id1, secret1, token1);
    const char *settings[] = {
        "{\"denied_accounts\":[\"123456789012\"],\"allowed_accounts\":[\"123456789012\"]}",
        "{\"allowed_accounts\":[\"999999999999\"]}",
    };
    for (size_t i = 0; i < 2; ++i) {
        br_json *value = json_tokener_parse(settings[i]); CHECK(value);
        fake_http fake = {.options = value};
        br_results results = scan(detector, input, true, &fake);
        CHECK(results.len == 1 && !results.items[0].verified);
        CHECK(!strcmp(results.items[0].verification_error, i ? "Account ID is not in the allow list for verification" : "Account ID is in the deny list for verification"));
        check_text(results.items[0].extra_data, "account", "123456789012"); br_results_clear(&results);
        results = scan(detector, input, false, &fake); CHECK(results.len == 1 && !results.items[0].verification_error);
        br_results_clear(&results); json_object_put(value);
    }
    snprintf(setting, sizeof(setting), "{\"skip_ids\":[\"%s\"]}", id1);
    br_json *value = json_tokener_parse(setting); CHECK(value);
    fake_http fake = {.options = value};
    br_results results = scan(detector, input, true, &fake); CHECK(!results.len); br_results_clear(&results);
    results = scan(detector, input, false, &fake); CHECK(!results.len); br_results_clear(&results); json_object_put(value);
    value = json_tokener_parse("{\"allowed_accounts\":[],\"denied_accounts\":[]}"); CHECK(value);
    fake = (fake_http){.options = value, .count = 1}; fake.steps[0] = response(200, "{}");
    results = scan(detector, input, true, &fake); CHECK(results.len == 1 && results.items[0].verified);
    check_text(results.items[0].extra_data, "account", ""); br_results_clear(&results); json_object_put(value);

    const char *bad[] = {"[]", "{\"skip_ids\":1}", "{\"allowed_accounts\":[null]}", "{\"denied_accounts\":[1]}"};
    for (size_t i = 0; i < 4; ++i) {
        value = json_tokener_parse(bad[i]); CHECK(value);
        br_scan_ctx ctx = {.options = value}; char *error = NULL;
        results = (br_results){0};
        CHECK(detector->scan(detector, &ctx, false, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) != 0);
        CHECK(error && !strncmp(error, "invalid AWS session key options:", 31) && !results.len);
        free(error); br_results_clear(&results); json_object_put(value);
    }
}

static void signing_and_unbounded(const br_detector *detector)
{
    /* Python hashlib/hmac goldens, computed independently from the source's
     * manual canonical GET (not the C signer or the access-key SDK signer). */
    char input[4096];
    snprintf(input, sizeof(input), "ASIAABCDEFGHIJKLMNOP\n%s \n%s", secret1, token1);
    fake_http fake = {.count = 1, .expected_token = token1,
        .signature = "4f633bbba6880cb6f4918ca887d655effb913b8ce0efaadd7a3407016e6eac2c"};
    fake.steps[0] = response(200, identity);
    br_results results = scan(detector, input, true, &fake);
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
    check_result(&results.items[0], "ASIAABCDEFGHIJKLMNOP", secret1, token1);
    check_text(results.items[0].extra_data, "account", "999999999999");
    check_text(results.items[0].extra_data, "user_id", "synthetic-user");
    check_text(results.items[0].extra_data, "arn", "synthetic-arn");
    check_text(results.items[0].extra_data, "rotation_guide", "https://howtorotate.com/docs/tutorials/aws/");
    br_results_clear(&results);
    fixed_time = 1706933106; /* 2024-02-03T04:05:06Z */
    fake = (fake_http){.count = 1, .date = "20240203T040506Z", .expected_token = token2,
        .signature = "81e943f9b6ec99e47d165c3ed3a0cba490d90b1c4a0f61ecb8781fe91d2cc568"};
    fake.steps[0] = response(200, "{}");
    snprintf(input, sizeof(input), "ASIAABCDEFGHIJKLMNOP\n%s \n%s", secret1, token2);
    results = scan(detector, input, true, &fake); CHECK(results.len == 1 && results.items[0].verified);
    check_text(results.items[0].extra_data, "account", ""); br_results_clear(&results);
    fixed_time = 1704164645;
    size_t len = 8193;
    char *long_token = malloc(len + 4), *long_input = malloc(len + 128); CHECK(long_token && long_input);
    make_token(long_token, len, 23, "YXdz", 2);
    snprintf(long_input, len + 128, "%s\n%s \n%s", id1, secret1, long_token);
    fake = (fake_http){.count = 1, .expected_token = long_token}; fake.steps[0] = response(200, "null");
    results = scan(detector, long_input, true, &fake); CHECK(results.len == 1 && results.items[0].verified);
    check_result(&results.items[0], id1, secret1, long_token);
    br_results_clear(&results); free(long_token); free(long_input);
}

static void json_success_policy(const br_detector *detector)
{
    char input[512]; snprintf(input, sizeof(input), "%s\n%s \n%s", id1, secret1, token1);
    const struct { int status; const char *body, *read_error, *error, *account; } cases[] = {
        {200, "{}", NULL, NULL, ""}, {201, "null", NULL, NULL, ""},
        {299, "{\"GetCallerIdentityResponse\":null}", NULL, NULL, ""},
        {200, "{\"GetCallerIdentityResponse\":{\"GetCallerIdentityResult\":{\"Account\":null,\"UserId\":null,\"Arn\":null},\"ResponseMetadata\":null}}", NULL, NULL, ""},
        {200, "{\"getcalleridentityresponse\":{\"getcalleridentityresult\":{\"account\":\"first\",\"ACCOUNT\":\"last\",\"Account\":null},\"ResponseMetadata\":{\"requestid\":\"unused\"}},\"ignored\":1e9999} trailing", NULL, NULL, "last"},
        {200, "{\"GetCallerIdentityResponse\":{\"GetCallerIdentityResult\":{\"Account\":\"kept\"}},\"GetCallerIdentityResponse\":null,\"GetCallerIdentityResponse\":{\"GetCallerIdentityResult\":null}}", NULL, NULL, "kept"},
        {200, "{} {}", NULL, NULL, ""}, {200, "{}", "late read failure", NULL, ""},
        {200, "", NULL, "EOF", NULL}, {204, "", NULL, "EOF", NULL},
        {200, "{", NULL, "unexpected EOF", NULL}, {200, "{", "synthetic read failure", "synthetic read failure", NULL},
        {200, "[]", NULL, "json: cannot unmarshal array into Go value of type aws.IdentityResponse", NULL},
        {200, "{\"GetCallerIdentityResponse\":[]}", NULL, "json: cannot unmarshal array into Go struct field IdentityResponse.GetCallerIdentityResponse of type struct { GetCallerIdentityResult struct { Account string \"json:\\\"Account\\\"\"; Arn string \"json:\\\"Arn\\\"\"; UserID string \"json:\\\"UserId\\\"\" } \"json:\\\"GetCallerIdentityResult\\\"\"; ResponseMetadata struct { RequestID string \"json:\\\"RequestId\\\"\" } \"json:\\\"ResponseMetadata\\\"\" }", NULL},
        {200, "{\"GetCallerIdentityResponse\":{\"GetCallerIdentityResult\":{\"Account\":1}}}", NULL, "json: cannot unmarshal number into Go struct field .GetCallerIdentityResponse.GetCallerIdentityResult.Account of type string", NULL},
        {200, "{\"GetCallerIdentityResponse\":{\"GetCallerIdentityResult\":{\"Arn\":true}}}", NULL, "json: cannot unmarshal bool into Go struct field .GetCallerIdentityResponse.GetCallerIdentityResult.Arn of type string", NULL},
        {200, "{\"GetCallerIdentityResponse\":{\"GetCallerIdentityResult\":{\"UserId\":[]}}}", NULL, "json: cannot unmarshal array into Go struct field .GetCallerIdentityResponse.GetCallerIdentityResult.UserId of type string", NULL},
        {200, "{\"GetCallerIdentityResponse\":{\"ResponseMetadata\":{\"RequestId\":1}}}", NULL, "json: cannot unmarshal number into Go struct field .GetCallerIdentityResponse.ResponseMetadata.RequestId of type string", NULL},
        {200, "{\"GetCallerIdentityResponse\":{\"ResponseMetadata\":[]}}", NULL, "json: cannot unmarshal array into Go struct field .GetCallerIdentityResponse.ResponseMetadata of type struct { RequestID string \"json:\\\"RequestId\\\"\" }", NULL},
        {200, "{\"GetCallerIdentityResponse\":{\"GetCallerIdentityResult\":[]}}", NULL, "json: cannot unmarshal array into Go struct field .GetCallerIdentityResponse.GetCallerIdentityResult of type struct { Account string \"json:\\\"Account\\\"\"; Arn string \"json:\\\"Arn\\\"\"; UserID string \"json:\\\"UserId\\\"\" }", NULL},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        fake_http fake = {.count = 1}; fake.steps[0] = response(cases[i].status, cases[i].body);
        fake.steps[0].body_error = cases[i].read_error;
        br_results results = scan(detector, input, true, &fake);
        CHECK(results.len == 1 && results.items[0].verified == (cases[i].error == NULL));
        if (cases[i].error) CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, cases[i].error));
        else { CHECK(!results.items[0].verification_error); check_text(results.items[0].extra_data, "account", cases[i].account); }
        br_results_clear(&results);
    }
}

static void retries_errors_and_redaction(const br_detector *detector)
{
    char input[512]; snprintf(input, sizeof(input), "%s\n%s \n%s", id1, secret1, token1);
    const struct { const char *body, *error; } cases[] = {
        {"{\"Error\":{\"Code\":\"InvalidClientTokenId\"}}", NULL}, {expired, NULL},
        {"{\"Error\":{\"Code\":\"ExpiredTo\\u212Aen\"}}", NULL},
        {"{", "couldn't parse the sts response body (unexpected EOF)"},
        {"", "couldn't parse the sts response body (EOF)"},
        {"[]", "couldn't parse the sts response body (json: cannot unmarshal array into Go value of type aws.ErrorResponseBody)"},
        {"{\"Error\":[]}", "couldn't parse the sts response body (json: cannot unmarshal array into Go struct field ErrorResponseBody.Error of type aws.Error)"},
        {"{\"Error\":{\"Code\":1}}", "couldn't parse the sts response body (json: cannot unmarshal number into Go struct field Error.Error.Code of type string)"},
        {"{\"Error\":{\"Message\":[]}}", "couldn't parse the sts response body (json: cannot unmarshal array into Go struct field Error.Error.Message of type string)"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        fake_http fake = {.count = 2, .hold_first = true};
        fake.steps[0] = response(403, "first body must not be decoded"); fake.steps[0].body_error = "ignored first read error";
        fake.steps[1] = response(403, cases[i].body);
        br_results results = scan(detector, input, true, &fake);
        CHECK(results.len == 1 && !results.items[0].verified);
        CHECK(fake.order[0] == 1 && fake.order[1] == 0);
        if (cases[i].error) CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, cases[i].error));
        else CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
    }
    fake_http fake = {.count = 2, .hold_first = true};
    fake.steps[0] = response(403, "ignored"); fake.steps[1] = response(200, identity);
    br_results results = scan(detector, input, true, &fake);
    CHECK(results.len == 1 && results.items[0].verified && fake.order[0] == 1 && fake.order[1] == 0);
    br_results_clear(&results);
    for (int status = 400; status <= 500; status += 50) {
        char expected[256]; snprintf(expected, sizeof(expected), "request to %s returned unexpected status %d", endpoint, status);
        fake = (fake_http){.count = 1}; fake.steps[0] = response(status, "not JSON"); fake.steps[0].body_error = "ignored drain failure";
        results = scan(detector, input, true, &fake);
        CHECK(results.len == 1 && !results.items[0].verified && !strcmp(results.items[0].verification_error, expected));
        br_results_clear(&results);
    }
    fake = (fake_http){.count = 2, .hold_first = true};
    fake.steps[0] = response(403, "ignored"); fake.steps[1] = response(403, "{"); fake.steps[1].body_error = "synthetic read error";
    results = scan(detector, input, true, &fake);
    CHECK(results.len == 1 && !strcmp(results.items[0].verification_error, "couldn't parse the sts response body (synthetic read error)"));
    br_results_clear(&results);
    fake = (fake_http){.count = 2, .hold_first = true};
    fake.steps[0] = response(403, "ignored"); fake.steps[1] = response(403, expired); fake.steps[1].body_error = "ignored late read error";
    results = scan(detector, input, true, &fake);
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    char body[1024], expected[1024];
    snprintf(body, sizeof(body), "{\"Error\":{\"Code\":\"Other\",\"Message\":\"%s %s %s\"}}", secret1, id1, token1);
    snprintf(expected, sizeof(expected), "request to %s returned status 403 with an unexpected reason (Other: [REDACTED] %s %s)", endpoint, id1, token1);
    fake = (fake_http){.count = 2, .hold_first = true}; fake.steps[0] = response(403, "ignored"); fake.steps[1] = response(403, body);
    results = scan(detector, input, true, &fake);
    CHECK(results.len == 1 && !strcmp(results.items[0].verification_error, expected)); br_results_clear(&results);
    char failure[512]; snprintf(failure, sizeof(failure), "synthetic transport failure %s %s %s", secret1, id1, token1);
    snprintf(expected, sizeof(expected), "synthetic transport failure [REDACTED] %s %s", id1, token1);
    fake = (fake_http){.count = 1}; fake.steps[0] = response(0, ""); fake.errors[0] = failure;
    results = scan(detector, input, true, &fake);
    CHECK(results.len == 1 && !results.items[0].verified && !strcmp(results.items[0].verification_error, expected)); br_results_clear(&results);
    fake = (fake_http){.count = 2, .hold_first = true}; fake.steps[0] = response(403, "ignored"); fake.steps[1] = response(0, ""); fake.errors[1] = failure;
    results = scan(detector, input, true, &fake);
    CHECK(results.len == 1 && !strcmp(results.items[0].verification_error, expected) && fake.order[0] == 1 && fake.order[1] == 0);
    br_results_clear(&results);
}

static void token_consumption(const br_detector *detector)
{
    char input[2048];
    /* Verified secret remains available to the next ID; only its token goes. */
    snprintf(input, sizeof(input), "%s\n%s\n%s \n%s \n%s", id1, id2, secret1, token1, token2);
    fake_http fake = {.count = 2}; fake.steps[0] = fake.steps[1] = response(200, "{}");
    br_results results = scan(detector, input, true, &fake);
    CHECK(results.len == 2 && results.items[0].verified && results.items[1].verified);
    check_result(&results.items[0], id1, secret1, token1);
    check_result(&results.items[1], id2, secret1, token2); br_results_clear(&results);
    /* A verified match does not break out of the ID's remaining secret loop. */
    snprintf(input, sizeof(input), "%s\n%s \n%s \n%s \n%s", id1, secret1, secret2, token1, token2);
    fake = (fake_http){.count = 2}; fake.steps[0] = fake.steps[1] = response(200, "{}");
    results = scan(detector, input, true, &fake);
    CHECK(results.len == 2 && results.items[0].verified && results.items[1].verified);
    check_result(&results.items[0], id1, secret1, token1);
    check_result(&results.items[1], id1, secret2, token2); br_results_clear(&results);
    /* Rejections do not consume tokens. Every pairing still retries its 403. */
    snprintf(input, sizeof(input), "%s\n%s \n%s \n%s", id1, secret1, secret2, token1);
    fake = (fake_http){.count = 4};
    for (size_t i = 0; i < 4; ++i) fake.steps[i] = response(403, expired);
    results = scan(detector, input, true, &fake);
    CHECK(results.len == 2 && !results.items[0].verified && !results.items[1].verified);
    check_result(&results.items[0], id1, secret1, token1);
    check_result(&results.items[1], id1, secret2, token1);
    CHECK(fake.order[0] == 1 && fake.order[1] == 0 && fake.order[2] == 3 && fake.order[3] == 2);
    br_results_clear(&results);
}

int main(void)
{
    make_id(id1, UINT64_C(123456789012), 7); make_id(id2, UINT64_C(234567890123), 19);
    memcpy(secret1, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn", 41);
    for (size_t i = 0; i < 40; ++i) secret2[i] = alphabet[(i + 32) % 64];
    secret2[40] = '\0';
    make_token(token1, 128, 7, "YXdz", 0); make_token(token2, 101, 19, "Jb3JpZ2luX2Vj", 3);
    CHECK(br_ascii_shannon_entropy((br_slice){(const unsigned char *)secret1, 40}) >= 4.25);
    CHECK(br_ascii_shannon_entropy((br_slice){(const unsigned char *)token1, strlen(token1)}) >= 4.5);
    const br_detector *detector = init();
    extraction(detector); products_and_cleaning(detector); options(detector);
    signing_and_unbounded(detector); json_success_policy(detector);
    retries_errors_and_redaction(detector); token_consumption(detector);
    return test_finish("AWS session keys manual GET/JSON + token lifecycle");
}
