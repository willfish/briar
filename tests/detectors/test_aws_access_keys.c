/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <inttypes.h>
#include <openssl/rand.h>
#include <strings.h>
#include <time.h>

/* Process-local interposition, not production hooks. No clock or RNG inputs
 * are obtained from credentials, configuration, services or another runtime. */
static time_t fixed_time = 1704164645; /* 2024-01-02T03:04:05Z */
static size_t uuid_calls, jitter_calls, sleep_calls;
static uint64_t slept_ns;
static bool fail_uuid, fail_jitter, fail_clock;

time_t time(time_t *out)
{
    if (out) *out = fixed_time;
    return fixed_time;
}

int clock_gettime(clockid_t clock, struct timespec *out)
{
    if (clock == CLOCK_REALTIME && fail_clock) return -1;
    *out = (struct timespec){clock == CLOCK_MONOTONIC ? 1000 : fixed_time, 0};
    return 0;
}

int RAND_bytes(unsigned char *out, int count)
{
    CHECK(count == 16 || count == 7);
    if (count == 16) {
        static const unsigned char raw[] = {0x11,0x11,0x11,0x11,0x22,0x22,0x33,0x33,0x44,0x44,0x55,0x55,0x55,0x55,0x55,0x55};
        memcpy(out, raw, 16);
        out[15] += (unsigned char)(uuid_calls++ % 16);
        if (fail_uuid) { memset(out, 0x71, 8); return 0; }
    } else {
        ++jitter_calls;
        memset(out, 0, 7); out[0] = 0x10; /* Fraction 1/2. */
        if (fail_jitter) return 0;
    }
    return 1;
}

int nanosleep(const struct timespec *delay, struct timespec *remaining)
{
    CHECK(delay->tv_sec >= 0 && delay->tv_nsec >= 0 && delay->tv_nsec < 1000000000);
    ++sleep_calls;
    slept_ns += (uint64_t)delay->tv_sec * 1000000000 + (uint64_t)delay->tv_nsec;
    if (remaining) *remaining = (struct timespec){0};
    return 0;
}

static char id1[21], id2[21], secret1[41], secret2[41];
static const char unsupported[] = "HTTP transport not installed";
static const char denied[] = "Account ID is in the deny list for verification";
static const char not_allowed[] = "Account ID is not in the allow list for verification";
static const char thinkst[] = "This is an AWS canary token generated at canarytokens.org.";
static const char knockoff[] = "This is an off brand AWS Canary inspired by canarytokens.org.";

typedef struct { const char *id, *secret, *account, *message, *error; } expected_pair;

static const br_detector *detector_init(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_aws_access_keys_init(NULL, &error) != 0 && error);
    free(error);
    error = NULL;
    CHECK(br_aws_access_keys_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_aws_access_keys_init(&again, &error) == 0 && !error && again == detector);
    CHECK(detector->type == 2 && detector->version == 0);
    CHECK(!strcmp(detector->name, "AWS") && !strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description,
        "AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. "
        "API keys for AWS can have varying amount of access to these services depending on the IAM policy attached."));
    CHECK(detector->nkeywords == 3 && !strcmp(detector->keywords[0], "AKIA") &&
          !strcmp(detector->keywords[1], "ABIA") && !strcmp(detector->keywords[2], "ACCA"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && detector->clean && detector->clean_always);
    CHECK(!detector->false_positive && !detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

/* Synthetic base32 IDs encode a chosen account and arbitrary suffix bytes.
 * No reference/live access-key ID or credential source is used. */
static void make_id(char out[21], const char *prefix, uint64_t account, unsigned seed)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    CHECK(account < (UINT64_C(1) << 40));
    for (unsigned attempt = 0; attempt < 256; ++attempt) {
        unsigned char raw[10];
        uint64_t first = UINT64_C(0x800000000000) | (account << 7) | ((seed + attempt) & 127);
        for (size_t i = 0; i < 6; ++i) raw[i] = (unsigned char)(first >> (8 * (5 - i)));
        for (size_t i = 6; i < 10; ++i) raw[i] = (unsigned char)((seed + attempt) * 37 + i * 53);
        memcpy(out, prefix, 4);
        unsigned buffer = 0, bits = 0;
        size_t at = 4;
        for (size_t i = 0; i < sizeof(raw); ++i) {
            buffer = (buffer << 8) | raw[i];
            bits += 8;
            while (bits >= 5) { bits -= 5; out[at++] = alphabet[(buffer >> bits) & 31]; }
            buffer &= (1u << bits) - 1;
        }
        out[20] = '\0';
        if (br_ascii_shannon_entropy((br_slice){(const unsigned char *)out, 20}) >= 3.0) return;
    }
    CHECK(!"synthetic ID entropy too low");
}

static void check_text(br_json *object, const char *name, const char *expected)
{
    br_json *value = NULL;
    CHECK(json_object_object_get_ex(object, name, &value));
    CHECK(json_object_is_type(value, json_type_string) && !strcmp(json_object_get_string(value), expected));
}

static void check_pair(const br_result *result, expected_pair pair)
{
    CHECK(result->detector_type == 2 && !result->detector_name);
    CHECK(result->raw.len == 20 && !memcmp(result->raw.data, pair.id, 20));
    CHECK(result->raw_v2.len == 61 && !memcmp(result->raw_v2.data, pair.id, 20));
    CHECK(result->raw_v2.data[20] == ':' && !memcmp(result->raw_v2.data + 21, pair.secret, 40));
    CHECK(result->redacted && !strcmp(result->redacted, pair.id));
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    check_text(result->secret_parts, "access_key_id", pair.id);
    check_text(result->secret_parts, "secret_access_key", pair.secret);
    CHECK(result->extra_data && json_object_object_length(result->extra_data) == 1 + (pair.account != NULL) + 2 * (pair.message != NULL));
    check_text(result->extra_data, "resource_type", !strncmp(pair.id, "AKIA", 4) ? "Access key" :
               !strncmp(pair.id, "ABIA", 4) ? "AWS STS service bearer token" : "Context-specific credential");
    if (pair.account) check_text(result->extra_data, "account", pair.account);
    if (pair.message) {
        check_text(result->extra_data, "message", pair.message);
        check_text(result->extra_data, "is_canary", "true");
    }
    CHECK(!result->verified && !result->verification_from_cache && !result->structured_data);
    if (pair.error) CHECK(result->verification_error && !strcmp(result->verification_error, pair.error));
    else CHECK(!result->verification_error);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static void expect_scan(const br_detector *detector, const char *input, bool verify, const br_json *options,
                         const expected_pair *pairs, size_t count)
{
    /* Local extraction/options tests intentionally install no transport. Wire
     * behavior is checked separately below using scripted injected responses. */
    test_http http = {0};
    br_scan_ctx ctx = {.options = options};
    br_results results = test_scan(detector, &ctx, verify, input, input ? strlen(input) : 0);
    CHECK(!http.calls && !http.releases && results.len == count);
    bool seen[8] = {0};
    CHECK(count <= sizeof(seen) / sizeof(seen[0]));
    for (size_t r = 0; r < results.len; ++r) {
        size_t found = count;
        for (size_t p = 0; p < count; ++p) {
            if (!seen[p] && results.items[r].raw_v2.len == 61 &&
                !memcmp(results.items[r].raw_v2.data, pairs[p].id, 20) &&
                !memcmp(results.items[r].raw_v2.data + 21, pairs[p].secret, 40)) { found = p; break; }
        }
        CHECK(found < count);
        seen[found] = true;
        check_pair(&results.items[r], pairs[found]);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    char input[4096], changed[64];
    const expected_pair one[] = {{id1, secret1, "123456789012", NULL, NULL}};
    const expected_pair two[] = {{id1, secret1, "123456789012", NULL, NULL}, {id1, secret2, "123456789012", NULL, NULL}};
    const expected_pair four[] = {
        {id1, secret1, "123456789012", NULL, NULL}, {id1, secret2, "123456789012", NULL, NULL},
        {id2, secret1, "234567890123", NULL, NULL}, {id2, secret2, "234567890123", NULL, NULL},
    };
    expect_scan(detector, NULL, false, NULL, NULL, 0);
    expect_scan(detector, id1, false, NULL, NULL, 0);
    expect_scan(detector, secret1, false, NULL, NULL, 0);
    snprintf(input, sizeof(input), "%s\n%s", id1, secret1);
    expect_scan(detector, input, false, NULL, one, 1);
    snprintf(input, sizeof(input), "%s\n%s", secret1, id1);
    expect_scan(detector, input, false, NULL, one, 1);
    snprintf(input, sizeof(input), "%s\n%s %s", id1, secret1, secret2);
    expect_scan(detector, input, false, NULL, one, 1); /* First match consumes the only separator. */
    snprintf(input, sizeof(input), "%s\n%s  %s", id1, secret1, secret2);
    expect_scan(detector, input, false, NULL, two, 2);
    snprintf(input, sizeof(input), "%s\n%s\n\n%s\n%s\n%s\n\n%s", id1, secret1, secret2, id1, id2, secret1);
    expect_scan(detector, input, false, NULL, four, 4);
    const char *const wrappers[] = {"_%s\n%s", "%s_\n%s", "Q%s\n%s", "%sQ\n%s"};
    for (size_t i = 0; i < sizeof(wrappers) / sizeof(wrappers[0]); ++i) {
        snprintf(input, sizeof(input), wrappers[i], id1, secret1);
        expect_scan(detector, input, false, NULL, NULL, 0);
    }
    memcpy(changed, id1, 21);
    changed[0] = 'a';
    snprintf(input, sizeof(input), "%s\n%s", changed, secret1);
    expect_scan(detector, input, false, NULL, NULL, 0);
    memcpy(changed, id1, 21);
    memcpy(changed, "ASIA", 4);
    snprintf(input, sizeof(input), "%s\n%s", changed, secret1);
    expect_scan(detector, input, false, NULL, NULL, 0);
    snprintf(input, sizeof(input), "AKIAAAAAAAAAAAAAAAAA\n%s", secret1);
    expect_scan(detector, input, false, NULL, NULL, 0);
    snprintf(input, sizeof(input), "%s\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", id1);
    expect_scan(detector, input, false, NULL, NULL, 0);
    snprintf(input, sizeof(input), "%s\n0123456789abcdef0123456789abcdef01234567", id1);
    expect_scan(detector, input, true, NULL, NULL, 0); /* Entropy/hash filtering, no verification request. */
    snprintf(input, sizeof(input), "%s\n%sQ", id1, secret1);
    expect_scan(detector, input, false, NULL, NULL, 0);
    snprintf(input, sizeof(input), "%s\n%s=", id1, secret1);
    expect_scan(detector, input, false, NULL, one, 1); /* '=' is an allowed, consumed delimiter. */
    memcpy(changed, secret1, 41);
    changed[0] = '+';
    const expected_pair leading[] = {{id1, changed, "123456789012", NULL, NULL}};
    snprintf(input, sizeof(input), "%s\n%s", changed, id1);
    expect_scan(detector, input, false, NULL, leading, 1);
    size_t at = (size_t)snprintf(input, sizeof(input), "%s\n", id1);
    memset(input + at, '-', 2000);
    snprintf(input + at + 2000, sizeof(input) - at - 2000, "\n%s", secret1);
    expect_scan(detector, input, false, NULL, one, 1); /* Span is metadata, not a scan-local cut. */
}

static void url_replacements(const br_detector *detector)
{
    char encoded[256], input[512];
    const expected_pair one[] = {{id1, secret1, "123456789012", NULL, NULL}};
    for (size_t lower = 0; lower < 2; ++lower) {
        size_t at = 0;
        for (size_t i = 0; i < 40; ++i) {
            const char *replacement = secret1[i] == '+' ? (lower ? "%2b" : "%2B") :
                                      secret1[i] == '/' ? (lower ? "%2f" : "%2F") : NULL;
            if (replacement) { memcpy(encoded + at, replacement, 3); at += 3; }
            else encoded[at++] = secret1[i];
        }
        memcpy(encoded + at, lower ? "%3d" : "%3D", 4);
        snprintf(input, sizeof(input), "%s\n%s", id1, encoded);
        expect_scan(detector, input, false, NULL, one, 1);
    }
    size_t at = 0;
    for (size_t i = 0; i < 40; ++i) {
        if (secret1[i] == '+') { memcpy(encoded + at, "%252B", 5); at += 5; }
        else encoded[at++] = secret1[i];
    }
    encoded[at] = '\0';
    snprintf(input, sizeof(input), "%s\n%s", id1, encoded);
    expect_scan(detector, input, false, NULL, NULL, 0); /* No recursive URL decoding. */
    snprintf(input, sizeof(input), "%s\n%%41%s", id1, secret1 + 1);
    expect_scan(detector, input, false, NULL, NULL, 0); /* Other escapes are not decoded. */
}

static void accounts(const br_detector *detector)
{
    char id[21], input[128];
    const struct { const char *prefix; uint64_t number; const char *text; } cases[] = {
        {"ABIA", UINT64_C(12345678), "000012345678"},
        {"ACCA", UINT64_C(1001234567890), "1001234567890"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        make_id(id, cases[i].prefix, cases[i].number, (unsigned)i + 41);
        snprintf(input, sizeof(input), "%s\n%s", id, secret1);
        const expected_pair pair[] = {{id, secret1, cases[i].text, NULL, unsupported}};
        expect_scan(detector, input, true, NULL, pair, 1);
    }
    const char *const old[] = {"AKIAI2BCDEFGHLMNPQR5", "ACCAJ2BCDEFGHLMNPQR5"};
    br_json *options = json_tokener_parse("{\"allowed_accounts\":[\"other\"]}");
    CHECK(options);
    for (size_t i = 0; i < sizeof(old) / sizeof(old[0]); ++i) {
        CHECK(strlen(old[i]) == 20);
        snprintf(input, sizeof(input), "%s\n%s", old[i], secret1);
        const expected_pair pair[] = {{old[i], secret1, NULL, NULL, unsupported}};
        expect_scan(detector, input, true, options, pair, 1); /* Undecodable accounts bypass account filtering. */
    }
    memcpy(id, id1, sizeof(id));
    id[10] = '9'; /* Allowed in the ID regex, invalid in standard base32. */
    snprintf(input, sizeof(input), "%s\n%s", id, secret1);
    const expected_pair invalid_base32[] = {{id, secret1, NULL, NULL, unsupported}};
    expect_scan(detector, input, true, options, invalid_base32, 1);
    json_object_put(options);
}

static void canaries(const br_detector *detector)
{
    const char *const account[] = {
        "052310077262", "171436882533", "534261010715", "595918472158", "717712589309", "819147034852", "992382622183", "730335385048", "266735846894", "893192397702",
        "044858866125", "251535659677", "344043088457", "351906852752", "390477818340", "426127672474", "427150556519", "439872796651", "445142720921", "465867158099", "637958123769", "693412236332", "732624840810", "735421457923", "959235150393", "982842642351",
    };
    for (size_t i = 0; i < sizeof(account) / sizeof(account[0]); ++i) {
        char id[21], input[128];
        make_id(id, "AKIA", strtoull(account[i], NULL, 10), (unsigned)i + 11);
        snprintf(input, sizeof(input), "%s\n%s", id, secret1);
        expected_pair pair = {id, secret1, account[i], i < 10 ? thinkst : knockoff, NULL};
        expect_scan(detector, input, false, NULL, &pair, 1);
        pair.error = unsupported;
        expect_scan(detector, input, true, NULL, &pair, 1);
    }
}

static void options(const br_detector *detector)
{
    char input[128], json[512], lower_id[21];
    snprintf(input, sizeof(input), "%s\n%s", id1, secret1);
    const struct { const char *json, *error; } cases[] = {
        {"null", unsupported}, {"{}", unsupported},
        {"{\"allowed_accounts\":null,\"denied_accounts\":[],\"skip_ids\":null}", unsupported},
        {"{\"allowed_accounts\":[\"123456789012\"]}", unsupported},
        {"{\"denied_accounts\":[\"other\"]}", unsupported},
        {"{\"allowed_accounts\":[\"other\"]}", not_allowed},
        {"{\"denied_accounts\":[\"123456789012\"]}", denied},
        {"{\"allowed_accounts\":[\"123456789012\"],\"denied_accounts\":[\"123456789012\"]}", denied},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        br_json *settings = json_tokener_parse(cases[i].json);
        CHECK(settings || !strcmp(cases[i].json, "null"));
        expected_pair pair = {id1, secret1, "123456789012", NULL, cases[i].error};
        expect_scan(detector, input, true, settings, &pair, 1);
        pair.error = NULL;
        expect_scan(detector, input, false, settings, &pair, 1);
        json_object_put(settings);
    }
    snprintf(json, sizeof(json), "{\"skip_ids\":[\"%s\",\"%s\"]}", id1, id1);
    br_json *settings = json_tokener_parse(json);
    CHECK(settings);
    expect_scan(detector, input, false, settings, NULL, 0);
    expect_scan(detector, input, true, settings, NULL, 0);
    json_object_put(settings);
    memcpy(lower_id, id1, sizeof(lower_id));
    lower_id[0] = 'a';
    snprintf(json, sizeof(json), "{\"skip_ids\":[\"%s\",\"%s\\u0000suffix\"]}", lower_id, id1);
    settings = json_tokener_parse(json);
    CHECK(settings);
    const expected_pair pair[] = {{id1, secret1, "123456789012", NULL, unsupported}};
    expect_scan(detector, input, true, settings, pair, 1);
    json_object_put(settings);

    char canary[21];
    make_id(canary, "AKIA", UINT64_C(52310077262), 25);
    snprintf(input, sizeof(input), "%s\n%s", canary, secret1);
    settings = json_tokener_parse("{\"allowed_accounts\":[\"other\"],\"denied_accounts\":[\"052310077262\"]}");
    CHECK(settings);
    const expected_pair filtered[] = {{canary, secret1, "052310077262", thinkst, denied}};
    expect_scan(detector, input, true, settings, filtered, 1);
    json_object_put(settings);

    const char *const malformed[] = {"[]", "{\"skip_ids\":false}", "{\"allowed_accounts\":{}}", "{\"denied_accounts\":[null]}", "{\"skip_ids\":[42]}"};
    for (size_t i = 0; i < sizeof(malformed) / sizeof(malformed[0]); ++i) {
        settings = json_tokener_parse(malformed[i]);
        CHECK(settings);
        test_http http = {0};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport, .options = settings};
        br_results results = {0};
        br_result prior = {0};
        CHECK(br_finding_key(&prior, 777, "prior", "key") == 0 && br_results_push(&results, &prior) == 0);
        unsigned char *saved_raw = results.items[0].raw.data;
        char *error = NULL;
        CHECK(detector->scan(detector, &ctx, false, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) != 0);
        CHECK(error && strstr(error, "invalid AWS access key options:"));
        CHECK(results.len == 1 && results.items[0].raw.data == saved_raw && results.items[0].detector_type == 777);
        CHECK(!http.calls && !http.releases);
        free(error);
        br_results_clear(&results);
        json_object_put(settings);
    }
}

static void cleaner(const br_detector *detector)
{
    const struct { const char *raw, *redacted; bool verified; } values[] = {
        {"a-first", "A", false}, {"b-first", "B", false}, {"a-old-verified", "A", true},
        {"c-first", "C", false}, {"a-last-verified", "A", true}, {"a-late", "A", false}, {"b-late", "B", false},
    };
    br_results results = {0};
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
        br_result result = {0};
        CHECK(br_finding_key(&result, 2, values[i].raw, "access_key_id") == 0);
        result.redacted = strdup(values[i].redacted);
        result.verified = values[i].verified;
        result.verification_error = strdup(values[i].raw);
        CHECK(result.redacted && result.verification_error && br_results_push(&results, &result) == 0);
    }
    br_result saved[7];
    memcpy(saved, results.items, sizeof(saved));
    detector->clean(detector, &results, false);
    CHECK(results.len == 7);
    for (size_t i = 0; i < results.len; ++i) {
        CHECK(results.items[i].raw.data == saved[i].raw.data && results.items[i].redacted == saved[i].redacted);
        CHECK(results.items[i].secret_parts == saved[i].secret_parts && results.items[i].verification_error == saved[i].verification_error);
        CHECK(results.items[i].verified == saved[i].verified);
    }
    detector->clean(detector, &results, true);
    CHECK(results.len == 3);
    bool saw_a = false, saw_b = false, saw_c = false;
    for (size_t i = 0; i < results.len; ++i) {
        br_result *r = &results.items[i];
        if (!strcmp(r->redacted, "A")) {
            CHECK(!saw_a && r->verified && r->raw.data == saved[4].raw.data && r->verification_error == saved[4].verification_error);
            saw_a = true;
        } else if (!strcmp(r->redacted, "B")) {
            CHECK(!saw_b && !r->verified && r->raw.data == saved[1].raw.data);
            saw_b = true;
        } else {
            CHECK(!strcmp(r->redacted, "C") && !saw_c && !r->verified && r->raw.data == saved[3].raw.data);
            saw_c = true;
        }
    }
    CHECK(saw_a && saw_b && saw_c);
    br_results_clear(&results);
    detector->clean(detector, &results, true);
    CHECK(!results.len);
}

static const char sts_success[] =
    "<GetCallerIdentityResponse xmlns='urn:unrestricted'><GetCallerIdentityResult>"
    "<Account>999999999999</Account><UserId>synthetic-user</UserId>"
    "<Arn>arn:aws:iam::999999999999:user/synthetic</Arn>"
    "</GetCallerIdentityResult></GetCallerIdentityResponse>";
static const char invalid_403[] = "<ErrorResponse><Error><Code>InvalidClientTokenId</Code><Message>invalid</Message></Error></ErrorResponse>";
static const char throttle[] = "<ErrorResponse><Error><Code>Throttling</Code><Message>slow down</Message></Error></ErrorResponse>";
static const char signature_error[] = "<ErrorResponse><Error><Code>SignatureDoesNotMatch</Code><Message>bad signature</Message></Error></ErrorResponse>";
static const char canary_denial[] =
    "<ErrorResponse><Error><Code>AuthorizationError</Code><Message>User: arn:aws:iam::052310077262:user/synthetic"
    " is not authorized to perform: sns:Publish on resource: 1</Message></Error><RequestId>xml-id</RequestId></ErrorResponse>";

typedef struct {
    bool sns;
    const br_json *options;
    int64_t deadline;
    br_http_response steps[8];
    size_t count;
    const char *golden;
    char uuids[8][37], metrics[8][32], dates[8][17], auth[8][512];
} aws_wire;

static const char *request_header(const br_http_request *request, const char *name)
{
    for (size_t i = 0; i < request->nheaders; ++i)
        if (!strcasecmp(request->headers[i].name, name)) return request->headers[i].value;
    return NULL;
}

static br_http_response response(int status, const char *body)
{
    return (br_http_response){.status = status, .body = {(const unsigned char *)body, body ? strlen(body) : 0}};
}

static void inspect_wire(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    aws_wire *wire = http->user;
    size_t at = http->calls - 1;
    CHECK(ctx && at < wire->count && at < 8);
    CHECK(request->profile == BR_HTTP_AWS && request->detector_type == 2 && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "POST"));
    CHECK(!strcmp(request->url, wire->sns ? "https://sns.us-east-1.amazonaws.com/" : "https://sts.us-east-1.amazonaws.com/"));
    const char *body = wire->sns ? "Action=Publish&Message=foo&PhoneNumber=1&Version=2010-03-31" : "Action=GetCallerIdentity&Version=2011-06-15";
    CHECK(request->body.len == strlen(body) && !memcmp(request->body.data, body, strlen(body)));
    CHECK(request->nheaders == 7 && !strcmp(request_header(request, "User-Agent"), "TruffleHog"));
    CHECK(!strcmp(request_header(request, "Content-Type"), "application/x-www-form-urlencoded"));
    CHECK(!strcmp(request_header(request, "Content-Length"), wire->sns ? "59" : "43"));
    CHECK(!request_header(request, "X-Amz-Security-Token") && !request_header(request, "X-Amz-Target") && !request_header(request, "X-Amz-Content-Sha256"));
    const char *uuid = request_header(request, "Amz-Sdk-Invocation-Id");
    CHECK(uuid && strlen(uuid) == 36 && uuid[14] == '4' && uuid[19] == '8');
    const char *metric = request_header(request, "Amz-Sdk-Request");
    const char *date = request_header(request, "X-Amz-Date");
    const char *auth = request_header(request, "Authorization");
    CHECK(metric && date && auth && strlen(date) == 16 && strlen(auth) < 512);
    CHECK(strstr(auth, "SignedHeaders=amz-sdk-invocation-id;amz-sdk-request;content-length;content-type;host;x-amz-date, Signature="));
    snprintf(wire->uuids[at], 37, "%s", uuid);
    snprintf(wire->metrics[at], 32, "%s", metric);
    snprintf(wire->dates[at], 17, "%s", date);
    snprintf(wire->auth[at], 512, "%s", auth);
    if (wire->golden && !at) {
        CHECK(!strcmp(uuid, "11111111-2222-4333-8444-555555555555"));
        CHECK(!strcmp(date, "20240102T030405Z") && !strcmp(metric, "attempt=1; max=3"));
        CHECK(strstr(auth, wire->golden) && !strcmp(auth + strlen(auth) - 64, wire->golden));
    }
    http->response = wire->steps[at];
}

static br_results wire_scan(const br_detector *detector, const char *input, aws_wire *wire, test_http *http)
{
    uuid_calls = jitter_calls = sleep_calls = 0;
    slept_ns = 0;
    *http = (test_http){.inspect = inspect_wire, .user = wire};
    br_transport transport = test_transport(http);
    br_scan_ctx ctx = {.transport = &transport, .options = wire->options, .deadline_monotonic_ms = wire->deadline};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(http->calls == wire->count && http->releases == http->calls);
    return results;
}

static void verified_result(const br_result *result, bool sns)
{
    CHECK(result->verified && !result->verification_error);
    if (sns) {
        check_text(result->extra_data, "arn", "arn:aws:iam::052310077262:user/synthetic");
        check_text(result->extra_data, "is_canary", "true");
        CHECK(!json_object_object_get_ex(result->extra_data, "rotation_guide", NULL));
    } else {
        check_text(result->extra_data, "rotation_guide", "https://howtorotate.com/docs/tutorials/aws/");
        check_text(result->extra_data, "account", "999999999999");
        check_text(result->extra_data, "user_id", "synthetic-user");
        check_text(result->extra_data, "arn", "arn:aws:iam::999999999999:user/synthetic");
    }
}

static void wire_success_and_errors(const br_detector *detector)
{
    char input[256], canary[21];
    const char *golden_secret = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn";
    make_id(canary, "AKIA", UINT64_C(52310077262), 25);
    /* Independent Python hashlib/hmac vectors using the SDK's observed
     * canonical requests (43/59 byte payloads), not the production C signer. */
    aws_wire wire = {.count = 1, .golden = "54d5a601f2a83add305d591dd5753e47d19c8c882df8ec43c3c3c950b96ce512"};
    wire.steps[0] = response(200, sts_success);
    snprintf(input, sizeof(input), "AKIAABCDEFGHIJKLMNOP\n%s", golden_secret);
    test_http http;
    br_results results = wire_scan(detector, input, &wire, &http);
    CHECK(results.len == 1 && uuid_calls == 1 && !jitter_calls);
    CHECK(strstr(wire.auth[0], "Credential=AKIAABCDEFGHIJKLMNOP/20240102/us-east-1/sts/aws4_request"));
    verified_result(&results.items[0], false);
    br_results_clear(&results);

    wire = (aws_wire){.sns = true, .count = 1, .golden = "ba3009bc37d1f327d7331b1aeb2e6c5023c94885c44795fd61a18f13d2bd7d59"};
    wire.steps[0] = response(403, canary_denial);
    snprintf(input, sizeof(input), "%s\n%s", canary, golden_secret);
    results = wire_scan(detector, input, &wire, &http);
    CHECK(results.len == 1 && uuid_calls == 1 && !jitter_calls);
    verified_result(&results.items[0], true);
    br_results_clear(&results);

    const struct { bool sns; int status; const char *body, *error; } cases[] = {
        {false, 403, signature_error, NULL},
        {false, 403, invalid_403, NULL},
        {false, 400, invalid_403, NULL},
        {false, 401, "<e><Error><Code>Other</Code><Message>nope</Message></Error></e>", "api error Other: nope"},
        {false, 400, "<e/>", "api error UnknownError: UnknownError"},
        {false, 400, "<e><Error><Code>OnlyCode</Code></Error></e>", "api error OnlyCode: UnknownError"},
        {false, 400, "<e><Error><Message>OnlyMessage</Message></Error></e>", "api error UnknownError: OnlyMessage"},
        {true, 403, signature_error, "api error SignatureDoesNotMatch: bad signature"},
        {true, 403, invalid_403, NULL},
        {true, 400, "<e><Error><Message>does not match the signature you provided</Message></Error></e>", NULL},
        {true, 400, "<e><Error><Code>authorizationerror</Code><mEsSaGe>nope</mEsSaGe></Error></e>", "AuthorizationError: nope"},
        {true, 400, "<e><Error><Code>AuthorizationError</Code></Error></e>", "AuthorizationError: "},
        {false, 200, "<e><Account>a</Account></e>", "GetCallerIdentityResult node not found"},
        {false, 200, "{\"Account\":\"synthetic\",\"Arn\":\"synthetic\",\"UserId\":\"synthetic\"}", "unsupported: AWS XML syntax/streaming diagnostics"},
        {false, 200, "<?xml version='1.0' encoding='ISO-8859-1'?><e><GetCallerIdentityResult><Account>a</Account><UserId>u</UserId><Arn>a</Arn></GetCallerIdentityResult></e>", "unsupported: AWS XML encoding"},
        {false, 200, "<e><GetCallerIdentityResult><Account><nested/></Account></GetCallerIdentityResult></e>", "unsupported: AWS XML simple-value token shape"},
        {false, 200, "<e><GetCallerIdentityResult><Account>a<!--not text-->b</Account><UserId>u</UserId><Arn>a</Arn></GetCallerIdentityResult></e>", "unsupported: AWS XML simple-value token shape"},
        {false, 200, "<e><GetCallerIdentityResult><Account><![CDATA[a]]><![CDATA[b]]></Account><UserId>u</UserId><Arn>a</Arn></GetCallerIdentityResult></e>", "unsupported: AWS XML simple-value token shape"},
        {false, 200, "<e><GetCallerIdentityResult><Account><![CDATA[]]><![CDATA[a]]></Account><UserId>u</UserId><Arn>a</Arn></GetCallerIdentityResult></e>", "unsupported: AWS XML simple-value token shape"},
        {false, 200, "<e><GetCallerIdentityResult><Account>a<![CDATA[]]></Account><UserId>u</UserId><Arn>a</Arn></GetCallerIdentityResult></e>", "unsupported: AWS XML simple-value token shape"},
        {false, 200, "<!DOCTYPE e [<!ENTITY a 'synthetic'>]><e/>", "unsupported: AWS XML DTD"},
        {false, 200, "<!DOCTYPE e SYSTEM 'https://must-not-resolve.invalid/aws.dtd'><e/>", "unsupported: AWS XML DTD"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        wire = (aws_wire){.sns = cases[i].sns, .count = 1};
        wire.steps[0] = response(cases[i].status, cases[i].body);
        snprintf(input, sizeof(input), "%s\n%s", cases[i].sns ? canary : id1, secret1);
        results = wire_scan(detector, input, &wire, &http);
        CHECK(results.len == 1 && !results.items[0].verified && uuid_calls == 1 && !jitter_calls);
        if (cases[i].error) CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, cases[i].error));
        else CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
    }

    /* libxml2 otherwise auto-detects UTF16 even without an encoding declaration. */
    unsigned char utf16[2 + 2 * (sizeof(sts_success) - 1)];
    utf16[0] = 0xff; utf16[1] = 0xfe;
    for (size_t i = 0; i < sizeof(sts_success) - 1; ++i) {
        utf16[2 + 2 * i] = (unsigned char)sts_success[i];
        utf16[3 + 2 * i] = 0;
    }
    wire = (aws_wire){.count = 1};
    wire.steps[0] = (br_http_response){.status = 200, .body = {utf16, sizeof(utf16)}};
    snprintf(input, sizeof(input), "%s\n%s", id1, secret1);
    results = wire_scan(detector, input, &wire, &http);
    CHECK(results.len == 1 && !results.items[0].verified && results.items[0].verification_error);
    CHECK(!strcmp(results.items[0].verification_error, "unsupported: AWS XML syntax/streaming diagnostics"));
    br_results_clear(&results);

    /* Case-folded immediate result/field names, duplicate fields, namespaces,
     * unknown subtree skipping, text/entity decoding and empty non-nil fields. */
    wire = (aws_wire){.count = 1};
    wire.steps[0] = response(201, "<odd xmlns:p='urn:any'><ignored><GetCallerIdentityResult/></ignored><p:gEtCaLlErIdEnTiTyReSuLt>"
        "<p:Account>old</p:Account><p:ACCOUNT>999999999999</p:ACCOUNT><p:UserId>synthetic-user</p:UserId>"
        "<p:Arn>arn:aws:iam::999999999999:user/synthetic</p:Arn><unknown><nested/></unknown></p:gEtCaLlErIdEnTiTyReSuLt></odd>");
    snprintf(input, sizeof(input), "%s\n%s", id1, secret1);
    results = wire_scan(detector, input, &wire, &http);
    CHECK(results.len == 1); verified_result(&results.items[0], false); br_results_clear(&results);
    wire.steps[0] = response(200, "<?xml version='1.0' encoding='uTf-8'?><e><GetCallerIdentityResult><Account/><UserId>a&amp;b</UserId><Arn><![CDATA[synthetic]]></Arn></GetCallerIdentityResult></e>");
    results = wire_scan(detector, input, &wire, &http);
    CHECK(results.len == 1 && results.items[0].verified);
    check_text(results.items[0].extra_data, "account", "");
    check_text(results.items[0].extra_data, "user_id", "a&b");
    check_text(results.items[0].extra_data, "arn", "synthetic");
    br_results_clear(&results);
    wire.steps[0] = response(200, "<e><GetCallerIdentityResult><Account><![CDATA[]]></Account><UserId> \t </UserId><Arn><![CDATA[]]></Arn></GetCallerIdentityResult></e>");
    results = wire_scan(detector, input, &wire, &http);
    CHECK(results.len == 1 && results.items[0].verified);
    check_text(results.items[0].extra_data, "account", "");
    check_text(results.items[0].extra_data, "user_id", " \t ");
    check_text(results.items[0].extra_data, "arn", "");
    br_results_clear(&results);

    char body[512], expected[512];
    snprintf(body, sizeof(body), "<e><Error><Code>Other</Code><Message>%s %s</Message></Error></e>", secret1, id1);
    snprintf(expected, sizeof(expected), "api error Other: [REDACTED] %s", id1);
    wire.steps[0] = response(400, body);
    results = wire_scan(detector, input, &wire, &http);
    CHECK(results.len == 1 && !strcmp(results.items[0].verification_error, expected));
    br_results_clear(&results);
    /* Header overrides XML request ID before the source substring classifier. */
    static const br_header request_id[] = {{"x-amzn-requestid", "InvalidClientTokenId"}};
    wire.steps[0].headers = request_id; wire.steps[0].nheaders = 1;
    results = wire_scan(detector, input, &wire, &http);
    CHECK(results.len == 1 && !results.items[0].verification_error);
    br_results_clear(&results);
}

static void retries_and_consumption(const br_detector *detector)
{
    char input[512];
    snprintf(input, sizeof(input), "%s\n%s", id1, secret1);
    test_http http;
    aws_wire wire = {.count = 3};
    wire.steps[0] = response(503, "<e/>"); wire.steps[1] = response(400, throttle); wire.steps[2] = response(200, sts_success);
    br_results results = wire_scan(detector, input, &wire, &http);
    CHECK(results.len == 1 && results.items[0].verified && uuid_calls == 1 && jitter_calls == 2);
    CHECK(sleep_calls && slept_ns == UINT64_C(3000000000));
    CHECK(!strcmp(wire.uuids[0], wire.uuids[1]) && !strcmp(wire.uuids[1], wire.uuids[2]));
    CHECK(!strcmp(wire.metrics[0], "attempt=1; max=3") && !strcmp(wire.metrics[1], "attempt=2; max=3") && !strcmp(wire.metrics[2], "attempt=3; max=3"));
    CHECK(strcmp(wire.auth[0], wire.auth[1]) && strcmp(wire.auth[1], wire.auth[2]));
    br_results_clear(&results);
    for (size_t i = 0; i < 3; ++i) wire.steps[i] = response(500, "<e/>");
    results = wire_scan(detector, input, &wire, &http);
    CHECK(results.len == 1 && !results.items[0].verified && !strcmp(results.items[0].verification_error, "api error UnknownError: UnknownError"));
    CHECK(jitter_calls == 2 && uuid_calls == 1);
    br_results_clear(&results);

    static const br_header skewed[] = {{"Date", "Tue, 02 Jan 2024 03:14:05 GMT"}};
    static const br_header aligned[] = {{"Date", "Tue, 02 Jan 2024 03:04:05 GMT"}};
    wire.steps[0] = response(403, signature_error); wire.steps[0].headers = skewed; wire.steps[0].nheaders = 1;
    wire.steps[1] = response(403, signature_error); wire.steps[1].headers = aligned; wire.steps[1].nheaders = 1;
    wire.steps[2] = response(200, sts_success);
    results = wire_scan(detector, input, &wire, &http);
    CHECK(results.len == 1 && results.items[0].verified && uuid_calls == 1 && jitter_calls == 2);
    CHECK(!strcmp(wire.dates[0], "20240102T030405Z") && !strcmp(wire.dates[1], "20240102T031405Z") && !strcmp(wire.dates[2], "20240102T030405Z"));
    br_results_clear(&results);
    wire.count = 1; wire.deadline = 2000000;
    results = wire_scan(detector, input, &wire, &http);
    CHECK(results.len == 1 && !results.items[0].verified && !strcmp(results.items[0].verification_error, "unsupported: AWS skew-adjusted deadline/TTL timing"));
    br_results_clear(&results);
    wire.deadline = 0;
    static const br_header boundary[] = {{"Date", "Tue, 02 Jan 2024 03:08:05 GMT"}};
    wire.steps[0].headers = boundary;
    results = wire_scan(detector, input, &wire, &http);
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error && !jitter_calls);
    br_results_clear(&results);
    static const br_header cached[] = {{"Date", "Tue, 02 Jan 2024 03:14:05 GMT"}, {"Age", "0"}};
    wire.steps[0].headers = cached; wire.steps[0].nheaders = 2;
    results = wire_scan(detector, input, &wire, &http);
    CHECK(results.len == 1 && !results.items[0].verification_error && !jitter_calls);
    br_results_clear(&results);

    /* Low-entropy unique matches still affect detector-level 403 retry count. */
    snprintf(input, sizeof(input), "%s\n%s \nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", id1, secret1);
    wire = (aws_wire){.count = 2};
    wire.steps[0] = wire.steps[1] = response(403, invalid_403);
    results = wire_scan(detector, input, &wire, &http);
    CHECK(results.len == 1 && !results.items[0].verification_error && uuid_calls == 2 && !jitter_calls);
    CHECK(strcmp(wire.uuids[0], wire.uuids[1]) && !strcmp(wire.metrics[1], "attempt=1; max=3"));
    br_results_clear(&results);
    /* Consumed secret is unavailable to the next ID. The remaining population
     * is now one, so its 403 does not cause another detector-level invocation. */
    snprintf(input, sizeof(input), "%s\n%s\n%s \n%s", id1, id2, secret1, secret2);
    wire.steps[0] = response(200, sts_success); wire.steps[1] = response(403, invalid_403);
    results = wire_scan(detector, input, &wire, &http);
    CHECK(results.len == 2 && results.items[0].verified && !results.items[1].verified);
    CHECK(!memcmp(results.items[0].raw_v2.data + 21, secret1, 40) && !memcmp(results.items[1].raw_v2.data + 21, secret2, 40));
    CHECK(!results.items[1].verification_error && uuid_calls == 2);
    br_results_clear(&results);
    wire.steps[1] = response(200, sts_success);
    results = wire_scan(detector, input, &wire, &http);
    CHECK(results.len == 2 && results.items[0].verified && results.items[1].verified && uuid_calls == 2);
    br_results_clear(&results);
}

static void guards_and_rollback(const br_detector *detector)
{
    char input[512], canary[21];
    make_id(canary, "AKIA", UINT64_C(52310077262), 25);
    snprintf(input, sizeof(input), "%s\n%s", id1, secret1);
    test_http http;
    aws_wire wire = {0};
    fail_uuid = true;
    br_results results = wire_scan(detector, input, &wire, &http);
    CHECK(results.len == 1 && !results.items[0].verified && !strcmp(results.items[0].verification_error, "unsupported: AWS invocation randomness failed"));
    CHECK(uuid_calls == 1 && !jitter_calls); br_results_clear(&results); fail_uuid = false;
    fail_clock = true;
    results = wire_scan(detector, input, &wire, &http);
    CHECK(results.len == 1 && !strcmp(results.items[0].verification_error, "unsupported: AWS signing clock unavailable"));
    br_results_clear(&results); fail_clock = false;
    wire.count = 1; wire.steps[0] = response(500, "<e/>"); fail_jitter = true;
    results = wire_scan(detector, input, &wire, &http);
    CHECK(results.len == 1 && !results.items[0].verified && !strcmp(results.items[0].verification_error, "unsupported: AWS retry randomness failed"));
    CHECK(jitter_calls == 1 && !sleep_calls); br_results_clear(&results); fail_jitter = false;
    wire.steps[0] = response(200, sts_success); wire.steps[0].body_error = "synthetic read failure";
    results = wire_scan(detector, input, &wire, &http);
    CHECK(results.len == 1 && !results.items[0].verified && !strcmp(results.items[0].verification_error, "unsupported: AWS XML read-error/streaming semantics"));
    br_results_clear(&results);
    br_json *settings = json_tokener_parse("{\"denied_accounts\":[\"052310077262\"]}");
    CHECK(settings); wire = (aws_wire){.sns = true, .options = settings};
    snprintf(input, sizeof(input), "%s\n%s", canary, secret1);
    results = wire_scan(detector, input, &wire, &http);
    CHECK(results.len == 1 && !results.items[0].verified && !strcmp(results.items[0].verification_error, denied));
    CHECK(!uuid_calls && !jitter_calls); br_results_clear(&results); json_object_put(settings);

    const struct { bool sns; const char *body, *error; } panic_cases[] = {
        {false, "<e><GetCallerIdentityResult><Account>a</Account><UserId>u</UserId></GetCallerIdentityResult></e>", "AWS STS response has nil identity fields"},
        {false, "", "AWS STS response has nil identity fields"},
        {true, "<e><PublishResult/></e>", "AWS SNS Publish returned nil error"},
        {true, "", "AWS SNS Publish returned nil error"},
        {true, "<e><Error><Code>AuthorizationError</Code><Message>not authorized to perform</Message></Error></e>", "AWS canary denial lacks User: "},
    };
    for (size_t i = 0; i < sizeof(panic_cases) / sizeof(panic_cases[0]); ++i) {
        wire = (aws_wire){.sns = panic_cases[i].sns, .count = 1};
        wire.steps[0] = response(i == 4 ? 403 : 200, panic_cases[i].body);
        /* For STS, add a candidate first, then trigger the guarded source panic. */
        if (!panic_cases[i].sns) {
            wire.count = 2; wire.steps[1] = wire.steps[0]; wire.steps[0] = response(400, "<e/>");
            snprintf(input, sizeof(input), "%s\n%s \n%s", id1, secret1, secret2);
        } else snprintf(input, sizeof(input), "%s\n%s", canary, secret1);
        http = (test_http){.inspect = inspect_wire, .user = &wire};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport};
        results = (br_results){0};
        br_result prior = {0};
        CHECK(!br_finding_key(&prior, 777, "prior", "key") && !br_results_push(&results, &prior));
        unsigned char *saved = results.items[0].raw.data;
        char *error = NULL;
        CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) != 0);
        CHECK(error && strstr(error, panic_cases[i].error));
        CHECK(results.len == 1 && results.items[0].raw.data == saved && results.items[0].detector_type == 777);
        CHECK(http.calls == wire.count && http.releases == http.calls);
        free(error); br_results_clear(&results);
    }
}

int main(void)
{
    make_id(id1, "AKIA", UINT64_C(123456789012), 7);
    make_id(id2, "AKIA", UINT64_C(234567890123), 19);
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (size_t i = 0; i < 40; ++i) {
        secret1[i] = alphabet[(i + 25) % 64];
        secret2[i] = alphabet[(i + 40) % 64];
    }
    secret1[40] = secret2[40] = '\0';
    CHECK(br_ascii_shannon_entropy((br_slice){(const unsigned char *)secret1, 40}) >= 4.25);
    CHECK(br_ascii_shannon_entropy((br_slice){(const unsigned char *)secret2, 40}) >= 4.25);
    const br_detector *detector = detector_init();
    extraction(detector);
    url_replacements(detector);
    accounts(detector);
    canaries(detector);
    options(detector);
    cleaner(detector);
    wire_success_and_errors(detector);
    retries_and_consumption(detector);
    guards_and_rollback(detector);
    return test_finish("AWS access keys local + evidenced Query/SigV4 verification");
}
