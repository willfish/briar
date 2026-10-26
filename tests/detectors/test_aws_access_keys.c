/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <inttypes.h>

static char id1[21], id2[21], secret1[41], secret2[41];
static const char unsupported[] = "unsupported: AWS SDK verification is not implemented";
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
    CHECK(detector->type == 1 && detector->version == 0);
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
    CHECK(result->detector_type == 1 && !result->detector_name);
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
    /* A guessed successful STS response must not enable the guarded verifier. */
    static const unsigned char body[] = "{\"Account\":\"123456789012\",\"Arn\":\"synthetic\",\"UserId\":\"synthetic\"}";
    test_http http = {.response = {.status = 200, .body = {body, sizeof(body) - 1}}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .options = options};
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
        CHECK(br_finding_key(&result, 1, values[i].raw, "access_key_id") == 0);
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
    return test_finish("AWS access keys local behavior (SDK verification unsupported)");
}
