/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/key_scan.h"
#include "../support/detector_test.h"

static size_t verification_calls;

static int verify_key(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    CHECK(ctx == NULL);
    CHECK(!strcmp(key, "tokenalpha") || !strcmp(key, "tokenbeta"));
    ++verification_calls;
    result->verified = true;
    return 0;
}

static int fail_second_key(const br_scan_ctx *ctx, const char *key, br_result *result)
{
    verify_key(ctx, key, result);
    return verification_calls == 2 ? 1 : 0;
}

static void rollback_failures(const br_detector *detector, br_slice input)
{
    /* Both iteration paths must discard only this invocation's findings after
     * a later positive verifier failure, even without an error-output pointer. */
    for (unsigned mode = 0; mode < 4; ++mode) {
        br_results results = {0};
        br_result caller = {.detector_type = 12345, .verified = true};
        caller.raw.data = (unsigned char *)strdup("keep"); caller.raw.len = 4;
        caller.verification_error = strdup("caller-owned");
        CHECK(caller.raw.data && caller.verification_error);
        CHECK(br_results_push(&results, &caller) == 0);
        br_result prior = results.items[0];
        char *error = NULL;
        char **error_out = mode & 2 ? NULL : &error;
        verification_calls = 0;
        int rc = mode & 1 ? br_scan_unique_key(detector, NULL, true, input, &results,
                               "key", fail_second_key, error_out) :
                           br_scan_key(detector, NULL, true, input, &results,
                               "key", fail_second_key, error_out);
        CHECK(rc != 0 && verification_calls == 2 && results.len == 1);
        CHECK(results.items[0].detector_type == 12345 && results.items[0].verified);
        CHECK(results.items[0].raw.data == prior.raw.data && results.items[0].raw.len == 4);
        CHECK(!memcmp(results.items[0].raw.data, "keep", 4));
        CHECK(results.items[0].verification_error == prior.verification_error);
        CHECK(!strcmp(results.items[0].verification_error, "caller-owned"));
        if (error_out) CHECK(error && !strcmp(error, "out of memory sanitizing verification error"));
        free(error);
        br_results_clear(&results);
    }
}

int main(void)
{
    br_regex *pattern = NULL;
    char *error = NULL;
    CHECK(br_regex_compile("(token[a-z]+)", &pattern, &error) == 0 && !error);
    br_detector detector = {.type = 239, .state = pattern};
    static const unsigned char data[] = "tokenalpha tokenbeta tokenalpha";
    const br_slice input = {data, sizeof(data) - 1};
    br_results results = {0};

    CHECK(br_scan_key(&detector, NULL, true, input, &results, "token", verify_key, &error) == 0);
    CHECK(!error && results.len == 3 && verification_calls == 3);
    test_key_result(&results.items[0], 239, "tokenalpha", "token");
    test_key_result(&results.items[1], 239, "tokenbeta", "token");
    test_key_result(&results.items[2], 239, "tokenalpha", "token");
    CHECK(results.items[0].verified && results.items[1].verified && results.items[2].verified);
    br_results_clear(&results);

    verification_calls = 0;
    CHECK(br_scan_unique_key(&detector, NULL, true, input, &results, "token", verify_key, &error) == 0);
    CHECK(!error && results.len == 2 && verification_calls == 2);
    test_key_result(&results.items[0], 239, "tokenalpha", "token");
    test_key_result(&results.items[1], 239, "tokenbeta", "token");
    CHECK(results.items[0].verified && results.items[1].verified);
    br_results_clear(&results);

    verification_calls = 0;
    CHECK(br_scan_unique_key(&detector, NULL, false, input, &results, "key", verify_key, &error) == 0);
    CHECK(!error && results.len == 2 && verification_calls == 0);
    test_key_result(&results.items[0], 239, "tokenalpha", "key");
    test_key_result(&results.items[1], 239, "tokenbeta", "key");
    CHECK(!results.items[0].verified && !results.items[1].verified);
    br_results_clear(&results);
    rollback_failures(&detector, input);
    verification_calls = 0;
    br_regex_free(pattern);

    pattern = NULL;
    CHECK(br_regex_compile("(a\\x00[b-c])", &pattern, &error) == 0 && !error);
    detector.state = pattern;
    static const unsigned char opaque[] = {'a', 0, 'b', ' ', 'a', 0, 'c', ' ', 'a', 0, 'b'};
    CHECK(br_scan_unique_key(&detector, NULL, false, (br_slice){opaque, sizeof(opaque)},
                             &results, "key", verify_key, &error) == 0);
    CHECK(!error && results.len == 2 && !verification_calls);
    CHECK(results.items[0].raw.len == 3 && !memcmp(results.items[0].raw.data, opaque, 3));
    CHECK(results.items[1].raw.len == 3 && !memcmp(results.items[1].raw.data, opaque + 4, 3));
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(results.items[0].secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == 3 && !memcmp(json_object_get_string(part), opaque, 3));
    br_results_clear(&results);
    br_regex_free(pattern);
    return test_finish("Single-key occurrence and unique scanning");
}
