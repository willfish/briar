/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

static bool fail_next_owned_allocation;

static void *owned_malloc(size_t size)
{
    if (fail_next_owned_allocation) {
        fail_next_owned_allocation = false;
        return NULL;
    }
    return malloc(size);
}

#define malloc owned_malloc
#include "../../src/detectors/privatekey.c"
#undef malloc

static const char valid_key[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n"
    "KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm\n"
    "o3qGy0t6z09AIJtH+5OeRV1be+N4cDYJKffGzDa88vQENZiRm0GRq6a+HPGQMd2k\n"
    "TQIhAKMSvzIBnni7ot/OSie2TmJLY4SwTQAevXysE2RbFDYdAiEBCUEaRQnMnbp7\n"
    "9mxDXDf6AU0cN/RPBjb9qSHDcWZHGzUCIG2Es59z8ugGrDY+pxLQnwfotadxd+Uy\n"
    "v/Ow5T0q5gIJAiEAyS4RaI9YG8EWx/2w0T67ZUVAw8eOMB6BIUg0Xcu+3okCIBOs\n"
    "/5OiPgoTdSy7bcF9IGpSE8ZgGKzgYQVZeN97YE00\n"
    "-----END RSA PRIVATE KEY-----\n";

static const char encrypted_key[] =
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDnvQyInG\n"
    "vB+yh/WYczTGXbAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAILUSv84lMSLVN0iP\n"
    "knFlHoYobo1oohtLNp/ihBaf76QxAAAAoErDjg2HQs1hgYm0vfyrpBxWrcJ1u/LQG4o6cm\n"
    "GJ3NnZmMmJemrnMXjGHB3zj63AEPxxyb6BWZH5Olb5gYMgWcnOU91cGvyC7aT6C5cOnFb1\n"
    "ZtkdxTxqeUOMFS51gwDT04aURSz/caCV9KN4Y2MCHyW+GWxxD7eL0R6KhyT2j0z2BewCw9\n"
    "kRN1fq3C2rTb+wTaNz8q9X0R+6JGxfXGhpTJ0=\n"
    "-----END OPENSSH PRIVATE KEY-----\n";

static const char *extra(const br_result *result, const char *name)
{
    br_json *value = NULL;
    if (!result->extra_data || !json_object_object_get_ex(result->extra_data, name, &value) ||
        !json_object_is_type(value, json_type_string)) return NULL;
    return json_object_get_string(value);
}

static void owned_failures(void)
{
    bool encrypted = false;
    fail_next_owned_allocation = true;
    CHECK(pk_pem_encrypted((br_slice){(const unsigned char *)encrypted_key,
                                      strlen(encrypted_key)}, &encrypted) != 0);
    CHECK(!encrypted && !fail_next_owned_allocation);
    EVP_PKEY *key = NULL;
    char *passphrase = NULL, *error = NULL;
    fail_next_owned_allocation = true;
    CHECK(pk_crack((br_slice){(const unsigned char *)encrypted_key, strlen(encrypted_key)},
                    &key, &passphrase, &error) != 0);
    CHECK(!key && !passphrase && error && !fail_next_owned_allocation);
    free(error);
    error = NULL;
    key = EVP_PKEY_new();
    CHECK(key != NULL);
    char *fingerprint = NULL;
    CHECK(pk_fingerprint(key, &fingerprint, &error) != 0 && !fingerprint && error);
    EVP_PKEY_free(key);
    free(error);
}

int main(void)
{
    owned_failures();
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_privatekey_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 15 && !strcmp(detector->name, "PrivateKey"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "private key"));
    CHECK(detector->max_secret_size == 4096);
    CHECK(detector->false_positive && !detector->false_positive(detector, NULL, &error) && error && !error[0]);
    free(error);
    error = NULL;
    CHECK(detector->state && detector->scan); /* Registry tests own default enablement. */

    char input[1024];
    snprintf(input, sizeof(input), "privatekey token = '%s'", valid_key);
    br_scan_ctx ctx = {0};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 1);
    CHECK(results.items[0].raw.len == strlen(valid_key) &&
          !memcmp(results.items[0].raw.data, valid_key, strlen(valid_key)));
    CHECK(results.items[0].redacted && strlen(results.items[0].redacted) == 64 &&
          !memcmp(results.items[0].redacted, valid_key, 64));
    CHECK(results.items[0].primary_secret.len > 0);
    CHECK(!results.items[0].verified && !results.items[0].verification_error);
    CHECK(results.items[0].extra_data && json_object_object_length(results.items[0].extra_data) == 0);
    br_results_clear(&results);

    snprintf(input, sizeof(input), "privatekey = '-----BEGIN?RSA?PRIVATE?KEY-----\\nnot-a-key\\n-----END RSA PRIVATE KEY-----'");
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);

    snprintf(input, sizeof(input), "privatekey = '%s'", encrypted_key);
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    CHECK(results.items[0].verification_error &&
          strstr(results.items[0].verification_error, "unable to crack encryption"));
    CHECK(extra(&results.items[0], "encrypted") && !strcmp(extra(&results.items[0], "encrypted"), "true"));
    br_results_clear(&results);

    test_http http = {.response = {.status = 200, .body = {(const unsigned char *)"{}", 2}}};
    br_transport transport = test_transport(&http);
    ctx.transport = &transport;
    snprintf(input, sizeof(input), "private key\n%s", valid_key);
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    CHECK(http.calls == 0);
    CHECK(results.items[0].verification_error &&
          strstr(results.items[0].verification_error, "unsupported HTTP client profile") &&
          strstr(results.items[0].verification_error, "unsupported: SSH verification is not available"));
    CHECK(!results.items[0].extra_data);
    br_results_clear(&results);

    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verification_error &&
          strstr(results.items[0].verification_error, "net/http: nil Context"));
    br_results_clear(&results);
    return test_finish("privatekey");
}
