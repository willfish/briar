/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/azureapimanagement_repositorykey.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char password1[106], password2[106], password3[106];
static unsigned host_counter;
static const char native_guard[] = "unsupported: native Git execution for Azure API Management repository keys";

typedef struct {
    br_azureapim_git_output mode;
    int rc;
    bool not_found;
    br_slice output;
    const char *leaf, *host, *password;
} git_step;
typedef struct { git_step steps[32]; size_t count, calls, allocations; } fake_git;

static void make_password(char out[106], size_t shift)
{
    memcpy(out, "git&123456789012&", 17);
    test_secret(out + 17, 83, shift);
    memcpy(out + 100, "+/Z==", 6);
}

static void fresh_host(char out[80])
{
    snprintf(out, 80, "synthetic-apim-%u.scm.azure-api.net", ++host_counter);
}

static size_t add_attempt(fake_git *fake, const char *host, const char *password)
{
    static const unsigned char initial[] = "ignored initial output";
    static const unsigned char version[] = "git version 2.44.0\n";
    static const unsigned char remote[] = "no matching ref is still success";
    size_t at = fake->count;
    CHECK(at + 3 <= sizeof(fake->steps) / sizeof(fake->steps[0]));
    fake->steps[at] = (git_step){BR_AZUREAPIM_GIT_DISCARD, 1, false,
        {initial, sizeof(initial) - 1}, "ignored initial exit status 1", NULL, NULL};
    fake->steps[at + 1] = (git_step){BR_AZUREAPIM_GIT_STDOUT, 0, false,
        {version, sizeof(version) - 1}, "ignored successful version leaf", NULL, NULL};
    fake->steps[at + 2] = (git_step){BR_AZUREAPIM_GIT_COMBINED, 0, false,
        {remote, sizeof(remote) - 1}, "ignored successful remote leaf", host, password};
    fake->count += 3;
    return at;
}

static int run_fake(void *user, const char *const *argv, size_t argc,
                      br_azureapim_git_output mode, br_azureapim_git_result *out)
{
    fake_git *fake = user;
    CHECK(fake && fake->calls < fake->count);
    const git_step *step = &fake->steps[fake->calls++];
    CHECK(!out->output.data && !out->output.len && !out->leaf_error && !out->not_found);
    CHECK(mode == step->mode && argv && !strcmp(argv[0], "git"));
    if (mode == BR_AZUREAPIM_GIT_DISCARD) CHECK(argc == 1);
    else if (mode == BR_AZUREAPIM_GIT_STDOUT) CHECK(argc == 2 && !strcmp(argv[1], "--version"));
    else {
        CHECK(mode == BR_AZUREAPIM_GIT_COMBINED && argc == 5);
        CHECK(!strcmp(argv[1], "ls-remote") && !strcmp(argv[3], "--quiet"));
        CHECK(!strcmp(argv[4], "TRUFFLEHOG_CHECK_GIT_REMOTE_URL_REACHABILITY"));
        /* The fixture has exactly one slash at byte 101; '&', '+' and '='
         * remain literal. There is no invented slash between '@' and HOST. */
        char expected[256];
        snprintf(expected, sizeof(expected), "https://apim:%.101s%%2F%s@%s",
                 step->password, step->password + 102, step->host);
        CHECK(!strcmp(argv[2], expected));
    }
    /* Owned buffers are returned on success, command failure AND resource
     * failure, including DISCARD. The provider must clear each before reuse. */
    out->output.data = malloc(step->output.len + 1);
    CHECK(out->output.data);
    if (step->output.len) memcpy(out->output.data, step->output.data, step->output.len);
    out->output.data[step->output.len] = 0;
    out->output.len = step->output.len;
    out->leaf_error = strdup(step->leaf ? step->leaf : "synthetic owned leaf");
    CHECK(out->leaf_error);
    out->not_found = step->not_found;
    fake->allocations += 2;
    return step->rc;
}

static br_results scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        const void *input, size_t len, fake_git *fake)
{
    br_azureapimanagement_repositorykey_set_git_runner(fake ? run_fake : NULL, fake);
    br_results results = test_scan(detector, ctx, verify, input, len);
    if (fake) CHECK(fake->calls == fake->count && fake->allocations == 2 * fake->calls);
    br_azureapimanagement_repositorykey_set_git_runner(NULL, NULL);
    return results;
}

static void check_result(const br_result *result, const char *host, const char *password)
{
    size_t host_len = strlen(host), password_len = strlen(password);
    CHECK(result->detector_type == 1018 && !result->detector_name);
    CHECK(result->raw.data && result->raw.len == password_len && !memcmp(result->raw.data, password, password_len));
    CHECK(result->raw_v2.data && result->raw_v2.len == host_len + password_len);
    CHECK(!memcmp(result->raw_v2.data, host, host_len));
    CHECK(!memcmp(result->raw_v2.data + host_len, password, password_len));
    CHECK(!result->redacted && !result->extra_data && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *url = NULL, *secret = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "url", &url));
    CHECK(json_object_object_get_ex(result->secret_parts, "password", &secret));
    CHECK(json_object_is_type(url, json_type_string) && !strcmp(json_object_get_string(url), host));
    CHECK(json_object_is_type(secret, json_type_string) && !strcmp(json_object_get_string(secret), password));
    CHECK(!result->verification_from_cache);
    CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    br_azureapimanagement_repositorykey_set_git_runner(NULL, NULL);
    CHECK(!br_azureapimanagement_repositorykey_init(&detector, &error) && detector && !error);
    CHECK(!br_azureapimanagement_repositorykey_init(&again, &error) && again == detector && !error);
    CHECK(detector->type == 1018 && detector->version == 0 && !strcmp(detector->name, "AzureApiManagementRepositoryKey"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description,
        "Azure API Management Repository Keys provide access to the API Management (APIM) configuration repository, "
        "allowing users to directly interact with and modify API definitions, policies, and settings. These keys "
        "enable programmatic access to APIM's Git-based repository, where configurations can be cloned, edited, "
        "and pushed back to apply changes. They are primarily used for managing API configurations as code, "
        "automating deployments, and synchronizing APIM settings across environments."));
    CHECK(detector->nkeywords == 2 && !strcmp(detector->keywords[0], "azure") &&
          !strcmp(detector->keywords[1], ".scm.azure-api.net"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->scan && detector->state && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    CHECK(br_azureapimanagement_repositorykey_init(NULL, &error) != 0 && error);
    free(error);
    return detector;
}

static void expect_extract(const br_detector *detector, const char *input, const char *host,
                             const char *password, size_t count)
{
    fake_git fake = {0};
    br_results results = scan(detector, NULL, false, input, strlen(input), &fake);
    CHECK(results.len == count);
    for (size_t i = 0; i < count; ++i) {
        check_result(&results.items[i], host, password);
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    const char *host = "synthetic-apim.scm.azure-api.net";
    char input[512];
    const struct { const char *format; size_t count; } cases[] = {
        {"url '%s'\npassword '%s'", 1},
        {"URL %s\nPASSWORD %s", 1},
        {"AZURE\r\n%s\nAZURE\r\n%s", 1},
        {"prefixurlsuffix %s\npassword %s", 1},
        {"url %sx\npassword %sx", 1}, /* Neither capture has a trailing boundary. */
        {"%s\n%s", 0},
        {"url %s", 0},
        {"url %s\npassword _%s", 0},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), cases[i].format, host, password1);
        expect_extract(detector, input, host, password1, cases[i].count);
    }
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "url", 3); memset(input + 3, '-', gap);
        snprintf(input + 3 + gap, sizeof(input) - 3 - gap, "%s\npassword %s", host, password1);
        expect_extract(detector, input, host, password1, gap == 40 ? 1 : 0);
        memcpy(input, "password", 8); memset(input + 8, '-', gap);
        /* Put the host afterwards so its internal 'azure' cannot prefix the password. */
        snprintf(input + 8 + gap, sizeof(input) - 8 - gap, "%s\nurl %s", password1, host);
        expect_extract(detector, input, host, password1, gap == 40 ? 1 : 0);
    }
    const char *bad_hosts[] = {"a.scm.azure-api.net", "SYNTHETIC.scm.azure-api.net", "ab.SCM.azure-api.net"};
    for (size_t i = 0; i < sizeof(bad_hosts) / sizeof(bad_hosts[0]); ++i) {
        snprintf(input, sizeof(input), "url %s\npassword %s", bad_hosts[i], password1);
        expect_extract(detector, input, NULL, NULL, 0);
    }
    char long_host[80];
    memset(long_host, 'b', 51); strcpy(long_host + 51, ".scm.azure-api.net");
    snprintf(input, sizeof(input), "url %s\npassword %s", long_host, password1);
    /* No leading host boundary: the capture is the last 50 stem characters. */
    expect_extract(detector, input, long_host + 1, password1, 1);
    char changed[106]; memcpy(changed, password1, sizeof(changed)); changed[0] = 'G';
    snprintf(input, sizeof(input), "url %s\npassword %s", host, changed);
    expect_extract(detector, input, NULL, NULL, 0);
    memcpy(changed, password1, sizeof(changed)); changed[17] = '_';
    snprintf(input, sizeof(input), "url %s\npassword %s", host, changed);
    expect_extract(detector, input, NULL, NULL, 0);
    snprintf(input, sizeof(input), "url %s\npassword %.104s", host, password1);
    expect_extract(detector, input, NULL, NULL, 0);
    expect_extract(detector, "", NULL, NULL, 0);
}

static void unique_pairs_and_native_guard(const br_detector *detector)
{
    char a[80], b[80], input[768]; fresh_host(a); fresh_host(b);
    snprintf(input, sizeof(input), "url %s\nurl %s\nurl %s\npassword %s\npassword %s\npassword %s",
             a, b, a, password1, password2, password1);
    const char *hosts[] = {a, b}, *passwords[] = {password1, password2};
    for (int verify = 0; verify <= 1; ++verify) {
        fake_git fake = {0};
        if (verify) for (size_t h = 0; h < 2; ++h) for (size_t p = 0; p < 2; ++p) add_attempt(&fake, hosts[h], passwords[p]);
        br_results results = scan(detector, NULL, verify, input, strlen(input), &fake);
        CHECK(results.len == 4);
        for (size_t i = 0; i < 4; ++i) {
            check_result(&results.items[i], hosts[i / 2], passwords[i % 2]);
            CHECK(results.items[i].verified == (bool)verify && !results.items[i].verification_error);
        }
        br_results_clear(&results);
    }
    snprintf(input, sizeof(input), "url %s\npassword %s", a, password1);
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    br_results results = scan(detector, &ctx, true, input, strlen(input), NULL);
    CHECK(results.len == 1 && !results.items[0].verified);
    CHECK(!strcmp(results.items[0].verification_error, native_guard));
    CHECK(http.calls == 0 && http.releases == 0);
    check_result(&results.items[0], a, password1);
    br_results_clear(&results);
}

static void command_and_version_branches(const br_detector *detector)
{
    const struct { const char *output, *bad_version; } cases[] = {
        {"git version 2.20.0\n", NULL},
        {"v02.00020.9.vendor", NULL},
        {"git version 2.999999999999999999999999.0", NULL},
        {"git version 2.19.99", "2.19.99"},
        {"git version 3.0.0", "3.0.0"},
        {"first 1.999.0 then 2.20.0", "1.999.0"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        char host[80], input[256], expected[256]; fresh_host(host);
        snprintf(input, sizeof(input), "url %s\npassword %s", host, password1);
        fake_git fake = {0}; add_attempt(&fake, host, password1);
        fake.steps[1].output = (br_slice){(const unsigned char *)cases[i].output, strlen(cases[i].output)};
        if (cases[i].bad_version) fake.count = 2;
        br_results results = scan(detector, NULL, true, input, strlen(input), &fake);
        CHECK(results.len == 1); check_result(&results.items[0], host, password1);
        CHECK(results.items[0].verified == !cases[i].bad_version);
        if (cases[i].bad_version) {
            snprintf(expected, sizeof(expected), "git version is %s, but must be greater than or equal to 2.20.0, and less than 3.0.0", cases[i].bad_version);
            CHECK(!strcmp(results.items[0].verification_error, expected));
        } else CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
    }
    char host[80], input[256]; fresh_host(host);
    snprintf(input, sizeof(input), "url %s\npassword %s", host, password1);
    fake_git fake = {0}; add_attempt(&fake, host, password1);
    fake.count = 1; fake.steps[0].not_found = true;
    br_results results = scan(detector, NULL, true, input, strlen(input), &fake);
    CHECK(results.len == 1 && !results.items[0].verified);
    CHECK(!strcmp(results.items[0].verification_error, "'git' command not found in $PATH. Make sure git is installed and included in $PATH"));
    br_results_clear(&results);
    fake = (fake_git){0}; add_attempt(&fake, host, password1);
    fake.count = 2; fake.steps[1].rc = 1; fake.steps[1].leaf = "exit status 7";
    results = scan(detector, NULL, true, input, strlen(input), &fake);
    CHECK(results.len == 1 && !results.items[0].verified && !strcmp(results.items[0].verification_error, "exit status 7"));
    br_results_clear(&results);
    static const unsigned char binary_version[] = "ignored\0git version 2.20.0";
    fake = (fake_git){0}; add_attempt(&fake, host, password1);
    fake.steps[1].output = (br_slice){binary_version, sizeof(binary_version) - 1};
    results = scan(detector, NULL, true, input, strlen(input), &fake);
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
}

static void remote_errors_and_redaction(const br_detector *detector)
{
    static const unsigned char auth[] = "\0Authentication failed and Could not resolve host";
    const struct { int rc; const char *output; size_t len; bool verified, error; } cases[] = {
        {1, (const char *)auth, sizeof(auth) - 1, false, false},
        {1, "authentication failed", sizeof("authentication failed") - 1, false, true},
        {1, "could not resolve host", sizeof("could not resolve host") - 1, false, true},
        {0, (const char *)auth, sizeof(auth) - 1, true, false},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        char host[80], input[256], leaf[384], expected[384]; fresh_host(host);
        snprintf(input, sizeof(input), "url %s\npassword %s", host, password1);
        snprintf(leaf, sizeof(leaf), "failed %s password=%s again=%s", host, password1, host);
        snprintf(expected, sizeof(expected), "failed [REDACTED] password=%s again=[REDACTED]", password1);
        fake_git fake = {0}; add_attempt(&fake, host, password1);
        fake.steps[2].rc = cases[i].rc; fake.steps[2].leaf = leaf;
        fake.steps[2].output = (br_slice){(const unsigned char *)cases[i].output, cases[i].len};
        br_results results = scan(detector, NULL, true, input, strlen(input), &fake);
        CHECK(results.len == 1 && results.items[0].verified == cases[i].verified);
        check_result(&results.items[0], host, password1);
        if (cases[i].error) {
            CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, expected));
            CHECK(!strstr(results.items[0].verification_error, host) && strstr(results.items[0].verification_error, password1));
        } else CHECK(!results.items[0].verification_error);
        br_results_clear(&results);
        /* Auth wins over DNS, wrong-case markers do not cache, and successful
         * commands ignore their output. All these hosts must still be attempted. */
        fake = (fake_git){0}; add_attempt(&fake, host, password1);
        results = scan(detector, NULL, true, input, strlen(input), &fake);
        CHECK(results.len == 1 && results.items[0].verified); br_results_clear(&results);
    }
}

static void host_cache(const br_detector *detector)
{
    char a[80], b[80], input[768]; fresh_host(a); fresh_host(b);
    const char *passwords[] = {password1, password2, password3};
    snprintf(input, sizeof(input), "url %s\nurl %s\npassword %s\npassword %s\npassword %s",
             a, b, password1, password2, password3);
    fake_git fake = {0}; add_attempt(&fake, a, password1);
    size_t dns = add_attempt(&fake, a, password2) + 2;
    static const unsigned char missing[] = "binary\0Could not resolve host";
    fake.steps[dns].rc = 1; fake.steps[dns].leaf = "exit status 128";
    fake.steps[dns].output = (br_slice){missing, sizeof(missing) - 1};
    for (size_t p = 0; p < 3; ++p) add_attempt(&fake, b, passwords[p]);
    br_results results = scan(detector, NULL, true, input, strlen(input), &fake);
    CHECK(results.len == 4); check_result(&results.items[0], a, password1);
    for (size_t i = 1; i < 4; ++i) check_result(&results.items[i], b, passwords[i - 1]);
    for (size_t i = 0; i < 4; ++i) CHECK(results.items[i].verified && !results.items[i].verification_error);
    br_results_clear(&results);
    fake = (fake_git){0};
    for (size_t p = 0; p < 3; ++p) add_attempt(&fake, b, passwords[p]);
    results = scan(detector, NULL, true, input, strlen(input), &fake);
    CHECK(results.len == 3);
    for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], b, passwords[i]);
    br_results_clear(&results);
    fake = (fake_git){0}; results = scan(detector, NULL, false, input, strlen(input), &fake);
    CHECK(results.len == 6);
    for (size_t i = 0; i < 6; ++i) {
        check_result(&results.items[i], i < 3 ? a : b, passwords[i % 3]);
        CHECK(!results.items[i].verified && !results.items[i].verification_error);
    }
    br_results_clear(&results);
    snprintf(input, sizeof(input), "url %s\npassword %s", a, password1);
    results = scan(detector, NULL, true, input, strlen(input), NULL);
    CHECK(results.len == 0); br_results_clear(&results);
}

static void panic_and_resource_guards(const br_detector *detector)
{
    for (size_t stage = 0; stage < 4; ++stage) {
        char host[80], input[512]; fresh_host(host);
        snprintf(input, sizeof(input), "url %s\npassword %s\npassword %s", host, password1, password2);
        fake_git fake = {0}; add_attempt(&fake, host, password1);
        size_t at = add_attempt(&fake, host, password2);
        if (!stage) {
            static const unsigned char malformed[] = "git version synthetic";
            fake.steps[at + 1].output = (br_slice){malformed, sizeof(malformed) - 1};
            fake.count = at + 2;
        } else {
            fake.steps[at + stage - 1].rc = -1;
            fake.count = at + stage;
        }
        br_results results = {0}; br_result prior = {0}; char *error = NULL;
        CHECK(!br_finding_key(&prior, 777, "prior synthetic finding", "key"));
        CHECK(!br_results_push(&results, &prior));
        unsigned char *saved = results.items[0].raw.data;
        br_azureapimanagement_repositorykey_set_git_runner(run_fake, &fake);
        CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) != 0);
        br_azureapimanagement_repositorykey_set_git_runner(NULL, NULL);
        CHECK(error && strstr(error, !stage ? "unsupported upstream panic:" : "resource failure running"));
        CHECK(results.len == 1 && results.items[0].detector_type == 777 && results.items[0].raw.data == saved);
        CHECK(fake.calls == fake.count && fake.allocations == 2 * fake.calls);
        free(error); br_results_clear(&results);
    }
}

int main(void)
{
    make_password(password1, 0); make_password(password2, 7); make_password(password3, 19);
    const br_detector *detector = descriptor();
    extraction(detector);
    unique_pairs_and_native_guard(detector);
    command_and_version_branches(detector);
    remote_errors_and_redaction(detector);
    host_cache(detector);
    panic_and_resource_guards(detector);
    printf("AzureApiManagementRepositoryKey: %zu assertions, 0 failures; synthetic C fake Git runner only, no process/network execution\n", test_assertions);
    return 0;
}
