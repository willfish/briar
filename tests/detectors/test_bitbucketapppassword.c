/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <limits.h>
#include <openssl/evp.h>
#include <strings.h>

static const char username[] = "offline-user";
static const char password[] = "ATBBsynthetic_9=.-";
static const char auth_golden[] = "Basic b2ZmbGluZS11c2VyOkFUQkJzeW50aGV0aWNfOT0uLQ==";
static const char status_503[] = "unexpected status code: 503";
static bool fail_status_copy;

char *strdup(const char *text)
{
    if (fail_status_copy && !strcmp(text, status_503)) { fail_status_copy = false; return NULL; }
    size_t len = strlen(text) + 1; char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}

static const br_detector *init(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_bitbucketapppassword_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Bitbucket App Password detector output"));
    free(error); error = NULL;
    CHECK(!br_bitbucketapppassword_init(&detector, &error) && detector && !error);
    CHECK(!br_bitbucketapppassword_init(&again, &error) && again == detector && !error);
    CHECK(detector->type == 1029 && detector->version == 0 && !strcmp(detector->name, "BitbucketAppPassword"));
    CHECK(!strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "Bitbucket is a Git repository hosting service by Atlassian. Bitbucket App Passwords are used to authenticate to the Bitbucket API."));
    CHECK(detector->nkeywords == 2 && !strcmp(detector->keywords[0], "bitbucket") && !strcmp(detector->keywords[1], "ATBB"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_text(br_json *object, const char *name, const char *text)
{
    br_json *value = NULL; CHECK(json_object_object_get_ex(object, name, &value)); CHECK(json_object_is_type(value, json_type_string));
    CHECK((size_t)json_object_get_string_len(value) == strlen(text)); CHECK(!memcmp(json_object_get_string(value), text, strlen(text)));
}

static void check_result(const br_result *result, const char *user, const char *pass)
{
    size_t ulen = strlen(user), plen = strlen(pass);
    CHECK(result->detector_type == 1029 && !result->detector_name);
    CHECK(result->raw.len == ulen + 1 + plen && !memcmp(result->raw.data, user, ulen));
    CHECK(result->raw.data[ulen] == ':' && !memcmp(result->raw.data + ulen + 1, pass, plen));
    CHECK(!result->raw_v2.data && !result->raw_v2.len && !result->redacted && !result->extra_data && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    check_text(result->secret_parts, "username", user); check_text(result->secret_parts, "password", pass);
    CHECK(!result->verification_from_cache && !result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static void check_error(const br_result *result, bool verified, const char *error)
{
    CHECK(result->verified == verified);
    if (error) CHECK(result->verification_error && !strcmp(result->verification_error, error));
    else CHECK(!result->verification_error);
}

static br_result *find_user(br_results *results, const char *user)
{
    for (size_t i = 0; i < results->len; ++i) {
        br_json *value = NULL; CHECK(json_object_object_get_ex(results->items[i].secret_parts, "username", &value));
        if (!strcmp(json_object_get_string(value), user)) return &results->items[i];
    }
    CHECK(false); return NULL;
}

static void extraction_case(const br_detector *detector, const char *input, const char *user, const char *pass)
{
    br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == (user ? 1u : 0u));
    if (user) { check_result(&results.items[0], user, pass); check_error(&results.items[0], false, NULL); }
    br_results_clear(&results);
}

static void extraction(const br_detector *detector)
{
    extraction_case(detector, "x:ATBBtest", "x", "ATBBtest"); /* Direct pattern, no provider prefix needed. */
    extraction_case(detector, "x:atbbtest", NULL, NULL);
    extraction_case(detector, "x:AtBBtest", NULL, NULL);
    extraction_case(detector, "x:XATBBtest", NULL, NULL);
    extraction_case(detector, "x:ATBB", NULL, NULL);
    extraction_case(detector, "x:ATBB-", NULL, NULL); /* + and the final word boundary both matter. */
    extraction_case(detector, "x:ATBBtest=.-", "x", "ATBBtest");
    extraction_case(detector, ".dash_name-9:ATBBtest_", "dash_name-9", "ATBBtest_");
    extraction_case(detector, "https://x:ATBBtest=.-@bitbucket.org", "x", "ATBBtest=.-");
    extraction_case(detector, "https://x:ATBB-@bitbucket.org.evil/path", "x", "ATBB-"); /* No P2 endpoint boundary. */
    extraction_case(detector, "HTTPS://x:ATBBtest=.-@bitbucket.org", "x", "ATBBtest"); /* Only P1 fires. */
    extraction_case(detector, "https://x:ATBBtest=.-@BITBUCKET.org", "x", "ATBBtest");
    extraction_case(detector, "\"x\",\"ATBB-\"", "x", "ATBB-");
    extraction_case(detector, "\"x\", \t\n\f\r\"ATBBtest=.-\"", "x", "ATBBtest=.-");
    extraction_case(detector, "\"x\",\f\"ATBBtest\"", "x", "ATBBtest");
    extraction_case(detector, "\"x\",\v\"ATBBtest\"", NULL, NULL); /* Go \\s excludes VT. */
    extraction_case(detector, "\"x\", \"atbbtest\"", NULL, NULL);
    extraction_case(detector, "", NULL, NULL);
    char input[128], user[32]; memset(user, 'a', 30); user[30] = '\0';
    snprintf(input, sizeof(input), "%s:ATBBtest", user); extraction_case(detector, input, user, "ATBBtest");
    user[30] = 'a'; user[31] = '\0'; snprintf(input, sizeof(input), "%s:ATBBtest", user); extraction_case(detector, input, NULL, NULL);
    const char quoted[] = "before\n\n(\"quoted_user\", \"ATBBquoted=.-\")";
    br_results results = test_scan(detector, NULL, false, quoted, sizeof(quoted) - 1); CHECK(results.len == 1);
    check_result(&results.items[0], "quoted_user", "ATBBquoted=.-");
    CHECK(br_slice_find((br_slice){(const unsigned char *)quoted, sizeof(quoted) - 1},
                        (br_slice){results.items[0].raw.data, results.items[0].raw.len}, 0) == SIZE_MAX);
    br_results_clear(&results); /* No password-based primary secret or fabricated location. */
}

static void ordered_overwrites(const br_detector *detector)
{
    extraction_case(detector, "u:ATBBfirst\nu:ATBBsecond", "u", "ATBBsecond");
    extraction_case(detector, "u:ATBBfirst\nu:ATBBfirst", "u", "ATBBfirst");
    extraction_case(detector, "https://u:ATBBurl=.-@bitbucket.org\nu:ATBBlater", "u", "ATBBurl=.-");
    extraction_case(detector, "https://u:ATBBurl1=.-@bitbucket.org\nhttps://u:ATBBurl2=.-@bitbucket.org\nu:ATBBlater", "u", "ATBBurl2=.-");
    extraction_case(detector, "\"u\", \"ATBBquoted=.-\"\nhttps://u:ATBBurl=.-@bitbucket.org\nu:ATBBlater", "u", "ATBBquoted=.-");
    extraction_case(detector, "\"u\", \"ATBBquoted1\"\n\"u\", \"ATBBquoted2=.-\"\nhttps://u:ATBBurl=.-@bitbucket.org", "u", "ATBBquoted2=.-");
    const char input[] = "User:ATBBold\nuser:ATBBshared\nUser:ATBBshared\nv:ATBBdifferent";
    br_results results = test_scan(detector, NULL, false, input, sizeof(input) - 1); CHECK(results.len == 3);
    check_result(find_user(&results, "User"), "User", "ATBBshared"); check_result(find_user(&results, "user"), "user", "ATBBshared");
    check_result(find_user(&results, "v"), "v", "ATBBdifferent"); br_results_clear(&results);
}

/* Independent OpenSSL Base64 fixture for the dynamic Basic header. A frozen
 * Python base64.b64encode golden also checks the representative credential. */
static char *expected_auth(const char *user, const char *pass)
{
    size_t ulen = strlen(user), plen = strlen(pass), len = ulen + 1 + plen;
    CHECK(len <= INT_MAX);
    unsigned char *joined = malloc(len); size_t encoded_len = 4 * ((len + 2) / 3);
    char *out = malloc(encoded_len + 7); CHECK(joined && out);
    memcpy(joined, user, ulen); joined[ulen] = ':'; memcpy(joined + ulen + 1, pass, plen); memcpy(out, "Basic ", 6);
    CHECK(EVP_EncodeBlock((unsigned char *)out + 6, joined, (int)len) == (int)encoded_len); free(joined); return out;
}

typedef struct { const char *user, *pass, *send_error; int status, send_rc; } reply;
typedef struct {
    reply replies[3]; size_t count, cancel_calls; bool cancel, expired;
    const br_scan_ctx *expected_ctx;
} script;

static const char *header(const br_http_request *request, const char *name)
{
    for (size_t i = 0; i < request->nheaders; ++i)
        if (!strcasecmp(request->headers[i].name, name)) return request->headers[i].value;
    return NULL;
}

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user; size_t at = http->calls - 1;
    CHECK(at < steps->count && at < 3 && http->releases == at && ctx == steps->expected_ctx);
    reply *step = &steps->replies[at];
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 1029 && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.bitbucket.org/2.0/user"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.len);
    CHECK(request->nheaders == 3 && header(request, "User-Agent") && !strcmp(header(request, "User-Agent"), "TruffleHog"));
    CHECK(header(request, "Accept") && !strcmp(header(request, "Accept"), "application/json"));
    CHECK(!header(request, "Content-Type") && !header(request, "Content-Length"));
    char *auth = expected_auth(step->user, step->pass);
    CHECK(header(request, "Authorization") && !strcmp(header(request, "Authorization"), auth)); free(auth);
    static const unsigned char body[] = "\xff\0not JSON";
    http->response = (br_http_response){.status = step->status, .body = {body, sizeof(body) - 1}, .body_error = "ignored body/drain/close failure"};
    http->send_error = step->send_error; http->send_rc = step->send_error ? -1 : step->send_rc;
}

static bool cancelled(void *user) { script *steps = user; ++steps->cancel_calls; return steps->cancel; }

static br_results scan(const br_detector *detector, const char *input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .cancelled = cancelled, .cancel_user = steps,
                       .deadline_monotonic_ms = steps->expired ? 1 : 0}; steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(http.calls == steps->count && http.releases == http.calls + (verify && (steps->cancel || steps->expired) ? 1u : 0u));
    return results;
}

static br_results single(const br_detector *detector, reply step)
{
    size_t len = strlen(step.user) + strlen(step.pass) + 16; char *input = malloc(len); CHECK(input);
    snprintf(input, len, "\"%s\", \"%s\"", step.user, step.pass);
    script steps = {.count = 1}; steps.replies[0] = step;
    br_results results = scan(detector, input, true, &steps); free(input); CHECK(results.len == 1);
    check_result(&results.items[0], step.user, step.pass); return results;
}

static void verification(const br_detector *detector)
{
    char *auth = expected_auth(username, password); CHECK(!strcmp(auth, auth_golden)); free(auth);
    const int statuses[] = {200, 403, 401, 201, 400, 503};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        br_results results = single(detector, (reply){.user = username, .pass = password, .status = statuses[i]});
        char expected[80]; snprintf(expected, sizeof(expected), "unexpected status code: %d", statuses[i]);
        check_error(&results.items[0], statuses[i] == 200 || statuses[i] == 403,
                      statuses[i] == 200 || statuses[i] == 403 || statuses[i] == 401 ? NULL : expected); br_results_clear(&results);
    }
    char cause[256]; snprintf(cause, sizeof(cause), "synthetic %s %s repeated %s %s; keep endpoint https://api.bitbucket.org/2.0/user", username, password, username, password);
    br_results results = single(detector, (reply){.user = username, .pass = password, .status = 200, .send_error = cause});
    check_error(&results.items[0], false, "synthetic [REDACTED] [REDACTED] repeated [REDACTED] [REDACTED]; keep endpoint https://api.bitbucket.org/2.0/user"); br_results_clear(&results);
    results = single(detector, (reply){.user = username, .pass = password, .status = 200, .send_rc = -1});
    check_error(&results.items[0], false, "HTTP transport failed"); br_results_clear(&results);
    /* Source replaces username before password, not longest-first. */
    results = single(detector, (reply){.user = "ATBB", .pass = "ATBBsynthetic", .send_error = "ATBBsynthetic"});
    check_error(&results.items[0], false, "[REDACTED]synthetic"); br_results_clear(&results);
}

static void long_password_and_context(const br_detector *detector)
{
    size_t len = 8197; char *large = malloc(len + 1); CHECK(large); memcpy(large, "ATBB", 4);
    const char alphabet[] = "Ab0_=.-9";
    for (size_t i = 4; i < len; ++i) large[i] = alphabet[i % (sizeof(alphabet) - 1)];
    large[len - 1] = 'Z'; large[len] = '\0';
    br_results results = single(detector, (reply){.user = username, .pass = large, .status = 403});
    check_error(&results.items[0], true, NULL); br_results_clear(&results); free(large);
    char input[128]; snprintf(input, sizeof(input), "\"%s\", \"%s\"", username, password);
    for (int deadline = 0; deadline < 2; ++deadline) {
        script steps = {.cancel = !deadline, .expired = deadline};
        results = scan(detector, input, false, &steps); CHECK(results.len == 1 && !steps.cancel_calls);
        check_result(&results.items[0], username, password); check_error(&results.items[0], false, NULL); br_results_clear(&results);
        results = scan(detector, input, true, &steps); CHECK(results.len == 1 && steps.cancel_calls);
        check_result(&results.items[0], username, password); check_error(&results.items[0], false, deadline ? "context deadline exceeded" : "context canceled"); br_results_clear(&results);
    }
    results = test_scan(detector, NULL, true, input, strlen(input)); CHECK(results.len == 1);
    check_result(&results.items[0], username, password); check_error(&results.items[0], false, "net/http: nil Context"); br_results_clear(&results);
}

static void final_map_only_and_resource_failure(const br_detector *detector)
{
    const char input[] = "\"u\", \"ATBBquoted=.-\"\nhttps://u:ATBBurl=.-@bitbucket.org\nu:ATBBlater\nv:ATBBother";
    script steps = {.count = 2}; steps.replies[0] = (reply){.user = "u", .pass = "ATBBquoted=.-", .status = 200};
    steps.replies[1] = (reply){.user = "v", .pass = "ATBBother", .status = 503};
    br_results results = scan(detector, input, true, &steps); CHECK(results.len == 2);
    check_result(find_user(&results, "u"), "u", "ATBBquoted=.-"); check_error(find_user(&results, "u"), true, NULL);
    check_result(find_user(&results, "v"), "v", "ATBBother"); check_error(find_user(&results, "v"), false, status_503); br_results_clear(&results);
    test_http http = {.inspect = inspect, .user = &steps}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
    br_result prior = {0}; char *error = NULL;
    CHECK(!br_finding_key(&prior, 777, "prior", "key") && !br_results_push(&results, &prior));
    unsigned char *saved = results.items[0].raw.data; fail_status_copy = true;
    int rc = detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, sizeof(input) - 1}, &results, &error);
    CHECK(!fail_status_copy && rc == -1 && error && !strcmp(error, "cannot verify Bitbucket App Password candidate"));
    CHECK(http.calls == 2 && http.releases == 2 && results.len == 1);
    CHECK(results.items[0].raw.data == saved && results.items[0].detector_type == 777); free(error); br_results_clear(&results);
    results = scan(detector, input, true, &steps); CHECK(results.len == 2); br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = init();
    extraction(detector); ordered_overwrites(detector); verification(detector);
    long_password_and_context(detector); final_map_only_and_resource_failure(detector);
    return test_finish("Bitbucket App Password ordered username map + assembled Raw + Basic verification");
}
