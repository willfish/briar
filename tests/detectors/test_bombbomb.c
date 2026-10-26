/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <strings.h>

#define SLICE(text) ((br_slice){(const unsigned char *)(text), sizeof(text) - 1})
static const char nul_guard[] = "unsupported: BombBomb embedded NUL Authorization header";
static const char status_503[] = "unexpected status code: 503";
static const char *fail_copy;

/* Only a selected verification-error copy fails; no general allocator rig. */
char *strdup(const char *text)
{
    if (fail_copy && !strcmp(text, fail_copy)) { fail_copy = NULL; return NULL; }
    size_t len = strlen(text) + 1; char *copy = malloc(len);
    if (copy) memcpy(copy, text, len);
    return copy;
}

static const br_detector *init(void)
{
    const br_detector *detector = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_bombbomb_init(NULL, &error) == -1 && error && !strcmp(error, "invalid BombBomb detector output")); free(error); error = NULL;
    CHECK(!br_bombbomb_init(&detector, &error) && detector && !error);
    CHECK(!br_bombbomb_init(&again, &error) && again == detector && !error);
    CHECK(detector->type == 565 && detector->version == 0 && !strcmp(detector->name, "BombBomb"));
    CHECK(!strcmp(detector->custom_name, ""));
    CHECK(!strcmp(detector->description, "BombBomb is a video messaging platform that allows users to create and send video emails. BombBomb API keys can be used to access and manage video email campaigns and contacts."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "bombbomb"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    CHECK(detector->scan && detector->state && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void check_result(const br_result *result, br_slice token)
{
    CHECK(result->detector_type == 565 && !result->detector_name);
    CHECK(result->raw.len == token.len && !memcmp(result->raw.data, token.data, token.len));
    CHECK(!result->raw_v2.data && !result->raw_v2.len && !result->redacted && !result->extra_data && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 1);
    br_json *part = NULL; CHECK(json_object_object_get_ex(result->secret_parts, "key", &part)); CHECK(json_object_is_type(part, json_type_string));
    CHECK((size_t)json_object_get_string_len(part) == token.len && !memcmp(json_object_get_string(part), token.data, token.len));
    CHECK(!result->verification_from_cache && !result->primary_secret.data && !result->primary_secret.len && !result->primary_line);
    CHECK(!result->chunk_offset && !result->chunk_offset_set);
}

static void check_error(const br_result *result, bool verified, const char *error)
{
    CHECK(result->verified == verified);
    if (error) CHECK(result->verification_error && !strcmp(result->verification_error, error));
    else CHECK(!result->verification_error);
}

static br_bytes prefixed(const char *prefix, size_t gap, const br_slice *tokens, size_t count)
{
    size_t plen = strlen(prefix), size = 1;
    for (size_t i = 0; i < count; ++i) size += plen + gap + tokens[i].len + 1;
    unsigned char *out = malloc(size); CHECK(out); size_t at = 0;
    for (size_t i = 0; i < count; ++i) {
        memcpy(out + at, prefix, plen); at += plen; memset(out + at, ' ', gap); at += gap;
        memcpy(out + at, tokens[i].data, tokens[i].len); at += tokens[i].len; out[at++] = '\n';
    }
    out[at] = 0; return (br_bytes){out, at};
}

static void extraction_case(const br_detector *detector, const char *prefix, size_t gap, br_slice token, const br_slice *expected)
{
    br_bytes input = prefixed(prefix, gap, &token, 1);
    br_results results = test_scan(detector, NULL, false, input.data, input.len); CHECK(results.len == (expected ? 1u : 0u));
    if (expected) { check_result(&results.items[0], *expected); check_error(&results.items[0], false, NULL); }
    br_results_clear(&results); free(input.data);
}

static br_bytes ranged_token(size_t first, size_t second, size_t third)
{
    size_t len = 2 + first + 1 + 2 + second + 1 + third;
    unsigned char *out = malloc(len); CHECK(out); size_t at = 0;
    memcpy(out + at, "ey", 2); at += 2; memset(out + at, 'A', first); at += first; out[at++] = '.';
    memcpy(out + at, "ey", 2); at += 2; memset(out + at, 'B', second); at += second; out[at++] = '.';
    memset(out + at, 'C', third); return (br_bytes){out, len};
}

static void extraction_and_limits(const br_detector *detector)
{
    br_slice minimal = SLICE("ey!eyZ"), punctuation = SLICE("ey?ey@A"), nul = SLICE("ey\0eyZ");
    extraction_case(detector, "bombbomb", 1, minimal, &minimal); /* All three minima zero; neither dot literal. */
    extraction_case(detector, "BOMBBOMB", 1, punctuation, &punctuation);
    extraction_case(detector, "bombbomb", 40, minimal, &minimal);
    extraction_case(detector, "bombbomb", 41, minimal, NULL);
    extraction_case(detector, "key", 1, minimal, NULL);
    extraction_case(detector, "bombbomb", 1, SLICE("Ey!eyZ"), NULL);
    extraction_case(detector, "bombbomb", 1, SLICE("ey!EyZ"), NULL);
    extraction_case(detector, "bombbomb", 1, SLICE("ey\neyZ"), NULL); /* Capture dots are not DOTALL. */
    extraction_case(detector, "bombbomb", 1, SLICE("ey.ey."), NULL); /* Final ASCII word boundary still matters. */
    extraction_case(detector, "bombbomb", 1, nul, &nul);
    br_bytes large = ranged_token(140, 419, 171); br_slice expected = {large.data, large.len}; CHECK(large.len == 736);
    extraction_case(detector, "bombbomb", 1, expected, &expected); free(large.data);
    large = ranged_token(141, 0, 1); extraction_case(detector, "bombbomb", 1, (br_slice){large.data, large.len}, NULL); free(large.data);
    large = ranged_token(0, 420, 1); expected = (br_slice){large.data, large.len - 2};
    extraction_case(detector, "bombbomb", 1, (br_slice){large.data, large.len}, &expected); free(large.data); /* Extra B becomes wildcard. */
    large = ranged_token(0, 0, 172); expected = (br_slice){large.data, 6};
    extraction_case(detector, "bombbomb", 1, (br_slice){large.data, large.len}, &expected); free(large.data); /* Third backtracks to zero. */
    br_slice duplicates[] = {minimal, minimal, nul}; br_bytes input = prefixed("bombbomb", 1, duplicates, 3);
    br_results results = test_scan(detector, NULL, false, input.data, input.len); CHECK(results.len == 3);
    for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], duplicates[i]);
    br_results_clear(&results); free(input.data);
}

/* Force the final wildcard to hold the suffix rune and the third class to be
 * empty: 172 A's cannot fit its 171-byte maximum with a final word boundary. */
static br_bytes suffix_input(br_slice suffix)
{
    static const unsigned char before[] = "bombbomb ey.ey";
    size_t len = sizeof(before) - 1 + suffix.len + 172; unsigned char *input = malloc(len); CHECK(input);
    memcpy(input, before, sizeof(before) - 1); memcpy(input + sizeof(before) - 1, suffix.data, suffix.len);
    memset(input + sizeof(before) - 1 + suffix.len, 'A', 172); return (br_bytes){input, len};
}

static void suffix_whitespace(const br_detector *detector)
{
    const br_slice spaces[] = {SLICE(" "), SLICE("\t"), SLICE("\v"), SLICE("\f"), SLICE("\r"),
        SLICE("\xc2\x85"), SLICE("\xc2\xa0"), SLICE("\xe1\x9a\x80"), SLICE("\xe2\x80\x80"), SLICE("\xe2\x80\x8a"),
        SLICE("\xe2\x80\xa8"), SLICE("\xe2\x80\xa9"), SLICE("\xe2\x80\xaf"), SLICE("\xe2\x81\x9f"), SLICE("\xe3\x80\x80")};
    for (size_t i = 0; i < sizeof(spaces) / sizeof(spaces[0]); ++i) {
        br_bytes input = suffix_input(spaces[i]); br_results results = test_scan(detector, NULL, false, input.data, input.len);
        CHECK(results.len == 1); check_result(&results.items[0], SLICE("ey.ey")); br_results_clear(&results); free(input.data);
    }
    br_bytes input = suffix_input(SLICE("\n")); br_results results = test_scan(detector, NULL, false, input.data, input.len);
    CHECK(!results.len); br_results_clear(&results); free(input.data);
    input = suffix_input(SLICE("\xe2\x80\x8b")); results = test_scan(detector, NULL, false, input.data, input.len);
    CHECK(results.len == 1); check_result(&results.items[0], SLICE("ey.ey" "\xe2\x80\x8b")); br_results_clear(&results); free(input.data); /* U+200B is not White_Space. */
    br_slice internal = SLICE("ey" "\xc2\xa0" "ey" "\xe2\x80\x83" "A");
    extraction_case(detector, "bombbomb", 1, internal, &internal); /* Internal whitespace remains byte-for-byte. */
}

typedef struct { br_slice token; int status, send_rc; const char *send_error; } reply;
typedef struct {
    reply replies[3]; size_t count, releases, cancel_calls; bool cancel, expired;
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
    script *steps = http->user; size_t at = http->calls - 1; CHECK(at < steps->count && at < 3 && ctx == steps->expected_ctx);
    reply *step = &steps->replies[at];
    CHECK(request->profile == BR_HTTP_SANE && request->detector_type == 565 && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.bombbomb.com/v2/user/"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && header(request, "User-Agent") && !strcmp(header(request, "User-Agent"), "TruffleHog"));
    CHECK(!header(request, "Content-Type") && !header(request, "Accept") && !header(request, "Content-Length"));
    const char *auth = header(request, "Authorization");
    CHECK(auth && strlen(auth) == 7 + step->token.len && !memcmp(auth, "Bearer ", 7));
    CHECK(!memcmp(auth + 7, step->token.data, step->token.len));
    static const unsigned char body[] = "\xff\0not JSON";
    http->response = (br_http_response){.status = step->status, .body = {body, sizeof(body) - 1}, .body_error = "ignored read/drain/close error"};
    http->send_error = step->send_error; http->send_rc = step->send_error ? -1 : step->send_rc;
}

static bool cancelled(void *user) { script *steps = user; ++steps->cancel_calls; return steps->cancel; }

static br_results scan(const br_detector *detector, br_slice input, bool verify, script *steps)
{
    test_http http = {.inspect = inspect, .user = steps}; br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport, .cancelled = cancelled, .cancel_user = steps,
                       .deadline_monotonic_ms = steps->expired ? 1 : 0}; steps->expected_ctx = &ctx;
    br_results results = test_scan(detector, &ctx, verify, input.data, input.len);
    CHECK(http.calls == steps->count && http.releases == steps->releases); return results;
}

static br_results single(const br_detector *detector, reply step)
{
    br_bytes input = prefixed("bombbomb", 1, &step.token, 1); script steps = {.count = 1, .releases = 1}; steps.replies[0] = step;
    br_results results = scan(detector, (br_slice){input.data, input.len}, true, &steps); free(input.data); CHECK(results.len == 1);
    check_result(&results.items[0], step.token); return results;
}

static void verification(const br_detector *detector)
{
    br_slice token = SLICE("ey!eyZ"); const int statuses[] = {200, 401, 201, 403, 503};
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        br_results results = single(detector, (reply){.token = token, .status = statuses[i]});
        char expected[80]; snprintf(expected, sizeof(expected), "unexpected status code: %d", statuses[i]);
        check_error(&results.items[0], statuses[i] == 200, statuses[i] == 200 || statuses[i] == 401 ? NULL : expected); br_results_clear(&results);
    }
    br_results results = single(detector, (reply){.token = token, .status = 200, .send_error = "unredacted ey!eyZ repeats ey!eyZ"});
    check_error(&results.items[0], false, "unredacted ey!eyZ repeats ey!eyZ"); br_results_clear(&results);
    results = single(detector, (reply){.token = token, .send_rc = -1}); check_error(&results.items[0], false, "HTTP transport failed"); br_results_clear(&results);
    results = single(detector, (reply){.token = SLICE("ey\teyZ"), .status = 200}); check_error(&results.items[0], true, NULL); br_results_clear(&results);
    results = single(detector, (reply){.token = SLICE("ey" "\xc2\xa0" "ey" "\xe2\x80\x83" "A"), .status = 200});
    check_error(&results.items[0], true, NULL); br_results_clear(&results);
    br_bytes input = suffix_input(SLICE("\xe3\x80\x80")); script steps = {.count = 1, .releases = 1};
    steps.replies[0] = (reply){.token = SLICE("ey.ey"), .status = 200}; results = scan(detector, (br_slice){input.data, input.len}, true, &steps);
    CHECK(results.len == 1); check_result(&results.items[0], SLICE("ey.ey")); check_error(&results.items[0], true, NULL); br_results_clear(&results); free(input.data);
}

static void guards_and_context(const br_detector *detector)
{
    br_slice tokens[] = {SLICE("ey\0eyZ"), SLICE("ey!eyZ"), SLICE("ey!eyZ")};
    br_bytes input = prefixed("bombbomb", 1, tokens, 3); script steps = {.count = 2, .releases = 2};
    steps.replies[0] = (reply){.token = tokens[1], .status = 200}; steps.replies[1] = (reply){.token = tokens[2], .status = 401};
    br_results results = scan(detector, (br_slice){input.data, input.len}, true, &steps); CHECK(results.len == 3);
    for (size_t i = 0; i < 3; ++i) check_result(&results.items[i], tokens[i]);
    check_error(&results.items[0], false, nul_guard); check_error(&results.items[1], true, NULL); check_error(&results.items[2], false, NULL);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input.data, input.len); CHECK(results.len == 3);
    for (size_t i = 0; i < 3; ++i) check_error(&results.items[i], false, "net/http: nil Context");
    br_results_clear(&results); free(input.data); /* Nil constructor context precedes NUL guard. */
    const br_slice controls[] = {SLICE("ey\reyZ"), SLICE("ey\veyZ"), SLICE("ey\feyZ"), SLICE("ey\x01" "eyZ"), SLICE("ey\x7f" "eyZ")};
    for (size_t i = 0; i < sizeof(controls) / sizeof(controls[0]); ++i) {
        input = prefixed("bombbomb", 1, &controls[i], 1); steps = (script){.releases = 1};
        results = scan(detector, (br_slice){input.data, input.len}, true, &steps); CHECK(results.len == 1);
        check_result(&results.items[0], controls[i]); check_error(&results.items[0], false, "invalid HTTP header"); br_results_clear(&results); free(input.data);
    }
    for (int deadline = 0; deadline < 2; ++deadline) {
        input = prefixed("bombbomb", 1, &tokens[1], 1); steps = (script){.cancel = !deadline, .expired = deadline};
        results = scan(detector, (br_slice){input.data, input.len}, false, &steps); CHECK(results.len == 1 && !steps.cancel_calls);
        check_error(&results.items[0], false, NULL); br_results_clear(&results);
        steps.releases = 1; results = scan(detector, (br_slice){input.data, input.len}, true, &steps); CHECK(results.len == 1 && steps.cancel_calls);
        check_error(&results.items[0], false, deadline ? "context deadline exceeded" : "context canceled"); br_results_clear(&results); free(input.data);
    }
}

static void setter_failure_rollback(const br_detector *detector)
{
    for (int guard = 0; guard < 2; ++guard) {
        br_slice tokens[] = {SLICE("ey!eyZ"), guard ? SLICE("ey\0eyZ") : SLICE("ey!eyZ")};
        br_bytes input = prefixed("bombbomb", 1, tokens, 2); script steps = {.count = guard ? 1u : 2u, .releases = guard ? 1u : 2u};
        steps.replies[0] = (reply){.token = tokens[0], .status = 200}; steps.replies[1] = (reply){.token = tokens[1], .status = 503};
        test_http http = {.inspect = inspect, .user = &steps}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        br_results results = {0}; br_result prior = {0}; char *error = NULL;
        CHECK(!br_finding_key(&prior, 777, "prior", "key") && !br_results_push(&results, &prior)); unsigned char *saved = results.items[0].raw.data;
        fail_copy = guard ? nul_guard : status_503;
        int rc = detector->scan(detector, &ctx, true, (br_slice){input.data, input.len}, &results, &error);
        CHECK(!fail_copy && rc == -1 && error && !strcmp(error, "cannot store BombBomb verification error"));
        CHECK(http.calls == steps.count && http.releases == steps.releases && results.len == 1);
        CHECK(results.items[0].raw.data == saved && results.items[0].detector_type == 777); free(error); br_results_clear(&results);
        results = scan(detector, (br_slice){input.data, input.len}, true, &steps); CHECK(results.len == 2);
        check_error(&results.items[0], true, NULL); check_error(&results.items[1], false, guard ? nul_guard : status_503);
        br_results_clear(&results); free(input.data);
    }
}

int main(void)
{
    const br_detector *detector = init();
    extraction_and_limits(detector); suffix_whitespace(detector); verification(detector);
    guards_and_context(detector); setter_failure_rollback(detector);
    return test_finish("BombBomb wildcard byte captures + Unicode suffix trim + NUL/header guards");
}
