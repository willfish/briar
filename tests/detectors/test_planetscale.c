/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <limits.h>

int br_planetscale_init(const br_detector **out, char **error);

#define br_http_send planetscale_real_send
#define br_http_release planetscale_real_release
#include "../../src/http.c"
#undef br_http_send
#undef br_http_release
#define br_results_push planetscale_real_push
#define br_result_set_verification_error planetscale_real_setter
#include "../../src/result.c"
#undef br_results_push
#undef br_result_set_verification_error

static char users[3][13], tokens[4][55], suffix[44];
static size_t fail_after, failed_allocations, fail_part_after, fail_request_after, fail_push_after;
static size_t fail_setter_after, setter_calls, setter_nsecrets, setter_secret_len, id_adds, token_adds;
static bool fail_next_malloc;
static char setter_cause[160];
static unsigned char setter_secret[80];

static struct {
    bool active, prepare, fail_headers, close_failed;
    const br_scan_ctx *ctx;
    br_results *out;
    size_t base, sends, releases;
    const br_http_request *requests[8];
    br_http_response *responses[8];
    bool completed[8], released[8];
    size_t release_len[8], release_order[8];
    const char *expect_auth[8];
} frames;

void *malloc(size_t size)
{
    if (fail_next_malloc || (fail_after && --fail_after == 0)) {
        fail_next_malloc = false;
        ++failed_allocations;
        return NULL;
    }
    return calloc(1, size);
}
char *strdup(const char *value)
{
    size_t n = strlen(value) + 1;
    char *copy = malloc(n);
    if (copy) memcpy(copy, value, n);
    return copy;
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "id")) ++id_adds;
    if (!strcmp(name, "token")) ++token_adds;
    if ((!strcmp(name, "id") || !strcmp(name, "token")) && fail_part_after && --fail_part_after == 0) return 1;
    int rc = json_object_object_add_ex(object, name, value, 0);
    if (!rc && !strcmp(name, "token") && fail_request_after && --fail_request_after == 0) fail_next_malloc = true;
    return rc;
}
int br_results_push(br_results *out, br_result *owned)
{
    if (fail_push_after && --fail_push_after == 0) return 1;
    return planetscale_real_push(out, owned);
}
int br_result_set_verification_error(br_result *result, const char *cause, const br_slice *secrets, size_t count)
{
    ++setter_calls;
    setter_nsecrets = count;
    setter_secret_len = 0;
    setter_cause[0] = '\0';
    if (cause) {
        size_t n = strlen(cause);
        if (n >= sizeof setter_cause) n = sizeof setter_cause - 1;
        memcpy(setter_cause, cause, n);
        setter_cause[n] = '\0';
    }
    if (count == 1 && secrets && secrets[0].data && secrets[0].len <= sizeof setter_secret) {
        memcpy(setter_secret, secrets[0].data, secrets[0].len);
        setter_secret_len = secrets[0].len;
    }
    if (fail_setter_after && --fail_setter_after == 0) return 1;
    return planetscale_real_setter(result, cause, secrets, count);
}

static void credential(char *out, size_t cap, const char *user, const char *token)
{
    int n = snprintf(out, cap, "%s:%s", user, token);
    CHECK(n > 0 && (size_t)n < cap && n == (int)(strlen(user) + 1 + strlen(token)));
}

static void build_identities(void)
{
    memcpy(users[0], "fo57eya1lvvh", 13);
    test_secret(users[1], 12, 3);
    test_secret(users[2], 12, 17);
    users[1][0] = 'a';
    users[2][0] = 'z';
    for (size_t i = 0; i < 4; ++i) {
        memcpy(tokens[i], "pscale_tkn_", 11);
        test_secret(suffix, 43, 20 + i * 7);
        memcpy(tokens[i] + 11, suffix, 44);
        tokens[i][14] = (char)('A' + i);
        tokens[i][25] = '_';
        CHECK(strlen(users[i < 3 ? i : 0]) == 12 && strlen(tokens[i]) == 54);
        CHECK(!strstr(tokens[i], users[0]) && !strstr(tokens[i], users[1]) && !strstr(tokens[i], users[2]));
    }
    CHECK(strcmp(users[0], users[1]) && strcmp(users[1], users[2]) && strcmp(tokens[0], tokens[1]));
}

static bool request_ok(const br_http_request *request, const char *auth)
{
    if (!request || strcmp(request->method, "GET") || strcmp(request->url, "https://api.planetscale.com/v1/organizations"))
        return false;
    if (request->body.data || request->body.len || request->timeout_ms || request->timeout_ms == 15000) return false;
    if (request->profile != BR_HTTP_SANE || request->detector_type != 195 || request->nheaders != 2 || !request->headers)
        return false;
    if (request->dedup_key.data || request->dedup_key.len) return false;
    if (strcmp(request->headers[0].name, "Authorization") || strcmp(request->headers[1].name, "Accept")) return false;
    if (!request->headers[0].value || strcmp(request->headers[0].value, auth) || strncmp(auth, "Basic ", 6) == 0)
        return false;
    return !strcmp(request->headers[1].value, "application/json");
}

int br_http_send(const br_scan_ctx *ctx, const br_http_request *request, br_http_response *response, char **error)
{
    if (frames.active) {
        size_t i = frames.sends++;
        CHECK(i < 8 && request_ok(request, frames.expect_auth[i]));
        frames.requests[i] = request;
        frames.responses[i] = response;
        frames.ctx = ctx;
        if (frames.prepare) {
            br_http_prepared_request prepared = {0};
            char *prep_error = NULL;
            CHECK(br_http_request_prepare(ctx, request, &prepared, &prep_error) == 0 && !prep_error);
            CHECK(prepared.request.timeout_ms == 5000 && prepared.request.timeout_ms != 15000);
            CHECK(prepared.request.profile == BR_HTTP_SANE && prepared.request.detector_type == 195);
            CHECK(prepared.request.nheaders == 3 && !strcmp(prepared.request.headers[2].name, "User-Agent"));
            CHECK(!strcmp(prepared.request.headers[2].value, "TruffleHog"));
            br_http_request_clear(&prepared);
        }
        if (frames.fail_headers) fail_next_malloc = true;
    }
    int rc = planetscale_real_send(ctx, request, response, error);
    if (frames.active) frames.completed[frames.sends - 1] = rc == 0;
    return rc;
}
void br_http_release(const br_scan_ctx *ctx, br_http_response *response)
{
    if (frames.active) {
        size_t found = 8;
        for (size_t i = 0; i < frames.sends; ++i)
            if (frames.responses[i] == response && !frames.released[i]) found = i;
        CHECK(found < 8 && frames.requests[found] && frames.requests[found]->headers);
        CHECK(frames.requests[found]->headers[0].value && frames.requests[found]->headers[1].value);
        ((char *)frames.requests[found]->headers[0].value)[0] = 'X';
        frames.released[found] = true;
        frames.release_len[found] = frames.out->len;
        frames.release_order[frames.releases++] = found;
        response->status = 418;
        frames.close_failed = true;
    }
    planetscale_real_release(ctx, response);
}

static const br_detector *descriptor(void)
{
    build_identities();
    const br_detector *d = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_planetscale_init(NULL, &error) == -1 && error && !strcmp(error, "invalid PlanetScale detector output"));
    free(error);
    error = NULL;
    CHECK(br_planetscale_init(NULL, NULL) == -1);
    fail_next_malloc = true;
    CHECK(br_planetscale_init(&d, &error) == -1 && !d && error && !strcmp(error, "out of memory compiling regex"));
    CHECK(!fail_next_malloc && failed_allocations == 1);
    free(error);
    error = NULL;
    CHECK(br_planetscale_init(&d, &error) == 0 && d && !error);
    CHECK(br_planetscale_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 195 && d->version == 0 && !strcmp(d->name, "PlanetScale") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "PlanetScale is a database platform. PlanetScale tokens can be used to access and manage database instances."));
    CHECK(d->nkeywords == 1 && d->keywords && !strcmp(d->keywords[0], "pscale_tkn_") && strcmp(d->keywords[0], "planetscale"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints);
    CHECK(!d->cloud_endpoint);
    return d;
}

static br_results caller_owned(void)
{
    br_results out = {0};
    br_result result = {0};
    CHECK(br_finding_key(&result, 195, "caller-owned", "id") == 0);
    result.extra_data = json_object_new_object();
    CHECK(result.extra_data && br_results_push(&out, &result) == 0 && out.len == 1);
    return out;
}
static void preserved(br_results *out)
{
    CHECK(out->len == 1 && out->items[0].raw.len == strlen("caller-owned"));
    CHECK(!memcmp(out->items[0].raw.data, "caller-owned", strlen("caller-owned")));
    CHECK(out->items[0].extra_data);
}
static void reset_counts(void)
{
    setter_calls = setter_nsecrets = setter_secret_len = id_adds = token_adds = 0;
    setter_cause[0] = '\0';
    memset(&frames, 0, sizeof frames);
}
static void expect_pair(const br_result *result, const char *user, const char *token, bool verified,
                        const char *cause, const char *redacted)
{
    char raw[128];
    credential(raw, sizeof raw, user, token);
    CHECK(result->detector_type == 195 && result->raw.len == strlen(raw) && !memcmp(result->raw.data, raw, strlen(raw)));
    CHECK(!result->detector_name && !result->raw_v2.data && !result->raw_v2.len && !result->extra_data);
    CHECK(!result->structured_data && !result->verification_from_cache && !result->primary_secret.data);
    CHECK(!result->primary_secret.len && !result->primary_line && !result->chunk_offset && !result->chunk_offset_set);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    br_json *id = NULL, *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "id", &id));
    CHECK(json_object_object_get_ex(result->secret_parts, "token", &part));
    CHECK(json_object_is_type(id, json_type_string) && !strcmp(json_object_get_string(id), user));
    CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), token));
    CHECK(result->verified == verified);
    if (cause) CHECK(result->verification_error && !strcmp(result->verification_error, cause));
    else CHECK(!result->verification_error);
    if (redacted) CHECK(result->redacted && !strcmp(result->redacted, redacted));
    else CHECK(!result->redacted);
}
static void password_only(const char *token)
{
    CHECK(setter_nsecrets == 1 && setter_secret_len == strlen(token));
    CHECK(!memcmp(setter_secret, token, strlen(token)));
}

static br_results scan_text(const br_detector *d, const br_scan_ctx *ctx, bool verify, const char *text, br_results *base)
{
    br_results out = base ? *base : (br_results){0};
    if (base) memset(base, 0, sizeof(*base));
    frames.active = true;
    frames.out = &out;
    frames.base = base ? 1 : 0;
    char *error = NULL;
    int rc = d->scan(d, ctx, verify, (br_slice){(const unsigned char *)text, strlen(text)}, &out, &error);
    if (error) fprintf(stderr, "scan error: %s\n", error);
    CHECK(rc == 0 && !error);
    return out;
}

static void rejected(const br_detector *d, const char *text)
{
    reset_counts();
    br_results out = scan_text(d, NULL, false, text, NULL);
    CHECK(out.len == 0 && frames.sends == 0 && setter_calls == 0);
    br_results_clear(&out);
}

static bool always_cancelled(void *user)
{
    (void)user;
    return true;
}

static int mix_calls;
static int mix_send(void *user, const br_scan_ctx *ctx, const br_http_request *request,
                    br_http_response *response, char **err)
{
    (void)user;
    (void)ctx;
    (void)request;
    response->status = 200;
    if (mix_calls++ == 0) return 0;
    *err = strdup("second pair failed");
    CHECK(*err);
    return 1;
}
static void mix_release(void *user, br_http_response *response)
{
    (void)user;
    (void)response;
}

int main(void)
{
    const br_detector *d = descriptor();
    char raw[128], bad[96], input[8192];
    br_results owned = caller_owned();
    char *error = NULL;

    reset_counts();
    br_detector blank = *d;
    blank.state = NULL;
    CHECK(blank.scan(&blank, NULL, false, (br_slice){(const unsigned char *)"", 0}, &owned, &error) == -1);
    CHECK(error && !strcmp(error, "invalid or uninitialized PlanetScale scan"));
    free(error);
    error = NULL;
    preserved(&owned);
    CHECK(d->scan(d, NULL, false, (br_slice){(const unsigned char *)"", 0}, NULL, &error) == -1);
    CHECK(error && !strcmp(error, "invalid or uninitialized PlanetScale scan"));
    free(error);
    error = NULL;

    reset_counts();
    snprintf(input, sizeof input, "%s %s", users[0], tokens[0]);
    br_results plain = scan_text(d, NULL, false, input, NULL);
    CHECK(plain.len == 1 && frames.sends == 0 && setter_calls == 0 && !strstr(input, "planetscale"));
    expect_pair(&plain.items[0], users[0], tokens[0], false, NULL, NULL);
    br_results_clear(&plain);

    reset_counts();
    snprintf(input, sizeof input, "%s %s %s %s", users[0], users[1], tokens[0], tokens[1]);
    plain = scan_text(d, NULL, false, input, NULL);
    CHECK(plain.len == 4 && frames.sends == 0);
    expect_pair(&plain.items[0], users[0], tokens[0], false, NULL, NULL);
    expect_pair(&plain.items[1], users[0], tokens[1], false, NULL, NULL);
    expect_pair(&plain.items[2], users[1], tokens[0], false, NULL, NULL);
    expect_pair(&plain.items[3], users[1], tokens[1], false, NULL, NULL);
    br_results_clear(&plain);

    reset_counts();
    snprintf(input, sizeof input, "%s %s %s %s", users[0], users[0], tokens[0], tokens[1]);
    plain = scan_text(d, NULL, false, input, NULL);
    CHECK(plain.len == 4);
    expect_pair(&plain.items[0], users[0], tokens[0], false, NULL, NULL);
    expect_pair(&plain.items[1], users[0], tokens[1], false, NULL, NULL);
    expect_pair(&plain.items[2], users[0], tokens[0], false, NULL, NULL);
    expect_pair(&plain.items[3], users[0], tokens[1], false, NULL, NULL);
    br_results_clear(&plain);

    reset_counts();
    size_t at = (size_t)snprintf(input, sizeof input, "%s ", tokens[0]);
    memset(input + at, '!', 1100);
    at += 1100;
    snprintf(input + at, sizeof input - at, " %s %s", users[0], users[1]);
    CHECK(strlen(input) > 1024 + 54);
    plain = scan_text(d, NULL, false, input, NULL);
    CHECK(plain.len == 2 && frames.sends == 0);
    expect_pair(&plain.items[0], users[0], tokens[0], false, NULL, NULL);
    expect_pair(&plain.items[1], users[1], tokens[0], false, NULL, NULL);
    br_results_clear(&plain);

    rejected(d, "planetscale");
    rejected(d, users[0]);
    rejected(d, tokens[0]);
    snprintf(bad, sizeof bad, "x%s", users[0]);
    rejected(d, bad);
    snprintf(bad, sizeof bad, "_%s", users[0]);
    rejected(d, bad);
    snprintf(bad, sizeof bad, "%sZ", users[0]);
    rejected(d, bad);
    rejected(d, "shortname11");
    rejected(d, "FO57EYA1LVVH");
    memcpy(bad, "Pscale_tkn_", 11);
    memcpy(bad + 11, tokens[0] + 11, 44);
    rejected(d, bad);
    memcpy(bad, "pscale_TKN_", 11);
    memcpy(bad + 11, tokens[0] + 11, 44);
    rejected(d, bad);
    snprintf(bad, sizeof bad, "%s", tokens[0]);
    bad[strlen(bad) - 1] = '\0';
    rejected(d, bad);
    snprintf(bad, sizeof bad, "%sx", tokens[0]);
    rejected(d, bad);
    snprintf(input, sizeof input, "-%s- %s.", users[0], tokens[0]);
    reset_counts();
    plain = scan_text(d, NULL, false, input, NULL);
    CHECK(plain.len == 1);
    expect_pair(&plain.items[0], users[0], tokens[0], false, NULL, NULL);
    br_results_clear(&plain);

    test_http http = {0};
    http.response.status = 200;
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    credential(raw, sizeof raw, users[0], tokens[0]);
    snprintf(input, sizeof input, "%s %s", users[0], tokens[0]);

    int statuses[] = {200, 201, 250, 299, 401, 199, 300, 500, 0, -1, INT_MAX, INT_MIN};
    for (size_t i = 0; i < sizeof statuses / sizeof statuses[0]; ++i) {
        reset_counts();
        http = (test_http){.response = {.status = statuses[i], .body_error = "ignored body"}};
        transport = test_transport(&http);
        ctx.transport = &transport;
        frames.prepare = true;
        frames.expect_auth[0] = raw;
        br_results got = scan_text(d, &ctx, true, input, NULL);
        CHECK(got.len == 1 && frames.sends == 1 && frames.releases == 1 && frames.release_order[0] == 0);
        CHECK(frames.completed[0] && frames.release_len[0] == 1 && http.calls == 1 && http.releases == 1);
        CHECK(frames.close_failed);
        bool verified = statuses[i] >= 200 && statuses[i] < 300;
        bool other = !verified && statuses[i] != 401;
        char message[64];
        snprintf(message, sizeof message, "unexpected status code %d", statuses[i]);
        expect_pair(&got.items[0], users[0], tokens[0], verified, other ? message : NULL, NULL);
        CHECK(setter_calls == (other ? 1 : 0));
        if (other) {
            CHECK(!strcmp(setter_cause, message));
            password_only(tokens[0]);
        }
        br_results_clear(&got);
    }

    reset_counts();
    char cause[160];
    snprintf(cause, sizeof cause, "denied %s with %s", users[0], tokens[0]);
    http = (test_http){.send_rc = 1, .send_error = cause, .response = {.status = 200}};
    transport = test_transport(&http);
    ctx.transport = &transport;
    frames.prepare = true;
    frames.expect_auth[0] = raw;
    br_results failed = scan_text(d, &ctx, true, input, NULL);
    char redacted[160];
    snprintf(redacted, sizeof redacted, "denied %s with [REDACTED]", users[0]);
    CHECK(failed.len == 1 && frames.sends == 1 && frames.releases == 1 && !frames.completed[0]);
    CHECK(frames.release_len[0] == 0 && frames.release_order[0] == 0);
    expect_pair(&failed.items[0], users[0], tokens[0], false, redacted, NULL);
    CHECK(setter_calls == 1 && !strcmp(setter_cause, cause));
    password_only(tokens[0]);
    CHECK(strstr(failed.items[0].verification_error, users[0]) && !strstr(failed.items[0].verification_error, tokens[0]));
    br_results_clear(&failed);

    const char *guards[] = {"context canceled", "context deadline exceeded", "invalid HTTP user agent",
                             "HTTP transport not installed", "out of memory constructing HTTP headers"};
    for (size_t i = 0; i < 5; ++i) {
        reset_counts();
        http = (test_http){.response = {.status = 200}};
        transport = test_transport(&http);
        br_scan_ctx guard = {.transport = &transport};
        if (i == 0) guard.cancelled = always_cancelled;
        if (i == 1) guard.deadline_monotonic_ms = 1;
        if (i == 2) guard.user_agent = "bad\nagent";
        if (i == 3) guard.transport = NULL;
        frames.prepare = false;
        frames.fail_headers = i == 4;
        frames.expect_auth[0] = raw;
        br_results got = scan_text(d, &guard, true, input, NULL);
        CHECK(got.len == 1 && frames.sends == 1 && frames.releases == 1 && !frames.completed[0]);
        CHECK(frames.release_len[0] == 0 && setter_calls == 1 && !strcmp(setter_cause, guards[i]));
        password_only(tokens[0]);
        expect_pair(&got.items[0], users[0], tokens[0], false, guards[i], NULL);
        br_results_clear(&got);
    }

    reset_counts();
    size_t before_adds = id_adds;
    frames.active = true;
    frames.out = &owned;
    frames.base = owned.len;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &owned, &error) == 0 && !error);
    CHECK(owned.len == 1 && frames.sends == 0 && frames.releases == 0 && setter_calls == 0);
    CHECK(id_adds == before_adds + 1 && token_adds == 1);
    preserved(&owned);

    reset_counts();
    credential(raw, sizeof raw, users[0], tokens[0]);
    char second[128], third[128], fourth[128];
    credential(second, sizeof second, users[0], tokens[1]);
    credential(third, sizeof third, users[1], tokens[0]);
    credential(fourth, sizeof fourth, users[1], tokens[1]);
    snprintf(input, sizeof input, "%s %s %s %s", users[0], users[1], tokens[0], tokens[1]);
    http = (test_http){.response = {.status = 204, .body_error = "drain ignored"}};
    transport = test_transport(&http);
    ctx.transport = &transport;
    frames.prepare = true;
    frames.expect_auth[0] = raw;
    frames.expect_auth[1] = second;
    frames.expect_auth[2] = third;
    frames.expect_auth[3] = fourth;
    br_results lifo = scan_text(d, &ctx, true, input, NULL);
    CHECK(lifo.len == 4 && frames.sends == 4 && frames.releases == 4 && http.calls == 4);
    CHECK(frames.release_order[0] == 3 && frames.release_order[1] == 2);
    CHECK(frames.release_order[2] == 1 && frames.release_order[3] == 0);
    for (size_t i = 0; i < 4; ++i) {
        CHECK(frames.completed[i] && frames.release_len[i] == 4 && lifo.items[i].verified);
        CHECK(!lifo.items[i].verification_error);
    }
    expect_pair(&lifo.items[0], users[0], tokens[0], true, NULL, NULL);
    expect_pair(&lifo.items[3], users[1], tokens[1], true, NULL, NULL);
    br_results_clear(&lifo);

    reset_counts();
    mix_calls = 0;
    snprintf(input, sizeof input, "%s %s %s", users[0], tokens[0], tokens[1]);
    br_transport mix_transport = {NULL, mix_send, mix_release};
    br_scan_ctx mix_ctx = {.transport = &mix_transport};
    frames.prepare = true;
    frames.expect_auth[0] = raw;
    frames.expect_auth[1] = second;
    br_results mixed = {0};
    frames.active = true;
    frames.out = &mixed;
    error = NULL;
    CHECK(d->scan(d, &mix_ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &mixed, &error) == 0 && !error);
    CHECK(mixed.len == 2 && frames.sends == 2 && frames.releases == 2 && mix_calls == 2);
    CHECK(frames.release_order[0] == 1 && frames.release_len[1] == 1 && !frames.completed[1]);
    CHECK(frames.release_order[1] == 0 && frames.release_len[0] == 2 && frames.completed[0]);
    expect_pair(&mixed.items[0], users[0], tokens[0], true, NULL, NULL);
    expect_pair(&mixed.items[1], users[0], tokens[1], false, "second pair failed", NULL);
    br_results_clear(&mixed);

    owned = caller_owned();
    reset_counts();
    fail_next_malloc = true;
    snprintf(input, sizeof input, "%s %s", users[0], tokens[0]);
    CHECK(d->scan(d, &ctx, false, (br_slice){(const unsigned char *)input, strlen(input)}, &owned, &error) == -1);
    CHECK(error && !strcmp(error, "out of memory iterating regex") && !fail_next_malloc);
    free(error);
    error = NULL;
    preserved(&owned);

    reset_counts();
    fail_part_after = 1;
    CHECK(d->scan(d, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &owned, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create PlanetScale result") && frames.sends == 0 && setter_calls == 0);
    free(error);
    error = NULL;
    preserved(&owned);

    reset_counts();
    fail_part_after = 2;
    CHECK(d->scan(d, &ctx, false, (br_slice){(const unsigned char *)input, strlen(input)}, &owned, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create PlanetScale result"));
    free(error);
    error = NULL;
    preserved(&owned);

    reset_counts();
    fail_request_after = 1;
    frames.active = true;
    frames.out = &owned;
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &owned, &error) == -1);
    CHECK(error && !strcmp(error, "cannot create PlanetScale request") && frames.sends == 0 && frames.releases == 0);
    CHECK(setter_calls == 0 && !fail_next_malloc && failed_allocations >= 1);
    free(error);
    error = NULL;
    preserved(&owned);

    reset_counts();
    fail_push_after = 1;
    CHECK(d->scan(d, NULL, false, (br_slice){(const unsigned char *)input, strlen(input)}, &owned, &error) == -1);
    CHECK(error && !strcmp(error, "cannot append PlanetScale result") && frames.sends == 0);
    free(error);
    error = NULL;
    preserved(&owned);

    reset_counts();
    http = (test_http){.response = {.status = 200}};
    transport = test_transport(&http);
    ctx.transport = &transport;
    frames.prepare = true;
    frames.expect_auth[0] = raw;
    frames.active = true;
    frames.out = &owned;
    frames.base = 1;
    fail_push_after = 1;
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &owned, &error) == -1);
    CHECK(error && !strcmp(error, "cannot append PlanetScale result"));
    CHECK(frames.sends == 1 && frames.releases == 1 && frames.completed[0] && setter_calls == 0);
    free(error);
    error = NULL;
    preserved(&owned);

    reset_counts();
    http = (test_http){.response = {.status = 300}};
    transport = test_transport(&http);
    ctx.transport = &transport;
    frames.prepare = true;
    frames.expect_auth[0] = raw;
    frames.active = true;
    frames.out = &owned;
    fail_setter_after = 1;
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &owned, &error) == -1);
    CHECK(error && !strcmp(error, "cannot set PlanetScale verification error"));
    CHECK(frames.sends == 1 && frames.releases == 1 && frames.completed[0] && setter_calls == 1);
    password_only(tokens[0]);
    free(error);
    error = NULL;
    preserved(&owned);

    reset_counts();
    http = (test_http){.send_rc = 1, .send_error = "transport down", .response = {.status = 200}};
    transport = test_transport(&http);
    ctx.transport = &transport;
    frames.prepare = true;
    frames.expect_auth[0] = raw;
    frames.active = true;
    frames.out = &owned;
    fail_setter_after = 1;
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &owned, &error) == -1);
    CHECK(error && !strcmp(error, "cannot set PlanetScale verification error"));
    CHECK(frames.sends == 1 && frames.releases == 1 && !frames.completed[0] && frames.release_len[0] == 1);
    CHECK(setter_calls == 1 && !strcmp(setter_cause, "transport down"));
    password_only(tokens[0]);
    free(error);
    error = NULL;
    preserved(&owned);
    br_results_clear(&owned);
    return test_finish("planetscale");
}
