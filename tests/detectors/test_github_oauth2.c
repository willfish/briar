/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/github_oauth2_private.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>

#define TEXT(s) ((br_slice){(const unsigned char *)(s), sizeof(s) - 1})
static const char id[] = "A1b2C3d4E5f6G7h8I9j0";
static const char secret[] = "0123456789abcdef0123456789abcdef01234567";
static const char input[] = "github A1b2C3d4E5f6G7h8I9j0\ngithub 0123456789abcdef0123456789abcdef01234567";
static bool equal(br_slice a, br_slice b) { return a.len == b.len && (!a.len || !memcmp(a.data, b.data, a.len)); }
typedef struct { int status, send_rc, read_rc; br_slice type, status_text, body, cause; } step;
typedef struct {
    step steps[4]; size_t count, sends, releases, offset, reads, bytes;
    bool repeat; const br_scan_ctx *ctx; const br_github_oauth2_request *borrowed;
} script;
static void request_check(const br_github_oauth2_request *r, bool params)
{
    CHECK(!strcmp(r->method, "POST") && equal(r->url, TEXT("https://github.com/login/oauth/access_token")));
    CHECK(r->nheaders == (params ? 1 : 2));
    CHECK(!strcmp(r->headers[0].name, "Content-Type") && equal(r->headers[0].value, TEXT("application/x-www-form-urlencoded")));
    if (params) CHECK(equal(r->body, TEXT("client_id=A1b2C3d4E5f6G7h8I9j0&client_secret=0123456789abcdef0123456789abcdef01234567&grant_type=client_credentials")));
    else {
        CHECK(equal(r->body, TEXT("grant_type=client_credentials")));
        CHECK(!strcmp(r->headers[1].name, "Authorization") && r->headers[1].value.len == 90 && !memcmp(r->headers[1].value.data, "Basic ", 6));
        unsigned char decoded[64]; int n = EVP_DecodeBlock(decoded, r->headers[1].value.data + 6, 84);
        CHECK(n == 63 && !memcmp(decoded, id, 20) && decoded[20] == ':' && !memcmp(decoded + 21, secret, 40) && !memcmp(r->headers[1].value.data + 88, "==", 2));
    }
}
static step *current(script *s) { return &s->steps[(s->sends - 1) % s->count]; }
static int send_bytes(void *user, const br_scan_ctx *ctx, const br_github_oauth2_request *r, br_github_oauth2_response *response, br_bytes *error)
{
    script *s = user; CHECK(ctx == s->ctx && s->sends == s->releases && (s->repeat || s->sends < s->count));
    request_check(r, s->sends % 2 != 0); ++s->sends; s->offset = 0; s->borrowed = r;
    step *st = current(s); response->status = st->status; response->content_type = st->type; response->status_text = st->status_text; response->reader = s;
    if (st->send_rc) {
        error->data = malloc(st->cause.len + 1); CHECK(error->data); memcpy(error->data, st->cause.data, st->cause.len); error->len = st->cause.len;
    }
    return st->send_rc;
}
static int read_bytes(void *user, br_github_oauth2_response *response, unsigned char *dst, size_t cap, size_t *n, br_bytes *error)
{
    script *s = user; CHECK(response->reader == s && cap > 0); step *st = current(s); ++s->reads;
    size_t remain = st->body.len - s->offset; *n = remain < cap ? remain : cap;
    if (*n) memcpy(dst, st->body.data + s->offset, *n);
    s->offset += *n; s->bytes += *n;
    if (st->read_rc) {
        error->data = malloc(st->cause.len + 1); CHECK(error->data); memcpy(error->data, st->cause.data, st->cause.len); error->len = st->cause.len;
    }
    return st->read_rc;
}
static void release_bytes(void *user, br_github_oauth2_response *response)
{
    script *s = user; CHECK(response->reader == s && s->sends == s->releases + 1 && s->borrowed);
    request_check(s->borrowed, (s->sends - 1) % 2 != 0); s->borrowed = NULL; ++s->releases;
}
static const br_github_oauth2_io io = {send_bytes, read_bytes, release_bytes};
static br_detector clone(const br_detector *base, br_github_oauth2_state *state, script *s)
{
    *state = *(const br_github_oauth2_state *)base->state; state->io = &io; state->user = s;
    br_detector d = *base; d.state = state; return d;
}
static void finding(const br_result *r, bool verified)
{
    CHECK(r->detector_type == 924 && equal((br_slice){r->raw.data, r->raw.len}, TEXT("A1b2C3d4E5f6G7h8I9j0")));
    CHECK(r->raw_v2.len == 60 && !memcmp(r->raw_v2.data, id, 20) && !memcmp(r->raw_v2.data + 20, secret, 40));
    CHECK(r->verified == verified && !r->verification_error && !r->verification_from_cache);
    CHECK(!r->detector_name && !r->redacted && !r->structured_data && !r->primary_secret.data && !r->primary_secret.len && !r->primary_line && !r->chunk_offset && !r->chunk_offset_set);
    CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 2);
    br_json *a = NULL, *b = NULL; CHECK(json_object_object_get_ex(r->secret_parts, "id", &a) && json_object_object_get_ex(r->secret_parts, "secret", &b));
    CHECK(!strcmp(json_object_get_string(a), id) && !strcmp(json_object_get_string(b), secret));
    CHECK(r->extra_data && json_object_object_length(r->extra_data) == 1 && json_object_object_get_ex(r->extra_data, "rotation_guide", &a) && !strcmp(json_object_get_string(a), "https://howtorotate.com/docs/tutorials/github/"));
}
static step json(int status, br_slice body) { return (step){.status = status, .type = TEXT("application/json"), .status_text = TEXT("synthetic status"), .body = body}; }
static void run_case(const br_detector *base, step final, bool expected)
{
    br_scan_ctx ctx = {0}; script s = {.count = 2, .ctx = &ctx};
    /* First error is discarded even if non-ASCII/NUL and already a match. */
    s.steps[0] = (step){.send_rc = 1, .cause = TEXT("\xff\0bad_verification_code")}; s.steps[1] = final;
    br_github_oauth2_state state; br_detector d = clone(base, &state, &s);
    br_results r = test_scan(&d, &ctx, true, input, sizeof(input) - 1);
    CHECK(r.len == 1 && s.sends == 2 && s.releases == 2); finding(&r.items[0], expected); br_results_clear(&r);
}
static void extraction(const br_detector *base)
{
    br_results r = test_scan(base, NULL, false, input, sizeof(input) - 1); CHECK(r.len == 1); finding(&r.items[0], false); br_results_clear(&r);
    const char duplicate[] = "github A1b2C3d4E5f6G7h8I9j0\ngithub A1b2C3d4E5f6G7h8I9j0\ngithub 0123456789abcdef0123456789abcdef01234567\ngithub 0123456789abcdef0123456789abcdef01234567";
    br_scan_ctx ctx = {0}; script s = {.count = 2, .ctx = &ctx, .repeat = true}; s.steps[0] = json(500, TEXT("first")); s.steps[1] = json(400, TEXT("{\"error\":\"bad_verification_code\"}"));
    br_github_oauth2_state state; br_detector d = clone(base, &state, &s);
    r = test_scan(&d, &ctx, true, duplicate, sizeof(duplicate) - 1); CHECK(r.len == 4 && s.sends == 8 && s.releases == 8);
    for (size_t i = 0; i < r.len; ++i) finding(&r.items[i], true);
    br_results_clear(&r);
    char far[1500]; int n = snprintf(far, sizeof(far), "github %s", id); memset(far + n, ' ', 1100); n += 1100; n += snprintf(far + n, sizeof(far) - (size_t)n, "github %s", secret);
    r = test_scan(base, NULL, false, far, (size_t)n); CHECK(r.len == 1); br_results_clear(&r); /* hint, not cap */
    for (size_t distance = 40; distance <= 41; ++distance) {
        char boundary[180]; memcpy(boundary, "GitHub", 6); memset(boundary + 6, ' ', distance); memcpy(boundary + 6 + distance, id, 20);
        size_t at = 26 + distance; at += (size_t)snprintf(boundary + at, sizeof(boundary) - at, "\ngithub %s", secret);
        r = test_scan(base, NULL, false, boundary, at); CHECK(r.len == (distance == 40 ? 1 : 0)); br_results_clear(&r);
    }
    r = test_scan(base, NULL, true, "github nothing", 14); CHECK(!r.len); br_results_clear(&r);
    const char ordered[] = "github A1b2C3d4E5f6G7h8I9j0\ngithub K9l8M7n6O5p4Q3r2S1t0\ngithub 0123456789abcdef0123456789abcdef01234567\ngithub fedcba9876543210fedcba9876543210fedcba98";
    r = test_scan(base, NULL, false, ordered, sizeof(ordered) - 1); CHECK(r.len == 4);
    for (size_t i = 0; i < 4; ++i) {
        CHECK(r.items[i].raw.len == 20 && !memcmp(r.items[i].raw.data, i < 2 ? id : "K9l8M7n6O5p4Q3r2S1t0", 20));
        CHECK(r.items[i].raw_v2.len == 60 && !memcmp(r.items[i].raw_v2.data + 20, i % 2 ? "fedcba9876543210fedcba9876543210fedcba98" : secret, 40));
    }
    br_results_clear(&r);
    const char bad_case[] = "github A1b2C3d4E5f6G7h8I9j0\ngithub ABCDEF0123456789ABCDEF0123456789ABCDEF01";
    r = test_scan(base, NULL, false, bad_case, sizeof(bad_case) - 1); CHECK(!r.len); br_results_clear(&r);
}
static void errors(const br_detector *base)
{
    run_case(base, json(400, TEXT("{\"error\":\"bad_verification_code\"}")), true);
    run_case(base, json(200, TEXT("{\"error\":\"other\",\"error_description\":\"bad_verification_code\"}")), true);
    run_case(base, json(200, TEXT("{\"error\":\"other\",\"error_uri\":\"bad_verification_code\"}")), true);
    run_case(base, json(500, TEXT("raw\0bad_verification_code")), true);
    run_case(base, json(400, TEXT("{\"error\":\"other\",\"ignored\":\"bad_verification_code\"}")), false);
    run_case(base, json(400, TEXT("{\"error\":\"BAD_VERIFICATION_CODE\"}")), false);
    run_case(base, json(200, TEXT("{\"access_token\":\"offline-not-a-token\",\"expires_in\":-1}")), false);
    run_case(base, json(200, TEXT("{\"error_description\":\"bad_verification_code\"}")), false);
    run_case(base, json(200, TEXT("{\"access_token\":42,\"access_token\":\"x\",\"error\":\"bad_verification_code\"}")), false);
    run_case(base, json(200, TEXT("{\"error\":\"bad_verification_code\",\"error\":\"other\",\"error\":null}")), false);
    run_case(base, json(200, TEXT("{\"error\":\"bad_verification_code\",\"unknown\":1e9999}")), true);
    run_case(base, json(200, TEXT("{\"access_token\":42,\"expires_in\":\"bad_verification_code\"}")), true);
    run_case(base, json(200, TEXT("{\"expires_in\":\"bad_verification\\u005fcode\"}")), false);
    run_case(base, json(200, TEXT("{\"expires_in\":\"1e999\",\"error\":\"bad_verification_code\"}")), false);
    run_case(base, json(400, TEXT("{\"expires_in\":\"bad_verification\\u005fcode\"}")), false);
    run_case(base, json(200, TEXT("{\"expires_in\":\"bad_verification_code\"} trailing")), false);
    step st = json(200, TEXT("ignored")); st.send_rc = 1; st.cause = TEXT("Do\0bad_verification_code"); run_case(base, st, true);
    st = json(400, TEXT("bad_verification_code")); st.read_rc = 1; st.cause = TEXT("ordinary read failure"); run_case(base, st, false);
    st.cause = TEXT("read\0bad_verification_code"); run_case(base, st, true);
    st = json(500, TEXT("{}")); st.status_text = TEXT("599 bad_verification_code"); run_case(base, st, true);
    st = json(200, TEXT("error=other&error_description=bad_verification_code")); st.type = TEXT("TEXT/PLAIN; charset=\"utf-8\"; broken"); run_case(base, st, true);
    st.body = TEXT("error=other&error_uri=bad%5Fverification_code"); run_case(base, st, true);
    st.body = TEXT("error=other&error=bad_verification_code"); run_case(base, st, false);
    st.body = TEXT("error=bad_verification_code&x=%zz"); run_case(base, st, false);
    st.status = 400; run_case(base, st, true);
    st.status = 200; st.body = TEXT("error=bad_verification_code&x=;"); run_case(base, st, false);
    st.body = TEXT("error=bad_verification_code"); st.type = TEXT("text/plain; x=a; X=b"); run_case(base, st, false);
}
static void boundaries(const br_detector *base)
{
    br_scan_ctx ctx = {0}; br_results r = {0}; char *error = NULL;
    CHECK(base->scan(base, &ctx, true, TEXT(input), &r, &error) < 0 && error && strstr(error, "native SDK")); CHECK(!r.len); free(error); error = NULL;
    CHECK(base->scan(base, NULL, true, TEXT(input), &r, &error) < 0 && error && strstr(error, "WithContext(nil)")); CHECK(!r.len); free(error); error = NULL;
    script s = {.count = 1, .ctx = &ctx}; s.steps[0] = json(200, TEXT("{\"access_token\":\"offline-only\"}"));
    br_github_oauth2_state state; br_detector d = clone(base, &state, &s); r = test_scan(&d, &ctx, true, input, sizeof(input) - 1);
    CHECK(s.sends == 1 && s.releases == 1 && r.len == 1); finding(&r.items[0], false); br_results_clear(&r);
    const size_t limit = (size_t)1 << 20; unsigned char *large = malloc(limit + 21); CHECK(large); memset(large, ' ', limit + 21); memcpy(large + limit, "bad_verification_code", 21);
    s = (script){.count = 2, .ctx = &ctx}; s.steps[0] = (step){.send_rc = 1, .cause = TEXT("first")}; s.steps[1] = json(500, (br_slice){large, limit + 21});
    d = clone(base, &state, &s); r = test_scan(&d, &ctx, true, input, sizeof(input) - 1); CHECK(s.bytes == limit && s.reads == 1 && s.releases == 2); finding(&r.items[0], false); br_results_clear(&r);
    memcpy(large + limit - 21, "bad_verification_code", 21); s.sends = s.releases = s.reads = s.bytes = 0;
    r = test_scan(&d, &ctx, true, input, sizeof(input) - 1); CHECK(s.bytes == limit && s.reads == 1); finding(&r.items[0], true); br_results_clear(&r); free(large);
    /* A late owned failure rolls back only this invocation, after releasing. */
    const char two[] = "github A1b2C3d4E5f6G7h8I9j0\ngithub 0123456789abcdef0123456789abcdef01234567\ngithub 0123456789abcdef0123456789abcdef01234567";
    r = test_scan(base, NULL, false, input, sizeof(input) - 1); unsigned char *preserved = r.items[0].raw.data;
    s = (script){.count = 3, .ctx = &ctx}; s.steps[0] = json(400, TEXT("first")); s.steps[1] = json(400, TEXT("{\"error\":\"bad_verification_code\"}")); s.steps[2] = (step){.send_rc = -1, .cause = TEXT("owned failure bad_verification_code")};
    d = clone(base, &state, &s); CHECK(d.scan(&d, &ctx, true, TEXT(two), &r, &error) < 0 && error); CHECK(s.sends == 3 && s.releases == 3 && r.len == 1 && r.items[0].raw.data == preserved); finding(&r.items[0], false); free(error); br_results_clear(&r); error = NULL;
    s = (script){.count = 1, .ctx = &ctx}; s.steps[0] = json(400, TEXT("bad_verification_code")); s.steps[0].read_rc = -1; s.steps[0].cause = TEXT("owned read failure");
    d = clone(base, &state, &s); CHECK(d.scan(&d, &ctx, true, TEXT(input), &r, &error) < 0 && error); CHECK(s.sends == 1 && s.releases == 1 && !r.len); free(error); br_results_clear(&r);
}
int main(void)
{
    const br_detector *d = NULL; char *error = NULL; CHECK(BR_ABI_REVISION == 1 && br_github_oauth2_init(&d, &error) == 0 && d && !error);
    CHECK(d->type == 924 && d->version == 0 && !strcmp(d->name, "GitHubOauth2") && !strcmp(d->custom_name, ""));
    CHECK(d->max_credential_span == 1024 && d->max_secret_size == -1 && d->start_offset == -1 && d->nkeywords == 1 && !strcmp(d->keywords[0], "github"));
    CHECK(!d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    CHECK(!strcmp(d->description, "GitHub OAuth2 credentials are used to authenticate and authorize applications to access GitHub's API on behalf of a user or organization. These credentials include a client ID and client secret, which can be used to obtain access tokens for accessing GitHub resources."));
    extraction(d); errors(d); boundaries(d); return test_finish("GitHub OAuth2 SDK byte flow");
}
