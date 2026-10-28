/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/gcp_oauth.h"
#include "../support/detector_test.h"

#define TEXT(s) ((br_slice){(const unsigned char *)(s), sizeof(s) - 1})
static char *credential(br_slice refresh)
{
    br_json *value = json_object_new_string_len((const char *)refresh.data, (int)refresh.len); CHECK(value);
    const char *encoded = json_object_to_json_string_ext(value, JSON_C_TO_STRING_PLAIN); CHECK(encoded);
    const char *format = "{\"client_id\":\"42.hidden.apps.googleusercontent.com\",\"client_secret\":\"offline-secret\",\"refresh_token\":%s,\"type\":\"authorized_user\",\"token_uri\":\"https://ignored.invalid\",\"unknown\":42}";
    size_t n = strlen(encoded) + strlen(format) + 1; char *out = malloc(n); CHECK(out);
    CHECK(snprintf(out, n, format, encoded) > 0); json_object_put(value); return out;
}
static void finding(const br_result *r, br_slice refresh, const unsigned char *redacted, size_t redacted_len, bool verified, const char *error)
{
    CHECK(r->detector_type == 983 && r->raw.len == 2 && !memcmp(r->raw.data, "42", 2));
    CHECK(r->raw_v2.len == refresh.len + 2 && !memcmp(r->raw_v2.data, "42", 2) && !memcmp(r->raw_v2.data + 2, refresh.data, refresh.len));
    CHECK(r->verified == verified && !r->extra_data && !r->detector_name && !r->structured_data && !r->verification_from_cache);
    CHECK(!r->primary_secret.data && !r->primary_secret.len && !r->primary_line && !r->chunk_offset_set);
    CHECK(error ? r->verification_error && !strcmp(r->verification_error, error) : !r->verification_error);
    CHECK(redacted ? r->redacted && strlen(r->redacted) == redacted_len && !memcmp(r->redacted, redacted, redacted_len) : !r->redacted);
    br_json *id = NULL, *token = NULL;
    CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 2 && json_object_object_get_ex(r->secret_parts, "client_id", &id) && json_object_object_get_ex(r->secret_parts, "refresh_token", &token));
    CHECK(!strcmp(json_object_get_string(id), "42") && (size_t)json_object_get_string_len(token) == refresh.len && !memcmp(json_object_get_string(token), refresh.data, refresh.len));
}
static void extraction(const br_detector *d)
{
    const struct { br_slice refresh, redacted; } cases[] = {
        {TEXT("abcdef"), TEXT("abc...f")}, {TEXT("\xf0\x9f\x98\x80XYZ"), TEXT("\xf0\x9f\x98...Z")}, {TEXT("abc"), {0}},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        char *input = credential(cases[i].refresh); br_results results = test_scan(d, NULL, false, input, strlen(input)); CHECK(results.len == 1);
        finding(&results.items[0], cases[i].refresh, cases[i].redacted.data, cases[i].redacted.len, false, NULL); br_results_clear(&results); free(input);
    }
    unsigned char refresh[60], redacted[19]; memset(refresh, 'b', sizeof(refresh)); memset(refresh, 'a', 10); refresh[10] = 0;
    memcpy(redacted, "aaa...", 6); memset(redacted + 6, 'b', 13); char *input = credential((br_slice){refresh, sizeof(refresh)});
    br_results results = test_scan(d, NULL, false, input, strlen(input)); CHECK(results.len == 1);
    finding(&results.items[0], (br_slice){refresh, sizeof(refresh)}, redacted, sizeof(redacted), false, NULL); br_results_clear(&results); free(input);
}

typedef struct {
    int mode, iam_status;
    size_t sends, releases, offset;
    const br_scan_ctx *ctx;
    const br_gcp_oauth_request *borrowed_request;
    br_slice body;
} script;
static const char form[] = "client_id=42.hidden.apps.googleusercontent.com&client_secret=offline-secret&grant_type=refresh_token&refresh_token=offline_refresh";
static void check_request(const br_gcp_oauth_request *r, size_t call, int mode)
{
    if (call == 1) {
        CHECK(r->role == BR_GCP_REFRESH_POST && !strcmp(r->method, "POST") && r->timeout_ns == 0);
        CHECK(r->url.len == sizeof("https://oauth2.googleapis.com/token") - 1 && !memcmp(r->url.data, "https://oauth2.googleapis.com/token", r->url.len));
        CHECK(r->nheaders == 1 && !strcmp(r->headers[0].name, "Content-Type") && r->headers[0].value.len == sizeof("application/x-www-form-urlencoded") - 1);
        CHECK(!memcmp(r->headers[0].value.data, "application/x-www-form-urlencoded", r->headers[0].value.len));
        CHECK(r->body.len == sizeof(form) - 1 && !memcmp(r->body.data, form, r->body.len)); /* FULL hidden ID, no Basic/scope/token_uri fallback. */
    } else {
        CHECK(call == 2 && r->role == BR_GCP_ADC_IAM && !strcmp(r->method, "GET") && r->timeout_ns == INT64_C(5000000000));
        CHECK(r->url.len == sizeof("https://iam.googleapis.com/v1/roles") - 1 && !memcmp(r->url.data, "https://iam.googleapis.com/v1/roles", r->url.len));
        CHECK(!r->body.data && !r->body.len && r->nheaders == 1 && !strcmp(r->headers[0].name, "Authorization"));
        if (mode == 4) CHECK(memchr(r->headers[0].value.data, 0, r->headers[0].value.len));
        else CHECK(r->headers[0].value.len == sizeof("Bearer offline-access") - 1 && !memcmp(r->headers[0].value.data, "Bearer offline-access", r->headers[0].value.len)); /* Injected I/O is NOT the exact source FakeTransport sentinel. */
    }
}
static int send_bytes(void *user, const br_scan_ctx *ctx, const br_gcp_oauth_request *request, br_gcp_oauth_response *response, br_gcp_oauth_error *error)
{
    script *s = user; (void)error; CHECK(ctx == s->ctx && s->sends == s->releases); ++s->sends; check_request(request, s->sends, s->mode);
    s->borrowed_request = request; s->offset = 0; response->reader = s;
    if (s->sends == 1) {
        response->status = s->mode == 1 ? 400 : s->mode == 2 || s->mode == 3 ? 500 : 200;
        response->status_text = s->mode == 1 ? TEXT("400 Bad Request") : s->mode == 2 || s->mode == 3 ? TEXT("500 Internal Server Error") : TEXT("200 OK");
        response->content_type = TEXT("application/json");
        s->body = s->mode == 4 ? TEXT("{\"access_token\":\"bad\\u0000token\",\"token_type\":\"bearer\"}") : s->mode == 1 ? TEXT("{\"error\":\"invalid_grant\"}") : s->mode == 2 ? TEXT("{\"error\":\"temporarily_unavailable\"}") : TEXT("{\"access_token\":\"offline-access\",\"token_type\":\"bearer\",\"expires_in\":3600}");
    } else { response->status = s->iam_status; response->status_text = TEXT("synthetic IAM status"); s->body = TEXT("ignored IAM body"); }
    return 0;
}
static int read_bytes(void *user, br_gcp_oauth_response *response, unsigned char *out, size_t capacity, size_t *n, br_gcp_oauth_error *error)
{
    script *s = user; CHECK(response->reader == s); size_t remaining = s->body.len - s->offset; *n = remaining < capacity ? remaining : capacity;
    if (*n) memcpy(out, s->body.data + s->offset, *n);
    s->offset += *n;
    if (s->sends == 1 && s->mode == 3) {
        error->text.data = (unsigned char *)strdup("synthetic read stopped"); CHECK(error->text.data); error->text.len = strlen((const char *)error->text.data); return 1;
    }
    return 0;
}
static void release_bytes(void *user, br_gcp_oauth_response *response)
{
    script *s = user; CHECK(response->reader == s && s->borrowed_request && s->sends == s->releases + 1);
    check_request(s->borrowed_request, s->sends, s->mode); s->borrowed_request = NULL; ++s->releases;
}
static void roundtrips(const br_detector *base)
{
    static const br_gcp_oauth_io io = {send_bytes, read_bytes, release_bytes};
    br_slice refresh = TEXT("offline_refresh"); char *input = credential(refresh);
    const int statuses[] = {200, 204, 299};
    for (size_t i = 0; i < 3; ++i) {
        script s = {.iam_status = statuses[i]}; br_scan_ctx ctx = {0}; s.ctx = &ctx; br_gcp_adc_state state = *(const br_gcp_adc_state *)base->state; state.io = &io; state.user = &s;
        br_detector d = *base; d.state = &state; br_results results = test_scan(&d, &ctx, true, input, strlen(input)); CHECK(results.len == 1 && s.sends == 2 && s.releases == 2);
        finding(&results.items[0], refresh, (const unsigned char *)"off...h", 7, true, NULL); br_results_clear(&results);
    }
    for (int mode = 1; mode <= 4; ++mode) {
        script s = {.mode = mode, .iam_status = 200}; br_scan_ctx ctx = {0}; s.ctx = &ctx; br_gcp_adc_state state = *(const br_gcp_adc_state *)base->state; state.io = &io; state.user = &s;
        br_detector d = *base; d.state = &state; br_results results = test_scan(&d, &ctx, true, input, strlen(input)); CHECK(results.len == 1 && s.sends == 1 && s.releases == 1);
        finding(&results.items[0], refresh, (const unsigned char *)"off...h", 7, false, mode == 2 ? "oauth2: \"temporarily_unavailable\"" : mode == 4 ? "net/http: invalid header field value for \"Authorization\"" : NULL); br_results_clear(&results);
    }
    br_scan_ctx ctx = {0}; br_results results = {0}; char *fatal = NULL;
    CHECK(base->scan(base, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &fatal) == -1 && fatal && strstr(fatal, "native SDK HTTP byte I/O"));
    CHECK(!results.len); free(fatal); br_results_clear(&results); free(input);
    input = credential(TEXT("")); results = test_scan(base, &ctx, true, input, strlen(input)); CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error); br_results_clear(&results); free(input);
}
int main(void)
{
    const br_detector *d = NULL; char *fatal = NULL; CHECK(BR_ABI_REVISION == 1 && br_gcpapplicationdefaultcredentials_init(&d, &fatal) == 0 && d && !fatal);
    CHECK(d->type == 983 && d->version == 0 && d->max_secret_size == 1024 && d->start_offset == 1024 && d->max_credential_span == -1);
    extraction(d); roundtrips(d); return test_finish("GCP ADC bounded recovery");
}
