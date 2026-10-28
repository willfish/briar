/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>

static const char ua[] = "AbC@de.fg", ub[] = "User123@TEAM-site";
static const char ka[] = "ghijklmn-opqr-stuv-wxyz-0123456789ab";
static const char kb[] = "98765432-abcd-efgh-ijkl-mnopqrstuvwx";
static const char un[] = "AbC@de\0fg", uu[] = "AbC@de💡fg";
static const char um[] = "ABCDEFGHIJKLMNOPQRST@abcdefghijkl💡ABCDE";
/* Independent Python standard Base64 goldens, not the production encoder. */
static const char *const goldens[] = {
    "Basic QWJDQGRlLmZnOmdoaWprbG1uLW9wcXItc3R1di13eHl6LTAxMjM0NTY3ODlhYg==",
    "Basic QWJDQGRlLmZnOjk4NzY1NDMyLWFiY2QtZWZnaC1pamtsLW1ub3BxcnN0dXZ3eA==",
    "Basic VXNlcjEyM0BURUFNLXNpdGU6Z2hpamtsbW4tb3Bxci1zdHV2LXd4eXotMDEyMzQ1Njc4OWFi",
    "Basic VXNlcjEyM0BURUFNLXNpdGU6OTg3NjU0MzItYWJjZC1lZmdoLWlqa2wtbW5vcHFyc3R1dnd4",
    "Basic QWJDQGRlAGZnOmdoaWprbG1uLW9wcXItc3R1di13eHl6LTAxMjM0NTY3ODlhYg==",
    "Basic QWJDQGRl8J+SoWZnOmdoaWprbG1uLW9wcXItc3R1di13eHl6LTAxMjM0NTY3ODlhYg==",
    "Basic QUJDREVGR0hJSktMTU5PUFFSU1RAYWJjZGVmZ2hpamts8J+SoUFCQ0RFOmdoaWprbG1uLW9wcXItc3R1di13eHl6LTAxMjM0NTY3ODlhYg==",
};
static size_t fail_size, fail_after, failed_allocations, fail_part_after;
static size_t encoder_calls, fail_encoder_after;
static bool fail_agent;
static const char *borrowed_auth, *borrowed_url, *expected_auth;

void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) { ++failed_allocations; return NULL; }
    return calloc(1, size);
}
char *strdup(const char *s)
{
    if (fail_agent && !strcmp(s, "TruffleHog")) { fail_agent = false; ++failed_allocations; return NULL; }
    size_t n = strlen(s) + 1; char *p = malloc(n); if (p) memcpy(p, s, n); return p;
}
int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (!strcmp(name, "key") && fail_part_after && --fail_part_after == 0) return 7;
    return json_object_object_add_ex(object, name, value, 0);
}
/* Interpose the real libcrypto entry. Normal calls use its streaming encoder. */
int EVP_EncodeBlock(unsigned char *out, const unsigned char *in, int len)
{
    ++encoder_calls; CHECK(len >= 46 && len <= 79 && in[len - 37] == ':');
    if (fail_encoder_after && --fail_encoder_after == 0) return 1;
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new(); CHECK(ctx);
    unsigned char wrapped[128]; int used = 0, tail = 0;
    EVP_EncodeInit(ctx); CHECK(EVP_EncodeUpdate(ctx, wrapped, &used, in, len) == 1);
    EVP_EncodeFinal(ctx, wrapped + used, &tail); EVP_ENCODE_CTX_free(ctx);
    size_t at = 0;
    for (int i = 0; i < used + tail; ++i) if (wrapped[i] != '\n') out[at++] = wrapped[i];
    out[at] = '\0'; return (int)at;
}
static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_guru_init(NULL, &error) != 0 && error); free(error);
    CHECK(br_guru_init(NULL, NULL) != 0);
    CHECK(br_guru_init(&d, &error) == 0 && d && !error);
    CHECK(br_guru_init(&again, NULL) == 0 && again == d);
    CHECK(d->type == 570 && !d->version && !strcmp(d->name, "Guru") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description, "Guru is a knowledge management solution. Guru credentials can be used to access and manage knowledge within an organization."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "guru"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == 1024);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void result(const br_result *r, const void *username, size_t len, bool verified)
{
    CHECK(r->detector_type == 570 && r->raw.len == len && !memcmp(r->raw.data, username, len));
    CHECK(!r->detector_name && !r->raw_v2.data && !r->raw_v2.len && !r->redacted);
    CHECK(!r->extra_data && !r->structured_data && !r->verification_error && !r->verification_from_cache);
    CHECK(r->verified == verified && r->secret_parts && json_object_object_length(r->secret_parts) == 1);
    br_json *part = NULL; CHECK(json_object_object_get_ex(r->secret_parts, "key", &part));
    CHECK(json_object_is_type(part, json_type_string) && json_object_get_string_len(part) == (int)len);
    CHECK(!memcmp(json_object_get_string(part), username, len));
    CHECK(!r->primary_secret.data && !r->primary_secret.len && !r->primary_line && !r->chunk_offset && !r->chunk_offset_set);
}
static size_t pair(unsigned char *input, const void *username, size_t len, const char *key)
{
    memcpy(input, "GuRu ", 5); memcpy(input + 5, username, len);
    memcpy(input + 5 + len, "\nguru ", 6); memcpy(input + 11 + len, key, strlen(key));
    return 11 + len + strlen(key);
}
static void extract_case(const br_detector *d, const void *input, size_t len, const void *username, size_t n)
{
    test_http http = {0}; br_transport transport = test_transport(&http); br_scan_ctx ctx = {.transport = &transport};
    size_t before = encoder_calls; br_results out = test_scan(d, &ctx, false, input, len);
    CHECK(out.len == (username ? 1u : 0u) && !http.calls && !http.releases && encoder_calls == before);
    if (username) result(&out.items[0], username, n, false);
    br_results_clear(&out);
}
static void wildcard_boundaries_and_hidden_key(const br_detector *d)
{
    unsigned char input[1800]; size_t n;
    const struct { const void *user; size_t len; bool match; } cases[] = {
        {ua, sizeof(ua)-1, true}, {ub, sizeof(ub)-1, true}, {un, sizeof(un)-1, true},
        {uu, sizeof(uu)-1, true}, {um, sizeof(um)-1, true}, {"abc@de\vfg", 9, true},
        {"abc@de\rfg", 9, true}, {"abc@de fg", 9, true}, {"abc@de/fg", 9, true},
        {"abc@abcdefgh", 12, true}, /* Greedy domain backtracks into wildcard/tail. */
        {"abc@de\nfg", 9, false}, {"ab@de.fg", 8, false}, {"_AbC@de.fg", 10, false},
        {"AbC@de.fg_", 10, false}, {"AbC@de.fghijk", 13, false},
        {"ABCDEFGHIJKLMNOPQRSTU@de.fg", 27, false},
    };
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); ++i) {
        n = pair(input, cases[i].user, cases[i].len, ka);
        extract_case(d, input, n, cases[i].match ? cases[i].user : NULL, cases[i].len);
    }
    /* Only the keyword folds; the hidden key accepts lowercase beyond hex. */
    char bad[37]; memcpy(bad, ka, sizeof(ka)); bad[0] = 'G';
    n = pair(input, ua, sizeof(ua)-1, bad); extract_case(d, input, n, NULL, 0);
    snprintf((char *)input, sizeof(input), "guru %s_\nguru %s", ka, ua); extract_case(d, input, strlen((char *)input), NULL, 0);
    snprintf((char *)input, sizeof(input), "%s\nguru %s", ka, ua); extract_case(d, input, strlen((char *)input), NULL, 0);
    snprintf((char *)input, sizeof(input), "guru %s\n%s", ka, ua); extract_case(d, input, strlen((char *)input), ua, sizeof(ua)-1);
    snprintf((char *)input, sizeof(input), "guru %s!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!%s", ka, ua); extract_case(d, input, strlen((char *)input), NULL, 0);
    snprintf((char *)input, sizeof(input), "guru %s", ua); extract_case(d, input, strlen((char *)input), NULL, 0);
    snprintf((char *)input, sizeof(input), "guru %s", ka); extract_case(d, input, strlen((char *)input), NULL, 0);
    for (size_t gap = 40; gap <= 41; ++gap) {
        memcpy(input, "guru", 4); memset(input + 4, ':', gap); memcpy(input + 4 + gap, ua, sizeof(ua)-1);
        n = 4 + gap + sizeof(ua)-1; n += (size_t)snprintf((char *)input+n, sizeof(input)-n, "\nguru %s", ka);
        extract_case(d, input, n, gap == 40 ? ua : NULL, sizeof(ua)-1);
        memcpy(input, "guru", 4); memset(input + 4, ':', gap); memcpy(input + 4 + gap, ka, sizeof(ka)-1);
        n = 4 + gap + sizeof(ka)-1; n += (size_t)snprintf((char *)input+n, sizeof(input)-n, "\nguru %s", ua);
        extract_case(d, input, n, gap == 40 ? ua : NULL, sizeof(ua)-1);
    }
    /* Prefix gap counts runes; 1024 is an engine hint, never a local pair cap. */
    memcpy(input, "guru", 4); for (size_t i=0; i<40; ++i) memcpy(input+4+4*i, "💡", 4);
    n=164; memcpy(input+n, ua, sizeof(ua)-1); n+=sizeof(ua)-1;
    n+=(size_t)snprintf((char *)input+n, sizeof(input)-n, "\nguru %s", ka); extract_case(d,input,n,ua,sizeof(ua)-1);
    n=(size_t)snprintf((char *)input,sizeof(input),"guru %s",ua); memset(input+n,'!',1200); n+=1200;
    n+=(size_t)snprintf((char *)input+n,sizeof(input)-n,"guru %s",ka); extract_case(d,input,n,ua,sizeof(ua)-1);
    extract_case(d, NULL, 0, NULL, 0);
}

typedef struct { const char *const *auths; size_t count; const br_scan_ctx *ctx; const char *agent; } expected;
static void inspect_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    expected *e = http->user; size_t at = http->calls - 1;
    CHECK(at < e->count && ctx == e->ctx && http->releases == at && !borrowed_auth);
    CHECK(request->detector_type == 570 && request->profile == BR_HTTP_SANE && request->timeout_ms == 5000);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.getguru.com/api/v1/teams/teamId/stats"));
    CHECK(!request->body.data && !request->body.len && !request->dedup_key.data && !request->dedup_key.len);
    CHECK(request->nheaders == 2 && !strcmp(request->headers[0].name, "Authorization"));
    expected_auth = e->auths[at]; CHECK(!strcmp(request->headers[0].value, expected_auth));
    CHECK(!strcmp(request->headers[1].name, "User-Agent") && !strcmp(request->headers[1].value, e->agent));
    borrowed_auth = request->headers[0].value; borrowed_url = request->url;
}
static void release_response(void *user, br_http_response *response)
{
    if (borrowed_auth) {
        CHECK(!strcmp(borrowed_auth, expected_auth));
        CHECK(!strcmp(borrowed_url, "https://api.getguru.com/api/v1/teams/teamId/stats"));
    } else CHECK(!response->status && !response->body.data && !response->body.len && !response->body_error);
    borrowed_auth = borrowed_url = expected_auth = NULL;
    test_http_release(user, response);
}
static void products_and_basic_goldens(const br_detector *d)
{
    unsigned char input[600];
    int n = snprintf((char *)input, sizeof(input), "guru %s\nguru %s\nguru %s\nguru %s\nguru %s\nguru %s", ua, ub, ua, ka, kb, ka);
    const char *auths[] = {goldens[0], goldens[1], goldens[0], goldens[2], goldens[3], goldens[2], goldens[0], goldens[1], goldens[0]};
    expected e = {.auths = auths, .count = 9, .agent = "TruffleHog guru-offline"};
    test_http http = {.inspect = inspect_request, .user = &e, .response = {.status = 200, .body_error = "ignored"}};
    br_transport transport = {&http, test_http_send, release_response}; br_scan_ctx ctx = {.transport = &transport, .user_agent = "guru-offline"}; e.ctx = &ctx;
    for (size_t pass=0; pass<2; ++pass) {
        size_t before=encoder_calls; br_results out=test_scan(d,&ctx,pass!=0,input,(size_t)n);
        CHECK(out.len==9 && http.calls==(pass?9u:0u) && http.releases==http.calls && encoder_calls==before+(pass?9u:0u));
        for (size_t i=0;i<9;++i) { const char *u=i/3==1?ub:ua; result(&out.items[i],u,strlen(u),pass!=0); }
        CHECK(out.items[0].raw.data!=out.items[6].raw.data && out.items[0].secret_parts!=out.items[6].secret_parts); br_results_clear(&out);
    }
    const char *users[]={un,uu,um}; const size_t lengths[]={sizeof(un)-1,sizeof(uu)-1,sizeof(um)-1};
    for(size_t i=0;i<3;++i) {
        size_t len=pair(input,users[i],lengths[i],ka); const char *auth[]={goldens[4+i]}; e.auths=auth; e.count=1;
        http.calls=http.releases=0; br_results out=test_scan(d,&ctx,true,input,len);
        CHECK(out.len==1 && http.calls==1 && http.releases==1); result(&out.items[0],users[i],lengths[i],true); br_results_clear(&out);
    }
    size_t len=pair(input,ua,sizeof(ua)-1,ka), before=encoder_calls;
    br_results out=test_scan(d,NULL,true,input,len); CHECK(!out.len && encoder_calls==before+1); br_results_clear(&out);
    fail_encoder_after=1; before=encoder_calls;
    out=test_scan(d,NULL,false,input,len); CHECK(out.len==1 && encoder_calls==before && fail_encoder_after==1); br_results_clear(&out);
    char *error=NULL; CHECK(d->scan(d,NULL,true,(br_slice){input,len},&out,&error)!=0 && error && !fail_encoder_after && encoder_calls==before+1);
    CHECK(!strcmp(error,"Guru native Base64 encoding failed") && !out.len); free(error); br_results_clear(&out);
}
static bool fail_headers(void *user) { (void)user; fail_size=2*sizeof(br_header); fail_after=1; return false; }
static bool arm_agent(void *user) { (void)user; fail_agent=true; return false; }
static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static void status_read_send_and_setup(const br_detector *d)
{
    unsigned char input[100]; size_t len=pair(input,ua,sizeof(ua)-1,ka);
    const char *auths[]={goldens[0]}; expected e={.auths=auths,.count=1,.agent="TruffleHog"};
    test_http http={.inspect=inspect_request,.user=&e}; br_transport transport={&http,test_http_send,release_response}; br_scan_ctx ctx={.transport=&transport}; e.ctx=&ctx;
    const int statuses[]={199,200,201,204,299,300,401,403,500}; static const unsigned char body[]={0,0xff,'{'};
    for(size_t i=0;i<sizeof(statuses)/sizeof(statuses[0]);++i) {
        http.calls=http.releases=0; http.response=(br_http_response){.status=statuses[i],.body={body,sizeof(body)},.body_error=i%2?"ignored":NULL};
        br_results out=test_scan(d,&ctx,true,input,len); CHECK(out.len==1 && http.calls==1 && http.releases==1);
        result(&out.items[0],ua,sizeof(ua)-1,statuses[i]>=200 && statuses[i]<300); br_results_clear(&out);
    }
    const struct {int rc; const char *error;} failures[]={{1,"timeout"},{-7,"cannot create Guru result"},{1,"out of memory constructing HTTP headers"},{-1,NULL},{1,ka}};
    for(size_t i=0;i<sizeof(failures)/sizeof(failures[0]);++i) {
        http.calls=http.releases=0; http.send_rc=failures[i].rc; http.send_error=failures[i].error;
        http.response=i==3?(br_http_response){0}:(br_http_response){.status=200};
        br_results out=test_scan(d,&ctx,true,input,len); CHECK(out.len==1 && http.calls==1 && http.releases==1); result(&out.items[0],ua,sizeof(ua)-1,false); br_results_clear(&out);
    }
    size_t cancellations=0;
    br_scan_ctx contexts[]={{0},{.transport=&transport,.cancelled=fail_headers},{.transport=&transport,.cancelled=arm_agent},{.transport=&transport,.cancelled=cancelled,.cancel_user=&cancellations},{.transport=&transport,.deadline_monotonic_ms=1},{.transport=&transport,.user_agent="bad\r\nagent"}};
    for(size_t i=0;i<sizeof(contexts)/sizeof(contexts[0]);++i) {
        size_t before=failed_allocations; http.calls=http.releases=0;
        br_results out=test_scan(d,&contexts[i],true,input,len);
        CHECK(out.len==1 && !http.calls && http.releases==(i?1u:0u));
        CHECK(!fail_after && !fail_agent && failed_allocations==before+(i==1 || i==2?1u:0u));
        result(&out.items[0],ua,sizeof(ua)-1,false); br_results_clear(&out);
    }
    CHECK(cancellations==1);
}
static void check_prior(const br_results *out, const br_result *prior)
{
    CHECK(out->len==1 && !memcmp(&out->items[0],prior,sizeof(*prior)));
    CHECK(prior->raw.len==5 && !memcmp(prior->raw.data,"prior",5) && !strcmp(prior->verification_error,"caller-owned"));
}
static void own_failures_and_rollback(const br_detector *d)
{
    unsigned char input[200]; size_t len=pair(input,ua,sizeof(ua)-1,ka);
    len+=(size_t)snprintf((char *)input+len,sizeof(input)-len,"\nguru %s",kb);
    const char *auths[]={goldens[0],goldens[1]}; expected e={.auths=auths,.count=2,.agent="TruffleHog"};
    test_http http={.inspect=inspect_request,.user=&e,.send_rc=-7,.send_error="synthetic Do failure"};
    br_transport transport={&http,test_http_send,release_response}; br_scan_ctx ctx={.transport=&transport}; e.ctx=&ctx;
    br_result prior={0}; CHECK(br_finding_key(&prior,777,"prior","key")==0);
    prior.verified=true; prior.verification_error=strdup("caller-owned"); CHECK(prior.verification_error);
    br_results out={0}; CHECK(br_results_push(&out,&prior)==0); prior=out.items[0]; char *error=NULL;
    for(size_t failure=0;failure<5;++failure) {
        if(failure==0) {fail_size=10;fail_after=1;} /* Username capture copy. */
        if(failure==1) {fail_size=37;fail_after=2;} /* Hidden second key capture. */
        if(failure==2) {fail_size=9;fail_after=2;} /* Second finding Raw. */
        if(failure==3) fail_part_after=2; /* Positive JSON insertion failure. */
        if(failure==4) fail_encoder_after=2;
        CHECK(d->scan(d,&ctx,true,(br_slice){input,len},&out,&error)!=0 && error);
        CHECK(!fail_after && !fail_part_after && !fail_encoder_after);
        CHECK(http.calls==(failure>=2?1u:0u) && http.releases==http.calls && !borrowed_auth);
        check_prior(&out,&prior); free(error); error=NULL; http.calls=http.releases=0;
    }
    /* Finding failure is fatal before encoding/nil constructor skip. */
    size_t before=encoder_calls; fail_size=9; fail_after=1; fail_encoder_after=1;
    CHECK(d->scan(d,NULL,true,(br_slice){input,len},&out,&error)!=0 && error && !fail_after);
    CHECK(encoder_calls==before && fail_encoder_after==1); check_prior(&out,&prior); free(error); error=NULL;
    CHECK(d->scan(d,NULL,true,(br_slice){input,len},&out,&error)!=0 && error && !fail_encoder_after);
    CHECK(encoder_calls==before+1); check_prior(&out,&prior); free(error); error=NULL;
    size_t cap=out.cap; out.cap=0;
    CHECK(d->scan(d,&ctx,true,(br_slice){input,len},&out,&error)!=0 && error && !strcmp(error,"cannot append Guru result"));
    out.cap=cap; CHECK(http.calls==1 && http.releases==1); check_prior(&out,&prior); free(error); br_results_clear(&out);
}
int main(void)
{
    const br_detector *d=descriptor(); wildcard_boundaries_and_hidden_key(d); products_and_basic_goldens(d);
    status_read_send_and_setup(d); own_failures_and_rollback(d);
    CHECK(!fail_after && !fail_part_after && !fail_encoder_after && !fail_agent && !borrowed_auth && !borrowed_url && !expected_auth);
    return test_finish("Guru");
}
