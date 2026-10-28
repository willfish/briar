/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

static char a[69], b[69];
static size_t fail_size, fail_after, fail_part;
static const char *borrowed_auth, *expected_key;

/* Interpose existing resource boundaries, without adding production seams. */
void *malloc(size_t size)
{
    if (fail_after && size == fail_size && --fail_after == 0) return NULL;
    return calloc(1, size);
}
int json_object_object_add(struct json_object *o, const char *name, struct json_object *v)
{
    if (!strcmp(name, "key") && fail_part && --fail_part == 0) return 7;
    return json_object_object_add_ex(o, name, v, 0);
}
static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }
static void result_is(const br_result *r, const char *key, bool verified)
{
    test_key_result(r, 210, key, "key");
    CHECK(r->raw.len == 68 && r->verified == verified && !r->verification_error);
}
static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_getgist_init(NULL, &error) != 0 && error); free(error);
    CHECK(br_getgist_init(NULL, NULL) != 0);
    CHECK(!br_getgist_init(&d, &error) && d && !error);
    CHECK(!br_getgist_init(&again, NULL) && again == d);
    CHECK(d->type == 210 && !d->version && !strcmp(d->name, "Getgist") && !strcmp(d->custom_name, ""));
    CHECK(!strcmp(d->description, "Getgist is a service used for managing contacts and communications. Getgist API keys can be used to access and manage contact data and communication settings."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0], "getgist"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && !d->clean && !d->clean_always && !d->false_positive && !d->validate_endpoints && !d->cloud_endpoint);
    return d;
}
static void extract_case(const br_detector *d, const void *input, size_t len, const char *capture)
{
    test_http http = {0}; br_transport t = test_transport(&http); br_scan_ctx ctx = {.transport=&t};
    br_results r = test_scan(d, &ctx, false, input, len);
    if (r.len != (capture ? 1u : 0u))
        fprintf(stderr,"fixture %.20s: got %zu findings, expected %u\n", input ? (const char *)input : "", r.len, capture ? 1u : 0u);
    CHECK(r.len == (capture ? 1u : 0u) && !http.calls && !http.releases);
    if (capture) result_is(&r.items[0], capture, false);
    br_results_clear(&r);
}
static void extraction(const br_detector *d)
{
    char input[400], leading[69];
    const struct { const char *format; bool match; } cases[] = {
        {"getgist '%s'",true}, {"GeTgIsT:%s",true}, {"preGETGISTsuffix\r\n%s",true},
        {"%s",false}, {"%s getgist",false}, {"get gist %s",false}, {"getgist%s",false},
        {"getgist _%s",false}, {"getgist %.67s",false},
        {"getgist %s_",true}, {"getgist %sXYZ+=",true}, {"getgist +%s",true},
        {"getgist =%s",true}, {"getgist %s/",true}, {"getgist %s %s",true},
    };
    for (size_t i=0; i<sizeof(cases)/sizeof(*cases); ++i) {
        snprintf(input,sizeof(input),cases[i].format,a,b);
        extract_case(d,input,strlen(input),cases[i].match ? a : NULL);
    }
    leading[0]='x'; memcpy(leading+1,a,67); leading[68]='\0';
    snprintf(input,sizeof(input),"getgist x%s",a); extract_case(d,input,strlen(input),leading);
    for (size_t i=0; i<2; ++i) {
        leading[0] = i ? '=' : '+'; memcpy(leading+1,a,67); leading[68]='\0';
        snprintf(input,sizeof(input),"getgist%s",leading); extract_case(d,input,strlen(input),leading);
        snprintf(input,sizeof(input),"GeTgIsT%c%s",leading[0],a); extract_case(d,input,strlen(input),leading);
        snprintf(input,sizeof(input),"getgist %s",leading); extract_case(d,input,strlen(input),NULL);
        snprintf(input,sizeof(input),"getgist!%s",leading); extract_case(d,input,strlen(input),NULL);
    }
    for (size_t gap=40; gap<=41; ++gap) {
        memcpy(input,"getgist",7); memset(input+7,'.',gap); memcpy(input+7+gap,a,68);
        extract_case(d,input,75+gap,gap==40 ? a : NULL);
    }
    snprintf(input,sizeof(input),"getgist %s",b); extract_case(d,input,strlen(input),b); /* No entropy or Base64 check. */
    memcpy(leading,a,69); leading[30]='/';
    snprintf(input,sizeof(input),"getgist %s",leading); extract_case(d,input,strlen(input),NULL);
    int n=snprintf(input,sizeof(input),"getgist%c%s",0,a); extract_case(d,input,(size_t)n,a);
    extract_case(d,NULL,0,NULL);
}
typedef struct { const char *const *keys; size_t count; const br_scan_ctx *ctx; const char *agent; } expected;
static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *r)
{
    expected *e=http->user; size_t at=http->calls-1;
    CHECK(at<e->count && ctx==e->ctx && http->releases==at && !borrowed_auth);
    CHECK(!strcmp(r->method,"GET") && !strcmp(r->url,"https://api.getgist.com/contacts/"));
    CHECK(r->profile==BR_HTTP_SANE && r->timeout_ms==5000 && r->detector_type==210);
    CHECK(!r->body.data && !r->body.len && !r->dedup_key.data && !r->dedup_key.len);
    CHECK(r->nheaders==2 && !strcmp(r->headers[0].name,"Authorization"));
    CHECK(strlen(r->headers[0].value)==75 && !memcmp(r->headers[0].value,"Bearer ",7));
    CHECK(!memcmp(r->headers[0].value+7,e->keys[at],69));
    CHECK(!strcmp(r->headers[1].name,"User-Agent") && !strcmp(r->headers[1].value,e->agent));
    /* Retain only original auth, never the temporary prepared request/UA. */
    borrowed_auth=r->headers[0].value; expected_key=e->keys[at];
}
static void release_response(void *user, br_http_response *response)
{
    CHECK(borrowed_auth && !memcmp(borrowed_auth,"Bearer ",7));
    CHECK(!memcmp(borrowed_auth+7,expected_key,69));
    borrowed_auth=expected_key=NULL; test_http_release(user,response);
}
static void occurrences(const br_detector *d)
{
    char input[300]; snprintf(input,sizeof(input),"getgist %s\nGETGIST %s\ngetgist %s",a,b,a);
    const char *keys[]={a,b,a}; expected e={.keys=keys,.count=3,.agent="TruffleHog getgist-offline"};
    test_http http={.inspect=inspect,.user=&e,.response={.status=204,.body_error="ignored"}};
    br_transport t={&http,test_http_send,release_response}; br_scan_ctx ctx={.transport=&t,.user_agent="getgist-offline"}; e.ctx=&ctx;
    br_results r=test_scan(d,&ctx,false,input,strlen(input)); CHECK(r.len==3 && !http.calls && !http.releases);
    for(size_t i=0;i<3;++i) result_is(&r.items[i],keys[i],false);
    CHECK(r.items[0].raw.data!=r.items[2].raw.data && r.items[0].secret_parts!=r.items[2].secret_parts); br_results_clear(&r);
    r=test_scan(d,&ctx,true,input,strlen(input)); CHECK(r.len==3 && http.calls==3 && http.releases==3);
    for(size_t i=0;i<3;++i) result_is(&r.items[i],keys[i],true);
    br_results_clear(&r);
    r=test_scan(d,NULL,true,input,strlen(input)); CHECK(!r.len); br_results_clear(&r);
    r=test_scan(d,NULL,false,input,strlen(input)); CHECK(r.len==3); br_results_clear(&r);
}
static void verification(const br_detector *d)
{
    char input[90]; snprintf(input,sizeof(input),"getgist %s",a);
    const char *keys[]={a}; expected e={.keys=keys,.count=1,.agent="TruffleHog"};
    test_http http={.inspect=inspect,.user=&e}; br_transport t={&http,test_http_send,release_response}; br_scan_ctx ctx={.transport=&t}; e.ctx=&ctx;
    const int statuses[]={0,199,200,201,204,299,300,401,403,429,500};
    static const unsigned char body[]={0,0xff,'!','{'};
    for(size_t i=0;i<sizeof(statuses)/sizeof(*statuses);++i) {
        http.calls=http.releases=0;
        http.response=(br_http_response){.status=statuses[i],.body={body,sizeof(body)},.body_error=i%2 ? "ignored read failure" : ""};
        br_results r=test_scan(d,&ctx,true,input,strlen(input)); CHECK(r.len==1 && http.calls==1 && http.releases==1);
        result_is(&r.items[0],a,statuses[i]>=200 && statuses[i]<300); br_results_clear(&r);
    }
    const struct { int rc; const char *message; } failures[]={{1,"net/http: nil Context"},{-7,"cannot create Getgist result"},{1,"out of memory constructing HTTP headers"},{-1,NULL},{7,a}};
    http.response.status=200;
    for(size_t i=0;i<sizeof(failures)/sizeof(*failures);++i) {
        http.calls=http.releases=0; http.send_rc=failures[i].rc; http.send_error=failures[i].message;
        br_results r=test_scan(d,&ctx,true,input,strlen(input)); CHECK(r.len==1 && http.calls==1 && http.releases==1);
        result_is(&r.items[0],a,false); br_results_clear(&r);
    }
}
static bool fail_headers(void *user) { (void)user; fail_size=2*sizeof(br_header); fail_after=1; return false; }
static bool cancelled(void *user) { ++*(size_t *)user; return true; }
static void shared_setup(const br_detector *d)
{
    char input[90]; snprintf(input,sizeof(input),"getgist %s",a);
    test_http http={0}; br_transport t=test_transport(&http); size_t calls=0;
    br_scan_ctx contexts[]={{0},{.transport=&t,.cancelled=fail_headers},{.transport=&t,.cancelled=cancelled,.cancel_user=&calls},{.transport=&t,.deadline_monotonic_ms=1},{.transport=&t,.user_agent="bad\r\nagent"}};
    for(size_t i=0;i<sizeof(contexts)/sizeof(*contexts);++i) {
        http.calls=http.releases=0;
        br_results r=test_scan(d,&contexts[i],true,input,strlen(input)); CHECK(r.len==1 && !http.calls && http.releases==(i ? 1u : 0u) && !fail_after);
        result_is(&r.items[0],a,false); br_results_clear(&r);
    }
    CHECK(calls==1);
}
static void resources(const br_detector *d)
{
    char input[180]; snprintf(input,sizeof(input),"getgist %s\ngetgist %s",a,b);
    br_result prior={0}; CHECK(!br_finding_key(&prior,777,"prior","key")); prior.verified=true;
    prior.verification_error=strdup("caller-owned"); CHECK(prior.verification_error);
    br_results r={0}; CHECK(!br_results_push(&r,&prior)); prior=r.items[0]; char *error=NULL;
    test_http http={.response={.status=200}}; br_transport t=test_transport(&http); br_scan_ctx ctx={.transport=&t};
    for(size_t failure=0;failure<5;++failure) {
        if(failure==0) { fail_size=69; fail_after=2; } /* Collect before any send. */
        if(failure==1) { fail_size=68; fail_after=2; } /* Roll back first pushed finding. */
        if(failure>=2) fail_part=2; /* Positive insertion error, including nil skip and suppressed Do. */
        http.calls=http.releases=0; http.send_rc=failure==4 ? 7 : 0;
        CHECK(d->scan(d,failure==3 ? NULL : &ctx,true,text(input),&r,&error)!=0 && error && !fail_after && !fail_part);
        CHECK(r.len==1 && r.items[0].raw.data==prior.raw.data && r.items[0].secret_parts==prior.secret_parts);
        CHECK(r.items[0].verified && r.items[0].verification_error==prior.verification_error && !strcmp(prior.verification_error,"caller-owned") && !memcmp(prior.raw.data,"prior",5));
        CHECK(http.calls==(failure==0 || failure==3 ? 0u : 1u) && http.releases==http.calls);
        free(error); error=NULL;
    }
    size_t cap=r.cap; r.cap=0; /* Existing push validation returns a positive failure. */
    CHECK(d->scan(d,&ctx,false,text(input),&r,&error)!=0 && error); r.cap=cap;
    CHECK(r.len==1 && r.items[0].raw.data==prior.raw.data); free(error); br_results_clear(&r);
    CHECK(d->scan(NULL,NULL,false,text(""),NULL,NULL)!=0);
}
int main(void)
{
    test_secret(a,68,0); a[0]='Z'; a[13]='+'; a[22]='='; a[23]='=';
    memset(b,'A',68); b[68]='\0';
    const br_detector *d=descriptor(); extraction(d); occurrences(d); verification(d); shared_setup(d); resources(d);
    CHECK(!fail_after && !fail_part && !borrowed_auth && !expected_key);
    return test_finish("Getgist grammar/metadata/nil/requests/status/read/send/resources/rollback");
}
