/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../../src/detectors/ftp_private.h"
#include "../support/detector_test.h"

#include <malloc.h>
#include <time.h>

#define TEXT(s) ((br_slice){(const unsigned char *)(s), sizeof(s)-1})
static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }
static size_t fail_malloc_size, fail_malloc_after, fail_realloc_size, fail_realloc_after, failures, fail_part_after;
void *malloc(size_t n)
{
    if (fail_malloc_after && n == fail_malloc_size && --fail_malloc_after == 0) { ++failures; return NULL; }
    return calloc(1, n);
}
char *strdup(const char *s)
{
    size_t n = strlen(s)+1; char *p = malloc(n); if (p) memcpy(p, s, n); return p;
}
void *realloc(void *old, size_t n)
{
    if (fail_realloc_after && n == fail_realloc_size && --fail_realloc_after == 0) { ++failures; return NULL; }
    if (!n) { free(old); return NULL; }
    size_t before = old ? malloc_usable_size(old) : 0; void *p = malloc(n);
    if (p) { if (old) memcpy(p, old, before < n ? before : n); free(old); } return p;
}
int json_object_object_add(struct json_object *o, const char *name, struct json_object *value)
{
    if (fail_part_after && !strcmp(name,"key") && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(o,name,value,0);
}
static const br_detector *descriptor(void)
{
    const br_detector *d = NULL, *again = NULL; char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_ftp_init(NULL,&error) == -1 && error); free(error); error = NULL;
    CHECK(br_ftp_init(&d,&error) == 0 && d && !error);
    CHECK(br_ftp_init(&again,&error) == 0 && again == d && !error);
    CHECK(d->type == 899 && d->version == 0 && !strcmp(d->name,"FTP") && d->custom_name && !*d->custom_name);
    CHECK(!strcmp(d->description,"FTP is a protocol for reading and writing files. An FTP password can be used to read and sometimes write files."));
    CHECK(d->nkeywords == 1 && !strcmp(d->keywords[0],"ftp://"));
    CHECK(d->max_secret_size == -1 && d->start_offset == -1 && d->max_credential_span == -1);
    CHECK(d->state && d->scan && d->false_positive && !d->clean && !d->clean_always && !d->validate_endpoints && !d->cloud_endpoint);
    const br_ftp_state *s = d->state; CHECK(s->regex && !s->io && !s->user && !s->timeout_ns); return d;
}
static void finding(const br_result *r, const char *raw, const char *redacted, bool verified, const char *cause)
{
    CHECK(r->detector_type == 899 && !r->detector_name && r->raw.len == strlen(raw) && !memcmp(r->raw.data,raw,r->raw.len));
    CHECK(!r->raw_v2.data && !r->raw_v2.len && r->redacted && !strcmp(r->redacted,redacted));
    CHECK(!r->extra_data && !r->structured_data && !r->primary_secret.data && !r->primary_secret.len && !r->primary_line);
    CHECK(!r->verification_from_cache && !r->chunk_offset && !r->chunk_offset_set && r->verified == verified);
    CHECK((r->verification_error != NULL) == (cause != NULL)); if (cause) CHECK(!strcmp(r->verification_error,cause));
    br_json *part = NULL; CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 1 && json_object_object_get_ex(r->secret_parts,"key",&part));
    CHECK(json_object_is_type(part,json_type_string) && (size_t)json_object_get_string_len(part) == strlen(raw) && !memcmp(json_object_get_string(part),raw,strlen(raw)));
}
static void fragment_control_regressions(const br_detector *d)
{
    const struct { br_slice input; const char *raw; } cases[] = {
        {TEXT("ftp://Briar86:B7r9P2@fixture.invalid/#x:abc\vdef@tail"), "ftp://Briar86:B7r9P2@fixture.invalid#x:abc%0Bdef@tail"},
        {TEXT("ftp://Briar86:B7r9P2@fixture.invalid/#x:abc\0def@tail"), "ftp://Briar86:B7r9P2@fixture.invalid#x:abc%00def@tail"},
    };
    for (size_t i=0;i<sizeof(cases)/sizeof(*cases);++i) {
        br_results out=test_scan(d,NULL,false,cases[i].input.data,cases[i].input.len);
        CHECK(out.len == 1); finding(&out.items[0],cases[i].raw,cases[i].raw,false,NULL); br_results_clear(&out);
    }
}
static void projection(const br_detector *d)
{
    const struct { const char *in, *raw, *redacted; } cases[] = {
        {"ftp://alice:secret@Example.invalid/path", "ftp://alice:secret@Example.invalid", "ftp://alice:********@Example.invalid"},
        {"ftp://alice:part:secret@host.invalid/dir", "ftp://alice:part%3Asecret@host.invalid", "ftp://alice:part%3A********@host.invalid"},
        {"ftp://alice:p%2fss@host.invalid/file", "ftp://alice:p%2Fss@host.invalid", "ftp://alice:p%2Fss@host.invalid"},
        {"ftp://al%69ce:p%40ss@host.invalid/dir", "ftp://alice:p%40ss@host.invalid", "ftp://alice:********@host.invalid"},
        {"ftp://alice:%24name@host.invalid/path", "ftp://alice:$name@host.invalid", "ftp://alice:$name@host.invalid"},
        {"ftp://alice:%2A%2A%2A@host.invalid/dir", "ftp://alice:%2A%2A%2A@host.invalid", "ftp://alice:********@host.invalid"},
        {"ftp://Anonymous:secret@host.invalid", "ftp://Anonymous:secret@host.invalid", "ftp://Anonymous:********@host.invalid"},
        {"ftp://alice:actual@real.invalid/path:capt@tail.invalid", "ftp://alice:actual@real.invalid", "ftp://alice:actual@real.invalid"},
        {"ftp://alice:actual@real.invalid?x:capt@tail.invalid", "ftp://alice:actual@real.invalid?x:capt@tail.invalid", "ftp://alice:actual@real.invalid?x:********@tail.invalid"},
        {"ftp://alice:actual@real.invalid#x:capt@tail.invalid", "ftp://alice:actual@real.invalid#x:capt@tail.invalid", "ftp://alice:actual@real.invalid#x:********@tail.invalid"},
        {"ftp://alice:actual@[::1]/x:capt@tail.invalid", "ftp://alice:actual@[::1]", "ftp://alice:actual@[::1]"},
        {"ftp://alice:actual@[fe80::1%25zone]:2121/x:capt@tail.invalid", "ftp://alice:actual@[fe80::1%25zone]:2121", "ftp://alice:actual@[fe80::1%25zone]:2121"},
        {"ftp://alice:actual@real.invalid#x%00:capt@tail.invalid", "ftp://alice:actual@real.invalid#x%00:capt@tail.invalid", "ftp://alice:actual@real.invalid#x%00:********@tail.invalid"},
        {"ftp://alice:$name@host.invalid/path", NULL, NULL},
        {"ftp://alice:actual@real.invalid/x:$capt@tail.invalid", NULL, NULL},
        {"ftp://alice:***@host.invalid", NULL, NULL}, {"ftp://anonymous:secret@host.invalid", NULL, NULL},
        {"ftp://%61nonymous:secret@host.invalid", NULL, NULL}, {"ftp://alice/path:secret@host.invalid", NULL, NULL},
        {"FTP://alice:secret@host.invalid", NULL, NULL}, {"xftp://alice:secret@host.invalid", NULL, NULL},
        {"ftp://alice:secret@host.invalid/%zz", NULL, NULL},
        {"ftp://alice:pw@first.invalid\vftp://bob:secret@last.invalid", NULL, NULL}, /* RE2 \S includes VT; whole greedy match then URL.Parse rejects control. */
    };
    for (size_t i=0;i<sizeof(cases)/sizeof(*cases);++i) {
        br_results out = test_scan(d,NULL,false,cases[i].in,strlen(cases[i].in)); CHECK(out.len == (cases[i].raw ? 1u : 0u));
        if (out.len) finding(&out.items[0],cases[i].raw,cases[i].redacted,false,NULL);
        br_results_clear(&out);
    }
    const char *duplicate = "ftp://alice:secret@host.invalid/a\nftp://alice:secret@host.invalid/b";
    br_results out = test_scan(d,NULL,false,duplicate,strlen(duplicate)); CHECK(out.len == 2);
    finding(&out.items[0],"ftp://alice:secret@host.invalid","ftp://alice:********@host.invalid",false,NULL);
    finding(&out.items[1],"ftp://alice:secret@host.invalid","ftp://alice:********@host.invalid",false,NULL);
    CHECK(out.items[0].raw.data != out.items[1].raw.data && out.items[0].secret_parts != out.items[1].secret_parts); br_results_clear(&out);
    char host[101], uri[160]; memset(host,'A',100); host[100]=0; snprintf(uri,sizeof(uri),"ftp://alice:secret@%s/path",host);
    out = test_scan(d,NULL,false,uri,strlen(uri)); CHECK(out.len == 1 && out.items[0].raw.len == 119); br_results_clear(&out); /* No DNS-label cap. */
    out = test_scan(d,NULL,false,NULL,0); CHECK(!out.len); br_results_clear(&out);
}

typedef struct { br_slice bytes, cause; int rc; bool progress_set; size_t progress; } step;
typedef struct {
    const char *address; int64_t timeout, seen_timeout; bool negative_timeout, tcp, give_handle, live;
    int dial_rc, deadline_rc; br_slice dial_cause, deadline_cause;
    step reads[16], writes[20]; size_t nreads,nwrites,ri,wi,dials,deadlines,closes;
    size_t expect_dials,expect_deadlines,expect_closes;
    size_t arm_close,arm_malloc,arm_realloc;
} fake_ftp;
static br_bytes own(br_slice s)
{
    br_bytes b={0}; if (s.len) { b.data=malloc(s.len); CHECK(b.data); memcpy(b.data,s.data,s.len); b.len=s.len; } return b;
}
static int fake_dial(void *user, br_slice address, int64_t timeout, br_ftp_conn *out, br_bytes *cause)
{
    fake_ftp *f=user; CHECK(!f->live && !out->handle && !cause->data && !cause->len);
    CHECK(address.len == strlen(f->address) && !memcmp(address.data,f->address,address.len));
    CHECK(f->negative_timeout ? timeout < 0 : timeout == f->timeout); f->seen_timeout=timeout; ++f->dials;
    if (f->give_handle) { *out=(br_ftp_conn){f,f->tcp}; f->live=true; } *cause=own(f->dial_cause); return f->dial_rc;
}
static int fake_deadline(void *user, br_ftp_conn c, int64_t timeout, br_bytes *cause)
{
    fake_ftp *f=user; CHECK(f->live && c.handle == f && f->dials == f->deadlines+1 && timeout == f->seen_timeout);
    CHECK(!cause->data && !cause->len); ++f->deadlines; *cause=own(f->deadline_cause); return f->deadline_rc;
}
static int fake_read(void *user, br_ftp_conn c, unsigned char *out, size_t capacity, size_t *n, br_bytes *cause)
{
    fake_ftp *f=user; CHECK(f->live && c.handle == f && f->deadlines == f->dials && f->ri < f->nreads);
    CHECK(!*n && !cause->data && !cause->len); step *s=&f->reads[f->ri++]; CHECK(s->bytes.len <= capacity);
    if (s->bytes.len) memcpy(out,s->bytes.data,s->bytes.len);
    *n=s->bytes.len; *cause=own(s->cause); return s->rc;
}
static int fake_write(void *user, br_ftp_conn c, br_slice data, size_t *n, br_bytes *cause)
{
    fake_ftp *f=user; CHECK(f->live && c.handle == f && f->deadlines == f->dials && f->wi < f->nwrites);
    CHECK(!*n && !cause->data && !cause->len); step *s=&f->writes[f->wi++];
    CHECK(data.len == s->bytes.len && (!data.len || !memcmp(data.data,s->bytes.data,data.len)));
    *n=s->progress_set ? s->progress : data.len; *cause=own(s->cause); return s->rc;
}
static void fake_close(void *user, br_ftp_conn c)
{
    fake_ftp *f=user; CHECK(f->live && c.handle == f); f->live=false; ++f->closes;
    if (f->arm_close == f->closes) {
        if (f->arm_malloc) { fail_malloc_size=f->arm_malloc; fail_malloc_after=1; }
        if (f->arm_realloc) { fail_realloc_size=f->arm_realloc; fail_realloc_after=1; }
    }
}
static const br_ftp_io memory_io={fake_dial,fake_deadline,fake_read,fake_write,fake_close};
static fake_ftp script(br_slice response, const char *const *commands, size_t n)
{
    fake_ftp f={.address="host.invalid:21",.timeout=1000000000,.tcp=true,.give_handle=true,.expect_dials=1,.expect_deadlines=1,.expect_closes=1};
    if (response.data || response.len) { f.reads[0]=(step){.bytes=response}; f.nreads=1; }
    CHECK(n <= 20); for (size_t i=0;i<n;++i) f.writes[i]=(step){.bytes=text(commands[i])}; f.nwrites=n; return f;
}
static void checked(const fake_ftp *f)
{
    CHECK(f->dials == f->expect_dials && f->deadlines == f->expect_deadlines && f->closes == f->expect_closes && !f->live);
    CHECK(f->ri == f->nreads && f->wi == f->nwrites);
}
static int invoke(const br_detector *base, const char *input, bool verify, const br_scan_ctx *ctx, int64_t timeout,
                   fake_ftp *fake, br_results *out, char **error)
{
    br_ftp_state state=*(const br_ftp_state *)base->state; state.io=fake ? &memory_io : NULL; state.user=fake; state.timeout_ns=timeout;
    br_detector d=*base; d.state=&state;
    int rc=d.scan(&d,ctx,verify,text(input),out,error); if (fake) checked(fake); return rc;
}
static br_results run(const br_detector *base, const char *input, fake_ftp *fake)
{
    br_scan_ctx ctx={0}; br_results out={0}; char *error=NULL;
    int rc=invoke(base,input,true,&ctx,1000000000,fake,&out,&error);
    if (error) fprintf(stderr,"scan error: %s\n",error);
    CHECK(rc == 0 && !error); return out;
}
static const char uri[]="ftp://alice:secret@host.invalid/path";
static const char raw[]="ftp://alice:secret@host.invalid", redact[]="ftp://alice:********@host.invalid";
static const char *const normal[]={"USER alice\r\n","PASS secret\r\n","FEAT\r\n","TYPE I\r\n","QUIT\r\n"};
static const char *const user230[]={"USER alice\r\n","FEAT\r\n","TYPE I\r\n","QUIT\r\n"};
static void control_states(const br_detector *d)
{
    fake_ftp f=script(TEXT("220 hello\r\n331 password\r\n230 yes\r\n500 no FEAT\r\n200 binary\r\n"),normal,5);
    br_results out=run(d,uri,&f); CHECK(out.len == 1); finding(&out.items[0],raw,redact,true,NULL); br_results_clear(&out);
    f=script(TEXT("220 hello\n230 yes\n530 ignored FEAT\n200 binary\n"),user230,4);
    out=run(d,uri,&f); finding(&out.items[0],raw,redact,true,NULL); br_results_clear(&out); /* USER230 skips PASS; FEAT530 is NOT a rejection. */
    const int opts[]={200,202,501,504};
    const char *const utf8[]={"USER alice\r\n","FEAT\r\n","TYPE I\r\n","OPTS UTF8 ON\r\n","QUIT\r\n"};
    for (size_t i=0;i<4;++i) {
        char response[160]; snprintf(response,sizeof(response),"220 hi\r\n230 yes\r\n211-features\r\n UTF8\r\n211 end\r\n200 binary\r\n%d yes\r\n",opts[i]);
        f=script(text(response),utf8,5); out=run(d,uri,&f); finding(&out.items[0],raw,redact,true,NULL); br_results_clear(&out);
    }
    f=script(TEXT("220 hi\r\n230 yes\r\n211-features\r\n utf8\r\n UTF8\tignored\r\n211 end\r\n200 binary\r\n"),user230,4);
    out=run(d,uri,&f); finding(&out.items[0],raw,redact,true,NULL); br_results_clear(&out);
    f=script(TEXT("220 hi\r\n230 yes\r\n211-features\r\n \xc2\xa0UTF8\xc2\xa0\r\n211 end\r\n200 yes\r\n200 yes\r\n"),utf8,5);
    out=run(d,uri,&f); finding(&out.items[0],raw,redact,true,NULL); br_results_clear(&out);
    const char *const quit[]={"QUIT\r\n"};
    f=script(TEXT("530 no\0secret\r\n"),quit,1); out=run(d,uri,&f); finding(&out.items[0],raw,redact,false,NULL); br_results_clear(&out);
    const char *const rejected[]={"USER alice\r\n","PASS secret\r\n","QUIT\r\n"};
    f=script(TEXT("220 hi\r\n331 pass\r\n530 no secret\r\n"),rejected,3); out=run(d,uri,&f); finding(&out.items[0],raw,redact,false,NULL); br_results_clear(&out);
    f=script(TEXT("220 hi\r\n230 yes\r\n500 none\r\n530 no secret\r\n"),user230,4); out=run(d,uri,&f); finding(&out.items[0],raw,redact,false,NULL); br_results_clear(&out);
    const char *const user_error[]={"USER alice\r\n","QUIT\r\n"};
    f=script(TEXT("220 hi\r\n530 no secret\r\n"),user_error,2); out=run(d,uri,&f); finding(&out.items[0],raw,redact,false,"no [REDACTED]"); br_results_clear(&out);
    f=script(TEXT("220 hi\r\n230 yes\r\n211-features\r\n UTF8\r\n211 end\r\n200 yes\r\n530 no secret\r\n"),utf8,5);
    out=run(d,uri,&f); finding(&out.items[0],raw,redact,false,"no [REDACTED]"); br_results_clear(&out);
    f=script(TEXT("220 hi\r\n331 pass\r\n550 no secret\r\n"),rejected,3); out=run(d,uri,&f); finding(&out.items[0],raw,redact,false,"550 no [REDACTED]"); br_results_clear(&out);
    f=script(TEXT("220 hi\r\n530 REDACTED\r\n"),user_error,2);
    out=run(d,"ftp://alice:REDACTED@host.invalid",&f); finding(&out.items[0],"ftp://alice:REDACTED@host.invalid",redact,false,"[REDACTED]"); br_results_clear(&out); /* Exactly ONE redaction pass. */
}
static void readers_writers_and_messages(const br_detector *d)
{
    const char *const quit[]={"QUIT\r\n"}, *const user_error[]={"USER alice\r\n","QUIT\r\n"};
    fake_ftp f=script(TEXT("220 he"),user_error,2); f.reads[0].rc=1; f.reads[0].cause=TEXT("deferred secret");
    br_results out=run(d,uri,&f); finding(&out.items[0],raw,redact,false,"deferred [REDACTED]"); br_results_clear(&out);
    f=script(TEXT("220 hi\r\n230 yes\r\n500 none\r\n200 binary\r\n"),user230,4); f.reads[0].rc=1; f.reads[0].cause=TEXT("unused\0error");
    out=run(d,uri,&f); finding(&out.items[0],raw,redact,true,NULL); br_results_clear(&out); /* Complete buffered replies can win a terminal error. */
    f=script(TEXT("220 hi\r\n"),user_error,2); f.nreads=2; /* explicit successful zero-byte read = EOF */
    out=run(d,uri,&f); finding(&out.items[0],raw,redact,false,"EOF"); br_results_clear(&out);
    f=script(TEXT("220 hi\r\n230 yes\r\n500 none\r\n200 final"),user230,4); f.nreads=2;
    out=run(d,uri,&f); finding(&out.items[0],raw,redact,true,NULL); br_results_clear(&out); /* No final LF is required. */
    f=script(TEXT("550-first secret\r\nnot a code\r\n550 last\r\n"),quit,1);
    out=run(d,uri,&f); finding(&out.items[0],raw,redact,false,"550 first [REDACTED]\nnot a code\nlast"); br_results_clear(&out);
    f=script(TEXT("530-first secret\r\n"),quit,1); f.nreads=2; f.reads[1]=(step){.rc=1,.cause=TEXT("later secret")};
    out=run(d,uri,&f); finding(&out.items[0],raw,redact,false,"later [REDACTED]"); br_results_clear(&out); /* I/O overrides initial typed530, not diagnostic classification. */
    f=script(TEXT("xyz\r\n"),quit,1); out=run(d,uri,&f); finding(&out.items[0],raw,redact,false,"short response: \"xyz\""); br_results_clear(&out);
    f=script(TEXT("abc bad\r\n"),quit,1); out=run(d,uri,&f); finding(&out.items[0],raw,redact,false,"invalid response code: \"abc bad\""); br_results_clear(&out);
    f=script(TEXT("\0x\r\n"),quit,1); out=run(d,uri,&f); finding(&out.items[0],raw,redact,false,"short response: \"\\x00x\""); br_results_clear(&out);
    f=script(TEXT("550 \xffsecret\r\n"),quit,1); out=run(d,uri,&f); finding(&out.items[0],raw,redact,false,"550 \xff[REDACTED]"); br_results_clear(&out);
    const char *const only_user[]={"USER alice\r\n"};
    f=script(TEXT("220 hi\r\n"),only_user,1); f.writes[0].progress_set=true; f.writes[0].progress=2;
    out=run(d,uri,&f); finding(&out.items[0],raw,redact,false,"short write"); br_results_clear(&out); /* Sticky writer prevents an underlying QUIT write. */
    f=script(TEXT("220 hi\r\n"),only_user,1); f.writes[0].rc=1; f.writes[0].cause=TEXT("530 text secret");
    out=run(d,uri,&f); finding(&out.items[0],raw,redact,false,"530 text [REDACTED]"); br_results_clear(&out);
    f=script(TEXT("220 hi\r\n230 yes\r\n500 none\r\n200 binary\r\n"),user230,4); f.writes[3].rc=1; f.writes[3].cause=TEXT("ignored\0QUIT error");
    out=run(d,uri,&f); finding(&out.items[0],raw,redact,true,NULL); br_results_clear(&out);
}
static void captured_decoded_and_unused_credentials(const br_detector *d)
{
    const char *const actual[]={"USER alice\r\n","PASS part:secret\r\n","FEAT\r\n","TYPE I\r\n","QUIT\r\n"};
    fake_ftp f=script(TEXT("220 hi\r\n331 pass\r\n230 yes\r\n500 none\r\n200 yes\r\n"),actual,5);
    br_results out=run(d,"ftp://alice:part:secret@host.invalid/path",&f);
    finding(&out.items[0],"ftp://alice:part%3Asecret@host.invalid","ftp://alice:part%3A********@host.invalid",true,NULL); br_results_clear(&out);
    const char *const pathpass[]={"USER alice\r\n","PASS actual\r\n","FEAT\r\n","TYPE I\r\n","QUIT\r\n"};
    f=script(TEXT("220 hi\r\n331 pass\r\n230 yes\r\n500 none\r\n200 yes\r\n"),pathpass,5); f.address="real.invalid:21";
    out=run(d,"ftp://alice:actual@real.invalid/path:$capt@tail.invalid",&f); finding(&out.items[0],"ftp://alice:actual@real.invalid","ftp://alice:actual@real.invalid",true,NULL); br_results_clear(&out);
    f=script(TEXT("220 hi\r\n230 yes\r\n500 none\r\n200 yes\r\n"),user230,4);
    out=run(d,"ftp://alice:p%0D%0Ass@host.invalid/path",&f);
    finding(&out.items[0],"ftp://alice:p%0D%0Ass@host.invalid","ftp://alice:********@host.invalid",true,NULL); br_results_clear(&out); /* Unused PASS cannot preempt USER230. */
    const char *const nuluser[]={"USER a", "PASS secret\r\n", "FEAT\r\n", "TYPE I\r\n", "QUIT\r\n"};
    f=script(TEXT("220 hi\r\n331 pass\r\n230 yes\r\n500 none\r\n200 yes\r\n"),nuluser,5); f.writes[0].bytes=TEXT("USER a\0bc\r\n");
    out=run(d,"ftp://a%00bc:secret@host.invalid",&f); finding(&out.items[0],"ftp://a%00bc:secret@host.invalid","ftp://a%00bc:********@host.invalid",true,NULL); br_results_clear(&out);
    const char *const passslash[]={"USER alice\r\n","PASS p/ss\r\n","QUIT\r\n"};
    f=script(TEXT("220 hi\r\n331 pass\r\n550 p/ss\r\n"),passslash,3);
    out=run(d,"ftp://alice:p%2fss@host.invalid",&f); finding(&out.items[0],"ftp://alice:p%2Fss@host.invalid","ftp://alice:p%2Fss@host.invalid",false,"550 p/ss"); br_results_clear(&out);
    f=script(TEXT("220 hi\r\n230 yes\r\n500 none\r\n200 yes\r\n"),user230,4);
    out=run(d,"ftp://alice:$name@host.invalid",&f); finding(&out.items[0],"ftp://alice:$name@host.invalid",redact,true,NULL); br_results_clear(&out);
    f=script(TEXT("220 hi\r\n230 yes\r\n500 none\r\n200 yes\r\n"),user230,4); f.address="[::1]";
    out=run(d,"ftp://alice:secret@[::1]/x:capt@tail.invalid",&f); finding(&out.items[0],"ftp://alice:secret@[::1]","ftp://alice:secret@[::1]",true,NULL); br_results_clear(&out);
}
static void bounded_commands_and_fragment_redaction(const br_detector *d)
{
    /* Source grammar maximum: abc + ':' + 46 a's + ':' + 50 b's is 101
     * valid ASCII userinfo bytes. The actual decoded password is 97 bytes,
     * not the separately captured final 50 b's. Check the COMPLETE frame. */
    char a[47],b[51],input[160],password_frame[105],expected_raw[160],expected_redacted[160];
    memset(a,'a',46); a[46]=0; memset(b,'b',50); b[50]=0;
    snprintf(input,sizeof(input),"ftp://abc:%s:%s@host.invalid",a,b);
    CHECK(snprintf(password_frame,sizeof(password_frame),"PASS %s:%s\r\n",a,b) == 104);
    snprintf(expected_raw,sizeof(expected_raw),"ftp://abc:%s%%3A%s@host.invalid",a,b);
    snprintf(expected_redacted,sizeof(expected_redacted),"ftp://abc:%s%%3A********@host.invalid",a);
    const char *const commands[]={"USER abc\r\n",password_frame,"FEAT\r\n","TYPE I\r\n","QUIT\r\n"};
    fake_ftp f=script(TEXT("220 hi\r\n331 pass\r\n230 yes\r\n500 none\r\n200 yes\r\n"),commands,5);
    br_results out=run(d,input,&f); CHECK(out.len == 1); finding(&out.items[0],expected_raw,expected_redacted,true,NULL); br_results_clear(&out);
    /* A fragment capture can itself contain NUL. Source single-pass binary
     * password redaction can REMOVE the diagnostic NUL before ABI1 publishing. */
    const char *const userquit[]={"USER Briar86\r\n","QUIT\r\n"};
    f=script(TEXT("220 hi\r\n530 abc\0def\r\n"),userquit,2); f.address="fixture.invalid:21";
    br_ftp_state state=*(const br_ftp_state *)d->state; state.io=&memory_io; state.user=&f; state.timeout_ns=1000000000;
    br_detector copy=*d; copy.state=&state; br_scan_ctx ctx={0}; char *error=NULL;
    CHECK(copy.scan(&copy,&ctx,true,TEXT("ftp://Briar86:B7r9P2@fixture.invalid/#x:abc\0def@tail"),&out,&error) == 0 && !error && out.len == 1);
    checked(&f);
    finding(&out.items[0],"ftp://Briar86:B7r9P2@fixture.invalid#x:abc%00def@tail","ftp://Briar86:B7r9P2@fixture.invalid#x:abc%00def@tail",false,"[REDACTED]"); br_results_clear(&out);
}
static bool would_cancel(void *p) { ++*(size_t *)p; return true; }
static void defaults_timeout_and_fp(const br_detector *d)
{
    br_scan_ctx ctx={0}; br_results out={0}; char *error=NULL;
    CHECK(invoke(d,uri,true,&ctx,0,NULL,&out,&error) == 0 && !error && out.len == 1);
    finding(&out.items[0],raw,redact,false,"unsupported: native FTP verification"); br_results_clear(&out);
    CHECK(invoke(d,"ftp://alice:$name@host.invalid",true,&ctx,0,NULL,&out,&error) == 0 && !error && !out.len); br_results_clear(&out);
    CHECK(invoke(d,uri,true,NULL,1,NULL,&out,&error) == 0 && !error && out.len == 1); br_results_clear(&out);
    const char *const quit[]={"QUIT\r\n"}; fake_ftp f=script(TEXT("530 no\r\n"),quit,1);
    size_t cancel_calls=0; ctx=(br_scan_ctx){.cancelled=would_cancel,.cancel_user=&cancel_calls}; f.timeout=5000000000;
    CHECK(invoke(d,uri,true,&ctx,0,&f,&out,&error) == 0 && !error && !cancel_calls); br_results_clear(&out);
    f=script(TEXT("530 no\r\n"),quit,1); f.negative_timeout=true; ctx=(br_scan_ctx){.deadline_monotonic_ms=1};
    CHECK(invoke(d,uri,true,&ctx,0,&f,&out,&error) == 0 && !error); br_results_clear(&out);
    f=script(TEXT("530 no\r\n"),quit,1); f.timeout=1234;
    CHECK(invoke(d,uri,true,&ctx,1234,&f,&out,&error) == 0 && !error); br_results_clear(&out); /* Positive override wins expired context deadline. */
    const char *const no_user[]={"USER alice\r\n","QUIT\r\n"}; f=script(TEXT("220 hi\r\n530 wrong\r\n"),no_user,2); f.timeout=1234;
    CHECK(invoke(d,uri,true,NULL,1234,&f,&out,&error) == 0 && !error); br_results_clear(&out);
    out=test_scan(d,NULL,false,"ftp://alice:secret@FTP.FreeBSD.ORG/path",sizeof("ftp://alice:secret@FTP.FreeBSD.ORG/path")-1);
    char *reason=NULL; CHECK(out.len == 1 && d->false_positive(d,&out.items[0],&reason) && reason && !strcmp(reason,"contains term: @ftp.freebsd.org")); free(reason); br_results_clear(&out);
    out=test_scan(d,NULL,false,"ftp://example:secret@host.invalid",sizeof("ftp://example:secret@host.invalid")-1); reason=NULL;
    CHECK(out.len == 1 && !d->false_positive(d,&out.items[0],&reason) && !reason); br_results_clear(&out); /* No inherited default terms/wordlists. */
    unsigned char bad[]={0xff}; br_result value={.raw={bad,1}};
    CHECK(d->false_positive(d,&value,&reason) && reason && !strcmp(reason,"invalid utf8")); free(reason);
}
static br_results prior_result(void)
{
    br_results out={0}; br_result r={0}; CHECK(br_finding_key(&r,17,"caller-owned","key") == 0);
    r.verified=true; r.verification_error=strdup("prior cause"); CHECK(r.verification_error && br_results_push(&out,&r) == 0); return out;
}
static void preserved(br_results *out, int rc, char *error, unsigned char *rawptr, br_json *parts, char *cause)
{
    CHECK(rc == -1 && error && out->len == 1); test_key_result(&out->items[0],17,"caller-owned","key");
    CHECK(out->items[0].verified && out->items[0].raw.data == rawptr && out->items[0].secret_parts == parts && out->items[0].verification_error == cause && !strcmp(cause,"prior cause"));
    free(error); br_results_clear(out);
}
static void fatal_case(const br_detector *d, const char *input, fake_ftp *f, const br_scan_ctx *ctx, int64_t timeout, const char *fragment)
{
    br_results out=prior_result(); unsigned char *p=out.items[0].raw.data; br_json *parts=out.items[0].secret_parts; char *cause=out.items[0].verification_error,*error=NULL;
    int rc=invoke(d,input,true,ctx,timeout,f,&out,&error); CHECK(error && strstr(error,fragment)); preserved(&out,rc,error,p,parts,cause);
}
static void safe_fatal_boundaries_and_cleanup(const br_detector *d)
{
    br_scan_ctx ctx={0}; const char *const quit[]={"QUIT\r\n"}, *const userquit[]={"USER alice\r\n","QUIT\r\n"};
    fatal_case(d,uri,NULL,NULL,0,"nil context Deadline");
    fake_ftp f=script((br_slice){0},NULL,0); f.tcp=false; f.expect_deadlines=1; f.expect_closes=1;
    fatal_case(d,uri,&f,&ctx,1000000000,"RemoteAddr is not TCP");
    f=script((br_slice){0},NULL,0); f.deadline_rc=1; f.deadline_cause=TEXT("deadline secret"); f.tcp=false;
    br_results out=run(d,uri,&f); finding(&out.items[0],raw,redact,false,"deadline [REDACTED]"); br_results_clear(&out); /* Deadline error PRECEDES TCP assertion. */
    f=script((br_slice){0},NULL,0); f.dial_rc=1; f.dial_cause=TEXT("dial secret"); f.expect_deadlines=0;
    out=run(d,"ftp://alice:p%0D%0Ass@host.invalid",&f); finding(&out.items[0],"ftp://alice:p%0D%0Ass@host.invalid","ftp://alice:********@host.invalid",false,"dial secret"); br_results_clear(&out);
    f=script(TEXT("220 hi\r\n331 pass\r\n"),userquit,2);
    fatal_case(d,"ftp://alice:p%0D%0Ass@host.invalid",&f,&ctx,1000000000,"credential CR/LF");
    f=script(TEXT("220 hi\r\n"),quit,1);
    fatal_case(d,"ftp://al%0Dice:secret@host.invalid",&f,&ctx,1000000000,"credential CR/LF");
    f=script(TEXT("550 no\0secret\r\n"),quit,1);
    fatal_case(d,uri,&f,&ctx,1000000000,"published verification error contains embedded NUL");
    f=script(TEXT("\xc3\xa5\r\n"),quit,1);
    fatal_case(d,uri,&f,&ctx,1000000000,"non-ASCII Go protocol diagnostic quoting");
    f=script(TEXT("220 hi\r\n230 yes\r\n500 none\r\n200 yes\r\n"),user230,4); f.writes[3].rc=-1; f.writes[3].cause=TEXT("fatal QUIT");
    fatal_case(d,uri,&f,&ctx,1000000000,"I/O resource failure");
    f=script((br_slice){0},NULL,0); f.dial_rc=-1; f.dial_cause=TEXT("partial dial resource"); f.expect_deadlines=0;
    fatal_case(d,uri,&f,&ctx,1000000000,"I/O resource failure");
    f=script(TEXT("220 hi\r\n"),quit,1); f.reads[0].rc=-1; f.reads[0].cause=TEXT("fatal partial reader");
    fatal_case(d,uri,&f,&ctx,1000000000,"I/O resource failure");
    br_ftp_state state=*(const br_ftp_state *)d->state; br_ftp_io bad=memory_io; bad.read=NULL; state.io=&bad; state.timeout_ns=1;
    br_detector copy=*d; copy.state=&state; out=prior_result(); char *error=NULL;
    CHECK(copy.scan(&copy,&ctx,true,text(uri),&out,&error) == -1 && error && strstr(error,"all five")); free(error); br_results_clear(&out);
    out=test_scan(&copy,NULL,false,uri,strlen(uri)); CHECK(out.len == 1); br_results_clear(&out); /* NoV does not invoke an unused I/O configuration. */
}
static void material_resources_and_rollback(const br_detector *d)
{
    br_scan_ctx ctx={0}; char *error=NULL; br_results out; unsigned char *p; br_json *parts; char *cause; int rc; size_t before;
    const size_t sizes[]={2*sizeof(br_span),sizeof("ftp://alice:secret@host.invalid")-1};
    for (size_t i=0;i<2;++i) {
        out=prior_result(); p=out.items[0].raw.data; parts=out.items[0].secret_parts; cause=out.items[0].verification_error; before=failures;
        fail_malloc_size=sizes[i]; fail_malloc_after=1; error=NULL;
        rc=d->scan(d,NULL,false,text("ftp://alice:secret@host.invalid"),&out,&error);
        CHECK(!fail_malloc_after && failures == before+1); preserved(&out,rc,error,p,parts,cause);
    }
    out=prior_result(); p=out.items[0].raw.data; parts=out.items[0].secret_parts; cause=out.items[0].verification_error; error=NULL; before=failures;
    fail_realloc_size=64; fail_realloc_after=1;
    rc=d->scan(d,NULL,false,text("ftp://alice:$name@host.invalid"),&out,&error); CHECK(!fail_realloc_after && failures == before+1); preserved(&out,rc,error,p,parts,cause); /* URL resource BEFORE $ drop. */
    out=prior_result(); p=out.items[0].raw.data; parts=out.items[0].secret_parts; cause=out.items[0].verification_error; error=NULL; fail_part_after=1;
    rc=d->scan(d,NULL,false,text("ftp://alice:$name@host.invalid"),&out,&error); CHECK(!fail_part_after); preserved(&out,rc,error,p,parts,cause); /* Finding failure BEFORE $ drop. */
    out=prior_result(); p=out.items[0].raw.data; parts=out.items[0].secret_parts; cause=out.items[0].verification_error; error=NULL; fail_part_after=2;
    rc=d->scan(d,NULL,false,text("ftp://alice:secret@host.invalid/a\nftp://alice:secret@host.invalid/b"),&out,&error);
    CHECK(!fail_part_after); preserved(&out,rc,error,p,parts,cause);
    const char *const userquit[]={"USER alice\r\n","QUIT\r\n"}; fake_ftp f=script(TEXT("220 hi\r\n530 ordinary secret\r\n"),userquit,2);
    f.arm_close=1; f.arm_malloc=sizeof("ordinary [REDACTED]");
    out=prior_result(); p=out.items[0].raw.data; parts=out.items[0].secret_parts; cause=out.items[0].verification_error; error=NULL; before=failures;
    rc=invoke(d,uri,true,&ctx,1000000000,&f,&out,&error); CHECK(!fail_malloc_after && failures == before+1 && error && strstr(error,"sanitize FTP")); preserved(&out,rc,error,p,parts,cause); /* Setter +1 cannot become ordinary false. */
    const char *const twice[]={"USER alice\r\n","FEAT\r\n","TYPE I\r\n","QUIT\r\n","USER alice\r\n","FEAT\r\n","TYPE I\r\n","QUIT\r\n"};
    f=script(TEXT("220 hi\r\n230 yes\r\n500 none\r\n200 yes\r\n"),twice,8); f.reads[1]=f.reads[0]; f.nreads=2; f.expect_dials=f.expect_deadlines=f.expect_closes=2;
    f.arm_close=2; f.arm_realloc=4*sizeof(br_result);
    out=prior_result(); out.cap=out.len; p=out.items[0].raw.data; parts=out.items[0].secret_parts; cause=out.items[0].verification_error; error=NULL; before=failures;
    rc=invoke(d,"ftp://alice:secret@host.invalid/a\nftp://alice:secret@host.invalid/b",true,&ctx,1000000000,&f,&out,&error);
    CHECK(!fail_realloc_after && failures == before+1); preserved(&out,rc,error,p,parts,cause);
}
int main(void)
{
    const br_detector *d=descriptor(); fragment_control_regressions(d); projection(d); control_states(d); readers_writers_and_messages(d);
    captured_decoded_and_unused_credentials(d); bounded_commands_and_fragment_redaction(d);
    defaults_timeout_and_fp(d); safe_fatal_boundaries_and_cleanup(d); material_resources_and_rollback(d);
    CHECK(!fail_malloc_after && !fail_realloc_after && !fail_part_after);
    printf("FTP: %zu assertions, 0 failures; memory-only scripted FTP byte I/O; no native FTP/DNS/login, source comparisons only\n",test_assertions);
    return 0;
}
