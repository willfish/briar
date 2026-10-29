/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/ldap_private.h"
#include "../support/detector_test.h"

typedef struct { const br_scan_ctx *ctx; unsigned calls; bool active; } fixture;
static int dial_ldap(void *user, br_slice url, bool tls, bool insecure,
                      const br_scan_ctx *ctx, int64_t timeout, void **handle,
                      br_ldap_error *ordinary, char **fatal)
{
    fixture *f = user;
    CHECK(!f->active && !f->calls && ctx == f->ctx && timeout == INT64_C(5000000000));
    CHECK(url.len == 11 && !memcmp(url.data, "ldap://host", 11) && !tls && !insecure);
    ++f->calls; f->active = true; *handle = f;
    *ordinary = (br_ldap_error){0}; *fatal = NULL; return 0;
}
static int bind_ldap(void *user, void *handle, const br_scan_ctx *ctx,
                      br_slice username, br_slice password,
                      br_ldap_error *ordinary, char **fatal)
{
    fixture *f = user;
    CHECK(f->active && handle == f && f->calls == 1 && ctx == f->ctx);
    CHECK(username.len == 4 && !memcmp(username.data, "user", 4));
    CHECK(password.len == 4 && !memcmp(password.data, "pass", 4));
    ++f->calls; *ordinary = (br_ldap_error){.presence = BR_LDAP_ERR_OTHER};
    /* Empty Error() is still a real error, including when every fact is false. */
    ordinary->innermost = (br_bytes){(unsigned char *)strdup(""), 0};
    CHECK(ordinary->innermost.data != NULL);
    *fatal = NULL; return 0;
}
static int starttls_ldap(void *user, void *handle, bool insecure,
                          br_ldap_error *ordinary, char **fatal)
{
    fixture *f = user;
    CHECK(f->active && handle == f && f->calls == 2 && insecure);
    ++f->calls;
    *ordinary = (br_ldap_error){.presence = BR_LDAP_ERR_OTHER, .is_canceled = true};
    ordinary->innermost = (br_bytes){(unsigned char *)strdup("canceled"), 8};
    CHECK(ordinary->innermost.data != NULL);
    *fatal = NULL; return 1;
}
static void close_ldap(void *user, void *handle)
{
    fixture *f = user;
    CHECK(f->active && handle == f && f->calls == 3);
    ++f->calls; f->active = false;
}
static int scan(const br_detector *d, const br_scan_ctx *c, bool v, br_slice i, br_results *o, char **e)
{
    (void)d; (void)c; (void)v; (void)i; (void)o; (void)e; return 0;
}
static int matches(void *user, const br_span *groups, size_t count)
{
    (void)groups; CHECK(count > 0); ++*(unsigned *)user; return 0;
}

int main(void)
{
    char *fatal = NULL;
    br_regex *regex = NULL;
    CHECK(br_regex_compile("test", &regex, &fatal) == 0 && regex && !fatal);
    br_ldap_state base_state = {.uri = regex, .username = regex, .password = regex, .iad = regex};
    const char *keywords[] = {"ldap://", "ldaps://"};
    br_detector base = {.type = 901, .name = "LDAP", .description = "borrowed",
        .keywords = keywords, .nkeywords = 2, .max_credential_span = 1024,
        .state = &base_state, .scan = scan};
    br_scan_ctx ctx = {.deadline_monotonic_ms = 123}; fixture f = {.ctx = &ctx};
    br_ldap_io io = {.dial = dial_ldap, .bind = bind_ldap, .starttls = starttls_ldap, .close = close_ldap};
    br_ldap_binding *binding = NULL;
    CHECK(br_ldap_binding_init(&base, &io, &f, &binding, &fatal) == 0 && binding && !fatal && !f.calls);
    const br_detector *bound = br_ldap_binding_detector(binding);
    CHECK(bound && bound != &base && bound->scan == base.scan && bound->keywords == keywords);
    CHECK(bound->description == base.description && bound->max_credential_span == 1024 && bound->version == 0);
    const br_ldap_state *state = bound->state;
    CHECK(state != &base_state && state->io != &io && state->io_user == &f);
    CHECK(state->uri == regex && state->username == regex && state->password == regex && state->iad == regex);
    CHECK(!base_state.io && !base_state.io_user);
    io = (br_ldap_io){0}; /* Vtable storage is copied, not borrowed. */
    CHECK(state->io->dial == dial_ldap && state->io->bind == bind_ldap && state->io->starttls == starttls_ldap && state->io->close == close_ldap);
    void *handle = NULL; br_ldap_error ordinary = {0};
    CHECK(state->io->dial(state->io_user, (br_slice){(const unsigned char *)"ldap://host", 11}, false, false, &ctx, INT64_C(5000000000), &handle, &ordinary, &fatal) == 0 && handle && !fatal && ordinary.presence == BR_LDAP_ERR_NONE);
    CHECK(state->io->bind(state->io_user, handle, &ctx, (br_slice){(const unsigned char *)"user", 4}, (br_slice){(const unsigned char *)"pass", 4}, &ordinary, &fatal) == 0 && !fatal);
    CHECK(ordinary.presence == BR_LDAP_ERR_OTHER && ordinary.innermost.len == 0 && !ordinary.has_op_error && !ordinary.is_deadline && !ordinary.is_canceled);
    br_ldap_error_clear(&ordinary);
    CHECK(state->io->starttls(state->io_user, handle, true, &ordinary, &fatal) == 1 && !fatal && ordinary.presence == BR_LDAP_ERR_OTHER && ordinary.is_canceled);
    br_ldap_error_clear(&ordinary);
    state->io->close(state->io_user, handle);
    CHECK(!f.active && f.calls == 4);
    br_ldap_binding_destroy(binding); binding = NULL;
    br_ldap_binding_destroy(NULL);
    CHECK(!br_ldap_binding_detector(NULL) && !base_state.io && !base_state.io_user);
    unsigned count = 0;
    CHECK(br_regex_each(regex, (br_slice){(const unsigned char *)"test", 4}, matches, &count, &fatal) == 0 && count == 1 && !fatal);

    io = (br_ldap_io){.dial = dial_ldap, .bind = bind_ldap, .starttls = starttls_ldap, .close = close_ldap};
    for (unsigned invalid = 0; invalid < 9; ++invalid) {
        br_detector bad = base; br_ldap_io bad_io = io;
        switch (invalid) {
        case 0: bad.type = 10; break;
        case 1: bad.version = 1; break;
        case 2: bad.state = NULL; break;
        case 3: bad.scan = NULL; break;
        case 4: bad_io.dial = NULL; break;
        case 5: bad_io.bind = NULL; break;
        case 6: bad_io.starttls = NULL; break;
        case 7: bad_io.close = NULL; break;
        case 8: break;
        }
        CHECK(br_ldap_binding_init(invalid == 8 ? NULL : &bad, &bad_io, &f, &binding, &fatal) != 0 && !binding && fatal);
        free(fatal); fatal = NULL;
    }
    CHECK(br_ldap_binding_init(&base, NULL, &f, &binding, &fatal) != 0 && !binding && fatal);
    free(fatal); fatal = NULL;
    CHECK(br_ldap_binding_init(&base, &io, &f, NULL, &fatal) != 0 && fatal);
    free(fatal); fatal = NULL;

    ordinary = (br_ldap_error){.presence = BR_LDAP_ERR_OTHER};
    CHECK(ordinary.presence != BR_LDAP_ERR_NONE && !ordinary.innermost.data && !ordinary.innermost.len);
    br_ldap_error_clear(&ordinary);
    ordinary = (br_ldap_error){.presence = BR_LDAP_ERR_OTHER, .has_op_error = true,
        .innermost = {(unsigned char *)malloc(4), 4}};
    CHECK(ordinary.innermost.data != NULL);
    if (ordinary.innermost.data) memcpy(ordinary.innermost.data, "x\0yz", 4);
    br_ldap_error_clear(&ordinary); br_ldap_error_clear(&ordinary); br_ldap_error_clear(NULL);
    CHECK(ordinary.presence == BR_LDAP_ERR_NONE && !ordinary.has_op_error && !ordinary.is_deadline && !ordinary.is_canceled && !ordinary.innermost.data && !ordinary.innermost.len);
    br_regex_free(regex);
    return test_finish("LDAP immutable private I/O configuration, borrowed context and owned typed errors");
}
