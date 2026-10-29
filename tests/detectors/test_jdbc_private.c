/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/jdbc_private.h"
#include "../support/detector_test.h"

typedef struct { unsigned calls; bool active; const br_scan_ctx *ctx; } fixture;
static int open_db(void *user, br_jdbc_driver driver, br_slice dsn, void **db,
                   br_jdbc_error *ordinary, char **fatal)
{
    fixture *f = user; CHECK(driver == BR_JDBC_MYSQL && dsn.len == 3 && !memcmp(dsn.data, "dsn", 3));
    CHECK(!f->active && !f->calls); ++f->calls; f->active = true;
    *db = f; *ordinary = (br_jdbc_error){0}; *fatal = NULL; return 0;
}
static int ping_db(void *user, void *db, const br_scan_ctx *ctx, br_jdbc_error *ordinary, char **fatal)
{
    fixture *f = user; CHECK(db == f && f->active && f->calls == 1 && ctx == f->ctx);
    ++f->calls; *ordinary = (br_jdbc_error){0}; *fatal = NULL; return 0;
}
static int close_db(void *user, void *db, br_jdbc_error *ordinary, char **fatal)
{
    fixture *f = user; CHECK(db == f && f->active && f->calls == 2);
    ++f->calls; f->active = false; *ordinary = (br_jdbc_error){0}; *fatal = NULL; return 0;
}
static int scan(const br_detector *d, const br_scan_ctx *c, bool v, br_slice i, br_results *o, char **e)
{
    (void)d; (void)c; (void)v; (void)i; (void)o; (void)e; return 0;
}

int main(void)
{
    br_jdbc_state base_state = {0};
    br_detector base = {.type = 10, .name = "JDBC", .state = &base_state, .scan = scan};
    br_scan_ctx ctx = {.deadline_monotonic_ms = 123}; fixture f = {.ctx = &ctx};
    br_jdbc_sql_ops ops = {.open = open_db, .ping = ping_db, .close = close_db};
    br_jdbc_binding *binding = NULL; char *error = NULL;
    CHECK(br_jdbc_binding_init(&base, &ops, &f, &binding, &error) == 0 && binding && !error);
    const br_detector *bound = br_jdbc_binding_detector(binding); CHECK(bound && bound != &base && bound->scan == base.scan);
    const br_jdbc_state *state = bound->state;
    CHECK(state != &base_state && state->sql != &ops && state->sql_user == &f && !base_state.sql && !base_state.sql_user);
    ops = (br_jdbc_sql_ops){0}; /* The clone owns the vtable snapshot. */
    CHECK(state->sql->open == open_db && state->sql->ping == ping_db && state->sql->close == close_db);
    void *db = NULL; br_jdbc_error ordinary = {0};
    CHECK(state->sql->open(state->sql_user, BR_JDBC_MYSQL, (br_slice){(const unsigned char *)"dsn", 3}, &db, &ordinary, &error) == 0 && db && !error && ordinary.root == BR_JDBC_ERR_NONE);
    CHECK(state->sql->ping(state->sql_user, db, &ctx, &ordinary, &error) == 0 && !error);
    CHECK(state->sql->close(state->sql_user, db, &ordinary, &error) == 0 && !error && !f.active && f.calls == 3);
    br_jdbc_binding_destroy(binding); br_jdbc_binding_destroy(NULL);
    CHECK(!br_jdbc_binding_detector(NULL) && !base_state.sql);
    binding = NULL;
    CHECK(br_jdbc_binding_init(&base, &ops, &f, &binding, &error) != 0 && !binding && error);
    free(error); error = NULL;

    ordinary.root = BR_JDBC_ERR_PQ_POINTER;
    ordinary.outer = (br_bytes){(unsigned char *)strdup("opaque outer"), 12};
    ordinary.pq_code = (br_bytes){(unsigned char *)strdup("28P01"), 5};
    ordinary.as_mssql_value = malloc(sizeof(*ordinary.as_mssql_value));
    CHECK(ordinary.outer.data && ordinary.pq_code.data && ordinary.as_mssql_value);
    *ordinary.as_mssql_value = (br_jdbc_mssql_value){.number = 18456, .message = {(unsigned char *)strdup("typed only"), 10}};
    CHECK(ordinary.as_mssql_value->message.data);
    br_jdbc_error_clear(&ordinary); br_jdbc_error_clear(&ordinary); br_jdbc_error_clear(NULL);
    CHECK(ordinary.root == BR_JDBC_ERR_NONE && !ordinary.outer.data && !ordinary.pq_code.data && !ordinary.as_mssql_value);
    return test_finish("JDBC immutable private SQL configuration/borrowed context/owned typed errors");
}
