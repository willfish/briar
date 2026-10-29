/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/findings.h"
#include "../../src/detectors/jdbc_private.h"
#include "../support/detector_test.h"

#include <stdint.h>
#include <time.h>

int br_jdbc_init(const br_detector **out, char **error);

static const br_scan_ctx empty_ctx;

static int setter_calls;
static char *setter_cause;
static int setter_fail;
static int (*real_set_verification_error)(br_result *, const char *, const br_slice *, size_t) =
    br_result_set_verification_error;

static int observe_setter(br_result *result, const char *cause, const br_slice *secrets, size_t nsecrets)
{
    ++setter_calls;
    free(setter_cause);
    setter_cause = cause ? strdup(cause) : NULL;
    if (setter_fail) return 1;
    return real_set_verification_error(result, cause, secrets, nsecrets);
}

static int fail_host_extra;

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_host_extra && name && !strcmp(name, "host")) {
        fail_host_extra = 0;
        return 1;
    }
    return json_object_object_add_ex(object, name, value, 0);
}

#define br_result_set_verification_error observe_setter
static const char *fail_jdbc_strdup;
static char *jdbc_strdup_wrap(const char *text)
{
    if (fail_jdbc_strdup && text && !strcmp(text, fail_jdbc_strdup)) {
        fail_jdbc_strdup = NULL;
        return NULL;
    }
    return strdup(text);
}
#define strdup jdbc_strdup_wrap
#include "../../src/detectors/jdbc.c"
#undef strdup
#undef br_result_set_verification_error

static br_jdbc_binding *binding;

typedef struct {
    int open_rc, ping_rc, close_rc;
    br_jdbc_error_root open_root, ping_root;
    uint16_t open_mysql, mysql_number;
    const char *open_pq, *pq;
    bool mssql;
    int32_t mssql_number;
    const char *mssql_message;
    const char *open_outer, *ping_outer, *close_outer;
    const char *open_fatal, *ping_fatal, *close_fatal;
    const unsigned char *ping_raw;
    size_t ping_raw_len;
    bool close_status_only;
} jdbc_step;

typedef struct {
    jdbc_step steps[3];
    int nsteps, opens, pings, closes;
    br_jdbc_driver drivers[3];
    char dsn[3][768];
    size_t dsn_len[3];
    const br_scan_ctx *child;
    int64_t deadline;
    bool (*cancelled)(void *);
    void *cancel_user;
    bool close_saw_ping;
    int phase;
    void *tokens[3];
} jdbc_script;

static int own_text(const char *text, br_bytes *out)
{
    *out = (br_bytes){0};
    if (!text) return 0;
    size_t n = strlen(text);
    if (!(out->data = malloc(n + 1))) return -1;
    memcpy(out->data, text, n + 1);
    out->len = n;
    return 0;
}

static int fill_error(br_jdbc_error *dst, br_jdbc_error_root root, const char *outer,
                      uint16_t mysql, const char *pq, bool mssql, int32_t number,
                      const char *message, char **fatal)
{
    *dst = (br_jdbc_error){0};
    dst->root = root;
    dst->mysql_number = mysql;
    if (own_text(outer, &dst->outer) != 0 || (pq && own_text(pq, &dst->pq_code) != 0)) goto oom;
    if (mssql) {
        if (!(dst->as_mssql_value = calloc(1, sizeof(*dst->as_mssql_value))) ||
            own_text(message ? message : "", &dst->as_mssql_value->message) != 0)
            goto oom;
        dst->as_mssql_value->number = number;
    }
    return 0;
oom:
    br_jdbc_error_clear(dst);
    *fatal = strdup("cannot own synthetic JDBC error");
    return -1;
}

static int script_open(void *user, br_jdbc_driver driver, br_slice dsn, void **db,
                       br_jdbc_error *ordinary, char **fatal)
{
    jdbc_script *script = user;
    int i = script->opens++;
    if (i >= script->nsteps || i >= 3) {
        *fatal = strdup("unexpected JDBC open");
        return -1;
    }
    script->drivers[i] = driver;
    script->dsn_len[i] = dsn.len < sizeof(script->dsn[i]) - 1 ? dsn.len : sizeof(script->dsn[i]) - 1;
    if (script->dsn_len[i] && dsn.data) memcpy(script->dsn[i], dsn.data, script->dsn_len[i]);
    script->dsn[i][script->dsn_len[i]] = 0;
    jdbc_step *step = &script->steps[i];
    if (step->open_rc) {
        *fatal = strdup(step->open_fatal ? step->open_fatal : "open fatal");
        return -1;
    }
    if (fill_error(ordinary, step->open_root, step->open_outer, step->open_mysql, step->open_pq,
                   false, 0, NULL, fatal) != 0)
        return -1;
    if (ordinary->root == BR_JDBC_ERR_NONE) {
        script->tokens[i] = (void *)(uintptr_t)(0x4100 + i);
        *db = script->tokens[i];
    }
    return 0;
}

static int script_ping(void *user, void *db, const br_scan_ctx *child, br_jdbc_error *ordinary, char **fatal)
{
    jdbc_script *script = user;
    int i = script->pings++;
    script->child = child;
    script->deadline = child ? child->deadline_monotonic_ms : 0;
    script->cancelled = child ? child->cancelled : NULL;
    script->cancel_user = child ? child->cancel_user : NULL;
    script->phase = 1;
    if (i >= script->nsteps || db != script->tokens[i]) {
        *fatal = strdup("unexpected JDBC ping");
        return -1;
    }
    jdbc_step *step = &script->steps[i];
    if (step->ping_rc) {
        *fatal = strdup(step->ping_fatal ? step->ping_fatal : "ping fatal");
        return -1;
    }
    if (step->ping_raw) {
        *ordinary = (br_jdbc_error){.root = step->ping_root ? step->ping_root : BR_JDBC_ERR_OTHER};
        ordinary->mysql_number = step->mysql_number;
        if (step->ping_raw_len && !(ordinary->outer.data = malloc(step->ping_raw_len))) {
            *fatal = strdup("cannot own synthetic JDBC error");
            return -1;
        }
        if (step->ping_raw_len) memcpy(ordinary->outer.data, step->ping_raw, step->ping_raw_len);
        ordinary->outer.len = step->ping_raw_len;
        return 0;
    }
    return fill_error(ordinary, step->ping_root, step->ping_outer, step->mysql_number, step->pq,
                      step->mssql, step->mssql_number, step->mssql_message, fatal);
}

static int script_close(void *user, void *db, br_jdbc_error *ordinary, char **fatal)
{
    jdbc_script *script = user;
    int i = script->closes++;
    if (script->phase == 1) script->close_saw_ping = true;
    script->phase = 2;
    if (i >= script->nsteps || db != script->tokens[i]) {
        *fatal = strdup("unexpected JDBC close");
        return -1;
    }
    jdbc_step *step = &script->steps[i];
    if (step->close_rc) {
        if (!step->close_status_only)
            *fatal = strdup(step->close_fatal ? step->close_fatal : "close fatal");
        return step->close_rc;
    }
    br_jdbc_error_root root = step->close_outer ? BR_JDBC_ERR_OTHER : BR_JDBC_ERR_NONE;
    return fill_error(ordinary, root, step->close_outer, 0, NULL, false, 0, NULL, fatal);
}

static const br_jdbc_sql_ops sql_ops = {script_open, script_ping, script_close};

static const br_detector *bind_script(const br_detector *base, jdbc_script *script)
{
    br_jdbc_binding_destroy(binding);
    binding = NULL;
    char *error = NULL;
    CHECK(br_jdbc_binding_init(base, &sql_ops, script, &binding, &error) == 0 && binding && !error);
    const br_detector *bound = br_jdbc_binding_detector(binding);
    CHECK(bound && ((const br_jdbc_state *)bound->state)->sql);
    CHECK(((const br_jdbc_state *)base->state)->sql == NULL);
    return bound;
}

static br_results caller_results(void)
{
    br_results results = {0};
    br_result kept = {0};
    CHECK(br_finding_key(&kept, 1, "caller", "kept") == 0);
    CHECK(br_results_push(&results, &kept) == 0);
    return results;
}

static void expect_caller_only(const br_results *results)
{
    CHECK(results->len == 1);
    CHECK(results->items[0].raw.len == 6 && !memcmp(results->items[0].raw.data, "caller", 6));
}

static const char *extra_get(const br_result *result, const char *key)
{
    struct json_object *value = NULL;
    if (!result->extra_data || !json_object_object_get_ex(result->extra_data, key, &value)) return NULL;
    return json_object_get_string(value);
}

static void expect_raw(const br_result *result, const char *raw)
{
    CHECK(result->detector_type == 10);
    CHECK(result->raw.len == strlen(raw) && !memcmp(result->raw.data, raw, result->raw.len));
    CHECK(!result->raw_v2.data && !result->detector_name);
    struct json_object *part = NULL;
    CHECK(result->secret_parts && json_object_object_get_ex(result->secret_parts, "connection_string", &part));
    CHECK(json_object_get_string_len(part) == (int)strlen(raw) && !strcmp(json_object_get_string(part), raw));
    struct json_object *password = NULL;
    CHECK(!result->extra_data || !json_object_object_get_ex(result->extra_data, "password", &password));
}

static void expect_match(const br_detector *detector, const char *input, const char *const *want, size_t n)
{
    br_results results = test_scan(detector, &empty_ctx, false, input, strlen(input));
    CHECK(results.len == n);
    for (size_t i = 0; i < n; ++i) expect_raw(&results.items[i], want[i]);
    br_results_clear(&results);
}

static int cancel_token;

static bool cancelled_probe(void *user)
{
    return user == &cancel_token;
}

static void reset_setter(void)
{
    setter_calls = 0;
    setter_fail = 0;
    free(setter_cause);
    setter_cause = NULL;
}

static int scan_of(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                   const char *input, br_results *results, char **error)
{
    return detector->scan(detector, ctx, verify, (br_slice){(const unsigned char *)input, strlen(input)},
                          results, error);
}

static void test_identity(const br_detector *detector)
{
    char *error = NULL;
    CHECK(br_jdbc_init(NULL, &error) != 0 && error && !strcmp(error, "invalid JDBC detector output"));
    free(error);
    const br_detector *again = NULL;
    CHECK(br_jdbc_init(&again, &error) == 0 && again == detector && !error);
    CHECK(detector->type == 10 && detector->version == 0 && !strcmp(detector->name, "JDBC"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "jdbc"));
    CHECK(!strcmp(detector->description,
                  "JDBC (Java Database Connectivity) is an API for connecting and executing queries with databases. "
                  "JDBC connection strings can be used to access and manipulate databases."));
    CHECK(detector->max_credential_span == 1024 && detector->max_secret_size == -1 && detector->start_offset == -1);
    CHECK(detector->custom_name && !detector->custom_name[0] && detector->false_positive && !detector->clean);
    br_result example = {.raw = {(unsigned char *)"jdbc:sqlite:/data/example.db", 28}};
    char *reason = NULL;
    CHECK(!detector->false_positive(detector, &example, &reason) && reason && !reason[0]);
    free(reason);
    CHECK(!detector->false_positive(detector, &example, NULL));
    const br_jdbc_state *state = detector->state;
    CHECK(state && state->regex && state->redact && !state->sql && !state->sql_user);
}

static void test_patterns(const br_detector *detector)
{
    static const char *valid[] = {
        "jdbc:postgresql://localhost:5432/postgres",
        "jdbc:mysql:localhost:3306/mydatabase",
        "jdbc:sqlserver://x.x.x.x:1433;databaseName=MY-DB;user=MY-USER;password=MY-PASSWORD;encrypt=false",
        "jdbc:sqlserver://localhost:1433;databaseName=AdventureWorks",
        "jdbc:mysql://testuser:testpassword@tcp(localhost:1521)/testdb",
        "jdbc:postgresql://localhost:1521/testdb?sslmode=disable&password=testpassword&user=testuser",
    };
    expect_match(detector,
                 "<?xml version=\"1.0\"?>\n"
                 "<jdbc-url>jdbc:postgresql://localhost:5432/postgres</jdbc-url>\n"
                 "<jdbc-url>jdbc:sqlserver:</jdbc-url>\n"
                 "<jdbc-url>jdbc:postgresql://#{uri.host}#{uri.path}?user=#{uri.user}</jdbc-url>\n"
                 "<jdbc-url>postgresql://postgres:postgres@<your-connection-ip-address>:5432</jdbc-url>\n"
                 "<jdbc-url>jdbc:mysql:localhost:3306/mydatabase</jdbc-url>\n"
                 "<jdbc-url>jdbc:sqlserver://x.x.x.x:1433;databaseName=MY-DB;user=MY-USER;password=MY-PASSWORD;encrypt=false</jdbc-url>\n"
                 "<jdbc-url>jdbc:sqlserver://localhost:1433;databaseName=AdventureWorks</jdbc-url>\n"
                 "<jdbc-url>(jdbc:mysql://testuser:testpassword@tcp(localhost:1521)/testdb)</jdbc-url>\n"
                 "<jdbc-url>jdbc:postgresql://localhost:1521/testdb?sslmode=disable&password=testpassword&user=testuser&</jdbc-url>\n",
                 valid, sizeof(valid) / sizeof(valid[0]));
    static const char *more[] = {
        "jdbc:postgresql://localhost:5432/mydb",
        "jdbc:mysql://user:pass@host:3306/db?param=1",
        "jdbc:sqlite:/data/test.db",
        "jdbc:oracle:thin:@host:1521:db",
        "jdbc:mysql://host:3306/db",
        "jdbc:db2://host:50000/db?param=1",
        "jdbc:postgresql://localhost:1521/testdb?sslmode=disable&password=testpassword&user=testuser",
        "jdbc:mysql://testuser:testpassword@tcp(localhost:1521)/testdb",
    };
    expect_match(detector,
                 "jdbc:postgresql://localhost:5432/mydb "
                 "jdbc:mysql://user:pass@host:3306/db?param=1 "
                 "jdbc:sqlite:/data/test.db "
                 "jdbc:oracle:thin:@host:1521:db "
                 "jdbc:mysql://host:3306/db,other_param "
                 "jdbc:db2://host:50000/db?param=1 "
                 "jdbc:postgresql://localhost:1521/testdb?sslmode=disable&password=testpassword&user=testuser "
                 "jdbc:mysql://testuser:testpassword@tcp(localhost:1521)/testdb",
                 more, sizeof(more) / sizeof(more[0]));
    static const char *hive[] = {
        "jdbc:hive9://foo.example.com:10191/default;user=MyRoleUser;password=MyPa$$w0rd...",
    };
    expect_match(detector, hive[0], hive, 1);
    expect_match(detector,
                 "jdbc:xyz:short somejdbc:mysql://host/db jdbc:invalid_driver:test "
                 "jdbc:mysql://host/db>next adjdbc:mysql://host/db "
                 "jdbc:my?ql:localhost:3306/my database",
                 NULL, 0);
    static const char *vt[] = {"jdbc:mysql://local\vhost:3306/abcd"};
    expect_match(detector, vt[0], vt, 1);
    expect_match(detector, "jdbc:mysql://local\fhost:3306/abcd", NULL, 0);
}

static void test_redaction(const br_detector *detector)
{
    struct { const char *input, *redacted; } cases[] = {
        {"jdbc:mysql://root:keepme@localhost:3306/db?password=hide&user=root",
         "jdbc:mysql://root:keepme@localhost:3306/db?password=****&user=root"},
        {"jdbc:mysql://localhost:3306/db?PassWord=ab",
         "jdbc:mysql://localhost:3306/db?PassWord=**"},
        {"jdbc:mysql://localhost:3306/db?password&user=abcdef",
         "jdbc:mysql://localhost:3306/db?password=&user=abcdef"},
        {"jdbc:mysql://localhost:3306/db?password=caf\xc3\xa9",
         "jdbc:mysql://localhost:3306/db?password=*****"},
        {"jdbc:sqlserver://localhost:1433;password=Pass123;user=sa",
         "jdbc:sqlserver://localhost:1433;password=*******;user=sa"},
        {"jdbc:mysql://root:visible@localhost/db;password=hide",
         "jdbc:mysql://root:visible@localhost/db;password=****"},
        {"jdbc:mysql://root:password@localhost:3306/testdb",
         "jdbc:mysql://root:********@localhost:3306/testdb"},
        {"jdbc:mysql://localhost@dbhost:3306/xxxx",
         "jdbc:mysql:***********@dbhost:3306/xxxx"},
        {"jdbc:customdb:password=supersecret",
         "jdbc:customdb:password=***********"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        br_results results = test_scan(detector, &empty_ctx, false, cases[i].input, strlen(cases[i].input));
        CHECK(results.len == 1);
        expect_raw(&results.items[0], cases[i].input);
        CHECK(results.items[0].redacted && !strcmp(results.items[0].redacted, cases[i].redacted));
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
        br_results_clear(&results);
    }
}

static void test_metadata(const br_detector *detector)
{
    struct { const char *input, *host, *user, *database; } cases[] = {
        {"jdbc:mysql://root:password@localhost:3306/testdb", "tcp(localhost:3306)", "root", "testdb"},
        {"jdbc:postgresql://postgres:secret@dbhost:5432/mydb", "dbhost:5432", "postgres", "mydb"},
        {"jdbc:sqlserver://server.example.com:1433;database=testdb;user=sa;password=Pass123",
         "server.example.com:1433", "sa", "testdb"},
        {"jdbc:mysql://dbhost:3307/testdb?user=admin&password=secret", "tcp(dbhost:3307)", "admin", "testdb"},
        {"jdbc:postgresql://localhost:1521/testdb?sslmode=disable&password=testpassword&user=testuser",
         "localhost:1521", "testuser", "testdb"},
        {"JDBC:MySQL://root:password@localhost:3306/testdb", "tcp(localhost:3306)", "root", "testdb"},
        {"jdbc:postgresql://user:pass@dbhost:5433", "dbhost:5433", "user", "postgres"},
        {"jdbc:sqlserver://localhost:1433;password=mypass", "localhost:1433", "sa", "master"},
        {"jdbc:sqlserver://server.example.com:1434;databaseName=mydb;userId=admin;pwd=admin123",
         "server.example.com:1434", "admin", "mydb"},
        {"jdbc:sqlserver://odbc:server=localhost;port=1433;database=testdb;password=testpassword",
         "localhost:1433", "sa", "testdb"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        br_results results = test_scan(detector, &empty_ctx, false, cases[i].input, strlen(cases[i].input));
        CHECK(results.len == 1);
        expect_raw(&results.items[0], cases[i].input);
        CHECK(extra_get(&results.items[0], "host") && !strcmp(extra_get(&results.items[0], "host"), cases[i].host));
        CHECK(extra_get(&results.items[0], "username") &&
              !strcmp(extra_get(&results.items[0], "username"), cases[i].user));
        CHECK(extra_get(&results.items[0], "database") &&
              !strcmp(extra_get(&results.items[0], "database"), cases[i].database));
        CHECK(json_object_object_length(results.items[0].extra_data) == 3);
        br_results_clear(&results);
    }
    const char *sqlite = "jdbc:sqlite:/data/test.db";
    br_results results = test_scan(detector, &empty_ctx, false, sqlite, strlen(sqlite));
    CHECK(results.len == 1 && !results.items[0].extra_data);
    expect_raw(&results.items[0], sqlite);
    br_results_clear(&results);

    const char *no_fallback = "jdbc:mysql://tcp(localhost:3306)/dbname?password=fromquery";
    results = test_scan(detector, &empty_ctx, false, no_fallback, strlen(no_fallback));
    CHECK(results.len == 1 && !results.items[0].extra_data);
    br_results_clear(&results);

    const char *missing = "jdbc:sqlserver://examplehost.net;databaseName=QRG1;sendStringParametersAsUnicode=false";
    results = test_scan(detector, &empty_ctx, false, missing, strlen(missing));
    CHECK(results.len == 1 && !results.items[0].extra_data);
    expect_raw(&results.items[0], missing);
    br_results_clear(&results);

    const char *both = "jdbc:sqlite:/data/test.db jdbc:postgresql://postgres:secret@dbhost:5432/mydb";
    results = test_scan(detector, &empty_ctx, false, both, strlen(both));
    CHECK(results.len == 2 && !results.items[0].extra_data);
    CHECK(extra_get(&results.items[1], "host") && !strcmp(extra_get(&results.items[1], "host"), "dbhost:5432"));
    br_results_clear(&results);
}

static void test_verify_policy(const br_detector *detector)
{
    const char *mysql = "jdbc:mysql://myuser:mypass@tcp(localhost:3307)/mydb";
    br_results results = caller_results();
    char *error = NULL;
    br_scan_ctx ctx = {0};
    CHECK(scan_of(detector, &ctx, true, mysql, &results, &error) != 0);
    CHECK(error && !strcmp(error, "unsupported: JDBC verification without injected SQL ops"));
    expect_caller_only(&results);
    free(error);
    error = NULL;
    br_results_clear(&results);
    results = caller_results();
    CHECK(scan_of(detector, &ctx, true, "", &results, &error) == 0 && !error);
    expect_caller_only(&results);
    br_results_clear(&results);
    results = caller_results();
    CHECK(scan_of(detector, &ctx, true, "jdbc:sqlite:/data/test.db", &results, &error) == 0 && !error);
    expect_caller_only(&results);
    br_results_clear(&results);
    fail_host_extra = 1;
    results = caller_results();
    CHECK(scan_of(detector, &ctx, true, mysql, &results, &error) != 0);
    CHECK(error && !strcmp(error, "cannot create JDBC finding"));
    expect_caller_only(&results);
    free(error);
    error = NULL;
    br_results_clear(&results);

    results = test_scan(detector, &empty_ctx, false, mysql, strlen(mysql));
    CHECK(results.len == 1 && extra_get(&results.items[0], "database") &&
          !strcmp(extra_get(&results.items[0], "database"), "mydb"));
    br_results_clear(&results);

    jdbc_script script = {0};
    script.nsteps = 1;
    const br_detector *bound = bind_script(detector, &script);
    reset_setter();
    results = caller_results();
    error = NULL;
    CHECK(scan_of(bound, &ctx, false, mysql, &results, &error) == 0 && !error);
    CHECK(results.len == 2 && script.opens == 0 && setter_calls == 0);
    br_results_clear(&results);

    script = (jdbc_script){.nsteps = 1};
    bound = bind_script(detector, &script);
    reset_setter();
    results = caller_results();
    CHECK(scan_of(bound, &ctx, true, "jdbc:sqlite:/data/test.db", &results, &error) == 0 && !error);
    expect_caller_only(&results);
    CHECK(script.opens == 0 && setter_calls == 0);
    br_results_clear(&results);

    script = (jdbc_script){.nsteps = 1};
    bound = bind_script(detector, &script);
    reset_setter();
    results = caller_results();
    CHECK(scan_of(bound, NULL, false, "", &results, &error) != 0);
    CHECK(error && !strcmp(error, "unsupported upstream panic: JDBC nil context"));
    expect_caller_only(&results);
    CHECK(script.opens == 0 && setter_calls == 0);
    free(error);
    br_results_clear(&results);

    script = (jdbc_script){.nsteps = 1};
    bound = bind_script(detector, &script);
    reset_setter();
    results = caller_results();
    error = NULL;
    CHECK(scan_of(bound, NULL, false, mysql, &results, &error) != 0);
    CHECK(error && !strcmp(error, "unsupported upstream panic: JDBC nil context"));
    expect_caller_only(&results);
    CHECK(script.opens == 0 && setter_calls == 0);
    free(error);
    br_results_clear(&results);

    script = (jdbc_script){.nsteps = 1};
    bound = bind_script(detector, &script);
    reset_setter();
    results = caller_results();
    error = NULL;
    CHECK(scan_of(bound, NULL, true, "", &results, &error) != 0);
    CHECK(error && !strcmp(error, "unsupported upstream panic: JDBC nil context"));
    expect_caller_only(&results);
    CHECK(script.opens == 0 && setter_calls == 0);
    free(error);
    br_results_clear(&results);

    script = (jdbc_script){.nsteps = 1};
    bound = bind_script(detector, &script);
    reset_setter();
    results = caller_results();
    error = NULL;
    CHECK(scan_of(bound, NULL, true, "jdbc:sqlite:/data/test.db", &results, &error) != 0);
    CHECK(error && !strcmp(error, "unsupported upstream panic: JDBC nil context"));
    expect_caller_only(&results);
    CHECK(script.opens == 0 && setter_calls == 0);
    free(error);
    br_results_clear(&results);

    script = (jdbc_script){.nsteps = 1};
    bound = bind_script(detector, &script);
    reset_setter();
    results = caller_results();
    error = NULL;
    CHECK(scan_of(bound, NULL, true, mysql, &results, &error) != 0);
    CHECK(error && !strcmp(error, "unsupported upstream panic: JDBC nil context"));
    expect_caller_only(&results);
    CHECK(script.opens == 0 && setter_calls == 0);
    free(error);
    br_results_clear(&results);

    results = caller_results();
    error = NULL;
    CHECK(scan_of(detector, &empty_ctx, false, mysql, &results, &error) == 0 && !error);
    CHECK(results.len == 2);
    br_results_clear(&results);

    results = caller_results();
    error = NULL;
    CHECK(scan_of(detector, &ctx, false, "jdbc:mysql://user:pass@tcp(localhost:3306)/db?strict=1",
                  &results, &error) != 0);
    CHECK(error && !strcmp(error, "unsupported: MySQL removed strict-mode panic boundary"));
    expect_caller_only(&results);
    free(error);
    br_results_clear(&results);

    fail_host_extra = 1;
    results = caller_results();
    error = NULL;
    CHECK(scan_of(detector, &ctx, false, mysql, &results, &error) != 0);
    CHECK(error && !strcmp(error, "cannot create JDBC finding"));
    expect_caller_only(&results);
    free(error);
    br_results_clear(&results);
}

static void expect_deadline(const jdbc_script *script, int64_t parent)
{
    if (parent) CHECK(script->deadline == parent);
    else {
        struct timespec now;
        CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
        int64_t current = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
        int64_t delta = script->deadline - current;
        CHECK(delta <= 5000 && delta >= 4000);
    }
    CHECK(script->cancelled == cancelled_probe && script->cancel_user == &cancel_token);
}

static void test_injected(const br_detector *detector)
{
    const char *mysql = "jdbc:mysql://myuser:mypass@tcp(localhost:3307)/mydb";
    br_scan_ctx ctx = {.cancelled = cancelled_probe, .cancel_user = &cancel_token};
    jdbc_script script = {.nsteps = 1};
    const br_detector *bound = bind_script(detector, &script);
    reset_setter();
    br_results results = caller_results();
    char *error = NULL;
    CHECK(scan_of(bound, &ctx, true, mysql, &results, &error) == 0 && !error);
    CHECK(results.len == 2 && results.items[1].verified && !results.items[1].verification_error);
    CHECK(setter_calls == 0 && script.opens == 1 && script.pings == 1 && script.closes == 1);
    CHECK(script.close_saw_ping && script.drivers[0] == BR_JDBC_MYSQL);
    CHECK(script.dsn_len[0] && !strcmp(script.dsn[0], "myuser:mypass@tcp(localhost:3307)/?timeout=5s"));
    expect_deadline(&script, 0);
    br_results_clear(&results);

    ctx.deadline_monotonic_ms = 1;
    script = (jdbc_script){.nsteps = 1};
    bound = bind_script(detector, &script);
    results = (br_results){0};
    CHECK(scan_of(bound, &ctx, true, mysql, &results, &error) == 0 && !error && results.items[0].verified);
    expect_deadline(&script, 1);
    br_results_clear(&results);
    ctx.deadline_monotonic_ms = 0;

    script = (jdbc_script){.nsteps = 1};
    script.steps[0].ping_root = BR_JDBC_ERR_MYSQL_POINTER;
    script.steps[0].mysql_number = 1045;
    script.steps[0].ping_outer = "access denied";
    bound = bind_script(detector, &script);
    reset_setter();
    results = caller_results();
    CHECK(scan_of(bound, &ctx, true, mysql, &results, &error) == 0 && !error);
    CHECK(results.len == 2 && !results.items[1].verified && !results.items[1].verification_error);
    CHECK(setter_calls == 0 && script.closes == 1);
    br_results_clear(&results);

    script = (jdbc_script){.nsteps = 1};
    script.steps[0].ping_root = BR_JDBC_ERR_MYSQL_POINTER;
    script.steps[0].mysql_number = 1044;
    script.steps[0].ping_outer = "failed for jdbc:mysql://myuser:mypass@tcp(localhost:3307)/mydb now";
    bound = bind_script(detector, &script);
    reset_setter();
    results = (br_results){0};
    CHECK(scan_of(bound, &ctx, true, mysql, &results, &error) == 0 && !error);
    CHECK(results.len == 1 && !results.items[0].verified);
    CHECK(setter_calls == 1 && setter_cause && !strcmp(setter_cause, script.steps[0].ping_outer));
    CHECK(results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "failed for [REDACTED] now"));
    br_results_clear(&results);

    script = (jdbc_script){.nsteps = 1};
    script.steps[0].open_root = BR_JDBC_ERR_OTHER;
    script.steps[0].open_outer = "open refused";
    bound = bind_script(detector, &script);
    reset_setter();
    results = (br_results){0};
    CHECK(scan_of(bound, &ctx, true, mysql, &results, &error) == 0 && !error);
    CHECK(script.opens == 1 && script.pings == 0 && script.closes == 0);
    CHECK(setter_calls == 1 && setter_cause && !strcmp(setter_cause, "open refused"));
    br_results_clear(&results);

    script = (jdbc_script){.nsteps = 1};
    script.steps[0].open_rc = -1;
    script.steps[0].open_fatal = "open exploded";
    bound = bind_script(detector, &script);
    reset_setter();
    results = caller_results();
    CHECK(scan_of(bound, &ctx, true, mysql, &results, &error) != 0);
    CHECK(error && !strcmp(error, "open exploded"));
    expect_caller_only(&results);
    CHECK(script.pings == 0 && script.closes == 0 && setter_calls == 0);
    free(error);
    error = NULL;
    br_results_clear(&results);

    script = (jdbc_script){.nsteps = 1};
    script.steps[0].ping_rc = -1;
    script.steps[0].ping_fatal = "ping exploded";
    script.steps[0].close_rc = -1;
    script.steps[0].close_fatal = "close exploded";
    bound = bind_script(detector, &script);
    results = caller_results();
    CHECK(scan_of(bound, &ctx, true, mysql, &results, &error) != 0);
    CHECK(error && !strcmp(error, "ping exploded"));
    expect_caller_only(&results);
    CHECK(script.closes == 1 && script.close_saw_ping && setter_calls == 0);
    free(error);
    error = NULL;
    br_results_clear(&results);

    script = (jdbc_script){.nsteps = 1};
    script.steps[0].close_outer = "close ignored";
    bound = bind_script(detector, &script);
    reset_setter();
    results = (br_results){0};
    CHECK(scan_of(bound, &ctx, true, mysql, &results, &error) == 0 && !error);
    CHECK(results.items[0].verified && !results.items[0].verification_error && setter_calls == 0);
    br_results_clear(&results);

    script = (jdbc_script){.nsteps = 1};
    script.steps[0].close_rc = -1;
    script.steps[0].close_fatal = "close exploded";
    bound = bind_script(detector, &script);
    results = caller_results();
    CHECK(scan_of(bound, &ctx, true, mysql, &results, &error) != 0);
    CHECK(error && !strcmp(error, "close exploded"));
    expect_caller_only(&results);
    free(error);
    error = NULL;
    br_results_clear(&results);

    script = (jdbc_script){.nsteps = 1};
    script.steps[0].close_rc = 1;
    script.steps[0].close_status_only = true;
    bound = bind_script(detector, &script);
    fail_jdbc_strdup = "unsupported: JDBC SQL close failed";
    results = caller_results();
    CHECK(scan_of(bound, &ctx, true, mysql, &results, &error) != 0);
    CHECK(error && !strcmp(error, "cannot copy JDBC SQL error"));
    expect_caller_only(&results);
    CHECK(script.opens == 1 && script.pings == 1 && script.closes == 1 && setter_calls == 0);
    free(error);
    error = NULL;
    br_results_clear(&results);
    fail_jdbc_strdup = NULL;

    static const unsigned char nul_diag[] = {'a', 0, 'b'};
    script = (jdbc_script){.nsteps = 1};
    script.steps[0].ping_root = BR_JDBC_ERR_OTHER;
    script.steps[0].ping_raw = nul_diag;
    script.steps[0].ping_raw_len = 3;
    bound = bind_script(detector, &script);
    results = caller_results();
    CHECK(scan_of(bound, &ctx, true, mysql, &results, &error) != 0);
    CHECK(error && !strcmp(error, "unsupported: JDBC SQL error contains NUL"));
    expect_caller_only(&results);
    CHECK(script.closes == 1 && setter_calls == 0);
    free(error);
    error = NULL;
    br_results_clear(&results);

    script = (jdbc_script){.nsteps = 1};
    script.steps[0].ping_root = BR_JDBC_ERR_MYSQL_POINTER;
    script.steps[0].mysql_number = 1045;
    script.steps[0].ping_raw = nul_diag;
    script.steps[0].ping_raw_len = 3;
    bound = bind_script(detector, &script);
    reset_setter();
    results = (br_results){0};
    CHECK(scan_of(bound, &ctx, true, mysql, &results, &error) == 0 && !error);
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    CHECK(setter_calls == 0 && script.closes == 1);
    br_results_clear(&results);

    script = (jdbc_script){.nsteps = 1};
    script.steps[0].ping_root = BR_JDBC_ERR_OTHER;
    script.steps[0].ping_outer = "";
    bound = bind_script(detector, &script);
    reset_setter();
    results = (br_results){0};
    CHECK(scan_of(bound, &ctx, true, mysql, &results, &error) == 0 && !error);
    CHECK(results.len == 1 && !results.items[0].verified && setter_calls == 1);
    br_results_clear(&results);

    script = (jdbc_script){.nsteps = 1};
    script.steps[0].ping_root = BR_JDBC_ERR_OTHER;
    script.steps[0].ping_outer = "indeterminate";
    bound = bind_script(detector, &script);
    setter_fail = 1;
    setter_calls = 0;
    results = caller_results();
    CHECK(scan_of(bound, &ctx, true, mysql, &results, &error) != 0);
    CHECK(error && !strcmp(error, "cannot set JDBC verification error"));
    expect_caller_only(&results);
    CHECK(setter_calls == 1 && script.closes == 1);
    free(error);
    error = NULL;
    br_results_clear(&results);

    const char *postgres = "jdbc:postgresql://dbuser:dbpass@dbhost:5432/mydb?sslmode=require";
    script = (jdbc_script){.nsteps = 2};
    script.steps[0].ping_root = BR_JDBC_ERR_PQ_POINTER;
    script.steps[0].pq = "3D000";
    script.steps[0].ping_outer = "db missing";
    bound = bind_script(detector, &script);
    reset_setter();
    results = (br_results){0};
    CHECK(scan_of(bound, &ctx, true, postgres, &results, &error) == 0 && !error);
    CHECK(results.items[0].verified && setter_calls == 0 && script.opens == 2 && script.closes == 2);
    CHECK(strstr(script.dsn[0], "user=dbuser") && strstr(script.dsn[0], "password=dbpass"));
    CHECK(strstr(script.dsn[0], "host=dbhost") && strstr(script.dsn[0], "port=5432"));
    CHECK(strstr(script.dsn[0], "connect_timeout=5") && strstr(script.dsn[0], "sslmode=require"));
    CHECK(strstr(script.dsn[0], "dbname=postgres") && !strstr(script.dsn[0], "dbname=mydb"));
    CHECK(!strstr(script.dsn[1], "dbname="));
    CHECK(script.drivers[0] == BR_JDBC_POSTGRES && script.drivers[1] == BR_JDBC_POSTGRES);
    br_results_clear(&results);

    script = (jdbc_script){.nsteps = 2};
    script.steps[0].ping_root = BR_JDBC_ERR_PQ_POINTER;
    script.steps[0].pq = "28P01";
    script.steps[0].ping_outer = "bad password";
    script.steps[1].ping_root = BR_JDBC_ERR_OTHER;
    script.steps[1].ping_outer = "should not run";
    bound = bind_script(detector, &script);
    reset_setter();
    results = (br_results){0};
    CHECK(scan_of(bound, &ctx, true, postgres, &results, &error) == 0 && !error);
    CHECK(!results.items[0].verified && !results.items[0].verification_error && setter_calls == 0);
    CHECK(script.opens == 1 && script.pings == 1);
    br_results_clear(&results);

    const char *bad_ssl = "jdbc:postgresql://dbuser:dbpass@dbhost:5432/mydb?sslmode=Require";
    script = (jdbc_script){.nsteps = 1};
    script.steps[0].ping_root = BR_JDBC_ERR_PQ_POINTER;
    script.steps[0].pq = "28P01";
    bound = bind_script(detector, &script);
    results = (br_results){0};
    CHECK(scan_of(bound, &ctx, true, bad_ssl, &results, &error) == 0 && !error);
    CHECK(!strstr(script.dsn[0], "sslmode="));
    br_results_clear(&results);

    script = (jdbc_script){.nsteps = 2};
    script.steps[0].ping_root = BR_JDBC_ERR_PQ_POINTER;
    script.steps[0].pq = "3D000";
    script.steps[0].ping_outer = "db missing";
    script.steps[1].ping_root = BR_JDBC_ERR_PQ_POINTER;
    script.steps[1].pq = "3F000";
    script.steps[1].ping_outer = "schema missing";
    bound = bind_script(detector, &script);
    reset_setter();
    results = (br_results){0};
    CHECK(scan_of(bound, &ctx, true, postgres, &results, &error) == 0 && !error);
    CHECK(!results.items[0].verified && setter_calls == 1);
    CHECK(setter_cause && !strcmp(setter_cause, "db missing\nschema missing"));
    CHECK(results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "db missing\nschema missing"));
    br_results_clear(&results);

    const char *mssql = "jdbc:sqlserver://localhost:1433;database=testdb;user=sa;password=Pass123;encrypt=false";
    script = (jdbc_script){.nsteps = 1};
    bound = bind_script(detector, &script);
    reset_setter();
    results = (br_results){0};
    CHECK(scan_of(bound, &ctx, true, mssql, &results, &error) == 0 && !error);
    CHECK(results.items[0].verified && script.drivers[0] == BR_JDBC_MSSQL);
    CHECK(!strcmp(script.dsn[0], "sqlserver://sa:Pass123@localhost:1433?database=master&connection+timeout=5"));
    CHECK(!strstr(script.dsn[0], "encrypt") && !strstr(script.dsn[0], "testdb"));
    CHECK(extra_get(&results.items[0], "database") && !strcmp(extra_get(&results.items[0], "database"), "testdb"));
    br_results_clear(&results);

    script = (jdbc_script){.nsteps = 1};
    script.steps[0].ping_root = BR_JDBC_ERR_OTHER;
    script.steps[0].mssql = true;
    script.steps[0].mssql_number = 18456;
    script.steps[0].mssql_message = "login error: Login failed for user 'sa'.";
    script.steps[0].ping_outer = "login failed";
    bound = bind_script(detector, &script);
    reset_setter();
    results = (br_results){0};
    CHECK(scan_of(bound, &ctx, true, mssql, &results, &error) == 0 && !error);
    CHECK(!results.items[0].verified && !results.items[0].verification_error && setter_calls == 0);
    br_results_clear(&results);

    script = (jdbc_script){.nsteps = 1};
    script.steps[0].ping_root = BR_JDBC_ERR_OTHER;
    script.steps[0].mssql = true;
    script.steps[0].mssql_number = 18456;
    script.steps[0].mssql_message = "login error: Login failed for user ''.";
    script.steps[0].ping_outer = "empty user";
    bound = bind_script(detector, &script);
    reset_setter();
    results = (br_results){0};
    CHECK(scan_of(bound, &ctx, true, mssql, &results, &error) == 0 && !error);
    CHECK(!results.items[0].verified && setter_calls == 1);
    CHECK(results.items[0].verification_error && !strcmp(results.items[0].verification_error, "empty user"));
    br_results_clear(&results);

    const char *pair = "jdbc:sqlite:/data/test.db jdbc:mysql://myuser:mypass@tcp(localhost:3307)/mydb";
    script = (jdbc_script){.nsteps = 1};
    bound = bind_script(detector, &script);
    reset_setter();
    results = caller_results();
    CHECK(scan_of(bound, &ctx, true, pair, &results, &error) == 0 && !error);
    CHECK(results.len == 2 && results.items[1].verified && script.opens == 1 && setter_calls == 0);
    br_results_clear(&results);
}

static void test_sqlserver_aliases(void)
{
    struct { const char *sub, *host, *user, *database, *password; bool ordinary; } cases[] = {
        {"//localhost:1433;user id=admin;password=secret", "localhost:1433", "admin", "master", "secret", false},
        {"//localhost:1433;uid=admin;pwd=secret", "localhost:1433", "admin", "master", "secret", false},
        {"//examplehost.net;databaseName=QRG1;sendStringParametersAsUnicode=false", "", "", "", "", true},
        {"//;password=secret123", "", "", "", "", true},
        {"localhost;database=test", "", "", "", "", true},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        jdbc_info info = {0};
        bool ordinary = false;
        char *error = NULL;
        CHECK(parse_sqlserver(slice_text(cases[i].sub), &info, &ordinary, &error) == 0 && !error);
        CHECK(ordinary == cases[i].ordinary);
        if (!ordinary) {
            CHECK(info.host.len == strlen(cases[i].host) && !memcmp(info.host.data, cases[i].host, info.host.len));
            CHECK(info.user.len == strlen(cases[i].user) && !memcmp(info.user.data, cases[i].user, info.user.len));
            CHECK(info.database.len == strlen(cases[i].database) &&
                  !memcmp(info.database.data, cases[i].database, info.database.len));
            CHECK(info.password.len == strlen(cases[i].password) &&
                  !memcmp(info.password.data, cases[i].password, info.password.len));
        }
        info_clear(&info);
    }
}

static void test_invalid_bytes(const br_detector *detector)
{
    static const unsigned char sample[] = {
        'j', 'd', 'b', 'c', ':', 's', 'q', 'l', 'i', 't', 'e', ':', '/', 'd', 'a', 't', 'a', '/',
        0xff, 't', 'e', 's', 't', '.', 'd', 'b',
    };
    CHECK(sizeof(sample) == 26);
    br_results results = test_scan(detector, &empty_ctx, false, sample, sizeof(sample));
    CHECK(results.len == 1 && results.items[0].raw.len == 26);
    CHECK(results.items[0].raw.data && !memcmp(results.items[0].raw.data, sample, 26));
    struct json_object *part = NULL;
    CHECK(results.items[0].secret_parts &&
          json_object_object_get_ex(results.items[0].secret_parts, "connection_string", &part));
    CHECK(json_object_get_string_len(part) == 26 && json_object_get_string(part) &&
          !memcmp(json_object_get_string(part), sample, 26));
    CHECK(results.items[0].redacted && strlen(results.items[0].redacted) == 26 &&
          !memcmp(results.items[0].redacted, sample, 26));
    CHECK(!results.items[0].extra_data && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);

    unsigned char ordered[28 + 25];
    ordered[0] = ' ';
    memcpy(ordered + 1, sample, 26);
    ordered[27] = ' ';
    memcpy(ordered + 28, "jdbc:sqlite:/data/other.db", 25);
    results = test_scan(detector, &empty_ctx, false, ordered, sizeof(ordered));
    CHECK(results.len == 2);
    CHECK(results.items[0].raw.len == 26 && !memcmp(results.items[0].raw.data, sample, 26));
    CHECK(results.items[1].raw.len == 25 &&
          !memcmp(results.items[1].raw.data, "jdbc:sqlite:/data/other.db", 25));
    br_results_clear(&results);

    const char *red_in = "jdbc:sqlite:foo=barpass=\xff\xffmore";
    const char *red_out = "jdbc:sqlite:foo=barpass=**more";
    results = test_scan(detector, &empty_ctx, false, red_in, strlen(red_in));
    CHECK(results.len == 1);
    CHECK(results.items[0].raw.len == strlen(red_in) &&
          !memcmp(results.items[0].raw.data, red_in, strlen(red_in)));
    CHECK(results.items[0].redacted && !strcmp(results.items[0].redacted, red_out));
    br_results_clear(&results);

    static const unsigned char nul_conn[] = {
        'j', 'd', 'b', 'c', ':', 's', 'q', 'l', 'i', 't', 'e', ':', '/', 'd', 'a', 't', 'a', '/',
        0, 't', 'e', 's', 't', '.', 'd', 'b',
    };
    br_results kept = caller_results();
    char *error = NULL;
    CHECK(detector->scan(detector, &empty_ctx, false, (br_slice){nul_conn, sizeof(nul_conn)}, &kept, &error) != 0);
    CHECK(error && !strcmp(error, "unsupported: JDBC redacted value contains NUL"));
    expect_caller_only(&kept);
    free(error);
    br_results_clear(&kept);

    static const unsigned char masked[] = {
        'j', 'd', 'b', 'c', ':', 'm', 'y', 's', 'q', 'l', ':', '/', '/', 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't',
        ':', '3', '3', '0', '6', '/', 'a', 'b', 'c', 'd', '?', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd', '=', 0, 'x',
    };
    const char *masked_out = "jdbc:mysql://localhost:3306/abcd?password=**";
    results = test_scan(detector, &empty_ctx, false, masked, sizeof(masked));
    CHECK(results.len == 1 && results.items[0].redacted && !strcmp(results.items[0].redacted, masked_out));
    br_results_clear(&results);

    static const unsigned char long_s[] = {
        'j', 'd', 'b', 'c', ':', 0xc5, 0xbf, 'q', 'l', 'i', 't', 'e', ':', '/', 'd', 'a', 't', 'a', '/',
        't', 'e', 's', 't', '.', 'd', 'b',
    };
    static const unsigned char kelvin[] = {
        'j', 'd', 'b', 'c', ':', 0xe2, 0x84, 0xaa, 'q', 'l', 'i', 't', 'e', ':', '/', 'd', 'a', 't', 'a', '/',
        't', 'e', 's', 't', '.', 'd', 'b',
    };
    CHECK(sizeof(long_s) == 26 && sizeof(kelvin) == 27);
    results = test_scan(detector, &empty_ctx, false, long_s, sizeof(long_s));
    CHECK(results.len == 1 && results.items[0].raw.len == 26 &&
          !memcmp(results.items[0].raw.data, long_s, 26) && !results.items[0].extra_data);
    br_results_clear(&results);
    results = test_scan(detector, &empty_ctx, false, kelvin, sizeof(kelvin));
    CHECK(results.len == 1 && results.items[0].raw.len == 27 &&
          !memcmp(results.items[0].raw.data, kelvin, 27) && !results.items[0].extra_data);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_jdbc_init(&detector, &error) == 0 && detector && !error);
    test_identity(detector);
    test_patterns(detector);
    test_redaction(detector);
    test_metadata(detector);
    test_invalid_bytes(detector);
    test_sqlserver_aliases();
    test_verify_policy(detector);
    test_injected(detector);
    br_jdbc_binding_destroy(binding);
    free(setter_cause);
    printf("JDBC: %zu assertions, 0 failures; synthetic injected SQL only\n", test_assertions);
    return 0;
}
