/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"
#include <json-c/json.h>
#include <string.h>
#include <time.h>

extern int br_postgres_init(const br_detector **, char **);
typedef struct {
    bool ok, ssl_not_supported;
    const char *message, *pg_code;
} br_postgres_sql_outcome;
typedef int (*br_postgres_sql_fn)(void *, bool, const char *, br_postgres_sql_outcome *, char **);
extern int br_postgres_set_detect_loopback(bool);
extern int br_postgres_set_sql_hook(br_postgres_sql_fn, void *);
extern int br_postgres_set_ignore_patterns(const char *const *, size_t, char **);

static int calls;
static bool saw_neon, saw_disable;
static const char *forced_code, *forced_message;
static bool force_ssl;

static int sql_hook(void *user, bool neon, const char *conninfo, br_postgres_sql_outcome *out, char **error)
{
    (void)user;
    (void)error;
    ++calls;
    saw_neon = neon;
    if (conninfo && strstr(conninfo, "sslmode='disable'")) saw_disable = true;
    CHECK(conninfo && strstr(conninfo, "password='"));
    *out = (br_postgres_sql_outcome){.ssl_not_supported = force_ssl, .message = forced_message, .pg_code = forced_code};
    return 0;
}

static const char *extra(const br_result *result, const char *key)
{
    br_json *item = NULL;
    if (!result->extra_data || !json_object_object_get_ex(result->extra_data, key, &item) ||
        !json_object_is_type(item, json_type_string))
        return NULL;
    return json_object_get_string(item);
}

static int64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int main(void)
{
    char *error = NULL;
    const br_detector *detector = NULL;
    CHECK(br_postgres_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 968 && !strcmp(detector->name, "Postgres"));
    CHECK(detector->max_credential_span == 1024);
    CHECK(detector->false_positive && !detector->false_positive(detector, NULL, &error) && !error);
    br_postgres_set_detect_loopback(false);
    br_postgres_set_sql_hook(NULL, NULL);
    br_postgres_set_ignore_patterns(NULL, 0, &error);
    const char *bad[] = {"["};
    CHECK(br_postgres_set_ignore_patterns(bad, 1, &error) != 0 && error);
    free(error);
    error = NULL;

    br_scan_ctx ctx = {0};
    const char *input = "postgres://app:s3cret@db.example.com/analytics";
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 1);
    CHECK(!strcmp((char *)results.items[0].raw.data, "postgres://app:s3cret@db.example.com:5432"));
    CHECK(!strcmp((char *)results.items[0].raw_v2.data, (char *)results.items[0].raw.data));
    CHECK(!strcmp((char *)results.items[0].primary_secret.data, input));
    CHECK(!strcmp(extra(&results.items[0], "sslmode"), "<unset>"));
    CHECK(!strcmp(extra(&results.items[0], "host"), "db.example.com:5432"));
    CHECK(!strcmp(extra(&results.items[0], "username"), "app"));
    CHECK(!strcmp(extra(&results.items[0], "database"), "analytics"));
    CHECK(!results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);

    input = "postgresql://admin:p%40ss@10.0.0.8:5433/production?sslmode=require";
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 1);
    CHECK(!strcmp((char *)results.items[0].raw.data, "postgresql://admin:p@ss@10.0.0.8:5433"));
    CHECK(!strcmp(extra(&results.items[0], "sslmode"), "require"));
    CHECK(!strcmp(extra(&results.items[0], "database"), "production"));
    br_results_clear(&results);

    input = "postgres://app:s3cret@localhost/db postgres://app:s3cret@127.0.0.1/db "
            "postgres://app:s3cret@[::1]/db";
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(!results.len);
    br_postgres_set_detect_loopback(true);
    results = test_scan(detector, &ctx, false, "postgres://app:s3cret@localhost/db", 35);
    CHECK(results.len == 1 && !strcmp(extra(&results.items[0], "host"), "localhost:5432"));
    br_results_clear(&results);
    br_postgres_set_detect_loopback(false);

    const char *ignore[] = {"db\\.example\\.com"};
    CHECK(br_postgres_set_ignore_patterns(ignore, 1, &error) == 0 && !error);
    results = test_scan(detector, &ctx, false, "postgres://app:s3cret@db.example.com/analytics", 45);
    CHECK(!results.len);
    CHECK(br_postgres_set_ignore_patterns(NULL, 0, &error) == 0);

    results = test_scan(detector, &ctx, false, "postgres://app@db.example.com/analytics", 38);
    CHECK(!results.len);
    input = "postgres://app:s3cret@db.example.com/analytics?requiressl=1";
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 1 && !strcmp(extra(&results.items[0], "sslmode"), "require"));
    br_results_clear(&results);

    input = "postgres://app:s3cret@db.example.com/analytics";
    char *scan_error = NULL;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)},
                         &results, &scan_error) != 0);
    CHECK(scan_error && strstr(scan_error, "nil context"));
    free(scan_error);
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)"none", 4},
                         &results, &scan_error) == 0 && !results.len && !scan_error);

    ctx.deadline_monotonic_ms = 1;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.len);
    ctx.deadline_monotonic_ms = now_ms() + 200;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.len);
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 1);
    br_results_clear(&results);
    ctx.deadline_monotonic_ms = 0;

    br_postgres_set_sql_hook(sql_hook, NULL);
    forced_message = "password authentication failed for user \"app\"";
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && calls == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    forced_message = NULL;
    forced_code = "3D000";
    calls = 0;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    forced_code = NULL;
    calls = 0;
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 1 && !calls && !results.items[0].verified);
    br_results_clear(&results);

    input = "postgres://app:s3cret@ep.neon.tech/analytics";
    calls = 0;
    forced_message = "connection refused";
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && calls == 1 && saw_neon && !results.items[0].verified);
    CHECK(!strcmp((char *)results.items[0].raw.data, "postgres://app:s3cret@ep.neon.tech:5432"));
    CHECK(!strcmp((char *)results.items[0].primary_secret.data, input));
    CHECK(!strcmp(extra(&results.items[0], "database"), "analytics"));
    CHECK(results.items[0].verification_error && strstr(results.items[0].verification_error, "connection refused"));
    br_results_clear(&results);

    input = "postgres://app:s3cret@db.example.com/analytics postgres://app:s3cret@db.example.com/analytics";
    calls = 0;
    forced_message = NULL;
    results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 2);
    br_results_clear(&results);

    force_ssl = true;
    calls = 0;
    saw_disable = false;
    input = "postgres://app:s3cret@db.example.com/analytics?sslmode=prefer";
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && calls == 2 && saw_disable);
    CHECK(!strcmp(extra(&results.items[0], "sslmode"), "prefer"));
    br_results_clear(&results);
    forced_message = NULL;
    forced_code = NULL;
    force_ssl = false;
    calls = 0;
    input = "postgres://app:s3cret@db.example.com/analytics";
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && calls == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    br_postgres_set_sql_hook(NULL, NULL);
    printf("postgres: %zu assertions, 0 failures; synthetic SQL hook only\n", test_assertions);
    return 0;
}
