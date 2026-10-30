/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

int br_sqlserver_init(const br_detector **out, char **error);
typedef int (*sqlserver_ping_fn)(const br_scan_ctx *, const char *, const char *,
                                 bool *, bool *, int32_t *, char **, char **);
int br_sqlserver_set_ping(sqlserver_ping_fn);
int br_sqlserver_set_ignore(const char *const *, size_t, char **);

static const char conn[] =
    "Server=localhost;Initial Catalog=master;User ID=sa;Password=P@ssw0rd!;Persist Security Info=true;MultipleActiveResultSets=true;";
static const char want[] =
    "sqlserver://sa:P%40ssw0rd%21@localhost?database=master&dial+timeout=15&disableretry=false";
static const char redacted[] =
    "sqlserver://sa:********@localhost?database=master&dial+timeout=15&disableretry=false";

static int ping_mode;
static char seen_address[128], seen_dsn[512];

static int ping(const br_scan_ctx *ctx, const char *address, const char *dsn,
                bool *verified, bool *is_mssql, int32_t *number, char **ordinary, char **fatal)
{
    CHECK(ctx && address && dsn);
    snprintf(seen_address, sizeof(seen_address), "%s", address);
    snprintf(seen_dsn, sizeof(seen_dsn), "%s", dsn);
    *verified = false;
    *is_mssql = false;
    *number = 0;
    *ordinary = NULL;
    *fatal = NULL;
    if (ping_mode == 0) { *verified = true; return 0; }
    if (ping_mode == 1) { *is_mssql = true; *number = 18456; *ordinary = strdup("login failed"); return 1; }
    if (ping_mode == 2) { *is_mssql = true; *number = 4060; *ordinary = strdup("missing db"); return 1; }
    if (ping_mode == 3) { *ordinary = strdup("dial tcp: connection refused"); return 1; }
    *fatal = strdup("injected fatal");
    return -1;
}

static void check_parts(const br_result *result)
{
    CHECK(result->detector_type == 898);
    CHECK(result->raw.len == 9 && !memcmp(result->raw.data, "P@ssw0rd!", 9));
    CHECK(result->raw_v2.len == strlen(want) && !memcmp(result->raw_v2.data, want, strlen(want)));
    CHECK(result->redacted && !strcmp(result->redacted, redacted));
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, "host", &part) && !strcmp(json_object_get_string(part), "localhost"));
    CHECK(json_object_object_get_ex(result->secret_parts, "database", &part) && !strcmp(json_object_get_string(part), "master"));
    CHECK(json_object_object_get_ex(result->secret_parts, "user", &part) && !strcmp(json_object_get_string(part), "sa"));
    CHECK(json_object_object_get_ex(result->secret_parts, "password", &part) && !strcmp(json_object_get_string(part), "P@ssw0rd!"));
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_sqlserver_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 898 && detector->nkeywords == 5 && !strcmp(detector->keywords[3], "Server="));
    char input[512];
    snprintf(input, sizeof(input), "sql - %s", conn);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    check_parts(&results.items[0]);
    CHECK(!results.items[0].verified);
    br_results_clear(&results);

    snprintf(input, sizeof(input), "Server=.;User ID=sa;Password=secret1;Database=db");
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    CHECK(results.items[0].raw_v2.len && strstr((char *)results.items[0].raw_v2.data, "@localhost?"));
    br_results_clear(&results);

    snprintf(input, sizeof(input), "Server=localhost;User ID=sa;Password=;Database=db");
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);

    const char *ignore[] = {"^Server=localhost"};
    CHECK(br_sqlserver_set_ignore(ignore, 1, &error) == 0 && !error);
    results = test_scan(detector, NULL, false, conn, strlen(conn));
    CHECK(results.len == 0);
    br_results_clear(&results);
    CHECK(br_sqlserver_set_ignore(NULL, 0, &error) == 0);

    CHECK(br_sqlserver_set_ping(ping) == 0);
    br_transport transport = {0};
    br_scan_ctx ctx = {.transport = &transport};
    ping_mode = 0;
    results = test_scan(detector, &ctx, true, conn, strlen(conn));
    CHECK(results.len == 1 && results.items[0].verified);
    CHECK(!strcmp(seen_address, "localhost:0"));
    CHECK(strstr(seen_dsn, "dial+timeout=3") && strstr(seen_dsn, "disableretry=true"));
    br_results_clear(&results);
    ping_mode = 1;
    results = test_scan(detector, &ctx, true, conn, strlen(conn));
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    ping_mode = 2;
    results = test_scan(detector, &ctx, true, conn, strlen(conn));
    CHECK(results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "SQL Server error 4060: missing db"));
    br_results_clear(&results);
    ping_mode = 3;
    results = test_scan(detector, &ctx, true, conn, strlen(conn));
    CHECK(results.items[0].verification_error &&
          !strcmp(results.items[0].verification_error, "dial tcp: connection refused"));
    br_results_clear(&results);
    ping_mode = 4;
    error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)conn, strlen(conn)}, &results, &error) != 0);
    CHECK(error && strstr(error, "injected fatal"));
    free(error);
    br_results_clear(&results);
    error = NULL;
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)conn, strlen(conn)}, &results, &error) != 0);
    CHECK(error && strstr(error, "nil context"));
    free(error);
    br_results_clear(&results);
    return test_finish("sqlserver");
}
