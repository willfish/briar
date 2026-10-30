/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"
#include <json-c/json.h>

int br_redis_init(const br_detector **out, char **error);

static const char password[] = "Xcc3S9d7And6aMdfOcUc0acHJh3CiDh3l9DsapNwGwyS";
static const char domain[] = "QZc67koZ6rUV.redis.cache.windows.net:6380";

static void expect_meta(const br_result *result, const char *raw, const char *host,
                        const char *pass, const char *username, const char *redacted)
{
    CHECK(result->detector_type == 900);
    CHECK(result->raw.len == strlen(raw) && !memcmp(result->raw.data, raw, result->raw.len));
    CHECK(!result->raw_v2.data && !result->verified && !result->verification_error);
    CHECK(result->redacted && !strcmp(result->redacted, redacted));
    CHECK(!strstr(result->redacted, pass));
    br_json *value = NULL;
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
    CHECK(json_object_object_get_ex(result->secret_parts, "host", &value));
    CHECK(!strcmp(json_object_get_string(value), host));
    CHECK(json_object_object_get_ex(result->secret_parts, "password", &value));
    CHECK(!strcmp(json_object_get_string(value), pass));
    CHECK(result->extra_data);
    if (host[0]) {
        CHECK(json_object_object_get_ex(result->extra_data, "host", &value));
        CHECK(!strcmp(json_object_get_string(value), host));
    }
    if (username) {
        CHECK(json_object_object_get_ex(result->extra_data, "username", &value));
        CHECK(!strcmp(json_object_get_string(value), username));
    } else CHECK(!json_object_object_get_ex(result->extra_data, "username", &value));
}

static br_results scan(const br_detector *detector, const char *input, bool verify)
{
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, verify, input, strlen(input));
    CHECK(!http.calls && !http.releases);
    return results;
}

int main(void)
{
    CHECK(BR_ABI_REVISION == 1);
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(br_redis_init(&detector, &error) == 0 && !error && detector);
    CHECK(br_redis_init(&again, &error) == 0 && again == detector);
    CHECK(detector->type == 900 && detector->version == 0);
    CHECK(!strcmp(detector->name, "Redis") && detector->nkeywords == 1 &&
          detector->max_credential_span == 1024);
    CHECK(!strcmp(detector->keywords[0], "redis"));
    CHECK(!strcmp(detector->description,
                  "Redis is an in-memory data structure store, used as a database, cache, and message broker. "
                  "Redis credentials can be used to access and manipulate stored data."));
    CHECK(br_redis_init(NULL, &error) != 0 && error);
    free(error);

    const char *uri = "redis://myuser:mysecretpass@redis.example.com:6379/0";
    br_results results = scan(detector, uri, false);
    CHECK(results.len == 1);
    expect_meta(&results.items[0], uri, "redis.example.com:6379", "mysecretpass", "myuser",
                "redis://myuser:*******@redis.example.com:6379/0");
    br_results_clear(&results);

    results = scan(detector, "redis://default:mysecretpass@redis.example.com:6379", true);
    CHECK(results.len == 1);
    expect_meta(&results.items[0], "redis://default:mysecretpass@redis.example.com:6379",
                "redis.example.com:6379", "mysecretpass", "default",
                "redis://default:*******@redis.example.com:6379");
    br_results_clear(&results);

    results = scan(detector, "redis://my%20user:password12@example.com:6379", false);
    CHECK(results.len == 1);
    expect_meta(&results.items[0], "redis://my%20user:password12@example.com:6379",
                "example.com:6379", "password12", "my user",
                "redis://my%20user:*******@example.com:6379");
    br_results_clear(&results);

    char azure[256];
    snprintf(azure, sizeof(azure),
             "mycache.redis.cache.windows.net:6380,password=%s,ssl=True,abortConnect=False", password);
    char azure_raw[256], azure_redacted[256];
    snprintf(azure_raw, sizeof(azure_raw), "rediss://:%s@mycache.redis.cache.windows.net:6380", password);
    snprintf(azure_redacted, sizeof(azure_redacted), "rediss://:*******@mycache.redis.cache.windows.net:6380");
    results = scan(detector, azure, false);
    CHECK(results.len == 1);
    expect_meta(&results.items[0], azure_raw, "mycache.redis.cache.windows.net:6380", password, NULL, azure_redacted);
    br_results_clear(&results);

    char combined[512];
    snprintf(combined, sizeof(combined), "%s\n%s", azure, uri);
    results = scan(detector, combined, false);
    CHECK(results.len == 2);
    expect_meta(&results.items[0], azure_raw, "mycache.redis.cache.windows.net:6380", password, NULL, azure_redacted);
    expect_meta(&results.items[1], uri, "redis.example.com:6379", "mysecretpass", "myuser",
                "redis://myuser:*******@redis.example.com:6379/0");
    br_results_clear(&results);

    char integration[512];
    snprintf(integration, sizeof(integration),
             "redis token - 'redis://1SHPg6BjyS:$YYbMDot25P@PvfdX9VshFjW'\n"
             "redis token - '%s,password=%s,ssl=True,abortConnect=False'\n",
             domain, password);
    results = scan(detector, integration, true);
    CHECK(results.len == 1);
    char want[256];
    snprintf(want, sizeof(want), "rediss://:%s@%s", password, domain);
    CHECK(results.items[0].raw.len == strlen(want) && !memcmp(results.items[0].raw.data, want, strlen(want)));
    br_results_clear(&results);

    results = scan(detector, "redis token - 'redis://1SHPg6BjySX$YYbMDot25P@PvfdX9VshFjW'\n"
                             "redis token - 'QZc67koZ6rUV.redis.cache.windows.net:6381,password=Xcc3S9d7And6aMdfOcUc0acHJh3CiDh3l9DsapNwGwyS,ssl=False,abortConnect=True'\n",
                   false);
    CHECK(!results.len);
    br_results_clear(&results);
    results = scan(detector, "redis://user:*****@localhost", true);
    CHECK(!results.len);
    br_results_clear(&results);
    results = scan(detector, "redis://user:$secret12@localhost", true);
    CHECK(!results.len);
    br_results_clear(&results);
    char control[] = "redis://user:ab\x01" "cd@localhost";
    results = scan(detector, control, false);
    CHECK(!results.len);
    br_results_clear(&results);
    results = scan(detector, "redi://user:password@localhost", false);
    CHECK(!results.len);
    br_results_clear(&results);
    results = scan(detector, "redis://user:passwor@localhost redis://user:passwor@localhost", false);
    CHECK(results.len == 2);
    expect_meta(&results.items[0], "redis://user:passwor@localhost", "localhost", "passwor", "user",
                "redis://user:*******@localhost");
    br_results_clear(&results);
    results = scan(detector, "redis://ab:password@host redis://usr:ab@host", false);
    CHECK(!results.len);
    br_results_clear(&results);

    char *scan_error = NULL;
    CHECK(detector->scan(detector, NULL, false, (br_slice){NULL, 0}, NULL, &scan_error) != 0 && scan_error);
    free(scan_error);
    return test_finish("Redis");
}
