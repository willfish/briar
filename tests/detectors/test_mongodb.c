/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_mongodb_init(const br_detector **out, char **error);

static const char *extra(const br_result *result, const char *name)
{
    br_json *value = NULL;
    if (!result->extra_data || !json_object_object_get_ex(result->extra_data, name, &value) ||
        !json_object_is_type(value, json_type_string)) return NULL;
    return json_object_get_string(value);
}

static void expect_raw(const br_detector *detector, const char *input, const char *want)
{
    br_scan_ctx ctx = {0};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 1);
    CHECK(results.items[0].raw.len == strlen(want) &&
          !memcmp(results.items[0].raw.data, want, strlen(want)));
    CHECK(extra(&results.items[0], "rotation_guide") &&
          !strcmp(extra(&results.items[0], "rotation_guide"),
                  "https://howtorotate.com/docs/tutorials/mongo/"));
    br_results_clear(&results);
}

static void expect_none(const br_detector *detector, const char *input)
{
    br_scan_ctx ctx = {0};
    br_results results = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_mongodb_init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 895 && !strcmp(detector->name, "MongoDB"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "mongodb"));
    CHECK(detector->false_positive && !detector->false_positive(detector, NULL, &error) && error && !error[0]);
    free(error);
    error = NULL;
    CHECK(!br_detector_is_default(detector, NULL));

    expect_raw(detector, "mongodb://myDBReader:D1fficultP%40ssw0rd@mongodb0.example.com:27017",
               "mongodb://myDBReader:D1fficultP%40ssw0rd@mongodb0.example.com:27017");
    expect_raw(detector, "mongodb://myDBReader:D1fficultP%40ssw0rd@mongodb0.example.com",
               "mongodb://myDBReader:D1fficultP%40ssw0rd@mongodb0.example.com");
    expect_raw(detector, "mongodb://myDBReader:D1fficultP%40ssw0rd@mongodb0.example.com:27017/?authSource=admin",
               "mongodb://myDBReader:D1fficultP%40ssw0rd@mongodb0.example.com:27017/?authSource=admin");
    expect_raw(detector, "mongodb://root:root@192.168.74.143:27018,192.168.74.143:27019/",
               "mongodb://root:root@192.168.74.143:27018,192.168.74.143:27019/");
    expect_raw(detector,
               "mongodb://username:password@mongodb1.example.com:27317,mongodb2.example.com,mongodb2.example.com:270/?connectTimeoutMS=300000&replicaSet=mySet&authSource=aDifferentAuthDB",
               "mongodb://username:password@mongodb1.example.com:27317,mongodb2.example.com,mongodb2.example.com:270/?authSource=aDifferentAuthDB&connectTimeoutMS=300000&replicaSet=mySet");
    expect_raw(detector,
               "mongodb://dave:password@localhost:27017/?authMechanism=DEFAULT&amp;authSource=db&amp;ssl=true&quot;",
               "mongodb://dave:password@localhost:27017/?authMechanism=DEFAULT&authSource=db&ssl=true");
    expect_raw(detector,
               "mongodb://username:password@host.docker.internal:27018/?authMechanism=PLAIN&tls=true&tlsCertificateKeyFile=/etc/certs/client.pem&tlsCaFile=/etc/certs/rootCA-cert.pem",
               "mongodb://username:password@host.docker.internal:27018/?authMechanism=PLAIN&tls=true&tlsCaFile=%2Fetc%2Fcerts%2FrootCA-cert.pem&tlsCertificateKeyFile=%2Fetc%2Fcerts%2Fclient.pem");
    expect_raw(detector,
               "mongodb://AKIAAAAAAAAAAAA:t9t2mawssecretkey@localhost:27017/?authMechanism=MONGODB-AWS&authsource=$external",
               "mongodb://AKIAAAAAAAAAAAA:t9t2mawssecretkey@localhost:27017/?authMechanism=MONGODB-AWS&authsource=%24external");
    expect_raw(detector,
               "mongodb://agenda-live:m21w7PFfRXQwfHZU1Fgx0rTX29ZBQaWMODLeAjsmyslVcMmcmy6CnLyu3byVDtdLYcCokze8lIE4KyAgSCGZxQ==@agenda-live.mongo.cosmos.azure.com:10255/csb-db?retryWrites=false&ssl=true&replicaSet=globaldb&maxIdleTimeMS=120000&appName=@agenda-live@",
               "mongodb://agenda-live:m21w7PFfRXQwfHZU1Fgx0rTX29ZBQaWMODLeAjsmyslVcMmcmy6CnLyu3byVDtdLYcCokze8lIE4KyAgSCGZxQ==@agenda-live.mongo.cosmos.azure.com:10255/csb-db?appName=%40agenda-live%40&maxIdleTimeMS=120000&replicaSet=globaldb&retryWrites=false&ssl=true");

    br_scan_ctx ctx = {0};
    br_results results = test_scan(detector, &ctx, false,
                                   "mongodb://db-user:db-password@mongodb-instance:27017/db-name",
                                   strlen("mongodb://db-user:db-password@mongodb-instance:27017/db-name"));
    CHECK(results.len == 1);
    CHECK(!strcmp(extra(&results.items[0], "host"), "mongodb-instance:27017"));
    CHECK(!strcmp(extra(&results.items[0], "username"), "db-user"));
    CHECK(!strcmp(extra(&results.items[0], "database"), "db-name"));
    br_results_clear(&results);

    expect_none(detector, "mongodb://mongodb0.example.com:27017/?replicaSet=myRepl");
    expect_none(detector, "mongodb://username:@mongodb0.example.com:27017/?replicaSet=myRepl");
    expect_none(detector, "mongodb://xxxx:xxxxx@xxxxxxx:3717/zkquant?replicaSet=mgset-3017917");
    expect_none(detector, "not a mongodb uri");

    const char *dup = "mongodb://user:pass@host:27017/db mongodb://user:pass@host:27017/db";
    results = test_scan(detector, &ctx, false, dup, strlen(dup));
    CHECK(results.len == 1);
    br_results_clear(&results);

    results = test_scan(detector, &ctx, true, "mongodb://user:pass@host:27017/db",
                        strlen("mongodb://user:pass@host:27017/db"));
    CHECK(results.len == 1 && !results.items[0].verified && results.items[0].verification_error &&
          strstr(results.items[0].verification_error, "unsupported: MongoDB wire verification is not available"));
    br_results_clear(&results);

    br_results empty = {0};
    CHECK(detector->scan(detector, NULL, false, (br_slice){(const unsigned char *)"x", 1}, &empty, &error) != 0);
    CHECK(error && strstr(error, "nil parent") && empty.len == 0);
    free(error);
    return test_finish("mongodb");
}
