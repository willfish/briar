/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

typedef struct {
    int32_t type, version;
    const char *name, *keyword;
    size_t key_len;
    bool enabled;
    int64_t span;
} registration;

static const registration expected[] = {
    {239, 0, "Abyssale", "abyssale", 40, true, -1},
    {384, 0, "Abstract", "abstract", 32, false, -1},
    {521, 0, "AbuseIPDB", "abuseipdb", 80, true, -1},
    {303, 1, "Accuweather", "accuweather", 35, true, -1},
    {303, 2, "Accuweather", "accuweather", 32, true, -1},
    {390, 0, "AdafruitIO", "aio_", 32, true, -1},
    {136, 0, "AdobeIO", "adobe", 32, false, 1024},
    {431, 0, "Adzuna", "adzuna", 32, true, 1024},
    {693, 0, "Aeroworkflow", "aeroworkflow", 20, true, 1024},
    {197, 0, "Agora", "agora", 32, true, 1024},
    {802, 0, "Aha", "aha.io", 64, true, 1024},
    {125, 0, "AirbrakeProjectKey", "airbrake", 32, true, 1024},
    {126, 0, "AirbrakeUserKey", "airbrake", 40, true, -1},
    {277, 0, "Airship", "airship", 91, true, -1},
    {1014, 0, "AirtableOAuth", "airtable", sizeof("Native7.v1.Synthetic_-Payload.1a2b3c") - 1, true, -1},
    {1015, 0, "AirtablePersonalAccessToken", "airtable", 82, true, -1},
    {498, 0, "AirVisual", "airvisual", 36, true, -1},
    {917, 0, "Aiven", "aiven", 372, true, -1},
    {907, 0, "Alchemy", "alchemy", 32, true, -1},
    {301, 0, "Alconost", "alconost", 32, false, -1},
    {375, 0, "Alegra", "alegra", 20, true, -1},
    {522, 0, "AletheiaApi", "aletheiaapi", 32, true, -1},
    {170, 0, "AlgoliaAdminKey", "algolia", 32, true, 1024},
    {0, 0, "Alibaba", "LTAI", 30, true, 1024},
    {399, 0, "AlienVault", "alienvault", 64, true, -1},
    {473, 0, "Allsports", "allsports", 64, true, -1},
    {453, 0, "Amadeus", "amadeus", 32, true, 1024},
    {457, 0, "Ambee", "ambee", 64, true, -1},
    {42, 0, "AmplitudeApiKey", "amplitude", 32, true, 1024},
    {933, 0, "Anthropic", "sk-ant-api03", 108, true, -1},
    {179, 0, "Anypoint", "anypoint", 36, true, 1024},
    {1032, 0, "AnypointOAuth2", "anypoint", 32, true, 1024},
    {632, 0, "Apacta", "apacta", 36, true, -1},
    {458, 0, "Api2Cart", "api2cart", 32, true, -1},
    {212, 0, "ApiDeck", "apideck", 101, true, 1024},
    {401, 0, "Apiflash", "apiflash", 32, true, 1024},
    {484, 0, "ApiFonica", "apifonica", 39, true, -1},
    {391, 0, "Apify", "apify", 46, true, -1},
    {788, 0, "Apilayer", "apilayer", 32, true, -1},
    {637, 0, "APIMatic", "apimatic", 64, true, 1024},
    {1004, 0, "ApiMetrics", "apimetrics", 32, true, -1},
    {768, 0, "APITemplate", "apitemplate", 39, true, -1},
    {293, 0, "Apollo", "apollo", 22, false, -1},
    {322, 0, "Appcues", "appcues", 36, true, 1024},
    {588, 0, "Appfollow", "appfollow", 155, true, -1},
    {816, 0, "Appointedd", "appointedd", 88, true, -1},
    {1052, 0, "AWSAppSync", "da2-", 30, true, 1024},
    {646, 0, "AppSynergy", "appsynergy", 64, true, -1},
    {269, 0, "Apptivo", "apptivo", 36, true, 1024},
    {181, 0, "ArtifactoryAccessToken", "artifactory", 73, true, 1024},
    {1042, 0, "ArtifactoryReferenceToken", "cmVmdGtu", 64, true, 1024},
    {278, 0, "Artsy", "artsy", 32, true, 1024},
    {98, 0, "AsanaOauth", "asana", 51, true, -1},
    {41, 0, "AsanaPersonalAccessToken", "asana", 51, true, -1},
    {389, 0, "AssemblyAI", "assemblyai", 32, true, -1},
    {800, 0, "Atera", "atera", 32, true, -1},
    {190, 1, "Atlassian", "atlassian", 24, true, -1},
    {190, 2, "Atlassian", "ATCTT3xFfG", 43, true, -1},
    {376, 0, "Audd", "audd", 32, true, -1},
    {110, 0, "Auth0ManagementApiToken", "auth0", 2000, true, 1024},
    {55, 0, "Auth0oauth", "auth0", 64, true, 1024},
    {604, 0, "Autodesk", "autodesk", 32, true, 1024},
    {323, 0, "Autoklose", "autoklose", 32, true, -1},
    {511, 0, "AutoPilot", "autopilot", 32, true, -1},
    {733, 0, "AvazaPersonalAccessToken", "avaza", 45, true, -1},
    {564, 0, "AviationStack", "aviationstack", 32, true, -1},
    {2, 0, "AWS", "AKIA", 20, true, 1024},
    {959, 0, "AWSSessionKey", "ASIA", 20, true, 2048},
    {320, 0, "Axonaut", "axonaut", 32, true, -1},
    {485, 0, "Aylien", "aylien", 32, true, 1024},
    {163, 0, "Ayrshare", "ayrshare", 35, true, -1},
    {1019, 0, "AzureAPIManagementSubscriptionKey", ".azure-api.net", sizeof("https://briar-api.azure-api.net") - 1, true, 1024},
    {1013, 0, "AzureRefreshToken", "0.A", 366, true, 1024},
    {3, 1, "Azure", "azure", 32, true, 1024},
    {3, 2, "Azure", "q~", 37, true, 1024},
    {957, 0, "AzureBatch", ".batch.azure.com", sizeof("https://briar.region.batch.azure.com") - 1, true, 1024},
    {1025, 0, "AzureAppConfigConnectionString", ".azconfig.io", 32, true, 1024},
    {971, 0, "AzureCosmosDBKeyIdentifiable", ".documents.azure.com", 88, true, -1},
    {1007, 0, "AzureOpenAI", ".openai.azure.com", 32, true, -1},
    {931, 0, "AzureStorage", "DefaultEndpointsProtocol=http", 88, true, 1024},
    {1018, 0, "AzureApiManagementRepositoryKey", "azure", 105, true, 1024},
    {1045, 0, "BitbucketDataCenter", "BBDC-", 45, true, 1024},
    {1047, 0, "ConfluenceDataCenter", "confluence", 44, true, 1024},
    {1046, 0, "JiraDataCenterPAT", "jira", 44, true, 1024},
};

/* Registration must dispatch real initialized scanners, not metadata stubs. */
static void check_dispatch(const br_detector *detector, const registration *entry)
{
    char key[5001], secondary_buffer[89], session_buffer[133], input[8192];
    test_secret(key, entry->key_len, 0);
    if (entry->type == 163) strcpy(key, "B7C9D2E5-F6G8H3J4-K1M0N2P4-Q6R8S1T3");
    if (entry->type == 3 && entry->version == 2) memcpy(key, "b7c1Q~", 6);
    if (entry->type == 1018) {
        memcpy(key, "git&000000000007&", 17);
        key[103] = key[104] = '=';
    }
    if (entry->type == 1013) {
        memcpy(key, "0.A", 3);
        test_secret(key + 3, 60, 11);
        memcpy(key + 63, ".Ag", 3);
        test_secret(key + 66, 300, 23);
    }
    if (entry->type == 41) {
        static const char prefix[] = "0/1234567890123456:";
        memcpy(key, prefix, sizeof(prefix) - 1);
    }
    if (entry->type == 190 && entry->version == 2) {
        memcpy(key, "ATCTT3xFfG", 10);
        key[34] = '=';
    }
    if (entry->type == 303 && entry->version == 1) key[7] = '%';
    if (entry->type == 110) memcpy(key, "ey", 2);
    if (entry->type == 390) memcpy(key, "aio_", 4);
    if (entry->type == 391) memcpy(key, "apify_api_", 10);
    if (entry->type == 181) memcpy(key, "AKCp", 4);
    if (entry->type == 1042) memcpy(key, "cmVmdGtu", 8);
    if (entry->type == 1045) memcpy(key, "BBDC-", 5);
    if (entry->type == 1052) memcpy(key, "da2-", 4);
    if (entry->type == 1047 || entry->type == 1046) strcpy(key, "MTIzNDU2Nzg5MDEyOmFiY2RlZmdoaWprbG1ub3BxcnN0");
    if (entry->type == 484) strcpy(key, "b7c9d2e5f6g-h3j4-k1m0-n2p4-q6r8s1t3u5v7");
    if (entry->type == 588) {
        static const char header[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.";
        memcpy(key, header, sizeof(header) - 1);
        key[sizeof(header) - 1 + 74] = '.';
    }
    const char *secondary = NULL, *secondary_name = NULL, *session = NULL;
    switch (entry->type) {
    case 959:
        strcpy(key, "ASIAQWERTYUIOPASDFGH");
        secondary = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN";
        secondary_name = "secret_access_key";
        memcpy(session_buffer, "YXdz", 4);
        for (size_t i = 4; i < sizeof(session_buffer) - 1; ++i)
            session_buffer[i] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[(i - 4) % 64];
        session_buffer[sizeof(session_buffer) - 1] = '\0';
        session = session_buffer;
        break;
    case 2:
        strcpy(key, "AKIAQWERTYUIOPASDFGH");
        secondary = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN";
        secondary_name = "secret_access_key";
        break;
    case 1025:
        secondary = "https://briar-config.azconfig.io";
        secondary_name = "endpoint";
        break;
    case 1019:
        strcpy(key, "https://briar-api.azure-api.net");
        test_secret(secondary_buffer, 32, 7);
        secondary_buffer[7] = '-';
        secondary = secondary_buffer;
        secondary_name = "key";
        break;
    case 1018:
        secondary = "briar-apim.scm.azure-api.net";
        secondary_name = "url";
        break;
    case 931:
        secondary = "briarstorage";
        secondary_name = "account_name";
        break;
    case 971:
        key[86] = key[87] = '=';
        secondary = "briar-cosmos.documents.azure.com";
        secondary_name = "account_url";
        break;
    case 957:
        strcpy(key, "https://briar.region.batch.azure.com");
        test_secret(secondary_buffer, 88, 7);
        secondary = secondary_buffer;
        secondary_name = "account_key";
        break;
    case 1052:
        secondary = "https://abcdefghijklmnopqrstuvwx12.appsync-api.us-east-1.amazonaws.com/graphql";
        secondary_name = "endpoint";
        break;
    case 0: secondary = "LTAIB7c9D2e5F6g8H3j4K"; secondary_name = "id"; break;
    case 42:
        for (size_t i = 0; i < 32; ++i) {
            key[i] = "0123456789abcdef"[i % 16];
            secondary_buffer[i] = "0123456789abcdef"[(i + 5) % 16];
        }
        secondary_buffer[32] = '\0';
        secondary = secondary_buffer;
        secondary_name = "secret";
        break;
    case 55:
        test_secret(secondary_buffer, 32, 11);
        secondary = secondary_buffer;
        secondary_name = "client_id";
        break;
    case 110: secondary = "fixture-tenant.us.auth0.com"; secondary_name = "domain"; break;
    case 125: secondary = "004207"; secondary_name = "id"; break;
    case 136: secondary = "C7d8E9f0.G1H"; secondary_name = "id"; break;
    case 170: secondary = "B7C9D2E5F6"; secondary_name = "id"; break;
    case 179:
        strcpy(key, "b7c9d2e5-f6g8-h3j4-k1m0-n2p4q6r8s1t3");
        secondary = "c7d8e9f0-g1h2-i3j4-k5l6-m7n8o9p0q1r2";
        secondary_name = "organization";
        break;
    case 269:
        test_secret(secondary_buffer, 32, 17);
        secondary = secondary_buffer;
        secondary_name = "id";
        break;
    case 278:
        test_secret(secondary_buffer, 20, 17);
        secondary = secondary_buffer;
        secondary_name = "id";
        break;
    case 322:
        test_secret(secondary_buffer, 39, 17);
        secondary = secondary_buffer;
        secondary_name = "username";
        break;
    case 375: secondary = "fixture@example.test"; secondary_name = "id"; break;
    case 431:
    case 485: secondary = "c7d8e9f0"; secondary_name = "id"; break;
    case 453: secondary = "B7c9D2e5F6g8H3j4"; secondary_name = "secret"; break;
    case 693: secondary = "00042"; secondary_name = "id"; break;
    case 604:
        test_secret(secondary_buffer, 16, 11);
        secondary = secondary_buffer;
        secondary_name = "secret";
        break;
    case 197:
        test_secret(secondary_buffer, 32, 11);
        secondary = secondary_buffer;
        secondary_name = "secret";
        break;
    case 802:
        for (size_t i = 0; i < 64; ++i) key[i] = "0123456789abcdef"[i % 16];
        key[64] = '\0';
        secondary = "synthetic.aha.io";
        secondary_name = "url";
        break;
    case 457:
    case 458:
    case 511:
    case 1007:
        for (size_t i = 0; i < entry->key_len; ++i) key[i] = "0123456789abcdef"[i % 16];
        break;
    case 212:
        memcpy(key, "sk_live_", 8);
        test_secret(secondary_buffer, 40, 7);
        secondary = secondary_buffer;
        secondary_name = "id";
        break;
    case 733:
        memcpy(key, "0007-", 5);
        for (size_t i = 5; i < 45; ++i) key[i] = "0123456789abcdef"[i % 16];
        break;
    case 522:
        for (size_t i = 0; i < 32; ++i) key[i] = "0123456789ABCDEF"[i % 16];
        break;
    case 933:
        memcpy(key, "sk-ant-api03-", 13);
        key[106] = key[107] = 'A';
        break;
    case 1032:
        for (size_t i = 0; i < 32; ++i) key[i] = "0123456789ABCDEF"[i % 16];
        secondary = "b7c9d2e5f6a8b3c4d1e0f2a4b6c8d0e2";
        secondary_name = "client_id";
        break;
    case 181:
    case 1042:
        secondary = "synthetic-fixture.jfrog.io";
        secondary_name = "domain";
        break;
    case 1046:
        secondary = "https://jira.invalid";
        secondary_name = "url";
        break;
    case 1047:
        secondary = "https://confluence.invalid";
        secondary_name = "url";
        break;
    case 1045:
        secondary = "https://bitbucket.invalid";
        secondary_name = "url";
        break;
    case 1014: strcpy(key, "Native7.v1.Synthetic_-Payload.1a2b3c"); break;
    case 1015:
        memcpy(key, "patN7c4P9d2R5s8T1.", 18);
        for (size_t i = 0; i < 64; ++i) key[18 + i] = "0123456789abcdef"[i % 16];
        key[82] = '\0';
        break;
    }
    if (entry->type == 1025)
        snprintf(input, sizeof(input), "Endpoint=%s;Id=%s;Secret=AQIDBA==", secondary, key);
    else if (entry->type == 3 && entry->version == 1)
        snprintf(input, sizeof(input), "azure\nclient_id a6b39f20-17c4-4d85-9e62-0f3a7b1c5d98\nsecret '%s'\n", key);
    else if (entry->type == 3)
        snprintf(input, sizeof(input), "%s", key);
    else if (session)
        snprintf(input, sizeof(input), "%s\n%s\n%s", key, secondary, session);
    else if (entry->type == 322)
        snprintf(input, sizeof(input), "appcues %s\nappcues %s\nappcues 00427", key, secondary);
    else if (entry->type == 197)
        snprintf(input, sizeof(input), "token %s\nsecret %s", key, secondary);
    else if (entry->type == 802)
        snprintf(input, sizeof(input), "aha %s\n%s", key, secondary);
    else if (entry->type == 1007)
        snprintf(input, sizeof(input), "briar.openai.azure.com\napi_key %s", key);
    else if (entry->type == 931)
        snprintf(input, sizeof(input), "DefaultEndpointsProtocol=https;AccountName=%s;AccountKey=%s;EndpointSuffix=core.windows.net", secondary, key);
    else if (entry->type == 179)
        snprintf(input, sizeof(input), "anypoint %s\norg %s", key, secondary);
    else if (entry->type == 55)
        snprintf(input, sizeof(input), "auth0 %s\n%s\nfixture-tenant.us.auth0.com", secondary, key);
    else if (entry->type == 1045)
        snprintf(input, sizeof(input), "%s\nbitbucket %s", key, secondary);
    else if (secondary)
        snprintf(input, sizeof(input), "%s %s\n%s %s", entry->keyword, key, entry->keyword, secondary);
    else if (entry->type == 390) snprintf(input, sizeof(input), "%s", key);
    else snprintf(input, sizeof(input), "%s %s", entry->keyword, key);

    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == (entry->type == 42 ? 2u : 1u));
    const br_result *result = &results.items[0];
    CHECK(result->detector_type == entry->type);
    CHECK(result->raw.len == entry->key_len && !memcmp(result->raw.data, key, entry->key_len));
    CHECK(!result->verified && !result->verification_error);
    br_json *part = NULL;
    const char *key_name = entry->type == 1025 ? "id" : entry->type == 1018 ? "password" : entry->type == 931 ? "account_key" : (entry->type == 957 || entry->type == 1019) ? "url" : (entry->type == 2 || entry->type == 959) ? "access_key_id" : entry->type == 1045 ? "secret" :
                           entry->type == 1032 || entry->type == 55 ? "client_secret" :
                           entry->type == 375 || entry->type == 1014 || entry->type == 1015 ||
                           entry->type == 181 || entry->type == 1042 || entry->type == 110 ||
                           entry->type == 1047 || entry->type == 1046 ? "token" : "key";
    CHECK(json_object_object_get_ex(result->secret_parts, key_name, &part));
    CHECK(!strcmp(json_object_get_string(part), key));
    CHECK(json_object_object_length(result->secret_parts) == (session || entry->type == 1025 ? 3 : secondary ? 2 : 1));
    if (entry->type == 1025) {
        CHECK(json_object_object_get_ex(result->secret_parts, "secret", &part));
        CHECK(!strcmp(json_object_get_string(part), "AQIDBA=="));
    }
    if (session) {
        CHECK(json_object_object_get_ex(result->secret_parts, "session_token", &part));
        CHECK(!strcmp(json_object_get_string(part), session));
    }
    if (secondary) {
        CHECK(json_object_object_get_ex(result->secret_parts, secondary_name, &part));
        CHECK(!strcmp(json_object_get_string(part), secondary));
        char raw_v2[sizeof(key) + sizeof(secondary_buffer) + sizeof(session_buffer) + 2];
        if (entry->type == 1025) snprintf(raw_v2, sizeof(raw_v2), "Endpoint=%s;Id=%s;Secret=AQIDBA==", secondary, key);
        else if (session) snprintf(raw_v2, sizeof(raw_v2), "%s:%s:%s", key, secondary, session);
        else if (entry->type == 931) snprintf(raw_v2, sizeof(raw_v2), "{\"accountName\":\"%s\",\"accountKey\":\"%s\"}", secondary, key);
        else if (entry->type == 971) snprintf(raw_v2, sizeof(raw_v2), "key: %s account_url: %s", key, secondary);
        else if (entry->type == 55 || entry->type == 1018) snprintf(raw_v2, sizeof(raw_v2), "%s%s", secondary, key);
        else if (entry->type == 170 || entry->type == 1032 || entry->type == 1052) snprintf(raw_v2, sizeof(raw_v2), "%s:%s", secondary, key);
        else snprintf(raw_v2, sizeof(raw_v2), entry->type == 1019 || entry->type == 2 || entry->type == 375 || entry->type == 1045 ||
                      entry->type == 1047 || entry->type == 1046 ? "%s:%s" : "%s%s", key, secondary);
        CHECK(result->raw_v2.len == strlen(raw_v2));
        CHECK(!memcmp(result->raw_v2.data, raw_v2, strlen(raw_v2)));
    } else CHECK(!result->raw_v2.data && !result->raw_v2.len);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *const *detectors = NULL;
    size_t count = 0;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_registry(&detectors, &count, &error) == 0 && error == NULL);
    CHECK(count == sizeof(expected) / sizeof(expected[0]));
    CHECK(!br_detector_type_name(-1));
    CHECK(!br_detector_type_name(1)); /* AMQP has no implementation yet. */
    CHECK(!br_detector_is_default(NULL, NULL));
    br_detector missing = {.type = 1};
    CHECK(!br_detector_is_default(&missing, NULL));
    br_json *flags = json_object_new_object();
    CHECK(flags && json_object_object_add(flags, "all", json_object_new_boolean(true)) == 0);
    for (size_t i = 0; i < count; ++i) {
        const br_detector *detector = detectors[i];
        const registration *entry = &expected[i];
        CHECK(detector->type == entry->type && detector->version == entry->version);
        CHECK(!strcmp(detector->name, entry->name));
        CHECK(!strcmp(br_detector_type_name(detector->type), entry->name));
        CHECK(detector->description && detector->description[0]);
        CHECK(detector->custom_name && !detector->custom_name[0]);
        CHECK(detector->nkeywords == (entry->type == 931 ? 15u : entry->type == 3 && entry->version == 1 ? 6u :
              entry->type == 2 || entry->type == 181 || entry->type == 1047 ? 3u :
              entry->type == 907 || entry->type == 170 || entry->type == 933 || entry->type == 1046 || entry->type == 971 || entry->type == 1013 || entry->type == 1018 ? 2u : 1u));
        CHECK(!strcmp(detector->keywords[0], entry->keyword));
        if (entry->type == 3 && entry->version == 1) {
            const char *aliases[] = {"az", "entra", "msal", "login.microsoftonline.com", ".onmicrosoft.com"};
            for (size_t j = 0; j < 5; ++j) CHECK(!strcmp(detector->keywords[j + 1], aliases[j]));
        }
        if (entry->type == 1018) CHECK(!strcmp(detector->keywords[1], ".scm.azure-api.net"));
        if (entry->type == 1013) CHECK(!strcmp(detector->keywords[1], "1.A"));
        if (entry->type == 971) CHECK(!strcmp(detector->keywords[1], ".table.cosmos.azure.com"));
        if (entry->type == 907) CHECK(!strcmp(detector->keywords[1], "alcht_"));
        if (entry->type == 170) CHECK(!strcmp(detector->keywords[1], "docsearch"));
        if (entry->type == 933) CHECK(!strcmp(detector->keywords[1], "sk-ant-admin01"));
        if (entry->type == 2) {
            CHECK(!strcmp(detector->keywords[1], "ABIA"));
            CHECK(!strcmp(detector->keywords[2], "ACCA"));
        }
        if (entry->type == 1046) CHECK(!strcmp(detector->keywords[1], "atlassian"));
        if (entry->type == 1047) {
            CHECK(!strcmp(detector->keywords[1], "atlassian"));
            CHECK(!strcmp(detector->keywords[2], "wiki"));
        }
        if (entry->type == 181) {
            CHECK(!strcmp(detector->keywords[1], "jfrog.io"));
            CHECK(!strcmp(detector->keywords[2], "AKCp"));
        }
        CHECK(detector->max_secret_size == (entry->type == 110 ? 5000 : entry->type == 1013 ? 2048 : -1) &&
              detector->start_offset == (entry->type == 1013 ? 4096 : -1) &&
              detector->max_credential_span == entry->span);
        CHECK(detector->state && detector->scan);
        if (entry->type == 957 || entry->type == 1019) {
            char *reason = NULL;
            CHECK(detector->false_positive && !detector->false_positive(detector, NULL, &reason));
            CHECK(reason && !strcmp(reason, ""));
            free(reason);
        } else CHECK(!detector->false_positive);
        if (entry->type == 2 || entry->type == 959) CHECK(detector->clean && detector->clean_always);
        else CHECK(!detector->clean && !detector->clean_always);
        if (entry->type == 181 || entry->type == 1042 || entry->type == 1047) {
            CHECK(detector->validate_endpoints && detector->cloud_endpoint);
            CHECK(!detector->cloud_endpoint[0]);
        } else if (entry->type == 1045 || entry->type == 1046) {
            CHECK(detector->validate_endpoints && !detector->cloud_endpoint);
        } else CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
        CHECK(br_detector_is_default(detector, NULL) == entry->enabled);
        CHECK(br_detector_is_default(detector, flags) == entry->enabled);
        br_detector copied = *detector;
        CHECK(br_detector_is_default(&copied, NULL) == entry->enabled);
        copied.version = 77;
        CHECK(!br_detector_is_default(&copied, NULL));
        copied.version = detector->version;
        copied.custom_name = "custom";
        CHECK(!br_detector_is_default(&copied, NULL));
        for (size_t j = 0; j < i; ++j) {
            CHECK(detector != detectors[j]);
            CHECK(detector->type != detectors[j]->type || detector->version != detectors[j]->version);
        }
        check_dispatch(detector, entry);
    }
    json_object_put(flags);
    const br_detector *const *again = NULL;
    size_t nagain = 0;
    CHECK(br_registry(&again, &nagain, &error) == 0 && !error && again == detectors && nagain == count);
    CHECK(br_registry(NULL, &nagain, &error) != 0 && error && nagain == 0);
    free(error); error = NULL;
    CHECK(br_registry(&again, NULL, &error) != 0 && error && !again);
    free(error);
    return test_finish("Registry identities, defaults and dispatch");
}
