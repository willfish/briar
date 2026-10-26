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
};

/* Registration must dispatch real initialized scanners, not metadata stubs. */
static void check_dispatch(const br_detector *detector, const registration *entry)
{
    char key[512], secondary_buffer[82], input[2048];
    test_secret(key, entry->key_len, 0);
    if (entry->type == 303 && entry->version == 1) key[7] = '%';
    if (entry->type == 390) memcpy(key, "aio_", 4);
    if (entry->type == 391) memcpy(key, "apify_api_", 10);
    if (entry->type == 484) strcpy(key, "b7c9d2e5f6g-h3j4-k1m0-n2p4-q6r8s1t3u5v7");
    if (entry->type == 588) {
        static const char header[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.";
        memcpy(key, header, sizeof(header) - 1);
        key[sizeof(header) - 1 + 74] = '.';
    }
    const char *secondary = NULL, *secondary_name = NULL;
    switch (entry->type) {
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
    case 125: secondary = "004207"; secondary_name = "id"; break;
    case 136: secondary = "C7d8E9f0.G1H"; secondary_name = "id"; break;
    case 170: secondary = "B7C9D2E5F6"; secondary_name = "id"; break;
    case 179:
        strcpy(key, "b7c9d2e5-f6g8-h3j4-k1m0-n2p4q6r8s1t3");
        secondary = "c7d8e9f0-g1h2-i3j4-k5l6-m7n8o9p0q1r2";
        secondary_name = "organization";
        break;
    case 322:
        test_secret(secondary_buffer, 39, 17);
        secondary = secondary_buffer;
        secondary_name = "username";
        break;
    case 375: secondary = "fixture@example.test"; secondary_name = "id"; break;
    case 431: secondary = "c7d8e9f0"; secondary_name = "id"; break;
    case 453: secondary = "B7c9D2e5F6g8H3j4"; secondary_name = "secret"; break;
    case 693: secondary = "00042"; secondary_name = "id"; break;
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
        for (size_t i = 0; i < entry->key_len; ++i) key[i] = "0123456789abcdef"[i % 16];
        break;
    case 212:
        memcpy(key, "sk_live_", 8);
        test_secret(secondary_buffer, 40, 7);
        secondary = secondary_buffer;
        secondary_name = "id";
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
    case 1014: strcpy(key, "Native7.v1.Synthetic_-Payload.1a2b3c"); break;
    case 1015:
        memcpy(key, "patN7c4P9d2R5s8T1.", 18);
        for (size_t i = 0; i < 64; ++i) key[18 + i] = "0123456789abcdef"[i % 16];
        key[82] = '\0';
        break;
    }
    if (entry->type == 322)
        snprintf(input, sizeof(input), "appcues %s\nappcues %s\nappcues 00427", key, secondary);
    else if (entry->type == 197)
        snprintf(input, sizeof(input), "token %s\nsecret %s", key, secondary);
    else if (entry->type == 802)
        snprintf(input, sizeof(input), "aha %s\n%s", key, secondary);
    else if (entry->type == 179)
        snprintf(input, sizeof(input), "anypoint %s\norg %s", key, secondary);
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
    const char *key_name = entry->type == 1032 ? "client_secret" :
                           entry->type == 375 || entry->type == 1014 || entry->type == 1015 ? "token" : "key";
    CHECK(json_object_object_get_ex(result->secret_parts, key_name, &part));
    CHECK(!strcmp(json_object_get_string(part), key));
    CHECK(json_object_object_length(result->secret_parts) == (secondary ? 2 : 1));
    if (secondary) {
        CHECK(json_object_object_get_ex(result->secret_parts, secondary_name, &part));
        CHECK(!strcmp(json_object_get_string(part), secondary));
        char raw_v2[1024];
        if (entry->type == 170 || entry->type == 1032) snprintf(raw_v2, sizeof(raw_v2), "%s:%s", secondary, key);
        else snprintf(raw_v2, sizeof(raw_v2), entry->type == 375 ? "%s:%s" : "%s%s", key, secondary);
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
    CHECK(!br_detector_type_name(1)); /* AWS has no implementation yet. */
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
        CHECK(detector->nkeywords == (entry->type == 907 || entry->type == 170 || entry->type == 933 ? 2u : 1u));
        CHECK(!strcmp(detector->keywords[0], entry->keyword));
        if (entry->type == 907) CHECK(!strcmp(detector->keywords[1], "alcht_"));
        if (entry->type == 170) CHECK(!strcmp(detector->keywords[1], "docsearch"));
        if (entry->type == 933) CHECK(!strcmp(detector->keywords[1], "sk-ant-admin01"));
        CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 &&
              detector->max_credential_span == entry->span);
        CHECK(detector->state && detector->scan);
        CHECK(!detector->clean && !detector->clean_always && !detector->false_positive);
        CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
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
