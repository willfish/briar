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
};

/* Registration must dispatch real initialized scanners, not metadata stubs. */
static void check_dispatch(const br_detector *detector, const registration *entry)
{
    char key[512], secondary_buffer[82], input[2048];
    test_secret(key, entry->key_len, 0);
    if (entry->type == 303 && entry->version == 1) key[7] = '%';
    if (entry->type == 390) memcpy(key, "aio_", 4);
    const char *secondary = NULL, *secondary_name = NULL;
    switch (entry->type) {
    case 125: secondary = "004207"; secondary_name = "id"; break;
    case 136: secondary = "C7d8E9f0.G1H"; secondary_name = "id"; break;
    case 431: secondary = "c7d8e9f0"; secondary_name = "id"; break;
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
    case 1014: strcpy(key, "Native7.v1.Synthetic_-Payload.1a2b3c"); break;
    case 1015:
        memcpy(key, "patN7c4P9d2R5s8T1.", 18);
        for (size_t i = 0; i < 64; ++i) key[18 + i] = "0123456789abcdef"[i % 16];
        key[82] = '\0';
        break;
    }
    if (entry->type == 197)
        snprintf(input, sizeof(input), "token %s\nsecret %s", key, secondary);
    else if (entry->type == 802)
        snprintf(input, sizeof(input), "aha %s\n%s", key, secondary);
    else if (secondary)
        snprintf(input, sizeof(input), "%s %s\n%s %s", entry->keyword, key, entry->keyword, secondary);
    else if (entry->type == 390) snprintf(input, sizeof(input), "%s", key);
    else snprintf(input, sizeof(input), "%s %s", entry->keyword, key);

    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    const br_result *result = &results.items[0];
    CHECK(result->detector_type == entry->type);
    CHECK(result->raw.len == entry->key_len && !memcmp(result->raw.data, key, entry->key_len));
    CHECK(!result->verified && !result->verification_error);
    br_json *part = NULL;
    const char *key_name = entry->type == 1014 || entry->type == 1015 ? "token" : "key";
    CHECK(json_object_object_get_ex(result->secret_parts, key_name, &part));
    CHECK(!strcmp(json_object_get_string(part), key));
    CHECK(json_object_object_length(result->secret_parts) == (secondary ? 2 : 1));
    if (secondary) {
        CHECK(json_object_object_get_ex(result->secret_parts, secondary_name, &part));
        CHECK(!strcmp(json_object_get_string(part), secondary));
        CHECK(result->raw_v2.len == entry->key_len + strlen(secondary));
        CHECK(!memcmp(result->raw_v2.data, key, entry->key_len));
        CHECK(!memcmp(result->raw_v2.data + entry->key_len, secondary, strlen(secondary)));
    } else CHECK(!result->raw_v2.data && !result->raw_v2.len);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *const *detectors = NULL;
    size_t count = 0, enabled = 0;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_registry(&detectors, &count, &error) == 0 && error == NULL);
    CHECK(count == sizeof(expected) / sizeof(expected[0]));
    CHECK(!br_detector_type_name(-1) && !br_detector_type_name(0));
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
        CHECK(detector->nkeywords == (entry->type == 907 ? 2u : 1u));
        CHECK(!strcmp(detector->keywords[0], entry->keyword));
        if (entry->type == 907) CHECK(!strcmp(detector->keywords[1], "alcht_"));
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
        enabled += br_detector_is_default(detector, NULL);
        for (size_t j = 0; j < i; ++j) {
            CHECK(detector != detectors[j]);
            CHECK(detector->type != detectors[j]->type || detector->version != detectors[j]->version);
        }
        check_dispatch(detector, entry);
    }
    CHECK(enabled == 17);
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
