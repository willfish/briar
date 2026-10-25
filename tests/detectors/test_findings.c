/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/findings.h"
#include "../support/detector_test.h"

int main(void)
{
    const unsigned char key[] = {'a', 0, 'b'};
    br_result result = {0};
    CHECK(br_finding_key_bytes(&result, 521, (br_slice){key, sizeof(key)}, "key") == 0);
    CHECK(result.detector_type == 521);
    CHECK(result.raw.len == sizeof(key) && !memcmp(result.raw.data, key, sizeof(key)));
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(result.secret_parts, "key", &part));
    CHECK(json_object_get_string_len(part) == (int)sizeof(key));
    CHECK(!memcmp(json_object_get_string(part), key, sizeof(key)));
    CHECK(!result.raw_v2.data && !result.raw_v2.len && !result.verified);
    br_result_clear(&result);

    CHECK(br_finding_pair(&result, 431, "first", "key", "second", "id") == 0);
    CHECK(result.raw.len == 5 && !memcmp(result.raw.data, "first", 5));
    CHECK(result.raw_v2.len == 11 && !memcmp(result.raw_v2.data, "firstsecond", 11));
    CHECK(json_object_object_length(result.secret_parts) == 2);
    CHECK(json_object_object_get_ex(result.secret_parts, "key", &part));
    CHECK(!strcmp(json_object_get_string(part), "first"));
    CHECK(json_object_object_get_ex(result.secret_parts, "id", &part));
    CHECK(!strcmp(json_object_get_string(part), "second"));
    CHECK(!result.verified && !result.verification_from_cache && !result.verification_error);
    CHECK(!result.extra_data && !result.structured_data && !result.redacted);
    br_result_clear(&result);
    CHECK(!result.raw.data && !result.raw_v2.data && !result.secret_parts);
    return test_finish("Finding construction");
}
