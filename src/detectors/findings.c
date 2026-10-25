/* SPDX-License-Identifier: AGPL-3.0-only */
#include "findings.h"

#include <json-c/json.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

static int add_part(br_result *result, const char *name, br_slice value)
{
    if ((!value.data && value.len) || value.len > INT_MAX) return -1;
    br_json *part = json_object_new_string_len(value.data ? (const char *)value.data : "",
                                              (int)value.len);
    if (!part) return -1;
    if (json_object_object_add(result->secret_parts, name, part) != 0) {
        json_object_put(part);
        return -1;
    }
    return 0;
}

int br_finding_key_bytes(br_result *result, int32_t type, br_slice key, const char *part_name)
{
    if ((!key.data && key.len) || key.len > INT_MAX) return -1;
    result->detector_type = type;
    result->raw.data = malloc(key.len ? key.len : 1);
    result->secret_parts = json_object_new_object();
    if (!result->raw.data || !result->secret_parts) goto failed;
    if (key.len) memcpy(result->raw.data, key.data, key.len);
    result->raw.len = key.len;
    if (add_part(result, part_name, key) != 0) goto failed;
    return 0;
failed:
    br_result_clear(result);
    return -1;
}

int br_finding_key(br_result *result, int32_t type, const char *key, const char *part_name)
{
    return br_finding_key_bytes(result, type,
                                (br_slice){(const unsigned char *)key, strlen(key)}, part_name);
}

int br_finding_pair_bytes(br_result *result, int32_t type, br_slice key, const char *key_name,
                          br_slice secondary, const char *secondary_name, br_slice separator)
{
    if (br_finding_key_bytes(result, type, key, key_name) != 0) return -1;
    if ((!secondary.data && secondary.len) || (!separator.data && separator.len) ||
        separator.len > SIZE_MAX - key.len || secondary.len > SIZE_MAX - key.len - separator.len)
        goto failed;
    result->raw_v2.len = key.len + separator.len + secondary.len;
    result->raw_v2.data = malloc(result->raw_v2.len ? result->raw_v2.len : 1);
    if (!result->raw_v2.data) goto failed;
    if (key.len) memcpy(result->raw_v2.data, key.data, key.len);
    if (separator.len) memcpy(result->raw_v2.data + key.len, separator.data, separator.len);
    if (secondary.len)
        memcpy(result->raw_v2.data + key.len + separator.len, secondary.data, secondary.len);
    if (add_part(result, secondary_name, secondary) != 0) goto failed;
    return 0;
failed:
    br_result_clear(result);
    return -1;
}

int br_finding_pair(br_result *result, int32_t type, const char *key, const char *key_name,
                    const char *secondary, const char *secondary_name)
{
    return br_finding_pair_bytes(result, type,
                                 (br_slice){(const unsigned char *)key, strlen(key)}, key_name,
                                 (br_slice){(const unsigned char *)secondary, strlen(secondary)},
                                 secondary_name, (br_slice){0});
}
