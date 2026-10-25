/* SPDX-License-Identifier: AGPL-3.0-only */
#include "findings.h"

#include <json-c/json.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

static int add_part(br_result *result, const char *name, const char *value)
{
    br_json *part = json_object_new_string(value);
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
    br_json *part = json_object_new_string_len(key.data ? (const char *)key.data : "", (int)key.len);
    if (!part) goto failed;
    if (json_object_object_add(result->secret_parts, part_name, part) != 0) {
        json_object_put(part);
        goto failed;
    }
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

int br_finding_pair(br_result *result, int32_t type, const char *key, const char *key_name,
                    const char *secondary, const char *secondary_name)
{
    if (br_finding_key(result, type, key, key_name) != 0) return -1;
    size_t first = result->raw.len, second = strlen(secondary);
    if (second > SIZE_MAX - first) goto failed;
    result->raw_v2.len = first + second;
    result->raw_v2.data = malloc(result->raw_v2.len ? result->raw_v2.len : 1);
    if (!result->raw_v2.data) goto failed;
    memcpy(result->raw_v2.data, key, first);
    memcpy(result->raw_v2.data + first, secondary, second);
    if (add_part(result, secondary_name, secondary) != 0) goto failed;
    return 0;
failed:
    br_result_clear(result);
    return -1;
}
