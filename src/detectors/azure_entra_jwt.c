/* SPDX-License-Identifier: AGPL-3.0-only */
/* Selected-claims parsing derived from github.com/golang-jwt/jwt/v5 v5.2.3
 * parser.go (MIT, Dave Grijalva and golang-jwt maintainers). See NOTICE.
 * Entra consumers ignore validation errors, but parser stages still matter. */
#include "azure_entra_jwt.h"
#include "json.h"

#include <json-c/json.h>
#include <stdlib.h>
#include <string.h>

/* Default jwt/v5 RawURLEncoding: no padding, ignore CR/LF, non-strict tail
 * bits. The consumer ignores decoder diagnostics, but not its parser stage. */
static int decode_segment(br_slice encoded, br_bytes *out)
{
    out->data = malloc(encoded.len ? encoded.len : 1);
    if (!out->data) return -1;
    unsigned values[4], count = 0;
    for (size_t i = 0; i < encoded.len; ++i) {
        unsigned char c = encoded.data[i];
        if (c == '\r' || c == '\n') continue;
        unsigned value;
        if (c >= 'A' && c <= 'Z') value = c - 'A';
        else if (c >= 'a' && c <= 'z') value = c - 'a' + 26;
        else if (c >= '0' && c <= '9') value = c - '0' + 52;
        else if (c == '-') value = 62;
        else if (c == '_') value = 63;
        else goto invalid;
        values[count++] = value;
        if (count == 4) {
            out->data[out->len++] = (unsigned char)((values[0] << 2) | (values[1] >> 4));
            out->data[out->len++] = (unsigned char)((values[1] << 4) | (values[2] >> 2));
            out->data[out->len++] = (unsigned char)((values[2] << 6) | values[3]);
            count = 0;
        }
    }
    if (count == 1) goto invalid;
    if (count >= 2) out->data[out->len++] = (unsigned char)((values[0] << 2) | (values[1] >> 4));
    if (count == 3) out->data[out->len++] = (unsigned char)((values[1] << 4) | (values[2] >> 2));
    return 0;
invalid:
    free(out->data); *out = (br_bytes){0};
    return 1;
}

static bool exact_name(br_slice name, const char *expected)
{
    return name.len == strlen(expected) && !memcmp(name.data, expected, name.len);
}

static int read_claim(void *user, br_slice name, br_json *value, br_slice encoded)
{
    br_azure_entra_jwt_fields *fields = user;
    br_json **slot = exact_name(name, "app_displayname") ? &fields->app :
                     exact_name(name, "email") ? &fields->email :
                     exact_name(name, "upn") ? &fields->upn :
                     exact_name(name, "unique_name") ? &fields->unique_name : NULL;
    if (!slot) return 0;
    /* A failed float64 conversion assigns nil to THIS map entry and continues
     * decoding. Do not discard other claims or stop at the first overflow. */
    if (value && (json_object_is_type(value, json_type_int) || json_object_is_type(value, json_type_double))) {
        char *cause = NULL;
        int rc = br_json_check_float64_numbers(encoded, &cause);
        free(cause);
        if (rc < 0) return -1;
        if (rc) value = NULL;
    }
    json_object_put(*slot); *slot = json_object_get(value); /* Map null replaces. */
    return 0;
}

void br_azure_entra_jwt_clear(br_azure_entra_jwt_fields *fields)
{
    if (!fields) return;
    json_object_put(fields->app); json_object_put(fields->email);
    json_object_put(fields->upn); json_object_put(fields->unique_name);
    *fields = (br_azure_entra_jwt_fields){0};
}

int br_azure_entra_jwt_read(br_slice access_token, br_azure_entra_jwt_fields *fields, char **error)
{
    if (error) *error = NULL;
    if (!fields || (!access_token.data && access_token.len)) {
        if (error) *error = strdup("invalid Azure JWT input");
        return -1;
    }
    static const unsigned char dot[] = ".";
    br_slice separator = {dot, 1};
    size_t first = br_slice_find(access_token, separator, 0);
    if (first == SIZE_MAX) return 0;
    size_t second = br_slice_find(access_token, separator, first + 1);
    if (second == SIZE_MAX || br_slice_find(access_token, separator, second + 1) != SIZE_MAX) return 0;
    br_bytes header = {0}, claims = {0};
    br_json *root = NULL;
    char *cause = NULL;
    int rc = decode_segment((br_slice){access_token.data, first}, &header);
    if (rc < 0) goto resource;
    if (!rc) rc = br_json_document((br_slice){header.data, header.len}, &root, &cause);
    if (rc < 0) goto resource;
    if (!rc && root && !json_object_is_type(root, json_type_object)) rc = 1;
    if (!rc) rc = br_json_check_float64_numbers((br_slice){header.data, header.len}, &cause);
    if (rc < 0) goto resource;
    if (rc) { rc = 1; goto cleanup; } /* Token exists, but Claims is still nil. */
    json_object_put(root); root = NULL; free(cause); cause = NULL;
    fields->token_present = true;
    rc = decode_segment((br_slice){access_token.data + first + 1, second - first - 1}, &claims);
    if (rc < 0) goto resource;
    if (!rc) {
        rc = br_json_document((br_slice){claims.data, claims.len}, &root, &cause);
        if (rc < 0) goto resource;
        if (!rc && json_object_is_type(root, json_type_object)) {
            rc = br_json_each_member((br_slice){claims.data, claims.len}, read_claim, fields);
            if (rc) goto resource;
        }
    }
    /* Claims is now MapClaims even after claim decoding errors. Method lookup,
     * signature decoding, nil keyfunc and validation cannot change these fields. */
    rc = 0;
    goto cleanup;
resource:
    if (error) *error = strdup("out of memory decoding Azure JWT claims");
    rc = -1;
cleanup:
    json_object_put(root); free(cause); free(header.data); free(claims.data);
    return rc;
}
