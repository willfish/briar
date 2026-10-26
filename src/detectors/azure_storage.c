/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/azure_storage/storage.go. */
#include "detectors.h"
#include "azure_shared_key.h"
#include "captures.h"
#include "findings.h"

#include <json-c/json.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct { br_regex *name, *key; } storage_patterns;
typedef struct { br_slice input; br_captures names; char *error; } storage_names;
typedef struct { char *data; size_t len, cap; } storage_text;
static const char emulator_key[] =
    "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static int candidate_cause(char **cause, const char *message)
{
    *cause = strdup(message);
    return *cause ? 1 : -1;
}

static int collect_names(void *user, const br_span *groups, size_t ngroups)
{
    storage_names *names = user;
    if (ngroups < 3) return fail(&names->error, "invalid Azure Storage name capture");
    br_span span = groups[1].begin != SIZE_MAX && groups[1].end > groups[1].begin ? groups[1] : groups[2];
    if (span.begin == SIZE_MAX || span.end <= span.begin || span.end > names->input.len)
        return fail(&names->error, "invalid Azure Storage name capture");
    br_slice value = {names->input.data + span.begin, span.end - span.begin};
    if ((value.len == 16 && !memcmp(value.data, "devstoreaccount1", 16)) ||
        (value.len == 13 && !memcmp(value.data, "storagesample", 13))) return 0;
    return br_captures_push(&names->names, value, true, &names->error);
}

static int add_text(br_json *object, const char *name, const char *text)
{
    br_json *value = json_object_new_string(text);
    if (!value) return -1;
    if (json_object_object_add(object, name, value) != 0) {
        json_object_put(value);
        return -1;
    }
    return 0;
}

static int append_text(storage_text *text, const char *value, size_t len)
{
    if (len > SIZE_MAX - text->len - 1) return -1;
    size_t needed = text->len + len + 1;
    if (needed > text->cap) {
        size_t cap = text->cap ? text->cap : 64;
        while (cap < needed) cap = cap > SIZE_MAX / 2 ? needed : cap * 2;
        char *data = realloc(text->data, cap);
        if (!data) return -1;
        text->data = data;
        text->cap = cap;
    }
    if (len) memcpy(text->data + text->len, value, len);
    text->len += len;
    text->data[text->len] = '\0';
    return 0;
}

static bool named(const xmlNode *node, const char *name)
{
    return node->type == XML_ELEMENT_NODE && !xmlStrcmp(node->name, BAD_CAST name);
}

/* Storage uses encoding/xml struct decoding, not the AWS SDK scalar policy.
 * Return 0 decoded, 1 candidate cause, -1 resource failure. Publish no names
 * until a supported complete UTF-8/XML-1.0 document has parsed successfully. */
static int decode_containers(const br_http_response *response, char **joined, bool *present, char **cause)
{
    *joined = NULL;
    *present = false;
    *cause = NULL;
    if (!response->body.len) return candidate_cause(cause, response->body_error ? response->body_error : "EOF");
    if (response->body.len > INT_MAX)
        return candidate_cause(cause, "unsupported: Azure Storage XML body size");
    xmlParserCtxt *parser = xmlNewParserCtxt();
    if (!parser) return -1;
    xmlDoc *doc = xmlCtxtReadMemory(parser, (const char *)response->body.data, (int)response->body.len,
        NULL, "UTF-8", XML_PARSE_NONET | XML_PARSE_NO_XXE | XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    /* Forced UTF-8 masks the original declaration in doc->encoding. */
    const xmlChar *declared = xmlCtxtGetDeclaredEncoding(parser);
    bool bad_encoding = declared && xmlStrcasecmp(declared, BAD_CAST "UTF-8");
    const xmlError *problem = xmlCtxtGetLastError(parser);
    bool memory_error = problem && problem->code == XML_ERR_NO_MEMORY;
    bool parse_error = problem && problem->level >= XML_ERR_ERROR;
    xmlFreeParserCtxt(parser);
    int rc = 0;
    if (memory_error) rc = -1;
    else if (bad_encoding) rc = candidate_cause(cause, "unsupported: Azure Storage XML encoding");
    else if (doc && doc->version && xmlStrcmp(doc->version, BAD_CAST "1.0"))
        rc = candidate_cause(cause, "unsupported: Azure Storage XML version");
    else if (doc && (doc->intSubset || doc->extSubset))
        rc = candidate_cause(cause, "unsupported: Azure Storage XML DTD");
    else if (!doc || parse_error)
        rc = candidate_cause(cause, response->body_error ? response->body_error :
            "unsupported: Azure Storage XML syntax/whole-document or namespace semantics");
    xmlNode *root = doc ? xmlDocGetRootElement(doc) : NULL;
    if (!rc && !root) rc = candidate_cause(cause, "EOF");
    storage_text names = {0};
    size_t count = 0;
    for (xmlNode *cs = !rc ? root->children : NULL; !rc && cs; cs = cs->next) {
        if (!named(cs, "Containers")) continue;
        for (xmlNode *c = cs->children; !rc && c; c = c->next) {
            if (!named(c, "Container")) continue;
            storage_text name = {0};
            for (xmlNode *field = c->children; !rc && field; field = field->next) {
                if (!named(field, "Name")) continue;
                free(name.data);
                name = (storage_text){0}; /* Last Name wins, including empty. */
                for (xmlNode *part = field->children; !rc && part; part = part->next) {
                    if ((part->type == XML_TEXT_NODE || part->type == XML_CDATA_SECTION_NODE) && part->content)
                        rc = append_text(&name, (const char *)part->content, (size_t)xmlStrlen(part->content));
                }
            }
            if (!rc && count) rc = append_text(&names, ", ", 2);
            if (!rc) rc = append_text(&names, name.data, name.len);
            free(name.data);
            ++count;
        }
    }
    xmlFreeDoc(doc);
    if (!rc && count) {
        *present = true;
        *joined = names.data; /* May be an owned empty string. */
    } else free(names.data);
    /* A complete supported root needs no later read: body_error is ignored
     * here, unlike an incomplete parse. Trailing-document rejection is a gap. */
    return rc;
}

static int verify_storage(const br_scan_ctx *ctx, const char *name, const char *key, br_result *result)
{
    time_t now = time(NULL);
    char date[30];
    if (now == (time_t)-1 || br_azure_http_date_utc((int64_t)now, date) != 0) return -1;
    char to_sign[256], url[128], authorization[128], signature[45];
    int n = snprintf(to_sign, sizeof(to_sign),
        "GET\n\n\n\n\n\n\n\n\n\n\n\nx-ms-date:%s\nx-ms-version:2019-12-12\n/%s/\ncomp:list", date, name);
    if (n < 0 || (size_t)n >= sizeof(to_sign)) return -1;
    br_bytes decoded = {0};
    size_t bad_offset = SIZE_MAX;
    int decoded_status = br_azure_base64_std_decode((br_slice){(const unsigned char *)key, strlen(key)},
                                                   &decoded, &bad_offset);
    /* Source ignores corruption (notably '-') but signs the decoded prefix. */
    int rc = decoded_status < 0 ? -1 : br_azure_hmac_sha256_base64(
        (br_slice){decoded.data, decoded.len}, (br_slice){(unsigned char *)to_sign, (size_t)n}, signature);
    free(decoded.data);
    if (rc) return -1;
    n = snprintf(url, sizeof(url), "https://%s.blob.core.windows.net/?comp=list", name);
    if (n < 0 || (size_t)n >= sizeof(url)) return -1;
    n = snprintf(authorization, sizeof(authorization), "SharedKey %s:%s", name, signature);
    if (n < 0 || (size_t)n >= sizeof(authorization)) return -1;
    const br_header headers[] = {
        {"x-ms-date", date}, {"x-ms-version", "2019-12-12"}, {"Authorization", authorization},
    };
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 3,
        .profile = BR_HTTP_DETECTOR_PUBLIC, .detector_type = 931,
    };
    br_http_response response = {0};
    char *error = NULL, *xml_cause = NULL, *joined = NULL;
    const char *cause = NULL;
    char status_error[80];
    if (br_http_send(ctx, &request, &response, &error) != 0) {
        if (!error || !strstr(error, "no such host")) cause = error ? error : "HTTP transport failed";
    } else {
        switch (response.status) {
        case 200: {
            bool present = false;
            int parsed = decode_containers(&response, &joined, &present, &xml_cause);
            if (parsed < 0) rc = -1;
            else if (parsed) cause = xml_cause;
            else {
                if (present) rc = add_text(result->extra_data, "container_names", joined);
                if (!rc) result->verified = true;
            }
            break;
        }
        case 403: break;
        default:
            snprintf(status_error, sizeof(status_error), "unexpected HTTP response status %d", response.status);
            cause = status_error;
            break;
        }
    }
    if (!rc) {
        br_slice secret = {result->raw.data, result->raw.len};
        rc = br_result_set_verification_error(result, cause, &secret, 1);
    }
    br_http_release(ctx, &response);
    free(error);
    free(xml_cause);
    free(joined);
    return rc;
}

static int storage_result(br_result *result, int32_t type, const char *name, const char *key)
{
    if (br_finding_key(result, type, key, "account_key") != 0) return -1;
    if (add_text(result->secret_parts, "account_name", name) != 0) return -1;
    char raw_v2[192];
    int n = snprintf(raw_v2, sizeof(raw_v2), "{\"accountName\":\"%s\",\"accountKey\":\"%s\"}", name, key);
    if (n < 0 || (size_t)n >= sizeof(raw_v2)) return -1;
    result->raw_v2.data = malloc((size_t)n);
    if (!result->raw_v2.data) return -1;
    memcpy(result->raw_v2.data, raw_v2, (size_t)n);
    result->raw_v2.len = (size_t)n;
    result->extra_data = json_object_new_object();
    if (!result->extra_data) return -1;
    return add_text(result->extra_data, "Account_name", name);
}

static int scan_storage(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                         br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid AzureStorage scan arguments");
    const storage_patterns *compiled = detector->state;
    if (!compiled->name || !compiled->key) return fail(error, "uninitialized AzureStorage patterns");
    storage_names names = {.input = input};
    br_captures keys = {0};
    char *regex_error = NULL;
    int rc = br_regex_each(compiled->name, input, collect_names, &names, &regex_error);
    if (names.error) { free(regex_error); regex_error = names.error; }
    if (error) *error = regex_error;
    else free(regex_error);
    if (!rc && names.names.len) rc = br_captures_find(compiled->key, input, &keys, true, error);
    /* Source maps are unique; this first-seen order is one allowed iteration order. */
    for (size_t a = 0; !rc && a < names.names.len; ++a) {
        for (size_t k = 0; !rc && k < keys.len; ++k) {
            if (!strcmp(keys.items[k], emulator_key)) continue;
            br_result result = {0};
            if (storage_result(&result, detector->type, names.names.items[a], keys.items[k]) != 0 ||
                (verify && verify_storage(ctx, names.names.items[a], keys.items[k], &result) != 0))
                rc = fail(error, "could not create or sign AzureStorage result");
            bool verified = result.verified;
            if (!rc && br_results_push(out, &result) != 0)
                rc = fail(error, "out of memory appending AzureStorage result");
            br_result_clear(&result);
            if (verified) break;
        }
    }
    br_captures_clear(&names.names);
    br_captures_clear(&keys);
    return rc;
}

static storage_patterns patterns;
static const char *const keywords[] = {
    "DefaultEndpointsProtocol=http", "EndpointSuffix", "core.windows.net",
    "AccountName", "Account_Name", "Account.Name", "Account-Name",
    "StorageAccount", "Storage_Account", "Storage.Account", "Storage-Account",
    "AccountKey", "Account_Key", "Account.Key", "Account-Key",
};
static const br_detector storage = {
    .type = 931, .version = 0, .name = "AzureStorage", .custom_name = "",
    .description = "Azure Storage is a Microsoft-managed cloud service that provides storage "
                   "that is highly available, secure, durable, scalable, and redundant. "
                   "Azure Storage Account keys can be used to access and manage data within storage accounts.",
    .keywords = keywords, .nkeywords = sizeof(keywords) / sizeof(keywords[0]),
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_storage,
};

int br_azure_storage_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid AzureStorage detector output");
    *out = NULL;
    /* Scoped DOTALL is language-equivalent to the source's overlapping .|\s. */
    if (!patterns.name && br_regex_compile(
        "(?i:Account[_.-]?Name|Storage[_.-]?(?:Account|Name))(?s:.{0,20}?)\\b([a-z0-9]{3,24})\\b|"
        "([a-z0-9]{3,24})(?i:\\.blob\\.core\\.windows\\.net)", &patterns.name, error) != 0) return -1;
    if (!patterns.key && br_regex_compile(
        "(?i:(?:Access|Account|Storage)[_.-]?Key)(?s:.{0,25}?)([a-zA-Z0-9+/\\-]{86,88}={0,2})",
        &patterns.key, error) != 0) return -1;
    *out = &storage;
    return 0;
}
