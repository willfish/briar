/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/mongodb/mongodb.go.
 * Verification stops at the missing native driver. It never dials or resolves. */
#include "detectors.h"
#include "findings.h"
#include "../go_url.h"

#include <json-c/json.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *canonical, *password, *host, *username, *database;
    size_t canonical_len, password_len;
} mongo_item;

typedef struct { mongo_item *items; size_t len, cap; } mongo_items;

static int mongo_fail(char **error, const char *message)
{
    if (error && !*error) *error = strdup(message);
    return -1;
}

static void mongo_items_clear(mongo_items *items)
{
    if (!items) return;
    for (size_t i = 0; i < items->len; ++i) {
        free(items->items[i].canonical);
        free(items->items[i].password);
        free(items->items[i].host);
        free(items->items[i].username);
        free(items->items[i].database);
    }
    free(items->items);
    memset(items, 0, sizeof(*items));
}

static char *mongo_dup(br_slice value)
{
    if (value.len == SIZE_MAX) return NULL;
    char *copy = malloc(value.len + 1);
    if (!copy) return NULL;
    if (value.len) memcpy(copy, value.data, value.len);
    copy[value.len] = '\0';
    return copy;
}

static bool mongo_space(unsigned char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}

static br_slice mongo_trim(br_slice value)
{
    while (value.len && mongo_space(value.data[0])) {
        value.data++;
        value.len--;
    }
    while (value.len && mongo_space(value.data[value.len - 1])) value.len--;
    return value;
}

static int mongo_replace_amp(br_slice input, br_bytes *out)
{
    *out = (br_bytes){0};
    if (input.len == SIZE_MAX) return -1;
    size_t extra = 0;
    for (size_t i = 0; i < input.len;)
        if (input.len - i >= 5 && !memcmp(input.data + i, "&amp;", 5)) { extra += 4; i += 5; }
        else ++i;
    if (extra > input.len) return -1;
    out->data = malloc(input.len - extra + 1);
    if (!out->data) return -1;
    size_t n = 0;
    for (size_t i = 0; i < input.len;) {
        if (input.len - i >= 5 && !memcmp(input.data + i, "&amp;", 5)) {
            out->data[n++] = '&';
            i += 5;
        } else out->data[n++] = input.data[i++];
    }
    out->data[n] = '\0';
    out->len = n;
    return 0;
}

static int mongo_query_escape(br_slice value, br_bytes *out)
{
    *out = (br_bytes){0};
    size_t need = 0;
    for (size_t i = 0; i < value.len; ++i) {
        unsigned char c = value.data[i];
        bool plain = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                     (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~';
        size_t extra = c == ' ' || plain ? 1 : 3;
        if (need > SIZE_MAX - extra - 1) return -1;
        need += extra;
    }
    out->data = malloc(need + 1);
    if (!out->data) return -1;
    size_t n = 0;
    static const char hex[] = "0123456789ABCDEF";
    for (size_t i = 0; i < value.len; ++i) {
        unsigned char c = value.data[i];
        bool plain = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                     (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~';
        if (c == ' ') out->data[n++] = '+';
        else if (plain) out->data[n++] = c;
        else {
            out->data[n++] = '%';
            out->data[n++] = (unsigned char)hex[c >> 4];
            out->data[n++] = (unsigned char)hex[c & 0xf];
        }
    }
    out->data[n] = '\0';
    out->len = n;
    return 0;
}

typedef struct { br_bytes key, value; } mongo_pair;
typedef struct { mongo_pair *items; size_t len, cap; } mongo_pairs;

static void mongo_pairs_clear(mongo_pairs *pairs)
{
    if (!pairs) return;
    for (size_t i = 0; i < pairs->len; ++i) {
        free(pairs->items[i].key.data);
        free(pairs->items[i].value.data);
    }
    free(pairs->items);
    memset(pairs, 0, sizeof(*pairs));
}

static int mongo_pairs_push(mongo_pairs *pairs, br_bytes key, br_bytes value)
{
    if (pairs->len == pairs->cap) {
        if (pairs->cap > SIZE_MAX / sizeof(*pairs->items) / 2) return -1;
        size_t cap = pairs->cap ? pairs->cap * 2 : 8;
        mongo_pair *items = realloc(pairs->items, cap * sizeof(*items));
        if (!items) return -1;
        pairs->items = items;
        pairs->cap = cap;
    }
    pairs->items[pairs->len++] = (mongo_pair){key, value};
    return 0;
}

static int mongo_decode_copy(br_slice raw, bool query, br_bytes *out, char **error)
{
    bool valid = false;
    if (br_go_url_decode(raw, query, out, &valid, error) != 0) return -1;
    if (!valid) {
        free(out->data);
        *out = (br_bytes){0};
        return 1;
    }
    return 0;
}

static int mongo_parse_query(br_slice query, mongo_pairs *pairs, char **error)
{
    size_t segments = 1;
    for (size_t i = 0; i < query.len; ++i)
        if (query.data[i] == '&' && ++segments > 10000) return 0;
    for (size_t at = 0; at < query.len;) {
        br_slice tail = {query.data + at, query.len - at};
        size_t amp = br_slice_find(tail, (br_slice){(const unsigned char *)"&", 1}, 0);
        br_slice pair = {tail.data, amp == SIZE_MAX ? tail.len : amp};
        at += pair.len + (amp != SIZE_MAX);
        if (!pair.len || br_slice_find(pair, (br_slice){(const unsigned char *)";", 1}, 0) != SIZE_MAX)
            continue;
        size_t equal = br_slice_find(pair, (br_slice){(const unsigned char *)"=", 1}, 0);
        br_slice name = {pair.data, equal == SIZE_MAX ? pair.len : equal};
        br_slice value = equal == SIZE_MAX ? (br_slice){0} : (br_slice){pair.data + equal + 1, pair.len - equal - 1};
        br_bytes decoded_name = {0}, decoded_value = {0};
        int name_rc = mongo_decode_copy(name, true, &decoded_name, error);
        int value_rc = name_rc == 0 ? mongo_decode_copy(value, true, &decoded_value, error) : 0;
        if (name_rc < 0 || value_rc < 0) {
            free(decoded_name.data);
            free(decoded_value.data);
            return -1;
        }
        if (name_rc > 0 || value_rc > 0) {
            free(decoded_name.data);
            free(decoded_value.data);
            continue;
        }
        if (mongo_pairs_push(pairs, decoded_name, decoded_value) != 0) {
            free(decoded_name.data);
            free(decoded_value.data);
            return mongo_fail(error, "cannot store MongoDB query");
        }
    }
    return 0;
}

static int mongo_key_cmp(const void *left, const void *right)
{
    const char *a = *(const char *const *)left, *b = *(const char *const *)right;
    return strcmp(a, b);
}

static int mongo_encode_query(mongo_pairs *pairs, br_bytes *out, char **error)
{
    *out = (br_bytes){0};
    bool saw_tls = false, tls_false = false;
    for (size_t i = 0; i < pairs->len; ++i) {
        if (pairs->items[i].key.len == 3 && !memcmp(pairs->items[i].key.data, "tls", 3)) {
            if (!saw_tls)
                tls_false = pairs->items[i].value.len == 5 &&
                            !memcmp(pairs->items[i].value.data, "false", 5);
            saw_tls = true;
        }
    }
    if (saw_tls) {
        size_t kept = 0;
        for (size_t i = 0; i < pairs->len; ++i) {
            if (pairs->items[i].key.len == 3 && !memcmp(pairs->items[i].key.data, "tls", 3)) {
                free(pairs->items[i].key.data);
                free(pairs->items[i].value.data);
                continue;
            }
            pairs->items[kept++] = pairs->items[i];
        }
        pairs->len = kept;
        br_bytes key = {0}, value = {0};
        key.data = (unsigned char *)strdup("tls");
        value.data = (unsigned char *)strdup(tls_false ? "false" : "true");
        if (!key.data || !value.data) {
            free(key.data);
            free(value.data);
            return mongo_fail(error, "cannot normalize MongoDB tls");
        }
        key.len = 3;
        value.len = tls_false ? 5 : 4;
        if (mongo_pairs_push(pairs, key, value) != 0) {
            free(key.data);
            free(value.data);
            return mongo_fail(error, "cannot store MongoDB tls");
        }
    }
    if (pairs->len > SIZE_MAX / sizeof(const char *)) return mongo_fail(error, "MongoDB query is too large");
    const char **keys = calloc(pairs->len ? pairs->len : 1, sizeof(*keys));
    if (!keys) return mongo_fail(error, "cannot sort MongoDB query");
    size_t nkeys = 0;
    for (size_t i = 0; i < pairs->len; ++i) {
        bool seen = false;
        for (size_t j = 0; j < nkeys; ++j)
            if (!strcmp(keys[j], (const char *)pairs->items[i].key.data)) seen = true;
        if (!seen) keys[nkeys++] = (const char *)pairs->items[i].key.data;
    }
    qsort(keys, nkeys, sizeof(*keys), mongo_key_cmp);
    br_bytes encoded = {0};
    for (size_t k = 0; k < nkeys; ++k) {
        for (size_t i = 0; i < pairs->len; ++i) {
            if (strcmp((const char *)pairs->items[i].key.data, keys[k])) continue;
            br_bytes ek = {0}, ev = {0};
            if (mongo_query_escape((br_slice){pairs->items[i].key.data, pairs->items[i].key.len}, &ek) != 0 ||
                mongo_query_escape((br_slice){pairs->items[i].value.data, pairs->items[i].value.len}, &ev) != 0) {
                free(ek.data);
                free(ev.data);
                free(keys);
                free(encoded.data);
                return mongo_fail(error, "cannot encode MongoDB query");
            }
            size_t fixed = encoded.len ? 3 : 2; /* separators and terminator */
            if (encoded.len > SIZE_MAX - fixed || ek.len > SIZE_MAX - fixed - encoded.len ||
                ev.len > SIZE_MAX - fixed - encoded.len - ek.len) {
                free(ek.data); free(ev.data); free(keys); free(encoded.data);
                return mongo_fail(error, "MongoDB query is too large");
            }
            size_t next = encoded.len + (encoded.len ? 1 : 0) + ek.len + 1 + ev.len;
            unsigned char *grown = realloc(encoded.data, next + 1);
            if (!grown) {
                free(ek.data);
                free(ev.data);
                free(keys);
                free(encoded.data);
                return mongo_fail(error, "cannot encode MongoDB query");
            }
            encoded.data = grown;
            if (encoded.len) encoded.data[encoded.len++] = '&';
            memcpy(encoded.data + encoded.len, ek.data, ek.len);
            encoded.len += ek.len;
            encoded.data[encoded.len++] = '=';
            memcpy(encoded.data + encoded.len, ev.data, ev.len);
            encoded.len += ev.len;
            encoded.data[encoded.len] = '\0';
            free(ek.data);
            free(ev.data);
        }
    }
    free(keys);
    *out = encoded;
    return 0;
}

static int mongo_add(mongo_items *items, br_slice canonical, br_slice password,
                     const br_go_url_parts *parts, char **error)
{
    for (size_t i = 0; i < items->len; ++i) {
        if (items->items[i].canonical_len == canonical.len &&
            !memcmp(items->items[i].canonical, canonical.data, canonical.len)) {
            char *next = mongo_dup(password);
            if (!next) return mongo_fail(error, "cannot store MongoDB password");
            free(items->items[i].password);
            items->items[i].password = next;
            items->items[i].password_len = password.len;
            return 0;
        }
    }
    if (items->len == items->cap) {
        if (items->cap > SIZE_MAX / sizeof(*items->items) / 2)
            return mongo_fail(error, "too many MongoDB matches");
        size_t cap = items->cap ? items->cap * 2 : 4;
        mongo_item *grown = realloc(items->items, cap * sizeof(*grown));
        if (!grown) return mongo_fail(error, "cannot store MongoDB match");
        items->items = grown;
        items->cap = cap;
    }
    mongo_item item = {0};
    item.canonical = mongo_dup(canonical);
    item.password = mongo_dup(password);
    if (!item.canonical || !item.password) {
        free(item.canonical);
        free(item.password);
        return mongo_fail(error, "cannot store MongoDB match");
    }
    item.canonical_len = canonical.len;
    item.password_len = password.len;
    if (parts->host.len) {
        item.host = mongo_dup(parts->host);
        if (!item.host) {
            free(item.canonical);
            free(item.password);
            return mongo_fail(error, "cannot store MongoDB host");
        }
    }
    if (parts->has_user && parts->raw_user.len) {
        br_bytes user = {0};
        bool valid = false;
        if (br_go_url_decode(parts->raw_user, false, &user, &valid, error) != 0) {
            free(item.canonical);
            free(item.password);
            free(item.host);
            return -1;
        }
        if (valid && user.len) {
            item.username = (char *)user.data;
        } else free(user.data);
    }
    if (parts->raw_path.len) {
        br_bytes path = {0};
        bool valid = false;
        if (br_go_url_decode(parts->raw_path, false, &path, &valid, error) != 0) {
            free(item.canonical);
            free(item.password);
            free(item.host);
            free(item.username);
            return -1;
        }
        br_slice database = {path.data, path.len};
        if (valid && database.len && database.data[0] == '/') {
            database.data++;
            database.len--;
        }
        if (valid && database.len) item.database = mongo_dup(database);
        free(path.data);
        if (database.len && valid && !item.database) {
            free(item.canonical);
            free(item.password);
            free(item.host);
            free(item.username);
            return mongo_fail(error, "cannot store MongoDB database");
        }
    }
    items->items[items->len++] = item;
    return 0;
}

static int mongo_extra_put(br_json *object, const char *name, const char *value)
{
    br_json *part = json_object_new_string(value);
    if (!part || json_object_object_add(object, name, part) != 0) {
        json_object_put(part);
        return -1;
    }
    return 0;
}

static int mongo_result(const br_detector *detector, const mongo_item *item, const br_scan_ctx *ctx,
                        bool verify, br_result *result, char **error)
{
    br_slice canonical = {(const unsigned char *)item->canonical, item->canonical_len};
    if (br_finding_key_bytes(result, detector->type, canonical, "key") != 0)
        return mongo_fail(error, "cannot create MongoDB result");
    result->extra_data = json_object_new_object();
    if (!result->extra_data ||
        mongo_extra_put(result->extra_data, "rotation_guide",
                        "https://howtorotate.com/docs/tutorials/mongo/") != 0)
        return mongo_fail(error, "cannot create MongoDB extra data");
    if (item->host && mongo_extra_put(result->extra_data, "host", item->host) != 0)
        return mongo_fail(error, "cannot store MongoDB host");
    if (item->username && mongo_extra_put(result->extra_data, "username", item->username) != 0)
        return mongo_fail(error, "cannot store MongoDB username");
    if (item->database && mongo_extra_put(result->extra_data, "database", item->database) != 0)
        return mongo_fail(error, "cannot store MongoDB database");
    if (!verify) return 0;
    (void)ctx;
    /* ApplyURI/Connect is the reached operation. No DNS, dial, or credential use. */
    const char *cause = "unsupported: MongoDB wire verification is not available";
    br_slice password = {(const unsigned char *)item->password, item->password_len};
    if (br_result_set_verification_error(result, cause, &password, 1) != 0)
        return mongo_fail(error, "cannot set MongoDB verification error");
    return 0;
}

typedef struct {
    br_slice input;
    const br_regex *placeholder;
    mongo_items *items;
    char *error;
} mongo_walk;

static int mongo_mark(void *user, const br_span *groups, size_t ngroups)
{
    (void)groups;
    (void)ngroups;
    *(bool *)user = true;
    return 0;
}

static int mongo_emit(void *user, const br_span *groups, size_t ngroups)
{
    mongo_walk *walk = user;
    if (ngroups < 4 || groups[1].begin == SIZE_MAX || groups[3].begin == SIZE_MAX ||
        groups[1].end > walk->input.len || groups[3].end > walk->input.len ||
        groups[3].end < groups[3].begin || groups[1].end < groups[1].begin)
        return mongo_fail(&walk->error, "invalid MongoDB capture");
    br_slice conn = mongo_trim((br_slice){walk->input.data + groups[1].begin,
                                         groups[1].end - groups[1].begin});
    br_slice password = {walk->input.data + groups[3].begin, groups[3].end - groups[3].begin};
    if (!password.len) return 0;
    bool placeholder = false;
    char *regex_error = NULL;
    if (br_regex_each(walk->placeholder, password, mongo_mark, &placeholder, &regex_error) != 0) {
        mongo_fail(&walk->error, regex_error ? regex_error : "cannot filter MongoDB password");
        free(regex_error);
        return -1;
    }
    free(regex_error);
    if (placeholder) return 0;
    br_bytes replaced = {0};
    if (mongo_replace_amp(conn, &replaced) != 0)
        return mongo_fail(&walk->error, "cannot normalize MongoDB connection string");
    br_go_url_parts parts = {0};
    br_go_url_error parsed = {0};
    char *fatal = NULL;
    int parsed_rc = br_go_url_parse((br_slice){replaced.data, replaced.len}, &parts, &parsed, &fatal);
    if (parsed_rc != 0) {
        mongo_fail(&walk->error, fatal ? fatal : "cannot parse MongoDB connection string");
        free(fatal);
        br_go_url_clear(&parts);
        free(replaced.data);
        return -1;
    }
    if (parsed.kind != BR_GO_URL_OK) {
        br_go_url_clear(&parts);
        free(replaced.data);
        return 0;
    }
    br_bytes query = {0};
    br_slice prefix = {replaced.data, replaced.len};
    if (parts.raw_query.len || parts.force_query) {
        mongo_pairs pairs = {0};
        if (mongo_parse_query(parts.raw_query, &pairs, &walk->error) != 0 ||
            mongo_encode_query(&pairs, &query, &walk->error) != 0) {
            mongo_pairs_clear(&pairs);
            br_go_url_clear(&parts);
            free(replaced.data);
            return -1;
        }
        mongo_pairs_clear(&pairs);
        size_t question = br_slice_find(prefix, (br_slice){(const unsigned char *)"?", 1}, 0);
        if (question != SIZE_MAX) prefix.len = question;
    }
    size_t fixed = query.len || parts.force_query ? 2 : 1;
    if (prefix.len > SIZE_MAX - fixed || query.len > SIZE_MAX - fixed - prefix.len) {
        free(query.data); br_go_url_clear(&parts); free(replaced.data);
        return mongo_fail(&walk->error, "MongoDB connection string is too large");
    }
    size_t canonical_len = prefix.len + (query.len || parts.force_query ? 1 + query.len : 0);
    unsigned char *canonical = malloc(canonical_len + 1);
    if (!canonical) {
        free(query.data);
        br_go_url_clear(&parts);
        free(replaced.data);
        return mongo_fail(&walk->error, "cannot store MongoDB connection string");
    }
    memcpy(canonical, prefix.data, prefix.len);
    if (query.len || parts.force_query) {
        canonical[prefix.len] = '?';
        if (query.len) memcpy(canonical + prefix.len + 1, query.data, query.len);
    }
    canonical[canonical_len] = '\0';
    int rc = mongo_add(walk->items, (br_slice){canonical, canonical_len}, password, &parts, &walk->error);
    free(canonical);
    free(query.data);
    br_go_url_clear(&parts);
    free(replaced.data);
    return rc;
}

static int mongo_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                      br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    /* WithTimeout panics before extraction when the parent context is nil. */
    if (!ctx) return mongo_fail(error, "cannot create context from nil parent");
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return mongo_fail(error, "invalid or uninitialized MongoDB scan");
    const br_regex *const *patterns = detector->state;
    size_t original_len = out->len;
    mongo_items items = {0};
    mongo_walk walk = {input, patterns[1], &items, NULL};
    char *regex_error = NULL;
    int rc = br_regex_each(patterns[0], input, mongo_emit, &walk, &regex_error);
    if (walk.error) {
        free(regex_error);
        regex_error = walk.error;
        rc = -1;
    }
    for (size_t i = 0; rc == 0 && i < items.len; ++i) {
        br_result result = {0};
        if (mongo_result(detector, &items.items[i], ctx, verify, &result, &regex_error) != 0 ||
            br_results_push(out, &result) != 0) {
            if (!regex_error) mongo_fail(&regex_error, "cannot append MongoDB result");
            br_result_clear(&result);
            rc = -1;
            break;
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    mongo_items_clear(&items);
    if (error) *error = regex_error;
    else free(regex_error);
    return rc == 0 ? 0 : -1;
}

static const char *const mongo_keywords[] = {"mongodb"};
static br_regex *mongo_patterns[2];
static bool mongo_never_false_positive(const br_detector *detector, const br_result *result, char **reason)
{
    (void)detector;
    (void)result;
    if (reason) *reason = strdup("");
    return false;
}
static br_detector mongo_detector = {
    .type = 895, .version = 0, .name = "MongoDB", .custom_name = "",
    .description = "MongoDB is a NoSQL database that uses a document-oriented data model. MongoDB credentials can be used to access and manipulate the database.",
    .keywords = mongo_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = mongo_scan, .state = mongo_patterns, .false_positive = mongo_never_false_positive,
};

int br_mongodb_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return mongo_fail(error, "invalid MongoDB detector output");
    *out = NULL;
    if (!mongo_patterns[0] &&
        (br_regex_compile("\\b(mongodb(?:\\+srv)?://([^\\t\\n\\f\\r ]{3,50}):([^\\t\\n\\f\\r ]{3,88})@([-.%\\w]+(?::\\d{1,5})?(?:,[-.%\\w]+(?::\\d{1,5})?)*)(?:/([\\w-]+)?(\\?\\w+=[\\w@/.$-]+(?:&(?:amp;)?\\w+=[\\w@/.$-]+)*)?)?)(?:\\b|$)",
                          &mongo_patterns[0], error) != 0 ||
         br_regex_compile("^[xX]+|\\*+$", &mongo_patterns[1], error) != 0))
        return -1;
    *out = &mongo_detector;
    return 0;
}
