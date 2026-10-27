/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

int br_couchbase_init(const br_detector **out, char **error);

static const char host[] = "cb.a1.cloud.couchbase.com";
static const char connection[] = "couchbases://cb.a1.cloud.couchbase.com";
static const char unsupported[] = "unsupported: Couchbase native SDK verification is not implemented";
static size_t fail_alloc_size, fail_alloc_after, fail_cause_after, fail_part_after;

/* Target real resource errors, including positive helper returns. No I/O or
 * shared implementation seams are introduced by this test. */
void *malloc(size_t size)
{
    if (fail_alloc_after && size == fail_alloc_size && --fail_alloc_after == 0) return NULL;
    return calloc(1, size);
}

char *strdup(const char *s)
{
    if (fail_cause_after && !strcmp(s, unsupported) && --fail_cause_after == 0) return NULL;
    size_t len = strlen(s) + 1;
    char *copy = malloc(len);
    if (copy) memcpy(copy, s, len);
    return copy;
}

int json_object_object_add(struct json_object *object, const char *name, struct json_object *value)
{
    if (fail_part_after && --fail_part_after == 0) return 1;
    return json_object_object_add_ex(object, name, value, 0);
}

static br_slice text(const char *s) { return (br_slice){(const unsigned char *)s, strlen(s)}; }

static bool equal(br_slice a, br_slice b)
{
    return a.len == b.len && (!a.len || !memcmp(a.data, b.data, a.len));
}

static br_slice part(const br_result *result, const char *name)
{
    br_json *value = NULL;
    CHECK(json_object_object_get_ex(result->secret_parts, name, &value));
    CHECK(value && json_object_is_type(value, json_type_string));
    return (br_slice){(const unsigned char *)json_object_get_string(value), (size_t)json_object_get_string_len(value)};
}

static void check_result(const br_result *result, br_slice conn, br_slice username,
                          br_slice password, bool verify)
{
    CHECK(result->detector_type == 920 && !result->verified && !result->verification_from_cache);
    CHECK(!result->detector_name && !result->raw_v2.data && !result->raw_v2.len);
    CHECK(!result->redacted && !result->extra_data && !result->structured_data);
    CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 3);
    CHECK(equal(part(result, "host"), conn));
    CHECK(equal(part(result, "username"), username));
    CHECK(equal(part(result, "password"), password));
    CHECK(result->raw.data && result->raw.len == username.len + password.len + conn.len + 2);
    size_t at = 0;
    CHECK(!memcmp(result->raw.data, username.data, username.len)); at += username.len;
    CHECK(result->raw.data[at++] == ':');
    CHECK(!memcmp(result->raw.data + at, password.data, password.len)); at += password.len;
    CHECK(result->raw.data[at++] == '@');
    CHECK(!memcmp(result->raw.data + at, conn.data, conn.len));
    CHECK(!result->primary_line && !result->chunk_offset && !result->chunk_offset_set);
    if (verify) {
        CHECK(result->verification_error && !strcmp(result->verification_error, unsupported));
        CHECK(equal((br_slice){result->primary_secret.data, result->primary_secret.len}, conn));
        CHECK(result->primary_secret.data != part(result, "host").data);
        CHECK(result->primary_secret.data != conn.data);
    } else {
        CHECK(!result->verification_error && !result->primary_secret.data && !result->primary_secret.len);
    }
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    CHECK(br_couchbase_init(NULL, &error) == -1 && error && !strcmp(error, "invalid Couchbase detector output"));
    free(error); error = NULL;
    CHECK(br_couchbase_init(NULL, NULL) == -1);
    CHECK(br_couchbase_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_couchbase_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 920 && detector->version == 0 && !strcmp(detector->name, "Couchbase"));
    CHECK(detector->custom_name && !*detector->custom_name);
    CHECK(!strcmp(detector->description, "Couchbase is a distributed NoSQL cloud database. Couchbase credentials can be used to access and modify data within the Couchbase database."));
    CHECK(detector->nkeywords == 2 && !strcmp(detector->keywords[0], "couchbase://") && !strcmp(detector->keywords[1], "couchbases://"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == 1024);
    CHECK(detector->state && detector->scan && !detector->clean && !detector->clean_always && !detector->false_positive);
    CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
    return detector;
}

static void one(const br_detector *detector, br_slice input, const char *username, const char *password)
{
    test_http http = {.response = {.status = 200}};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, false, input.data, input.len);
    if (results.len != (username && password ? 1u : 0u)) {
        fprintf(stderr, "extraction length %zu; expected %u; input=%.*s\n", results.len, username && password ? 1u : 0u,
                (int)input.len, input.data ? (const char *)input.data : "");
        if (results.len) {
            br_slice u = part(&results.items[0], "username"), p = part(&results.items[0], "password");
            fprintf(stderr, "actual username=%.*s password=%.*s\n", (int)u.len, u.data, (int)p.len, p.data);
        }
    }
    CHECK(results.len == (username && password ? 1u : 0u));
    CHECK(!http.calls && !http.releases);
    if (results.len) check_result(&results.items[0], text(connection), text(username), text(password), false);
    br_results_clear(&results);
}

static void hosts(const br_detector *detector)
{
    const struct { const char *value; bool match; } cases[] = {
        {"cb.a1.cloud.couchbase.com", true}, {"couchbase://cb.a1.cloud.couchbase.com", true},
        {"couchbases://cb.a1.cloud.couchbase.com", true}, {"other://cb.a1.cloud.couchbase.com:8091", true},
        {"cb.a1.cloud.couchbase.com.evil", true}, {"\xc3\xa9" "cb.a1.cloud.couchbase.com\xc3\xa9", true},
        {"xcb.a1.cloud.couchbase.com", false}, {"_cb.a1.cloud.couchbase.com", false},
        {"cb.a1.cloud.couchbase.com_", false}, {"cb.a1.cloud.couchbase.comx", false},
        {"CB.a1.cloud.couchbase.com", false}, {"cb.A1.cloud.couchbase.com", false},
        {"cb.a1.cloud.Couchbase.com", false}, {"cb.a-1.cloud.couchbase.com", false},
        {"cb.a_1.cloud.couchbase.com", false}, {"cb..cloud.couchbase.com", false},
    };
    char input[256];
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), "%s\nuser:Name\npass:aA1!\n", cases[i].value);
        one(detector, text(input), cases[i].match ? "Name" : NULL, "aA1!");
    }
    one(detector, (br_slice){0}, NULL, NULL);
    one(detector, text("user:Name\npass:aA1!"), NULL, NULL);
    one(detector, text("cb.a1.cloud.couchbase.com\npass:aA1!"), NULL, NULL);
    one(detector, text("cb.a1.cloud.couchbase.com\nuser:Name"), NULL, NULL);
}

static void common_patterns(const br_detector *detector)
{
    const struct { const char *token, *capture; } users[] = {
        {"user:Name", "Name"}, {"usr:Name", "Name"}, {"xxUsErNAME=Name", "Name"},
        {"u\xc5\xbf" "er:Name", "Name"}, {"u\xc5\xbf" "r:Name", "Name"},
        {"user:abc", NULL}, {"user:'abc", "abc"}, {"user:''''X", "X"},
        {"user:ab\\Cd", "ab\\Cd"}, {"user:abc+def", NULL}, {"user:abcd+efgh", "abcd"},
        {"user:abcd?efgh", "abcd"}, {"user:abcd/efgh", "abcd"}, {"user:abcd=efgh", "abcd"},
        {"user:abcd;tail", "abcd;tail"}, {"user\vName", NULL}, {"user\v:Name", "Name"},
        {"user:ab\vcd", "ab\vcd"}, {"user:\vName", "Name"},
        {"user\tName", "Name"}, {"user\nName", "Name"}, {"user\fName", "Name"},
        {"user\rName", "Name"}, {"user Name", "Name"}, {"user\n= 'Name", "Name"},
        {"user     Name", NULL}, {"user:Name?tail", "Name"},
        {"user:\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9", NULL},
        {"user:Name\xc3\xa9", "Name"},
    };
    const struct { const char *token, *capture; } passwords[] = {
        {"pass:aA1!", "aA1!"}, {"password:aA1!", "aA1!"}, {"xxPaSsWORD:aA1!", "aA1!"},
        {"pa\xc5\xbf\xc5\xbf" "word:aA1!", "aA1!"},
        {"pass:aA1!^tail", "aA1!"}, {"pass:aA1!<tail", "aA1!"}, {"pass:aA1!>tail", "aA1!"},
        {"pass:aA1!;tail", "aA1!"}, {"pass:aA1!.tail", "aA1!"}, {"pass:aA1!*tail", "aA1!"},
        {"pass:aA1!&tail", "aA1!"}, {"pass:aA1!|tail", "aA1!"}, {"pass:aA1!\xc2\xa3" "tail", "aA1!"},
        {"pass:aA1!\\tail", "aA1!\\tail"}, {"pass:aA1!+tail", "aA1!+tail"},
        {"pass:aA1!\vZ", "aA1!\vZ"}, {"pass\vaA1!", NULL}, {"pass\v:aA1!", "aA1!"},
        {"pass:aA1!suffix", "aA1!suffix"}, {"pass:'aA1!',)", "aA1!"},
        {"pass:''\xc2\xa0" "aA1!\xc2\xa0'", "\xc2\xa0" "aA1!\xc2\xa0"},
        {"pass:\xc2\xa0" "aA1!\xc2\xa0", "aA1!"},
        {"pass:aA1'", NULL}, /* Four captured runes, but quote trimming removes the special. */
    };
    char input[512];
    for (size_t i = 0; i < sizeof(users) / sizeof(users[0]); ++i) {
        snprintf(input, sizeof(input), "%s\npass:aA1!\n%s\n", host, users[i].token);
        one(detector, text(input), users[i].capture, "aA1!");
    }
    for (size_t i = 0; i < sizeof(passwords) / sizeof(passwords[0]); ++i) {
        snprintf(input, sizeof(input), "%s\nuser:Name\n%s\n", host, passwords[i].token);
        one(detector, text(input), "Name", passwords[i].capture);
    }
    /* A failed short capture can make the lazy nonspace prefix consume :abc,
     * then use LF as the delimiter and capture the NEXT field's keyword. */
    one(detector, text("cb.a1.cloud.couchbase.com\nuser:abc\npass:aA1!\n"), "pass", "aA1!");
    /* All Go TrimSpace ranges allowed by the capture class, including VT and
     * NEL. ASCII HT/LF/FF/CR/SPACE are excluded by the regex instead. */
    const char spaces[] = "\v\xc2\x85\xc2\xa0\xe1\x9a\x80\xe2\x80\x80\xe2\x80\x8a"
                          "\xe2\x80\xa8\xe2\x80\xa9\xe2\x80\xaf\xe2\x81\x9f\xe3\x80\x80";
    snprintf(input, sizeof(input), "%s\nuser:Name\npass:%saA1!%s\n", host, spaces, spaces);
    one(detector, text(input), "Name", "aA1!");
}

static void rune_limits(const br_detector *detector)
{
    char input[768], token[256], username[128], password[128];
    for (size_t gap = 40; gap <= 41; ++gap) {
        for (int kind = 0; kind < 2; ++kind) {
            size_t at = (size_t)snprintf(token, sizeof(token), "%s", kind ? "pass" : "user");
            for (size_t r = 0; r < gap; ++r) { memcpy(token + at, "\xc2\xa0", 2); at += 2; }
            snprintf(token + at, sizeof(token) - at, ":%s", kind ? "aA1!" : "Name");
            snprintf(input, sizeof(input), "%s\n%s\n%s\n", host, token, kind ? "user:Name" : "pass:aA1!");
            one(detector, text(input), gap == 40 ? "Name" : NULL, "aA1!");
        }
    }
    /* 40 RUNES, not bytes, in both greedy captures. */
    size_t at = 0;
    for (size_t r = 0; r < 39; ++r) { memcpy(username + at, "\xc3\xa9", 2); at += 2; }
    username[at++] = 'Z'; username[at] = '\0';
    memcpy(password, "aA1!", 4); at = 4;
    for (size_t r = 0; r < 36; ++r) { memcpy(password + at, "\xc3\xa9", 2); at += 2; }
    password[at] = '\0';
    snprintf(input, sizeof(input), "%s\nuser:%s\npass:%s\n", host, username, password);
    one(detector, text(input), username, password);
    snprintf(input, sizeof(input), "%s\nuser:%s\npass:%sZ\n", host, username, password);
    one(detector, text(input), username, password); /* No password trailing boundary. */
    memset(username, 'A', 40); username[40] = '\0';
    snprintf(input, sizeof(input), "%s\nuser:%s\npass:aA1!\n", host, username);
    one(detector, text(input), username, "aA1!");
    snprintf(input, sizeof(input), "%s\nuser:%sA\npass:aA1!\n", host, username);
    one(detector, text(input), NULL, "aA1!"); /* Username DOES have a trailing boundary. */

    /* The capture before X is forty quotes; after Matches it is the empty
     * username. Multiple empty transformed captures remain one set member. */
    memset(token, '\'', 41); token[41] = 'X'; token[42] = '\0';
    snprintf(input, sizeof(input), "%s\nuser:%s\nuser:%s\npass:aA1!\n", host, token, token);
    one(detector, text(input), "", "aA1!");
    snprintf(input, sizeof(input), "%s\nuser:Name\npass:''''\n", host);
    one(detector, text(input), "Name", NULL); /* Empty password fails policy. */
}

static void password_policy(const br_detector *detector)
{
    const struct { const char *value; bool valid; } cases[] = {
        {"aA1!", true}, {"AA1!", false}, {"aa1!", false}, {"aAb!", false}, {"aA1a", false},
        {"\xc3\xa9\xc3\x89" "1!", true}, /* Ll and Lu, not ASCII-only. */
        {"a\xc7\x85" "1!", false}, /* Lt is not Lu. */
        {"aA\xd9\xa1!", true}, {"aA\xe2\x85\xab!", true}, {"aA\xc2\xb2!", true}, /* Nd, Nl, No. */
        {"aA1_", true}, {"aA1\xe2\x82\xac", true}, {"aA1\xef\xbf\xbd", true}, /* P, S, real U+FFFD. */
        {"aA1\xcc\x81", false}, /* Mn is neither P nor S. */
        {"a\xe1\xb2\x89" "1!", false}, {"\xe1\xb2\x8a" "A1!", false}, /* Unicode 16 additions are NOT Go 15 case. */
    };
    char input[256];
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        snprintf(input, sizeof(input), "%s\nuser:Name\npass:%s\n", host, cases[i].value);
        one(detector, text(input), "Name", cases[i].valid ? cases[i].value : NULL);
    }
}

static void products(const br_detector *detector)
{
    char input[4096];
    size_t at = (size_t)snprintf(input, sizeof(input),
        "couchbase://%s\ncouchbases://%s\ncb.b2.cloud.couchbase.com\nuser:Name\nuser:'Name\nusr:Else\n", host, host);
    memset(input + at, '.', 2048); at += 2048;
    at += (size_t)snprintf(input + at, sizeof(input) - at, "\npass:aA1!\npassword:'aA1!'\npass:bB2?\npass:invalid\n");
    br_results results = test_scan(detector, NULL, false, input, at);
    CHECK(results.len == 8); /* Independently transformed host x username x password sets. */
    const char *connections[] = {connection, "couchbases://cb.b2.cloud.couchbase.com"};
    const char *users[] = {"Name", "Else"}, *passwords[] = {"aA1!", "bB2?"};
    bool seen[2][2][2] = {{{false}}};
    for (size_t i = 0; i < results.len; ++i) {
        size_t h = equal(part(&results.items[i], "host"), text(connections[0])) ? 0 : 1;
        size_t u = equal(part(&results.items[i], "username"), text(users[0])) ? 0 : 1;
        size_t p = equal(part(&results.items[i], "password"), text(passwords[0])) ? 0 : 1;
        CHECK(!seen[h][u][p]); seen[h][u][p] = true;
        check_result(&results.items[i], text(connections[h]), text(users[u]), text(passwords[p]), false);
    }
    br_results_clear(&results);

    /* Keep composed/decomposed UTF-8 and every byte AFTER NUL independently. */
    static const char binary[] = "cb.a1.cloud.couchbase.com\nuser:ab\0Cx\nusr:ab\0Cy\npass:aA1!\0x\npass:aA1!\0y\n";
    results = test_scan(detector, NULL, false, binary, sizeof(binary) - 1);
    CHECK(results.len == 4);
    bool binary_seen[2][2] = {{false}};
    for (size_t i = 0; i < results.len; ++i) {
        br_slice u = part(&results.items[i], "username"), p = part(&results.items[i], "password");
        CHECK(u.len == 5 && p.len == 6);
        size_t ui = u.data[4] == 'x' ? 0 : 1, pi = p.data[5] == 'x' ? 0 : 1;
        CHECK(!binary_seen[ui][pi]); binary_seen[ui][pi] = true;
        const unsigned char *expected_u = (const unsigned char *)(ui ? "ab\0Cy" : "ab\0Cx");
        const unsigned char *expected_p = (const unsigned char *)(pi ? "aA1!\0y" : "aA1!\0x");
        check_result(&results.items[i], text(connection), (br_slice){expected_u, 5}, (br_slice){expected_p, 6}, false);
    }
    br_results_clear(&results);
    const char unicode[] = "cb.a1.cloud.couchbase.com\nuser:\xc3\xa9" "abc\nuser:e\xcc\x81" "abc\npass:aA1!\n";
    results = test_scan(detector, NULL, false, unicode, sizeof(unicode) - 1);
    CHECK(results.len == 2);
    CHECK(!equal(part(&results.items[0], "username"), part(&results.items[1], "username")));
    br_results_clear(&results);
}

static void unbounded_hosts(const br_detector *detector)
{
    /* Neither a DNS label limit nor an arbitrary candidate/product limit exists
     * in this source. Exercise a long capture and more than 100 products. */
    const size_t label = 8192;
    size_t capacity = label + 8192;
    char *input = malloc(capacity), *conn = malloc(label + 64);
    CHECK(input && conn);
    memcpy(input, "cb.", 3); memset(input + 3, 'a', label);
    size_t at = 3 + label;
    at += (size_t)snprintf(input + at, capacity - at, ".cloud.couchbase.com\nuser:Name\npass:aA1!\n");
    memcpy(conn, "couchbases://cb.", 16); memset(conn + 16, 'a', label);
    strcpy(conn + 16 + label, ".cloud.couchbase.com");
    br_results results = test_scan(detector, NULL, false, input, at);
    CHECK(results.len == 1);
    check_result(&results.items[0], text(conn), text("Name"), text("aA1!"), false);
    br_results_clear(&results);
    at = (size_t)snprintf(input, capacity, "user:Name\npass:aA1!\n");
    for (size_t h = 0; h < 129; ++h)
        at += (size_t)snprintf(input + at, capacity - at, "cb.%zu.cloud.couchbase.com\n", h);
    CHECK(at < capacity);
    results = test_scan(detector, NULL, false, input, at);
    CHECK(results.len == 129);
    for (size_t h = 0; h < results.len; ++h) {
        snprintf(conn, label + 64, "couchbases://cb.%zu.cloud.couchbase.com", h);
        check_result(&results.items[h], text(conn), text("Name"), text("aA1!"), false);
    }
    br_results_clear(&results); free(input); free(conn);
}

static bool cancelled(void *user) { ++*(size_t *)user; return true; }

static void verification_boundary(const br_detector *detector)
{
    char input[] = "couchbase://cb.a1.cloud.couchbase.com\nuser:Couchbase\npass:aA1!\n";
    test_http http = {.response = {.status = 200}};
    br_transport transport = test_transport(&http);
    size_t cancellations = 0;
    br_scan_ctx ctx = {.transport = &transport, .deadline_monotonic_ms = 1,
                       .cancelled = cancelled, .cancel_user = &cancellations};
    for (int mode = 0; mode < 3; ++mode) {
        br_results results = test_scan(detector, mode == 2 ? NULL : &ctx, mode != 0, input, sizeof(input) - 1);
        CHECK(results.len == 1 && !http.calls && !http.releases && !cancellations);
        check_result(&results.items[0], text(connection), text("Couchbase"), text("aA1!"), mode != 0);
        /* Username overlaps the static cause: no invented redaction arguments. */
        if (mode) CHECK(strstr(results.items[0].verification_error, "Couchbase") && !strstr(results.items[0].verification_error, "[REDACTED]"));
        br_results_clear(&results);
    }
    br_results results = test_scan(detector, NULL, true, input, sizeof(input) - 1);
    memset(input, 'x', sizeof(input));
    check_result(&results.items[0], text(connection), text("Couchbase"), text("aA1!"), true);
    br_results_clear(&results);
}

static br_results prior_results(void)
{
    br_result prior = {.detector_type = 12345, .verified = true};
    prior.raw.data = malloc(4); CHECK(prior.raw.data); memcpy(prior.raw.data, "keep", 4); prior.raw.len = 4;
    prior.verification_error = strdup("caller-owned"); CHECK(prior.verification_error);
    br_results results = {0}; CHECK(br_results_push(&results, &prior) == 0);
    return results;
}

static void check_prior(const br_results *results, br_result prior)
{
    CHECK(results->len == 1 && results->items[0].detector_type == 12345 && results->items[0].verified);
    CHECK(results->items[0].raw.data == prior.raw.data && results->items[0].raw.len == 4 && !memcmp(prior.raw.data, "keep", 4));
    CHECK(results->items[0].verification_error == prior.verification_error && !strcmp(prior.verification_error, "caller-owned"));
}

static void invalid_utf8(const br_detector *detector)
{
    static const char input[] = "cb.a1.cloud.couchbase.com\nuser:Name\npass:aA1!\n\xff";
    static const unsigned char prefix[] = {0xff, 'x'};
    const br_slice cases[] = {{(const unsigned char *)input, sizeof(input) - 1}, {prefix, sizeof(prefix)}};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        br_results results = prior_results(); br_result prior = results.items[0]; char *error = NULL;
        CHECK(detector->scan(detector, NULL, true, cases[i], &results, &error) == -1);
        CHECK(error && !strcmp(error, "unsupported: Couchbase extraction of invalid UTF-8 input is not implemented"));
        check_prior(&results, prior); free(error); br_results_clear(&results);
    }
}

static void fatal_errors(const br_detector *detector)
{
    const char input[] = "cb.a1.cloud.couchbase.com\nuser:Name\npass:aA1!\npass:bB2?\n";
    br_slice data = { (const unsigned char *)input, sizeof(input) - 1 };
    br_results results = prior_results(); br_result prior = results.items[0]; char *error = NULL;
    /* A metadata +1 on the second product rolls back the first product even
     * though verification would otherwise retain an unsupported candidate. */
    fail_part_after = 6;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1);
    CHECK(!fail_part_after && error && !strcmp(error, "cannot add Couchbase secret part"));
    check_prior(&results, prior); free(error); error = NULL;

    /* The real sanitized setter returns POSITIVE +1 on its second cause copy. */
    fail_cause_after = 2;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1);
    CHECK(!fail_cause_after && error && !strcmp(error, "cannot set Couchbase verification error"));
    check_prior(&results, prior); free(error); error = NULL;

    /* Primary-secret, raw, and capture allocations fail independently. */
    fail_alloc_size = strlen(connection); fail_alloc_after = 2;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1);
    CHECK(!fail_alloc_after && error && !strcmp(error, "cannot create Couchbase primary secret"));
    check_prior(&results, prior); free(error); error = NULL;
    const char raw_input[] = "cb.a1.cloud.couchbase.com\nuser:abcdefghijklmnopqrstuvwxyzABCDE\npass:aA1!\npass:bB2?\n";
    fail_alloc_size = strlen(connection) + 31 + 4 + 2; fail_alloc_after = 2;
    CHECK(detector->scan(detector, NULL, false, text(raw_input), &results, &error) == -1);
    CHECK(!fail_alloc_after && error && !strcmp(error, "cannot create Couchbase raw"));
    check_prior(&results, prior); free(error); error = NULL;
    fail_alloc_size = strlen(host) + 1; fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, &error) == -1);
    CHECK(!fail_alloc_after && error && !strcmp(error, "out of memory copying detector capture"));
    check_prior(&results, prior); free(error); error = NULL;
    fail_alloc_size = 2 * sizeof(br_span); fail_alloc_after = 1;
    CHECK(detector->scan(detector, NULL, true, data, &results, NULL) == -1 && !fail_alloc_after);
    check_prior(&results, prior);

    /* The shared push guard also returns +1, never a successful empty scan. */
    size_t capacity = results.cap; results.cap = 0;
    CHECK(detector->scan(detector, NULL, false, data, &results, &error) == -1);
    CHECK(error && !strcmp(error, "cannot append Couchbase result")); results.cap = capacity;
    check_prior(&results, prior); free(error); error = NULL;
    br_results_clear(&results);
    /* A failure must not poison the immutable patterns or a later invocation. */
    results = test_scan(detector, NULL, true, input, sizeof(input) - 1);
    CHECK(results.len == 2);
    check_result(&results.items[0], text(connection), text("Name"), text("aA1!"), true);
    check_result(&results.items[1], text(connection), text("Name"), text("bB2?"), true);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    hosts(detector); common_patterns(detector); rune_limits(detector); password_policy(detector);
    products(detector); unbounded_hosts(detector); verification_boundary(detector);
    invalid_utf8(detector); fatal_errors(detector);
    printf("Couchbase: %zu assertions, 0 failures; synthetic offline, zero transport calls\n", test_assertions);
    return 0;
}
