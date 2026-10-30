/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"

int br_voicegain_init(const br_detector **out, char **error);

static char key[192], dotted[192];

struct json_object *json_object_new_string_len(const char *value, const int len)
{
    CHECK(len == 191);
    char copy[192]; memcpy(copy, value, 191); copy[191] = '\0';
    return json_object_new_string(copy);
}

static void make_key(char out[192], char fill, char separator)
{
    memcpy(out, "ey", 2);
    memset(out + 2, fill, 34);
    out[36] = separator;
    memcpy(out + 37, "ey", 2);
    memset(out + 39, fill, 108);
    out[147] = separator;
    memset(out + 148, fill, 43);
    out[191] = '\0';
}

static void check_result(const br_result *result, const char *expected, bool verified)
{
    test_key_result(result, 417, expected, "key");
    CHECK(result->verified == verified && !result->verification_error);
}

typedef struct { const char *key; int status; } reply;
typedef struct { reply row; const br_scan_ctx *expected_ctx; } script;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    script *steps = http->user;
    CHECK(ctx == steps->expected_ctx);
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://api.voicegain.ai/v1/sa/config"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == 5000 && request->detector_type == 417);
    CHECK(request->nheaders == 3);
    CHECK(!strcmp(request->headers[0].name, "Content-Type") && !strcmp(request->headers[0].value, "application/json"));
    CHECK(!strcmp(request->headers[1].name, "Authorization"));
    CHECK(!strncmp(request->headers[1].value, "Bearer ", 7) && !strcmp(request->headers[1].value + 7, steps->row.key));
    CHECK(!strcmp(request->headers[2].name, "User-Agent"));
    http->response = (br_http_response){.status = steps->row.status};
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL; char *error = NULL;
    make_key(key, 'a', '.'); make_key(dotted, 'b', 'X');
    CHECK(strlen(key) == 191 && strlen(dotted) == 191);
    CHECK(br_voicegain_init(NULL, &error) == -1); free(error);
    CHECK(!br_voicegain_init(&detector, &error) && !error);
    CHECK(detector->type == 417 && !strcmp(detector->name, "Voicegain"));
    CHECK(!strcmp(detector->description, "Voicegain is a speech recognition and natural language processing service. Voicegain API keys can be used to access and manage Voicegain services and data."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "voicegain") && detector->max_credential_span == -1);
    return detector;
}

static void extraction(const br_detector *detector)
{
    char input[280];
    snprintf(input, sizeof(input), "voicegain %s", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1); check_result(&results.items[0], key, false); br_results_clear(&results);
    snprintf(input, sizeof(input), "VOICEGAIN %s", dotted); /* Unescaped dots match any non-newline. */
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1); check_result(&results.items[0], dotted, false); br_results_clear(&results);
    char broken[192]; make_key(broken, 'a', '\n');
    snprintf(input, sizeof(input), "voicegain %s", broken);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
    snprintf(input, sizeof(input), "voicegain %s", key);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len); br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    char input[220]; snprintf(input, sizeof(input), "voicegain %s", key);
    const int codes[] = {200, 299, 300};
    for (size_t i = 0; i < 3; ++i) {
        script steps = {.row = {.key = key, .status = codes[i]}};
        test_http http = {.inspect = inspect, .user = &steps};
        br_transport transport = test_transport(&http);
        br_scan_ctx ctx = {.transport = &transport}; steps.expected_ctx = &ctx;
        br_results results = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(http.calls == 1 && http.releases == 1 && results.len == 1);
        check_result(&results.items[0], key, codes[i] < 300);
        br_results_clear(&results);
    }
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector); verification(detector);
    return test_finish("Voicegain unescaped separators + bearer config request + nil drop");
}
