/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"
#include "../../src/detectors/json.h"

static int calls;
static int force_json;
static const char *mode = "ok";
static const char *body_text = "{\"services\":[{\"friendly_name\":\"demo\",\"account_sid\":\"ACabc\"}]}";
static const char *sid = "ACabcdefabcdefabcdefabcdefabcdefab";
static const char *api_key = "0123456789abcdef0123456789abcdef";

static int (*real_first_document)(br_slice, const char *, br_json **, size_t *, char **) = br_json_first_document;
static int first_hook(br_slice body, const char *read_error, br_json **out, size_t *end, char **cause)
{
    if (force_json) {
        *out = NULL;
        if (end) *end = 0;
        *cause = NULL;
        return force_json;
    }
    return real_first_document(body, read_error, out, end, cause);
}
#define br_json_first_document first_hook

static int fail_local(char **error)
{
    if (error) *error = strdup("unsupported HTTP client profile");
    return 1;
}

static int twilio_send(const br_scan_ctx *ctx, const br_http_request *request,
                       br_http_response *response, char **error)
{
    (void)ctx;
    calls++;
    CHECK(request->profile == BR_HTTP_RETRYABLE);
    CHECK(request->dedup_key.len > 3 && !memcmp(request->dedup_key.data, "26:", 3));
    CHECK(!strcmp(request->method, "GET") && !strcmp(request->url, "https://verify.twilio.com/v2/Services"));
    CHECK(!strcmp(request->headers[0].value, "application/x-www-form-urlencoded"));
    CHECK(!strcmp(request->headers[1].value, "*/*"));
    CHECK(!strcmp(request->headers[2].name, "Authorization") && !strncmp(request->headers[2].value, "Basic ", 6));
    if (!strcmp(mode, "blocked")) return fail_local(error);
    if (!strcmp(mode, "other")) { response->status = 500; return 0; }
    response->status = 200;
    response->body = (br_slice){(const unsigned char *)body_text, strlen(body_text)};
    return 0;
}
#define br_http_send twilio_send
#include "../../src/detectors/twilio.c"
#undef br_http_send

int main(void)
{
    CHECK(strlen(sid) == 34 && strlen(api_key) == 32);
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_twilio_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 26 && detector->max_credential_span == 1024);
    char input[96];
    snprintf(input, sizeof(input), "twilio %s %s", sid, api_key);
    br_scan_ctx ctx = {0};
    br_results results = {0};
    char *scan_error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &scan_error) == 0);
    CHECK(results.len == 1 && results.items[0].verified && !scan_error);
    CHECK(!strcmp(results.items[0].redacted, sid));
    CHECK(results.items[0].raw_v2.len == 34 + 32);
    br_json *name = NULL;
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "friendly_name", &name));
    CHECK(!strcmp(json_object_get_string(name), "demo"));
    br_json *guide = NULL;
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "rotation_guide", &guide));
    CHECK(!strcmp(json_object_get_string(guide), "https://howtorotate.com/docs/tutorials/twilio/"));
    br_results_clear(&results);
    mode = "other";
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &scan_error) == 0);
    CHECK(results.items[0].verification_error && strstr(results.items[0].verification_error, "unexpected HTTP response status 500"));
    br_results_clear(&results);
    mode = "blocked";
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &scan_error) == 0);
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    CHECK(detector->scan(detector, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &scan_error) == 0);
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);

    mode = "ok";
    body_text = "{\"Services\":[{\"Friendly_Name\":\"Folded\",\"Account_SID\":\"ACfold\",\"SID\":\"exact\"}]}";
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &scan_error) == 0);
    CHECK(results.len == 1 && results.items[0].verified);
    br_json *folded = NULL, *account = NULL;
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "friendly_name", &folded));
    CHECK(!strcmp(json_object_get_string(folded), "Folded"));
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "account_sid", &account));
    CHECK(!strcmp(json_object_get_string(account), "ACfold"));
    br_results_clear(&results);

    body_text = "{\"services\":[{\"friendly_name\":\"first\",\"friendly_name\":\"second\",\"account_sid\":\"A\",\"sid\":\"S\"}]}";
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &scan_error) == 0);
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "friendly_name", &folded));
    CHECK(!strcmp(json_object_get_string(folded), "second"));
    br_results_clear(&results);

    body_text = "{\"services\":[{\"friendly_name\":\"demo\",\"sid\":1,\"account_sid\":\"A\"}]}";
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &scan_error) == 0);
    CHECK(results.items[0].verified);
    CHECK(!json_object_object_get_ex(results.items[0].extra_data, "friendly_name", &folded));
    br_results_clear(&results);

    body_text = "{\"services\":[{\"friendly_name\":\"demo\",\"account_sid\":\"A\",\"sid\":\"S\"},{\"sid\":false}]}";
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &scan_error) == 0);
    CHECK(results.items[0].verified);
    CHECK(!json_object_object_get_ex(results.items[0].extra_data, "friendly_name", &folded));
    br_results_clear(&results);

    body_text = "{\"services\":[null,{\"friendly_name\":\"later\",\"account_sid\":\"A\",\"sid\":\"S\"}]}";
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &scan_error) == 0);
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "friendly_name", &folded));
    CHECK(!strcmp(json_object_get_string(folded), ""));
    br_results_clear(&results);

    body_text = "{\"services\":[{\"friendly_name\":\"old\",\"account_sid\":\"OLD\"}],\"services\":[{\"friendly_name\":\"new\"}]}";
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &scan_error) == 0);
    CHECK(results.items[0].verified);
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "friendly_name", &folded));
    CHECK(!strcmp(json_object_get_string(folded), "new"));
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "account_sid", &account));
    CHECK(!strcmp(json_object_get_string(account), ""));
    br_results_clear(&results);
    body_text = "{\"services\":[{\"friendly_name\":\"old\",\"account_sid\":\"OLD\"}],\"services\":null}";
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &scan_error) == 0);
    CHECK(results.items[0].verified && !json_object_object_get_ex(results.items[0].extra_data, "friendly_name", &folded));
    br_results_clear(&results);
    body_text = "{\"services\":[{\"friendly_name\":\"old\",\"account_sid\":\"OLD\"}],\"services\":[]}";
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &scan_error) == 0);
    CHECK(results.items[0].verified && !json_object_object_get_ex(results.items[0].extra_data, "friendly_name", &folded));
    br_results_clear(&results);
    body_text = "{\"services\":[{\"friendly_name\":\"A\\u0000B\",\"account_sid\":\"C\\u0000D\"}]}";
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &scan_error) == 0);
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "friendly_name", &folded));
    CHECK(json_object_get_string_len(folded) == 3 && !memcmp(json_object_get_string(folded), "A\0B", 3));
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "account_sid", &account));
    CHECK(json_object_get_string_len(account) == 3 && !memcmp(json_object_get_string(account), "C\0D", 3));
    br_results_clear(&results);
    body_text = "{";
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &scan_error) == 0);
    CHECK(results.items[0].verified && !json_object_object_get_ex(results.items[0].extra_data, "friendly_name", &folded));
    br_results_clear(&results);

    force_json = 1;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &scan_error) == 0);
    CHECK(results.len == 1 && results.items[0].verified && !scan_error);
    CHECK(!json_object_object_get_ex(results.items[0].extra_data, "friendly_name", &folded));
    br_results_clear(&results);
    force_json = 2;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &scan_error) != 0);
    CHECK(!results.len);
    free(scan_error);
    br_results_clear(&results);
    return test_finish("Twilio");
}
