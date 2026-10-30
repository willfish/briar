/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

int br_userflow_init(const br_detector **out, char **error);

static const char key[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char other[] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

typedef struct {
    test_http http;
    const char *url_part;
    const char *header_name;
    const char *header_value;
    int nheaders;
    uint32_t timeout;
    int status;
    const char *body;
    const char *send_error;
    int send_rc;
} probe;

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    probe *p = http->user;
    CHECK(ctx && request && !strcmp(request->method, "GET"));
    CHECK(request->profile == BR_HTTP_SANE && request->timeout_ms == p->timeout);
    CHECK(request->detector_type == 779);
    CHECK(!request->body.data && !request->body.len);
    if (p->url_part) CHECK(strstr(request->url, p->url_part));
    CHECK(request->nheaders == (size_t)p->nheaders);
    if (p->header_name) {
        bool found = false;
        for (size_t i = 0; i < request->nheaders; ++i)
            if (!strcmp(request->headers[i].name, p->header_name) &&
                !strcmp(request->headers[i].value, p->header_value)) found = true;
        CHECK(found);
    }
    CHECK(!strcmp(request->headers[request->nheaders - 1].name, "User-Agent"));
    http->response.status = p->status;
    http->response.body = p->body ? (br_slice){(const unsigned char *)p->body, strlen(p->body)} : (br_slice){0};
    http->send_error = p->send_error;
    http->send_rc = p->send_rc;
}

static br_results scan_probe(const br_detector *detector, const char *input, probe *p)
{
    p->http.inspect = inspect;
    p->http.user = p;
    br_transport transport = {p, test_http_send, test_http_release};
    br_scan_ctx ctx = {.transport = &transport};
    return test_scan(detector, &ctx, true, input, strlen(input));
}

static const br_detector *descriptor(void)
{
    const br_detector *detector = NULL, *again = NULL;
    char *error = NULL;
    CHECK(br_userflow_init(NULL, &error) != 0 && error);
    free(error);
    error = NULL;
    CHECK(br_userflow_init(&detector, &error) == 0 && detector && !error);
    CHECK(br_userflow_init(&again, NULL) == 0 && again == detector);
    CHECK(detector->type == 779 && !strcmp(detector->name, "Userflow"));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "userflow"));
    CHECK(!strcmp(detector->description, "Userflow is a service for creating user onboarding experiences. Userflow API keys can be used to access and modify user onboarding data and workflows."));
    CHECK(detector->scan && detector->state);
    return detector;
}

static void extraction(const br_detector *detector)
{
    char input[512];
    snprintf(input, sizeof(input), "userflow %s", key);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    test_key_result(&results.items[0], 779, key, "key");
    br_results_clear(&results);
    snprintf(input, sizeof(input), "userflow %s\nuserflow %s", key, other);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 2);
    test_key_result(&results.items[1], 779, other, "key");
    br_results_clear(&results);
    results = test_scan(detector, NULL, false, key, strlen(key));
    CHECK(results.len == 0);
    br_results_clear(&results);
}

static void verification(const br_detector *detector)
{
    char input[512];
    snprintf(input, sizeof(input), "userflow %s", key);
    probe ok = {.url_part = "https://api.userflow.com/users", .header_name = "Authorization",
                 .header_value = "Bearer aaaaaaaaaaaaaaaaaaaaaaaaaaaaa", .nheaders = 3, .timeout = 5000,
                 .status = 204, .body = NULL, .send_rc = 0};
    br_results results = scan_probe(detector, input, &ok);
    CHECK(results.len == 1 && results.items[0].verified && ok.http.calls == 1 && ok.http.releases == 1);
    br_results_clear(&results);
    probe quiet = ok;
    quiet.status = 403;
    quiet.body = "no";
    results = scan_probe(detector, input, &quiet);
    CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(results.len == 0);
    br_results_clear(&results);
}

int main(void)
{
    const br_detector *detector = descriptor();
    extraction(detector);
    verification(detector);
    return test_finish("userflow");
}
